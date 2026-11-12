"""Password-protected, self-hosted choir scoring service."""

import argparse
import fcntl
import getpass
import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import tempfile
import threading
import time
import unicodedata
from datetime import datetime, timezone
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


HERE = Path(__file__).resolve().parent
AWARDS = {"style", "performance", "arrangement"}
GROUPS = {"expert", "teacher", "student"}
SESSION_SECONDS = 12 * 60 * 60
ONLINE_SECONDS = 60
COOKIE = "choir_session"
MAX_BODY = 2 * 1024 * 1024


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"{salt.hex()}:{digest.hex()}"


def matches_password(password, stored):
    return bool(stored) and hmac.compare_digest(
        password_hash(password, bytes.fromhex(stored.split(":", 1)[0])), stored
    )


def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def write_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            json.dump(value, file, ensure_ascii=False, indent=2, allow_nan=False)
            file.flush()
            os.fsync(file.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def valid_score(value):
    return value is None or (type(value) in (int, float) and 0 <= value <= 100 and math.isfinite(value))


def valid_state(data):
    def valid_record(record):
        return (isinstance(record, dict) and isinstance(record.get("id"), str)
                and re.fullmatch(r"[a-z]+[0-9]+", record["id"]) is not None
                and isinstance(record.get("name"), str) and 0 < len(record["name"].strip())
                and len(record["name"]) <= 60)

    if not isinstance(data, dict) or data.get("version") != 1:
        return False
    next_id, teams, judges = data.get("nextId"), data.get("teams"), data.get("judges")
    if (type(next_id) is not int or not 1 <= next_id < 2**53 or not isinstance(teams, list)
            or not teams or not isinstance(judges, list)):
        return False
    if not all(valid_record(judge) and judge.get("group") in GROUPS
               and type(judge.get("active")) is bool for judge in judges):
        return False
    judge_ids = {judge["id"] for judge in judges}
    if len(judge_ids) != len(judges):
        return False
    return all(valid_record(team) and isinstance(team.get("ballots"), dict)
               and all(judge in judge_ids and valid_score(score) for judge, score in team["ballots"].items())
               and isinstance(team.get("votes", {}), dict)
               and all(judge in judge_ids and isinstance(vote, str) and vote in AWARDS
                       for judge, vote in team.get("votes", {}).items()) for team in teams
               ) and len({team["id"] for team in teams}) == len(teams)


def revision(state):
    return hashlib.sha256(json.dumps(state, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def now_text():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ScoringServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, directory, origin, desktop_key=None):
        self.directory = directory
        self.score_file = directory / "合唱比赛计分-自动备份.json"
        self.auth_file = directory / ".choir-auth.json"
        self.login_file = directory / "合唱比赛登录记录.json"
        self.auth = read_json(self.auth_file, {})
        if not self.auth.get("admin"):
            raise ValueError("请先运行 set-admin 设置管理密码。")
        self.state = read_json(self.score_file, None)
        if self.state is not None and not valid_state(self.state):
            raise ValueError("自动备份格式有误，请先检查备份文件。")
        self.activity = self.state.pop("_scoreActivity", {}) if self.state else {}
        if not isinstance(self.activity, dict):
            self.activity = {}
        self.activity.setdefault("authors", {})
        self.activity.setdefault("conflicts", [])
        self.activity.setdefault("lastConflict", 0)
        self.logins = read_json(self.login_file, [])
        self.sessions = {}
        self.failures = {}
        self.lock = threading.RLock()
        self.desktop_key = desktop_key
        self.page = (HERE / "合唱比赛计分.html").read_bytes()
        self.login_page = (HERE / "login.html").read_bytes()
        super().__init__(address, Request)
        self.scoring = self
        self.local_origin = f"http://127.0.0.1:{self.server_port}"
        self.shared_origin = origin
        self.allowed_origins = (self.local_origin, self.shared_origin)
        self.lan_origin = None

    def update_access(self, settings, revoke):
        write_json(self.auth_file, settings)
        self.auth = settings
        self.sessions = {token: session for token, session in self.sessions.items() if not revoke(session)}

    def save_state(self, state, activity=None):
        activity = self.activity if activity is None else activity
        write_json(self.score_file, {**state, "_scoreActivity": activity})
        self.state = state
        self.activity = activity

    def add_score_conflict(self, team, judge, current, value, previous_author, submitter):
        activity = self.activity
        conflict_id = activity["lastConflict"] + 1
        notice = {
            "id": conflict_id, "team": team["name"], "judge": judge["name"],
            "current": current, "proposed": value,
            "previousName": previous_author["name"] if previous_author else "原录入人",
            "proposedName": submitter["name"],
        }
        recipients = [score_actor(submitter)]
        if previous_author:
            recipients.append(previous_author["actor"])
        entry = {"notice": notice, "recipients": recipients}
        updated = {**activity, "lastConflict": conflict_id, "conflicts": [*activity["conflicts"][-199:], entry]}
        self.save_state(self.state, updated)
        return notice

    def snapshot(self):
        timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        target = self.directory / f"合唱比赛计分备份-{timestamp}-{secrets.token_hex(3)}.json"
        write_json(target, self.state)


class RecorderListener(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, scoring):
        super().__init__(address, Request)
        self.scoring = scoring
        self.origin = f"http://{address[0]}:{self.server_port}"
        self.allowed_origins = (self.origin,)


class Request(BaseHTTPRequestHandler):
    server_version = "Choir"
    sys_version = ""

    @property
    def scoring(self):
        return self.server.scoring

    def setup(self):
        self.request.settimeout(15)
        super().setup()

    def log_message(self, *_args):
        pass

    def respond(self, status, data=None, *, page=None, cookie=None, location=None):
        body = page if page is not None else (json.dumps(data, ensure_ascii=False).encode() if data is not None else b"")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8" if page is not None else "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def cookie(self, token, lifetime):
        secure = "; Secure" if self.request_origin.startswith("https://") else ""
        return f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={lifetime}{secure}"

    def session(self):
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", "")).get(COOKIE)
        except CookieError:
            return None, None
        if not cookie:
            return None, None
        session = self.scoring.sessions.get(cookie.value)
        now = time.time()
        if not session or session["expires"] <= now:
            self.scoring.sessions.pop(cookie.value, None)
            return None, None
        if session["origin"] != self.request_origin:
            return None, None
        session["seen"] = now
        return cookie.value, session

    def check_host(self):
        for origin in self.server.allowed_origins:
            if origin and self.headers.get("Host") == urlsplit(origin).netloc:
                self.request_origin = origin
                return True
        self.respond(421, {"error": "请使用管理员给出的计分台地址。"})
        return False

    def do_GET(self):
        if not self.check_host():
            return
        route = urlsplit(self.path).path
        with self.scoring.lock:
            _, session = self.session()
            if route == "/":
                if session:
                    return self.respond(303, location="/app")
                return self.respond(200, page=self.scoring.login_page)
            if route == "/desktop" and self.scoring.desktop_key and self.request_origin == self.scoring.local_origin:
                return self.respond(200, page=self.scoring.login_page)
            if route == "/app":
                return self.respond(200, page=self.scoring.page) if session else self.respond(303, location="/")
            if not session:
                return self.respond(401, {"error": "请重新登录。"})
            if route == "/state":
                state = self.scoring.state
                response = {"state": state, "revision": revision(state), "role": session["role"],
                            "name": session["name"], "owner": self.is_owner(session)}
                cursor = parse_qs(urlsplit(self.path).query).get("after", [""])[0]
                if cursor.isascii() and cursor.isdecimal() and len(cursor) <= 16:
                    last_seen = int(cursor)
                    actor = score_actor(session)
                    response["conflicts"] = [
                        entry["notice"] for entry in self.scoring.activity["conflicts"]
                        if entry["notice"]["id"] > last_seen
                        and (session["role"] == "admin" or actor in entry["recipients"])
                    ]
                    response["conflictCursor"] = self.scoring.activity["lastConflict"]
                return self.respond(200, response)
            if route == "/audit" and self.is_owner(session):
                current = time.time()
                online = [{"name": item["name"], "role": item["role"], "login": item["login"], "remote": item.get("remote", False)}
                          for item in self.scoring.sessions.values()
                          if item["expires"] > current and current - item["seen"] <= ONLINE_SECONDS]
                staff_url = self.scoring.shared_origin or self.scoring.lan_origin
                return self.respond(200, {"online": online, "logins": self.scoring.logins[-100:][::-1],
                                          "staffConfigured": bool(self.scoring.auth.get("staff")),
                                          "staffUrl": staff_url,
                                          "sharedEnabled": self.scoring.auth.get("sharedEnabled", True),
                                          "staffEnabled": self.scoring.auth.get("staffEnabled", True),
                                          "blocked": list(self.scoring.auth.get("blocked", {}).values())})
            self.respond(404, {"error": "页面不存在。"})

    def do_POST(self):
        if not self.check_host():
            return
        if self.headers.get("Origin") != self.request_origin or self.headers.get_content_type() != "application/json":
            return self.respond(403, {"error": "请求来源不正确。"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                return self.respond(413, {"error": "请求大小不正确。"})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeError):
            return self.respond(400, {"error": "请求格式不正确。"})
        route = urlsplit(self.path).path
        try:
            with self.scoring.lock:
                if route == "/login":
                    return self.login(data)
                if route == "/desktop-login":
                    key = data.get("key")
                    if (self.request_origin != self.scoring.local_origin or not self.scoring.desktop_key
                            or not isinstance(key, str) or not key.isascii()
                            or not hmac.compare_digest(key, self.scoring.desktop_key)):
                        return self.respond(403, {"error": "请从这台 Mac 的桌面应用打开。"})
                    return self.create_session("admin", "管理员")
                token, session = self.session()
                if not session:
                    return self.respond(401, {"error": "请重新登录。"})
                if route == "/logout":
                    del self.scoring.sessions[token]
                    return self.respond(200, {}, cookie=self.cookie("", 0))
                if route == "/cell":
                    return self.update_cell(data, session)
                if session["role"] != "admin":
                    return self.respond(403, {"error": "此操作需要管理员权限。"})
                if route == "/save":
                    return self.replace_state(data)
                if route == "/snapshot":
                    self.scoring.snapshot()
                    return self.respond(200, {})
                if route in ("/staff-password", "/staff-access", "/shared-access"):
                    if not self.is_owner(session):
                        return self.respond(403, {"error": "登录权限只能在计分主机上管理。"})
                    if route == "/staff-password":
                        return self.change_staff_password(data)
                    if route == "/staff-access":
                        return self.change_staff_access(data)
                    return self.change_shared_access(data)
                return self.respond(404, {"error": "页面不存在。"})
        except (OSError, ValueError, TypeError):
            return self.respond(400, {"error": "保存失败，请检查数据格式和主机文件夹。"})

    def login(self, data):
        role, password, name = data.get("role"), data.get("password"), data.get("name")
        if role not in ("admin", "staff") or not isinstance(password, str) or len(password) > 256:
            return self.respond(400, {"error": "请输入有效密码。"})
        if self.request_origin != self.scoring.local_origin and not self.scoring.auth.get("sharedEnabled", True):
            return self.respond(403, {"error": "计分主机已暂停其他设备登录。"})
        if role == "staff" and (not isinstance(name, str) or not 1 <= len(name.strip()) <= 50
                                or any(ord(char) < 32 for char in name)):
            return self.respond(400, {"error": "请输入你的姓名。"})
        current = time.time()
        address = self.client_address[0]
        failures = [stamp for stamp in self.scoring.failures.get(address, []) if current - stamp < 60]
        if len(failures) >= 10:
            return self.respond(429, {"error": "尝试过多，请稍等一分钟。"})
        if not matches_password(password, self.scoring.auth.get(role)):
            self.scoring.failures[address] = [*failures, current]
            return self.respond(401, {"error": "密码错误，或管理员尚未设置录分密码。"})
        self.scoring.failures.pop(address, None)
        name = "管理员" if role == "admin" else name.strip()
        if role == "staff" and (not self.scoring.auth.get("staffEnabled", True)
                                or staff_key(name) in self.scoring.auth.get("blocked", {})):
            return self.respond(403, {"error": "管理员已暂停此录分权限。"})
        self.create_session(role, name)

    def create_session(self, role, name):
        current = time.time()
        prior, _ = self.session()
        if prior:
            self.scoring.sessions.pop(prior, None)
        entry = {"name": name, "role": role, "login": now_text(),
                 "remote": self.request_origin != self.scoring.local_origin}
        write_json(self.scoring.login_file, [*self.scoring.logins, entry])
        self.scoring.logins.append(entry)
        for token in list(self.scoring.sessions):
            if self.scoring.sessions[token]["expires"] <= current:
                del self.scoring.sessions[token]
        token = secrets.token_urlsafe(32)
        self.scoring.sessions[token] = {**entry, "origin": self.request_origin,
                                        "seen": current, "expires": current + SESSION_SECONDS}
        self.respond(200, {}, cookie=self.cookie(token, SESSION_SECONDS))

    def replace_state(self, request):
        data = request.get("state")
        if not valid_state(data):
            return self.respond(400, {"error": "参赛名单或备份格式不正确。"})
        data.pop("_scoreActivity", None)
        if self.scoring.state != data and request.get("revision") != revision(self.scoring.state):
            return self.respond(409, {"error": "记录已更新，请重新核对后再操作。"})
        old_teams = {team["id"]: team["ballots"] for team in (self.scoring.state or {}).get("teams", [])}
        new_teams = {team["id"]: team["ballots"] for team in data["teams"]}
        judge_ids = {judge["id"] for judge in data["judges"]}
        authors = {}
        for cell, author in self.scoring.activity["authors"].items():
            team_id, judge_id = cell.split("/", 1)
            if (team_id in old_teams and team_id in new_teams and judge_id in judge_ids
                    and old_teams[team_id].get(judge_id) == new_teams[team_id].get(judge_id)):
                authors[cell] = author
        self.scoring.save_state(data, {**self.scoring.activity, "authors": authors})
        self.respond(200, {"state": data, "revision": revision(data)})

    def update_cell(self, data, session):
        state = self.scoring.state
        kind = data.get("kind")
        value = data.get("value")
        if not state or kind not in ("ballots", "votes"):
            return self.respond(400, {"error": "请等待管理员初始化名单。"})
        judge_id = data.get("judge")
        judge = next((item for item in state["judges"] if item["id"] == judge_id and item["active"]), None)
        if (not judge
                or ("value" not in data or "previous" not in data)
                or (kind == "ballots" and not valid_score(value))
                or (kind == "votes" and value is not None and (not isinstance(value, str) or value not in AWARDS))):
            return self.respond(400, {"error": "评委或录入值不正确。"})
        team = next((team for team in state["teams"] if team["id"] == data.get("team")), None)
        if team is None:
            return self.respond(400, {"error": "该参赛单位已移除，请刷新页面。"})
        current = team.get(kind, {}).get(judge_id)
        if current == value:
            return self.respond(200, {"state": state, "revision": revision(state)})
        cell = f'{team["id"]}/{judge_id}'
        previous_author = self.scoring.activity["authors"].get(cell)
        actor = score_actor(session)
        different_recorder = (kind == "ballots" and current is not None and session["role"] != "admin"
                              and (not previous_author or previous_author["actor"] != actor))
        if current != data["previous"] or different_recorder:
            response = {"current": current, "state": state, "revision": revision(state)}
            if kind == "ballots":
                response["notice"] = self.scoring.add_score_conflict(team, judge, current, value, previous_author, session)
            return self.respond(409, response)
        # The same lock covers comparison, durable write and publication to other sessions.
        updated = json.loads(json.dumps(state))
        record = next(item for item in updated["teams"] if item["id"] == team["id"]).setdefault(kind, {})
        if value is None:
            record.pop(judge_id, None)
        else:
            record[judge_id] = value
        activity = self.scoring.activity
        if kind == "ballots":
            authors = {**activity["authors"]}
            authors[cell] = {"actor": actor, "name": session["name"]}
            activity = {**activity, "authors": authors}
        self.scoring.save_state(updated, activity)
        self.respond(200, {"state": updated, "revision": revision(updated)})

    def change_staff_password(self, data):
        password = data.get("password")
        if not isinstance(password, str) or not 7 <= len(password) <= 256:
            return self.respond(400, {"error": "录分密码须至少 7 位。"})
        if matches_password(password, self.scoring.auth["admin"]):
            return self.respond(400, {"error": "请为录分员设置一个独立的密码。"})
        updated = {**self.scoring.auth, "staff": password_hash(password)}
        self.scoring.update_access(updated, lambda session: session["role"] == "staff")
        self.respond(200, {})

    def change_staff_access(self, data):
        enabled = data.get("enabled")
        if type(enabled) is not bool:
            return self.respond(400, {"error": "请指定是否允许录分。"})
        name = data.get("name")
        if name is None:
            settings = {**self.scoring.auth, "staffEnabled": enabled}
            self.scoring.update_access(settings, lambda session: not enabled and session["role"] == "staff")
        else:
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 50:
                return self.respond(400, {"error": "姓名格式不正确。"})
            key = staff_key(name)
            blocked = {**self.scoring.auth.get("blocked", {})}
            if enabled:
                blocked.pop(key, None)
            else:
                blocked[key] = name.strip()
            settings = {**self.scoring.auth, "blocked": blocked}
            self.scoring.update_access(settings, lambda session:
                                      not enabled and session["role"] == "staff" and staff_key(session["name"]) == key)
        self.respond(200, {})

    def is_owner(self, session):
        return session["role"] == "admin" and self.request_origin == self.scoring.local_origin

    def change_shared_access(self, data):
        enabled = data.get("enabled")
        if type(enabled) is not bool:
            return self.respond(400, {"error": "请指定是否允许其他设备登录。"})
        settings = {**self.scoring.auth, "sharedEnabled": enabled}
        self.scoring.update_access(settings, lambda session: not enabled and session["remote"])
        self.respond(200, {})


def staff_key(name):
    return unicodedata.normalize("NFKC", name.strip()).casefold()


def score_actor(session):
    return f'{session["role"]}:{staff_key(session["name"])}'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("serve", "set-admin", "set-staff"))
    parser.add_argument("--data-dir", type=Path, default=Path.home() / ".choir129")
    parser.add_argument("--port", type=int, default=8789)
    parser.add_argument("--origin", help="HTTPS address from a reverse proxy on this computer")
    parser.add_argument("--lan-host", help="Private IPv4 address for a recorder-only listener")
    parser.add_argument("--lan-port", type=int, default=8789)
    parser.add_argument("--parent-pid", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.command in ("set-admin", "set-staff"):
        role = "admin" if args.command == "set-admin" else "staff"
        label = "管理密码" if role == "admin" else "录分密码"
        password = getpass.getpass(f"{label}：")
        minimum = 8 if role == "admin" else 7
        if len(password) < minimum or len(password) > 256 or password != getpass.getpass(f"再次输入{label}："):
            parser.error(f"两次密码须一致，且长度为 {minimum} 至 256 位。")
        path = args.data_dir / ".choir-auth.json"
        auth = read_json(path, {})
        if matches_password(password, auth.get("staff" if role == "admin" else "admin")):
            parser.error("管理密码和录分密码须分别设置。")
        write_json(path, {**auth, role: password_hash(password)})
        print(f"{label}已保存。重启服务后生效。")
        return
    if args.origin:
        parsed = urlsplit(args.origin)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
            parser.error("--origin 必须是无路径的 HTTPS 地址。")
    if args.lan_host:
        try:
            ip = ipaddress.IPv4Address(args.lan_host)
            private_networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            if not any(ip in ipaddress.IPv4Network(network) for network in private_networks):
                raise ValueError()
        except ValueError:
            parser.error("--lan-host 必须是本机的私有 IPv4 地址。")
    args.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (args.data_dir / ".choir-server.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error("该数据目录已有一个计分服务，请打开正在运行的服务。")
        desktop_key = os.environ.pop("CHOIR_DESKTOP_KEY", None) if args.parent_pid and not args.origin else None
        with ScoringServer(("127.0.0.1", args.port), args.data_dir, args.origin, desktop_key) as server:
            recorders = None
            if args.lan_host:
                try:
                    recorders = RecorderListener((args.lan_host, args.lan_port), server)
                except OSError:
                    try:
                        recorders = RecorderListener((args.lan_host, 0), server)
                    except OSError:
                        pass
                if recorders:
                    server.lan_origin = recorders.origin
                    threading.Thread(target=recorders.serve_forever, daemon=True).start()
            if args.parent_pid:
                def stop_when_launcher_exits():
                    while os.getppid() == args.parent_pid:
                        time.sleep(1)
                    server.shutdown()
                threading.Thread(target=stop_when_launcher_exits, daemon=True).start()
            print(server.local_origin, flush=True)
            if recorders:
                print(recorders.origin, flush=True)
            try:
                server.serve_forever()
            finally:
                if recorders:
                    recorders.shutdown()
                    recorders.server_close()


if __name__ == "__main__":
    main()
