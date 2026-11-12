import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let dataDirectory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Desktop/大三-主席团/06_129合唱比赛", isDirectory: true)
    private var server: Process?
    private var statusItem: NSStatusItem?
    private var address: URL?
    private let desktopKey = UUID().uuidString + UUID().uuidString

    func applicationDidFinishLaunching(_ notification: Notification) {
        installMenu()
        guard let python = pythonExecutable(),
              let script = Bundle.main.url(forResource: "server", withExtension: "py") else {
            showError("请先安装 Python 3.10 或更新版本，并使用完整的计分台应用。")
            return
        }
        let server = Process()
        let output = Pipe()
        server.executableURL = python
        server.arguments = [script.path, "serve", "--data-dir", dataDirectory.path, "--port", "0",
                            "--parent-pid", String(ProcessInfo.processInfo.processIdentifier)]
        var environment = ProcessInfo.processInfo.environment
        environment["CHOIR_DESKTOP_KEY"] = desktopKey
        server.environment = environment
        server.standardOutput = output
        server.standardError = output
        self.server = server
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let handle = output.fileHandleForReading
            var line = Data()
            while let byte = try? handle.read(upToCount: 1), !byte.isEmpty, byte[0] != 10 {
                line.append(byte)
            }
            let firstLine = String(decoding: line, as: UTF8.self)
            if let url = URL(string: firstLine), url.host == "127.0.0.1" {
                DispatchQueue.main.async {
                    self?.address = url
                    self?.openScoring()
                }
            } else {
                let remainder = handle.readDataToEndOfFile()
                let details = firstLine + "\n" + String(decoding: remainder, as: UTF8.self)
                DispatchQueue.main.async { self?.showError(details.trimmingCharacters(in: .whitespacesAndNewlines)) }
            }
        }
        do {
            try server.run()
        } catch {
            output.fileHandleForWriting.closeFile()
            showError(error.localizedDescription)
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openScoring()
        return false
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let server, server.isRunning { server.terminate() }
    }

    private func pythonExecutable() -> URL? {
        let versions = URL(fileURLWithPath: "/Library/Frameworks/Python.framework/Versions", isDirectory: true)
        let installed = (try? FileManager.default.contentsOfDirectory(at: versions, includingPropertiesForKeys: nil)) ?? []
        let frameworkPaths = installed.sorted { $0.lastPathComponent.compare($1.lastPathComponent, options: .numeric) == .orderedDescending }
            .map { $0.appendingPathComponent("bin/python3").path }
        let paths = frameworkPaths + ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
        return paths.first(where: { FileManager.default.isExecutableFile(atPath: $0) }).map { URL(fileURLWithPath: $0) }
    }

    private func installMenu() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(systemSymbolName: "music.note", accessibilityDescription: "合唱比赛计分台")
        let menu = NSMenu()
        let open = menu.addItem(withTitle: "在 Chrome 中打开计分台", action: #selector(openScoring), keyEquivalent: "")
        open.target = self
        let folder = menu.addItem(withTitle: "打开备份文件夹", action: #selector(openBackups), keyEquivalent: "")
        folder.target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: "退出计分台", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "")
        item.menu = menu
        statusItem = item
    }

    @objc private func openScoring() {
        guard let address, var entry = URLComponents(url: address, resolvingAgainstBaseURL: false) else { return }
        entry.path = "/desktop"
        entry.fragment = desktopKey
        guard let url = entry.url else { return }
        let workspace = NSWorkspace.shared
        guard let chrome = workspace.urlForApplication(withBundleIdentifier: "com.google.Chrome") else {
            showError("请安装 Google Chrome 后重新打开计分台。")
            return
        }
        workspace.open([url], withApplicationAt: chrome, configuration: NSWorkspace.OpenConfiguration()) { [weak self] _, error in
            guard let error else { return }
            DispatchQueue.main.async { self?.showError(error.localizedDescription) }
        }
    }

    @objc private func openBackups() {
        NSWorkspace.shared.open(dataDirectory)
    }

    private func showError(_ details: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "计分台启动失败"
        alert.informativeText = details.isEmpty ? "请检查 Python 和比赛文件夹。" : details
        alert.runModal()
        NSApp.terminate(nil)
    }
}

@main
struct DesktopApp {
    static func main() {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        application.delegate = delegate
        withExtendedLifetime(delegate) { application.run() }
    }
}
