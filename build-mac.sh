#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
app="${1:-build/合唱比赛计分台.app}"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>local.buct.choir129</string>
  <key>CFBundleExecutable</key><string>ChoirScoring</string>
  <key>CFBundleName</key><string>合唱比赛计分台</string>
  <key>CFBundleDisplayName</key><string>合唱比赛计分台</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>AppIcon.icns</string>
  <key>LSUIElement</key><true/>
  <key>CFBundleShortVersionString</key><string>2.0.0</string>
  <key>CFBundleVersion</key><string>11</string>
  <key>NSDesktopFolderUsageDescription</key><string>读取合唱比赛设置并保存评分、投票和登录记录。</string>
</dict>
</plist>
PLIST
cp AppIcon.icns server.py login.html '合唱比赛计分.html' "$app/Contents/Resources/"
swiftc -parse-as-library -O DesktopApp.swift -o "$app/Contents/MacOS/ChoirScoring"
codesign --force --sign - "$app"
codesign --verify --strict "$app"
