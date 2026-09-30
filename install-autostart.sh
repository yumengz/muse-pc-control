#!/bin/zsh
set -euo pipefail

ROOT_DIR=${0:A:h}
label='com.muse.pc-control'
launch_agents_dir="$HOME/Library/LaunchAgents"
logs_dir="$HOME/Library/Logs/MusePCControl"
plist_path="$launch_agents_dir/$label.plist"

mkdir -p "$launch_agents_dir" "$logs_dir"

cat >"$plist_path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/zsh</string>
        <string>$ROOT_DIR/start.sh</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$ROOT_DIR</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>15</integer>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>StandardOutPath</key>
    <string>$logs_dir/service.log</string>
    <key>StandardErrorPath</key>
    <string>$logs_dir/service-error.log</string>
</dict>
</plist>
PLIST

chmod 600 "$plist_path"
plutil -lint "$plist_path" >/dev/null

print "Installed $plist_path"
print "Muse PC Control will start automatically at the next macOS login."
print "To load it now, run: launchctl bootstrap gui/$(id -u) '$plist_path'"
