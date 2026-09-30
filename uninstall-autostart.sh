#!/bin/zsh
set -euo pipefail

label='com.muse.pc-control'
plist_path="$HOME/Library/LaunchAgents/$label.plist"

launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
rm -f "$plist_path"
print "Muse PC Control automatic startup has been removed."
