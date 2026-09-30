#!/bin/zsh
set -eu
printf 'Host: %s\n' "$(hostname)"
printf 'macOS: %s\n' "$(sw_vers -productVersion)"
printf 'Architecture: %s\n' "$(uname -m)"
