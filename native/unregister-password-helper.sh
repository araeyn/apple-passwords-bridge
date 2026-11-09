#!/bin/bash
set -euo pipefail

APP="$HOME/Applications/Open Passwords Helper.app/Contents/MacOS/OpenPasswordsHelper"
if [ ! -x "$APP" ]; then
  echo "Open Passwords Helper is not installed in ~/Applications." >&2
  exit 1
fi
"$APP" --remove-host
printf 'Removed the browser registration. The app remains in ~/Applications.\n'
