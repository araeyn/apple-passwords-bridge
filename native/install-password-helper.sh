#!/bin/bash
set -euo pipefail

NATIVE_DIR="$(cd "$(dirname "$0")" && pwd)"
"$NATIVE_DIR/build.sh"
"$NATIVE_DIR/build/Open Passwords Helper.app/Contents/MacOS/OpenPasswordsHelper" --install
printf 'Installed the Open Passwords native host. Reload the extension in your browser.\n'
