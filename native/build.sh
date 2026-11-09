#!/bin/bash
set -euo pipefail

NATIVE_DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$NATIVE_DIR/build/Open Passwords Helper.app"
RESOURCES="$APP/Contents/Resources"
/usr/bin/swift "$NATIVE_DIR/generate-icons.swift"
mkdir -p "$APP/Contents/MacOS" "$RESOURCES"

/usr/bin/clang -fobjc-arc -O2 -Wall -Wextra -mmacosx-version-min=13.0 \
  -framework AppKit -framework CoreGraphics -framework Security \
  "$NATIVE_DIR/OpenPasswordsHelper.m" \
  "$NATIVE_DIR/PasskeyHost.m" \
  -o "$APP/Contents/MacOS/OpenPasswordsHelper"
/bin/cp "$NATIVE_DIR/Info.plist" "$APP/Contents/Info.plist"
/bin/cp "$NATIVE_DIR/OpenPasswordsPasskeyHost" "$RESOURCES/OpenPasswordsPasskeyHost"
/bin/cp "$NATIVE_DIR/OpenPasswords.icns" "$RESOURCES/OpenPasswords.icns"
/usr/bin/printf 'APPL????' > "$APP/Contents/PkgInfo"
/bin/chmod 755 "$RESOURCES/OpenPasswordsPasskeyHost"
/usr/bin/codesign --force --deep --sign - "$APP"
printf 'Built %s\n' "$APP"
