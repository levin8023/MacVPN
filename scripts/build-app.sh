#!/bin/sh
set -eu
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TASK_ROOT"
VERSION=$(cat VERSION)
mkdir -p "$TASK_ROOT/.build/module-cache" "$TASK_ROOT/build"
# Never reuse a bundle that may contain stale resources or local files.
STAGE=$(mktemp -d "$TASK_ROOT/.build/app.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT HUP INT TERM
APP="$STAGE/MacVPN.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
xcrun swiftc -O -parse-as-library -swift-version 5 -module-cache-path "$TASK_ROOT/.build/module-cache" \
  -debug-prefix-map "$TASK_ROOT"=. -file-prefix-map "$TASK_ROOT"=. \
  -target arm64-apple-macosx13.0 Sources/*.swift -o "$APP/Contents/MacOS/MacVPN"
cp backend/strongvpn.py backend/vpn_backend.py backend/app_bridge.py "$APP/Contents/Resources/"
/usr/bin/python3 - "$APP/Contents/Info.plist" "$VERSION" <<'PY'
import plistlib
import sys
with open(sys.argv[1], 'wb') as stream:
    plistlib.dump(dict(CFBundleIdentifier='io.github.macvpn.app', CFBundleName='MacVPN',
                      CFBundleDisplayName='MacVPN', CFBundleExecutable='MacVPN',
                      CFBundlePackageType='APPL', CFBundleShortVersionString=sys.argv[2],
                      CFBundleVersion='1', LSUIElement=True, LSMinimumSystemVersion='13.0',
                      NSHighResolutionCapable=True,
                      NSDocumentsFolderUsageDescription='Read the VPN configuration you select.'), stream)
PY
/usr/bin/codesign --force --sign - "$APP"
/usr/bin/codesign --verify --strict "$APP"
rm -rf "$TASK_ROOT/build/MacVPN.app"
mv "$APP" "$TASK_ROOT/build/MacVPN.app"
printf '%s\n' "$TASK_ROOT/build/MacVPN.app"
