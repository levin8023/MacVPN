#!/bin/sh
set -eu
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TASK_ROOT"
APP="$TASK_ROOT/build/MacVPN.app"
VERSION=$(cat VERSION)
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$TASK_ROOT/.build/module-cache"
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
printf '%s\n' "$APP"
