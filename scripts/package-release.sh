#!/bin/sh
# Only explicitly listed, credential-free files enter the release archive.
set -eu
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TASK_ROOT"
./scripts/build-app.sh
VERSION=$(cat VERSION)
mkdir -p "$TASK_ROOT/.build/release" "$TASK_ROOT/dist"
# Use a fresh staging directory to exclude leftovers from earlier packages.
STAGE=$(mktemp -d "$TASK_ROOT/.build/release/package.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT HUP INT TERM
mkdir "$STAGE/MacVPN"
cp -R build/MacVPN.app "$STAGE/MacVPN/"
cp README.md config.example.json CHANGELOG.md "$STAGE/MacVPN/"
if [ -f LICENSE ]; then cp LICENSE "$STAGE/MacVPN/"; fi
ARCHIVE="$TASK_ROOT/dist/MacVPN-$VERSION-macos-arm64.zip"
/usr/bin/ditto -c -k --norsrc --noextattr --noqtn --keepParent "$STAGE/MacVPN" "$ARCHIVE"
cd "$TASK_ROOT/dist"
/usr/bin/shasum -a 256 "$(basename "$ARCHIVE")" > SHA256SUMS
printf '%s\n' "$ARCHIVE"
