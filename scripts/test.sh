#!/bin/sh
set -eu
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TASK_ROOT"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$TASK_ROOT/backend${PYTHONPATH:+:$PYTHONPATH}" \
  /usr/bin/python3 -m unittest discover -s tests -v

mkdir -p "$TASK_ROOT/.build/module-cache"
xcrun swiftc -module-cache-path "$TASK_ROOT/.build/module-cache" \
  Sources/ConfigurationStore.swift tests/ConfigurationStoreTests.swift -o .build/configuration-store-tests
.build/configuration-store-tests
