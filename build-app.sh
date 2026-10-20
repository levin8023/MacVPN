#!/bin/sh
# Compatibility entry point. Build products are written to build/.
set -eu
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$TASK_ROOT/scripts/build-app.sh" "$@"
