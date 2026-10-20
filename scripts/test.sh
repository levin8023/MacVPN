#!/bin/sh
set -eu
TASK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$TASK_ROOT"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$TASK_ROOT/backend${PYTHONPATH:+:$PYTHONPATH}" \
  /usr/bin/python3 -m unittest discover -s tests -v
