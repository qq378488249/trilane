#!/bin/sh
# 跑批失败排障。用法：
#   sh deploy/triage.sh runs/<批次>
#   sh deploy/triage.sh runs/<批次> --json
#
# 只读文件，不改任何东西，也不启动容器。
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "找不到 python3/python" >&2
  exit 2
fi

exec "$PY" "$DIR/triage.py" "$@"
