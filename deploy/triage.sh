#!/bin/sh
# 跑批失败排障。用法：
#   sh deploy/triage.sh runs/<批次>
#   sh deploy/triage.sh runs/<批次> --json
#
# 只读文件，不改任何东西，也不启动容器。
#
# triage.py 可能在脚本旁边，也可能不在（脚本被复制到别处时），
# 所以这里按顺序找几个常见位置；都找不到就把找过的地方列出来。
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "找不到 python3/python" >&2
  exit 2
fi

TRIAGE=""
for candidate in \
  "$SCRIPT_DIR/triage.py" \
  "$SCRIPT_DIR/../deploy/triage.py" \
  "$SCRIPT_DIR/../triage.py" \
  "$PWD/triage.py" \
  "$PWD/deploy/triage.py"
do
  if [ -f "$candidate" ]; then
    TRIAGE="$candidate"
    break
  fi
done

if [ -z "$TRIAGE" ]; then
  echo "找不到 triage.py。找过：" >&2
  for candidate in \
    "$SCRIPT_DIR/triage.py" \
    "$SCRIPT_DIR/../deploy/triage.py" \
    "$SCRIPT_DIR/../triage.py" \
    "$PWD/triage.py" \
    "$PWD/deploy/triage.py"
  do
    echo "  $candidate" >&2
  done
  echo >&2
  echo "triage.py 在仓库的 deploy/ 下，正常用法是：" >&2
  echo "  sh deploy/triage.sh runs/<批次>" >&2
  echo "  python3 deploy/triage.py runs/<批次>" >&2
  exit 2
fi

exec "$PY" "$TRIAGE" "$@"
