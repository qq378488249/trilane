#!/bin/sh
# 仓库根的快捷入口：真正的脚本在 deploy/triage.sh。
#   ./triage.sh runs/<批次>
#   ./triage.sh runs/<批次> --json
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$DIR/deploy/triage.sh" "$@"
