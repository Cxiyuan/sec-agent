#!/usr/bin/env bash
# 健康检查：读入口写的哨兵文件（healthy / unhealthy <时间> <原因>）。
# 没有哨兵文件 = 入口还没起来，按不健康算（start-period 已经给足时间）。
set -euo pipefail
HEALTH_FILE="${SURICATA_HEALTH_FILE:-/tmp/shentong-suricata-health}"
if [ ! -s "$HEALTH_FILE" ]; then
  echo "unhealthy：哨兵文件不存在（$HEALTH_FILE）"
  exit 1
fi
head -1 "$HEALTH_FILE" | grep -q '^healthy' || {
  echo "$(head -1 "$HEALTH_FILE")"
  exit 1
}
exit 0
