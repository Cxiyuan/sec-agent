#!/bin/sh
# 深瞳 · Zeek 采集容器健康检查（Dockerfile HEALTHCHECK 调用）。
#
# 判定依据是入口脚本（entrypoint.sh: start_health_loop）写的哨兵文件：
#   ok <UTC 时间> zeek_pid=<pid> flaps=<n>   → 健康
#   unhealthy <UTC 时间> <原因>              → 不健康
#   文件缺失 / 超过 2 分钟没更新              → 不健康（健康循环自己挂了）
#
# 只上报状态，不重启容器：compose 的 restart 策略不看健康状态，因此不会和
# entrypoint 的「Zeek 退出就重拉」循环互相打架。
set -eu

f="${ZEEK_HEALTH_FILE:-/tmp/zeek-health}"

if [ ! -s "$f" ]; then
  echo "健康哨兵不存在或为空：${f}（入口的健康循环可能没起来）"
  exit 1
fi

line="$(head -n 1 "$f")"
if ! printf '%s' "$line" | grep -q '^ok '; then
  echo "不健康：${line}"
  exit 1
fi

# 哨兵过期 = 健康循环停摆（默认允许 2 分钟，是 30s 周期的 4 倍）
if ! find "$f" -mmin -2 2>/dev/null | grep -q .; then
  echo "健康哨兵已过期（>2 分钟未更新）：${line}"
  exit 1
fi

echo "ok：${line}"
exit 0
