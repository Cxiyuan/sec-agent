#!/bin/sh
# 智能体容器入口：种 profile → 自愈插件 → 组装信任围栏参数 → 起 dsh web。
set -eu

DSH_HOME="${DSH_HOME:-/data/dsh}"
PLUGIN_DIR="/opt/agent/plugins/xdr-ingest"
BIN="/opt/agent/dsh/apps/cli/lib/bin.js"
BAKED_HOME="/opt/dsh-home"
PROFILE_PKG="$DSH_HOME/profiles/web/package.json"

mkdir -p "$DSH_HOME"

# 首次运行（卷为空）：把镜像里 bake 好的 profile 种进去。
# bake 时 link: 依赖已按镜像内绝对路径装好，种入后无需联网。
if [ ! -d "$DSH_HOME/profiles/web" ]; then
  echo "[xdr-agent] seeding dsh home from image..."
  cp -a "$BAKED_HOME/." "$DSH_HOME/"
fi

# 自愈：卷里有旧 profile 但插件依赖缺失（如手工清过 node_modules）时补装
if ! grep -q '"@sec-agent/xdr-ingest"' "$PROFILE_PKG" 2>/dev/null; then
  echo "[xdr-agent] xdr-ingest missing from web profile, installing..."
  node "$BIN" plugin --profile web add "link:$PLUGIN_DIR"
fi

# 组装启动命令。dsh web 默认自动绑定容器内第一块非内部 IPv4（LAN 默认）；
# DSH_WEB_HOST 可显式覆盖。
set -- node "$BIN" --profile web --no-open
if [ -n "${DSH_WEB_HOST:-}" ]; then
  set -- "$@" --host "$DSH_WEB_HOST"
fi

# 信任围栏：浏览器经 docker 发布口访问时 Host 是宿主机名/IP，不在
# 「loopback / 容器绑定 IP」放行名单里，必须显式声明（逗号或空格分隔，
# 不带端口的条目匹配该主机名的任意端口）。
if [ -n "${AGENT_TRUSTED_HOSTS:-}" ]; then
  for host in $(printf '%s' "$AGENT_TRUSTED_HOSTS" | tr ',' ' '); do
    if [ -n "$host" ]; then
      set -- "$@" --trusted-host "$host"
    fi
  done
fi

echo "[xdr-agent] starting: $*"
exec "$@"
