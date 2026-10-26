#!/bin/sh
# 智能体容器入口：种 profile → 自愈插件 → 组装信任围栏参数 → 起 dsh web。
set -eu

DSH_HOME="${DSH_HOME:-/data/dsh}"
BIN="/opt/agent/dsh/apps/cli/lib/bin.js"
BAKED_HOME="/opt/dsh-home"
PROFILE_PKG="$DSH_HOME/profiles/web/package.json"

mkdir -p "$DSH_HOME"

# 首次运行（卷为空）：把镜像里 bake 好的 profile 种进去。
# bake 时 file: 依赖已快照进 profile 自带 store，种入后无需联网。
if [ ! -d "$DSH_HOME/profiles/web" ]; then
  echo "[xdr-agent] seeding dsh home from image..."
  cp -a "$BAKED_HOME/." "$DSH_HOME/"
fi

# 自愈：卷里有旧 profile 但插件依赖缺失（镜像新增插件、手工清过 node_modules）时补装。
# 优先从镜像里 bake 好的 profile 离线合并：卷里 node_modules 记录的 pnpm store
# 路径来自上一次构建（/home/node/.local/share/pnpm/store/v11），新镜像的 pnpm
# 会改用卷内 store，于是现场 `plugin add` 直接 ERR_PNPM_UNEXPECTED_STORE 起不来
# （2026-10-26 上线踩过：新增 xdr-ui 后容器无限重启）。
sync_from_image() {
  pkg="$1"
  baked="$BAKED_HOME/profiles/web"
  vol="$DSH_HOME/profiles/web"
  [ -e "$baked/node_modules/$pkg/package.json" ] || return 1
  echo "[xdr-agent] syncing $pkg from baked profile (offline)"
  mkdir -p "$vol/node_modules"
  # 目录并集：镜像新增的插件/依赖补进卷，用户自己加装的插件不被删。
  cp -a "$baked/node_modules/." "$vol/node_modules/"
  # 依赖声明按并集合并：镜像期望的插件必须出现，卷里已有的额外插件保留。
  node - "$PROFILE_PKG" "$baked/package.json" <<'NODE'
const fs = require('node:fs')
const [volPath, bakedPath] = process.argv.slice(2)
const vol = JSON.parse(fs.readFileSync(volPath, 'utf8'))
const baked = JSON.parse(fs.readFileSync(bakedPath, 'utf8'))
vol.dependencies = { ...(vol.dependencies ?? {}), ...(baked.dependencies ?? {}) }
vol.dsh = vol.dsh ?? {}
vol.dsh.profile = vol.dsh.profile ?? {}
vol.dsh.profile.bundles = [
  ...new Set([...(vol.dsh.profile.bundles ?? []), ...(baked.dsh?.profile?.bundles ?? [])]),
]
fs.writeFileSync(volPath, `${JSON.stringify(vol, null, 2)}\n`)
NODE
  cp -f "$baked/pnpm-lock.yaml" "$vol/pnpm-lock.yaml" 2>/dev/null || true
  cp -f "$baked/pnpm-workspace.yaml" "$vol/pnpm-workspace.yaml" 2>/dev/null || true
  return 0
}

install_checked() {
  pkg="$1"; dir="$2"
  if ! grep -q "\"$pkg\"" "$PROFILE_PKG" 2>/dev/null \
    || [ ! -e "$DSH_HOME/profiles/web/node_modules/$pkg/package.json" ]; then
    if sync_from_image "$pkg"; then
      return 0
    fi
    echo "[xdr-agent] $pkg missing from web profile, installing..."
    node "$BIN" plugin --profile web add "file:$dir"
  fi
}
install_checked @sec-agent/xdr-ingest /opt/agent/plugins/xdr-ingest
install_checked @sec-agent/xdr-ui /opt/agent/plugins/xdr-ui

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
