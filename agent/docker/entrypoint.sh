#!/bin/sh
# 智能体容器入口：种 profile → 同步镜像里的插件 → 自愈缺失插件 → 起 dsh web。
set -eu

DSH_HOME="${DSH_HOME:-/data/dsh}"
BIN="/opt/agent/dsh/apps/cli/lib/bin.js"
BAKED_HOME="/opt/dsh-home"
PROFILE_PKG="$DSH_HOME/profiles/web/package.json"
BAKED_PROFILE="$BAKED_HOME/profiles/web"
STAMP="$DSH_HOME/.plugins.stamp"
BAKED_STAMP="$BAKED_HOME/.plugins.stamp"

mkdir -p "$DSH_HOME"

# 首次运行（卷为空）：把镜像里 bake 好的 profile 种进去。
if [ ! -d "$DSH_HOME/profiles/web" ]; then
  echo "[xdr-agent] seeding dsh home from image..."
  cp -a "$BAKED_HOME/." "$DSH_HOME/"
fi

# 依赖声明按并集合并：镜像期望的插件必须出现，卷里已有的额外插件保留。
# （node 脚本从 stdin 读，参数是「卷里的 package.json」与「镜像里的 package.json」。）
merge_profile_manifest() {
  node - "$PROFILE_PKG" "$BAKED_PROFILE/package.json" <<'NODE'
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
}

# 目录并集：镜像新增/更新的插件与依赖覆盖进卷，用户自己加装的插件不被删。
sync_profile_from_image() {
  mkdir -p "$DSH_HOME/profiles/web/node_modules"
  cp -a "$BAKED_PROFILE/node_modules/." "$DSH_HOME/profiles/web/node_modules/"
  merge_profile_manifest
  cp -f "$BAKED_PROFILE/pnpm-lock.yaml" "$DSH_HOME/profiles/web/pnpm-lock.yaml" 2>/dev/null || true
  cp -f "$BAKED_PROFILE/pnpm-workspace.yaml" "$DSH_HOME/profiles/web/pnpm-workspace.yaml" 2>/dev/null || true
}

# 镜像重建后插件代码会变，而卷里是上一次构建的副本。只补「缺失」不够——
# 升级后容器会一直跑旧插件（2026-10-26 控制台上线踩过）。指纹不同就整体刷新。
if [ -f "$BAKED_STAMP" ] && [ "$(cat "$BAKED_STAMP" 2>/dev/null || true)" != "$(cat "$STAMP" 2>/dev/null || true)" ]; then
  echo "[xdr-agent] image plugins changed: refreshing profile from image"
  sync_profile_from_image
  cp -f "$BAKED_STAMP" "$STAMP"
fi

# 部署级技能：镜像里的技能每次启动覆盖到用户技能根（$DSH_HOME/skills 是
# dsh-skill-filesystem 的 user 根），用户自建的其它技能目录保持不动。
sync_skills() {
  src="/opt/agent/skills"
  [ -d "$src" ] || return 0
  dest="$DSH_HOME/skills"
  mkdir -p "$dest"
  for dir in "$src"/*/; do
    [ -d "$dir" ] || continue
    name="$(basename "$dir")"
    rm -rf "$dest/$name"
    cp -a "$dir" "$dest/$name"
  done
  # 平铺的单文件技能（<name>.md）同样覆盖
  for file in "$src"/*.md; do
    [ -f "$file" ] || continue
    cp -af "$file" "$dest/"
  done
}
sync_skills

# 自愈：卷里有旧 profile 但插件依赖缺失（手工清过 node_modules）时补装。
# 优先从镜像离线合并：卷里 node_modules 记录的 pnpm store 路径来自上一次构建
# （/home/node/.local/share/pnpm/store/v11），新镜像的 pnpm 会改用卷内 store，
# 现场 `plugin add` 直接 ERR_PNPM_UNEXPECTED_STORE 起不来。
install_checked() {
  pkg="$1"; dir="$2"
  if ! grep -q "\"$pkg\"" "$PROFILE_PKG" 2>/dev/null \
    || [ ! -e "$DSH_HOME/profiles/web/node_modules/$pkg/package.json" ]; then
    if [ -e "$BAKED_PROFILE/node_modules/$pkg/package.json" ]; then
      echo "[xdr-agent] $pkg missing from web profile, syncing from image"
      sync_profile_from_image
      cp -f "$BAKED_STAMP" "$STAMP" 2>/dev/null || true
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
