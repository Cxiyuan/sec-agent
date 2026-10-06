#!/usr/bin/env bash
# 深瞳 · 签名引擎（Suricata）容器入口
#   1) 读**共享**采集配置 /config/interface.conf（界面「监控网段」页维护，网络采集器用同一份）
#   2) 渲染 /etc/suricata/suricata.yaml：HOME_NET=监控网段、抓包网卡、明文 HTTP 端口
#   3) 守护：Suricata 退出即重拉；配置变化 → 重渲染 + 重启（只有重启才让网卡/HOME_NET 生效）
#   4) eve.json 按天/按大小轮转进 archive/，归档留 N 天（Suricata 自己不做日志过期）
#   5) 健康哨兵 /tmp/shentong-suricata-health（Dockerfile 的 HEALTHCHECK 读它）
#
# 为什么配置只读共享文件、不在界面再加一组字段：网卡与监控网段是**同一件事**（同一个镜像口、
# 同一批要看的网段），两处配置必然漂移；共用一份还能保证「HOME_NET 和我们自己的网段过滤口径」
# 完全一致（采集范围错了，两边一起错，运维一眼能看出来）。
set -euo pipefail

CONF_DIR="${SURICATA_CONF_DIR:-/config}"
LOG_DIR="${SURICATA_LOG_DIR:-/logs}"
OUT_DIR="${LOG_DIR}/suricata"
ARCHIVE_DIR="${OUT_DIR}/archive"
IFACE_CONF="${CONF_DIR}/interface.conf"
TEMPLATE="${SURICATA_TEMPLATE:-/usr/local/share/shentong/suricata.yaml.tmpl}"
YAML_OUT="${SURICATA_YAML:-/etc/suricata/suricata.yaml}"
PID_FILE="/tmp/suricata.pid"
HEALTH_FILE="${SURICATA_HEALTH_FILE:-/tmp/shentong-suricata-health}"

# 抓包网卡：优先 .env 的 SURICATA_IFACE；没给就取共享配置里的 interface；再没有就自动挑物理网卡
IFACE_ENV="${SURICATA_IFACE:-}"
WATCH_INTERVAL="${SURICATA_WATCH_INTERVAL:-10}"
HEALTH_INTERVAL="${SURICATA_HEALTH_INTERVAL:-30}"
ROTATE_INTERVAL="${SURICATA_ROTATE_INTERVAL:-300}"
ROTATE_MAX_BYTES="${SURICATA_ROTATE_MAX_BYTES:-67108864}"
ROTATE_MAX_AGE="${SURICATA_ROTATE_MAX_AGE:-86400}"
RETENTION_DAYS="${SURICATA_RETENTION_DAYS:-3}"

# Zeek 的 HTTP::ports 默认集（**引擎默认值**，不是客户环境的东西）：
# 明文 HTTP 端口 = 这一集 - 共享配置里声明「按 TLS 解析」的端口（tls_ports）
HTTP_PORT_BASE="80,81,88,8000,8008,8010,8011,8048,8080,8088,8888"

case "$RETENTION_DAYS" in ''|*[!0-9]*) RETENTION_DAYS=3 ;; esac

log() { echo "[suricata-entry] $*"; }

# 自动挑网卡：只认物理网卡（sysfs 有 device 链接，docker0/veth/br-* 没有），
# 优先 operstate=up 的第一块（口径与 Zeek 容器一致，见 ndr/zeek/entrypoint.sh）。
auto_iface() {
  local dev name state fallback=""
  for dev in /sys/class/net/*; do
    [ -e "$dev/device" ] || continue
    name="$(basename "$dev")"
    [ "$name" = "lo" ] && continue
    state="$(cat "$dev/operstate" 2>/dev/null || echo unknown)"
    if [ "$state" = "up" ]; then
      echo "$name"
      return 0
    fi
    [ -n "$fallback" ] || fallback="$name"
  done
  echo "$fallback"
}

conf_get() {
  grep -E "^$1=" "$IFACE_CONF" 2>/dev/null | head -1 | cut -d= -f2- || true
}

resolved_iface() {
  if [ -n "$IFACE_ENV" ]; then
    echo "$IFACE_ENV"
    return
  fi
  local from_conf
  from_conf="$(conf_get interface)"
  if [ -n "${from_conf// /}" ]; then
    echo "${from_conf// /}"
    return
  fi
  auto_iface
}

# 监控网段 → YAML 列表。没配网段时用**通用私网**兜底（不是某个客户的值）：
# HOME_NET 为空会让 `EXTERNAL_NET: !$HOME_NET` 变成「全是外部」，方向类签名会全量误报。
home_net() {
  local nets
  nets="$(conf_get monitored_nets)"
  nets="${nets// /}"
  if [ -z "$nets" ]; then
    log "警告：共享配置里没有监控网段，HOME_NET 回落到通用私网段（请在界面「监控网段」页配置）"
    echo "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    return
  fi
  printf '[%s]' "$nets"
}

# 明文 HTTP 端口 = 引擎默认集 - 按 TLS 解析的端口
http_ports() {
  local tls out="" p
  tls=",$(conf_get tls_ports),"
  tls="${tls// /}"
  local IFS=','
  for p in $HTTP_PORT_BASE; do
    case "$tls" in *",$p,"*) continue ;; esac
    [ -z "$out" ] && out="$p" || out="$out,$p"
  done
  echo "$out"
}

# 镜像里**没有 cmp**（实测 MISSING cmp），用 sha256 比：先比大小（不同即定），再比哈希。
same_file() {
  [ -f "$1" ] || return 1
  [ -f "$2" ] || return 1
  [ "$(wc -c < "$1")" = "$(wc -c < "$2")" ] || return 1
  [ "$(sha256sum < "$1" | cut -d' ' -f1)" = "$(sha256sum < "$2" | cut -d' ' -f1)" ]
}


# 把镜像里的规则/分类同步到运行目录。
#
# 为什么需要：基础镜像把 /var/lib/suricata 与 /etc/suricata 声明成了 **VOLUME**，
# Docker 会为它们建匿名卷、并在容器重建时**保留**（即使镜像换了）—— 于是「升级镜像」
# 后容器里仍然是上一版的规则文件（实机踩到：镜像内 69028 行，容器里还是旧的 69096 行，
# 被裁掉的引擎流异常照旧刷）。这里每次启动都以镜像里的副本为准同步一次，幂等且便宜。
sync_rules() {
  local dst_dir=/var/lib/suricata/rules
  local src=/usr/local/share/shentong/suricata.rules
  mkdir -p "$dst_dir" /etc/suricata
  if ! same_file "$src" "${dst_dir}/suricata.rules"; then
    cp -f "$src" "${dst_dir}/suricata.rules"
    log "签名规则已同步到运行目录（$(wc -l < "${dst_dir}/suricata.rules" | tr -d ' ') 行）"
  fi
  # 分类/引用文件同理（匿名卷里可能是上一版镜像的）
  local f
  for f in classification.config reference.config; do
    if ! same_file "/usr/local/share/shentong/${f}" "/etc/suricata/${f}"; then
      cp -f "/usr/local/share/shentong/${f}" "/etc/suricata/${f}"
    fi
  done
}


render_config() {
  local iface nets ports
  iface="$(resolved_iface)"
  nets="$(home_net)"
  ports="$(http_ports)"
  if [ ! -f "$TEMPLATE" ]; then
    log "配置模板不存在：$TEMPLATE"
    return 1
  fi
  # 用 | 当分隔符：网段里有 /（CIDR），用 / 会切错
  sed -e "s|%IFACE%|${iface}|g" -e "s|%HOME_NET%|${nets}|g" -e "s|%HTTP_PORTS%|${ports}|g" \
    "$TEMPLATE" > "${YAML_OUT}.tmp"
  mv "${YAML_OUT}.tmp" "$YAML_OUT"
  log "配置已渲染：网卡=${iface:-无} 网段=${nets} HTTP端口=${ports}"
}

start_suricata() {
  local iface
  iface="$(resolved_iface)"
  if [ -z "$iface" ]; then
    log "没有可用网卡（共享配置为空且自动探测失败）：等待下一拍重试"
    return 1
  fi
  log "启动 Suricata：网卡=${iface}"
  suricata -c "$YAML_OUT" --af-packet="$iface" >/dev/null 2>&1 &
  SURICATA_PID=$!
  echo "$SURICATA_PID" > "$PID_FILE"
  # 给 3 秒确认没有立刻退出（规则加载失败/网卡不可用会立刻退，直接把原因写进哨兵）
  sleep 3
  if ! kill -0 "$SURICATA_PID" 2>/dev/null; then
    printf 'unhealthy %s Suricata 启动即退出（看容器日志 / suricata -T 自检）\n' \
      "$(date -u +%FT%TZ)" > "$HEALTH_FILE"
    return 1
  fi
  printf 'healthy %s iface=%s\n' "$(date -u +%FT%TZ)" "$iface" > "$HEALTH_FILE" 2>/dev/null || true
  return 0
}

# ---------- eve.json 轮转与归档清理 ----------
# Suricata 自己不删日志：一个 eve.json 会一直长。这里按「超过 N 字节」或「超过 24h」把它
# 改名进 archive/，然后重启 Suricata 让它新开一个 eve.json（重启只丢一两秒抓包，代价可接受）。
# 归档目录不放采集通配范围内（Filebeat 只扫 /logs/suricata/*.json），已读过的内容不会被重读。
rotate_once() {
  local now size age newest
  local eve="${OUT_DIR}/eve.json"
  [ -f "$eve" ] || return 0
  now="$(date +%s)"
  size="$(stat -c %s "$eve" 2>/dev/null || echo 0)"
  newest="$(stat -c %Y "$eve" 2>/dev/null || echo "$now")"
  age=$(( now - newest ))
  if [ "$size" -lt "$ROTATE_MAX_BYTES" ] && [ "$age" -lt "$ROTATE_MAX_AGE" ]; then
    return 0
  fi
  mkdir -p "$ARCHIVE_DIR"
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if mv "$eve" "${ARCHIVE_DIR}/eve.${stamp}.json" 2>/dev/null; then
    log "eve.json 已归档（size=${size} age=${age}s）→ archive/eve.${stamp}.json，重启 Suricata"
    if [ -f "$PID_FILE" ]; then
      kill "$(cat "$PID_FILE")" 2>/dev/null || true
    fi
  fi
}

start_rotate_loop() {
  (
    while true; do
      sleep "$ROTATE_INTERVAL"
      rotate_once || true
      # 归档过期清理（只清我们自己的 archive/，不碰 Zeek 的日志）
      find "$ARCHIVE_DIR" -type f -name 'eve.*.json' -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
    done
  ) &
  log "轮转循环已启动（每 ${ROTATE_INTERVAL}s 检查，归档保留 ${RETENTION_DAYS} 天）"
}

# ---------- 健康哨兵 ----------
start_health_loop() {
  (
    while true; do
      sleep "$HEALTH_INTERVAL"
      if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        printf 'healthy %s iface=%s\n' "$(date -u +%FT%TZ)" "$(resolved_iface)" > "$HEALTH_FILE" 2>/dev/null || true
        write_status 0
      else
        printf 'unhealthy %s Suricata 未在运行\n' "$(date -u +%FT%TZ)" > "$HEALTH_FILE" 2>/dev/null || true
        write_status 1
      fi
    done
  ) &
}

# 给后端看的机器可读状态：入口挂在**共享日志卷**里（后端只读挂载同一卷），
# 这样界面不用去问容器（产品里没有 docker socket），也能知道签名引擎到底在不在跑。
write_status() {
  local alive="$1" rules="" version=""
  if [ -s /var/lib/suricata/rules/suricata.rules ]; then
    rules="$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null | tr -d ' ')"
  fi
  version="$(suricata -V 2>/dev/null | head -1 || true)"
  cat > "${OUT_DIR}/status.json.tmp" <<EOF
{"alive": $( [ "$alive" = "0" ] && echo true || echo false ),
 "updated_at": "$(date -u +%FT%TZ)",
 "iface": "$(resolved_iface)",
 "home_net": "$(home_net | tr -d '\n')",
 "http_ports": "$(http_ports)",
 "rule_lines": ${rules:-0},
 "version": "${version}"}
EOF
  mv "${OUT_DIR}/status.json.tmp" "${OUT_DIR}/status.json" 2>/dev/null || true
}

# ---------- 配置看门狗 ----------
start_watchdog() {
  (
    local last cur
    last="$(sha256sum "$IFACE_CONF" 2>/dev/null | awk '{print $1}')"
    while true; do
      sleep "$WATCH_INTERVAL"
      cur="$(sha256sum "$IFACE_CONF" 2>/dev/null | awk '{print $1}')"
      [ "$cur" = "$last" ] && continue
      last="$cur"
      log "检测到采集配置变化，重渲染配置并重启 Suricata"
      render_config || true
      if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
      fi
    done
  ) &
  log "看门狗已启动（每 ${WATCH_INTERVAL}s 检查共享配置）"
}

main() {
  mkdir -p "$OUT_DIR" "$ARCHIVE_DIR" /etc/suricata
  sync_rules
  if [ ! -f "$IFACE_CONF" ]; then
    log "共享采集配置不存在（$IFACE_CONF）：先用默认值渲染，等后端写入后看门狗会自动重载"
  fi
  render_config || true
  start_rotate_loop
  start_health_loop
  write_status 1
  start_watchdog

  while true; do
    if ! start_suricata; then
      sleep 30
      continue
    fi
    wait "$SURICATA_PID" 2>/dev/null || true
    printf 'unhealthy %s Suricata 已退出，等待重拉\n' "$(date -u +%FT%TZ)" > "$HEALTH_FILE" 2>/dev/null || true
    log "Suricata 已退出，2 秒后重新拉起"
    sleep 2
  done
}

# CI / 排障用的自检模式：只渲染配置并跑 `suricata -T`（自检配置与规则），不抓包。
# 退出码就是结果 —— 配置模板与容器版本不兼容时，这一步会先把问题暴露出来
# （CI 入口：tests/suricata/run.sh）。
if [ "${1:-}" = "--render-only" ]; then
  mkdir -p "$OUT_DIR" "$ARCHIVE_DIR" /etc/suricata
  sync_rules
  render_config
  exec suricata -T -c "$YAML_OUT"
fi

# 只渲染并把渲染结果打到 stdout（不做 `suricata -T` 那趟昂贵自检）：
# CI 靠它断言渲染结果（网卡/HOME_NET/HTTP 端口/只开 alert/community-id）。
if [ "${1:-}" = "--render-config" ]; then
  mkdir -p "$OUT_DIR" "$ARCHIVE_DIR" /etc/suricata
  sync_rules
  render_config
  cat "$YAML_OUT"
  exit 0
fi

# 注意：本镜像的 ENTRYPOINT 就是这个脚本 —— 要进容器里敲 shell 得写 `--entrypoint sh`，
# 否则参数会被当成脚本参数走到下面的抓包主循环（会一直不退出）。
main
