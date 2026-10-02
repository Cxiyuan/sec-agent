#!/usr/bin/env bash
# 深瞳 · Zeek 适配容器入口
#   1) 枚举宿主网卡写入共享文件（供 Web 后台下拉选择）
#   2) 渲染 Site::local_nets 与可扩展脚本加载器
#   3) 启动 Zeek + Filebeat
#   4) 看门狗：网卡配置变化 → 容器内重载 Zeek（不重启容器、不需要 docker socket）
#   5) 本地日志只保留 3 天（Zeek 日志框架只做轮转、不做过期删除，故由这里保证）
#   6) 提取件清理：只留白名单类型，目录超上限按 mtime 淘汰（批 4）
set -euo pipefail

CONF_DIR="${ZEEK_CONF_DIR:-/config}"
SITE_DIR="${ZEEK_SITE_DIR:-/usr/local/zeek/share/zeek/site}"
LOG_DIR="${ZEEK_LOG_DIR:-/logs}"
IFACE_CONF="${CONF_DIR}/interface.conf"
INTERFACES_JSON="${CONF_DIR}/interfaces.json"
LAST_RELOAD="${CONF_DIR}/last_reload"
PID_FILE="/tmp/zeek.pid"
RETENTION_DAYS="${ZEEK_RETENTION_DAYS:-3}"
WATCH_INTERVAL="${ZEEK_WATCH_INTERVAL:-10}"
CLEAN_INTERVAL="${ZEEK_CLEAN_INTERVAL:-3600}"
# 提取件（采集批 4）：Zeek 把明文文件落到 EXTRACT_DIR，这里按白名单与容量上限清理。
EXTRACT_DIR="${ZEEK_EXTRACT_DIR:-/extract}"
EXTRACT_CLEAN_INTERVAL="${ZEEK_EXTRACT_CLEAN_INTERVAL:-300}"
EXTRACT_MAX_BYTES="${ZEEK_EXTRACT_MAX_BYTES:-10737418240}"
EXTRACT_MIN_AGE="${ZEEK_EXTRACT_MIN_AGE:-120}"
EXTRACT_MIME_ALLOW="${ZEEK_EXTRACT_MIME_ALLOW:-}"
EXTRACT_HELPER="${ZEEK_EXTRACT_HELPER:-/usr/local/bin/extract_cleanup.py}"

log() { echo "[zeek-entry] $*"; }

# ---------- 1) 枚举网卡 ----------
write_interfaces() {
  local tmp="${INTERFACES_JSON}.tmp" first=1
  echo "[" > "$tmp"
  for dev in /sys/class/net/*; do
    [ -e "$dev" ] || continue
    local name state mtu
    name="$(basename "$dev")"
    [ "$name" = "lo" ] && continue
    state="$(cat "$dev/operstate" 2>/dev/null || echo unknown)"
    mtu="$(cat "$dev/mtu" 2>/dev/null || echo 0)"
    if [ "$first" -eq 1 ]; then first=0; else echo "," >> "$tmp"; fi
    printf '{"name":"%s","state":"%s","mtu":%s}' "$name" "$state" "$mtu" >> "$tmp"
  done
  echo "]" >> "$tmp"
  mv "$tmp" "$INTERFACES_JSON"
  log "网卡清单已写入 ${INTERFACES_JSON}"
}

# ---------- 2) 配置读写与脚本渲染 ----------
ensure_iface_conf() {
  if [ ! -f "$IFACE_CONF" ]; then
    cat > "$IFACE_CONF" <<EOF
# 由深瞳 Web 后台维护；本文件变化会被看门狗检测并重载 Zeek
interface=${ZEEK_IFACE:-eth0}
monitored_nets=${ZEEK_MONITORED_NETS:-}
bpf_filter=${ZEEK_BPF_FILTER:-}
local_nets=${ZEEK_LOCAL_NETS:-}
bpf_extra=${ZEEK_BPF_EXTRA:-}
body_max_bytes=${ZEEK_BODY_MAX_BYTES:-16384}
resp_body_max_bytes=${ZEEK_RESP_BODY_MAX_BYTES:-65536}
EOF
    log "已生成默认网卡配置（interface=${ZEEK_IFACE:-eth0}）"
  fi
}

conf_get() {
  grep -E "^$1=" "$IFACE_CONF" 2>/dev/null | head -1 | cut -d= -f2- || true
}

render_nets() {
  local nets
  nets="$(conf_get local_nets)"
  {
    echo "## 由 start.sh 自动生成，请勿手工修改"
    echo "module Site;"
    echo ""
    if [ -n "${nets// /}" ]; then
      echo "redef Site::local_nets = {"
      local n
      # 用 read 逐行读取（IFS 仅作用于该次 read，避免全局影响分词）
      while IFS= read -r n; do
        n="${n// /}"
        [ -z "$n" ] && continue
        echo "    ${n},"
      done < <(printf '%s\n' "$nets" | tr ',' '\n')
      echo "};"
    else
      echo "# local_nets 为空：沿用 Zeek 默认的网段判定"
    fi
  } > "${SITE_DIR}/shentong-nets.zeek"
  log "网段脚本已渲染（local_nets=${nets:-空}）"
}

render_limits() {
  local body resp
  body="$(conf_get body_max_bytes)"; resp="$(conf_get resp_body_max_bytes)"
  # 只接受纯数字（防手改配置写坏脚本 / 注入）；缺失或非法都回落到默认值
  case "$body" in ''|*[!0-9]*) body=16384;; esac
  case "$resp" in ''|*[!0-9]*) resp=65536;; esac
  {
    echo "## 由 entrypoint.sh 自动生成（render_limits），请勿手工修改"
    echo "redef ShentongHTTP::max_body_len = ${body};"
    echo "redef ShentongHTTP::max_resp_body_len = ${resp};"
  } > "${SITE_DIR}/shentong-limits.zeek"
  log "正文上限脚本已渲染（请求 ${body} 字节 / 响应 ${resp} 字节）"
}

render_scripts_loader() {
  {
    echo "## 由 start.sh 自动生成：加载可扩展目录 scripts.d 下的所有脚本"
    local found=0
    for f in "${SITE_DIR}"/scripts.d/*.zeek; do
      [ -e "$f" ] || continue
      echo "@load ./scripts.d/$(basename "$f")"
      found=1
    done
    [ "$found" -eq 0 ] && echo "# scripts.d 为空"
  } > "${SITE_DIR}/shentong-scripts-d.zeek"
  log "可扩展脚本加载器已生成"
}

# ---------- 3) Zeek 与 Filebeat ----------
start_zeek() {
  local iface bpf
  iface="$(conf_get interface)"; iface="${iface:-eth0}"
  bpf="$(conf_get bpf_filter)"

  mkdir -p "$LOG_DIR"
  cd "$LOG_DIR"
  if [ -n "${bpf// /}" ]; then
    log "启动 Zeek：iface=${iface} bpf='${bpf}'"
    # 过滤器必须用 -f 传给 Zeek：直接当位置参数写会被当成脚本文件名，
    # Zeek 启动即报 `fatal error: can't find net 172.16.196.0/24` 并无限重启。
    zeek -C -i "$iface" -f "$bpf" "${SITE_DIR}/local.zeek" &
  else
    log "启动 Zeek：iface=${iface}"
    zeek -C -i "$iface" "${SITE_DIR}/local.zeek" &
  fi
  ZEEK_PID=$!
  echo "$ZEEK_PID" > "$PID_FILE"
  date -u +%FT%TZ > "$LAST_RELOAD"
}

start_filebeat() {
  if [ -x /usr/local/bin/filebeat ]; then
    log "启动 Filebeat"
    ZEEK_LOG_DIR="$LOG_DIR" /usr/local/bin/filebeat -e -c /etc/filebeat/filebeat.yml \
      > /var/log/filebeat.out 2>&1 &
  else
    log "未找到 Filebeat，跳过发运"
  fi
}

# ---------- 4) 保留 3 天（只清已轮转文件，不动正在写的活动日志）----------
cleanup_once() {
  # 轮转命名由 Log::default_rotation_date_format 决定，当前是「<name>.<YYYY-MM-DD>.log」
  # 放在**顶层**（不是日期子目录）。原来只按 mindepth 2 找子目录 → 永远清不掉，
  # /logs 会无限增长（生产上一天涨到 1.3G，并导致 Filebeat 重读洪水）。
  # 两种布局都清，避免任一种漏掉；只删已轮转文件，活动日志（*.log）不动。
  find "$LOG_DIR" -xdev -mindepth 2 -type f -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
  find "$LOG_DIR" -xdev -maxdepth 1 -type f -name "*.????-??-??.log" -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
}

start_cleanup_loop() {
  (
    cleanup_once
    while true; do
      sleep "$CLEAN_INTERVAL"
      cleanup_once
    done
  ) &
  log "清理循环已启动（保留 ${RETENTION_DAYS} 天）"
}

# ---------- 5) 提取件清理（批 4）----------
# Zeek 侧只负责落盘（site/shentong-file-extract.zeek），判定与删除在这里做：Zeek 脚本没有
# 删文件的 BIF。助手读 files.log 的 mime_type，删掉「没有记录 / 不在白名单」的提取件，
# 再把目录按容量上限从最老开始淘汰。
extract_cleanup_once() {
  [ -d "$EXTRACT_DIR" ] || return 0
  if ! command -v python3 > /dev/null 2>&1; then
    log "未找到 python3，跳过提取件清理"
    return 0
  fi
  if [ ! -f "$EXTRACT_HELPER" ]; then
    log "未找到提取件清理助手 ${EXTRACT_HELPER}，跳过"
    return 0
  fi
  local args=(--dir "$EXTRACT_DIR" --logs "$LOG_DIR" --max-bytes "$EXTRACT_MAX_BYTES" --min-age "$EXTRACT_MIN_AGE")
  if [ -n "$EXTRACT_MIME_ALLOW" ]; then
    args+=(--mime-allow "$EXTRACT_MIME_ALLOW")
  fi
  python3 "$EXTRACT_HELPER" "${args[@]}" || log "提取件清理异常（已忽略，下一轮重试）"
}

start_extract_cleanup_loop() {
  (
    extract_cleanup_once
    while true; do
      sleep "$EXTRACT_CLEAN_INTERVAL"
      extract_cleanup_once
    done
  ) &
  log "提取件清理循环已启动（目录 ${EXTRACT_DIR}，每 ${EXTRACT_CLEAN_INTERVAL}s，上限 ${EXTRACT_MAX_BYTES} 字节）"
}

# ---------- 6) 看门狗 ----------
start_watchdog() {
  (
    local last
    last="$(sha256sum "$IFACE_CONF" | awk '{print $1}')"
    while true; do
      sleep "$WATCH_INTERVAL"
      local cur
      cur="$(sha256sum "$IFACE_CONF" | awk '{print $1}')"
      [ "$cur" = "$last" ] && continue
      last="$cur"
      log "检测到采集配置变化，重载 Zeek"
      render_nets
      render_limits
      if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
      fi
    done
  ) &
  log "看门狗已启动（每 ${WATCH_INTERVAL}s 检查配置）"
}

# ---------- 主流程 ----------
main() {
  mkdir -p "$CONF_DIR" "$LOG_DIR" "$EXTRACT_DIR" "${SITE_DIR}/scripts.d"
  write_interfaces
  ensure_iface_conf
  render_nets
  render_limits
  render_scripts_loader
  start_filebeat
  start_cleanup_loop
  start_extract_cleanup_loop
  start_watchdog

  # 保持 Zeek 存活；配置变化时看门狗会杀进程，这里自动拉起
  while true; do
    start_zeek
    wait "$ZEEK_PID" 2>/dev/null || true
    log "Zeek 已退出，2 秒后重新拉起"
    sleep 2
  done
}

main
