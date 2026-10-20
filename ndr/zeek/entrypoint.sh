#!/usr/bin/env bash
# 深瞳 · Zeek 适配容器入口
#   1) 枚举宿主网卡写入共享文件（供 Web 后台下拉选择）
#   2) 渲染 Site::local_nets 与可扩展脚本加载器
#   3) 启动 Zeek + Filebeat（两者都有存活守护，Filebeat 死了会被重拉）
#   4) 看门狗：网卡配置变化 → 容器内重载 Zeek（不重启容器、不需要 docker socket）
#   5) 本地日志保留 N 天（Zeek 日志框架只做轮转、不做过期删除，故由这里保证；
#      发运方 Filebeat 不在时不删，避免删掉还没上报的归档）
#   6) 提取件清理：只留白名单类型，目录超上限按 mtime 淘汰（批 4）
#   7) 健康哨兵 /tmp/zeek-health：Zeek 起不来/抖动/Filebeat 掉线都写 unhealthy，
#      供 Dockerfile 的 HEALTHCHECK 判定（容器状态能反映真实采集能力）
set -euo pipefail

CONF_DIR="${ZEEK_CONF_DIR:-/config}"
SITE_DIR="${ZEEK_SITE_DIR:-/usr/local/zeek/share/zeek/site}"
LOG_DIR="${ZEEK_LOG_DIR:-/logs}"
IFACE_CONF="${CONF_DIR}/interface.conf"
INTERFACES_JSON="${CONF_DIR}/interfaces.json"
LAST_RELOAD="${CONF_DIR}/last_reload"
PID_FILE="/tmp/zeek.pid"
FILEBEAT_PID_FILE="/tmp/filebeat.pid"
HEALTH_FILE="${ZEEK_HEALTH_FILE:-/tmp/zeek-health}"
ZEEK_RESTART_LOG="/tmp/zeek-restarts"
# 监听网卡：优先 .env 的 ZEEK_IFACE；没给就自动取**第一块物理网卡**（见 auto_iface）。
# 为什么不写死一个网卡名：网卡名属于「客户环境」的东西（ens192 / ens224 / eth0 … 每家不一样），
# 产品代码里放一个具体名字，换台机器就是错的（2026-10 硬编码审计）。
IFACE_ENV="${ZEEK_IFACE:-}"

# 自动挑网卡：只认物理网卡（sysfs 有 device 链接，docker0/veth/br-* 没有），
# 优先 operstate=up 的第一块；都不 up 就回第一块物理网卡；一块都没有则回空串，
# 由 start_zeek 显式报「没有可用网卡」（而不是拿空名字去启动 Zeek）。
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

IFACE_DEFAULT="${IFACE_ENV:-$(auto_iface)}"
# 日志保留期（分钟）：**默认 4 小时**，不对外开放配置（用户口径 2026-10）。
# 为什么按分钟而不是按天：高流量环境一天能写几百 G，按天保留等于必然写满磁盘
# （2026-10 实测：累积到 601G 把根盘 1005G 打满，容器连 exec 都起不来）。
RETENTION_MINUTES="${ZEEK_RETENTION_MINUTES:-240}"
WATCH_INTERVAL="${ZEEK_WATCH_INTERVAL:-10}"
CLEAN_INTERVAL="${ZEEK_CLEAN_INTERVAL:-3600}"
FILEBEAT_CHECK_INTERVAL="${ZEEK_FILEBEAT_CHECK_INTERVAL:-30}"
HEALTH_INTERVAL="${ZEEK_HEALTH_INTERVAL:-30}"
# Zeek 反复启动失败（抖动）判定：窗口秒数 + 窗口内允许的启动次数
ZEEK_FLAP_WINDOW="${ZEEK_FLAP_WINDOW:-300}"
ZEEK_FLAP_MAX="${ZEEK_FLAP_MAX:-5}"
# 提取件（采集批 4）：Zeek 把明文文件落到 EXTRACT_DIR，这里按白名单与容量上限清理。
EXTRACT_DIR="${ZEEK_EXTRACT_DIR:-/extract}"
EXTRACT_CLEAN_INTERVAL="${ZEEK_EXTRACT_CLEAN_INTERVAL:-300}"
EXTRACT_MAX_BYTES="${ZEEK_EXTRACT_MAX_BYTES:-10737418240}"
EXTRACT_MIN_AGE="${ZEEK_EXTRACT_MIN_AGE:-120}"
EXTRACT_MIME_ALLOW="${ZEEK_EXTRACT_MIME_ALLOW:-}"
EXTRACT_HELPER="${ZEEK_EXTRACT_HELPER:-/usr/local/bin/extract_cleanup.py}"
# Filebeat 可执行文件（固定路径，留变量只为可测试/可替换）
FILEBEAT_BIN="${ZEEK_FILEBEAT_BIN:-/usr/local/bin/filebeat}"

# 保留天数必须能参与算术（find -mmin）；环境变量写坏了就回默认，别让清理循环静默死掉
case "$RETENTION_MINUTES" in ''|*[!0-9]*) RETENTION_MINUTES=240 ;; esac
# 兜底硬上限：即使 Filebeat 挂了（清理被跳过），超过 6 倍保留期也必须删 ——
# 否则"不删未上报归档"会变成"永远不删"，直接把磁盘写满（真实事故）。
HARD_CAP_MINUTES=$((RETENTION_MINUTES * 6))

log() { echo "[zeek-entry] $*"; }

# ---------- 1) 枚举网卡 ----------
write_interfaces() {
  local tmp="${INTERFACES_JSON}.tmp" first=1
  echo "[" > "$tmp"
  for dev in /sys/class/net/*; do
    [ -e "$dev" ] || continue
    local name state mtu physical
    name="$(basename "$dev")"
    [ "$name" = "lo" ] && continue
    state="$(cat "$dev/operstate" 2>/dev/null || echo unknown)"
    mtu="$(cat "$dev/mtu" 2>/dev/null || echo 0)"
    # 物理网卡在 sysfs 里有 `device` 链接；docker0 / veth / br-* / tun / dummy 这类虚拟网卡没有。
    # 为什么必须在这里判：只有本容器是 host 网络，能看到宿主机**全部**网卡的 sysfs；
    # 后端容器只能看到自己的 eth0。界面上的「监听网卡」下拉只显示 physical=true 的。
    if [ -e "$dev/device" ]; then physical=true; else physical=false; fi
    if [ "$first" -eq 1 ]; then first=0; else echo "," >> "$tmp"; fi
    printf '{"name":"%s","state":"%s","mtu":%s,"physical":%s}' "$name" "$state" "$mtu" "$physical" >> "$tmp"
  done
  echo "]" >> "$tmp"
  mv "$tmp" "$INTERFACES_JSON"
  log "网卡清单已写入 ${INTERFACES_JSON}"
}

# ---------- 2) 配置读写与脚本渲染 ----------
ensure_iface_conf() {
  if [ ! -f "$IFACE_CONF" ]; then
    # 只预置网卡。网段 / BPF / 正文上限一律由后台 PUT /api/zeek/interface 下发：
    # 曾经的 ZEEK_MONITORED_NETS / ZEEK_BPF_FILTER / ZEEK_LOCAL_NETS / ZEEK_BPF_EXTRA /
    # ZEEK_BODY_MAX_BYTES / ZEEK_RESP_BODY_MAX_BYTES 六个环境变量，两个 compose 都不传、
    # 且只在「文件不存在」时读一次，实际从来不起作用（2026-10 QA），已删除。
    cat > "$IFACE_CONF" <<EOF
# 由深瞳 Web 后台维护；本文件变化会被看门狗检测并重载 Zeek
interface=${IFACE_DEFAULT}
monitored_nets=
bpf_filter=
local_nets=
bpf_extra=
body_max_bytes=16384
resp_body_max_bytes=65536
EOF
    log "已生成默认网卡配置（interface=${IFACE_DEFAULT}）"
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
      # 必须先关掉 Zeek 的「私有地址自动算本地」：base/utils/site.zeek 的
      # update_local_nets_table() 会把 Site::private_address_space（RFC1918 等 42 条）并进
      # local_nets，只 redef local_nets 收窄不掉 —— 2026-10 实测：配 1 条网段后 |Site::local_nets|=43，
      # 于是 10/8、192.168/16 也被判成本地，与后台配置的监控网段口径不一致。
      echo "redef Site::private_address_space_is_local = F;"
      echo ""
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
      echo "# local_nets 为空：沿用 Zeek 默认的网段判定（含私有地址自动算本地）"
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

render_ports() {
  local ports list p
  ports="$(conf_get tls_ports)"
  {
    echo "## 由 entrypoint.sh 自动生成（render_ports），请勿手工修改"
    echo "# 这些端口在本环境是 TLS：不要把 HTTP 解析器挂上去（否则 TLS 字节被当成 HTTP 行，"
    echo "# 刷出 bad_HTTP_request / line_terminated_with_single_CR 这类假协议异常）。"
    echo "@load base/protocols/http"
    echo ""
    list=""
    # 用 read 逐行读取（IFS 仅作用于该次 read，避免全局影响分词）
    while IFS= read -r p; do
      p="$(printf '%s' "$p" | tr -d ' ')"
      [ -z "$p" ] && continue
      # 只接受纯数字（防手改配置写坏脚本 / 注入）
      case "$p" in *[!0-9]*) continue ;; esac
      list="${list}${list:+, }${p}/tcp"
    done < <(printf '%s\n' "$ports" | tr ',' '\n')
    if [ -n "$list" ]; then
      echo "redef HTTP::ports -= { ${list} };"
    else
      echo "# tls_ports 为空：沿用 Zeek 默认的 HTTP 端口表"
    fi
  } > "${SITE_DIR}/shentong-ports.zeek"
  log "HTTP 端口排除脚本已渲染（tls_ports=${ports:-空}）"
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
# Zeek 每次启动都记一笔（供健康哨兵判定「反复启动失败」）
record_zeek_start() {
  date +%s >> "$ZEEK_RESTART_LOG" 2>/dev/null || true
}

start_zeek() {
  local iface bpf
  iface="$(conf_get interface)"; iface="${iface:-$IFACE_DEFAULT}"
  if [ -z "$iface" ]; then
    # 没网卡可用：显式报错 + 哨兵 unhealthy，不拿空名字去启动 Zeek（那会变成无限重启刷日志，
    # 与之前 BPF 被当脚本名导致的重启循环是同一类坑）。上层会 sleep 后重试。
    log "✗ 没有可用的监听网卡：ZEEK_IFACE 未设置，且未探测到任何物理网卡。"
    log "  请在 .env 里设 ZEEK_IFACE=<网卡名>，或到后台「监控网段」选择一块物理网卡。"
    printf 'unhealthy %s 未找到可用网卡（ZEEK_IFACE 未设置）\n' "$(date -u +%FT%TZ)" > "$HEALTH_FILE" 2>/dev/null || true
    return 1
  fi
  bpf="$(conf_get bpf_filter)"

  mkdir -p "$LOG_DIR"
  cd "$LOG_DIR"
  if [ -n "${bpf// /}" ]; then
    log "启动 Zeek：iface=${iface} bpf='${bpf}'"
    # 过滤器必须用 -f 传给 Zeek：直接当位置参数写会被当成脚本文件名，
    # Zeek 启动即报 `fatal error: can't find net <你配的网段>` 并无限重启。
    zeek -C -i "$iface" -f "$bpf" "${SITE_DIR}/local.zeek" &
  else
    # 没有网段 = 按镜像口**全量抓包**（packet_filter.log 记 "ip or not ip"）。这是上线前
    # 最常见的一种「容器正常但采集没配」：日志里显式告警，别只靠人记得去界面下发。
    log "⚠ 未配置监控网段（bpf_filter 为空）：Zeek 将按 ${iface} 全量抓包！"
    log "  请到后台「Zeek 抓包 → 监控网段」下发网段后核对 packet_filter.log 的 filter 字段。"
    zeek -C -i "$iface" "${SITE_DIR}/local.zeek" &
  fi
  ZEEK_PID=$!
  echo "$ZEEK_PID" > "$PID_FILE"
  record_zeek_start
  date -u +%FT%TZ > "$LAST_RELOAD"
}

# Filebeat 存活判定：先用 PID 文件（守护重拉时更新），退回进程名匹配。
# 不依赖 procps 之外的包：pgrep 来自 procps，zeek 基础镜像自带。
filebeat_alive() {
  local pid
  pid="$(cat "$FILEBEAT_PID_FILE" 2>/dev/null || true)"
  if [ -n "$pid" ] && [ -r "/proc/$pid/comm" ] && [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "filebeat" ]; then
    return 0
  fi
  pgrep -x filebeat > /dev/null 2>&1
}

start_filebeat() {
  if [ ! -x "$FILEBEAT_BIN" ]; then
    log "未找到 Filebeat，跳过发运"
    return 0
  fi
  if filebeat_alive; then
    return 0
  fi
  log "启动 Filebeat"
  # 追加而不是截断：守护重拉后，上一次退出前的原因还能在文件尾部看到
  ZEEK_LOG_DIR="$LOG_DIR" "$FILEBEAT_BIN" -e -c /etc/filebeat/filebeat.yml \
    >> /var/log/filebeat.out 2>&1 &
  echo $! > "$FILEBEAT_PID_FILE"
}

# Filebeat 守护：2026-10 QA 的发现是「只在启动时拉起一次，死了没人管」，而日志清理照常
# 按天删档 → 未上报的事件被删掉。这里每 ZEEK_FILEBEAT_CHECK_INTERVAL 秒确认一次存活。
start_filebeat_supervisor() {
  (
    while true; do
      sleep "$FILEBEAT_CHECK_INTERVAL"
      if [ -x "$FILEBEAT_BIN" ] && ! filebeat_alive; then
        log "检测到 Filebeat 已退出，重新拉起（守护循环）"
        start_filebeat
      fi
    done
  ) &
  log "Filebeat 守护循环已启动（每 ${FILEBEAT_CHECK_INTERVAL}s 检查）"
}

# ---------- 4) 本地日志保留（只清已轮转文件，不动正在写的活动日志）----------
cleanup_once() {
  # 发运方不在时**不删**：删掉还没上报的归档就是永久丢数据（Filebeat 死了没人拉起的年代踩过）。
  if [ -x "$FILEBEAT_BIN" ] && ! filebeat_alive; then
    log "Filebeat 未在运行，跳过本轮日志清理（避免删掉还没上报的归档）"
    return 0
  fi
  # 轮转命名由 Log::default_rotation_date_format 决定，当前是「<name>.<YYYY-MM-DD-HH-MM-SS>.log」，
  # 与活动日志**同在 /logs 顶层平铺**（实测没有日期子目录）。历史上用过只到天的
  # 「<name>.<YYYY-MM-DD>.log」，两种模式都匹配，老归档也能被清掉。
  # 子目录布局（历史/其它部署可能出现）也只清「轮转命名」的文件，不做无差别 -delete。
  # 用 -mmin 而不是 -mtime：-mtime +3 实际会把文件留到第 4 天以上，与「保留 3 天」的
  # 对外说法不符；-mmin +4320 才是字面的「超过 3 天就删」。
  local age_min="$RETENTION_MINUTES"
  local name_args=(-name "*.????-??-??-??-??-??.log" -o -name "*.????-??-??.log")
  find "$LOG_DIR" -xdev -maxdepth 1 -type f \( "${name_args[@]}" \) -mmin "+${age_min}" -delete 2>/dev/null || true
  find "$LOG_DIR" -xdev -mindepth 2 -type f \( "${name_args[@]}" \) -mmin "+${age_min}" -delete 2>/dev/null || true
}

# 兜底清理：不看 Filebeat 是否存活，只按时间硬删（超过 6 倍保留期）。
cleanup_hard_cap() {
  local name_args=(-name "*.????-??-??-??-??-??.log" -o -name "*.????-??-??.log")
  find "$LOG_DIR" -xdev -maxdepth 1 -type f \( "${name_args[@]}" \) -mmin "+${HARD_CAP_MINUTES}" -delete 2>/dev/null || true
  find "$LOG_DIR" -xdev -mindepth 2 -type f \( "${name_args[@]}" \) -mmin "+${HARD_CAP_MINUTES}" -delete 2>/dev/null || true
}

start_cleanup_loop() {
  (
    cleanup_once
    while true; do
      sleep "$CLEAN_INTERVAL"
      cleanup_once
      # 不管 Filebeat 是否存活，超硬上限一律删（防"跳过清理"变成"永不清理"）
      cleanup_hard_cap
    done
  ) &
  log "清理循环已启动（保留 ${RETENTION_MINUTES} 分钟；超 $((HARD_CAP_MINUTES / 60)) 小时强制删除）"
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

# ---------- 6) 健康哨兵（供 Dockerfile HEALTHCHECK 读取）----------
# 为什么需要：Zeek 起不来时主循环只是每 2 秒重拉、容器永远 Up；Filebeat 死了同样没人发现。
# 哨兵把「Zeek 进程在不在 + 是否在抖动 + 发运方在不在」写成一行文本，容器健康状态才反映
# 真实采集能力。健康检查只上报，**不触发 docker 重启**（compose 的 restart 策略不看健康状态），
# 所以不会和无限重启互相打架。
restart_count_window() {
  [ -f "$ZEEK_RESTART_LOG" ] || { echo 0; return 0; }
  local cutoff n
  cutoff=$(( $(date +%s) - ZEEK_FLAP_WINDOW ))
  # 顺手修剪窗口外的时间戳，避免文件无限增长
  awk -v c="$cutoff" '$1 + 0 >= c' "$ZEEK_RESTART_LOG" > "${ZEEK_RESTART_LOG}.tmp" 2>/dev/null || true
  mv "${ZEEK_RESTART_LOG}.tmp" "$ZEEK_RESTART_LOG" 2>/dev/null || true
  n="$(wc -l < "$ZEEK_RESTART_LOG" 2>/dev/null || echo 0)"
  echo "${n// /}"
}

# Zeek 存活判定：PID 文件 + /proc/<pid>/comm（只看 PID 会被 PID 复用骗过）
zeek_alive() {
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [ -n "$pid" ] && [ -r "/proc/$pid/comm" ] && [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "zeek" ]
}

health_snapshot() {
  local ok=1 why="" pid flaps
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if ! zeek_alive; then
    ok=0; why="zeek 进程不在"
  fi
  flaps="$(restart_count_window)"
  if [ "$ok" = 1 ] && [ "$flaps" -gt "$ZEEK_FLAP_MAX" ]; then
    ok=0; why="Zeek 在 ${ZEEK_FLAP_WINDOW}s 内启动 ${flaps} 次（起不来或刚到就退）"
  fi
  if [ "$ok" = 1 ] && [ -x "$FILEBEAT_BIN" ] && ! filebeat_alive; then
    ok=0; why="filebeat 进程不在"
  fi
  if [ "$ok" = 1 ]; then
    printf 'ok %s zeek_pid=%s flaps=%s\n' "$(date -u +%FT%TZ)" "$pid" "$flaps"
  else
    printf 'unhealthy %s %s\n' "$(date -u +%FT%TZ)" "$why"
  fi
}

start_health_loop() {
  (
    while true; do
      health_snapshot > "${HEALTH_FILE}.tmp" 2>/dev/null || true
      mv "${HEALTH_FILE}.tmp" "$HEALTH_FILE" 2>/dev/null || true
      sleep "$HEALTH_INTERVAL"
    done
  ) &
  log "健康哨兵循环已启动（每 ${HEALTH_INTERVAL}s 写 ${HEALTH_FILE}）"
}

# ---------- 7) 看门狗 ----------
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
      render_ports
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
  render_ports
  render_scripts_loader
  start_filebeat
  start_filebeat_supervisor
  start_cleanup_loop
  start_extract_cleanup_loop
  start_health_loop
  start_watchdog

  # 保持 Zeek 存活；配置变化时看门狗会杀进程，这里自动拉起。
  # Zeek 一退出就把哨兵写成 unhealthy，健康检查不用等循环下一拍。
  while true; do
    if ! start_zeek; then
      sleep 30
      continue
    fi
    wait "$ZEEK_PID" 2>/dev/null || true
    printf 'unhealthy %s zeek 已退出，等待重拉\n' "$(date -u +%FT%TZ)" > "$HEALTH_FILE" 2>/dev/null || true
    log "Zeek 已退出，2 秒后重新拉起"
    sleep 2
  done
}

main
