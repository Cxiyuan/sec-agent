#!/usr/bin/env bash
# 深瞳 · 签名引擎（Suricata）容器入口
#   1) 读**共享**采集配置 /config/interface.conf（界面「监控网段」页维护，网络采集器用同一份）
#   2) 规则：/rules/active/*.rules 是生效规则（初始只有镜像带的空占位文件）；
#      支持后端下发的三个请求标记（后端不碰 docker socket，只写共享卷）：
#        validate.request  → 对 /rules/staging 跑 `suricata -T` 并写校验结果
#        activate.request  → 复校验 staging，通过则切到 active 并重载规则
#        reset.request     → 清空规则（回到空占位）
#   3) 渲染 /etc/suricata/suricata.yaml：网卡 / HOME_NET / 明文 HTTP 端口 / 规则文件列表
#   4) 守护 Suricata；配置或规则变化 → `suricatasc reload-rules`（不可用则重启，主循环重拉）
#   5) eve.json 按天/按大小轮转进 archive/（Suricata 自己不做日志过期）
#   6) 健康哨兵 /tmp/shentong-suricata-health + 机器可读状态 /rules/runtime.json（给后端/界面读）
#
# 为什么规则放 /rules 这个独立卷、而不是镜像基础里的 /var/lib/suricata：
# 基础镜像把 /var/lib/suricata（和 /etc/suricata）声明成了 VOLUME，Docker 的匿名卷在容器重建时
# **被保留** —— 升级镜像后容器里读到的还是上一版规则（实机踩过）。/rules 是我们自己的命名卷，
# 规则内容只在「校验通过 + 人工确认」后由本入口切换，行为完全可预期。
set -euo pipefail

CONF_DIR="${SURICATA_CONF_DIR:-/config}"
LOG_DIR="${SURICATA_LOG_DIR:-/logs}"
RULES_DIR="${SURICATA_RULES_DIR:-/rules}"
OUT_DIR="${LOG_DIR}/suricata"
ARCHIVE_DIR="${OUT_DIR}/archive"
IFACE_CONF="${CONF_DIR}/interface.conf"
TEMPLATE="${SURICATA_TEMPLATE:-/usr/local/share/shentong/suricata.yaml.tmpl}"
YAML_OUT="${SURICATA_YAML:-/etc/suricata/suricata.yaml}"
YAML_STAGING="/tmp/suricata-staging.yaml"
PLACEHOLDER_DIR="${SURICATA_PLACEHOLDER_DIR:-/usr/local/share/shentong/rules}"
PID_FILE="/tmp/suricata.pid"
HEALTH_FILE="${SURICATA_HEALTH_FILE:-/tmp/shentong-suricata-health}"

ACTIVE_DIR="${RULES_DIR}/active"
STAGING_DIR="${RULES_DIR}/staging"
PREVIOUS_DIR="${RULES_DIR}/previous"
REJECTED_DIR="${RULES_DIR}/rejected"
RUNTIME_JSON="${RULES_DIR}/runtime.json"
VALIDATION_JSON="${RULES_DIR}/validation.json"
VALIDATE_REQ="${RULES_DIR}/validate.request"
ACTIVATE_REQ="${RULES_DIR}/activate.request"
RESET_REQ="${RULES_DIR}/reset.request"
KEEP_REJECTED=5

IFACE_ENV="${SURICATA_IFACE:-}"
WATCH_INTERVAL="${SURICATA_WATCH_INTERVAL:-10}"
HEALTH_INTERVAL="${SURICATA_HEALTH_INTERVAL:-30}"
ROTATE_INTERVAL="${SURICATA_ROTATE_INTERVAL:-300}"
ROTATE_MAX_BYTES="${SURICATA_ROTATE_MAX_BYTES:-67108864}"
ROTATE_MAX_AGE="${SURICATA_ROTATE_MAX_AGE:-86400}"
RETENTION_DAYS="${SURICATA_RETENTION_DAYS:-3}"
# 校验（suricata -T）超时：给大规则集留足时间，但绝不允许挂死
VALIDATE_TIMEOUT="${SURICATA_VALIDATE_TIMEOUT:-300}"

# Zeek 的 HTTP::ports 默认集（**引擎默认值**，不是客户环境的东西）：
# 明文 HTTP 端口 = 这一集 - 共享配置里声明「按 TLS 解析」的端口（tls_ports）
HTTP_PORT_BASE="80,81,88,8000,8008,8010,8011,8048,8080,8088,8888"

case "$RETENTION_DAYS" in ''|*[!0-9]*) RETENTION_DAYS=3 ;; esac

log() { echo "[suricata-entry] $*"; }
now_iso() { date -u +%FT%TZ; }

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

# ---------- 规则目录 ----------

rule_files_in() {
  # 输出目录里的 *.rules 文件名（排序、去路径）；没有就什么都不输出
  local dir="$1" f
  for f in "$dir"/*.rules; do
    [ -f "$f" ] || continue
    basename "$f"
  done | sort
}

# 把文件名列表渲染成 YAML 流式列表：a.rules,b.rules → ["a.rules","b.rules"]
rule_files_yaml() {
  local out="" f
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    [ -z "$out" ] && out="\"$f\"" || out="$out,\"$f\""
  done
  printf '[%s]' "$out"
}

count_rules_in() {
  local dir="$1" total=0 n f
  for f in "$dir"/*.rules; do
    [ -f "$f" ] || continue
    n="$(grep -cE '^[[:space:]]*(alert|drop|pass|reject)[[:space:]]' "$f" 2>/dev/null || true)"
    total=$((total + ${n:-0}))
  done
  echo "$total"
}

# 首次启动（或规则被清空后）必须保证 active/ 里至少有一个可加载的文件，
# 否则 Suricata 的 rule-files 为空会起不来。占位文件来自镜像（内容只有注释 ⇒ 0 条规则）。
bootstrap_rules() {
  mkdir -p "$ACTIVE_DIR" "$STAGING_DIR" "$PREVIOUS_DIR" "$REJECTED_DIR"
  local existing
  existing="$(rule_files_in "$ACTIVE_DIR")"
  if [ -z "$existing" ]; then
    cp -f "${PLACEHOLDER_DIR}/shentong.rules" "${ACTIVE_DIR}/shentong.rules" 2>/dev/null \
      || : > "${ACTIVE_DIR}/shentong.rules"
    log "规则目录为空，已放置空占位规则文件（当前加载 0 条规则）"
  fi
}

# ---------- 渲染配置 ----------

# render_config <默认规则目录> <输出文件> [规则文件名列表文件]
render_config_to() {
  local rule_dir="$1" out="$2" list="${3:-}"
  local iface nets ports files_yaml
  iface="$(resolved_iface)"
  nets="$(home_net)"
  ports="$(http_ports)"
  if [ -z "$list" ]; then
    files_yaml="$(rule_files_in "$rule_dir" | rule_files_yaml)"
  else
    files_yaml="$(cat "$list")"
  fi
  if [ ! -f "$TEMPLATE" ]; then
    log "配置模板不存在：$TEMPLATE"
    return 1
  fi
  # 用 | 当分隔符：网段里有 /（CIDR），用 / 会切错
  sed -e "s|%IFACE%|${iface}|g" \
      -e "s|%HOME_NET%|${nets}|g" \
      -e "s|%HTTP_PORTS%|${ports}|g" \
      -e "s|%RULE_DIR%|${rule_dir}|g" \
      -e "s|%RULE_FILES%|${files_yaml}|g" \
      "$TEMPLATE" > "${out}.tmp"
  mv "${out}.tmp" "$out"
}

render_config() {
  render_config_to "$ACTIVE_DIR" "$YAML_OUT"
  log "配置已渲染：网卡=$(resolved_iface) 网段=$(home_net) HTTP端口=$(http_ports) 规则=$(count_rules_in "$ACTIVE_DIR") 条"
}

# ---------- 校验 / 生效 / 重置（后端用共享卷里的请求标记驱动） ----------

write_validation() {
  # $1=版本 $2=ok(true/false) $3=错误摘要
  local version="$1" ok="$2" err="${3:-}"
  err="$(printf '%s' "$err" | tr '\n' ' ' | cut -c1-800)"
  cat > "${VALIDATION_JSON}.tmp" <<EOF
{"version": "${version}",
 "ok": ${ok},
 "error": "${err}",
 "at": "$(now_iso)"}
EOF
  mv "${VALIDATION_JSON}.tmp" "$VALIDATION_JSON"
}

# 对 staging 跑一次 `suricata -T`（用临时配置指向 staging 目录）
validate_staging() {
  local version="$1" list rc=0 out_file="/tmp/suricata-validate.log"
  # Suricata 启动前会检查 `default-log-dir` 是否存在（`-T` 也一样）：先建出来。
  # CI 里没挂 /logs，缺这一步会得到 “The logging directory "/logs/suricata" ... doesn't exist”，
  # 校验路变成永假（实机踩到）。
  mkdir -p "$OUT_DIR" "$ARCHIVE_DIR"
  rule_files_in "$STAGING_DIR" > /tmp/suricata-staging-files.txt
  if [ ! -s /tmp/suricata-staging-files.txt ]; then
    write_validation "$version" false "暂存目录里没有规则文件"
    return 1
  fi
  rule_files_yaml < /tmp/suricata-staging-files.txt > /tmp/suricata-staging-files.yaml
  render_config_to "$STAGING_DIR" "$YAML_STAGING" /tmp/suricata-staging-files.yaml || {
    write_validation "$version" false "配置渲染失败"
    return 1
  }
  if timeout "$VALIDATE_TIMEOUT" suricata -T -c "$YAML_STAGING" > "$out_file" 2>&1; then
    log "规则校验通过（版本 ${version}，$(count_rules_in "$STAGING_DIR") 条）"
    write_validation "$version" true ""
  else
    rc=$?
    log "规则校验失败（版本 ${version}，退出码 ${rc}）：$(tail -3 "$out_file" | tr '\n' ' ')"
    write_validation "$version" false "$(grep -E '^[[:space:]]*E:|error' "$out_file" | head -5 | tr '\n' ' ' || tail -3 "$out_file")"
    archive_rejected "$version" "$out_file"
    return 1
  fi
}

archive_rejected() {
  local version="$1" logfile="$2" stamp dir
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dir="${REJECTED_DIR}/${stamp}-${version:-unknown}"
  mkdir -p "$dir"
  cp -f "$STAGING_DIR"/*.rules "$dir/" 2>/dev/null || true
  cp -f "$STAGING_DIR/manifest.json" "$dir/" 2>/dev/null || true
  [ -f "$logfile" ] && tail -30 "$logfile" > "${dir}/error.txt" 2>/dev/null || true
  prune_rejected
}

# 只留最近 KEEP_REJECTED 次（用 stat 时间排序，不用 ls：文件名可能带特殊字符）
prune_rejected() {
  local entries=() d line
  for d in "$REJECTED_DIR"/*; do
    [ -d "$d" ] || continue
    entries+=("$(stat -c %Y "$d" 2>/dev/null || echo 0):$d")
  done
  [ "${#entries[@]}" -le "$KEEP_REJECTED" ] && return 0
  printf '%s\n' "${entries[@]}" | sort -rn | tail -n +$((KEEP_REJECTED + 1)) \
    | while IFS= read -r line; do
        rm -rf "${line#*:}"
      done
}

# 把 staging 切到 active（保留上一版到 previous/ 以便回滚）
activate_staging() {
  local version="$1"
  rm -rf "$PREVIOUS_DIR"
  mkdir -p "$PREVIOUS_DIR"
  mv "$ACTIVE_DIR"/* "$PREVIOUS_DIR"/ 2>/dev/null || true
  rmdir "$ACTIVE_DIR" 2>/dev/null || true
  mkdir -p "$ACTIVE_DIR"
  mv "$STAGING_DIR"/* "$ACTIVE_DIR"/ 2>/dev/null || true
  bootstrap_rules
  render_config
  log "已切换到新规则（版本 ${version}，$(count_rules_in "$ACTIVE_DIR") 条）"
}

reset_rules() {
  rm -rf "$PREVIOUS_DIR"
  mkdir -p "$PREVIOUS_DIR"
  mv "$ACTIVE_DIR"/* "$PREVIOUS_DIR"/ 2>/dev/null || true
  rmdir "$ACTIVE_DIR" 2>/dev/null || true
  mkdir -p "$ACTIVE_DIR"
  bootstrap_rules
  render_config
  log "规则已清空（回到空占位，$(count_rules_in "$ACTIVE_DIR") 条）"
}

reload_suricata() {
  local out
  if command -v suricatasc >/dev/null 2>&1; then
    if out="$(suricatasc -c reload-rules 2>&1)"; then
      log "规则已热重载（suricatasc reload-rules）"
      return 0
    fi
    log "suricatasc 热重载失败，改为重启 Suricata：$(printf '%s' "$out" | tail -2 | tr '\n' ' ')"
  fi
  if [ -f "$PID_FILE" ]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
  fi
}

# 处理后端请求标记（每次只处理一个文件；处理完删掉标记）
handle_requests() {
  local version
  if [ -f "$VALIDATE_REQ" ]; then
    version="$(head -1 "$VALIDATE_REQ" | tr -d '\r\n')"
    rm -f "$VALIDATE_REQ"
    log "收到校验请求（版本 ${version}）"
    validate_staging "$version" || true
    return 0
  fi
  if [ -f "$ACTIVATE_REQ" ]; then
    version="$(head -1 "$ACTIVATE_REQ" | tr -d '\r\n')"
    rm -f "$ACTIVATE_REQ"
    log "收到生效请求（版本 ${version}）"
    if validate_staging "$version"; then
      activate_staging "$version"
      reload_suricata
    fi
    return 0
  fi
  if [ -f "$RESET_REQ" ]; then
    rm -f "$RESET_REQ"
    log "收到清空规则请求"
    reset_rules
    reload_suricata
    return 0
  fi
}

# ---------- 状态文件 ----------

write_runtime() {
  local alive="$1" files_json f
  files_json=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    [ -z "$files_json" ] && files_json="\"$f\"" || files_json="${files_json},\"$f\""
  done < <(rule_files_in "$ACTIVE_DIR")
  local active_version=""
  if [ -f "${ACTIVE_DIR}/manifest.json" ]; then
    active_version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${ACTIVE_DIR}/manifest.json" | head -1)"
  fi
  cat > "${RUNTIME_JSON}.tmp" <<EOF
{"alive": $( [ "$alive" = "0" ] && echo true || echo false ),
 "updated_at": "$(now_iso)",
 "iface": "$(resolved_iface)",
 "home_net": "$(home_net | tr -d '\n')",
 "http_ports": "$(http_ports)",
 "rule_files": [${files_json}],
 "rule_count": $(count_rules_in "$ACTIVE_DIR"),
 "active_version": "${active_version}",
 "suricata": "$(suricata -V 2>/dev/null | head -1 || true)"}
EOF
  mv "${RUNTIME_JSON}.tmp" "$RUNTIME_JSON" 2>/dev/null || true
}

# ---------- Suricata 生命周期 ----------

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
  sleep 3
  if ! kill -0 "$SURICATA_PID" 2>/dev/null; then
    printf 'unhealthy %s Suricata 启动即退出（看容器日志 / 规则是否可加载）\n' "$(now_iso)" > "$HEALTH_FILE"
    return 1
  fi
  printf 'healthy %s iface=%s rules=%s\n' "$(now_iso)" "$iface" "$(count_rules_in "$ACTIVE_DIR")" > "$HEALTH_FILE" 2>/dev/null || true
  write_runtime 0
  return 0
}

# ---------- eve.json 轮转与归档清理 ----------

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
      find "$ARCHIVE_DIR" -type f -name 'eve.*.json' -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
    done
  ) &
  log "轮转循环已启动（每 ${ROTATE_INTERVAL}s 检查，归档保留 ${RETENTION_DAYS} 天）"
}

start_health_loop() {
  (
    while true; do
      sleep "$HEALTH_INTERVAL"
      if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        printf 'healthy %s iface=%s rules=%s\n' "$(now_iso)" "$(resolved_iface)" "$(count_rules_in "$ACTIVE_DIR")" > "$HEALTH_FILE" 2>/dev/null || true
        write_runtime 0
      else
        printf 'unhealthy %s Suricata 未在运行\n' "$(now_iso)" > "$HEALTH_FILE" 2>/dev/null || true
        write_runtime 1
      fi
      handle_requests || true
    done
  ) &
}

# ---------- 看门狗（共享配置变化 / 规则目录被外部改动） ----------

rules_signature() {
  # 用内容哈希（不是 ls 列表）作签名：外部直接改文件内容也能被看门狗发现
  sha256sum "$ACTIVE_DIR"/*.rules 2>/dev/null | sha256sum | cut -d' ' -f1
}

start_watchdog() {
  (
    local last_conf last_rules
    last_conf="$(sha256sum "$IFACE_CONF" 2>/dev/null | awk '{print $1}')"
    last_rules="$(rules_signature)"
    while true; do
      sleep "$WATCH_INTERVAL"
      local cur_conf cur_rules
      cur_conf="$(sha256sum "$IFACE_CONF" 2>/dev/null | awk '{print $1}')"
      cur_rules="$(rules_signature)"
      if [ "$cur_conf" != "$last_conf" ]; then
        last_conf="$cur_conf"
        log "检测到采集配置变化，重渲染配置并重启 Suricata"
        render_config || true
        if [ -f "$PID_FILE" ]; then
          kill "$(cat "$PID_FILE")" 2>/dev/null || true
        fi
      elif [ "$cur_rules" != "$last_rules" ]; then
        last_rules="$cur_rules"
        log "检测到规则文件变化（外部直放），重载规则"
        render_config || true
        reload_suricata
      fi
    done
  ) &
  log "看门狗已启动（每 ${WATCH_INTERVAL}s 检查共享配置与规则目录）"
}

# ---------- 主流程 ----------

if [ "${1:-}" = "--render-only" ]; then
  mkdir -p "$OUT_DIR" "$ARCHIVE_DIR" /etc/suricata
  bootstrap_rules
  render_config
  exec suricata -T -c "$YAML_OUT"
fi

if [ "${1:-}" = "--render-config" ]; then
  mkdir -p "$OUT_DIR" "$ARCHIVE_DIR" /etc/suricata
  bootstrap_rules
  render_config
  cat "$YAML_OUT"
  exit 0
fi

if [ "${1:-}" = "--validate-staging" ]; then
  # CI / 排障：直接对 staging 跑一次校验
  mkdir -p /etc/suricata
  bootstrap_rules
  validate_staging "${2:-manual}"
  exit $?
fi

if [ "${1:-}" = "--handle-requests" ]; then
  # CI / 排障：立即处理一次共享卷里的请求标记（validate / activate / reset）后退出，
  # **不进入抓包主循环** —— CI 靠它验证「校验 → 生效 → 清空」这套协议真的能跑通。
  # 忘了实现这个模式会掉进主循环不退出（CI 上挂过一次 20 多分钟），tests/suricata/run.sh
  # 与它配套加了 timeout。
  mkdir -p /etc/suricata "$RULES_DIR"
  bootstrap_rules
  render_config
  handle_requests
  exit 0
fi

main() {
  mkdir -p "$OUT_DIR" "$ARCHIVE_DIR" /etc/suricata "$RULES_DIR"
  bootstrap_rules
  if [ ! -f "$IFACE_CONF" ]; then
    log "共享采集配置不存在（$IFACE_CONF）：先用默认值渲染，等后端写入后看门狗会自动重载"
  fi
  render_config || true
  start_rotate_loop
  start_health_loop
  start_watchdog

  while true; do
    handle_requests || true
    if ! start_suricata; then
      sleep 30
      continue
    fi
    wait "$SURICATA_PID" 2>/dev/null || true
    printf 'unhealthy %s Suricata 已退出，等待重拉\n' "$(now_iso)" > "$HEALTH_FILE" 2>/dev/null || true
    log "Suricata 已退出，2 秒后重新拉起"
    sleep 2
  done
}

main
