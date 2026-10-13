#!/bin/sh
# 前端容器入口：确保自签名证书存在 → 起应用（内部 3000）→ 起 TLS 终结（443 / 80 跳转）。
#
# 证书 SAN 决定「浏览器会不会报不受信任」：现代浏览器忽略 CN，只认 SAN，
# 所以必须把运维实际访问用的地址（主机 IP / 域名）逐个列进 SAN。
# 组成：DNS:<TLS_CN> + IP:127.0.0.1 + 自动识别的宿主 IP + 部署侧 TLS_SANS 追加。
# TLS_SANS 逗号分隔，元素形如 IP:192.0.2.10 / DNS:ndr.example.com，裸地址按 IP 处理，例如：
#   TLS_SANS=IP:192.0.2.10,DNS:ndr.example.com
set -eu

CERT_DIR="${TLS_CERT_DIR:-/certs}"
CERT="${CERT_DIR}/tls.crt"
KEY="${CERT_DIR}/tls.key"
SAN_MARK="${CERT_DIR}/.san"

TLS_CN_NAME="${TLS_CN:-shentong-ndr}"
SANS="DNS:${TLS_CN_NAME}"

# 追加一个 SAN 条目（重复的不再追加）
add_san() {
  [ -n "$1" ] || return 0
  case ",$SANS," in
    *",$1,"*) return 0 ;;
  esac
  SANS="$SANS,$1"
}

add_san "IP:127.0.0.1"

# 自动补宿主 IP：compose 里配了 host.docker.internal:host-gateway 时可用；
# 拿不到就跳过（此时靠 TLS_SANS 显式指定）。
HOST_IP="$(getent hosts host.docker.internal 2>/dev/null | awk '{print $1; exit}' || true)"
case "$HOST_IP" in
  "") : ;;
  *[!0-9.]*) : ;;          # 只认 IPv4 字面量，IPv6 一律跳过
  *) add_san "IP:$HOST_IP" ;;
esac

if [ -n "${TLS_SANS:-}" ]; then
  set -f                   # 关掉通配，避免地址里的字符被当 glob 展开
  for item in $(printf '%s' "$TLS_SANS" | tr ',' ' '); do
    case "$item" in
      IP:*|DNS:*) add_san "$item" ;;
      *) add_san "IP:$item" ;;
    esac
  done
  set +f
fi

# SAN 变了就重签：老部署只留了证书/私钥（没有 .san 指纹），会在这里自动补签一次
if [ -s "$CERT" ] && [ -s "$KEY" ] && [ -f "$SAN_MARK" ] && [ "$(cat "$SAN_MARK")" = "$SANS" ]; then
  echo "[frontend-entry] 复用已有证书：$CERT（SAN: $SANS）"
else
  mkdir -p "$CERT_DIR"
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=${TLS_CN_NAME}" \
    -addext "subjectAltName=$SANS" \
    -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
  chmod 600 "$KEY"
  printf '%s' "$SANS" > "$SAN_MARK"
  echo "[frontend-entry] 已生成自签名证书：$CERT"
  echo "[frontend-entry] 证书 SAN：$SANS"
  echo "[frontend-entry] 若用没列进 SAN 的地址访问，浏览器会报不受信任；把该地址加进 TLS_SANS 并重启容器即可重签"
fi

# 应用照旧监听 3000（容器内部），TLS 终结在 443 / 80 由 tls-server.mjs 负责
npm start &
exec node /app/tls-server.mjs
