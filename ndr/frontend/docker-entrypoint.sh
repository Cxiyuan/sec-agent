#!/bin/sh
# 前端容器入口：确保自签名证书存在 → 起应用（内部 3000）→ 起 TLS 终结（443 / 80 跳转）。
set -eu

CERT_DIR="${TLS_CERT_DIR:-/certs}"
CERT="${CERT_DIR}/tls.crt"
KEY="${CERT_DIR}/tls.key"

if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
  mkdir -p "$CERT_DIR"
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=${TLS_CN:-shentong-ndr}" \
    -addext "subjectAltName=DNS:${TLS_CN:-shentong-ndr},IP:127.0.0.1" \
    -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
  chmod 600 "$KEY"
  echo "[frontend-entry] 已生成自签名证书：$CERT（浏览器提示不受信任属预期；换掉就覆盖这两个文件）"
else
  echo "[frontend-entry] 复用已有证书：$CERT"
fi

# 应用照旧监听 3000（容器内部），TLS 终结在 443 / 80 由 tls-server.mjs 负责
npm start &
exec node /app/tls-server.mjs
