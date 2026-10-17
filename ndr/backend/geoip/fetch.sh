#!/bin/sh
# 构建期下载离线地理库（DB-IP City Lite，CC BY 4.0）。
#
# 为什么不在仓库里放 57MB 的 .mmdb.gz（2026-10 用户要求）：仓库变重、每次 clone 都要拖；
# 改成**构建镜像时现下**，仓库里只留这个脚本。下载失败**不阻断构建**——
# 地域是可选能力，没库时 `app/geoip.py` 返回空、界面显示「未知」，其它功能照常。
#
# 归属要求（CC BY 4.0）：IP Geolocation by DB-IP (https://db-ip.com)
set -eu

OUT_DIR="${1:-/app/geoip}"
MONTH="$(date -u +%Y-%m)"
URL="https://download.db-ip.com/free/dbip-city-lite-${MONTH}.mmdb.gz"

mkdir -p "$OUT_DIR"
if [ -s "$OUT_DIR/ip.mmdb" ]; then
  echo "[geoip] 已存在 $OUT_DIR/ip.mmdb，跳过下载"
  exit 0
fi

echo "[geoip] 下载 $URL"
if ! command -v curl >/dev/null 2>&1; then
  echo "[geoip] 镜像里没有 curl，改用 python 下载"
  python - "$URL" "$OUT_DIR/ip.mmdb" <<'PY' || echo "[geoip] 下载失败：地理库不可用（不影响其它功能）"
import gzip, sys, urllib.request
url, dest = sys.argv[1], sys.argv[2]
gz = urllib.request.urlopen(url, timeout=180).read()
with gzip.decompress(gz) if False else gzip.GzipFile(fileobj=__import__("io").BytesIO(gz)) as fh:
    data = fh.read()
open(dest, "wb").write(data)
print(f"[geoip] 已解压到 {dest}（{len(data)//1024//1024}MB）")
PY
  exit 0
fi

if curl -fsSL --retry 3 --max-time 300 -o /tmp/geoip.mmdb.gz "$URL"; then
  gunzip -c /tmp/geoip.mmdb.gz > "$OUT_DIR/ip.mmdb"
  rm -f /tmp/geoip.mmdb.gz
  echo "[geoip] 就绪：$OUT_DIR/ip.mmdb"
else
  echo "[geoip] 下载失败：地理库不可用（不影响其它功能）"
fi
