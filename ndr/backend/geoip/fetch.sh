#!/bin/sh
# 构建期下载离线地理库（DB-IP City Lite，CC BY 4.0）。
#
# 为什么不在仓库里放 57MB 的 .mmdb.gz（2026-10 用户要求）：仓库太重、每次 clone 都要拖；
# 改成**构建镜像时现下**，仓库里只留这个脚本。
# 下载失败**不阻断构建**：地域是可选能力，没库时界面显示「未知」，其它功能照常。
#
# 归属要求（CC BY 4.0）：IP Geolocation by DB-IP (https://db-ip.com)
set -eu

OUT_DIR="${1:-/app/geoip}"
mkdir -p "$OUT_DIR"

if [ -s "$OUT_DIR/ip.mmdb" ]; then
  echo "[geoip] 已存在 $OUT_DIR/ip.mmdb，跳过下载"
  exit 0
fi

# 解释器：镜像里通常有 python3，个别发行版只有 python —— 自动探测，都没有就跳过（不阻断构建）
PY_BIN="$(command -v python3 || command -v python || true)"
if [ -z "$PY_BIN" ]; then
  echo "[geoip] 找不到 python，跳过下载（地理库不可用，不影响其它功能）"
  exit 0
fi

# 当月文件可能还没发布 → 依次回退到上一个月，最多回退 3 个月
download() {
  # 纯 python 实现（镜像里不一定有 curl；不再依赖外部命令）
  "$PY_BIN" - "$1" "$OUT_DIR/ip.mmdb" <<'PY'
import gzip, sys, urllib.request

url, dest = sys.argv[1], sys.argv[2]
# 必须带 UA：DB-IP 会 403 掉 urllib 的默认 UA（`Python-urllib/3.x`），curl 的则放行
req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
raw = urllib.request.urlopen(req, timeout=300).read()
data = gzip.decompress(raw)
if len(data) < 1024 * 1024:
    raise SystemExit(f"下载内容太小（{len(data)} 字节），八成不是地理库")
with open(dest, "wb") as fh:
    fh.write(data)
print(f"[geoip] 已解压到 {dest}（{len(data)//1024//1024}MB）")
PY
}

MONTH_OFFSET=0
while [ "$MONTH_OFFSET" -le 3 ]; do
  MONTH="$(date -u -d "-${MONTH_OFFSET} month" +%Y-%m 2>/dev/null || date -u -v-"${MONTH_OFFSET}"m +%Y-%m)"
  URL="https://download.db-ip.com/free/dbip-city-lite-${MONTH}.mmdb.gz"
  echo "[geoip] 下载 $URL"
  if download "$URL"; then
    echo "[geoip] 就绪：$OUT_DIR/ip.mmdb"
    exit 0
  fi
  echo "[geoip] $MONTH 不可用，回退上一月"
  MONTH_OFFSET=$((MONTH_OFFSET + 1))
done

echo "[geoip] 下载失败：地理库不可用（不影响其它功能，界面显示「未知」）"
exit 0
