#!/usr/bin/env bash
# 在**运行中**的 Wazuh manager 里幂等开启 JSON 原始日志（archives.json）。
#
# 背景：Wazuh 默认只写 alerts.json（告警）；archives.json 是 <logall_json> 打开后
# 才有全量原始日志。深瞳的「原始日志只入库、不喂检测器」策略就建立在它上面
# （见 ndr/backend/app/collector/normalizer_service.py 与 ST_WAZUH_ARCHIVE_TO_DETECTOR）。
#
# 为什么不整体替换 ossec.conf：不同 4.14.x 小版本的默认配置有差异（agentless、
# vulnerability-detection、cluster 段都不一样），写错会让 manager 起不来。
# 这里只在 <global> 段补两行，其余原样保留；重复执行不会重复插入。
#
# 用法（在 ndr/ 目录下）：
#   ./wazuh/enable-logall.sh                       # 用默认 compose 组合
#   COMPOSE_FILES="-f docker-compose.deploy.yml -f docker-compose.wazuh.yml" ./wazuh/enable-logall.sh
# 改完重启 manager 才生效：
#   docker compose -f docker-compose.yml -f docker-compose.wazuh.yml restart wazuh-manager
#
# 注意：打开后磁盘占用与采集量都会明显上升（全量原始日志）。只想要告警就别执行。
set -euo pipefail

SERVICE="${1:-wazuh-manager}"
read -r -a FILES <<< "${COMPOSE_FILES:--f docker-compose.yml -f docker-compose.wazuh.yml}"

docker compose "${FILES[@]}" exec -T "$SERVICE" bash -s <<'EOS'
set -euo pipefail
conf=/var/ossec/etc/ossec.conf

if [ ! -f "$conf" ]; then
  echo "找不到 $conf，manager 镜像结构可能变了" >&2
  exit 1
fi

if grep -q "<logall_json>yes</logall_json>" "$conf"; then
  echo "已开启 logall_json，无需改动"
  exit 0
fi

backup="$conf.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$conf" "$backup"
awk '{ print } /<global>/{ print "    <logall>yes</logall>"; print "    <logall_json>yes</logall_json>" }' "$conf" > "$conf.new"

if ! grep -q "<logall_json>yes</logall_json>" "$conf.new"; then
  echo "没找到 <global> 段，未改动（ossec.conf 结构可能变了）" >&2
  rm -f "$conf.new"
  exit 1
fi

mv "$conf.new" "$conf"
echo "已写入 logall / logall_json，原文件备份为 $backup"
echo "重启 manager 后生效：docker compose ... restart $SERVICE"
EOS
