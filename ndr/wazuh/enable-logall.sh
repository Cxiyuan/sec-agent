#!/usr/bin/env bash
# 在**运行中**的 Wazuh manager 里幂等开启 JSON 原始日志（archives.json）。
#
# 背景：Wazuh 默认只写 alerts.json（告警）；archives.json 是 <logall_json> 打开后
# 才有全量原始日志。深瞳的「原始日志只入库、不喂检测器」策略就建立在它上面
# （见 ndr/backend/app/collector/normalizer_service.py 与 ST_WAZUH_ARCHIVE_TO_DETECTOR）。
#
# 为什么不整体替换 ossec.conf：不同 4.14.x 小版本的默认配置有差异（agentless、
# vulnerability-detection、cluster 段都不一样），写错会让 manager 起不来。
# 这里只动 <global> 里的这两行，其余原样保留；重复执行不会重复插入。
#
# ⚠ 2026-10-03 实机（manager 4.14.8）踩到的坑，改法因此变过：
#   官方镜像的默认 ossec.conf **本来就写着** <logall>no</logall> / <logall_json>no</logall_json>
#   （就在 <global> 段开头）。老版本「在 <global> 之后插入两行 yes」的做法会留下
#   「yes 在前、no 在后」两组互相矛盾的键 —— 解析器取哪一个不可依赖，实测那台机器上
#   等于没生效（脚本却报成功）。现在改成：**先就地改值**，键不存在时才退回插入；
#   改完自检「两个键各恰好一处 yes、没有 no」，不通过就回滚，绝不把 manager 重启成起不来。
#
# 用法（在 ndr/ 目录下）：
#   ./wazuh/enable-logall.sh                       # 用默认 compose 组合
#   COMPOSE_FILES="-f docker-compose.deploy.yml" ./wazuh/enable-logall.sh
# 脚本只改 manager 侧的 ossec.conf。**采集侧还有第二个开关**：Filebeat 的
# WAZUH_ARCHIVES_ENABLED（wazuh/filebeat.yml 的 `enabled: ${WAZUH_ARCHIVES_ENABLED:false}`），
# 必须在 .env 里设成 true 并重启 wazuh-filebeat，archives.json 才会真的上报。
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

if grep -q "<logall_json>yes</logall_json>" "$conf" && grep -q "<logall>yes</logall>" "$conf"; then
  echo "已开启 logall / logall_json，无需改动"
  exit 0
fi

backup="$conf.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$conf" "$backup"

# ① 先就地改值：默认文件里这两个键（值为 no）本来就在 <global> 段
sed -i 's#<logall>no</logall>#<logall>yes</logall>#; s#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' "$conf"

# ② 键不存在的小版本才插入（只插到第一个 <global>，别插进 cluster/sca 里的同名段）
insert_after_first_global() {
  awk -v line="    <$1>yes</$1>" '{ print } /<global>/ && !done { print line; done=1 }' "$conf" > "$conf.new"
  mv "$conf.new" "$conf"
}
grep -q "<logall>yes</logall>" "$conf" || insert_after_first_global logall
grep -q "<logall_json>yes</logall_json>" "$conf" || insert_after_first_global logall_json

# ③ 自检：允许出现 <logall>yes</logall> 恰好 1 处、<logall>no</logall> 0 处
for key in logall logall_json; do
  yes_n=$(grep -c "<$key>yes</$key>" "$conf" || true)
  no_n=$(grep -c "<$key>no</$key>" "$conf" || true)
  if [ "$yes_n" != "1" ] || [ "$no_n" != "0" ]; then
    echo "自检失败：<$key> yes=$yes_n no=$no_n，已回滚到 $backup" >&2
    cp -a "$backup" "$conf"
    exit 1
  fi
done

echo "已写入 logall / logall_json = yes（自检通过），原文件备份为 $backup"
# 注意：下面两行只是给操作者的提示，运行在**容器内**（这里没有 $SERVICE），所以写死服务名。
echo "① 重启 manager 后生效：docker compose ... restart wazuh-manager"
echo "② 采集侧还要把 archives 输入打开（两处开关缺一不可，只做①不上报）："
echo "     在 .env 里加或改 WAZUH_ARCHIVES_ENABLED=true，然后重启 Filebeat："
echo "       docker compose ... up -d wazuh-filebeat"
echo "   否则 archives.json 会被写出来，但永远不会进 Redis/ES。"
EOS
