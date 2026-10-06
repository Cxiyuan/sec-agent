#!/bin/sh
# 签名引擎（Suricata）配置与规则的自检（**只在 CI 跑**）。
#
# 为什么必须有这一层：配置是我们渲染出来的（网卡/网段/HTTP 端口三个占位符替换），
# 而「渲染出来的 YAML 这个版本的 Suricata 到底认不认」只有在真容器里跑 `suricata -T`
# 才知道 —— 本地静态检查看不出配置能不能加载，更看不出 ET Open 规则有没有拉下来。
# 与 tests/zeek/run.sh 同一做法：CI 里可以拉镜像 / 构建镜像。
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
IMG="${SURICATA_TEST_IMAGE:-shentong-suricata-ci:test}"
CONF_DIR=$(mktemp -d)
trap 'rm -rf "$CONF_DIR"' EXIT

# 样例共享采集配置：网卡名是**假的**（CI 里没有那块网卡），只验证渲染与自检能过；
# 网段与 tls_ports 用真实形态（CIDR + 端口列表），把「网段里的 / 会不会切坏 sed」也测到。
cat > "$CONF_DIR/interface.conf" <<'EOF'
# 由深瞳 Web 后台维护；本文件变化会被看门狗检测并重载
interface=ens192
monitored_nets=10.10.0.0/16,172.16.0.0/12
bpf_filter=
local_nets=
bpf_extra=
body_max_bytes=16384
resp_body_max_bytes=65536
tls_ports=8000,8011
EOF

echo "== 构建签名引擎镜像（CI 里构建，本地禁止）=="
docker build -t "$IMG" "$ROOT/ndr/suricata"

echo "== 渲染配置 + suricata -T 自检 =="
docker run --rm -v "$CONF_DIR:/config:ro" "$IMG" --render-only

echo "== 断言渲染结果的关键形状 =="
RENDERED=$(docker run --rm -v "$CONF_DIR:/config:ro" "$IMG" \
  sh -c 'mkdir -p /etc/suricata && /usr/local/bin/shentong-suricata-entrypoint.sh --render-only >/dev/null 2>&1; cat /etc/suricata/suricata.yaml')
echo "$RENDERED" | grep -q 'interface: ens192' || { echo "未按共享配置渲染网卡" >&2; exit 1; }
echo "$RENDERED" | grep -q 'HOME_NET: "\[10.10.0.0/16,172.16.0.0/12\]"' \
  || { echo "HOME_NET 没有按监控网段渲染（CIDR 里的 / 有没有被 sed 切坏？）" >&2; exit 1; }
echo "$RENDERED" | grep -q 'community-id: yes' || { echo "community-id 没开（Zeek↔Suricata 无法关联）" >&2; exit 1; }
# tls_ports 里的 8000/8011 必须从 HTTP 端口里剔掉
echo "$RENDERED" | grep -q 'HTTP_PORTS: "80,81,88,8008,8010,8048,8080,8088,8888"' \
  || { echo "HTTP 端口没有按 tls_ports 剔除" >&2; exit 1; }
# 只发 alert：其它类型（flow/dns/http/tls/stats）不应该出现在 eve-log 的 types 里
echo "$RENDERED" | grep -A 3 'types:' | grep -q -- '- alert:' \
  || { echo "eve-log 的 types 里没有 alert" >&2; exit 1; }
if echo "$RENDERED" | grep -A 6 'types:' | grep -Eq -- '- (flow|dns|http|tls|stats|files):'; then
  echo "eve-log 打开了 alert 以外的类型（只应输出命中规则的事件）" >&2
  exit 1
fi

echo "== 断言规则真的拉下来了（ET Open，MIT）=="
RULES=$(docker run --rm "$IMG" sh -c 'wc -l < /var/lib/suricata/rules/suricata.rules')
echo "规则行数: $RULES"
[ "$RULES" -gt 1000 ] || { echo "规则文件太小（ET Open 没拉下来？）" >&2; exit 1; }
docker run --rm "$IMG" sh -c 'grep -q "ET " /var/lib/suricata/rules/suricata.rules' \
  || { echo "规则文件里没有 ET 签名" >&2; exit 1; }

echo "签名引擎自检通过"
