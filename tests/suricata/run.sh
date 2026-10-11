#!/bin/sh
# 签名引擎（Suricata）配置与规则加载的自检（**只在 CI 跑**）。
#
# 规则来源是「开发者提供的规则全集 → 按攻击类型分类 → 作为**内置默认**加载」，另有 manifest
# 在线更新路径；引擎自带事件规则（SURICATA *）一律不加载。这个脚本验证的都是容易静默失效的点：
#   ① **内置默认规则集全量能被 suricata -T 加载**（11k+ 条；任何一条语法/关键字不被支持就红）；
#   ② 渲染出的配置确实引用了全部 7 个分类文件、并把分类索引抄进了卷（界面按攻击类型展示）；
#   ③ 渲染出的配置只引用 active/ 里的规则、不引用任何 *-events.rules（引擎事件确实关掉了）；
#   ④ staging 校验与 activate 切换这套共享卷协议真的能跑通。
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
IMG="${SURICATA_TEST_IMAGE:-shentong-suricata-ci:test}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK" 2>/dev/null || true' EXIT
mkdir -p "$WORK/config" "$WORK/rules/active" "$WORK/rules/staging" "$WORK/rules/previous" "$WORK/rules/rejected"

# 样例共享采集配置：网卡名是假的（CI 里没有那块网卡），网段与 tls_ports 用真实形态，
# 把「网段里的 / 会不会切坏 sed」也测到。
cat > "$WORK/config/interface.conf" <<'EOF'
interface=ens192
monitored_nets=10.10.0.0/16,172.16.0.0/12
tls_ports=8000,8011
EOF

# 期望条数从分类索引里读（与镜像里的内置规则集同源，避免手写数字漂移）
INDEX="$ROOT/ndr/suricata/rules/builtin/index.json"
[ -f "$INDEX" ] || { echo "缺少分类索引 $INDEX（先跑 ndr/suricata/tools/classify_rules.py）" >&2; exit 1; }
EXPECT_TOTAL=$(sed -n 's/^  "total": \([0-9]*\),$/\1/p' "$INDEX" | head -1)
EXPECT_FILES=$(grep -c '"file":' "$INDEX")
[ -n "$EXPECT_TOTAL" ] && [ "$EXPECT_TOTAL" -gt 0 ] || { echo "索引里读不到 total" >&2; exit 1; }

RUN() {
  # 加超时：一次性模式如果忘了实现，容器会掉进抓包主循环不退出（CI 上挂过 20+ 分钟）
  timeout 600 docker run --rm -v "$WORK/config:/config:ro" -v "$WORK/rules:/rules" "$@"
}

count_from_entry() {
  # 取入口自己打的条数（我们的日志格式，稳定；Suricata 7.0.17 的 -T 输出**不可靠**：
  # 实测 0 条时只打一条 warning、有规则时连统计行都不打，日志级别一变就解析不到）
  printf '%s\n' "$1" | sed -n 's/.*规则=\([0-9][0-9]*\) 条.*/\1/p' | tail -1
}

echo "== 构建签名引擎镜像（CI 里构建，本地禁止）=="
docker build -t "$IMG" "$ROOT/ndr/suricata"

echo "== ① 内置默认规则集：全量加载（$EXPECT_TOTAL 条，$EXPECT_FILES 个分类文件）=="
OUT=$(RUN "$IMG" --render-only 2>&1) || {
  printf '%s\n' "$OUT" | tail -40 >&2
  echo "内置默认规则集让 suricata -T 失败了（语法/关键字不被支持）——看上面的原始报错定位规则" >&2
  exit 1
}
N=$(count_from_entry "$OUT")
if [ -z "$N" ]; then
  printf '%s\n' "$OUT" | tail -20 >&2
  echo "没能从入口日志里解析出规则条数" >&2
  exit 1
fi
[ "$N" = "$EXPECT_TOTAL" ] || {
  printf '%s\n' "$OUT" | tail -30 >&2
  echo "入口统计 $N 条，索引里是 $EXPECT_TOTAL 条（分类文件有没有漏拷/重复？）" >&2
  exit 1
}
# 分类索引要抄进卷里，后端/界面据此按攻击类型展示
[ -f "$WORK/rules/builtin-index.json" ] || { echo "没有把 builtin-index.json 抄进规则卷" >&2; exit 1; }
echo "内置默认规则集：$N 条，suricata -T 通过 ✓"

echo "== ② 渲染结果的关键形状 =="
RENDERED=$(RUN --entrypoint sh "$IMG" -c '/usr/local/bin/shentong-suricata-entrypoint.sh --render-config')
printf '%s\n' "$RENDERED" | grep -q 'interface: ens192' || { echo "未按共享配置渲染网卡" >&2; exit 1; }
printf '%s\n' "$RENDERED" | grep -q 'HOME_NET: "\[10.10.0.0/16,172.16.0.0/12\]"' \
  || { echo "HOME_NET 没按监控网段渲染（CIDR 里的 / 有没有被 sed 切坏？）" >&2; exit 1; }
printf '%s\n' "$RENDERED" | grep -q 'HTTP_PORTS: "80,81,88,8008,8010,8048,8080,8088,8888"' \
  || { echo "HTTP 端口没有按 tls_ports 剔除" >&2; exit 1; }
printf '%s\n' "$RENDERED" | grep -q 'community-id: yes' || { echo "community-id 没开" >&2; exit 1; }
printf '%s\n' "$RENDERED" | grep -q 'unix-command:' || { echo "没开热重载用的 unix socket" >&2; exit 1; }
# 规则列表只含 active 里的文件；引擎自带事件规则（*-events.rules）一个都不能引用
for f in 10-web-attack 20-exploit 30-credential 40-scan 50-malware-c2 60-sensitive-data 90-other; do
  printf '%s\n' "$RENDERED" | grep -q "$f.rules" \
    || { echo "rule-files 里缺少分类文件 $f.rules" >&2; exit 1; }
done
if printf '%s\n' "$RENDERED" | grep -q 'events.rules'; then
  echo "配置里引用了引擎自带事件规则（本项目口径：不加载）" >&2
  exit 1
fi
if printf '%s\n' "$RENDERED" | grep -A 6 'types:' | grep -Eq -- '- (flow|dns|http|tls|stats|files):'; then
  echo "eve-log 打开了 alert 以外的类型（只应输出命中规则的事件）" >&2
  exit 1
fi
echo "渲染形状 ✓"

echo "== ③ 开发人员写的规则：能加载（样例断言 2 条）=="
cp "$ROOT/tests/suricata/sample/shentong-sample.rules" "$WORK/rules/active/"
OUT=$(RUN "$IMG" --render-only 2>&1) || {
  printf '%s\n' "$OUT" | tail -30 >&2
  echo "样例规则让 suricata -T 失败了（语法/变量/字段有问题）" >&2
  exit 1
}
N=$(count_from_entry "$OUT")
[ "$N" = "2" ] || {
  printf '%s\n' "$OUT" | tail -30 >&2
  echo "入口统计的样例规则条数是 $N，应为 2" >&2
  exit 1
}
echo "样例规则：2 条，suricata -T 通过 ✓"

echo "== ④ staging 校验 + activate 切换（共享卷协议）=="
# 校验：把新版本放进 staging 并下发 validate.request（不吞容器输出，失败要能看到原因）
cp "$ROOT/tests/suricata/sample/shentong-sample.rules" "$WORK/rules/staging/"
printf 'ci-test-1\n' > "$WORK/rules/validate.request"
RUN "$IMG" --handle-requests 2>&1 | tail -15 || true
if [ ! -f "$WORK/rules/validation.json" ]; then
  echo "容器没有写 validation.json（请求标记没被处理？）" >&2
  exit 1
fi
if ! grep -q '"ok": true' "$WORK/rules/validation.json"; then
  echo "staging 校验没有通过，validation.json：" >&2
  cat "$WORK/rules/validation.json" >&2 || true
  echo "--- 容器里 suricata -T 的原始输出（rejected/error.txt）---" >&2
  for f in "$WORK"/rules/rejected/*/error.txt; do
    [ -f "$f" ] && cat "$f" >&2
  done
  exit 1
fi
# 生效：写 activate.request → 容器切 active（带 manifest.json 供界面显示版本）
printf '{"version": "ci-test-1", "files": [{"name": "shentong-sample.rules"}]}\n' \
  > "$WORK/rules/staging/manifest.json"
printf 'ci-test-1\n' > "$WORK/rules/activate.request"
RUN "$IMG" --handle-requests 2>&1 | tail -15 || true
[ -f "$WORK/rules/active/manifest.json" ] || { echo "activate 没有把 staging 切到 active" >&2; exit 1; }
grep -q '"ci-test-1"' "$WORK/rules/active/manifest.json" || { echo "生效版本不对" >&2; exit 1; }
[ -f "$WORK/rules/active/shentong-sample.rules" ] || { echo "规则文件没切过去" >&2; exit 1; }
ls "$WORK"/rules/previous/*.rules >/dev/null 2>&1 || { echo "上一版（内置默认集）没有留到 previous" >&2; exit 1; }
echo "校验与生效协议 ✓"

echo "== ⑤ 清空规则：回到内置默认规则集 =="
printf 'reset\n' > "$WORK/rules/reset.request"
RUN "$IMG" --handle-requests 2>&1 | tail -10 || true
[ ! -f "$WORK/rules/active/manifest.json" ] || { echo "清空后 active 里还有 manifest（应为内置默认）" >&2; exit 1; }
N=$(RUN "$IMG" --render-only 2>&1 | sed -n 's/.*规则=\([0-9][0-9]*\) 条.*/\1/p' | tail -1)
[ "$N" = "$EXPECT_TOTAL" ] || { echo "清空后加载 $N 条，应为内置默认的 $EXPECT_TOTAL 条" >&2; exit 1; }
echo "清空规则 → 回到内置默认 ✓"

# 容器以 root 写的文件，CI 用户删不掉：收尾把权限放开（免得 trap 里 rm 报一堆 Permission denied）
RUN --entrypoint sh "$IMG" -c 'chmod -R a+rwX /rules' >/dev/null 2>&1 || true

echo "签名引擎自检通过"
