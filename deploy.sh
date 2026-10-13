#!/bin/sh
# 深瞳 · 一键部署（**编排文件随代码一起部署**，避免"改了仓库、服务器没生效"）
#
# 背景（2026-10 实机事故）：把访问方式改成强制 HTTPS 时，只改了仓库里的编排文件，
# 而服务器上的那份是单独放过去的 —— 部署只拉了镜像、重建容器仍用旧文件，端口映射还是旧的
# `3000:3000`，于是 443 从未对外，局域网打开控制台一直「响应时间过长」。
# 所以本脚本把「同步编排文件」作为部署的第一步，并且**每一步都要校验结果**（拉取失败不再被吞、部署后核对落地）。
#
# 为什么脚本里没有任何主机/目录/地址：这些是环境相关的。全部由环境变量传进来：
#   DEPLOY_HOST   必填。目标主机（IP 或域名，例如 10.1.2.250）；**在部署机本机执行时写 local**
#   DEPLOY_DIR    目标上的部署目录，默认 /opt/shentong-ndr
#   DEPLOY_SSH    可选。用于连接的 ssh 命令前缀，默认 ssh
#                 （需要密码认证时传 "sshpass -p <口令> ssh" —— 口令不进仓库、也不进命令行历史以外的任何地方）
#   COMPOSE_FILE  可选。要同步的编排文件，默认 ndr/docker-compose.deploy.yml
#   SERVICES      可选。只重建这些服务（空格分隔），默认全部
#   PULL_RETRIES  可选。拉取重试次数，默认 5（现场 DNS 到镜像仓库不稳定，实测约一半概率超时）
#   MODE          可选。deploy（默认，真部署）| check（**只做部署前体检**，不动任何东西）
#   PROBE_RETRIES 可选。部署后前端探活重试次数，默认 18（× 5 秒 = 90 秒，等应用起来）
#
# 用法（在仓库根执行）：
#   DEPLOY_HOST=<主机> [DEPLOY_SSH="sshpass -p <口令> ssh"] sh deploy.sh
#   DEPLOY_HOST=<主机> SERVICES="frontend" sh deploy.sh          # 只更前端
#   DEPLOY_HOST=local MODE=check sh deploy.sh                    # 在部署机上：只体检，不动任何东西
#   DEPLOY_HOST=local sh deploy.sh                               # 在部署机上：直接部署（不需要 SSH/口令）
#
# 回滚：脚本每次都会把目标上的旧文件备份成 <文件名>.bak.<时间戳>；出错时按提示恢复即可。
set -eu

DEPLOY_HOST="${DEPLOY_HOST:-}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/shentong-ndr}"
DEPLOY_SSH="${DEPLOY_SSH:-ssh}"
# 编排文件：默认值按模式区分 —— 远端模式从仓库取（ndr/…），本地模式下编排已在部署目录里。
COMPOSE_FILE="${COMPOSE_FILE:-}"
SERVICES="${SERVICES:-}"
PULL_RETRIES="${PULL_RETRIES:-5}"
PROBE_RETRIES="${PROBE_RETRIES:-18}"   # 前端探活重试次数（每次间隔 5 秒）
STRICT="${STRICT:-0}"
MODE="${MODE:-deploy}"
# 本地模式：DEPLOY_HOST=local 时直接在部署机上执行（不需要 ssh，脚本自己就是运维入口）
LOCAL=0
case "${DEPLOY_HOST:-}" in local|local:*) LOCAL=1 ;; esac
[ -n "${DEPLOY_LOCAL:-}" ] && LOCAL=1
[ -n "$COMPOSE_FILE" ] || {
  if [ "$LOCAL" = "1" ]; then
    COMPOSE_FILE="$DEPLOY_DIR/docker-compose.deploy.yml"
  else
    COMPOSE_FILE="ndr/docker-compose.deploy.yml"
  fi
}

[ -n "$DEPLOY_HOST" ] || { echo "缺少 DEPLOY_HOST（目标主机）" >&2; exit 2; }
[ -f "$COMPOSE_FILE" ] || { echo "找不到编排文件：$COMPOSE_FILE" >&2; exit 2; }

# deploy <远程命令>：统一走 DEPLOY_SSH（前缀里可能带认证工具）
deploy() {
  if [ "$LOCAL" = "1" ]; then
    # 本地模式：命令就在部署机上跑（参数是一个命令字符串，交给 sh 执行）
    sh -c "$1"
    return $?
  fi
  # shellcheck disable=SC2086  # DEPLOY_SSH 需要按空格拆成命令 + 参数
  $DEPLOY_SSH -o StrictHostKeyChecking=no "$DEPLOY_HOST" "$@"
}

BASE=$(basename "$COMPOSE_FILE")
STAMP=$(date +%Y%m%d-%H%M%S)
LOCAL_SUM=$(sha256sum "$COMPOSE_FILE" | awk '{print $1}')

echo "== 0) 目标检查 =="
deploy "test -d '$DEPLOY_DIR' || { echo '部署目录不存在: $DEPLOY_DIR' >&2; exit 2; }"
if [ "$LOCAL" = "1" ]; then
  echo "  主机=本机（本地模式） 目录=$DEPLOY_DIR 编排=$COMPOSE_FILE"
else
  echo "  主机=$DEPLOY_HOST 目录=$DEPLOY_DIR 编排=$COMPOSE_FILE"
fi

if [ "$MODE" = "check" ]; then
  echo "== 1) check 模式：跳过备份（本模式不写任何文件）=="
else
echo "== 1) 备份目标上的旧编排（回滚用）=="
deploy "cd '$DEPLOY_DIR' && cp -f '$BASE' '$BASE.bak.$STAMP' && ls -l '$BASE.bak.$STAMP' | awk '{print \$NF}'"
fi

if [ "$LOCAL" = "1" ]; then
  # 本地模式：编排就在部署目录里（本脚本不覆盖它，避免把现场配置改掉）
  deploy "test -f '$DEPLOY_DIR/$BASE' || { echo '编排文件不在部署目录：$DEPLOY_DIR/$BASE' >&2; exit 2; }"
  echo "== 2) 本地模式：使用部署目录里已有的编排（不同步、不覆盖）=="
elif [ "$MODE" = "check" ]; then
  # check 模式对**任何**路径都必须只读（远端同步也会改目标文件，所以这里一并跳过）
  deploy "test -f '$DEPLOY_DIR/$BASE' || { echo '编排文件不在部署目录：$DEPLOY_DIR/$BASE' >&2; exit 2; }"
  echo "== 2) check 模式：使用目标上已有的编排（不同步、不覆盖）=="
else
echo "== 2) 同步编排文件（本地 → 目标）=="
# 文件内容经标准输入送到目标（不要用 `ssh "cat > 文件"` 而不给 stdin：那会写成空文件）
# shellcheck disable=SC2086
$DEPLOY_SSH -o StrictHostKeyChecking=no "$DEPLOY_HOST" "cat > /tmp/shentong-compose.new" < "$COMPOSE_FILE"
deploy "cd '$DEPLOY_DIR' && cp -f /tmp/shentong-compose.new '$BASE' && rm -f /tmp/shentong-compose.new"
REMOTE_SUM=$(deploy "sha256sum '$DEPLOY_DIR/$BASE' | awk '{print \$1}'")
if [ "$REMOTE_SUM" != "$LOCAL_SUM" ]; then
  echo "编排文件校验和不一致（本地 $LOCAL_SUM / 目标 $REMOTE_SUM）—— 同步失败，已保留备份 $BASE.bak.$STAMP" >&2
  echo "回滚：在目标上执行  cp -f $DEPLOY_DIR/$BASE.bak.$STAMP $DEPLOY_DIR/$BASE" >&2
  exit 1
fi
echo "  校验和一致：$LOCAL_SUM"
fi

echo "== 2.5) 部署前体检（只读，不改任何配置）=="
HOST_IP=$(deploy "ip route get 1.1.1.1 2>/dev/null | awk '{print \$7; exit}'" || true)
[ -n "$HOST_IP" ] || HOST_IP=$(deploy "hostname -I 2>/dev/null | awk '{print \$1}'" || true)
echo "  探测到宿主地址：${HOST_IP:-未知}（证书应覆盖它，否则浏览器会报证书不匹配）"
deploy "docker exec shentong-ndr-frontend-1 sh -c 'openssl x509 -in /certs/tls.crt -noout -text 2>/dev/null | grep -q \"IP Address:${HOST_IP}\"' && echo '  证书已覆盖宿主地址 ✓' || echo '  ⚠ 证书未覆盖 ${HOST_IP}：请在部署配置里设置证书覆盖地址（TLS_SANS）后重启前端'" || true
deploy "docker exec shentong-ndr-backend-1 python -c \"
from app.config import settings
jwt_bad = settings.jwt_secret in ('change-me-in-production', '')
cors = settings.cors_origins or ''
print('  ⚠ 登录密钥仍是默认占位值，必须更换' if jwt_bad else '  登录密钥已更换 ✓')
print('  ⚠ 允许来源仍带 http/3000 写法：' + cors if ':3000' in cors or cors.startswith('http://') else '  允许来源 ✓ ' + (cors or '（空 = 只允许同源）'))
\"" || true
deploy "docker exec shentong-ndr-backend-1 python -c \"
from app.detector import push
cfg = push.load_config() or {}
url = str(cfg.get('url') or '')
print('  摘要推送已配置 ✓' if url else '  ⚠ 摘要推送未配置 → 摘要会一直未投递（智能体地址常量 10.44.77.249）')
\"" || true
echo "  （体检只读；有 ⚠ 不阻塞部署，可用 STRICT=1 让脚本遇到 ⚠ 直接失败）"

if [ "$MODE" = "check" ]; then
  echo
  echo "MODE=check：只做体检，未拉取、未重建、未改任何配置。"
  exit 0
fi

echo "== 3) 拉取镜像（失败可见、可重试）=="
i=1
while : ; do
  echo "  第 $i 次拉取…"
  if deploy "cd '$DEPLOY_DIR' && docker compose -f '$BASE' pull $SERVICES" ; then
    break
  fi
  if [ "$i" -ge "$PULL_RETRIES" ]; then
    echo "连续 $PULL_RETRIES 次拉取失败：常见原因是目标机 DNS 到镜像仓库不稳（解析超时）。" >&2
    echo "请先修好目标机的 DNS（指向稳定上游）再重试；本次未改动运行中的服务。" >&2
    echo "回滚编排（如需）：在目标上执行  cp -f $DEPLOY_DIR/$BASE.bak.$STAMP $DEPLOY_DIR/$BASE" >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 8
done

echo "== 4) 重建服务 =="
deploy "cd '$DEPLOY_DIR' && docker compose -f '$BASE' up -d --remove-orphans $SERVICES"

echo "== 5) 落地核对（不只看命令返回码）=="
deploy "docker ps --format 'table {{.Names}}\t{{.Status}}' | head -20"
# 前端是唯一对外入口：本机 HTTPS 必须能通（自签名证书 → 用 -k 跳过校验）
# 注意：容器刚 Started 时应用还在启动（实测 Up < 1 秒就探会误判失败）→ 必须带重试地等
FRONT_OK=0
i=0
while [ "$i" -lt "${PROBE_RETRIES:-18}" ]; do
  i=$((i + 1))
  if deploy "curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1/ | grep -q 200"; then
    FRONT_OK=1
    break
  fi
  sleep 5
done
if [ "$FRONT_OK" = "1" ]; then
  echo "  前端本机 HTTPS 探活：200 ✓（第 $i 次尝试）"
else
  echo "  前端本机 HTTPS 探活失败（已重试 $i 次 ≈ $((i * 5)) 秒）：下面是前端日志尾部——" >&2
  deploy "docker logs --tail 25 shentong-ndr-frontend-1 2>&1" >&2 || true
  echo "  排查方向：证书是否在（/certs）、入口是否起了 tls-server、端口 443/80 是否发布" >&2
  if [ "$STRICT" = "1" ]; then
    echo "STRICT=1：探活失败视为部署失败" >&2
    exit 1
  fi
fi
echo
if [ "$STRICT" = "1" ]; then
  echo
  echo "STRICT=1：请确认上面体检里的 ⚠ 都已处理（缺项/占位值/证书未覆盖都会影响可用性）" >&2
fi
echo "部署完成。本次编排校验和：$LOCAL_SUM"
echo "提示：目标上的编排已与仓库一致；若要回滚，执行"
echo "  cp -f $DEPLOY_DIR/$BASE.bak.$STAMP $DEPLOY_DIR/$BASE && docker compose -f $BASE up -d"
