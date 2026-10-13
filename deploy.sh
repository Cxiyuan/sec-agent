#!/bin/sh
# 深瞳 · 一键部署（**编排文件随代码一起部署**，避免"改了仓库、服务器没生效"）
#
# 背景（2026-10 实机事故）：把访问方式改成强制 HTTPS 时，只改了仓库里的编排文件，
# 而服务器上的那份是单独放过去的 —— 部署只拉了镜像、重建容器仍用旧文件，端口映射还是旧的
# `3000:3000`，于是 443 从未对外，局域网打开控制台一直「响应时间过长」。
# 所以本脚本把「同步编排文件」作为部署的第一步，并且**每一步都要校验结果**（拉取失败不再被吞、部署后核对落地）。
#
# 为什么脚本里没有任何主机/目录/地址：这些是环境相关的。全部由环境变量传进来：
#   DEPLOY_HOST   必填。目标主机（IP 或域名），例如 10.1.2.250
#   DEPLOY_DIR    目标上的部署目录，默认 /opt/shentong-ndr
#   DEPLOY_SSH    可选。用于连接的 ssh 命令前缀，默认 ssh
#                 （需要密码认证时传 "sshpass -p <口令> ssh" —— 口令不进仓库、也不进命令行历史以外的任何地方）
#   COMPOSE_FILE  可选。要同步的编排文件，默认 ndr/docker-compose.deploy.yml
#   SERVICES      可选。只重建这些服务（空格分隔），默认全部
#   PULL_RETRIES  可选。拉取重试次数，默认 5（现场 DNS 到镜像仓库不稳定，实测约一半概率超时）
#
# 用法（在仓库根执行）：
#   DEPLOY_HOST=<主机> [DEPLOY_SSH="sshpass -p <口令> ssh"] sh deploy.sh
#   DEPLOY_HOST=<主机> SERVICES="frontend" sh deploy.sh          # 只更前端
#
# 回滚：脚本每次都会把目标上的旧文件备份成 <文件名>.bak.<时间戳>；出错时按提示恢复即可。
set -eu

DEPLOY_HOST="${DEPLOY_HOST:-}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/shentong-ndr}"
DEPLOY_SSH="${DEPLOY_SSH:-ssh}"
COMPOSE_FILE="${COMPOSE_FILE:-ndr/docker-compose.deploy.yml}"
SERVICES="${SERVICES:-}"
PULL_RETRIES="${PULL_RETRIES:-5}"

[ -n "$DEPLOY_HOST" ] || { echo "缺少 DEPLOY_HOST（目标主机）" >&2; exit 2; }
[ -f "$COMPOSE_FILE" ] || { echo "找不到编排文件：$COMPOSE_FILE" >&2; exit 2; }

# deploy <远程命令>：统一走 DEPLOY_SSH（前缀里可能带认证工具）
deploy() {
  # shellcheck disable=SC2086  # DEPLOY_SSH 需要按空格拆成命令 + 参数
  $DEPLOY_SSH -o StrictHostKeyChecking=no "$DEPLOY_HOST" "$@"
}

BASE=$(basename "$COMPOSE_FILE")
STAMP=$(date +%Y%m%d-%H%M%S)
LOCAL_SUM=$(sha256sum "$COMPOSE_FILE" | awk '{print $1}')

echo "== 0) 目标检查 =="
deploy "test -d '$DEPLOY_DIR' || { echo '部署目录不存在: $DEPLOY_DIR' >&2; exit 2; }"
echo "  主机=$DEPLOY_HOST 目录=$DEPLOY_DIR 编排=$COMPOSE_FILE"

echo "== 1) 备份目标上的旧编排（回滚用）=="
deploy "cd '$DEPLOY_DIR' && cp -f '$BASE' '$BASE.bak.$STAMP' && ls -l '$BASE.bak.$STAMP' | awk '{print \$NF}'"

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
if deploy "curl -sk -o /dev/null -w '%{http_code}' --max-time 10 https://127.0.0.1/ | grep -q 200"; then
  echo "  前端本机 HTTPS 探活：200 ✓"
else
  echo "  前端本机 HTTPS 探活失败：请查 docker logs 前端容器（证书/端口/入口脚本）" >&2
fi
echo
echo "部署完成。本次编排校验和：$LOCAL_SUM"
echo "提示：目标上的编排已与仓库一致；若要回滚，执行"
echo "  cp -f $DEPLOY_DIR/$BASE.bak.$STAMP $DEPLOY_DIR/$BASE && docker compose -f $BASE up -d"
