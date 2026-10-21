# 深瞳 · 智能体镜像：dsh（Web 版）+ xdr 自研插件
#
# 构建统一在 GitHub Actions 完成（根 CI build job 的 "Build & push agent"），
# 本地不构建（项目约定 B 方案）。
#
# 多阶段：
#   builder — 与 CI agent-web / agent-plugins job 完全同命令：
#             dsh monorepo 冻结锁文件安装 + 全量构建；插件不冻结安装 + 构建
#   runtime — 只带产物；把 xdr-ingest bake 进 web profile（link: 绝对路径
#             固定在 /opt/agent/plugins/xdr-ingest）；卷空时由 entrypoint
#             把 bake 好的 profile 种进 DSH_HOME，运行期无需联网装依赖
FROM node:24-bookworm AS builder

RUN corepack enable && corepack prepare pnpm@11.28.5 --activate

# ---- dsh monorepo（上游源码，保持原样）----
WORKDIR /build/dsh
COPY dsh/ ./
RUN pnpm install --frozen-lockfile
# dsh 构建脚本要把 commit 哈希盖进客户端构建环境（DSH_CLIENT_COMMIT_HASH），
# 默认读 git rev-parse——docker 上下文里没有 .git，必须经 build-arg 注入。
# CI 传 ${{ github.sha }}；本地构建不传时用全零占位（合法 hex，标记无版本信息）。
ARG DSH_CLIENT_COMMIT_HASH=0000000000000000000000000000000000000000
RUN pnpm run build

# ---- 自研插件（out-of-tree，与上游物理分离；锁文件尚未入库故不冻结）----
WORKDIR /build/plugins
COPY plugins/ ./
RUN pnpm install --no-frozen-lockfile
RUN pnpm run build

# ============================= runtime ============================
FROM node:24-bookworm-slim AS runtime

# pnpm：bake profile 与运行期自愈都要用；git：dsh 工具链会 shell out；
# tzdata：让 TZ=Asia/Shanghai 真正生效（slim 基线不带时区数据库）
RUN npm install -g pnpm@11.28.5 \
  && apt-get update \
  && apt-get install -y --no-install-recommends git tzdata \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agent
COPY --from=builder /build/dsh ./dsh
COPY --from=builder /build/plugins ./plugins
COPY docker/entrypoint.sh /usr/local/bin/xdr-agent-entrypoint
RUN chmod +x /usr/local/bin/xdr-agent-entrypoint

# bake：以 node 用户把插件装进 web profile，产物归 node 所有，
# 之后 entrypoint 种入卷时运行时用户可直接写（HMR / 插件管理需要）
ENV DSH_HOME=/opt/dsh-home
USER node
RUN node /opt/agent/dsh/apps/cli/lib/bin.js plugin --profile web add link:/opt/agent/plugins/xdr-ingest

# 运行期：数据目录用卷持久化（dsh home：profile、会话历史、插件管理状态）
ENV DSH_HOME=/data/dsh
RUN mkdir -p /data/dsh && chown node:node /data/dsh
VOLUME /data/dsh
EXPOSE 3080

ENTRYPOINT ["/usr/local/bin/xdr-agent-entrypoint"]
