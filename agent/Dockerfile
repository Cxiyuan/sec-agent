# 深瞳 · 智能体镜像：dsh（Web 版）+ xdr 自研插件
#
# 构建统一在 GitHub Actions 完成（根 CI build job 的 "Build & push agent"），
# 本地不构建（项目约定 B 方案）。
#
# 多阶段：
#   builder — 与 CI agent-web / agent-plugins job 完全同命令：
#             dsh monorepo 冻结锁文件安装 + 全量构建；插件不冻结安装 + 构建
#   runtime — 只带产物；把 xdr-ingest bake 进 web profile（file: 快照进
#             profile 自带 store，路径固定在 /opt/agent/plugins/xdr-ingest）；
#             卷空时由 entrypoint 把 bake 好的 profile 种进 DSH_HOME，
#             运行期无需联网装依赖
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
# 部署级技能（项目自带的处置手册/Ndr 工具用法），启动时同步进 DSH_HOME/skills
COPY skills /opt/agent/skills
COPY docker/entrypoint.sh /usr/local/bin/xdr-agent-entrypoint
RUN chmod +x /usr/local/bin/xdr-agent-entrypoint

# 目录准备（必须在切用户之前：/opt 与 / 都归 root，node 用户建不了）：
#   /opt/dsh-home — bake 用的默认 profile 家目录
#   /data/dsh    — 运行期 DSH_HOME 卷挂载点（命名卷首次初始化会继承镜像里的属权）
ENV DSH_HOME=/opt/dsh-home
RUN mkdir -p /opt/dsh-home /data/dsh && chown -R node:node /opt/dsh-home /data/dsh
USER node
# file: 而非 link:：link: 的 symlink 按相对路径记录，bake 在 /opt/dsh-home、
# 运行期卷在 /data/dsh，整体搬迁后相对解析会悬空（CI 冒烟实测过）。
# file: 把插件快照进 profile 自带的 .pnpm store，随卷一起搬迁、自包含。
RUN node /opt/agent/dsh/apps/cli/lib/bin.js plugin --profile web add file:/opt/agent/plugins/xdr-ingest
RUN node /opt/agent/dsh/apps/cli/lib/bin.js plugin --profile web add file:/opt/agent/plugins/xdr-ui
RUN node /opt/agent/dsh/apps/cli/lib/bin.js plugin --profile web add file:/opt/agent/plugins/xdr-agent-pack

# 会话检索 bundle：包本体随 apps/cli 一起装好，这里只把它加进 profile 的激活列表。
# 走 pnpm add 会去 registry 找这个私有 workspace 包（找不到），所以直接改 bake 出的清单；
# 入口脚本刷新 profile 时按并集合并 bundles，不会把它冲掉。
RUN node -e "const fs=require('node:fs');const p='/opt/dsh-home/profiles/web/package.json';const m=JSON.parse(fs.readFileSync(p,'utf8'));m.dsh=m.dsh||{};m.dsh.profile=m.dsh.profile||{};const b=m.dsh.profile.bundles||[];const n='@deepseek-ai/dsh-experimental-session-search';if(!b.includes(n))b.push(n);m.dsh.profile.bundles=b;fs.writeFileSync(p,JSON.stringify(m,null,2)+'\n')"

# 插件指纹：镜像每次重建都会刷新它，入口脚本据此判断卷里的插件副本是不是旧镜像
# 留下的。只比版本号不够——本项目插件版本号长期不变，代码却每次都在变。
RUN cd /opt/dsh-home/profiles/web \
  && find node_modules/@sec-agent -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum \
  | cut -d' ' -f1 > /opt/dsh-home/.plugins.stamp

# 运行期：数据目录用卷持久化（dsh home：profile、会话历史、插件管理状态）
ENV DSH_HOME=/data/dsh
VOLUME /data/dsh
EXPOSE 3080

ENTRYPOINT ["/usr/local/bin/xdr-agent-entrypoint"]
