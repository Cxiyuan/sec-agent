# syntax=docker/dockerfile:1.7
# 深瞳 XDR · OpenCode 免费模型桥接（自研，随 agent 部署）
#
# 设计要点：
# - opencode 二进制**打进镜像**，版本 pin 死，不依赖宿主机装了什么；
# - 桥接代码零运行时依赖（Node 内置 fetch），构建阶段不需要 npm install；
# - 非 root、只读根文件系统（compose 里再收紧），唯一可写目录是 /data 卷。
#
# 构建只在 GitHub Actions 执行（见 .github/workflows/ci.yml 的 bridge-build）。

FROM node:22-bookworm-slim

# opencode 官方 npm 包（MIT）。版本与 sha512 完整性都固定，升级走一次提交。
ARG OPENCODE_VERSION=2.0.18
ARG OPENCODE_INTEGRITY=""

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /opt/opencode /tmp/opencode-pkg \
 && curl -fsSL --retry 3 -o /tmp/opencode-pkg/cli.tgz \
      "https://registry.npmjs.org/@opencode/cli-linux-x64/-/cli-linux-x64-${OPENCODE_VERSION}.tgz" \
 && if [ -n "$OPENCODE_INTEGRITY" ]; then \
      node -e "const fs=require('node:fs'),c=require('node:crypto');const got='sha512-'+c.createHash('sha512').update(fs.readFileSync('/tmp/opencode-pkg/cli.tgz')).digest('base64');if(got!==process.env.OPENCODE_INTEGRITY){console.error('opencode 包完整性校验失败',got);process.exit(1)}" ; \
    else \
      echo "WARN: 未提供 OPENCODE_INTEGRITY，跳过完整性校验（构建时应传入）" >&2 ; \
    fi \
 && tar -xzf /tmp/opencode-pkg/cli.tgz -C /tmp/opencode-pkg package/bin/opencode \
 && mv /tmp/opencode-pkg/package/bin/opencode /opt/opencode/opencode \
 && chmod 0755 /opt/opencode/opencode \
 && rm -rf /tmp/opencode-pkg \
 && /opt/opencode/opencode --version

ENV NODE_ENV=production \
    BRIDGE_HOST=127.0.0.1 \
    BRIDGE_PORT=41980 \
    BRIDGE_DATA_DIR=/data \
    BRIDGE_OPENCODE_BIN=/opt/opencode/opencode \
    BRIDGE_OPENCODE_VERSION=${OPENCODE_VERSION} \
    HOME=/data/home

WORKDIR /app
COPY package.json /app/package.json
COPY src /app/src

# /data 由命名卷挂载；镜像里先建好并让 node 拥有，卷首次创建时会继承属主。
RUN mkdir -p /data /data/home \
 && chown -R node:node /app /data

USER node

EXPOSE 41980

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.BRIDGE_PORT||41980)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "/app/src/main.js"]
