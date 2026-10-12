# 深瞳 · NDR 前端（Next.js）—— 使用仓库根作为构建上下文（需 COPY 共享包 packages/ui）
FROM node:20-alpine AS builder
WORKDIR /app
ARG BACKEND_URL=http://backend:8000
ENV BACKEND_URL=$BACKEND_URL

# npm workspaces：根清单 + 共享包 + 两个前端应用（install 需所有 workspace 成员在场）
COPY package.json ./
COPY packages/ui ./packages/ui
COPY ndr/frontend ./ndr/frontend
COPY agent/frontend ./agent/frontend
RUN npm install --no-audit --no-fund

WORKDIR /app/ndr/frontend
RUN npm run build

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/ndr/frontend/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/ndr/frontend/.next ./.next
COPY --from=builder /app/ndr/frontend/next.config.mjs ./next.config.mjs
COPY --from=builder /app/ndr/frontend/public ./public
# 站点强制 HTTPS：TLS 终结（443）+ HTTP 跳转（80）在容器内，应用仍监听 3000（仅容器内部）
COPY ndr/frontend/tls-server.mjs ./tls-server.mjs
COPY ndr/frontend/docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh \
    && apk add --no-cache openssl
EXPOSE 3000 443 80
CMD ["sh", "./docker-entrypoint.sh"]
