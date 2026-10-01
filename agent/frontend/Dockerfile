# 深瞳 · Agent 前端（Next.js）—— 使用仓库根作为构建上下文（需 COPY 共享包 packages/ui）
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

WORKDIR /app/agent/frontend
RUN npm run build

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/agent/frontend/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/agent/frontend/.next ./.next
COPY --from=builder /app/agent/frontend/next.config.mjs ./next.config.mjs
COPY --from=builder /app/agent/frontend/public ./public
EXPOSE 3000
CMD ["npm", "start"]
