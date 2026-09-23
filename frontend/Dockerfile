# 深瞳前端镜像（Next.js）
FROM node:20-alpine AS builder
WORKDIR /app
# 后端地址在「构建时」烙进 rewrites（Next 的 rewrites 不读运行时环境变量）
ARG BACKEND_URL=http://backend:8000
ENV BACKEND_URL=$BACKEND_URL
COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/next.config.mjs ./next.config.mjs
COPY --from=builder /app/public ./public
EXPOSE 3000
CMD ["npm", "start"]
