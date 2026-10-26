# agent/ — 深瞳智能体线路

本线路是「深瞳 · 安全分析智能体」的 agent 侧：以 **DeepSeek Harness（dsh）** 为
运行时，全部自研能力以 dsh 插件形态开发。数据面（ES / Redis / 统一 PG）在
`ndr/` 线路，两线路经网络互访。

## 目录

```
agent/
├── dsh/       dsh v0.2.1-rc.2 完整 monorepo（上游源码，保持原样，无 .git）
├── plugins/   自研 dsh 插件（out-of-tree，与上游物理分离）
│   ├── xdr-ingest/   NDR 门铃/摘要 + 事件分析 ID + 冷热两级缓存 + 领取分析循环
│   └── xdr-ui/       登录鉴权的分析工作台 /xdr/ui（admin/admin123）
├── skills/    调查方法论 / 角色模板（prompt 资产）
├── docker/    容器入口脚本
├── Dockerfile         智能体镜像（多阶段，构建统一在 GitHub Actions）
├── docker-compose.yml 智能体线路编排
└── .env.example       环境变量示例
```

## 与 ndr 线路的对接

| 方向 | 通道 | 配置 |
|---|---|---|
| NDR → agent | 检测器命中后 HTTP 推送摘要 | ndr 侧 `ST_AGENT_PUSH_URL=http://<宿主机IP>:3080/xdr/ingest/digests`，token 与 agent 侧 `AGENT_PUSH_TOKEN` 一致 |
| agent → 数据面 | 统一 PG（冷库 + 判重缓存落盘） | `XDR_INGEST_PG_URL`，默认宿主机 ndr 栈发布的 5432 |
| agent → 数据面 | NDR MCP 服务取数（规划中） | ndr 侧 `ndr-mcp:8090/mcp` |

插件自带两级缓存（内存热层 + PG 冷层），**不需要 Redis**；分析结果的唯一持久化
载体是统一 PG（表 `xdr_ingest_analysis`，插件启动时自建）。

## 部署

镜像由根 CI 的 build job 构建并推送 GHCR（`ghcr.io/cxiyuan/sec-agent/
shentong-agent:latest`），本地不构建（项目约定 B 方案）。

```sh
cp .env.example .env   # 至少填 AGENT_PUSH_TOKEN（与 NDR 侧一致）
docker compose up -d            # 拉取 GHCR 镜像
docker compose up -d --build    # 本地源码构建（开发调试）
```

起来后：

- Web 界面：`http://<宿主机IP>:3080`（原生 dsh 界面：**登录页账号密码
  admin / admin123**，环境缝 `DSH_WEB_AUTH_USER` / `DSH_WEB_AUTH_PASSWORD`；
  首次打印的带 token URL 在容器日志里，`docker compose logs agent`）
- 分析工作台：`http://<宿主机IP>:3080/xdr/ui`（登录鉴权，同一组凭据；
  运行总览 + PG 历史分析记录 + 「立即领取」；原生界面右下角有跳转角标）
- 连通性自检：`curl -H "Authorization: Bearer $AGENT_PUSH_TOKEN" \
  http://<宿主机IP>:3080/xdr/ingest/ping` → `ok`
- 分层缓存观测：同 `/xdr/ingest/stats`（热层/冷层条数、命中/晋升/降级计数）

**信任围栏**：dsh 只放行 Host 为 loopback、容器绑定 IP、或 `--trusted-host`
声明值的请求。浏览器经 docker 发布口访问时 Host 是宿主机名/IP，需在
`AGENT_TRUSTED_HOSTS` 里声明（默认已含 `host.docker.internal`；局域网其他
机器访问再加宿主机 LAN IP 或域名）。

**跨机部署（agent 与 NDR 不在一台）**：NDR 的 Postgres 只绑回环（仓库红线
`tests/py/test_deploy_exposure.py`），agent 侧要连统一 PG 必须在 agent 宿主机上
建 SSH 隧道，把 NDR 的 `127.0.0.1:5432` 映射到 `172.17.0.1:5432`，`.env` 里
`XDR_INGEST_PG_URL` 保持 `host.docker.internal`。隧道要 systemd 常驻（示例见
`.env.example` 对应注释）；隧道断了插件会降级成纯内存去重并打日志，不会崩。

## 开发

见 `plugins/README.md` 与 `plugins/xdr-ingest/README.md`。约定：本地不装依赖
不构建（`pnpm install`/build 全在 CI），本地只写代码改配置；一切逻辑进插件包，
组合只写 patch 声明，不改 `dsh/` 内任何上游文件。
