# 深瞳 · OpenCode 免费模型桥接（agent/bridge）

把**隔离运行的 OpenCode**包装成一个 OpenAI 兼容接口，给 dsh 当模型通道。
镜像里同时打进 opencode 二进制，**不依赖宿主机装了什么**；与 agent 作为 sidecar
一起部署，共用网络命名空间。

> 只解决"模型接入"，不改变分析架构：NDR 仍然只发门铃/任务，dsh 仍然自己取证、
> 调 MCP 工具、交回结论。

## 为什么需要它

OpenCode 的免费模型**只允许从 OpenCode 客户端内部调用**，其他客户端（包括直接
用 `Bearer public` 调 `https://opencode.ai/inference/openai/v1`）会被 403/429 拒绝。
所以桥接必须自己拉起一个真正的 `opencode serve`，再把它包装成 OpenAI 接口。

## 结构

```
dsh agent 容器 ──(http://ow-bridge:41980/v1, OpenAI 兼容)──> ow-bridge sidecar
                                                      │ 隔离 XDG + 自带 opencode serve
                                                      └─> opencode.ai 免费模型
```

- `src/main.js`：入口；启动 OpenCode、读免费模型目录、监听回环端口；
- `src/opencode.js`：opencode v2 HTTP API 的最小封装（会话/模型/提示/权限/清理）；
- `src/translate.js`：OpenAI messages/tools ↔ JSON 信封的翻译与校验；
- `src/models.js`：从 `/api/model` 里筛零成本、启用、支持工具的模型；
- `src/server.js`：鉴权、并发/每日预算、`/v1/models`、`/v1/chat/completions`、`/health`。

## 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/health` | 无 | 版本、模型、计数、预算、最近错误（不含密钥） |
| GET | `/v1/models` | Bearer | 当前免费模型（默认只含声明支持工具的） |
| POST | `/v1/chat/completions` | Bearer | 支持 `stream` / `tools` / `tool_choice` |
| POST | `/admin/refresh` | Bearer | 重新读取免费模型目录 |

模型 id 用原始名（如 `deepseek-v4.1-flash-free`），也接受 `opencode/<id>`。

## 安全边界

- 桥接容器只加入 agent 的 compose 网络（不发布宿主机端口），dsh 用服务名访问；
- 默认只监听 `127.0.0.1`，compose 里覆盖为 `0.0.0.0`（仅容器网络可达）；
- 必须带本地 `BRIDGE_API_KEY`，拒绝带浏览器 `Origin` 的请求；
- 容器：非 root、根文件系统只读、`/tmp` tmpfs、`cap_drop: ALL`、无特权；
- 唯一可写卷是 `/data`（隔离的 opencode 配置/缓存/工作目录）；
- OpenCode 权限全 `deny`：模型不能 shell / 读写文件 / 抓网页；
  每次请求一个 session，结束即删；
- 不接触 agent 的 `/data/dsh`、MCP 令牌或 NDR 数据。

## 模型语义

- 客户端（dsh）的 `tools` 原样写进提示词，模型**只能返回 JSON 信封**：
  `{"content":"...","calls":[{"name":"...","arguments":{...}}]}`；
- 工具名/参数不合法会纠正一次（同一 session 追加提示），仍不合格返回 502；
- 模型尝试原生工具会被拒绝（权限 deny + 主动 reject 待审批），只允许把动作作为
  `calls` 交回；
- `usage` 优先取 OpenCode 的 token 计数；拿不到就不返回（不编造）。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `BRIDGE_API_KEY` | 必填 | 本地 Bearer 密钥（dsh 里填同一个） |
| `BRIDGE_PORT` | `41980` | 监听端口（回环） |
| `BRIDGE_DATA_DIR` | `/data` | 隔离目录与卷挂载点 |
| `BRIDGE_MAX_CONCURRENCY` | `2` | 同时进行的上游请求数 |
| `BRIDGE_MAX_REQUESTS_PER_DAY` | `200` | 每日上游请求硬预算；0=不限（不建议） |
| `BRIDGE_TIMEOUT_MS` | `300000` | 单次等待模型完成的上限 |
| `BRIDGE_MODEL_REFRESH_MS` | `600000` | 免费模型目录刷新周期 |
| `BRIDGE_INCLUDE_CHAT_ONLY` | `0` | 是否把不支持工具的免费模型也放出来（实验用） |
| `BRIDGE_OPENCODE_VERSION` | `2.0.18` | 版本校验（镜像里已 pin） |

## 部署（agent 宿主机）

1. 拉镜像（CI 构建产物）：
   ```bash
   docker pull ghcr.io/cxiyuan/sec-agent/shentong-ow-bridge:latest
   ```
2. `.env` 增加：
   ```bash
   OW_BRIDGE_KEY=$(openssl rand -hex 32)
   OW_BRIDGE_DAILY_BUDGET=200
   ```
3. 启动 sidecar（与主 compose 叠加）：
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.bridge.yml up -d
   ```
4. 验证（在 agent 容器里没有 curl，用 healthcheck 或 dsh）：
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.bridge.yml logs --tail 20 ow-bridge
   docker inspect --format '{{.State.Health.Status}}' shentong-agent-ow-bridge-1
   ```
5. dsh 控制台 → 系统 → 模型接入（自定义服务商）：
   - route：`oc-free`
   - 协议：`openai-completions`
   - Base URL：`http://ow-bridge:41980/v1`
   - 模型：`deepseek-v4.1-flash-free`（或 `/v1/models` 里的其他 id）
   - API Key：`OW_BRIDGE_KEY`
6. 项目组织 → 编辑项目 → 模型：
   - 推荐 **付费主 + 免费兜底**：主 `opencode-go/qwen3.8-flash`，备用 `oc-free/deepseek-v4.1-flash-free`；
   - 免费额度耗尽时只会影响兜底路径，不会把主链路拖死。

## 测试

本地纯 Node（不需要 Docker/外网）：

```bash
cd agent/bridge
npm test          # node --test，22 个用例
```

CI：`bridge-test`（语法 + 单测）+ `bridge-build`（构建/推镜像 + `opencode --version` 冒烟）。

## 限制（务必知道）

- **免费额度是硬天花板**：动态、按天/按身份，社区实测十几到几百次请求就会耗尽；
  一个分析任务通常 5~20 次工具往返 = 5~20 次模型请求。免费模型只适合兜底或低优先级任务。
- **限时促销**：免费模型会轮换/下线；`/v1/models` 是实时的，桥接不写死名单。
- **数据留存**：免费模型的数据策略与付费不同；把 NDR 事件数据交给免费模型前，
  要确认客户侧可接受。
- **不要用它规避配额**：桥接只是"让 OpenCode 客户端内部能力可被 dsh 使用"，
  不提供换身份刷额度之类的功能。

## 回滚

- 项目模型改回 `opencode-go/qwen3.8-flash`；
- `docker compose -f docker-compose.yml -f docker-compose.bridge.yml stop ow-bridge`
  （或删掉 `docker-compose.bridge.yml` 后重新 `up -d`）；
- 桥接不写 NDR、不改插件，回滚不影响已有任务与结论。
