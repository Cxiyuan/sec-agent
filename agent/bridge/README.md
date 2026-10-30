# 深瞳 · OpenCode 免费模型桥接（agent/bridge）

把 **宿主机上已有的 OpenCode** 包装成 OpenAI 兼容接口，给 dsh 当模型通道。
与 agent 作为 sidecar 部署（host 网络、只绑 Docker 网关），不修改宿主机 OpenCode
的配置或数据。

> 为什么连宿主机 OpenCode（2026-10-30 实测）：
> - 免费模型资格按“安装身份”算：镜像内新起的隔离 opencode 一律 429，宿主机
>   这个已有安装正常；两边看到的免费模型目录也不一样。
> - 会话权限设成 `deny` 也会触发免费层 429；用 `ask` + 桥接层拒绝审批即可。
> 因此镜像里虽然仍带 opencode 二进制（离线兜底），默认走宿主机服务。

## 结构

```
dsh agent 容器 ──(http://172.20.0.1:41980/v1, OpenAI 兼容)──> ow-bridge (host network)
                                                                  │ 127.0.0.1:49374
                                                                  └─> 宿主机 OpenCode（免费模型）
```

- `src/main.js`：入口；连接 OpenCode、读免费模型目录、监听回环/网关；
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

模型 id 用原始名（如 `mimo-v2.6-flash-free`），也接受 `opencode/<id>`。

## 安全边界

- 桥接进程只监听 Docker 网关 `172.20.0.1`（agent 容器可达，LAN 不可达）；
- 必须带本地 `BRIDGE_API_KEY`，拒绝带浏览器 `Origin` 的请求；
- 容器：非 root、根文件系统只读、`/tmp` tmpfs、`cap_drop: ALL`、无特权；
- OpenCode 会话权限 `ask`：模型想执行原生工具（shell/read/write…）会挂起，
  桥接层每 500ms 轮询审批并**立即拒绝**，只允许把动作作为 `calls` 交给 dsh；
- **不能用 `deny`**：实测会让上游把会话当自动化流量，免费模型直接 429；
- 不修改宿主机 OpenCode 配置文件；只通过它的本地 HTTP API 建会话（结束即删）。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `BRIDGE_API_KEY` | 必填 | 本地 Bearer 密钥（dsh 里填同一个） |
| `BRIDGE_PORT` | `41980` | 监听端口 |
| `BRIDGE_HOST` | `127.0.0.1` | compose 里设为 `172.20.0.1` |
| `BRIDGE_OPENCODE_URL` | 空 | 空=自己拉起隔离运行时；生产填 `http://127.0.0.1:49374` |
| `BRIDGE_OPENCODE_PASSWORD` | 空 | 宿主机 OpenCode 的服务密码（`/root/.config/opencode/service.json`） |
| `BRIDGE_OPENCODE_PASSWORD_FILE` | 空 | 也可从 JSON 文件读取密码（可选） |
| `BRIDGE_OPENCODE_AGENT` | `xdr-bridge` | 连宿主机时设为空，用对方默认 agent |
| `BRIDGE_OPENCODE_PERMISSIONS` | `ask` | `ask` / `none` / `deny`（`deny` 会 429） |
| `BRIDGE_MAX_CONCURRENCY` | `2` | 同时进行的上游请求数 |
| `BRIDGE_MAX_REQUESTS_PER_DAY` | `200` | 每日上游请求硬预算；0=不限（不建议） |
| `BRIDGE_TIMEOUT_MS` | `300000` | 单次等待模型完成的上限 |
| `BRIDGE_MODEL_REFRESH_MS` | `600000` | 免费模型目录刷新周期 |

## 部署（agent 宿主机）

1. `.env`：
   ```bash
   OW_BRIDGE_KEY=$(openssl rand -hex 32)
   OW_BRIDGE_DAILY_BUDGET=200
   # 宿主机 OpenCode 的服务密码（读一次写进 .env；容器非 root 读不了 600 文件）
   OW_BRIDGE_OPENCODE_PASSWORD=$(python3 -c \
     'import json;print(json.load(open("/root/.config/opencode/service.json"))["password"])')
   ```
2. 启动 sidecar（与主 compose 叠加）：
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.bridge.yml up -d
   ```
3. dsh 控制台 → 系统 → 模型接入（自定义服务商）：
   - route：`oc-free`
   - 协议：`openai-completions`
   - Base URL：`http://172.20.0.1:41980/v1`
   - 模型：`mimo-v2.6-flash-free`（或 `/v1/models` 里的其他 id）
   - API Key：`OW_BRIDGE_KEY`
4. 项目组织 → 编辑项目 → 模型：`oc-free/mimo-v2.6-flash-free`。

## 测试

本地纯 Node（不需要 Docker/外网）：

```bash
cd agent/bridge
npm test          # node --test，25 个用例
```

CI：`bridge-test`（语法 + 单测）+ `bridge-build`（构建/推镜像 + `opencode --version` 冒烟）。

## 限制

- **免费额度/资格**：动态、按安装身份/天，免费模型会轮换；一个分析任务通常
  5~20 次工具往返 = 5~20 次模型请求，只适合兜底或低优先级任务。
- **依赖宿主机 OpenCode 服务**：它停了桥接就没有模型；桥接只读它的 API，不改配置。
- **数据留存**：免费模型的数据策略与付费不同；确认客户侧可接受。
- **不要用它规避配额**：桥接只是把 OpenCode 客户端内部能力接到 dsh，不做换身份刷额度。

## 回滚

- 项目模型改回付费 provider；
- `docker compose -f docker-compose.yml -f docker-compose.bridge.yml stop ow-bridge`；
- 桥接不写 NDR、不改插件，回滚不影响已有任务与结论。
