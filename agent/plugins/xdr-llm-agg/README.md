# xdr-llm-agg — LLM-AGG 专用模型连接器

给分析智能体接 **Free-LLM-API / LLM-API-AGG 聚合网关**的 dsh 适配器。只声明

```
provider route = llm-agg
```

这一条路由；选择其它服务商（DeepSeek 官方、pi-ai 自定义网关…）不受任何影响。

## 为什么不能直接用 llm-pi-ai

聚合网关的智能负载路由依赖**请求级会话标识**：

- `model=auto` 时网关挑选当前最稳的后端；
- 请求头 `x-session-id` 相同的会话粘在同一后端模型（除非它不可用）；
- 并发会话按 session-id 分摊到不同模型。

dsh 已经在 `GenerateOptions.sessionId` 上把会话身份交到适配器边界，但通用
`llm-pi-ai` 适配器只能给服务商配**静态**请求头，没法逐请求写动态头。本插件
自己实现 `LlmAdapter`，在 `stream()` 里把 `sessionId` 写成 `x-session-id`。

## 配置

profile 的 `cordis.patch.yml` 已插好默认数据块（`id: xdr-llm-agg`）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `baseURL` | `http://host.docker.internal:8788/v1` | 网关 `/v1` 根路径 |
| `apiKeyEnv` | `LLM_AGG_API_KEY` | 池 Key 的 credential-ref（存 dsh 凭证库） |
| `models` | `auto` / `free` / `cheap` | 选择器里的模型；也可填显式模型 ID |
| `defaultContextWindow` | `128000` | 未声明上下文的模型的保守值 |
| `maxTokens` | `8192` | 请求未带 `maxTokens` 时的输出上限 |
| `sessionHeader` | `x-session-id` | 会话标识头名（网关读这个） |
| `streamIdleTimeoutMs` | `300000` | 两帧之间的空闲超时 |
| `requestTimeoutMs` | `900000` | 单次请求总时长上限 |

字段全部 **volatile**：控制台（`/xdr/ui` → 系统）保存后下一轮请求立即生效，
无需重启。池 Key 只从 dsh credentials 服务（或同名环境变量）解析，不落
profile 明文、不写日志。

环境变量缝：`LLM_AGG_BASE_URL`（端点默认值）、`LLM_AGG_API_KEY`（无凭证库
时的兜底）。

## 行为

- **请求**：`POST {baseURL}/chat/completions`，`stream:true`，
  `stream_options.include_usage`；只发文本消息与工具声明，图片输入以
  `UNSUPPORTED_CONTENT` 明确失败。
- **会话头**：`options.sessionId` 非空时写 `x-session-id: <sessionId>`；
  xdr-ingest 的分析会话 ID 形如 `xdr-analysis-<task>-<ts>-<n>`。
- **响应**：SSE 翻译成 dsh `StreamChunk`（文本/推理/工具调用增量 + usage +
  finish）；网关忽略 `stream:true` 时按完整响应兜底。
- **失败码**：429→`RATE_LIMIT`、401/403→`INVALID_CREDENTIAL`、402 或额度
  文本→`QUOTA`、5xx→`SERVER`、超时→`TIMEOUT`、网络→`TRANSPORT`、
  空响应→`EMPTY_RESPONSE`（这些码与 dsh 默认重试策略对齐）。
- **推理强度**：本路由不透传 `reasoning_effort`——`auto` 背后可能是不同
  后端，交给网关与后端默认值更稳。

## 控制台

系统页的「服务商预设」里有 **LLM-AGG（智能路由）**：选中后填端点与池 Key，
保存即写入本插件的 volatile 配置 + dsh 凭证库；勾选「设为默认」后，
分析会话默认走 `llm-agg`，会话 ID 自动随请求下发。

## 测试

```
pnpm --filter @sec-agent/xdr-llm-agg test
```

覆盖请求投影、SSE 解帧、流式翻译、usage 归一化与失败分类；不依赖网络或
真实网关。端到端验证在部署机连真实聚合网关完成。
