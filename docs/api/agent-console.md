# 智能体控制台（xdr-ui）HTTP 接口

> 生成时间：2026-10-28（P2 多项目 + P3 分析过程 + P4 脚本管理）
> 适用：智能体控制台页面开发（运行总览 / 项目组织 / 分析过程 / 分析记录 / 分析脚本 / 配置）。
> 数据来源：xdr-ingest 插件（同进程服务 `xdrIngest`），**所有数据按项目组织隔离**。

---

## 一、通用约定

| 项 | 说明 |
| --- | --- |
| 基路径 | 控制台挂载路径（默认 `/`，反向代理下可能是 `/xdr/`）；下文用 `{BASE}` 表示 |
| 鉴权 | 登录后 Cookie（`dsh_auth` 之类，由 dsh-host-webserver 下发）。未登录一律 **401**，前端跳 `{BASE}/login` |
| 方法 | 只读用 `GET`；写操作 `POST`（部分用 `DELETE`）；`405` = 方法不对 |
| 项目参数 | 所有**数据类**接口都接受 `?project=XXXXXXXX`（NDR 授权ID，8 位大写字母+数字）。不传 = 默认项目（单项目部署等价于原来）；传了不存在的项目 = 该接口返回空数据 |
| 错误体 | `{ok:false, error:"中文原因"}`；列表类接口降级为 `{available:false, ...}` 而不是 5xx |
| 时间 | ISO8601 字符串（UTC），前端自行本地化 |

> 项目ID 从哪来：NDR 控制台「配置管理 → 系统授权」页显示，接口是 NDR 的
> `GET /api/system/license` → `{auth_id, source, source_label, stable, note}`。
> 详见 [NDR 接口文档](./README.md)。

---

## 二、项目组织（多项目）

一个 agent 可以接多台 NDR；**每台 NDR = 一个项目**，项目主键就是 NDR 的授权ID。
项目之间数据完全隔离（结论复用、脚本、抑制记忆、分析过程、结论留档、运行参数）。

### `GET {BASE}/api/projects`

```json
{
  "available": true,
  "projects": [
    {
      "projectId": "ZPL6QQLG",
      "name": "南充职业技术学院",
      "mcpUrl": "http://ndr-mcp:8090/mcp",
      "mcpToken": "stmcp_****",
      "pushToken": "****",
      "enabled": true,
      "status": "ok",
      "statusDetail": "",
      "lastCheckedAt": "2026-10-28T12:00:00.000Z",
      "createdAt": "2026-10-28T10:00:00.000Z",
      "updatedAt": "2026-10-28T12:00:00.000Z"
    }
  ]
}
```

`status` 取值：

| 值 | 含义 | 界面建议 |
| --- | --- | --- |
| `ok` | 校验通过、领取循环在跑 | 绿色「分析中」 |
| `unchecked` | 还没校验 / 没配 MCP 令牌 | 灰色「待校验」 |
| `auth_mismatch` | NDR 返回的授权ID 与项目ID 不一致 | **红色报警**：改绑定ID 或核对填错的项目 |
| `unreachable` | MCP 连不上 | 橙色「不可达」 |
| `disabled` | 项目被停用 | 灰色「已停用」 |

### `POST {BASE}/api/projects` — 新增 / 编辑

请求体：

```json
{
  "projectId": "ZPL6QQLG",
  "previousId": "OLDID234",
  "name": "南充职业技术学院",
  "mcpUrl": "http://172.16.196.77:8090/mcp",
  "mcpToken": "stmcp_xxx",
  "pushToken": "推送令牌（与 NDR agent_push.token 一致）",
  "enabled": true
}
```

- `projectId`：**必填**，8 位大写字母或数字（与 NDR 授权ID 完全一致）；不合法 → `400`
- `previousId`：编辑时如果改了授权ID，把它原来的 ID 填进来 → 视为"换绑"，旧项目行删除（数据保留在旧项目下，不自动迁移）
- `mcpUrl`：必填，必须 `http(s)://`；一般是 NDR 的 MCP 地址（`http://<NDR>:8090/mcp`）
- `mcpToken`：MCP 令牌（`stmcp_` 开头）；留空 = 只收门铃不分析
- `pushToken`：门铃推送令牌；多项目下**每个项目一个**，agent 按它路由门铃

响应：`{ok:true, project:{...}}`；校验不过 `{ok:false, error:"..."}`（项目仍会落库，方便改完再校验）。

保存后行为：立即拉起该项目自己的领取循环；校验不通过（授权ID 对不上 / NDR 不可达）则只落库并标状态，**不会**误用别的项目的数据。

### `POST {BASE}/api/projects/{projectId}/verify` — 手动复核

重新调 NDR 的 `server_info` 核对授权ID：一致 → 起循环并置 `ok`；不一致 → 停掉该项目并置 `auth_mismatch`。
响应 `{ok:true, project:{...}}`；项目不存在 → `404`。

### `DELETE {BASE}/api/projects/{projectId}`

删除项目与运行时（历史数据仍留在库里，只是不再展示）。`{ok:true}` / `404` / `400`（ID 格式不对）。

---

## 三、分析过程（P3）

数据来自 agent 自己的**过程索引**（任务 → 会话）+ DSH 会话日志（时间线）。
运行中的会话可以轮询拿增量。

### `GET {BASE}/api/processes`

查询参数：`limit`（默认 20，上限 200）、`offset`、`q`（搜任务ID/对象/模型）、`outcome`、`project`。

```json
{
  "available": true,
  "total": 128,
  "items": [
    {
      "taskId": "a2e55326-8c85-4894-8a03-efc48cc970b9",
      "sessionId": "xdr-analysis-a2e55326-...-25",
      "kind": "hit",
      "subject": "10.90.130.102",
      "model": "minimax/MiniMax-M2.5",
      "startedAt": "2026-10-28T13:38:50.000Z",
      "endedAt": "2026-10-28T13:52:10.000Z",
      "outcome": "done",
      "toolsUsed": 12,
      "durationMs": 800000,
      "verdict": "false_positive",
      "note": ""
    }
  ]
}
```

`outcome`：`running`（在跑）/ `done` / `reused`（复用旧结论，没起会话）/ `suppressed`（被抑制跳过）/ `deferred`（没交回，已延后）/ `failed`（会话出错）。

### `GET {BASE}/api/processes/{taskId}`

详情 + **时间线首段**（少一次往返）：

```json
{
  "entry": { "taskId": "...", "sessionId": "...", "outcome": "done", "...": "同列表" },
  "timeline": { "ok": true, "sessionId": "...", "running": false, "events": [], "tools": [], "tokens": {}, "nextSeq": 42 }
}
```

### `GET {BASE}/api/processes/{taskId}/events?after={nextSeq}`

时间线（增量）：

```json
{
  "ok": true,
  "sessionId": "xdr-analysis-...-25",
  "running": true,
  "startedAt": "2026-10-28T13:38:50.000Z",
  "updatedAt": "2026-10-28T13:52:10.000Z",
  "events": [
    { "seq": 12, "time": 1793165930966, "kind": "thinking", "label": "思考", "detail": "先看连接状态…", "turn": 1, "step": 6, "tokens": 0, "isError": false },
    { "seq": 13, "time": 1793165931000, "kind": "tool", "label": "调用 mcp__ndr__search_events", "detail": "{\"filters\":{...}}", "turn": 1, "step": 6, "tokens": 0, "isError": false },
    { "seq": 14, "time": 1793165931500, "kind": "tool_result", "label": "工具返回", "detail": "{\"returned\":5}", "turn": 1, "step": 6, "tokens": 0, "isError": false },
    { "seq": 15, "time": 1793165932000, "kind": "usage", "label": "token 用量", "detail": "输入 12000 / 输出 800", "turn": 1, "step": 6, "tokens": 12800, "isError": false }
  ],
  "tools": [{ "name": "mcp__ndr__search_events", "count": 3, "errors": 0, "totalMs": 1800 }],
  "tokens": { "input": 12000, "output": 800, "total": 12800 },
  "nextSeq": 15,
  "truncated": false
}
```

前端用法：
- 首次打开用详情里的 `timeline`；`running=true` 时每 2~3 秒带上一次的 `nextSeq` 轮询，把新事件追加到列表；
- `kind` → 渲染样式：`task`（下发任务）/ `thinking` / `assistant` / `tool` / `tool_result` / `usage` / `error` / `turn`；
- `isError=true` 标红（`error` 事件带模型侧报错原文，例如配额 429）；
- 帧内最多 400 条（`truncated=true` 表示更早的被裁掉，需要完整日志去「原始会话界面」）。

---

## 四、分析记录（结论留档）

### `GET {BASE}/api/conclusions?limit=&offset=&q=&project=`

```json
{
  "available": true,
  "total": 352,
  "entries": [
    {
      "id": "c-1",
      "taskId": "…",
      "kind": "hit",
      "subjectKind": "ip",
      "subject": "203.0.113.7",
      "verdict": "false_positive",
      "confidence": 0.86,
      "summary": "业务正常流量",
      "findings": {},
      "evidenceRefs": ["es:…"],
      "toolsUsed": 12,
      "durationMs": 4200,
      "reused": false,
      "reusedFrom": "",
      "terminalReason": "concluded",
      "createdAt": "2026-10-28T02:00:00Z"
    }
  ]
}
```

`verdict` 词表：`true_positive / false_positive / benign / suspicious / inconclusive`。
`reused=true` 的行是复用旧结论，不计入成本统计。

### `GET {BASE}/api/conclusions/{id}` → `{entry}` / 404

---

## 五、分析脚本（P4）

模型在分析中写的脚本存在这里；控制台可以看、改、停用、删除。控制台**不执行**脚本。

| 接口 | 说明 |
| --- | --- |
| `GET {BASE}/api/scripts?q=&limit=&offset=&project=` | `{available,total,items[]}`，item 见下 |
| `GET {BASE}/api/scripts/{nameOrId}?project=` | `{entry}` / 404 |
| `POST {BASE}/api/scripts` | 新建/编辑（同名覆盖），body 见下；非法 JSON 400，体过大 413 |
| `POST {BASE}/api/scripts/{nameOrId}/enabled` | body `{enabled:false}`；停用后模型侧 find/get 不再返回（记录保留） |
| `DELETE {BASE}/api/scripts/{nameOrId}` | 删除 |

```json
{
  "id": "s-1",
  "name": "ssh-timeout-scan",
  "scenario": "什么场景用、输入什么、产出什么（检索主要依据）",
  "language": "bash",
  "tags": ["ssh"],
  "variables": { "TARGET": { "说明": "目标 IP", "默认": "" } },
  "notes": "依赖 jq",
  "code": "…",
  "origin": "console",
  "enabled": true,
  "usageCount": 3,
  "createdAt": "…",
  "updatedAt": "…",
  "updatedBy": "console"
}
```

`origin`：`agent`（模型保存）/ `console`（控制台新建）。两者对模型等价。

---

## 六、运行观测与参数

| 接口 | 说明 |
| --- | --- |
| `GET {BASE}/api/overview` | `{available, status, cache, conclusions}`；`status.projects` 是全部项目运行态 |
| `GET {BASE}/api/settings?project=` | 当前生效运行参数 `{poll_seconds, max_concurrent, claim_limit, store}` |
| `POST {BASE}/api/settings?project=` | body 同上（可只传要改的键）；校验失败 400 |
| `POST {BASE}/api/wake?project=` | 手动叫醒一次领取（等同一记门铃）；`{accepted:true/false}` |
| `GET {BASE}/api/analyses` | 旧摘要缓存（回滚专用，新架构下为空，**不要用于新页面**） |

---

## 七、门铃接收（agent 侧 webhook，供 NDR 配置参考）

`POST {BASE}/xdr/ingest/digests`（实际是 `/xdr/ingest` 基路径 + `/digests`）

- `Authorization: Bearer <pushToken>`：**每个项目一个推送令牌**，agent 按令牌路由到对应项目的领取循环；不认识的令牌 → 401
- 载荷（NDR → agent，只发门铃，不含事件数据）：

```json
{ "doorbell": { "project": "ZPL6QQLG", "queue_len": 12, "top_kind": "hit",
                "max_strength": 0.82, "watermark": "…", "ts": "2026-10-28T12:00:00Z" } }
```

- `project` 与令牌所属项目不一致 → agent 停用该项目并告警（`auth_mismatch`）
- 回执 2xx = 已收；门铃格式不对 400；内部错误 500（NDR 会重推，幂等）
- `GET {BASE}/xdr/ingest/ping` 连通性自检；`GET {BASE}/xdr/ingest/status` 运行快照
