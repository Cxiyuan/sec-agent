# @sec-agent/xdr-ingest — NDR 摘要接收插件

首个 XDR 自研 dsh 插件：接收 NDR 检测器 HTTP 推送的聚合摘要，为每条摘要生成
**内容派生的事件分析 ID**，命中分析缓存则直接复用结果并累计次数，未命中才进入
分析——避免重复分析同类事件。

## 事件分析 ID 机制（核心设计）

指标与 NDR 摘要指纹（`ndr/backend/app/detector/fingerprint.py`）采用同一套内容
元组，但**去掉 30 分钟时间桶**：

```
NDR 指纹   = sha256("{rule}|{src}|{桶起点}|{dsts}|{ports}|{etypes}")[:32]   ← 回答"本窗口是否新事件"
事件分析ID = "EA-" + sha256("{rule}|{src}|{dsts}|{ports}|{etypes}")[:32]   ← 回答"跨窗口是否同类事件"
```

- **参与身份的指标**：规则名、源 IP、目标集合（≤20）、端口集合（≤20）、事件类型
  集合（≤10）；排序规范化逐字节对齐 NDR 的 `sorted(str(x))`，日志并排可对照。
- **刻意排除的易变字段**：count、first_seen/last_seen、samples、real_client_ips
  （XFF 随客户端变化）、proxied/conn_states（随路径翻转）、rule_severity。
- **复用有效期**：结果默认 24h（`resultTtlHours` 可调），过期重分析但累计
  occurrences/firstSeen 保留——「同类事件反复出现」这个信号永不丢失。

## HTTP 契约（对齐 ndr/backend/app/detector/push.py）

| 端点 | 方法 | 说明 |
|---|---|---|
| `{basePath}/digests` | POST | 批量接收 `{"items":[{event_id,fingerprint,digest}]}`，**2xx 即回执** |
| `{basePath}/ping` | GET | NDR 连通性自检（把推送地址的 `/digests` 换成 `/ping` 即此端点） |
| `{basePath}/stats` | GET | 缓存规模与计数（分析/复用/重分析次数） |

响应语义与 NDR 重试分类对齐：

- 鉴权失败 / 载荷坏 / 超限 → **4xx**（NDR 判永久失败，立刻暴露配置错误，不空转）
- 内部分析出错 → **500**（NDR 稍后重推整批；判重缓存幂等，重推零副作用）
- 内容无法识别的单条 → 200 回执里逐条标注 `rejected`（其余照常处理）

NDR 侧配置（`system_config` 键 `agent_push.params`）：URL 指向
`http://<agent-host>:<dsh 端口>/xdr/ingest/digests`，token 与插件 `token` 一致。

## 配置

| 字段 | 默认 | 说明 |
|---|---|---|
| `basePath` | `/xdr/ingest` | 路由基路径（刻意避开 dsh 的 `/api` 前缀） |
| `token` | 必填 | Bearer token；留空插件**拒绝加载**（不收无鉴权的安全事件） |
| `maxBodyBytes` | 4 MiB | 请求体上限 |
| `resultTtlHours` | 24 | 分析结果有效期 |
| `maxEntries` | 20000 | 缓存容量，超出淘汰最久未见的记录 |

## 安装与挂载

```sh
dsh plugin install link:/path/to/agent/plugins/xdr-ingest
# 或在 profile 依赖里声明 link: 路径；bundle patch（cordis.patch.yml）自动生效
```

token 默认从 `XDR_INGEST_TOKEN` 环境变量读取（bundle patch 里的 `!!js` 缝），
也可在 profile patch / 设置页写定值。

## 当前限制与后续

- **v0 分析器是启发式**（规则关键词 + 端口广度），P1 换 LLM 分析器（同签名替换）。
- **缓存是进程内存**：重启丢结果与统计（NDR 重推自动重建）；P2 接 `ctx.storageDomain`。
- **LLM 分析入口**：P1 经 dsh `webhookRuntime` 为缓存未命中的事件创建分析
  Session——运行时明确不做判重（"rules that need idempotency own it"），本插件的
  分析 ID 缓存正是那道 idempotency 闸门。

## 开发

```sh
pnpm install          # CI 里执行（B 方案：本地不装依赖）
pnpm run typecheck    # tsc --noEmit
pnpm test             # node --test（零运行时依赖，本地可用 node 22.6+ 直接跑）
pnpm run build        # tsc 产出 lib/ 与 lib/types/
```

本地不装依赖时，纯逻辑测试可直接跑：
`node --experimental-strip-types --test tests/identity.test.ts tests/cache.test.ts tests/handler.test.ts`
