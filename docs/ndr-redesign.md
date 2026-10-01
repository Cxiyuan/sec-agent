# NDR 改造方案：采集 → 归一化 → 过滤 → 检测 → 推送智能体

状态：**第 1~7 期已实施完成**（监控网段 / 归一化前置 / MCP 服务 + 智能体切到 MCP / 过滤规则 / HTTP 推送智能体 / Wazuh 4.14 集成与容量 / 界面整理，代码与门禁均已过、单进程与纸面实测通过，**待实机验收**——第 2、5、6 期的容器侧与真实流量未跑过，见各期末尾与第 8 节开放问题 6）。全新服务器环境部署，无历史数据迁移。
范围：`ndr/`（主改）+ `agent/`（接收端与 ES 文档形态同步改）

---

## 1. 目标（用户需求原文要点）

- NDR 的功能边界：**采集 Zeek/Wazuh 原始数据 → 推入 Logstash 处理并落库 Elasticsearch 存储**。
- Logstash 对数据进行处理过滤，并**完成字段归一化**；过滤规则在**用户界面**定义。
- 过滤后的数据推送给**规则检测器**做安全分析；匹配事件触发后推送给智能体（**网络推送**）。
- Elasticsearch **直接落库未过滤的全量数据**。
- 集成 **Wazuh 4.14**（不要 wazuh-dashboard）；为 Zeek / Wazuh / Logstash / Elasticsearch 提供管理界面。

## 2. 已定决策（用户拍板）

### 采集与归一化

| # | 问题 | 结论 |
|---|---|---|
| 1 | 过滤语义 | **两种规则分开**：① **监控网段**——Zeek 抓包层（BPF），一行一条网段/IP，只抓这些，其余丢弃；② **过滤规则**——已知某些固定 IP/端口/内容无分析价值时编写，手动精准降噪、减轻分析压力 |
| 2 | 原「分析网段」（AnalysisScope） | 并入监控网段，同一套概念 |
| 3 | 监控网段的作用面 | 同一份列表**同时喂** `bpf_filter`（只抓这些）与 `local_nets`（Zeek 内部/外部判定），因为规则里的 `src_internal` / `dst_internal` 依赖后者 |
| 4 | 归一化位置 | `normalizer.py` 提到 Logstash **之前**，由它完成字段归一化 |
| 5 | normalizer 接口 | **B**：Filebeat `redis` 输出 → normalizer 消费并 ack → Logstash `http` 输入 |
| 6 | Wazuh | 仓库内起 `wazuh-manager` 4.14，**不含** indexer / dashboard |
| 7 | Wazuh 采集范围 | **告警 `alerts.json` + 全量日志 `archives.json`**（manager 需开 `logall` / `logall_json`，Filebeat 侧开 archives 输入）。数据量显著上升，容量单列评估 |
| 8 | Wazuh 管理深度 | **通过 Wazuh API(55000) 管 agent 注册与规则下发**（不只是只读状态）：后端经 Basic 换 JWT、token 过期需刷新，界面可列 agent / 下发规则文件并校验生效；**凭据存 `SystemConfig` 表、界面可配**（改完即时生效，不必重启容器），回显脱敏 |

### 存储与字段

| # | 问题 | 结论 |
|---|---|---|
| 9 | ES 文档形态 | **只存归一化后的文档**，智能体侧同步改。另有两条落地约定：只输出**非空字段**（避免大量 null 撑爆 mapping），原始文档整份进 `raw` |
| 10 | ES 索引名 | 不再沿用 `zeek-*` / `wazuh-alerts-*` 两族，改用**统一索引族 `shentong-events-*`**（按日期滚动），智能体只面对一个索引模式 |
| 11 | 过滤条件字段 | 源/目的 **地址 + 端口**，**再加协议内容字段**（`uri_path` / `host` / `user_agent` / `body` / `command` / `query` 等），操作符含「包含」与「正则」 |
| 12 | URL 解码语义 | 现在规则引擎（Python）对 `contains`/`regex` 自动做 URL 解码，Logstash 不会。**由 normalizer 归一化时解码干净**，保证检测器与过滤器行为一致 |

### 投递与回执

| # | 问题 | 结论 |
|---|---|---|
| 13 | 投递智能体 | **换掉 Redis 改 HTTP**；推送地址在 Web 界面配置（要能推给远程/异构的接收方） |
| 14 | 可靠性 | **要持久化重试**（失败落盘/队列，后台重发） |
| 15 | 回执形式 | **用 HTTP 响应当回执**：NDR POST → agent 返回 200 + 「已收到」。不需要反向通道，agent 也不必知道 NDR 地址 |
| 16 | 判重责任 | **移到智能体侧**。NDR 生成**事件ID + 指纹**放进载荷；智能体收到先查表，近期已分析过就只累加计数、不进分析流程 |
| 17 | 事件ID / 指纹 | **事件ID = 每次投递生成 UUID**（追踪与回执对应）；**指纹 = 确定性哈希**（沿用现在 NDR `digest_fingerprint` 的算法，作判重键） |
| 18 | 判重窗口 | ~~默认 7 天~~ → **实施结果**：判重键 = 事件组指纹（IP 集合 + `group_bucket_minutes` 时间桶，默认 30 分钟）+ Redis 占位 TTL 两个桶；与保留期无关（见 §8.1） |
| 19 | Logstash → 检测器 | **继续走 Redis**（`shentong:events:raw`），本次只改「检测器 → 智能体」那一跳 |

### 智能体接口（MCP）

| # | 问题 | 结论 |
|---|---|---|
| 20 | NDR 对外接口 | **提供完整 MCP server** 供智能体调用：分析事件时的查询、调查、分析端点（详见第 6 节） |
| 21 | 能力范围 | **只读 + 写回结论**：查询/调查工具只读；另开一组把调查结论写回 NDR（标记已分析 / 定级 / 结论摘要），NDR 界面可见。**不给管理动作**——智能体不能改监控网段、过滤规则，也不能启停规则 |
| 22 | 托管方式 | **独立 MCP 服务**（独立进程/容器），不挂在 NDR 后端进程上 |
| 23 | 认证 | **令牌校验**；令牌由 **NDR Web 界面**生成与吊销（只完整显示一次，库里存哈希） |
| 24 | 智能体数据访问 | **完全走 MCP，不再直连 ES**：`agent/backend/app/investigation/es_query.py` 的 ES 查询整体退役，改由 MCP 工具承担 |

### 部署前提：全新服务器环境

现网已下线，改造后将在**全新服务器环境**部署，ES 里没有需要兼容的历史数据。因此**不存在新旧格式并存的问题**，也不需要任何数据迁移、双查兜底或过渡期代码 —— 智能体一律按新字段路径查新索引即可。

### 两条已确认的既有事实

- **智能体没有自己的 Redis / ES**：`agent/backend/app/config.py:38-40` 的 `ST_REDIS_URL` / `ST_CELERY_BROKER_URL` / `ST_CELERY_RESULT_BACKEND` 全部指向 `NDR_REDIS_URL`（`/0`、`/1`、`/2`）。**ES 这一侧的直连由第 6 节的 MCP 彻底切断**（智能体从此不需要 ES 地址）；剩下的只有 Celery broker/backend 仍在用 NDR 的 Redis ——「推送改 HTTP」解不掉它，真要解耦得连 broker 一起换，本次不做。
- **现状链路里没有归一化**（第 2 期已改掉）：改造前是 `Filebeat → Logstash → ES`，`ndr/backend/app/collector/template.py` 的 filter 段只补一个 `source_system`，文档原样落库（Zeek 在 `zeek.*`、Wazuh 在 `data.*`）——`agent/backend/app/investigation/catalog.py:7-12` 的注释正是照此写的。现在归一化提前到 normalizer 服务，ES 只存统一字段。

## 3. 目标数据流

```
Zeek(只抓监控网段 / BPF) ─ Filebeat ┐
                                    ├→ Redis 队列 shentong:events:collect（LPUSH；设长度上限）
Wazuh 4.14(alerts + archives) ──────┘             │
                          normalizer 服务（BRPOPLPUSH 取出 → 归一化 → 成功后确认）
                                                  │
                     ┌────────────────────────────┴───────────────────────────┐
                     │ ① LPUSH 归一化文档（先做：检测不被 ES/Logstash 拖住）      │ ② POST NDJSON
                     ▼                                                        ▼
        Redis shentong:events:raw                                Logstash http :8080
                     │                                                        │
             规则检测器（规则匹配 / 聚合）                        output : ES（无条件，全量）
                     │ 命中                                        索引 shentong-events-<日期>
        HTTP POST（持久化重试）→ 智能体
        ← 200 + 已收到（这就是回执）
                     │
   智能体 ──MCP over HTTP（令牌）──→ NDR MCP 服务
                                       ├─→ ES（查询 / 聚合 / 原始证据）
                                       ├─→ 规则 / 检测器状态 / 网段与过滤配置
                                       └←─ record_conclusion（写回结论，只给界面看）
```

> 第 4 期的「过滤规则（降噪）」落在**归一化服务**里判定（决定要不要把这条投进检测器队列），不再写成 Logstash 的 `drop` —— 因为原始日志已经不经过 Logstash，而第 2 期之后 ES 只有 Logstash 一个写入方。

### 三条红线

1. **过滤绝不用 `drop{}`**。Logstash 的 `drop` 会**终止整个事件**，连 ES 那条输出一起没了，直接违反「ES 落全量」。**最终落法**：过滤压根不写在 Logstash 里，而是归一化服务里的一次判断（`ndr/backend/app/ingestion/ingest_filter.py`）—— 命中就跳过「投检测器队列」那一步，ES 那条 POST 照旧发全量。
2. **ES 输出永远无条件**。
3. **ES 输出的分流判断已被消灭**（第 2 期落地）。原方案要求把 `if [log_type]` 改成按 `source_system` 分流；实际上归一化前置后**只剩一族索引** `shentong-events-*`，`render()` 里已没有任何分流：原始文档根本不经过 Logstash。归一化后 Wazuh 也带 `log_type="wazuh"`（`ndr/backend/app/ingestion/normalizer.py:373`）这个坑随之不存在。

## 4. 关键契约变更：ES 文档形态

现在 ES 存**原始**文档，智能体按来源走不同字段路径：

| 概念 | 现在（zeek） | 现在（wazuh） | 改后（统一） |
|---|---|---|---|
| 源地址 | `zeek.id.orig_h` | `data.srcip` | `src_ip` |
| 目的地址 | `zeek.id.resp_h` | `data.dstip` | `dst_ip` |
| 源端口 | `zeek.id.orig_p` | `data.srcport` | `src_port` |
| 目的端口 | `zeek.id.resp_p` | `data.dstport` | `dst_port` |

改后的统一字段 = `ndr/backend/app/schemas.py:14` 的 `class UnifiedLog`：
`source_system / ts / event_type / log_type / src_ip / dst_ip / src_port / dst_port / protocol / conn_state / hostname / user / process / command / query / uri_path / query_string / method / body / referer / cookie / auth_scheme / content_type / user_agent / status_code / resp_mime / bytes_out / bytes_in / ja3 / ja3s / tls_version / cert_issuer / qtype / filename / mime_type / account / rule_id / rule_groups / mitre / severity / summary / raw`。

**原始数据不会丢**：`UnifiedLog.raw: dict[str, Any]` 把原始文档整份带进 ES。

### 智能体侧必须同步改的点（已定位）

| 文件:行 | 现在 | 改后 |
|---|---|---|
| `agent/backend/app/investigation/catalog.py` | 26 个字段条目、51 处 `"zeek": ...` 双列映射（`{"zeek": "zeek.id.orig_h", "wazuh": "data.srcip", ...}`） | 单列：概念 → 统一字段名。**净简化** |
| `agent/backend/app/investigation/es_query.py:284` | 硬编码 `for extra in ("zeek.body", "data.command", "rule.description")` | 用统一字段名 |
| `agent/backend/app/ingestion/es_schema.py:20-21` | `es_source_fields()` 返回原始路径（与 `ndr/backend/app/ingestion/es_schema.py` 逐字相同） | 返回 `src_ip` / `dst_ip` |
| `agent/backend/app/config.py:29-32` | `es_zeek_src_fields="zeek.id.orig_h"` 等 4 项（`ndr/backend/app/config.py:31-34` 同） | 新索引名 + 统一字段名 |
| `agent/backend/app/consumer.py` | Redis 消费端 | 退役，改 HTTP 接收端点 |

> 其中 `catalog.py` 与 `es_query.py` **随第 3 期整体搬到 NDR**（改由 MCP 的 `describe_data` 等工具提供），所以这两处不在智能体侧改，而是在 NDR 侧按统一字段重写一次 —— 避免同一份改动做两遍。`es_schema.py` / `config.py` 的 ES 相关项在智能体侧**直接删除**。

## 5. 判重与回执（已实施，第 5 期）

```
NDR 检测器                               智能体 POST /api/push/digests
  命中 → 聚合摘要（一批 = 一次图运行）
  每条配 event_id(UUID) + fingerprint     逐条：算事件组指纹
  POST {"items":[...]} ─────────────────→   ① 库里有同指纹 EventGroup → event_count += count、
  Authorization: Bearer <令牌>                 window_end 前移，**不跑图**
                                            ② 库里没有、Redis 桶内占位已存在（同桶在跑）→ 跳过
  ←────────── 200 + PushResult ──────────   ③ 都没有 → Redis 占位(nx) + 投 Celery 跑图
  失败 → 落 shentong:events:pushretry
         检测循环后台重发（2xx 才算送达）
```

- **判重落在智能体侧**（`agent/backend/app/api/routes/push.py`）：只有它知道某个事件组分析过没有。指纹算法下沉到 `agent/backend/app/digest.py` 的 `group_fingerprint(ips, start)`，与图里落库用的完全同源（`agent/backend/app/agents/nodes.py:_group_fingerprint` 现在转发调用它），桶宽 = `group_bucket_minutes`；**必须用「现在」的桶**，与 `agent/backend/app/workers/tasks.py` 里 `window_start = now` 对齐。
- **不预建 EventGroup 行**：`agent/backend/app/agents/persistence.py:save_groups` 会用 `row.event_count = len(existing)`（现有 Event 行数）覆盖计数，预建行会污染它；「同桶第一批还在跑」用 Redis 占位（`set(nx, ex=bucket*2)`）拦，Redis 不可用时放行（fail-open，宁可多跑不漏报）。
- **回执 = HTTP 2xx**：`ndr/backend/app/detector/push.py:push_batch()` 收到 2xx 即算送达；非 2xx/超时 → 整批落 `shentong:events:pushretry`（`ReliableQueue`，processing 队列兜住进程崩），由检测循环每轮的 `push.retry_pending()` 重发，失败放回队尾并停止本轮（智能体整体不可达时空转没意义）。
- **NDR 侧不再有闸门**：`analyzed_fingerprints` 表、`ndr/backend/app/detector/analyzed.py`、`_drain_done`、`analyzed:done` 队列、agent 侧 `consumer.py` 与 `_notify_done` 已全部删除；`ndr/backend/app/detector/fingerprint.py` 保留 `digest_age`（超龄丢弃）与 `digest_fingerprint`（推送载荷用）。
- **升级注意**：老部署里 `analyzed_fingerprints` 表会留下（`Base.metadata.create_all` 不删表），不再写入、可手工 drop；`shentong:detector:dedup` 只剩历史计数，界面标注为「退役前」。
- **验收对照**（单进程实测，`/tmp/test_push_api.py` 30 项、`/tmp/test_agent_push.py` 51 项、`/tmp/test_runner_push.py` 15 项全过）：重复推送同一指纹 → 只加计数、不投任务 ✅；未配/配错令牌 → 503/401，界面报错可见 ✅；推送失败 → 落重试队列并在下一轮重发 ✅；智能体不可达且重试队列写不进 → 摘要放回检测队列，不静默丢 ✅。**未在真实 Zeek/Wazuh 流量与双机部署下端到端跑过**（与第 1~4 期同批实机验收）。

## 6. 智能体接口：MCP（新）

NDR 对外提供 **MCP server**，智能体在分析事件时通过它查询、调查、分析。

**现状**：全仓没有任何 MCP 代码（`grep -i 'mcp|modelcontextprotocol|fastmcp'` 零命中）；NDR 侧也**没有事件查询 API**——`ndr/backend/app/api/router.py` 只挂 `auth` / `exclusions` / `rules` / `es_admin` / `logstash` / `detector` / `zeek` 七组管理类路由（原 `analysis_scopes` 已随第 1 期并入 `zeek`）。所以智能体现在是**直接连 NDR 的 ES 查**（`agent/backend/app/investigation/es_query.py`）。

### 工具面

| 分组 | 工具 | 来源 |
|---|---|---|
| 查询 | `describe_data`（数据源 / 真实时间范围 / 字段清单）、`search_events`、`aggregate_events`、`raw_evidence` | `agent/backend/app/investigation/tools.py:636-718`，走 `es_query.py` |
| 调查 | `timeline`、`net_flows`、`dns_queries`、`tls_fingerprints`、`web_requests`、`file_hashes` | 同上，整体搬到 NDR |
| NDR 上下文 | `get_event`（按事件ID/指纹取摘要）、`get_rule`（触发规则定义）、`detector_status`（检测器 / 队列 / 速率）、`list_networks`、`list_filters` | **NDR 独有，新增**——现在智能体只能从推送载荷里猜 |
| 写回 | `record_conclusion`（按事件ID/指纹写：状态、定级、结论摘要、thread_id） | **新增**，就是「只读 + 写回结论」里的那一半写 |

**留在智能体本地、不进 MCP 的 8 个工具**：`asset_lookup`、`topology_neighbors`、`entity_profile`、`memory_recall`、`group_history`、`threat_intel`、`record_finding`、`note_gap` —— 它们查的是智能体自己的 Postgres 与外部情报，与 NDR 无关。

### 为什么智能体侧改动小

`agent/backend/app/investigation/planner.py` 是**文本 ReAct，不是原生 function-calling**：`:286` 把 `tools.tool_catalog_text()` 拼进提示词，`:448-451` 拿模型输出的 `action` + `params` 调 `tools.execute(action, params, ctx)` 派发（`FREE_TOOLS = {"record_finding", "note_gap"}` 在 `:29` 直接放行）。于是：

- 只需在 `tools.execute` 的**派发层**把 NDR 类工具转成 MCP 调用，**调查循环一行不用改**。
- 工具清单可以**从 MCP server 动态拉**（`list_tools`），NDR 以后加工具不需要智能体重启或重新部署。
- 字段目录 `agent/backend/app/investigation/catalog.py`（26 个字段条目、51 处 `"zeek":` 双列映射）连同 `es_query.py`（511 行）一起搬到 NDR，改由 `describe_data` 提供 —— 这正好和第 4 节的字段契约变更**合并成同一次改动**，不重复做两遍。

### 两组令牌不要混

| 令牌 | 方向 | 谁生成 | 谁校验 | 存哪 |
|---|---|---|---|---|
| **推送令牌** | NDR → 智能体 | 智能体侧定，填进 NDR 的「智能体推送」配置 | 智能体的 HTTP 入口 | NDR 的 `SystemConfig` |
| **MCP 令牌** | 智能体 → NDR | **NDR 界面生成 / 吊销** | NDR 的 MCP 服务 | NDR 新表（只存哈希，明文只显示一次） |

两者方向相反，是两份不同的密钥，互不替代。

### 结论回写与判重的关系

- **判重的权威仍在智能体**（第 16 / 17 条）：收到推送先按指纹查 `agent/backend/app/db/models.py:59` 的 `EventGroup`，命中只累加 `event_count`。
- NDR 侧由 `record_conclusion` 写下的记录**只是给界面看和审计的镜像**，不参与判重 —— 避免两边各判一次、结论对不上。
- 镜像的保留期（`ST_MCP_CONCLUSION_RETENTION_DAYS`，默认 7 天）只影响这些镜像记录能查多久，**不参与判重**（判重看事件组时间桶，见 §8.1）。

### 部署与配置

- compose 新增 `mcp` 服务（同 NDR 镜像，`command: python -m app.mcp_server`），单独暴露一个端口。
- 传输用 MCP **streamable HTTP**（要跨机部署，不走 stdio）。
- 依赖新增官方 `mcp` Python SDK（写进 `ndr/backend/pyproject.toml`）。
- 智能体侧配置：MCP 地址 + MCP 令牌；`es_query.py` 退役后，智能体的 ES 相关配置项一并删除。

## 7. 分期实施

### 第 1 期 · 监控网段（Zeek 抓包层）

> ✅ **已完成**。一份多行清单成为唯一来源，Zeek 的 `bpf_filter` 与 `Site::local_nets` 都由它生成。

**落地形态**：

- 清单存在 SystemConfig 的 `zeek.monitored_nets`（换行分隔）；同时以**逗号**形式写进 `/config/interface.conf` —— 该文件是 `key=value` 行格式，多行值必须压成逗号，Zeek 入口（`ndr/zeek/entrypoint.sh: render_nets`）按逗号切开渲染 `Site::local_nets`。
- `/config/interface.conf` 现在写 5 个键：`interface` / `monitored_nets` / `bpf_filter` / `local_nets` / `bpf_extra`。其中 **`bpf_filter` 与 `local_nets` 是生成物**，输入只有 `interface` / `monitored_nets` / `bpf_extra`。
- BPF 生成规则（`ndr/backend/app/ingestion/scope.py: build_bpf`）：CIDR → `net 10.0.0.0/8`，单 IP → `host 1.2.3.4`，多项取「或」并加括号（BPF 里 `net X` 本身即「源或目的落在 X」，无需写 src/dst）；`bpf_extra` 非空时以 ` and (...)` 追加。
- 校验（`validate_nets`）：至少 1 条、最多 200 条、逐条 `is_valid_ip_or_cidr`（CIDR 主机位必须为 0，排除 /32、/128）。
- 接口：`GET /api/zeek/status`（回 `networks` / `bpf_extra` / 生成的 `bpf_filter` 与 `local_nets`）、`GET /api/zeek/networks/status`（供前端首次向导拦截）、`PUT /api/zeek/interface`（`interface` 留空 = 保持当前网卡，首次向导只提交网段即可）。
- 落库镜像键：`zeek.interface` / `zeek.monitored_nets` / `zeek.bpf_filter` / `zeek.local_nets` / `zeek.bpf_extra`。**检测器读库**（`ndr/backend/app/detector/runner.py: _load_scopes` → `monitored_nets()`），因为它不挂 `/config` 卷；配置文件里 `monitored_nets` 为空时 Zeek 侧回落读库，避免共享卷被清后抓包范围丢失。
- 概念合并已完成：删除 `AnalysisScope` 表与模型、`ndr/backend/app/api/routes/analysis_scopes.py`、`ndr/backend/app/api/validation.py`、`ndr/frontend/components/scope-manager.tsx`；`ndr/frontend/components/nav.tsx` 的首次向导拦截改打 `/api/zeek/networks/status`，不再有「多套网段组 + 启用/停用」的概念。

**验收**：界面改网段 → 生效可见 → Zeek 只抓到该网段；非法输入被拒。

### 第 2 期 · normalizer 前置

> ✅ **已完成**。⚠️ 但**必须和第 3 期同批上线**：第 2 期一改 ES 文档格式，智能体现有直连 ES 的查询（按 `zeek.id.orig_h` / `data.srcip`）就查不到了，两期之间不能留窗口。

**落地形态**：

- 新服务 `ndr/backend/app/collector/normalizer_service.py`（入口 `python -m app.collector.normalizer_service`）：复用 `ndr/backend/app/detector/queue.py:18 class ReliableQueue` 的 raw→processing→ack 模式消费 `shentong:events:collect`，逐条 `normalize(source_of(doc), doc)` 得 `UnifiedLog`，`_payload()` 只留非空字段（`raw` 永远保留），再走两条路：
  - **① 先** `LPUSH` 到 `shentong:events:raw`（检测是实时车道，不该被 ES/Logstash 的抖动拖住）；
  - **② 再** 以 NDJSON 批量 POST `http://logstash:8080/`，**2xx 才 ack**；失败则把本批**放回队尾**重试（`recover()` 只兜底进程崩溃留下的残留 —— 只在启动时跑一次，靠它重试会让 Logstash 一挂就永久躺平）。重放造成的重复由检测器 `handled` 注册表按文档哈希挡住。
- `source_of(doc)` 是新增的**归一化前来源判定**（`ndr/backend/app/ingestion/normalizer.py`）：`source_system` 优先，缺失则看顶层 `log_type` 或 `zeek` 是否为 dict → `zeek`，否则 `wazuh`。
- 坏消息（JSON 坏 / 非 dict / 归一化返回 None）**直接确认掉并记数**，否则一条坏消息会把队列卡死。
- 队列封顶 `_trim_queue()`（`ltrim` 裁掉最旧，上限 `collector_queue_max=30000`）；周期日志汇报「入库 / 待重试 / 坏消息 / 积压」。
- `ndr/backend/app/config.py` 新增采集段 9 项：`collector_collect_queue` / `collector_processing_queue` / `collector_queue_max` / `collector_consume_batch=500` / `collector_poll_timeout=5` / `collector_post_timeout_seconds=20` / `collector_post_retries=3` / `collector_retry_backoff_seconds=1.0` / `collector_stats_log_seconds=300`；`logstash_beats_port=5044` → `logstash_http_port=8080`。
- ES 索引名全链路收敛为一族：`es_events_index="shentong-events-*"`（模板渲染成 `shentong-events-%{+yyyy.MM.dd}`），删掉 `es_zeek_index` / `es_wazuh_index` 与 `es_zeek_src_fields` / `es_zeek_dst_fields` / `es_wazuh_src_fields` / `es_wazuh_dst_fields`，改为 `es_events_src_fields="src_ip"` / `es_events_dst_fields="dst_ip"`。
- `ndr/backend/app/collector/template.py` 整体重写：input 段 `beats{port 5044}` → `http{port 8080}`，**必须用 `codec => "json_lines"` + `additional_codecs => { "application/json" => "json_lines" }`**（http 输入默认「一个请求 = 一个事件」，否则一批 NDJSON 会被当成一条、json 解析失败）；`remote_host_target_field` / `request_headers_target_field` 挪进 `[@metadata]`（默认会写成 `host`、`headers` 并入库）；filter 段只把 `ts` 搬进 `@timestamp`；output 段只剩一条无条件 ES 输出。
- Logstash 开持久化队列（`ndr/logstash/config/logstash.yml` 的 `queue.type: persisted` + `path.queue` + `queue.max_bytes: 2gb`），让「Logstash 返回 200 = 已持久化」成立，normalizer 的 ack 才有意义。
- compose 两份都加了 `normalizer` 服务与 `logstash-queue` 卷、logstash 端口 `5044` → `8080`；zeek 容器 env 从 `LOGSTASH_HOST`/`LOGSTASH_PORT` 改为 `REDIS_HOST`/`REDIS_PORT`/`REDIS_DB`/`REDIS_KEY`。
- `ndr/zeek/filebeat.yml`：`output.logstash` → `output.redis`（`key: shentong:events:collect`、`data_type: list`）。
- 顺手清掉的死代码：`ndr/backend/app/ingestion/es_client.py` 的 `fetch_window_logs` / `_scroll` / `scope_clause` / `FetchResult`（水位全量重放移除后已无调用者）。
- 前端同步：`es-panel` 两个索引输入框合并成一个「索引模式」；`logstash-panel` 去掉 Redis 参数一栏、`beats` → `http`、「旁路队列」→「待归一化积压」。

**两条方案外的发现（实现时才暴露，已按此落地）**：

1. **检测器必须改吃「已归一化」文档**。原方案没说这条：既然归一化提前了，`shentong:events:raw` 里放的就是归一化文档，检测器不该再归一化一遍（白费 CPU）。`ndr/backend/app/detector/runner.py` 加了 `_to_entry()`：文档带 `source_system` + `event_type` + `raw` 三个标记 → 直接 `UnifiedLog.model_validate()`，否则回退老路 `normalize()`。**兼容改造前格式，新旧混跑不炸。**
2. **投给智能体的摘要样本里必须仍是「原始文档」**。`agent/backend/app/agents/nodes.py:197-203` 会拿样本里的 `doc` 再归一化一次（`entry = normalize(log_source, raw_doc)`），所以检测器聚合时要传 `entry.raw`（原始文档、已脱敏），**不能**传消费到的归一化文档。`_aggregate()` 的形参已从 `doc` 改名 `raw_doc` 并写明这条。

**验收**：三个容器起来后，Zeek 与 Wazuh 事件都进 `shentong-events-*` 且字段统一；停掉 Logstash 不丢数据（消息放回队列尾等下轮重试，检测器侧不重复灌）。

### 第 3 期 · MCP 服务 + 智能体切到 MCP

> ✅ **已完成（2026-02）**。原方案的「急」在于第 2 期一落地、ES 里只剩 `shentong-events-*` 一族扁平字段，而 agent 侧还在按 `zeek.id.orig_h` / `data.srcip` 旧路径查（`es_zeek_index="zeek-*"` / `es_wazuh_index="wazuh-alerts-*"`）。第 3 期已把这条缝补上：agent 侧不再有任何 ES 直连代码与配置，取数全部经 `ndr-mcp`。

- NDR 侧新增 MCP 服务（独立进程 / 容器 `ndr-mcp`）：用官方 `mcp` SDK 起 streamable HTTP 服务，Bearer 令牌校验，工具实现复用 NDR 现有的 ES 客户端与配置。
- 把 `agent/backend/app/investigation/es_query.py`(511 行) 与 `catalog.py`(450 行) 整体搬到 NDR，**按新统一字段重写路径** —— 一次改完，不留旧路径。
- 智能体侧：`agent/backend/app/investigation/tools.py` 的 `execute()` 派发层里，NDR 类工具改走 MCP 客户端；`es_query.py` 删除；ES 相关配置项删除。
- NDR 新表存 **MCP 令牌哈希**（明文只在生成时显示一次）与 **`record_conclusion` 回写记录**（按事件ID / 指纹）。
- NDR 界面新增「MCP」面板：令牌生成 / 吊销、服务状态、最近调用与错误。

**验收**：智能体不配 ES 地址也能跑完一次完整调查；NDR 界面能看到调用记录；令牌吊销后智能体立刻调不通；`record_conclusion` 写回的内容在 NDR 界面可见。

#### 服务端：✅ 已完成（2026-02，实施记录）

落地形态：

1. **`ndr/backend/app/mcp/server.py`**（入口 `python -m app.mcp.server`）：

   ```python
   MCPServer(name="shentong-ndr", title="深瞳 NDR", instructions=..., version="0.1.0")
   server.streamable_http_app(streamable_http_path=settings.mcp_path, host=settings.mcp_host)
   ```

   **共 17 个工具**（10 个 ES 查询/调查 + 7 个 NDR 自身），全部写成**显式形参的普通函数**注册 —— MCP 的 `inputSchema` 由函数签名推导，用 `**kwargs` 会被当成一个必填参数（实测报 `1 validation error for search_eventsArguments kwargs Field required`），这个坑踩过一次。工具名与参数名**逐字沿用**智能体原来的 10 个工具，提示词与调用样例不用改。

2. **ES 查询层搬进 NDR 并重写**：新增 `ndr/backend/app/investigation/{__init__,catalog,es_query,tools}.py`（1595 行）；字段目录从 50 条收敛到 **42 条**（删掉只在 `raw` 里的 `duration`/`rcode`/`answers`/`fuid`/`md5`/`sha1`、合并掉 `service`/`host`/`server_name`/`uri`/`note`/`msg`/`rule_level`/`agent_name`/`wazuh_url` 等，新增 12 条顶层统一字段）。索引选择塌成单族：

   ```python
   def index_pattern() -> str:
       return settings.es_events_index          # 原「按来源选 zeek-*/wazuh-alerts-*」整段删除
   ```

   `source_clause()` 改 `build_clause("source_system", source)`；`ts` 路径是 ES 元字段 `@timestamp`；`sha256` 路径落 `raw.sha256`。上限值原为 agent 侧配置项、NDR 没有对应物，写成模块常量（`QUERY_TIMEOUT_SECONDS=45` / `TIMELINE_MAX_HOURS=72` / `DEFAULT_LOOKBACK_DAYS=30` / `max_docs()=2000` / `RAW_EVIDENCE_MAX=20`）。

3. **NDR 自身 7 个工具**（`ndr/backend/app/mcp/ndr_tools.py`，形状与 ES 侧一致、无 `ctx`、纯函数）：`get_event`（按事件ID/指纹查结论历史；NDR 侧已不记录投递指纹，只回一句指向智能体的说明）、`get_rule`、`detector_status`（队列积压 / 五段速率 / 丢弃 / 去重 / 任务失败 / 选主 / Redis 内存，口径与 `ndr/backend/app/api/routes/detector.py` 对齐）、`list_networks`、`list_filters`、`record_conclusion`（按 `dedup_key = event_id or fingerprint` upsert）、`fetch_window`（按时间窗 + 网段/IP 拉原始条目，给回溯用；返回每条 log 带 `ref = es:<索引>/<文档id>` 与**完整 `raw` 原文**）。

   八个查询工具（`search_events` / `aggregate_events` / `timeline` / `net_flows` / `dns_queries` / `tls_fingerprints` / `web_requests` / `file_hashes`）都收 `source`（`zeek|wazuh|both`，空 = 两个来源）—— 下层 `ndr/backend/app/investigation/tools.py:114 _resolve_sources()` 本来就有这个参数，补的是 MCP 包装层缺的形参（缺了会被**静默丢弃**）。包装层类型必须与下层取值函数对齐：`web_requests.status_code` 下层用 `_str_param()`（支持 `4xx` 这类关键字匹配），包装层原写 `int = 0` 会让非数字状态码在 MCP 校验层就被拒，已改 `str = ""`。

   > `raw_evidence` 的 ref 白名单校验与 `describe_data` 的「案件已知事实」**留在智能体侧**（NDR 不知道本轮调查查到过什么），所以 NDR 侧工具必须是无状态纯函数：参数进、JSON 文本出。

4. **令牌**（`ndr/backend/app/mcp/auth.py` + 新表 `mcp_tokens`）：只存 sha256 哈希 + 明文前 8 位 `prefix`；明文只在 `POST /api/mcp/tokens` 返回一次；**每次调用都查库、不缓存**，所以界面一吊销就立刻调不通（单次调查的工具调用量才几十次，多一次主键查询不值得引入缓存失效的坑）。

5. **令牌校验不用 SDK 自带那套**：`mcp.server.auth` 的 `TokenVerifier` / `AuthSettings` 是 OAuth 风格（要求 `issuer_url`），改为一个纯 ASGI `BearerAuth` 中间件包住 `streamable_http_app()` 的返回值；`/health` 与 `/healthz` 免令牌（容器健康检查要用）。

6. **调用记录**（`ndr/backend/app/mcp/calls.py`）：Redis 有界列表 `LPUSH` + `LTRIM`，**记录失败整体吞异常**（旁路不该让智能体的调查挂掉）。

7. **管理接口** `ndr/backend/app/api/routes/mcp.py`（NDR 后端第 8 组路由）：`GET /status`、`GET /tools`、`GET|POST /tokens`、`POST /tokens/{id}/state`（启用/吊销）、`DELETE /tokens/{id}`、`GET|DELETE /calls`、`GET /conclusions`（顺手清过期结论）。界面面板 `ndr/frontend/components/mcp-panel.tsx`（第 7 期拆页后挂在 `/admin/agent`「智能体对接」页）。

8. **编排**：两份 compose 都加 `ndr-mcp` 服务（`command: python -m app.mcp.server`、端口 8090、healthcheck 打 `/health` —— 镜像里没有 curl，用 `python -c` 打）。`ndr/backend/pyproject.toml` 依赖加 `mcp>=2.2,<3`。

   > **MCP SDK 2.x 与 1.x 差别很大**，写代码前先确认版本：`FastMCP` 已改名 `MCPServer`（`from mcp.server.mcpserver import MCPServer`，1.x 的 `mcp.server.fastmcp` 直接 `ModuleNotFoundError`）；客户端也换了（`from mcp.client.streamable_http import streamable_http_client`，只 yield `(read, write)` 二元组，带 Authorization 要自己建 `httpx2.AsyncClient(headers=...)` 传进去）。

9. **实测**（真起 uvicorn + 真 SDK 客户端，桩掉 ES）：无令牌 / 错令牌 → 401；`/health` 免令牌 → 200；`tools/list` → 17 个工具；工具调用回正确 JSON；`search_events` 在 ES 不可用时回**结构化降级结果**（`{"returned": 0, "by_source": {}, "notes": [...]}`）且 `isError: False` —— 模型能据此自我纠正，不会整轮失败。17 个工具的 `required` 全空、无一个含 `kwargs`；八个查询工具的 `input_schema` 都带 `source`。

#### 智能体侧：✅ 已完成（2026-02，实施记录）

1. **新增 `agent/backend/app/investigation/mcp_client.py`**：`call(name, args, *, timeout=None) -> dict`，**永不抛异常**、失败回 `{"error": ...}`（调查流程不该因取数失败整轮挂掉）；`enabled()` 看 `settings.mcp_url` 是否为空；`list_tools()` 失败回 `[]`。

   > 为什么客户端是**同步**的：调查规划器 `agent/backend/app/investigation/planner.py` 是文本 ReAct 循环（把动作名与参数写在提示词里、解析后交给 `tools.execute()` 派发），全文件没有一个 `async def` / `await`。所以实现成「常驻后台事件循环线程 + `run_in_threadpool` 式提交」：`_ensure_loop()` 开一个 daemon 线程跑 `asyncio.new_event_loop().run_forever()`，调用方 `run_coroutine_threadsafe` 取结果。连接键是 `(mcp_url, mcp_token)`，配置一变就重连。

2. **10 个 NDR 类工具改走 MCP**（`agent/backend/app/investigation/tools.py`，702 行；`MAX_ROWS = 2000`）：每次调用 `mcp_client.call("<工具名>", {...})`。`raw_evidence` 的 **ref 白名单校验留在本地**（先用自己的 `ToolCtx` 校验再调用），`describe_data` 的「案件已知事实」块也留在本地 —— NDR 侧那个工具用的是一个新建的空 `ToolCtx`，看不到案件。

3. **字段目录改为动态拉取**：`agent/backend/app/investigation/catalog.py` 重写为**纯展示目录**（42 个字段的名字/类型/说明，与 NDR 侧逐字对齐，AST 对比全等），并新增 `catalog_text(index, fields=None, *, sources=("zeek","wazuh"), max_chars=2600)`；`planner.py` 的 `_field_catalog_text()` 调 MCP `describe_data` 拿索引名与字段清单后渲染，**进程内缓存 10 分钟**（`_case_context` 每轮循环都算，而 `describe_data` 在 NDR 侧要做时间边界聚合）。索引名不再在 agent 侧硬编码。

4. **回溯改为拉 MCP 窗口**：`agent/backend/app/agents/nodes.py` 的 `lookback_node` 用 `mcp_client.call("fetch_window", {"start","end","nets","limit"})` 取代 `es_client.fetch_window_logs()`；新增 `_doc_list()` / `_to_log()` 把返回条目还原成 `UnifiedLog`（条目里已带统一字段就直接 `model_validate`，否则按 `raw` 原文再走一次 `normalize()`）。

5. **删除的 ES 直连面**（`git rm`）：`agent/backend/app/investigation/es_query.py`(511 行)、`agent/backend/app/ingestion/es_client.py`、`es_config.py`、`es_schema.py`；`agent/backend/app/config.py` 的 12 个 `es_*` 配置项整段删除；`agent/backend/pyproject.toml` 去掉 `elasticsearch` 依赖。

6. **配置**：`agent/backend/app/config.py` 加 `mcp_url`（默认 `http://ndr-mcp:8090/mcp`）/ `mcp_token` / `mcp_timeout_seconds`；两份 compose 把 `ST_ES_URL` 换成 `ST_MCP_URL` + `ST_MCP_TOKEN`（外部变量 `NDR_MCP_URL` / `NDR_MCP_TOKEN`）。

7. **方案外发现（顺手修掉）**：agent 侧还留着一份**重复的网段配置** —— `agent/backend/app/ingestion/scope.py` 的 `enabled_cidrs()` 读自己的 `AnalysisScope` 表（`agent/backend/app/db/models.py` 原 282 行，`main.py` 播种 `10.0.0.0/8` 等三段私网兜底），而这份配置**没有任何界面**，且 NDR 第 1 期已把网段唯一来源改成 `zeek.monitored_nets` —— 两份会不一致，回溯就会按错误网段筛日志。现改为 `enabled_cidrs()` 调 MCP `list_networks`（进程内缓存 60 秒；拿不到时回空列表 = **不限制**，因为 NDR 的语义是「清单为空 = 抓全部」），`AnalysisScope` 模型与播种函数一并删除。

**验收对照**：智能体不配 ES 地址也能跑完一次完整调查 ✅（配置项已不存在）；NDR 界面能看到调用记录 ✅；令牌吊销后智能体立刻调不通 ✅（每次调用查库不缓存）；`record_conclusion` 写回的内容在 NDR 界面可见 ✅。四项均以「真起服务 + 真 SDK 客户端」实测过，**未在真实 Zeek/Wazuh 流量下端到端跑过**（与第 2 期同批上线，实机验收一并做）。

### 第 4 期 · 过滤规则

> ✅ **已完成（2026-02）**。原方案的「渲染器：条件树 → Logstash 条件表达式」这一条**已作废** —— 第 2 期把归一化提到 Logstash 之前，原始日志不再经过 Logstash，于是「要不要投检测器」这个判断只能落在**归一化服务**里（`ndr/backend/app/collector/normalizer_service.py`）。红线仍是红线：**绝不用 Logstash `drop{}`**（`drop` 会终止整条事件、把 ES 那条输出一起丢，`shentong-events-*` 就不是全量了），**ES 输出永远无条件**。

- 新表 `IngestFilter`（名字 / 启用 / 优先级 / 条件树），照抄 `ndr/backend/app/ingestion/exclusion.py`(237 行) 的范式：条件树 `{"rules": [{"field","op","value"} | {"logic":"and"|"or","rules":[...]} | {"not":{...}}]}`、`validate_conditions()`（拒绝空 rules / 未知字段 / 正则错），求值复用 `app.rules.engine.evaluate_conditions`。
- 字段白名单 = 源/目的 **地址 + 端口** + **协议内容字段**（`uri_path` / `host` / `user_agent` / `body` / `command` / `query` 等），操作符含「包含」与「正则」。
- 渲染器：条件树 → Logstash 条件表达式（只作用于送检测器那条输出）。→ **作废**，改为归一化服务里的 `ingest_filter.match()`。
- UI：过滤规则页，复用 `ndr/frontend/components/condition-editor.tsx`；**带「试运行 / 干跑」**（先看会命中哪些历史事件，再启用）。
- `template.py` 三段化：① 统一字段兜底 ② 过滤条件 ③ 输出。→ **作废**（同上；`template.py` 里已无任何索引分流与过滤条件）。

#### 实施记录（2026-02）

1. **新表** `ndr/backend/app/db/models.py`：`class IngestFilter(Base)` → 表 `ingest_filters`（`id` / `name`(unique,index,128) / `description`(Text) / `conditions`(JSON) / `enabled`(默认 True) / `priority`(默认 100) / `created_at` / `updated_at`）。docstring 写明与 `ExclusionFilter` 的**作用点差异**：这张在归一化之后、规则之前，决定「要不要进检测器」；那张在规则命中之后，决定「要不要跑模型」。NDR 侧 `_MIGRATIONS = ()`，新表靠 `Base.metadata.create_all` 建。

2. **判定引擎** `ndr/backend/app/ingestion/ingest_filter.py`：

   - `ADDRESS_FIELDS = ("src_ip","dst_ip","src_port","dst_port")`；`CONTENT_FIELDS` 35 个协议/日志内容字段；`allowed_fields()` = 地址 ∪ 内容 ∪ `VIRTUAL_FIELDS`（复用 `src_internal` / `dst_internal` 这类方向虚拟字段）。**刻意不含 `raw`**，也不含 `hit_rule` / `rule_source` / `rule_severity` —— 这三个是「规则命中之后」才有的东西，在归一化时点根本不存在。
   - `load_filters(force=False)` 按 `settings.ingest_filter_cache_seconds`（默认 30s）缓存，**DB 异常沿用上次缓存**（配置读不到就按旧的判）；`invalidate_cache()` 由写接口调用。
   - `match(entry: UnifiedLog) -> str | None` 按 priority 顺序逐条求值，**任何异常都按「未命中」处理（fail-open）**：宁可多跑检测器，不能因为一条写错的正则把真实攻击静默挡下。
   - `record_hit(name, entry)` 写 Redis（`shentong:ingestfilter:stats` 计数 + `shentong:ingestfilter:samples` 每条例最多 3 条样例，TTL 30 天），供界面回答「到底挡掉了什么」。

3. **试运行（干跑）** `ingest_filter.dry_run(conditions, *, hours=0, limit=0)`：回看 `hours`（默认 `ST_INGEST_FILTER_DRY_RUN_HOURS=24`）、最多取样 `limit`（默认 `ST_INGEST_FILTER_DRY_RUN_MAX=500`，硬上限 5000）条，返回 `{source, hours, scanned, matched, ratio, samples, exclude_name, hint}`。取数顺序 **ES（`shentong-events-*`，按 `@timestamp` 范围、倒序、ref=`es:<索引>/<文档id>`）→ 检测器待处理队列 → 采集队列**，ES 不可用时只 log 后降级到队列（`source` 字段告诉界面数据来自哪层）。原始文档（只有 `source_system`/`event_type`/`raw`）会现场再跑一次 `normalize()`，所以「刚采集还没落库」的事件也能试。

4. **接线** `ndr/backend/app/collector/normalizer_service.py`：`_split()` 改为返回 `UnifiedLog`（每条只 `model_dump` 一次）；主循环建成「全量 `payloads`」与「未命中 `kept`」两份，**只把 `kept` LPUSH 进检测器队列**，而 `_post()` 依旧发**全量**（含被降噪的）→ 成功才 ack 全部。所以被降噪的事件照样进 ES、照样 ack，只是检测器看不到。`_maybe_log` 加了「降噪挡下 N 条」。

5. **接口** 新增 `ndr/backend/app/api/routes/ingest_filters.py`（NDR 后端第 9 组路由，`prefix="/api/ingest-filters"`）：`GET ""`（list，每条带 `hit_count` 与 `samples`）、`GET "/fields"`（字段分组 + 运算符 + **三条现成示例**：内网互扫 / 监控探活 UA / 心跳域名）、`GET "/stats"`、`POST "/dry-run"`、`POST ""`、`PUT "/{id}"`、`DELETE "/{id}"`；三道校验（400 空条件/未知字段/正则错、404 不存在、409 同名），写操作后 `invalidate_cache()`。挂在 `ndr/backend/app/api/router.py` 的 exclusions 之后。

6. **界面** 新增 `ndr/frontend/components/ingest-filters-panel.tsx`，与排除过滤面板同挂在 `/admin/filters`「过滤规则」页（第 7 期拆页前是 `ndr/frontend/app/admin/settings/page.tsx` 里 MCP 面板与排除过滤面板之间），复用 `condition-editor.tsx`；面板带**「试运行（不保存）」**按钮 + 回看小时/取样条数输入，结果区显示取数来源、扫描/命中条数与比例、命中样例（含事件 ref），以及三条示例的一键套用；列表显示每条例「已挡下」计数与最近命中的样例。`ndr/frontend/lib/api.ts` 补 `IngestFilterItem` / `IngestFilterSample` / `IngestFilterFields` / `IngestFilterDryRunResult` 等类型。

7. **顺手扩了 MCP `list_filters`**：原来只回排除过滤，现在回 `{"filters": 排除, "ingest_filters": 降噪, "hint": ...}`，hint 明确「两道闸门都会导致没有告警，别把被过滤当成没有异常」。智能体侧从未调用过该工具，改形状安全。

8. **实测**（`/tmp/test_ingest_filter.py`，24 项全过）：校验四类拒绝逐条覆盖；`match()` 命中/不命中/**求值抛异常时回 None（fail-open）**；`dry_run()` 含原始文档的混合取样、非法条件回 error、无数据回提示；`normalizer_service.run()` 用 FakeRedis + FakeQueue + FakeHttp 整轮跑，断言「**检测器队列只剩未命中的那条**」「**ES 收到 2 行、含被挡下的那条**」「两条都 ack」「命中计数 1 / 样例 1」「重试列表为空」。

**验收对照**：加「忽略 10.0.0.5:445」→ 试运行先看到命中量与样例 ✅（`POST /api/ingest-filters/dry-run`）；该流量不再进检测器 ✅（主循环只 LPUSH `kept`）；**ES 里仍有** ✅（`_post` 发全量，测试断言 2 行含被挡下的）。均为单进程内实测，**未在真实 Zeek/Wazuh 流量下端到端跑过**（与第 2、3 期同批实机验收）。

### 第 5 期 · HTTP 推送智能体 ✅ 已完成（2026-02，实施记录）

- **agent 侧接收端点**：`agent/backend/app/api/routes/push.py` —— `GET /api/push/ping`（连通性自检）、`POST /api/push/digests`；Bearer 令牌常数时间比较（未配 `ST_PUSH_TOKEN` → 503，令牌不符 → 401，超 `push_max_items` → 413）；逐条按「查库 → Redis 占位」判重（见第 5 节），新摘要用 `celery_app.send_task("analysis.analyze_digests", args=[accepted])` 投递（API 进程不必 import 整个任务模块）。指纹下沉：`agent/backend/app/digest.py` 新增 `group_fingerprint` / `time_bucket` / `bucket_minutes` / `digest_ips`，`agents/nodes.py:_group_fingerprint` 改为转发。
- **NDR 侧推送与重发**：`ndr/backend/app/detector/push.py`（配置读写 / 分片 / 2xx 判定 / 统计 / `deliver` 四态 off·pushed·queued·lost / `retry_pending`）、`ndr/backend/app/detector/fingerprint.py`（`digest_age` + `digest_fingerprint` 从原闸门搬出）；`runner._flush()` 交接改写为「优先 HTTP 推 → 没配地址回落旧队列」，`lost` 时摘要放回检测队列绝不静默丢；主循环每轮调 `push.retry_pending()`。
- **配置接口与界面**：`ndr/backend/app/api/routes/agent_push.py`（`GET`/`PUT /api/agent-push`、`POST /test`、`POST /retry`；令牌只回显打码，`token=None` 表示不改动）；`ndr/frontend/components/agent-push-panel.tsx`（第 7 期拆页后挂在 `/admin/agent`「智能体对接」页）（地址 / 令牌 / 超时 / 单次条数 / 开关 + 已送达·失败待重发·重发成功·重发失败·待重发批数 + 测试连接 / 立即重发）。配置存 `ndr/backend/app/db/models.py:SystemConfig`（键 `agent_push.params`），环境变量只作默认值。
- **退役**：删 `agent/backend/app/consumer.py`、`agent/backend/app/workers/tasks.py:_notify_done()`、NDR `detector/analyzed.py`、`AnalyzedFingerprint` 模型、两侧 `analyzed_done_queue` 配置、agent 两份 compose 的 `consumer` 服务；`/api/detector/stats` 与 MCP `detector_status` 的 `dedup` 字段改为「判重已下放到智能体」+ 退役前历史计数，前端同步。
- **配置项**：NDR `ST_AGENT_PUSH_URL` / `ST_AGENT_PUSH_TOKEN` / `ST_AGENT_PUSH_ENABLED` / `ST_AGENT_PUSH_TIMEOUT_SECONDS` / `ST_AGENT_PUSH_MAX_PER_PUSH` / `ST_DETECTOR_PUSH_RETRY_QUEUE` / `ST_DETECTOR_PUSH_PROCESSING_QUEUE` / `ST_DETECTOR_PUSH_RETRY_MAX_PER_ROUND` / `ST_DETECTOR_PUSH_STATS_KEY`；agent `ST_PUSH_TOKEN` / `ST_PUSH_DEDUP_KEY` / `ST_PUSH_MAX_ITEMS`。**两侧令牌必须一致**，compose 分别从 `NDR_AGENT_PUSH_TOKEN` / `PUSH_TOKEN` 取。
- **实测**：`/tmp/test_push_api.py` 30 项（鉴权 / 首次 / 重复 / 占位冲突 / 无 IP / 413 / 422 / 指纹与图一致）；`/tmp/test_agent_push.py` 51 项（`deliver` 四态与分片 / 重发队列回灌与失败停止 / 配置合并与 `_to_bool`（"no"/"false"/"0"/"off" 认成假）/ 路由 GET·PUT·test·retry）；`/tmp/test_runner_push.py` 15 项（`_flush` 四态交接、超龄丢弃先于推送、旧队列写不进则回队）。写库测试用 FakeSession / FakeRedis / `dependency_overrides`，**未连真 PG / 真 Redis**。

**验收对照**：agent 挂掉 → 摘要落 `shentong:events:pushretry`、恢复后由检测循环补齐 ✅（测试覆盖 queued → retry_pending 全成功）；地址配错 → 界面「失败待重发 / 最近失败」有计数与原因 ✅；重复推送同一指纹 → 只累加 `event_count`、不投任务、不出第二份报告 ✅。

### 第 6 期 · Wazuh 4.14 集成与容量 ✅ 已完成（2026-02，实施记录）

- **告警与原始日志分流**（`ndr/backend/app/ingestion/normalizer.py` 与 agent 侧同名文件**同步**改）：`normalize_wazuh` 用 `is_archive = not rule` 区分 —— `alerts.json` 每条都带 `rule`，`archives.json`（`logall_json` 的全量原始日志）没有。告警 → `log_type="wazuh"` + 事件类型（`_wazuh_event_type`）；原始日志 → `log_type="wazuh_archive"` + `event_type="wazuh_log"`（不套告警事件类型，规则不会误命中；`ndr/backend/app/rules/builtin.py:1045` 那条 `log_type == "wazuh"` 的规则天然不会跑），`summary` 取 `full_log` 单行化后 200 字。理由：archives 量级远大于告警，混在一起会让告警规则被全量日志触发。
- **原始日志默认只入库、不喂检测器**：`ST_WAZUH_ARCHIVE_TO_DETECTOR`（默认 false）；`ndr/backend/app/collector/normalizer_service.py` 分流处 `elif entry.log_type == "wazuh_archive" and not settings.wazuh_archive_to_detector: stats["archive_es_only"] += 1`，统计行加「原始日志只入库 %d」。红线「ES 落全量」不受影响（Logstash 那条线照旧）。
- **容器侧（opt-in 叠加编排）**：`ndr/docker-compose.wazuh.yml` 加 `wazuh-manager`（官方 `wazuh/wazuh-manager:4.14.8`，不含 indexer/dashboard，暴露 55000 与可选 1514/1515，8 个命名卷）与**独立的** `wazuh-filebeat`（官方 beats 8.15.3，`user: root` + `-strict.perms=false`，只读挂载 `wazuh-logs`，命令指向 `ndr/wazuh/filebeat.yml`）。**为什么另起一个 Filebeat**：manager 自带那个是为「发往 Wazuh indexer」预设的，其 `output.redis` 支持在 4.14 未经实机验证（开放问题 6）——另起一个用我们自己的配置，与 Zeek 线行为一致；Filebeat 只支持单一 output，这也顺带绕开了「Zeek 与 Wazuh 各发各的」这个纠结点。`docker compose -f docker-compose.yml -f docker-compose.wazuh.yml config -q` 与 deploy 版组合**均校验通过**。
- **`ndr/wazuh/filebeat.yml`**：两个 filestream（`alerts.json` 常开 / `archives.json` 由 `WAZUH_ARCHIVES_ENABLED` 控制），都 `ndjson: {overwrite_keys: true, add_error_key: true}` 且**不设 target**（`normalize_wazuh` 从根读 `rule`/`data`/`agent`/`full_log`；`overwrite_keys` 防 Filebeat 的 ECS 顶层 `agent` 盖掉 Wazuh 的 `agent.name`，否则主机名丢失），`fields: {source_system: wazuh}` + `fields_under_root`，`output.redis` 指向 `${REDIS_KEY:shentong:events:collect}`。
- **`ndr/wazuh/enable-logall.sh`**：幂等开 `archives.json` —— 先查 `<logall_json>yes</logall_json>`，`cp -a` 备份后在 `<global>` 之后 **awk 插入两行**；**不整体替换 `ossec.conf`**（4.14.x 小版本默认配置有差异，写错 manager 起不来），找不到 `<global>` 就报错回滚、不动原文件。
- **Wazuh API 管理面**：`ndr/backend/app/api/routes/wazuh.py`（564 行）+ 路由注册 + `ndr/frontend/components/wazuh-panel.tsx`（第 7 期拆页后挂在 `/admin/collect`「采集接入」页）。凭据存 `SystemConfig` 键 `wazuh.params`（环境变量 `ST_WAZUH_API_*` 作默认值，库里优先）；Basic → JWT（`POST /security/user/authenticate`，token 按 `(url, user)` 进程内缓存，按 `expires_at` 提前 60 秒失效）；端点 `GET ""`/`PUT ""`（密码只写不回显、`None` = 不改、`""` = 清空）、`POST /test`、`GET /status`、`GET /agents`（汇总 + 列表）、`GET /rules`（标出 `etc/rules` 下的本地自定义文件）、`POST /rules`（下发后 `GET /rules?filename=…` 取生效条数 + `GET /rules/files/…?raw=true` 回读比对，两者都对才算 `verified`；文件名白名单 `^[A-Za-z0-9_.-]{1,64}\.xml$` 挡目录穿越）。接入状态**同时**看 API 与 ES 入库量：面板的「近 24h 入库 告警 N / 原始日志 N」查 `source_system=wazuh` 并按 `log_type` 分桶 —— 这是链路真通了的证据，不只是「API 通」。
- **容量评估（本机实测 + 纸面推算，2026-02）**：本机跑 `normalize("wazuh", doc)` + `_payload` 实测（CPython 3.11，单核）：**告警 94 µs/条（≈1.06 万条/秒）、原始日志 63 µs/条（≈1.6 万条/秒）**；单条线上载荷 **1.36 KB / 1.17 KB**（含 `raw` 整份原始文档）。据此：
  - **ES 日增量** ≈ 单条载荷 × 日条数（单副本）：10 万条告警/天 ≈ **0.13 GB/天（3.9 GB/月）**；100 万条原始日志/天 ≈ **1.11 GB/天（33 GB/月）**。原始日志是容量主项 —— **先按现场日志量估算，再决定是否开 `logall_json`**。
  - **normalizer 吞吐**：单进程 1 万条/秒以上，高于同机 ES/Logstash 的写入能力 —— 瓶颈在 ES，不在归一化。
  - **Redis**：collect 队列上限 `collector_queue_max=30000`，满载约 **40 MB（告警）/ 34 MB（原始日志）**；历史上出过 noeviction 卡死事故，故内存仍要留余量并按 `maxmemory` 观察。
  - **磁盘**：manager 侧的 `archives.json` 由 Wazuh 自己滚动、**不设保留期**，长期开 `logall_json` 要配合宿主/卷的清理策略。
  - **检测器与推送不受原始日志影响**（默认不喂检测器），仍按告警量计。

**验收**：Wazuh 告警与（可选的）全量日志都进 ES、可查、状态页可见；容量数字落在可接受区间。实施取证：`/tmp/test_wazuh.py` **65/65**（凭据脱敏与 `None`/`""` 语义、JWT 缓存与 401 提示、agents 汇总、规则下发回读校验与文件名穿越拦截、ES 按 `log_type` 分桶与读失败回显）、两侧 ruff/pyright 0 error、`ndr/frontend` `npx tsc --noEmit` 通过、两份 compose 组合 `config -q` 通过、`normalize` 分流与载荷大小本机实测如上。**未取证**：容器侧与真实 Wazuh 环境（无实机）——见 `ndr/wazuh/README.md` 第五节「待实机验证」；容量数字是纸面 + 本机估算，**需在现场按真实日志量复核**。

### 第 7 期 · 界面整理 ✅ 已完成（2026-02，实施记录）

原来八个面板全挤在 `ndr/frontend/app/admin/settings/page.tsx` 一页里（Zeek / Wazuh / ES / Logstash / MCP / 智能体推送 / 降噪 / 排除），随 Wazuh 与推送接入后页面已经过长。现按「配置的是哪一段链路」拆成六个子页，`/admin/settings` 保留为**配置总览索引**（旧链接不失效）：

1. **`ndr/frontend/components/page-shell.tsx`（新增）**：统一页面骨架 `PageShell({title, desc, children})` = 左侧 `Nav` + `ml-56` 主区 + 标题/说明 + `space-y-4` 内容栈，新页不再各写一遍布局。
2. **六个新页面**（均在 `ndr/frontend/app/admin/` 下，套 `PageShell`）：
   - `collect/page.tsx`「采集接入」= `<ZeekPanel section="iface"/>`（监听网卡）+ `<WazuhPanel/>`（API 凭据、下发规则、入库量）
   - `networks/page.tsx`「监控网段」= `<ZeekPanel section="networks"/>`（抓包范围 + 附加 BPF）
   - `storage/page.tsx`「数据存储」= `<EsPanel/>` + `<LogstashPanel/>`
   - `filters/page.tsx`「过滤规则」= `<IngestFiltersPanel/>` + `<ExclusionsPanel/>`
   - `agent/page.tsx`「智能体对接」= `<McpPanel/>` + `<AgentPushPanel/>`
   - `status/page.tsx`「运行状态」= `<StatusPanel/>`（新增，见下）
3. **`ndr/frontend/components/zeek-panel.tsx` 按 section 复用**：签名改为 `ZeekPanel({ section = "all" }: { section?: "all" | "iface" | "networks" })`，标题/说明/可见块随 section 切；`save()` 仍一次性 PUT `{interface, networks, bpf_extra}`，**没显示的那部分原样回传**，因此「采集接入」与「监控网段」两页互不覆盖。旧的 `section="all"` 形态保留。
4. **`ndr/frontend/components/status-panel.tsx`（新增，运行状态页主体）**：只读既有接口、不新增后端 —— `/api/detector/stats`（队列深度 / 投递速率 / 丢弃 / 选主 / Redis 体检）、`/api/agent-push`（送达与重发）、`/api/wazuh`（API 可达性 + 近 24h 入库量）。四个块 + **每 15 秒自刷新**（可关）；Redis 用量超过告警线时显式标红「内存接近上限，整链路会卡死」—— 历史上出过 noeviction 卡死事故，这是最该被看见的前兆。
5. **`ndr/frontend/components/nav.tsx` 七项导航**：规则配置 / 采集接入 / 监控网段 / 数据存储 / 过滤规则 / 智能体对接 / 运行状态；**配置总览（`/admin/settings`）挂在左上角标题**上（标题可点，带齿轮图标），不占导航行。
6. **顺手修掉两处死跳转**：`ndr/frontend/app/setup/page.tsx`（首次向导保存后）与 `ndr/frontend/app/login/page.tsx`（登录后）原本都 `router.replace("/dashboard")`，而本前端没有 `/dashboard`（首页 `app/page.tsx` 即 `/`，它再 redirect 到 `/admin/rules`）→ 都改为 `"/"`。原先这两处会跳到 404。
7. **第 6 期那条说明在拆页后保留**：`networks/page.tsx` 的页面说明里写明「这份清单只约束 Zeek 抓包，不影响 Wazuh 采到的主机日志」，`wazuh.py` 的 `HINT` 里也有一句同样的话。

**验收**：六个子页可直达、旧 `/admin/settings` 仍是有效入口、导航七项高亮正确、首次向导与登录不再跳 404。实施取证：`ndr/frontend` `npx tsc --noEmit` 通过（`agent/frontend` 未改动，另行复跑）；后端本轮无改动，收尾仍复跑 ruff/pyright。**未取证**：浏览器里的实际渲染与交互（未起前端 dev server，按 AGENTS.md 也不本地 build）。

### 每期收尾门禁

仓库根执行：`.venv/bin/ruff check ndr/backend/app agent/backend/app`、`.venv/bin/pyright ndr/backend/app agent/backend/app`；前端在 `ndr/frontend` / `agent/frontend` 下 `npx tsc --noEmit`。构建只走 GitHub Actions（AGENTS.md 禁止本地 build）。

## 8. 开放问题

1. ~~判重窗口的默认值~~（**已定**，第 5 期）：不用「7 天保留期」做判重窗口，而是**事件组时间桶**（`group_bucket_minutes`，默认 30 分钟）+ Redis 占位 TTL 两个桶；库里 `EventGroup` 命中即累加计数，等价于「同一事件组只出一份报告」，与保留期无关。
2. **跨机部署时智能体仍依赖 NDR 的 Redis**：ES 直连已由第 6 节的 MCP 切断，推送那跳也改成 HTTP 了；但 `agent/backend/app/config.py:38-40` 的 Celery broker/backend 仍指 `NDR_REDIS_URL`。本次是否接受这个残留耦合，还是要一并把 broker 也换掉？
3. **监控网段只对 Zeek 生效** —— Wazuh 是主机日志，与网段无关。**已在界面上写明**（第 6 期）：Wazuh 面板的提示语里带一句「Wazuh 采的是主机日志，与『监控网段』无关 —— 那份清单只约束 Zeek 抓包」；第 7 期拆页时保留这条说明。
4. ~~推送载荷除了摘要还带什么~~（**已定**，第 5 期）：载荷 = `{items: [{event_id, fingerprint, digest}]}`，只加 NDR 生成的事件ID与摘要级指纹（供排查与回执对账），触发规则/原始事件数/时间窗仍在摘要里（`rule` / `count` / `first_seen` / `last_seen`），不额外冗余。
5. **MCP 服务与 NDR 后端的代码共享边界**：MCP 服务是独立进程但同镜像，ES 客户端、配置、字段目录会共用 `app.` 包 —— 要不要为它单独切一层接口，还是直接 import 后端模块？
6. **待实机验证（第 2 期遗留 + 第 5 期 + 第 6 期）**：~~Wazuh 4.14 自带的 Filebeat 是否支持 `output.redis`~~（**已绕开**，第 6 期）：不再指望 manager 自带的 Filebeat，`ndr/docker-compose.wazuh.yml` 另起一个官方 Filebeat 容器用 `ndr/wazuh/filebeat.yml` 投 Redis；manager 自带那个只留着报「找不到 indexer」的错。仍待实机：两个 Filebeat（Zeek 与 Wazuh）同时 `LPUSH` 同一 list 的实际吞吐，以及 `ndr/wazuh/README.md` 第五节列出的容器侧清单。
