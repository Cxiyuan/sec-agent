---
name: ndr-tools
description: 使用 NDR 的 MCP 工具做取证与结论回填：先调哪个、证据引用怎么留、结论怎么交、抑制什么时候能提。
whenToUse: 领到分析工单、需要查事件/资产/历史结论、准备 complete_task 交回结论时
---

# 深瞳 · NDR 取数工具（分析闭环专用）

## 你手上的武器（analyst 档 41 个只读工具）

模型侧的名字带命名空间：`mcp__ndr__<工具名>`（例如 `mcp__ndr__search_events`）。
下文用裸名，执行时换成带前缀的名字。

**取数**

- `describe_data`：先调它。拿字段清单、真实时间范围、各来源数据量。**不先看数据地图就搜，等于闭眼开车。**
- `search_events` / `aggregate_events`：检索归一化事件、做统计聚合（谁多、谁新、哪个端口集中）；不要用搜索代替聚合。
- `timeline` / `net_flows` / `dns_queries` / `tls_fingerprints` / `web_requests` / `file_hashes`：细分取证（连接/会话/域名/指纹/HTTP/文件样本），比全量搜索更省时。
- `fetch_window`：按时间窗整窗回溯（自己拉一段再筛）。
- `file_content`：事件带 `extracted`/`fuid` 时取提取件正文（有界只读）。
- `raw_evidence`：取原始证据，返回可被引用的 ref。**结论里引用的每条证据都必须来自它**（或 `search_events` 的返回引用）。

**事件面与历史**

- `search_hits`：看规则命中记录（不含规则严重度结论，严重度由你自己判）。
- `get_event_detail`：单条事件的完整细节（含 `direction`）。
- `prior_findings`：同类主体/规则以前是否分析过、当时结论是什么。**先查历史，避免重复劳动和自相矛盾。**
- `hit_clusters`：把一次扫描命中的几十个地址折成一件事，按簇看规模与分布。
- `get_rule` / `list_rules`：看规则原文与匹配条件（`hint` 只给规则名，猜不出它在抓什么）。

**上下文与态势**

- `asset_context`：这个 IP 是什么资产（业务、责任人、内网角色）。
- `relay_nodes`：哪些地址是反代 / DNS 转发。**不查这个，代理访问会被误判成内网主动外联。**
- `asset_map`：资产分组与拓扑关系。
- `coverage_report`：当前采集/检测覆盖面与盲区——结论要说明"没看到"是不是因为没采集。
- `list_networks`：监控网段（**内外判定的唯一坐标系**；未配置时内网判定失效，结论要打折）。
- `list_filters` / `detector_status`：入库/排除过滤现状、检测器健康（查不到 ≠ 没发生）。

**基线与事实**

- `baseline_lookup`：某 IP / 某维度的长期均值与标准差（是否过观测期）。
- `asset_baseline`：**被访问方资产**的窗口基线（客户端数/请求数均值、样本数、`warmed`）——回答"这次访问量是不是真的异常"。
- `list_observations`：行为基线事实（外连新目标/罕见/持续、异地登录、爆破、404、资产访问量偏离、画像异常）——只有事实，没有结论。
- `egress_baseline`：某资产已学到的外连目的地与白名单（核实「新目标」是否真的新）。
- `entity_profile`：账号/会话画像（长期基线、风险分与异常理由）。

**过程与成本**

- `task_stats`：看队列与自己最近的预算消耗，决定领取节奏。
- `log_step` / `search_traces` / `get_trace`：记过程轨迹、查自己查过什么，避免重复取数。

**派工闭环**

- `claim_tasks` / `complete_task` / `defer_task` / `task_state`。

**抑制**

- `submit_suppression` / `list_suppressions`（撤销抑制不在你的权限里，交给人）。

**身份**

- `server_info`：本 NDR 的授权ID（与项目组织绑定校验）。

## 一条工单的标准流程

1. `claim_tasks` 领活（领不到看 reason：`queue_empty` 是正常回执；NDR 不设领取额度上限）。
2. 看任务回执的 `direction` / `principal_asset` / `affected_assets` / `peers`：主体是监控网段内资产，
   外部地址只是对端；方向不明先 `list_networks` 确认网段。
3. `describe_data` 确认时间窗与字段。
4. `prior_findings` 看历史，`asset_context` 看资产。
5. `search_events` / `aggregate_events` 取证；关键证据用 `raw_evidence` 固化。
6. `complete_task` 交回结论。

判断"查够了"的标准：能回答**谁、对谁、做了什么、成功没有、为什么这么判**。答不上就继续查；时间/预算不够就 `defer_task` 并写清缺什么，别硬下结论。

## 任务类型与你该做什么

| kind | 含义 | 分析重心 |
|---|---|---|
| `hit_cluster` | 同一（归类·网段·小时）的一批规则命中折成一件 | 先看簇全貌（事件数/受影响资产/对端），再决定要不要逐条下钻；别把"扫了几十个 IP"拆成几十个结论 |
| `observation` | 行为基线事实（外连新目标、爆破、异地、404、资产访问量偏离、画像异常） | 事实已给全，判断"是不是异常/攻击"；方向在 hint 里 |
| `novelty` | 资产/服务端口/账号首次出现（反复出现才算） | 判断"新"是正常新增还是不该出现 |
| `coverage` | 从未/久未分析的对象（保留原主体类型） | 做基线建档，别硬找攻击 |
| `shift` / `structure` | 自身数值基线偏离 / 失败响应结构异常 | 先看规模与时间分布 |
| `retest` | 复测当初判误报、且仍挂着抑制的对象 | 重新验证同一现象是否仍无害 |

强度 < 0.45 的事实（`conn_shift`、`egress_rare`）**不会派工**，只能自己 `list_observations` 查到。

## 结论怎么写（complete_task）

- `verdict` 只能是：`true_positive` / `false_positive` / `benign` / `suspicious` / `inconclusive`（中文别名也认，但别自造词）。
- `summary`：一句话结论 + 最关键的 1~2 条证据（不要复述工具输出）。
- `recommendation`：可执行、分主次；没有把握时给"下一步验证方法"，不要直接要求封禁。
- `evidence_refs`：必须是**本次会话真取回过的 ref**，伪造引用会被直接拒绝；
  `verdict=true_positive` 至少要 1 条（benign/false_positive/inconclusive 可空）。
- `confidence`：0~1，拿不准就给低值，别为了好看写 0.9。
- `findings`：结构化事实（命中主体、时间线、内外方向、成功/失败特征）。
- `next_tasks`：需要继续跟的线索（例如"扩大时间窗看同一源 IP""核查目的资产是否打补丁"）。
- 追问与抑制都受服务端上限约束（深度 2 层、单任务 3 条），别指望用它量产任务。

## 抑制（只有误报才允许）

- 只有 `verdict=false_positive` 时才能带 `suppression`。
- 至少要 **2 个匹配维度**（例如源 IP + 规则、目的端口 + 事件类型），否则校验会打回。
- 证据必须来自**至少 2 种不同的取数工具**——只看一段正文就申请抑制不算数。
- 新出现的现象有保护期；抑制不通过往往说明"这可能是新攻击面"，改判 `suspicious` 更合适。

## 硬规矩

- **不许编造**：没查到的字段就说没查到，没取回的引用不许写。
- **不越权**：只做 analyst 档给你的动作；撤销抑制、改规则、改网段都不在你的工具面里。
- **不重复**：`prior_findings` 已经定过性的同类线索，除非有新证据，引用旧结论即可。
- **不空转**：同一查询连续两次没新信息就换角度（换时间窗、换聚合维度、看资产上下文）。
