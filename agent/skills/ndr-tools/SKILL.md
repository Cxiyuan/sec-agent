---
name: ndr-tools
description: 使用 NDR 的 MCP 工具做取证与结论回填：先调哪个、证据引用怎么留、结论怎么交、抑制什么时候能提。
whenToUse: 领到分析工单、需要查事件/资产/历史结论、准备 complete_task 交回结论时
---

# 深瞳 · NDR 取数工具（分析闭环专用）

## 你手上的武器（analyst 档 22 个工具）

模型侧的名字带命名空间：`mcp__ndr__<工具名>`（例如 `mcp__ndr__search_events`）。
下文用裸名，执行时换成带前缀的名字。

**取数**

- `describe_data`：先调它。拿字段清单、真实时间范围、各来源数据量。**不先看数据地图就搜，等于闭眼开车。**
- `search_events`：按条件检索归一化事件（五元组、协议字段、时间窗）。
- `aggregate_events`：做统计聚合（谁多、谁新、哪个端口集中），看规模与频率；不要用搜索代替聚合。
- `raw_evidence`：取原始证据，返回可被引用的 ref。**结论里引用的每条证据都必须来自它**（或 `search_events` 的返回引用）。

**事件面与历史**

- `search_hits`：看规则命中记录（不含规则严重度结论，严重度由你自己判）。
- `get_event_detail`：单条事件的完整细节。
- `prior_findings`：同类主体/规则以前是否分析过、当时结论是什么。**先查历史，避免重复劳动和自相矛盾。**
- `hit_clusters`：把一次扫描命中的几十个地址折成一件事，按簇看规模与分布。
- `get_rule` / `list_rules`：看规则原文与匹配条件（`hint` 只给规则名，猜不出它在抓什么）。

**上下文与态势**

- `asset_context`：这个 IP 是什么资产（业务、责任人、内网角色）。
- `relay_nodes`：哪些地址是反代 / DNS 转发。**不查这个，代理访问会被误判成内网主动外联。**
- `asset_map`：资产分组与拓扑关系。
- `coverage_report`：当前采集/检测覆盖面与盲区——结论要说明"没看到"是不是因为没采集。

**派工闭环**

- `claim_tasks` / `complete_task` / `defer_task` / `task_state`。

**抑制**

- `submit_suppression` / `list_suppressions`（撤销抑制不在你的权限里，交给人）。

## 一条工单的标准流程

1. `claim_tasks` 领活（领不到看 reason：`queue_empty` 是正常回执；NDR 不设领取额度上限）。
2. `describe_data` 确认时间窗与字段。
3. `prior_findings` 看历史，`asset_context` 看资产。
4. `search_events` / `aggregate_events` 取证；关键证据用 `raw_evidence` 固化。
5. `complete_task` 交回结论。

判断"查够了"的标准：能回答**谁、对谁、做了什么、成功没有、为什么这么判**。答不上就继续查；时间/预算不够就 `defer_task` 并写清缺什么，别硬下结论。

## 结论怎么写（complete_task）

- `verdict` 只能是：`true_positive` / `false_positive` / `benign` / `suspicious` / `inconclusive`（中文别名也认，但别自造词）。
- `summary`：一句话结论 + 最关键的 1~2 条证据（不要复述工具输出）。
- `recommendation`：可执行、分主次；没有把握时给"下一步验证方法"，不要直接要求封禁。
- `evidence_refs`：必须是**本次会话真取回过的 ref**，伪造引用会被直接拒绝。
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
