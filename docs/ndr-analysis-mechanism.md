# 深瞳 NDR · 智能体驱动分析机制（改造方案与接口契约）

> 状态：**部分实施**。阶段 0（精准抑制）已落地，其余待建。
> 本文是决策记录，不是愿望清单：所有"已定"项都不要再在对话里重开。
> **给 agent 团队的落地契约见 `docs/agent-contract.md`**（门铃载荷、领取循环、抑制六道门槛、错误码）。
> 立项初衷：**以 AI 智能体为驱动**分析 NDR 采集的网络元数据；NDR 不靠规则检测替智能体下判断，
> 而是由智能体自己规划看什么数据、查什么日志。

---

## 一、为什么要改（现状与病根）

| 事实 | 后果 |
| --- | --- |
| NDR 规则命中 → 聚合摘要 → HTTP 推送给智能体（`detector/push.py`） | 智能体退化成"规则结果解释器"，分析入口被 NDR 判断垄断 |
| 所有摘要都推，无预算 | 240 事件/秒 → ~5 摘要/分钟 全部推过去，吃不消 |
| 智能体侧已有 20 个 MCP 取数工具（`ndr-mcp`），但只在被推送后才用 | 取数能力齐了，缺的是"活从哪来、怎么限量" |
| `detector_status` 里明写「判重已下放到智能体」，NDR 侧判重闸门已退役 | NDR 侧对"要不要再分析一次"完全无记忆 |
| 行为分析误报（会话画像 10.3 万实体、`[C2信标-04]` 一条弱签名占高危事件 72%） | 噪声淹没真信号 |

**结论**：把"推送"改成"派工 + 主动领取"，并给智能体一份能自主规划的数据地图。

---

## 二、已锁定的 7 项决策

| # | 决策 | 内容 |
| --- | --- | --- |
| D1 | 领取通道 | **门铃 + MCP 领取**：NDR 只在有新线索时按门铃（**不含任何数据**），智能体收到后经 MCP `claim_tasks` 领取并自主决定查什么；另加**低频自轮询兜底**（建议 15 分钟） |
| D2 | 优先级归属 | **NDR 只排客观强度**（显著性 p、是否首见、影响面规模、距上次分析时长），**不写威胁语义** |
| D3 | 找活方式 | **双通道**：① 数据地图（智能体自主选目标）② 客观线索队列（NDR 报"变了/第一次见/很久没看"） |
| D4 | 规则命中的地位 | `hit_events` **进队列**（`kind=hit`），但只按客观强度排队（规模/首见），**不用 rule_severity**；智能体可整体不领这类活 |
| D5 | 切换方式 | 门铃**直接复用现有推送路径**，载荷一次性换成门铃对象（不分两条路径、不留双载荷语义）；两侧同版本上线 |
| D6 | 队列溢出 | **延后重排 + 队列容量**：不静默丢弃；同族线索合并计数（`coalesced`），超过容量按强度替换或可见计数后丢弃 |
| D7 | 误报抑制 | **全自动生效**（够证据就连事件生成都抑制），但必须过**机械护栏**（见第七节）；理由必须落白名单码，不接受自由文本当判据 |

**范围边界**：本方案只做 **NDR 侧 + 给智能体团队的接口契约**；`@sec-agent/xdr-ingest` 插件侧（收门铃、起会话、领取循环）由智能体团队实现。NDR 不限制领取额度或并发。

---

## 三、架构

```text
NDR（只做廉价统计与派工，不替智能体下威胁判断）              智能体（自主规划）
┌───────────────────────────────┐                ┌──────────────────────────────┐
│ 全量元数据 ES / PG             │◄──取数────────│ 数据地图：describe_data /      │
│   （永不被"抑制"影响）         │                │   asset_map / coverage_report │
│                               │                │   → 自己挑目标、自己定计划     │
│ 候选生成器（检测器 leader 内） │                │                                │
│  novelty / shift / structure  │   写队列       │  claim_tasks(limit, kinds,    │
│  coverage / hit(=kind)        ├───────────────►│     min_strength, wait)        │
│        ↓                      │  analysis_tasks│  fetch_window / logs / profile │
│  analysis_suppressions 拦截   │                │  complete_task(verdict,        │
│        ↓                      │◄───────────────│     evidence_refs, suppression)│
│ 门铃（无数据·合并限频）───────┼───────────────►│  defer_task / task_stats       │
│ 复用 agent_push 路径          │   POST         │        ↓                       │
└───────────────────────────────┘                │  analysis_results / 抑制条目   │
                                                 └──────────────────────────────┘
```

红线：

1. **门铃不含数据**：只有 `{queue_len, top_kind, max_strength, watermark, ts}`。含了数据，智能体就又变成被动解释器（违背 D1/D3）。
2. **派工不是结论**：任务给的是"入口 + 客观事实"，不给"这是攻击"。
3. **原始数据永不被抑制影响**：抑制只改变"要不要打扰分析"，ES/入库/基线学习照旧（否则一次误抑制就永久失去取证能力）。

---

## 四、数据模型

### 4.1 `analysis_tasks`（线索队列，待建）

| 列 | 说明 |
| --- | --- |
| `id` | UUID 主键 |
| `dedupe_key` | **唯一**，`{kind}\|{subject_kind}:{subject}\|{feature}\|{时间桶}` —— 同现象同桶只一条（防队列爆） |
| `kind` | `novelty` / `shift` / `structure` / `coverage` / `hit` |
| `strength` | 0~1 客观强度（见第五节公式） |
| `priority` | `round(strength*100)`；同分按 `created_at` 先进先出 |
| `subject_kind` / `subject` | `ip` / `asset` / `segment` / `protocol` / `account` / `cluster` |
| `window_start` / `window_end` | 建议分析的时间窗 |
| `hint` | **客观元数据**：均值/当前值/p 值/是否首见/涉及对象数/原始日志字段。不含 severity、结论或查询计划 |
| `state` | `pending` / `claimed` / `done` / `deferred` / `stuck` / `expired` |
| `lease_until` / `claimed_by` / `attempts` | 租约（超时自动回收）、领取令牌名、领取次数 |
| `coalesced` | 被合并的同族条数 |
| `parent_id` / `depth` | 追问链（`depth` 超上限即拒绝） |
| `created_at` / `updated_at` | |

索引：`(state, priority DESC, created_at)`、`dedupe_key` 唯一、`(subject)`、`lease_until`。

### 4.2 `analysis_results`（结论回收，待建）

`id`、`task_id`、`subject_kind`、`subject`、`kind`、`verdict`、`confidence`、`summary`、
`findings(JSONB)`、`evidence_refs(JSONB)`、`tools_used`、`duration_ms`、`claimed_by`、`created_at`。

`verdict` 词表（与 `record_conclusion` 一致，避免两套语义）：
`true_positive` / `false_positive` / `benign` / `needs_more` / `inconclusive`。

### 4.3 `observed_subjects`（"首见"与覆盖率的地基，待建）

`kind`（asset/service_port/peer/protocol/signature/…）、`value`、`first_seen_at`、
`last_seen_at`、`seen_count`、`analyzed_count`、`last_analyzed_at`。主键 `(kind, value)`。

- 只在这张表上算 **novelty** 与 **coverage**，避免"每次现算"打爆 ES；
- 按 `last_seen_at` 定期清理（保留期与 `hit_events` 保留期同一套约定），**不许只增不减**。

### 4.4 `analysis_suppressions`（精准抑制，✅ 已实施）

见第七节。

---

## 五、候选生成与客观强度

### 5.1 生成器落点

**在检测器主循环内**（leader 单写者，与 `engine.maybe_flush()` 同节奏），不新增容器：

- 每窗口对**全量事件**（非仅命中规则的）统计三个计数特征 —— 这条采样通道已存在
  （`baseline/sampler.py`），`shift` 直接复用它的判定结果；
- `novelty`：**跨窗口反复出现、且还在"新面孔窗口"内**的对象 —— 新资产 / 新服务端口 /
  新外部对端 / 新协议 / 新签名（查 `observed_subjects`）。
  **为什么不是"第一次见到就派工"**：镜像口上的一次性连接（代理/NAT 的临时套接字、扫描器的
  单次探测）每次端口都不同，一个采集窗口能刷出 25 万个"新服务端口"，队列直接被垃圾线索
  灌满（实测丢弃 1.5 万条、真正的新服务被挤掉）。所以只把「第二个窗口仍出现」的对象交出去
  （`seen_count ≥ 2`），首次出现时间一并写进 `hint`，由智能体自己判断是新服务还是老熟人。
  **为什么"首见"只派一次**：首见是一次性事件，同一个对象不该每个小时再排一条工
  （实测 3581 个资产轮着来、队列每小时涨 700，真正该看的规则命中被挤在后面）。所以
  `novelty` 的去重键**不带时间桶**（同一现象只排一条，后来只累加出现次数；现象变强时
  重新排队），并且对象首次出现超过 `analysis.novelty_newcomer_hours`（默认 24 小时）
  就不再算"新面孔"——它已经是环境的一部分，改由 `coverage`（久未分析的盲区）提醒；
- `structure`：失败率、端口熵、周期性初筛（只给事实，如「404 占比 0.62」）；
- `coverage`：`observed_subjects` 里"从未 / 久未分析"的对象（低强度，保证不抢占）；
- `hit`：新落库的 `hit_events`（D4）。

异常处理：生成器整体 `try/except`，失败只计数（`candidate_error`），**绝不影响检测与入库**。

### 5.2 强度公式（**取最大，不求和**）

```text
strength = max(rarity, significance, scale, staleness, coalescing)
```

| 分量 | 口径 |
| --- | --- |
| `rarity` | 首见 = 1.0；14 天内见 ≥2 次 = 0.4；长期高频见 = 0.1 |
| `significance` | 计数上尾 p 值 → `clamp(-log10(p)/8, 0, 1)`（复用 `baseline/poisson.py`） |
| `scale` | 现象涉及对象数（不同源/目的）→ `log10` 归一 |
| `staleness` | 距上次分析：从未 = 1.0，>7 天 = 0.9，>2 天 = 0.5 |
| `coalescing` | 同族合并次数 `n` → `+0.05*min(n,5)` |

**为什么不求和**：画像侧加和打分的教训（三个弱信号 ≈ 一个强信号，OA 换手机就过线；
`[C2信标-04]` 一条弱签名刷出 200+ 高危）。求和必然重演。

### 5.3 `hit` 类的强度

只用**规模与首见**：该签名近 N 天涉及多少个不同源、是否首次出现该 SID。**绝不读 `rule_severity`**。

---

## 六、队列容量、公平与溢出（D6）

### 6.1 队列与租约参数（界面可调，进 `system_config`）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `analysis.followup_depth` | 2 | 追问链深度 |
| `analysis.lease_seconds` | 900 | 租约（超时回收，`attempts += 1`） |
| `analysis.pending_ttl_hours` | 48 | 过老的线索自动 `expired` |
| `analysis.queue_capacity` | 2000 | 队列硬上限 |
| `analysis.stuck_after_attempts` | 5 | 反复领取不交回 → `stuck`，不再派发，界面可见 |
| `analysis.dedupe_bucket_minutes` | 60 | 同一现象的去重时间桶（`novelty` 不用时间桶：首见只派一次） |
| `analysis.novelty_newcomer_hours` | 24 | 新面孔窗口：对象首次出现后多久内还算"新" |
| `analysis.doorbell_cooldown_seconds` | 180 | 门铃合并限频 |
| `analysis.enabled` | true | 总开关 |

### 6.2 领取语义

`claim_tasks` 必须**原子**：`SELECT ... WHERE (state = 'pending'
OR (state = 'deferred' AND (lease_until IS NULL OR lease_until <= now))
OR (state = 'claimed' AND lease_until < now)) ORDER BY priority DESC, created_at
FOR UPDATE SKIP LOCKED LIMIT n`，然后同事务把状态改成 `claimed` 并写租约。

**`deferred` 必须等租约到期才可再领**：`defer_task` 写的「下次可领时间」是给智能体的承诺，
领取查询若把 `pending` 与 `deferred` 一视同仁，这条承诺就是空的 —— 实测同 3 个任务被反复
领走、反复没交回、反复延后，日志刷了 40 多次，纯烧模型调用。

**NDR 不限制领取额度或并发**：没有每令牌/每小时的配额、没有保留名额、没有按令牌的在跑数上限。
一次领取多少、多久领一次由智能体自己决定；服务端只负责原子领取和任务生命周期。

### 6.3 队列满 / 溢出

- 同 `dedupe_key`：不新增行，`coalesced += 1` + 记 `task_merged`；
- 新线索强度**高于**队列里最低强度：替换之（旧行 `state=expired` + `superseded` 计数，保留 id 供审计）；
- 否则：不入队，只累加 `task_dropped_overflow` —— **可见，不静默**。

---

## 七、精准抑制（D7，✅ 已实施 v2）

### 7.1 匹配口径：结构化条件树（**不用扁平四元组**）

```json
{"logic": "and", "rules": [
  {"field": "signature_id", "op": "eq", "value": "9110004"},
  {"field": "src_ip", "op": "eq", "value": "10.1.2.3"},
  {"field": "http.hostname", "op": "contains", "value": "example.edu.cn"}
]}
```

复用规则引擎的 `evaluate_conditions`（同一套语法、同一套算子 `eq/ne/contains/regex/gt/gte/lt/lte/exists`），
字段必须落在白名单里（`suppression.ALLOWED_FIELDS`）：

`src_ip` `dst_ip` `dst_port` `segment`（v4 /24、v6 /64）`protocol` `rule` `signature_id`
`http.uri` `http.hostname` `user_agent` `ja3` `fuid`

三条硬约束：

- **≥2 个独立维度**（同一字段写两次不算），`min_match_dims` 下限**硬编码锁 2** ——
  只写一条签名/一条规则等于关掉一条检测规则；
- **正文类字段不在白名单**（`payload`/`body`/`resp_body`）：正文能被投毒
  （攻击者在里面写「这是内部测试流量」），不能当判据；要按内容收敛用 `http.uri`；
- **宽域条件拒绝**：`*`/`any`/空值/`0.0.0.0/0` 这类等于没约束；`src_ip` 只收单地址（按网段请用 `segment`）。

### 7.2 命中后的行为（求值点在规则命中后、聚合前）

| mode | 事件 | 派工/推送 | 记录 |
| --- | --- | --- | --- |
| `suppress` | **不生成** `hit_events` | 不派工、不推送 | 抑制条目 `hits += 1`、`last_hit_at` |
| `record_only`（降级档） | 仍生成（`excluded=True`，原因写「已抑制(条目名)」） | 不投递、不进基线 | 同上 |

原始数据（ES）、入库、基线学习**均不受影响**。

**两个档位都不再派工**（`excluded` 的摘要不进线索队列）：智能体已经为这类现象交过结论
并提交了抑制，再排一遍工只是让它重复分析同一件事 —— 也就不会为它按门铃。

### 7.3 六道机械门槛 + 三道兜底（"全自动"的形态）

| # | 门槛 | 拒绝/降级表现 | 参数 |
| --- | --- | --- | --- |
| G1 | 结构化匹配 + 字段白名单 + 拒绝宽域 | `field_errors` | — |
| G2 | **≥2 个独立维度**（硬下限） | `至少要 2 个独立匹配维度` | `min_match_dims` |
| G3 | **证据真实性**：引用必须本会话真取回 | `这些引用本会话没真取回过` | — |
| G4 | **证据多样性**：≥3 条且来自 ≥2 种取数工具 | `证据只来自 N 种取数工具` | `min_refs` / `min_tools` |
| G5 | **置信度** ≥0.85 | `置信度 x 低于门槛` | `min_confidence` |
| G6 | **新现象保护期** 24h（首见不足不许抑制） | `该现象首见仅 x 小时` | `newcomer_hours` |

| # | 兜底 | 行为 |
| --- | --- | --- |
| B1 | **爆炸半径试算**（近 7 天命中量/源数/跨网段数任一超阈值） | 自动降级 `record_only`（事件仍生成） |
| B2 | 试算失败（影响面未知） | 同样降级 `record_only` |
| B3 | **单条命中量熔断**（累计 >20000 条） | 自动撤销 + WARN + `stats` 可见 |

其余：默认 **14 天到期**（上限 30，到期重新申请会重新试算）、活跃条目上限 200
（超出按最早到期淘汰）、`auto_apply=false` 可整体退回"只抑制派工"灰度档、
求值/读表异常一律 **fail-open**（照常派工）。

**为什么不需要人工审批**：G1~G6 与 B1~B3 全是服务端能算的客观判据；
"攻击者在正文里写『这是测试流量』"既进不了字段白名单，也过不了证据多样性 + 置信度 + 保护期。
再加原始数据不受抑制（逃生门），全自动的风险是有界的、可回滚的。

### 7.3.1 自动生效闭环（降级 → 收窄 → 同名重提 → 生效）

降级不是死胡同，**闭环由智能体自己走完，人工只做复核**：

1. 智能体 `submit_suppression` → 服务端试算 → 影响面在护栏内就 **直接生效**（`mode=suppress`）；
2. 影响面超阈值 → 降级 `record_only`，并在返回里写清 **哪个维度超了、实际值、上限、怎么收窄**
   （`downgrade.dimension / actual / limit / reason / advice`）；
3. 智能体按建议收窄条件（例如补 `src_ip`、把匹配面改成"某目的主机 + 某端口"），
   用**同一个 `name`** 重新提交 → **同名覆盖**旧条目（不会堆一串半成品）→ 通过护栏即真正生效；
4. 生效后：这类现象**不再派工、不再按门铃**（§7.2），智能体侧也**记住**它 ——
   插件把生效中的抑制同步进本地记忆（`xdr_ingest_task_seen`），同一现象从别的线索类型
   再冒出来时**不起会话**直接交回，省一次模型会话与一轮取数；
5. 兜底不变：命中量熔断、到期失效、真阳性回弹（`suppression_rebound`）都还在。

### 7.4 与既有三处抑制面的分工

| 机制 | 谁写 | 语义 | 事件 |
| --- | --- | --- | --- |
| `ingest_filters` | 人工 | 不投检测器（**ES 仍有全量**） | — |
| `exclusion_filters` | 人工 | 事件仍生成、跳过模型 | 生成 |
| `alert_dispositions` | 人工/智能体 | 画像/实体侧降权（不参与打分） | — |
| **`analysis_suppressions`** | **智能体（带证据）** | **不派工、不推送** | `suppress` 不生成 / `record_only` 生成 |

求值顺序：入库过滤 → **抑制匹配（本机制）** → 排除过滤（人工）→ 规则匹配 → 事件落库。

---

## 七点五、从 artex 双图借鉴的四个机制（✅ 已实施）

参考了 `autonomous-pentest-agent`（artex 衍生）的双图架构，**只借机制、不搬结构**。
判断依据是"它解决的是不是我们的空缺"以及"会不会与我们已有能力重叠"。

### 7.5.1 锚点（结论 ↔ 资产多对多）

**借什么**：它用 `(node_id, asset_id)` 把探索图里的意图/事实/结论锚定到资产图上，
于是覆盖度与影响面都能双向查。

**我们的空缺**：`analysis_results` 只挂**单个 `subject`**。一条「这台是反向代理」的结论
影响不到它后面的 20 台后端，覆盖度也只能回答"分析过没有"，答不了"对这台机器我们知道什么"。

**落地**：新表 `analysis_anchors(result_id, task_id, asset_kind, asset_value)`；
`complete_task(anchors=[{kind,value}])` 写入（服务端归一，单结论上限 50）；
`prior_findings(via_asset=true)` 与 `coverage_report(by="asset")` 走它。

### 7.5.2 冷摘要（概览恒定大小）

**借什么**：cold-digest 把冷的子图压成摘要节点，保证"概览恒定、明细按需下钻"。

**我们的空缺**：`prior_findings` 逐条吐原始结论，返回量随历史线性膨胀，上下文迟早被三个月前撑爆。

**落地**：`analysis_results.digested_at` + 表 `analysis_digests`；
后台每 6 小时把超过 `analysis.digest_after_days`（默认 30）的结论按对象折叠成一句
（次数 + verdict 分布 + 最近一次）。**原始行永不删除**，`detail=true` 仍可下钻。

### 7.5.3 过程轨迹（信息以"步骤"为粒度流动）

**借什么**：它的 worker 能检索**别的 worker 的执行过程**（自动排除自己），
于是"某个报错、某段响应、某个隐藏参数"这类观察不会随会话消失。

**落地**：表 `analysis_traces` + `log_step` / `search_traces` / `get_trace`；
每任务上限 20 条、`summary ≤ 500` 字。

**红线（与它不同的地方）**：轨迹是**未经核实的他人观察**，
**绝不能**作为抑制证据 —— 抑制的 `evidence_refs` 只认 `es:`/`ev:`（本会话真取回过的数据）。
理由：轨迹是模型写的自由文本，而抑制是"关掉一部分检测"，判据必须站在取数结果上。

### 7.5.4 复测（主动回头看）

**借什么**：它的 retester 用独立会话定期复核既有结论，三态（仍成立/已变化/无法确认）。

**我们的空缺**：抑制**到期是静默的**，没人回头看它是不是又变成真问题
（攻击者换手法、业务变更、或者当初就判错）。我们只有"真阳性自动回弹"——**被动**等事实打脸。

**落地**：新线索类型 `retest`。同时满足三条才生成：最近结论是 `false_positive`/`benign`、
距上次分析超过 `analysis.retest_days`（默认 30）、且该对象身上有**生效中的抑制**。
每轮上限 `analysis.retest_max_per_round`（默认 5，0=关闭），不能挤掉新线索。
复测若判 `true_positive`，已有的 `suppression.rebound_for_subject` 会自动撤销那条抑制。

### 7.5.5 工具面收敛（替代它的 deferred tools）

artex 用"系统提示尾部只列工具名、skill 加载时解锁"来省上下文。
**dsh 没有这套机制**（MCP 工具本来就以结构化定义下发），所以按**同族能力**落地：
按档位收窄工具面 —— `/mcp` 是 analyst 档（22 个），`/mcp/full` 是全量（43 个），共用一层鉴权。
附带修掉一个真实缺口：原来任何持令牌方都能看到并调用 `revoke_suppression`。

### 7.5.6 明确不借

| 机制 | 为什么不借 |
| --- | --- |
| planner / worker 分离 + 跨唤醒共享 todolist | 它解决"城市级目标上串行走多步利用链"；我们的任务是单对象短调查（~8 次工具调用），加规划层是过度设计 |
| 人在环路审批门（guard / intercept） | 已定全自动 + 六道机械门槛，不回退人工审批（审批详情只能作界面参考） |
| MITM 记录代理 / 异步补全（enrich） | 与 NDR 已有能力（全量流量、资产台账）重叠 |
| 本地启发式判 severity | 与"智能体判断、NDR 只给事实"的架构冲突，也不符合我们"不读 rule_severity"的决策 |

### 7.5.7 终态原因（顺手补的）

`analysis_results.terminal_reason`：`concluded` / `budget_exhausted` / `tool_error` / `timeout` / `aborted`。
为什么不只看 verdict：`inconclusive` 分不清「查了没证据」和「根本没查完」——
前者说明线索质量差，后者说明预算不够，处置方式相反。

---

## 八、MCP 契约（新增工具）

现有 **43 个**（10 查 ES + 33 NDR 原生：状态/基线/画像/取数/写回 + 派工与轨迹 11 + 事件与抑制 7 + 资产与聚合 6），
令牌鉴权 + Redis 调用记录（含耗时）。MCP 只准依赖 `app.mcpapi` 门面，
边界由 `tests/py/test_mcp_boundary.py` 用 AST 静态守住（新工具跨了 3 个子系统也没穿透）。

### 8.1 队列四件

```text
claim_tasks(limit=0, kinds="", min_strength=0.0, wait_seconds=0)
 → {tasks:[{id,kind,strength,priority,subject_kind,subject,feature,window_start,window_end,hint,
            attempts,coalesced}],
     watermark}

complete_task(task_id, verdict, summary, confidence=0.0, findings={}, evidence_refs=[],
              next_tasks=[], tools_used=0, duration_ms=0, suppression={})
 → {ok, task_state, results_written, followup_rejected_reason?, suppression_result?}

defer_task(task_id, reason="", retry_after_seconds=3600) → {ok, state, next_due_at}

task_stats() → {queue_by_kind, queue_by_state, wait_p50_s, throughput_per_hour,
                merged, superseded, stuck, coverage:{assets_total, assets_analyzed_7d, never_analyzed}}
```

规则：

- `next_tasks` 受 `followup_depth` 限制，超限**拒绝并说明原因**（不静默丢）；
- `complete_task` 的 `verdict` 必须落词表，未知值报错并列出可选值（沿用 `record_conclusion` 的做法）；
- `claim_tasks` 不设令牌额度、小时配额或并发额度，领取数量/节奏由智能体决定；
- `wait_seconds` 长轮询上限 30 秒。

### 8.2 事件面与抑制（G1 / G2 / G3，✅ 已实施）

```text
search_hits(ip, source_kinds, cluster_id, minutes, limit)
   → 命中事件清单（新架构没有推送，事件靠自己捞；返回 cluster_id 把一次扫描折成一件事）
get_event_detail(event_id)
   → 单条事件完整内容（事件类型 / 三类来源 / 源与目的 / 证据 / 簇）+ 已有结论
prior_findings(subject, kind, verdict, limit)
   → 该对象的既往结论：开工前先问「看过没有」，避免重复分析白烧预算
submit_suppression(match, reason_code, evidence_refs, confidence, name?, note?, ttl_days?, task_id?)
   → 申请自动抑制（六道机械门槛 + 爆炸半径试算）；影响面过大会降级返回 mode=record_only
list_suppressions(q, enabled_only, include_expired, limit)
   → 当前精准抑制（含命中数、试算结果与到期）；抑制会挡派工，不看一眼无法解释「为什么没活」
revoke_suppression(suppression_id, reason)
   → 主动收回一条抑制；reason 必填（抑制是关掉一部分检测，放开同样要留审计）
add_task(subject, subject_kind, kind, note, strength)
   → 智能体自己登记线索（外部情报/巡逻发现时用）；同一套去重与容量规则，不插队
```

护栏（均在打库前的早退路径上）：未知的 `source_kinds` / `kind` 直接报错并列出可选值；
`strength` 脏值报错而不是静默兜底；`revoke` 缺原因直接拒。

### 8.3 事件聚合、资产上下文与画像降权（M1–M6，✅ 已实施）

```text
asset_context(ips | q, criticality, limit)
   → 台账上下文：主机名 / 重要级别 / 责任人 / 分组 / 标签
     + unknown_ips（没登记 ≠ 不重要，必须显式区分）——判严重度的唯一依据
hit_clusters(minutes, source_kind, limit, include_ignored)
   → 告警簇视图（一簇多少事件、多少不同源、最高级别、首末时间）
hit_stats(minutes)
   → 事件面统计：总量、按三类来源/级别分布、TOP 事件归类、趋势
list_rules(source_kind, limit)
   → NDR 现在到底在检测什么（防「没事件」被误读成「没攻击」）
relay_nodes()
   → 中继清单与角色/侧向（反代的 src_ip 是代理本身，不知道就会把代理访问误判成内网主动外联）
record_disposition(profile_id, verdict, signal, note)
   → 画像级误报降权（与事件流 suppression 分工不同：这里管账号/会话实体与单路证据）
```

**只读优先**：以上只有 `record_disposition` 是写动作，其余全部只读；
六个能力都复用界面既有实现（`assets_center.records*`、`hits.clusters/hits_stats`、
`rules.all_rules`、`relay_nodes.describe`、`profile.disposition_for`），
**没有第二套口径**——这一点由 `test_single_source_of_truth_for_shared_paths` 钉住。

### 8.4 数据地图（D3 的另一条腿，✅ 已实施）

```text
describe_data()            每来源量级 / 近 24h 增量 / 字段数 / 可聚合字段 / 时间覆盖
                           （与时间边界同一次聚合拿全，不多打 ES；track_total_hits 防 1 万截断）
asset_map(kind="", limit=100)
   → 资产 / 服务端口 / 外部对端 / 协议 / 签名 / 账号清单
     + first_seen + last_seen + seen_count + analyzed_count
coverage_report(days=7, kind="", limit=100)
   → 覆盖率、从未分析、久未分析的对象（自主找活入口）
```

**只读**、不含威胁语义、不返回建议结论。

---

## 九、REST（NDR 界面与集成用）

已实施（`/api/suppressions`，8 个）：清单 / `stats` / `config`(GET,PUT) / `config/reset` /
`preview` / `POST /` / `PUT /{id}` / `POST /{id}/revoke` / `POST /{id}/restore`。

待建（`/api/analysis`）：

| 端点 | 用途 |
| --- | --- |
| `GET /api/analysis/tasks` | 队列浏览（state/kind/subject/q/limit/offset/sort） |
| `GET /api/analysis/tasks/{id}` | 任务详情（含 hint 全量与结论历史） |
| `GET /api/analysis/results` | 结论清单（按 verdict/subject/时间筛） |
| `GET /api/analysis/stats` | 积压、等待分位、吞吐、merged/superseded、**覆盖率**、verdict 分布 |
| `GET /api/analysis/coverage` | 覆盖率明细（哪些对象从没看过） |
| `POST /api/analysis/tasks` | **人工派工**（运维"我想看看这台"直接进队） |
| `GET/PUT /api/analysis/config`、`POST /api/analysis/config/reset` | 6.1 全部参数 |

**约定（沿用仓库既有规范）**：列表统一 `{items,total,returned}`；写操作 400 参数错 /
404 不存在 / 409 重名；参数只认白名单键，校验失败回 `field_errors`；时间入参 UTC ISO，
界面展示北京时间；错误回中文 `detail`。

**待议（不阻塞）**：`analysis_suppressions` 与 `alert_dispositions` 是否合并成一张表两类作用域。

---

## 十、门铃（D1 + D5）

- 走**现有** `detector/push.py` 的 HTTP 通道（沿用地址、令牌、超时、重试队列、
  `sent/queued/retried/retry_lost/undelivered` 指标与「测试连接」）；
- 载荷：

```json
{"doorbell": {"queue_len": 7, "top_kind": "shift", "max_strength": 0.83,
              "watermark": "2026-10-23T09:12:00Z", "ts": "2026-10-23T09:12:03Z"}}
```

- **合并限频**：Redis `SET ... NX EX doorbell_cooldown_seconds`；队列**从空变非空**时立即发一次（不受冷却）；
- 失败落现有重试队列（"一批"= 一次门铃），语义不变；
- `detector_max_digests_per_minute` / `max_per_push` 对门铃失去意义 → 从配置面移除（门铃自身由 `analysis.doorbell_cooldown_seconds` 限频）；
- **未配置地址时不发门铃、也不累加 `undelivered`**（当前该值已在无消费者时长期增长，属噪声）。

---

## 十一、验收指标（必须能量出来）

| 指标 | 目标 | 来源 |
| --- | --- | --- |
| **自主度** | 智能体自建任务（`coverage`/`structure` + 追问）占完成总数 ≥ 40% | `analysis_results` vs `tasks.kind` |
| **成本** | 平均 `tools_used` ≤ 8（NDR 不设领取额度上限） | `task_stats` |
| **覆盖率** | 近 7 天被分析过的内网资产占比 ≥ 60%，且逐周上升 | `/api/analysis/coverage` |
| **积压** | `pending` p95 等待 < 2 小时 | `/api/analysis/stats` |
| **误抑制回弹** | 被抑制匹配后来又判 `true_positive` 的次数 = 0（出现即人工复查） | 抑制条目 ↔ `analysis_results` 关联 |
| **降噪** | 「木马与后门活动」这类噪声事件量下降 ≥ 90% | `hit_events` 按 rule 统计 |

---

## 十二、实施顺序

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| **P0** | 精准抑制：表 + 匹配 + 试算降级 + 护栏 + 8 个 REST + 热路径接入 + 守卫 | ✅ 完成（待提交/部署） |
| **P1** | 队列骨架：`analysis_tasks` + `claim/complete/defer/task_stats` + `shift`/`novelty` 两类候选 + 门铃替换推送载荷 + `analysis.*` 参数 | ✅ 完成（含 `observed_subjects`、`hit`/`coverage` 候选、租约回收、`analysis.enabled` 回滚开关；待提交/部署） |
| **P2** | 数据地图：`describe_data` 增强 + `asset_map` + `coverage_report` + `observed_subjects` + `coverage` 候选 | ✅ 完成（`describe_data` 给出每来源量级 / 近 24h 增量 / 字段数 / 可聚合字段，并提示「查不到不等于没发生」；与时间边界共用**一次**聚合，不多打 ES） |
| **P3** | 只读 REST + 前端（归 workbuddy）+ 人工派工 + 覆盖率看板 | ⚠️ 后端全部完成（10 个只读/派工/参数端点 + 全部 `analysis.*` 参数（以 `GET /api/analysis/config` 的 `items` 为准））；**前端页面归 workbuddy**，接口与字段已写进 `docs/api/README.md` |
| **P4** | 学习闭环：`hit`/`structure` 候选调优、误抑制回弹、FP 衰减、`analysis_results` 驱动强度重排 | ✅ 完成（`analysis/feedback.py`：一次 GROUP BY 出系数表 + 120 秒缓存；五类线索全部套系数；**只衰减不否决**，区间 0.4~1.6；`true_positive` 自动撤销该对象身上的抑制并计数 `suppression_rebound`） |

**P1 与门铃必须同版本与智能体侧一起上线**（D5 一次切换）。

实际接入方式：`analysis.enabled` 打开时，检测器**不再把摘要投递给智能体**（`digest_q` 不再写入），
改为“入队 + 门铃”；关掉开关就回到旧的推送契约 —— 这是本次改动的**回滚开关**，
不需要回退代码。

---

## 十三、给智能体团队的契约要点（他们实现，我们不写插件代码）

1. 接收端点改为解析 **门铃对象**（不是摘要数组）；未配置/关闭时 NDR 不发；
2. 收到门铃 → `claim_tasks(limit=3)`（NDR 不限制额度，领多少由智能体决定）；
3. 每任务按 `hint` 自主规划；`describe_data` 校字段，再取数；
4. 必须 `complete_task` 或 `defer_task` 释放租约（900 秒不交回自动回收，`attempts` 累加）；
5. 误报判定时按第七节提交 `suppression`（含理由码 + 真取过的证据引用），否则会持续被派同一现象；
6. **低频自轮询兜底 15 分钟**（门铃可能因重启/网络丢）；
7. `verdict` 用第五节词表。

---

## 十四、假设与默认（已按需拍板，可界面调）

1. 6.1 与 7.3 的所有默认值按"先保守、再放开"给出，上线后按实测调；
2. `hit` 类强度不用 `rule_severity`（D2/D4 的直接推论）；
3. 任务级结论写 `analysis_results`；`record_conclusion`（事件级，界面已展示）保留，
   任务若关联到具体事件则**同时**回写一份，失败不影响任务完成；
4. 不新增容器：候选生成与门铃都在检测器 leader 循环内；
5. 数据地图读 PG/Redis 快照，不让智能体每次巡逻都全量扫 ES；
6. 时间一律 UTC 存储、北京时间展示（沿用既有全局约定）。
