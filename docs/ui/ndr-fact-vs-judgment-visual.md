# 事实层 / 判断层：NDR 视觉语义分层规范

> 作者：visual-auditor（只读审计，本文是唯一产出）
> 审计对象：`ndr/frontend`（Next.js + Tailwind）、`packages/ui`（token 与徽章原语）
> 依据：`docs/agent-contract.md`、`docs/ndr-analysis-mechanism.md`（D2 / D4 决策）、以及逐行读过的源码（见 §0）
> 一句话结论：**`sev-*` 这套色现在同时承载五种互不相同的意思，其中两种是"平台在下判断"。新架构里平台不下判断，所以必须把"判断"这件事从颜色里拆出来，改由「谁说的 + 什么形态」承载。**

**五个问题的落点**

| 问题 | 在哪一节 |
|---|---|
| ① 哪些颜色/徽章在断言判断 | §1（问题陈述，逐处带 `文件:行号`）+ §6（逐文件改造点） |
| ② 色阶够不够用、怎么分层 | §2（含新增 token 的确切取值与区分度理由） |
| ③ `inconclusive` 怎么画 | §3 |
| ④ 强度 `0~1` 的视觉编码 | §4 |
| ⑤ 字号/视觉重量要不要调 | §5 |

---

## 0. 依据（结论都是对着源码写的）

| 文件 | 读它是为了确认什么 |
|---|---|
| `ndr/frontend/app/globals.css:70-107` | `--sev-*` / `--src-*` 三件套的确切取值与色相分工 |
| `ndr/frontend/tailwind.config.ts:79-111` | token → 类名映射（`bg-sev-critical-bg` 等） |
| `packages/ui/src/components/ui/badge.tsx:18-59` | 9 个 variant 与 `severityVariant()` 的回落逻辑（未知值 → `info`） |
| `packages/ui/src/components/ui/stat.tsx:35-53` | `Stat` 的 `tone` 只能取 `sev-*`，`size="lg"` = 28px |
| `packages/ui/src/lib/format.ts:11-17,55-59` | `severityText()`：空值 → 「未定级」 |
| `ndr/frontend/lib/hits.ts:220-223,270-277` | `severityBadge()`：空值 → **「信息」**（与上一行不一致） |
| `ndr/frontend/lib/analysis.ts:124-130,157-161` | verdict / mode 的徽章映射（全部复用 `sev-*`） |
| `ndr/backend/app/detector/hits.py:284` | `HitEventItem.severity` ← `HitEvent.rule_severity` |
| `ndr/backend/app/detector/hits.py:511-512,572,609,643` | 同一个 `rule_severity` 的**三个产地**（规则自带 / 风险分换算 / 写死 `high`） |
| `ndr/backend/app/detector/history.py:47,50` | `d_digest_sev_*` 与 `by_rule` **同出一个 `mark_digest()`** |
| `ndr/backend/app/detector/runner.py:326-331` | `mark_digest()` 在 `analysis.enabled` 的 `continue` **之后** → 默认配置下永不执行 |
| `ndr/backend/app/analysis/params.py:31` | `analysis.enabled` 默认 `True` → 上面那条是默认路径，不是边缘分支 |
| `ndr/backend/app/analysis/candidates.py:328` | 「不读 `rule_severity` —— 严重度是 NDR 的判断，读它等于继续替智能体下结论」 |
| `ndr/frontend/components/{events,status,behavior,logs,traffic,assets,analysis,suppressions,mcp}-panel.tsx`、`rule-tree.tsx`、`config/rules/page.tsx`、`status-charts.ts`、`event-charts.ts` | 逐处枚举颜色用法 |

**与既有规范的关系（重要，避免实现方看到矛盾就停手）**

- 本文**取代** `docs/ui/events-center-visual-spec.md:65` 的两句约束：「颜色只用既有语义 token，本页不新增一个变量」「严重度 = `sev-*` 三件套」。该规范写在架构切换之前，前提已经不成立。
- `docs/ui/analysis-suppression-visual-spec.md:38` 的「数据是冷的，判断是热的」、`analysis-panel.tsx:1239` 的「红只留给卡住与超容量」**是本文的直接前身**，本文把它从两个新页面推广到全部存量页面。
- `analysis-suppression-visual-spec.md:48` 的「0 新增变量」只约束那两页，**依然有效**；本文新增的 3 个 token 不进入那两页。

---

## 1. 问题陈述：这套色在新架构下怎么误导人

### 1.1 落地页有一整组"恒为 0 / 恒为空"的图与数字，而且它们不会走空态

**先看代码。** `detector/runner.py:324-332`：

```python
if analysis_params.enabled():
    continue                    # ← 派工模式下摘要不投递，直接跳过
digest_q.push(json.dumps(digest, ensure_ascii=False))
stats["digest"] += 1
mark_digest(stats, digest)      # ← d_digest_sev_* 与 by_rule 的唯一写入点
```

`analysis.enabled` 的默认值是 **`True`**（`analysis/params.py:31`），所以默认部署下 `continue` 永远先命中，**`mark_digest()` 与 `stats["digest"] += 1` 一次都不会执行**。

#### 控制流边界（已核，这决定"命中线活不活"）

这是本轮唯一一处可能把结论整块翻盘的事实，逐行列号核过：

| 行 | 缩进 | 内容 | 层级 |
|---|---|---|---|
| `:223` | 4 | `while True:` | 主循环 |
| `:300` | 8 | `for digest in agg.pop_due():` | 主循环体内 |
| `:328` | 16 | `continue` | **`for digest` 体内** |
| `:332` | 12 | `mark_digest(stats, digest)` | `for digest` 体内 |
| `:333` | **8** | `# 采样窗口到期 → 每 IP 一条样本…`（注释行本身就是证据） | **缩进回到 8 = `for digest` 已结束** |
| `:335` | 8 | `for sample in sampler.pop_ready():` | **与 `for digest` 同级** |
| `:380` | 8 | `if time.time() - last_stats >= ...`（统计块） | **与 `for digest` 同级** |
| `:490` | 12 | `history_append(...)` | 统计块体内 |

结论：**统计块与 `history_append` 在 `for digest` 循环之外、`while` 循环之内**，`continue` 只跳过 `:329-332`（`push` / `digest += 1` / 一行注释 / `mark_digest`），**不会跳过采样**。因此：

- `d_hit` **是活的** —— 来源 `stats["hit"]`，增量在 `:988`（raw 扫描路径），与 digest 循环无关；`history_append` 每个统计区间照写一条 → 采样点非空；
- `d_digest`（`:330`）、`d_delivered`（`_flush` → `:777`）、`d_digest_sev_*`、`by_rule`（`:332`）**全死**。

所以「命中线可以留、其余全部撤」成立，**不需要连图一起撤**。反过来的风险要写死在注释里：**若将来有人把 `history_append` 挪进 `for digest` 循环，命中线会一起死** —— 届时整块图表都不成立。

于是这些数字/图在生产配置下没有任何数据：

| 界面位置 | 依赖字段 | 唯一写入点 | 默认配置下的表现 |
|---|---|---|---|
| `status-panel.tsx:368` KPI「24h 摘要」 | `d_digest` | `runner.py:330` | **恒为 0**（不是"没有摘要"，是这项已不存在） |
| `status-panel.tsx:441` 图「24h 命中与摘要趋势」的「摘要」线 | `d_digest` | 同上 | 一条贴着 0 的直线 |
| 同图「投递」线 | `d_delivered` | 只有 `digest_q` 投递成功才 +1 | 恒 0 |
| `status-panel.tsx:448` 图「24h 严重度分布」 | `d_digest_sev_*` | `history.py:47` ← `mark_digest()` | **饼图数据全 0，渲染成一张空白卡** |
| `status-panel.tsx:456` 图「规则 TOP 15」 | `by_rule` | `history.py:50` ← `mark_digest()` | **横条图全空，同样是一张空白卡** |
| `status-panel.tsx:529` KPI「待聚合队列」 | Redis `LLEN digest_queue` | 入队才增长 | 恒 0 |
| `status-panel.tsx:530-534` KPI「本分钟投递」+ `:252-257` 投递额度环 | Redis 投递计数 | 投递才增长 | 恒 0 / 恒 0% |
| `status-panel.tsx:568` 图「投递 / 重发计数」 | `AgentPushPayload`（`status-charts.ts:549-559`） | 推送成功/重试才增长 | 恒空 |
| `status-panel.tsx:567` 图「丢弃原因分布」 | `stats.dropped`（`status-charts.ts:522-548`） | 检测器丢弃计数 | **活**（别误删；只有其中「未投递（没配推送）」一档恒 0） |

**上表前 8 行是一族**（`d_digest` / `d_digest_sev_*` / `by_rule` / `digest` / `LLEN digest_queue` / 投递计数 / 推送计数）—— 它们不是"某张图没数据"，是同一条退役管道的全部出口。**最后一行故意留着**：它是活的，写在这里是为了防止实现方按"这一片都是死的"连带删掉。

**为什么这条属于"视觉语义"而不是"后端 bug"**：`analysis.enabled=true` 是 D5 的**有意设计**（推送通道整体退役，改门铃 + 领取）。问题在于界面**没有跟上**——它把这批"结构上不存在的指标"和活指标画成了完全一样的东西：一样的位置、一样的大小、一样的 `tabular-nums`、一样的空图。

运维看到 `0` 读作"今天没有发生"，看到空白卡读作"读取失败"或"系统还没跑起来"。**两种情况都不对，而界面没有任何线索让人分辨。** 这是最纯粹的事实层误标：`0` 与"不适用"是两件事。

更糟的是**空态不会触发**：`status-panel.tsx:451` 与 `:459` 的 `empty` 条件只判 `historyItems.length`（采样点数量），而采样点因为 `d_hit` 还在增长所以**非空**（上表已核：采样块在 `for digest` 之外照常写入）。结果是饼图拿到全 0 数据、ECharts 画出空白画布，`EmptyState` 永远不出现 —— 运维看到的是"白卡"，读成"读取失败"或"系统还没跑起来"。

顺带说清一件事：这张饼图的**字段选择**本身也是错的。即便把 `mark_digest()` 前移修好，它画的仍是 `rule_severity` 的直方图（`history.py:47`），而 D4 明令「不用 `rule_severity`」。

**因此处置不是"改标题"，是"撤图 + 回收版面"。** 给一个永远空的图换个中性名字，比保留原名更糟：读者会更难判断"是这个维度最近没数据"还是"这个统计已经停更" —— 而这两件事的下一步动作完全不同。**空图必须消失，位置回收给新架构真正会动的数字。**

回收给什么，边界在这里钉死（避免实现方和 `/analysis` 各画一版）：

| 允许出现在总览「线索与派工」块 | 形态 | 来源 |
|---|---|---|
| 待处理线索数 / 队列是否非空 | **一个** `Stat`（`md`，不上语义色；只有"队列为 0 但明明该有活"时才允许 `medium`） | `/api/analysis/stats` 的 `pending` / `by_state` |
| 门铃最近一次发送 + `undelivered` 计数 | 一行 12px 文字 + 数字；`undelivered` 必须带 `title="只表示这次没叫醒，队列数据仍完整可拉"` | 门铃计数（**前端取不到就不显示，不要用 0 冒充**） |
| 跳转 | 一个文字链「打开派工队列 →」 | `/analysis` |

**不在总览画**：容量压力条、六状态徽章组、预算环、任何分布图 —— 这些在 `/analysis` 里已经是主场，总览的职责只是"要不要现在去看"。**也不画任何趋势图**：`/api/analysis/stats` 只有当前快照、没有时间序列，画出来只能是假平线（见 B3）。未实现的东西**不出现在界面上**，不留占位、不写"即将上线"。


### 1.2 事件主表有一列叫「严重度」，而这一列的来源是**三种不同的东西**

`events-panel.tsx:166` 定义列 `{ key: "severity", label: "严重度", w-[5rem] }`，`:291` 用 `severityBadge(row.maxSeverity)` 渲染；聚合口径在 `lib/hits.ts:270-277`（`SEV_RANK`）与 `:372`（取 rank 最大）。

`HitEventItem.severity` 一律来自 `hit_events.rule_severity`（`hits.py:284`），但这一列在库里有**三个互不相同的产地**：

| `source_kind` | 产地 | `rule_severity` 怎么来的 |
|---|---|---|
| `feature_match` / `behavior_analysis`（规则命中） | 规则定义 | 规则自带的 `severity`，缺失时回落 `medium`（`hits.py:511-512`） |
| `baseline_deviation`（账号/会话画像） | 画像风险分 | `_severity_of_risk(risk)` 按 0.75 / 0.45 换算成 high/medium/low（`hits.py:572,609`） |
| `baseline_deviation`（数值 2σ 偏离） | **硬编码** | 写死 `"high"`（`hits.py:643`） |

也就是说，同一列里既有"规则出厂标签"，也有"NDR 自己按画像风险分现算的等级"，还有"写死的 high"。
把它叫「规则标注」会是**用一个新名字继续说谎**——比现在的「严重度」更难排查，因为名字看起来更精确了。

红色 `critical` 实心徽章（`badge.tsx:25`）贴在这一行的规则名旁边，于是颜色、位置、列名三重都在说"平台认为这台主机有严重威胁"。
抽屉里的 `events-panel.tsx:1035-1036`（「最高严重度：」）与 `:1128`（子列表每条）重复了同一个断言。

**这块不只是"展示层下判断"，它已经在影响计数与聚合。** `hits.ts:270-277` 的 `SEV_RANK` + `:372` 按字面量取最大 → `hits.py:643` 写死的 `"high"` 会让一条「数值 2σ 偏离」永久压过「画像 risk=0.5 → medium」，也压过真实的 `medium`/`low` 签名命中。同一份字面量还被用来算首屏 KPI「高危及以上」（`events-panel.tsx:602-607`，值来自 `hits_stats` 的服务端分组计数）—— **平台不仅在展示层写了威胁语义，还在聚合与计数里替运维下了判断。**

补一个必须写准的事实，避免把问题说大：**事件表没有"按级别排序"的控件**（`events-panel.tsx:133-137` 的 `SORTS` 只有 `recent` / `oldest` / `count`）。所以写死 `high` 的后果落在两处 —— ① 聚合行主徽章 `maxSeverity`（`hits.ts:372`，同一份值还喂抽屉摘要 `:1036` 与无障碍标签 `:905`）；② 首屏 KPI 的计数（服务端算，前端改不了）。**行顺序本身从没按级别排过**，说"列表顺序被污染"是错的。

**取值决策（P0 #2/#3 的依据）：不把基线偏离踢出主徽章，改为逐行标注产地。**

- **踢出去不成立**：一个只有 2σ 偏离的 IP 会在主徽章上显示成"什么都没有"，可它确实产生了一条命中事件。从"高估"变成"漏读"，同样是假。
- **可落地**：`aggregateByIp` 在 `:372` 那个比较里顺手记下"这个最大值是谁给的"（`maxSeveritySource`）和"该 IP 是否混有基线偏离"（`hasDerivedSeverity`），`RuleMarkBadge` 据此给**上标符号 + `title`**：签名不加符号、推算加 `~`、混合加 `*`。纯前端改动，不依赖 B2。
- **标记必须可见**：只靠 `title` 不算 —— `title` 是 hover-only，触屏和键盘都到不了，而对这部分用户来说"这个级别是谁说的"等于没标。所以 `~` / `*` 要进正文（8px 上标，不占列宽），`title` 只负责给完整解释，另配一行表脚图例。
- **硬约束**：**将来若给这张表加"按级别排序"，禁止只按 `maxSeverity` 排** —— 必须把 `derived` 排在同档签名之后，否则等于把写死的 `high` 直接变成第一屏顺序。


**修法必须同时做到四件事**：① 列名退到不撒谎的中性词（「级别」）；② **产地必须在页面上可见**（上标 `~` / `*`，不能只靠 `title` —— hover 对触屏和键盘等于不存在）；③ `title` 给完整解释；④ 这四处（列头 / 首屏 KPI / 抽屉标题 / 筛选下拉）**共用同一句**（`LEVEL_COLUMN_TITLE`，见 §6.1），防止说法各漂一版。这句是全篇最准确的表述，直接定稿：

> 「签名自带标注 / 基线偏离按统计强度折算；均非本次判定，也不参与派工优先级」

前端只能如实标注，不能替后端掩盖——`hits.py:609` 与 `:643` 把风险分换算成 `rule_severity`，本身违反 D2「NDR 只排客观强度，不写威胁语义」，属**后端整改项**（见 §8）。

### 1.3 首屏最高视觉重量给了这个徽章，而不是客观事实

`events-panel.tsx:602-607`：

```tsx
<Stat label="高危及以上" value={fmt(crit + high)} tone="high"
      hint={`严重 ${fmt(crit)} · 高危 ${fmt(high)}`} />
```

`Stat` 的 `size="lg"` 默认值是 28px（`stat.tsx:36,61`），`tone="high"` 把它染成 `text-sev-high-fg`。
同一屏里真正的客观事实——命中次数（`events-panel.tsx:292-293`，普通前景色数字）、事件数（`:294-295`，灰色）、最近时间（`:296-297`，灰色小字）——**没有任何视觉编码**；整张表唯一有颜色的列，就是「严重度」（`:290-291`）。

**视觉重量和"谁下判断"完全反了**：平台最重的那个数字是"规则标签的加权计数"；"发生了什么、发生了几次、什么时候开始的"则是全表最轻的字。

### 1.4 智能体结论与"命中事件的级别"同色同形，且大多数地方没有归属标记

`lib/analysis.ts:124-130`：

```ts
true_positive: "critical",   // 红实心
suspicious:    "medium",
benign:        "success",
false_positive:"secondary",
inconclusive:  "info",
```

同一种红实心，在 `/events` 里代表「这条命中事件的级别标签」（三种产地混在一起，见 1.2），在 `/analysis` 里代表「智能体判定这是攻击」。
两者外形、色号、字号完全一致，唯一区别是所在页。

更麻烦的是**归属**：`/analysis` 的结论表确实跟了「结论人」列（`analysis-panel.tsx:1044-1046`）、抽屉里 verdict 与 `claimed_by` 同行（`:1462-1466`）——这两处是对的；
但 `behavior-panel.tsx:1299-1301` 的处置记录把 `confirm`（确认攻击）画成 `outline`（**无色**）、把 `false_positive` 画成 `secondary`（灰底），`mcp-panel.tsx:772` 则直接打印英文原值 `c.severity` 并上严重度色。
**同一个"判定"，三处三套画法，其中两套还缺归属。**

### 1.5 两处把"量"画成了"危"

- `assets-panel.tsx:337`：暴露端口数 `>= 5` → `critical` 红徽章。端口多是**暴露面**，是判断的输入，不是判断本身。
- `assets-panel.tsx:808`：资产重要级别 `core`（核心）→ `critical` 红徽章。核心资产**恰恰最不该被读成"危险资产"**。

染红之后，它们与「确认攻击」共用同一个色号。而 `docs/agent-contract.md:106` 明确说 `asset_context` 是「**判严重度的唯一依据**」——判定依据被画成了判定结论，逻辑上是闭环错误。

---

## 2. 语义分层表

### 2.1 现状：一套 `sev-*` 承载五种语义

| # | 语义 | 谁产出的 | 现在的载体 | 出现位置 |
|---|---|---|---|---|
| A | **命中事件级别**（`rule_severity`：规则自带 / 画像风险分换算 / 写死 `high`，三源混合）+ 资产重要级别 | 规则定义、画像打分、台账 | `sev-*` 实心徽章 | events、status、assets、rules、logs |
| B | **客观强度**（`strength` 0~1、命中次数、规模） | 平台统计 | 裸数字（好）／`critical` 红徽章（坏） | analysis、assets |
| C | **智能体结论**（`verdict` 5 值、`confidence`） | 智能体 | `sev-*` 实心徽章 | analysis、behavior、mcp |
| D | **系统健康 / 流程态**（组件灯、已暂停、卡住、待派…） | 平台自身 | `sev-*` 圆点 / 徽章 | status、analysis、各配置页 |
| E | **后果 / 代价**（抑制 mode：完全抑制 = 事件消失） | 人工/智能体动作 | `critical` / `medium` 整带 | suppressions |

A、B 是**事实**，C 是**判断**，D 是**自身状态**，E 是**动作后果**。
其中只有 C 需要"重"；A 和 B 必须"轻"；D 和 E 保持现状即可（它们本来就不是关于流量的判断）。

### 2.2 分层表（实现方照这张表改）

| 层 | 语义 | 用途 | 载体与 token / 变体 | 是否新增 |
|---|---|---|---|---|
| **L1 事实·量** | 强度、计数、规模、暴露面、覆盖条数 | 让运维估"有多大" | 等宽数字 `tabular-nums text-foreground`；需要在列内比较时加 **石墨有序条** `bg-intensity-1/2/3` + 槽 `bg-chart-track` | **新增 `--intensity-1..3`（仅 3 个 token）**；槽复用 `--chart-track` |
| **L1 事实·量（热格）** | 时段分布这类"形状" | 看形态不看程度 | 保持 `behavior-panel.tsx:150-156` 的 `bg-primary/30…bg-primary` 五档 | 复用，不动 |
| **L2 事实·标注** | 命中事件的级别（三源混合，见 §1.2）、签名自带级别 | 说明"这条数据自带的等级是从哪来的" | **空心**徽章：`variant="outline"` + `border-sev-*-bd text-sev-*-fg bg-transparent`；列名只能用中性词「级别」；**产地必须双通道可见**——上标符号（`~` 折算 / `*` 混合 / 签名不加）+ `title` 全解 + 表脚一行图例 | 复用 `sev-*`，**禁止再用 `-bg`** |
| **L2 事实·属性** | 资产重要级别（core/high/normal/test）、来源三类 | 描述对象属性，不评价 | 资产级别：`variant="outline"` + `text-foreground`（`core` 加 `font-medium`）；来源三类：`src-*` 不动 | 复用，不新增 |
| **L3 判断** | `verdict` 5 值、`confidence`、`terminal_reason` | **只有智能体能下** | **实心**徽章 `sev-*`（`true_positive`/`suspicious`/`benign`）+ `secondary`（`false_positive`）+ **虚线空心**（`inconclusive`）；必须与「结论人」同现 | 复用 `sev-*`；`inconclusive` 用形态而非新色 |
| **L4 状态** | 组件健康、流程态（6 态）、容量超限、配置错误 | 平台自己的健康与流程 | 全部保持现状（见 §7） | 复用，不动 |
| **L5 后果** | 抑制 mode 两档、熔断、真阳推翻 | 说明"这个动作用掉了什么" | 整带底色 + 左侧 3px 竖条 + 图标 + 长文案，保持 `suppressions-panel.tsx:812-830` | 复用，不动 |

### 2.3 判定规则：**形态优先于色相**

L2 与 L3 都会用到 `sev-critical` 的红色（"签名自带标注" vs "智能体判定攻击"）。在不新增色相的前提下，用**三种可辨识的填充形态**把它们分开：

| 形态 | 含义 | 实现 | 一眼可辨的依据 |
|---|---|---|---|
| **实心**（底 + 字 + 边） | 有人下了判断 / 有事发生 | `border-sev-*-bd bg-sev-*-bg text-sev-*-fg` | 有底气块，在密集表格里最先跳出来 |
| **空心实线**（只有边 + 字） | 这是**资料**（签名自带标注、对象属性） | `border-sev-*-bd bg-transparent text-sev-*-fg` | 没有底气块 → 读作"附注"而不是"结论" |
| **空心虚线**（只有虚线边 + 字） | 这件事**还没结论** | `border border-dashed border-border bg-transparent text-muted-foreground` | 虚线 = 未完成（与 skeleton 同一套语言） |

配色上的铁律（写进 `lib/visual-semantics.ts` 的注释里）：

> **`-bg` 只属于"判断"与"状态"。凡是用 `-bg` 的地方，必须能回答"这是谁说的"。**
> 回答不出来（出厂定义、统计量、对象属性），一律只用 `-bd` + `-fg`。

### 2.4 新增 token：`--intensity-1..3`（石墨有序阶）

现有三套色都不能表达"量"：

- `sev-*` = 判断（用了就是在断言危险）；
- `brand-*`/`primary` = 可操作 / 选中 / 焦点 —— `globals.css:18-19` 明写「品牌蓝…绝不用来画数据或状态」；
- `chart-*` = **无序**分类色板（`chart-tokens.ts:13-16` 注释写的是「多系列 / 饼图」），不能表达大小关系。

而"量"恰恰是新架构里最核心的事实（`strength`、命中次数、规模）。所以新增一组**只表达量级**的有序阶。

**关键取向：不引入新色相，把既有的中性灰在明度轴上有序拉开。**

`globals.css` 的 `:root` 段（建议插在 `--src-*` 之后、`--chart-*` 之前）：

```css
  /* ---------- 量级阶（只表"多少"，不表好坏）----------
     2026-10 新增。新架构里 NDR 只排客观强度（D2），强度是 0~1 的显著性，不是严重度；
     于是"红色/橙色/金色"这套判断色不能用来画条，而品牌蓝按规矩不画数据、chart-* 又是无序分类板。
     这里是第四类：把既有的中性灰（与 --border 213°、--muted-foreground 213° 同一色相带）
     按明度拉开成 3 档。饱和压到 12~22%，因此永远不会被读成某一档严重度，只会被读成"量的多少"。
     只能出现在**条 / 格 / 刻度**里，永远不做徽章、不给文字上色。
     （明度步长：槽 --chart-track 88 → 68 → 50 → 30，ΔL = 20 / 18 / 20，
       4px 高的实心条上每一档都能分辨；数值本身仍在旁边，不依赖颜色传递精确量。） */
  --intensity-1: 213 16% 68%;
  --intensity-2: 213 14% 50%;
  --intensity-3: 213 20% 30%;
```

`.dark` 段：

```css
  --intensity-1: 216 14% 40%;
  --intensity-2: 214 13% 60%;
  --intensity-3: 212 12% 82%;
```

`tailwind.config.ts` 的 `colors`（接在 `sev` 之后）：

```ts
        /* 量级阶：只给条/格用，不接 Badge（见 docs/ui/ndr-fact-vs-judgment-visual.md §2.4） */
        intensity: {
          1: "hsl(var(--intensity-1))",
          2: "hsl(var(--intensity-2))",
          3: "hsl(var(--intensity-3))",
        },
```

**与现有 `sev-*` 的区分度理由（实现方需要的话照这段答复评审）**

| 维度 | `sev-info-fg` | `--intensity-2` | 区分依据 |
|---|---|---|---|
| 色相 | 214° | 213° | 同族（刻意如此——量级不该有独立色相） |
| 饱和度 | 15% | 14% | 几乎相同 |
| **明度** | 38% | 50% | 相差 12 个明度档 |
| **出现形态** | 徽章 / 文字 | **只做 4~6px 条** | 形态不同 → 不会被并排比较 |
| 语义方向 | 一档离散值 | 有序三档 | 若把 intensity 当色阶用，三档本身就能读出顺序 |

即：**它不需要"和 sev-* 区分开"，它需要的只是"不像任何一档严重度那样出现在文字上"。** 这条靠使用范围约束（只做条），不靠色相。

### 2.5 为什么 verdict **不**新增色相

做过一轮色相盘点，现有占用：

```
352° sev-critical   29° sev-high    45° sev-medium   227° sev-low
213° sev-info       154° sev-ok      253° src-feature 180° src-behavior
317° src-baseline   212° brand
```

10 个色相把 0°~360° 里"看起来不像报警也不像品牌"的空档占得差不多了，唯一还剩两段：

- **60°~130°（黄绿 / 黄）**：与 `sev-ok`（154°）在 12px 徽章上分不开，且黄绿在中文界面里天然读作"注意"；
- **270°~300°（紫）**：左边是 `src-feature` 253°，右边是 `src-baseline` 317°，夹在中间只能做到"看起来像这两者的亲戚"。

**再塞第 11 个色相，在 12px、白色底、5.5:1 对比度的约束下是不可辨识的。** 而 §1.4 的问题本质不是"色号不够"，是**归属不清**——所以解法是「形态 + 归属字段」，不是「第 11 个颜色」。

---

## 3. `verdict` 五值与 `inconclusive`

### 3.1 五值的视觉方案

| verdict | 中文（**改**） | 形态 | className | 理由 |
|---|---|---|---|---|
| `true_positive` | 确认攻击 | 实心红 | `border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg` | 唯一允许"最重"的判断 |
| `suspicious` | 可疑 | 实心琥珀 | `border-sev-medium-bd bg-sev-medium-bg text-sev-medium-fg` | 与"确认"拉开一档 |
| `benign` | 正常 | 实心绿 | `border-sev-ok-bd bg-sev-ok-bg text-sev-ok-fg` | 已查清且无问题 |
| `false_positive` | 误报 | 实心灰 | `variant="secondary"`（`border-transparent bg-secondary text-secondary-foreground`） | 已了结，不该抢注意力；灰底 =「关掉了」 |
| `inconclusive` | **未定论** | **空心虚线灰** | `border border-dashed border-border bg-transparent text-muted-foreground` | 见 3.2 |

文案改动：`lib/analysis.ts:120` 的 `inconclusive: "不确定"` → **`"未定论"`**。
理由：「不确定」在中文里偏"我没把握"，读起来像平台在犹豫；「未定论」明确是"分析做完了、但没有定论"，并且与 `terminal_reason` 配合能读出"为什么没定论"（`docs/ndr-analysis-mechanism.md:329-331` 明确说这是 `terminal_reason` 存在的唯一理由）。

### 3.2 `inconclusive` 为什么是"虚线空心"，不是灰、不是斜纹

三个候选都试过：

| 候选 | 判 | 理由 |
|---|---|---|
| 灰（= 现在的 `info`） | **否** | 与「已忽略 / 已过期 / 已撤销 / 未读到」同形。灰色在密集表格里等于"没有信息"，会被眼睛直接跳过——而"查了没定论"是**一条需要人接手的工作**，不能长得像空行 |
| 斜纹（`repeating-linear-gradient`） | **否** | 12px 徽章里 45° 斜纹会摩尔纹化，缩放/打印后糊成一片；且它强到会把整行的注意力吸干。**斜纹可以用，但只能用在结论卡片的底色上（`bg-[repeating-linear-gradient(...)]`），不能进徽章** |
| **空心 + 虚线边** | **是** | 虚线在 UI 语言里普遍表示"未完成/占位"（与 skeleton 同源），不需要新色相，暗色与打印都稳；且与 `outline`（实线空心）、`secondary`（实心灰）构成三态互不混淆 |

### 3.3 具体实现

```tsx
// lib/visual-semantics.ts
import { CircleDashed } from "lucide-react";

export const TERMINAL_LABEL: Record<string, string> = {
  concluded: "已查完",
  budget_exhausted: "预算耗尽",
  tool_error: "取数失败",
  timeout: "超时",
  aborted: "中止",
};

/** 未定论：虚线空心 + 空心圆点图标；terminal_reason 作为后缀，只有"没查完"那几种上琥珀色 */
export function InconclusiveBadge({ terminalReason }: { terminalReason?: string }) {
  const unfinished = terminalReason && terminalReason !== "concluded";
  return (
    <Badge variant="outline" className="border-dashed bg-transparent text-muted-foreground">
      <CircleDashed className="h-3 w-3 shrink-0" aria-hidden />
      未定论
      {terminalReason ? (
        <span className={cn("ml-0.5 text-[11px]", unfinished && "text-sev-medium-fg")}>
          · {TERMINAL_LABEL[terminalReason] ?? terminalReason}
        </span>
      ) : null}
    </Badge>
  );
}
```

三条配套规则：

1. **`terminal_reason` 在界面上必须出现**，否则 `inconclusive` 分不清「查了没证据」（`concluded`，线索质量差）和「根本没查完」（`budget_exhausted` / `tool_error` / `timeout` / `aborted`，是运维/预算问题）——这两种的处置动作相反。
2. **只有"没查完"那几种后缀上 `text-sev-medium-fg`**。因为"没查完"本身就是一个待办的操作问题；而 `concluded` 的"没定论"是分析结论，不该再上一层情绪色。
3. **`inconclusive` 永远不配 `bg-*`**。整行唯一的颜色就是那个琥珀后缀（如果有的话）。

### 3.4 同一语义，一处定义

现在 verdict 有三套画法（`lib/analysis.ts:124`、`behavior-panel.tsx:1299`、`mcp-panel.tsx:772`）。改造后统一收口到 `lib/visual-semantics.ts`：

```ts
export function VerdictBadge({ verdict, terminalReason }: { verdict: string; terminalReason?: string }) {
  if (verdict === "inconclusive") return <InconclusiveBadge terminalReason={terminalReason} />;
  return <Badge variant={VERDICT_VARIANT[verdict] ?? "outline"}>{verdictLabel(verdict)}</Badge>;
}
```

`behavior-panel.tsx:1299-1301` 的 `confirm` 必须走 `verdictVariant("true_positive")`（红实心），不是 `outline`——「确认」是这个列表里唯一有分量的判定。

---

## 4. 强度（`strength` 0~1）的视觉编码

### 4.1 现状

- `/analysis` 任务表：`analysis-panel.tsx:822` 列名「强度」宽 `w-16`，`:850` 渲染 `task.strength.toFixed(3)` —— **裸数字，无色**（这一点是对的）；
- 详情抽屉：`:1391` 「强度 0.723」同样裸数字；
- 事件页没有 `strength`，但**等价的"规模事实"里有一处被画成了严重度色阶**：`assets-panel.tsx:337`（暴露端口数 ≥5 → 红）。

也就是说：**没有把强度画成严重度色阶（好），但也没给它任何视觉锚点（不足），而隔壁的"量"却被染红了（坏）。**

### 4.2 取舍：要不要给条形？

结论：**宽表给"长度 + 三档深浅"，窄列只给数字 + 阈值旗标。**

| 形态 | 用在哪 | 编码 | 为什么 |
|---|---|---|---|
| **宽表** | `/analysis` 任务队列「强度」列（≥xl 视口） | 2 位小数数字 + 32px 宽 4px 高小条，条长连续 = 值本身，条色 = 三档 | 一列 50 行时，眼睛扫条长找"哪几条更强"比读 0.72/0.81 快一个数量级；条只有 4px 高，不构成噪声 |
| **窄列 / 卡片 / 抽屉头** | `<xl` 的折叠行、抽屉、日志式列表 | **只数字**，`≥0.8` 时数字后跟一个 4px 实心方块 `bg-intensity-3` | 40px 以下宽度里，条长与三档色都不可分辨，画了是纯噪声 |

**为什么"长度连续 + 颜色三档"要分开**：长度承载精确量级（可跨行比较），颜色只承载"落在哪一档"。三档不是平均切分，而是**按产品真实门槛切**：

```ts
// 0.8 = analysis.reserved_min_strength 默认值（保留名额只给 ≥0.8 的线索）
// 0.4 = rarity 分量的「14 天内见 ≥2 次」档（docs/ndr-analysis-mechanism.md §5.2）
const STRENGTH_TONE: Record<1 | 2 | 3, string> = {
  1: "bg-intensity-1",
  2: "bg-intensity-2",
  3: "bg-intensity-3",
};

export function strengthStep(s: number): 1 | 2 | 3 {
  if (s >= 0.8) return 3;
  if (s >= 0.4) return 2;
  return 1;
}
export function strengthTone(s: number): string {
  return STRENGTH_TONE[strengthStep(s)];
}
```

> 必须用**静态映射表**而不是 `` `bg-intensity-${n}` ``：Tailwind 的 JIT 只扫描源码里的完整类名字符串，拼出来的类名会被 purge 掉（这条同样适用于 §6.1 的 `SEV_HOLLOW`——它本来就是静态表，是对的）。

这样"第三档"在语义上就是"够进保留名额的强度"，而不是随便画的阈值。

### 4.3 具体代码

宽表（替换 `analysis-panel.tsx:850`）：

```tsx
<TableCell className="tabular-nums">
  <span className="flex items-center gap-1.5">
    <span className="w-8 shrink-0 text-13 text-foreground">{task.strength.toFixed(2)}</span>
    <span className="h-1 w-8 shrink-0 overflow-hidden rounded-full bg-chart-track" aria-hidden>
      <span
        className={cn("block h-full rounded-full", strengthTone(task.strength))}
        style={{ width: `${Math.max(2, task.strength * 100)}%` }}
      />
    </span>
  </span>
</TableCell>
```

**不在条上画 0.8 刻度**：4px 高的条里，1px 刻度线无论用亮色还是暗色，都会有一半长度落在同色像素上而消失；而"第三档颜色本身就是 0.8 门槛"（`strengthStep` 只在 `≥0.8` 时返回 3）——门槛已经由颜色表达了，再画一条线是重复编码。列头 tooltip 里说明门槛即可：

```tsx
<TableHead className="w-[5.5rem]" title="客观强度 0~1（显著性/规模，不是严重度）；最深一档 = ≥0.8，够进保留名额">强度</TableHead>
```

窄列（替换 `analysis-panel.tsx:1391`）：

```tsx
<span className="inline-flex items-center gap-1 tabular-nums">
  强度 {detail.strength.toFixed(2)}
  {detail.strength >= 0.8 ? (
    <span className="h-1.5 w-1.5 rounded-[1px] bg-intensity-3" aria-hidden title="≥0.8：够进保留名额" />
  ) : null}
</span>
```

### 4.4 三条不做

1. **不给强度上 `sev-*`**。一旦上色，0.92 就会被读成"严重"——这正是这次要拆掉的东西。
2. **不给数字本身变色**（`text-sev-*`）。数字变色会让整列变成调色板，且与"判定"抢色。
3. **不做五档 / 渐变条**。5 档在 4px 高度里分不开；渐变在中文界面里是最难读的一种"伪精度"。

### 4.5 顺带的精度问题

`toFixed(3)` 是**视觉上的假精确**：`strength = max(5 个 clamp 过的分量)`（`docs/ndr-analysis-mechanism.md:128-143`），它不是一次测量，而是取最大值。三位小数暗示"算得很准"。
建议统一 `toFixed(2)`（`:850` 与 `:1391` 两处，人工派工对话框 `:1552` 的 `step` 也建议从 `0.05` 保持不变即可）。

---

## 5. 字号与视觉重量：首屏该给谁

### 5.1 对比：两页的分配方式完全相反

| | `/analysis`（新口径，**对**） | `/events`（旧口径，**错**） |
|---|---|---|
| 首屏 KPI | 6 格，全部 `size="md"`（20px）、`tone="default"`，只有覆盖率 <0.2 时用 `medium`（`analysis-panel.tsx:663-703`） | 3 格，`size="lg"`（28px），中间那格 `tone="high"` 且值是「高危及以上」（`events-panel.tsx:596-613`） |
| 首屏第二个元素 | 容量压力条（`PressureBar`，唯一自绘图元） | 来源 chips（中性，对） |
| 首屏主图 | 无 / 表格 | 「近 24 小时命中」趋势（`chart-1`，对）+ 「事件归类 TOP 10」（中性，对） |

`/analysis` 的写法证明：**事实优先不需要靠缩小字号来委屈信息**——6 格 md 一排，读起来比 3 格 28px 更"有事可做"。

### 5.2 改法（不重排布局，只改重量与语义）

| 位置 | 现在 | 改成 |
|---|---|---|
| `events-panel.tsx:596-613` 三格 | 全 `lg`(28px)；第 2 格 `tone="high"`、label「高危及以上」 | 第 1 格「命中总数」保留 `text-28`（唯一英雄数字）；第 2、3 格降 `size="md"`；第 2 格 `tone="default"`，label 改「**级别：高危以上**」（**不叫「规则标注」**，那一格混了三种产地，见 §1.2），hint 改「来源三种，见列头说明」 |
| 全站事实数字字重 | `font-medium`(500) 已经是主流 | 保持 500；**不要**为强调改成 600/700（中文在 13px 下会发糊，`tailwind.config.ts:165` 的注释已记录这条） |
| 判定徽章字重 | `text-xs font-medium`（`badge.tsx:19`） | 不动。判定靠"实心 + 归属"胜出，不靠加粗 |

**为什么第 1 格可以留 28px**：`命中总数` 是纯事实（多少条），且它是这一屏唯一的"总账"。**唯一允许 28px 的必须是事实，不能是判断** —— 这条可以直接当作验收口径。

### 5.3 一个"想做但本任务不做"的备注

理想的首屏第 2 格应该是「涉及主机 N」（规模事实），但 `HitEventStats`（`lib/api.ts:784-795`）没有 distinct host 字段。**这里不提出后端改动**，只把「高危及以上」降级 + 改名；将来后端补 `distinct_hosts` 时，第 2 格换过去即可，不需要再动视觉方案。

---

## 6. 逐文件改造点（按"会不会误导判断"排序）

三层共 **26 条**（P0 11 / P1 9 / P2 6）。编号不按文件顺序，按"误导程度"；同一编号内的多条改动可以一次提交。

> 修订轨迹（三版都在本表内就地改，不另立补遗）：v1 的 P0 是 12 条 → v2 把「区块更名 / 撤饼图 / 改饼图配色」三条并成一条、新增「恒 0 一族」，变 11 条 → **v3 把 #7 从"改标题"升级为"撤 5 个图元 + 回收版面"、把 #7/#8 的边界按图元重新切分，条数不变仍是 11**。列名口径同步收回：**不叫「规则标注」，叫「级别」**（理由见 §1.2）。

### P0 —— 正在替运维下判断 / 正在给出假数据，必须改

| # | 位置 | 现在 | 改成 |
|---|---|---|---|
| 1 | `events-panel.tsx:166` | 列名「严重度」，`w-[5rem]` | 列名**「级别」**（中性词，不宣称产地），`w-[4.5rem]`（空心徽章没有底气块，视觉重量小一档；该列无排序控件，不必给排序图标留位）；`title={LEVEL_COLUMN_TITLE}` = **「签名自带标注 / 基线偏离按统计强度折算；均非本次判定，也不参与派工优先级」**；表格脚注加一行 `LEVEL_LEGEND`（`~ 按统计强度折算 · * 含推算来源 · 均非本次判定`）——**图例必须在页面上，不能只在 `title` 里** |
| 2 | `events-panel.tsx:291` | `severityBadge(row.maxSeverity)` 实心红 | `<RuleMarkBadge severity={row.maxSeverity} provenance={aggregateProvenance(row)} />`（空心，见 §6.1）。**不把 `baseline_deviation` 踢出主徽章**，理由见 §1.2「取值决策」：踢出去会让只有 2σ 偏离的 IP 显示成"什么都没发生"。产地靠**上标符号**显形（`高~` / `高*`），**不许只靠 `title`** |
| 3 | `lib/hits.ts:220-223` + `:372` | `(sev \|\| "info")`：**空值渲染成「信息」**；函数只收一个参数；`aggregateByIp` 只记 `maxSeverity` 不记产地 | ① `severityBadge` 删除，统一走 `RuleMarkBadge`；② `aggregateByIp` 在 `:372` 的比较里补记 `maxSeveritySource: "signature" \| "derived"` 与 `hasDerivedSeverity: boolean`（`IpAggRow` 同步加两个字段）；③ 空值兜底用 `severityText()`（`format.ts:57` →「未定级」），修掉与现有「信息」的口径不一致 |
| 4 | `events-panel.tsx:602-607` | `label="高危及以上"` `tone="high"` `size="lg"` | `label="级别：高危以上"`、`tone="default"`、`size="md"`、`hint="含推算来源 · 严重 X · 高危 Y"`。**这一格的计数仍受 `hits.py:643` 写死 `high` 影响，前端只能降权 + 在文案里标明"含推算"，改不了数**（B2） |
| 5 | `events-panel.tsx:1035-1036` | 抽屉摘要「最高严重度：」+ 实心红 | 「最高级别（来源混合）：」+ `<RuleMarkBadge severity={ipSummary.maxSeverity} provenance={aggregateProvenance(ipSummary)} />`。**同一句 `LEVEL_COLUMN_TITLE` 挂在冒号后面做 `title`**，不要另写一版文案 |
| 6 | `events-panel.tsx:1128` | 子列表每条实心红 | 同 #2，但这里**必须传 `provenance={labelProvenance(ev.source_kind)}`**（单条数据产地明确，不能笼统写"混合"）；`source_kind` 由 `api.ts:708` 直出，无需后端改动 |
| 7 | `status-panel.tsx:421-462` 整个「威胁事件」区块 | 标题「威胁事件」；三个图元里两个恒空（`:448` 严重度分布、`:456` 规则 TOP 15），趋势图（`:441`）四条线里两条恒 0；`empty` 判 `historyItems.length` 所以**不走空态**，渲染成空白卡 | 按 **§6.0** 逐图元处置：区块改名「**规则命中**」，趋势图删掉摘要/投递两条线；饼图与规则 TOP 15 连 `severityOption` / `ruleTopOption` 一起删。回收的版面新增「线索与派工」块（只 `Stat` + 门铃一行 + 跳转，**不画图**）。**不要用"改标题"代替撤图**，理由见 §6.0 末段 |
| 8 | `status-panel.tsx:368`「24h 摘要」KPI、`:252-259` 投递额度环、`:529` 待聚合队列、`:531` 本分钟投递、`:568` 投递·重发计数 | 在 `analysis.enabled=true` 下**结构上恒为 0 / 恒空**（§1.1 表），却和活指标长得一模一样 | 分三种处理：**① 有活数可换**（「24h 摘要」→ `/api/analysis/stats` 的待处理线索数）；**② 该删的删**（待聚合队列 / 本分钟投递 / 投递额度环 —— 这三个概念在派工模式下不存在，写 `—` 也是噪音）；**③ 删不掉又恒 0 的**（投递·重发计数）→ 数字显示 `—` + 容器挂 `<Badge variant="outline">派工模式不产生</Badge>` + `title="analysis.enabled=true 时摘要不再投递（D5），这些计数不会增长"`。**`—` 与 `0` 必须分开**（`lib/analysis.ts:443` `numText()` 的既有口径） |
| 9 | `assets-panel.tsx:337` | `row.exposure >= 5 ? "critical" : "secondary"` 红徽章 | 改为纯事实：`<span className="tabular-nums text-foreground">{row.exposure}</span>`，`≥5` 时数字后加 `bg-intensity-3` 小方块（与 §4.3 窄列同款） |
| 10 | `assets-panel.tsx:808-810` | `criticality === "core" ? "critical" : "secondary"` | `variant="outline"`；`core` 追加 `className="border-border text-foreground font-medium"`，其余 `text-muted-foreground` |
| 11 | `mcp-panel.tsx:772` | 打印英文原值 `c.severity` 并上严重度色 | 用 `<VerdictBadge verdict={c.status} />`（`status` 才是判定）+ 一行 `text-xs text-muted-foreground` 显示 `severityText(c.severity)`（若后端确实写了级别）。**英文原值一律不出现**（`lib/analysis.ts:143` 已有这条铁律）。⚠️ `record_conclusion` 的 `status` 还接受 `pending` / `done` 两个**流程态**（`mcp/server.py:325-326`），它们不是 verdict：`pending` → 「待分析」`outline`、`done` → 「已分析（未给结论）」`outline`，需要 `VerdictBadge` 内先分流，否则会掉进 `verdictLabel()` 的英文兜底（`lib/analysis.ts:133` 的 `?? verdict`） |

#### 6.0 落地页图元处置（P0 #7 / #8 的实现依据）

派工模式下，「威胁事件」区块的三个图元里，两个维度已停更（原因见 §1.1 的控制流表）。**处置只有四种：留（改名删线）、删、换源、标不适用**。不允许的做法是"留一张空图 + 换个中性标题"。

| 图元 | 位置 | 数据源 | `analysis.enabled=true` 下的实际状态 | 处置 |
|---|---|---|---|---|
| 24h 命中与摘要趋势 | `:441`（`rateTrendOption`，`status-charts.ts:280-308`） | **四条** series：扫描 `d_scanned` / 命中 `d_hit` / 摘要 `d_digest` / 投递 `d_delivered`（`:282-290`） | 扫描**活**、命中**活**、摘要**死**、投递**死** | **删掉「摘要」「投递」两条 series 与 legend 项**；保留扫描 + 命中。标题改「**24h 扫描与命中**」 |
| 24h 严重度分布 | `:448`（`severityOption`，`:311-345`） | `d_digest_sev_*` | **空**（`filter(v > 0)` 得空数组） | **删**，连 `severityOption` 一起删（死代码） |
| 规则 TOP 15 | `:456`（`ruleTopOption`，`:348-366`） | `by_rule` | **空**（`{}`） | **删**，连 `ruleTopOption` 一起删 |
| 待聚合队列 | `:529` | `LLEN digest_queue` | **恒 0**（队列从不入队） | **删**（不是改 `—`：这一项在派工模式下根本不存在，占一格就是噪音） |
| 本分钟投递 | `:531` | `delivered_this_minute` | **恒 0** | **删** |

关于第一行的一个订正：口径原是"只留命中一条线"，但核代码后发现**「扫描」这条也活着**（`d_scanned`），而它是命中线的分母 —— 10 条命中发生在 100 万次扫描里，和发生在 100 次里完全是两回事。所以保留两条、标题用「24h 扫描与命中」。**这张图上只允许存在这两条 series。**

删掉的两条要在注释里写明**删的理由是"没有数据源"，不是"这两条线不重要"**：

```ts
// 删除原因：数据源已断（派工模式下 `continue` 跳过了 producer），不是"这维度没意义"。
//  - 「摘要」：`stats["digest"] += 1` 在 runner.py:330，`continue`（:328）之后 → 恒 0
//  - 「投递」：`stats["delivered"]` 只在 `_flush`（runner.py:777）里增长，而 `digest_q` 不再有内容
// 后果：恢复推送模式（analysis.enabled=false）后，这两条**应当原样加回来**（含 legend 项）。
// 但在派工模式下不要用 0 值占位 —— 贴 0 的线会被读成"归零了"，比没有线更误导。
```

区块结构随之变成两块（不是一个块塞两件事）：

1. **「规则命中」**（原「威胁事件」区块 `:421-462` 改名）：只剩那张双线趋势图 + **保留** description 里那个「完整列表与处置 → 事件中心」链接（值班从图上看到异常后的下一步动作，删了会让人以为事件没了）。
2. **「线索与派工」**（新增，用回收出来的版面）：**只有三类内容** —— 一个 `Stat`（待处理线索数）+ 一行门铃文字 + 一个跳转链接。允许/禁止清单见 §1.1 的表，**这一块不放任何图**。

顺序：`规则命中` 在前（回答"最近有没有事"），`线索与派工` 在后（回答"要不要现在去看"）。

**为什么不能"改个中性标题就留着"**：① 三个图元里有两个的数据源是同一个 `mark_digest()`，改名不会让计数器动一格；② 读者面对一张空图 + 中性标题，会判断成"这个维度最近没数据"，而事实是"这个统计已停更"——两种情况该做的事完全不同；③ 派工模式下「摘要」这个概念本身不存在，任何以它为主的图都是在给一个已退役的管道立碑。

### P1 —— 语义撞色 / 同一语义多套画法

| # | 位置 | 现在 | 改成 |
|---|---|---|---|
| 12 | `lib/analysis.ts:124-130` | `inconclusive: "info"` | 移除该键，`inconclusive` 统一走 `InconclusiveBadge`（§3.3）；`:120` 文案改「未定论」 |
| 13 | `analysis-panel.tsx:1024,1462` | `verdictVariant()` 直接渲染 | 换 `<VerdictBadge verdict={row.verdict} terminalReason={row.terminal_reason} />`；`:1462` 处已有 `claimed_by`（`:1466`），保持同现 |
| 14 | `behavior-panel.tsx:1299-1301` | `confirm → outline`（无色）、`false_positive → secondary` | 走 `VerdictBadge`：`confirm` → `true_positive` 红实心，`false_positive` → 灰实心 |
| 15 | `behavior-panel.tsx:643` | `<Badge variant="critical">风险 {x}</Badge>` —— **所有风险值一视同仁全红** | 风险分是**平台自己的打分**（不是智能体结论），按 §2.2 属 L1：`<span className="tabular-nums text-foreground">{risk.toFixed(2)}</span>` + 过阈值时加 `bg-intensity-3` 小方块；`title` 说明"平台画像打分，不是结论" |
| 16 | `behavior-panel.tsx:902-912` | 风险列 `>= threshold → critical` 红徽章 | 同 #15：数字 + 阈值小方块，不上红 |
| 17 | `behavior-panel.tsx:137-142` + `:682-683,791-793,981-982` | `StateBadge` 用 `success`/`medium`（绿/琥珀），三处 legend 用 `text-sev-ok-fg`/`text-sev-medium-fg` | **`观测中` 从 `medium` 改 `outline` + `text-muted-foreground`**。理由：「还在学习」不是警告，琥珀会让人以为基线有问题；`生效中` 的绿保留（它确实是"可以判定了"的正向状态）。三处 legend 同步改 `text-muted-foreground` |
| 18 | `behavior-panel.tsx:934-937` | `error_count > 0 → text-sev-medium-fg` | 改 `text-foreground`（有错误响应是事实，阈值判断不该由颜色代劳）；如要保留提示，用 `title` 说明"404 风暴这类探测痕迹" |
| 19 | `logs-panel.tsx:581` | `["严重度", cellText(detail.doc.severity)]` —— 英文原值 + 叫"严重度" | `["签名自带级别", severityText(String(detail.doc.severity))]`；这是**签名文件**里的级别，不是 NDR 判断 |
| 20 | `config/rules/page.tsx:132-134,647,659,715` | `severityBadge()` 实心 + 列名「级别」 | 规则管理页的 `RuleItem.severity` **就是规则定义自己写的**（`api.ts:283-284`，来源 `builtin`/`custom`），没有混合 —— 所以这一页**有权**如实叫它「规则自带级别」。只改文案：列名「级别」→「**规则自带级别**」，`:1155` 的 `Field label="级别"` 同步；徽章保持**实心**：换 `<RuleMarkBadge severity={r.severity} provenance="signature" surface="solid" />`（此处产地唯一，且是"资料的主场"，实心不误导）。⚠️ 与事件页的「级别」**故意不同名**：那一列混合了三种产地（§1.2），不能沿用这个名字 |

### P2 —— 配色借用 / 精度 / 一致性精修

| # | 位置 | 现在 | 改成 |
|---|---|---|---|
| 21 | `analysis-panel.tsx:850` | `task.strength.toFixed(3)` | §4.3 宽表形态，`toFixed(2)` |
| 22 | `analysis-panel.tsx:1391` | `强度 {detail.strength.toFixed(3)}` | §4.3 窄列形态，`toFixed(2)` |
| 23 | `analysis-panel.tsx:822` | 列名「强度」`w-16` | 列名不变（已正确），宽度提到 `w-[5.5rem]` 容纳"数字 + 条" |
| 24 | `traffic-panel.tsx:117` | 下行流量用 `bg-sev-ok-fg`（绿） | 换 `bg-chart-2`。上下行是**中性对比**，"下行"不等于"健康"，占用 `sev-ok` 会污染"ok"的唯一含义 |
| 25 | `behavior-panel.tsx:150-156` | `bg-primary/30…bg-primary` 五档热格 | **不动**。这是全站最正确的量级编码，本次新增的 `--intensity-*` 与它同一思路；只需在注释里补一句"与 `--intensity-*` 同族，若将来要统一再迁" |
| 26 | `hits.ts:220` / `rules/page.tsx:132` | 两个同名的 `severityBadge` 行为不一致 | 合并为 `visual-semantics.ts` 里的 `RuleMarkBadge`，两处 import（顺带修 #3） |

### 6.1 需要新建的 helper（`ndr/frontend/lib/visual-semantics.ts`）

```ts
/**
 * 事实层 / 判断层的唯一映射点。
 * 铁律：-bg（底气块）只属于"判断"与"状态"；资料只用 -bd + -fg。
 * 见 docs/ui/ndr-fact-vs-judgment-visual.md
 */

/** 列头 / 首屏 KPI / 抽屉标题 / 筛选下拉 共用这一句（改口径只改这里，防四处漂移） */
export const LEVEL_COLUMN_TITLE =
  "签名自带标注 / 基线偏离按统计强度折算；均非本次判定，也不参与派工优先级";

/** 表格脚注：跟随列头出现在**页面上**，不能只放 `title`（hover-only 对触屏/键盘等于不存在） */
export const LEVEL_LEGEND = "~ 按统计强度折算 · * 含推算来源 · 均非本次判定";

const SEV_HOLLOW: Record<string, string> = {
  critical: "border-sev-critical-bd bg-transparent text-sev-critical-fg",
  high: "border-sev-high-bd bg-transparent text-sev-high-fg",
  medium: "border-sev-medium-bd bg-transparent text-sev-medium-fg",
  low: "border-sev-low-bd bg-transparent text-sev-low-fg",
  info: "border-sev-info-bd bg-transparent text-sev-info-fg",
};

/**
 * 唯一允许实心的例外：规则管理页（`config/rules`）。
 * 那一页的 `severity` 就是规则定义自己写的（`api.ts:283-284`），没有混合产地，
 * 且那是"资料的主场"——实心不误导。事件页**永远**走 hollow。
 */
const SEV_SOLID: Record<string, string> = {
  critical: "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg",
  high: "border-sev-high-bd bg-sev-high-bg text-sev-high-fg",
  medium: "border-sev-medium-bd bg-sev-medium-bg text-sev-medium-fg",
  low: "border-sev-low-bd bg-sev-low-bg text-sev-low-fg",
  info: "border-sev-info-bd bg-sev-info-bg text-sev-info-fg",
};

export function ruleMarkClass(sev: string, surface: "hollow" | "solid" = "hollow"): string {
  const table = surface === "solid" ? SEV_SOLID : SEV_HOLLOW;
  return table[sev] ?? "border-border-subtle bg-transparent text-muted-foreground";
}

/**
 * 「级别」的**产地**（不是级别本身）。四种值，对应四句 title。
 *
 * 为什么必须是四种而不是"规则 / 非规则"两种：`hit_events.rule_severity` 有三个产地
 * （规则自带 / 画像风险分折算 / 数值 2σ 写死 high，见 §1.2）；前端只有 `source_kind`
 * 能分辨前两种，第三种与第二种同为 `baseline_deviation`，只能靠「数值 2σ 固定为高」
 * 这句把两种都覆盖。聚合行还要再分"最高值是谁给的"与"是否混有折算值"。
 *
 * **到此为止，再细就分不出来了**：前端无法知道这一格是 0.83 还是 0.9 折算来的，
 * 也无法知道是画像还是 2σ 数值偏离。要更细只能等 B2（后端补 `label_level` / 细分
 * `source_kind`）。**不要试图在前端按 `rule_severity` 的档位反推来源**。
 */
export type LabelProvenance = "signature" | "derived" | "mixed" | "unknown";

/** 单条事件：`source_kind` → 产地（`api.ts:708` 直出，不需要后端改） */
export function labelProvenance(sourceKind?: string | null): LabelProvenance {
  switch (sourceKind) {
    case "feature_match":
    case "behavior_analysis":
      return "signature";
    case "baseline_deviation":
      return "derived";
    default:
      return "unknown";
  }
}

/** 聚合行：一格里的值是 max(rule_severity)，所以要靠 #3 记的两个字段还原产地 */
export function aggregateProvenance(row: {
  maxSeveritySource?: "signature" | "derived" | "";
  hasDerivedSeverity?: boolean;
}): LabelProvenance {
  if (row.maxSeveritySource === "derived") return "derived";
  if (row.maxSeveritySource === "signature") {
    return row.hasDerivedSeverity ? "mixed" : "signature";
  }
  return "unknown";
}

const PROVENANCE_TITLE: Record<LabelProvenance, string> = {
  signature: "签名自带标注（规则定义里写的）。NDR 不据此排优先级",
  derived:
    "基线偏离级别：画像按风险分折算（≥0.75 高 / ≥0.45 中），数值 2σ 偏离固定为高。不是签名标注",
  mixed: "该对象最高级别来自签名自带标注；同一对象下另有基线偏离，其级别按统计强度折算",
  unknown: "级别来源未知（数据异常，正常库里不该出现）",
};

/**
 * 产地**必须可见**，不能只靠 `title` —— `title` 是 hover-only，触屏与键盘都到不了，
 * 等于对一部分用户不存在。而这次要修的恰恰是"用户不知道这个级别是谁说的"。
 */
const PROVENANCE_MARK: Record<LabelProvenance, string> = {
  signature: "", // 默认态不加符号
  derived: "~", // 按统计强度折算
  mixed: "*", // 同一条聚合里混有推算来源
  unknown: "", // 不加符号，但属数据异常态：验收要求为 0（§6.3）
};

export function RuleMarkBadge({
  severity,
  provenance = "unknown",
  surface = "hollow",
}: {
  severity?: string | null;
  provenance?: LabelProvenance;
  /** 只有规则管理页传 "solid"；事件页不要传（默认 hollow） */
  surface?: "hollow" | "solid";
}) {
  const key = String(severity || "").toLowerCase();
  const mark = PROVENANCE_MARK[provenance];
  return (
    <Badge variant="outline" className={ruleMarkClass(key, surface)} title={PROVENANCE_TITLE[provenance]}>
      {severityText(key)}   {/* 空值 → 「未定级」，与 format.ts:57 同源 */}
      {mark ? (
        <sup className="ml-px align-super text-[8px] leading-none opacity-80">{mark}</sup>
      ) : null}
    </Badge>
  );
}
```

`cn` 用的是 `twMerge`（`packages/ui/src/lib/utils.ts:6`），所以 `variant="outline"` 的 `border-border / text-foreground` 会被 `className` 里的 `border-sev-* / text-sev-*` 正确覆盖，**不需要给 `Badge` 新增 variant**。

配套的聚合改动（`lib/hits.ts:291-306` 的 `IpAggRow` / `:308-322` 的 `IpAggBuilder`）：

```ts
// 两个 interface 各加两个字段（IpAggRow :291-306 / IpAggBuilder :308-322）
maxSeveritySource: "signature" | "derived" | "";
hasDerivedSeverity: boolean;

// aggregateByIp（:341 起）：:355 初始化 与 :372 比较 两处都要改
const derived = it.source_kind === "baseline_deviation";
if (derived) b.hasDerivedSeverity = true;
if (SEV_RANK[it.severity || ""] > SEV_RANK[b.maxSeverity]) {
  b.maxSeverity = it.severity;
  b.maxSeveritySource = derived ? "derived" : "signature";
}
```

注意两处易错：① 初始化（`:355`）也要给 `maxSeveritySource` 赋初值，否则"第一条就是最大值"的行会落到 `unknown`；② `hasDerivedSeverity` 必须**无条件**累加（不受"是否刷新最大值"影响），否则 `mixed` 永远出不来。


### 6.2 落地顺序

1. 先落 §2.4 的 3 个 token + §6.1 的 helper（无行为变化，tsc 必过）；
2. 然后按 P0 单条替换（每条都是独立、可单独验证的 diff）；
3. P1 里 #12-#14 必须一起改（`VerdictBadge` 引入后旧调用点会类型报错，正好当检查清单）；
4. 收尾用一条 grep 自检——**改完后 `grep -rn "severityBadge\|severityVariant(" ndr/frontend` 应为空**（两处 `severityBadge` 都已合并进 `RuleMarkBadge`；`severityVariant()` 只保留给 `verdict` 以外的流程态，若仍有调用需逐条确认它不是在画"级别"）：

```bash
grep -rn "severityBadge(\|severityVariant(\|verdictVariant(" ndr/frontend --include=*.tsx
```

### 6.3 验收口径（可量）

- 事件中心主表**不再存在**任何 `bg-sev-*-bg` 的徽章（全部空心），且每条的空心徽章 `title` 里能读到**产地**（`signature` / `derived` / `mixed` / `unknown` 四种之一，不是笼统一句"来源可能混合"）；
- 产地**在页面上可见**，不只靠 `title`：推算来源的徽章带 `~` 上标、混合来源带 `*`，表格脚注有一行 `LEVEL_LEGEND`；`unknown`（无上标且 title 说"来源未知"）在真实数据里计数应为 **0**，出现即按 B2 的数据问题追；
- 全站**不存在**「规则标注」这个词（该说法已收回）：事件页叫「级别」、规则管理页叫「规则自带级别」，`grep -rn "规则标注" ndr/frontend` 为空；
- 落地页「规则命中」区块**只有一张图、且 `rateTrendOption` 只输出两条 series**（扫描 + 命中）；`severityOption` / `ruleTopOption` 在仓库中不存在（`grep -rn "severityOption\|ruleTopOption" ndr/frontend` 为空）；不存在任何贴 0 的 series；
- 落地页**不存在**用 `0` 表示"结构上不产生"的指标：「待聚合队列」「本分钟投递」「投递额度」三处已删除（不是改 `—`），「投递·重发计数」显示 `—` 并挂「派工模式不产生」；`grep -rn "queue_digest\|delivered_this_minute" ndr/frontend/components` 为空；
- 新增的「线索与派工」块**没有 canvas**：该 `Section` 内 `ChartCard` 出现 0 次，只有 `Stat` + 一行文字 + 一个 `<Link href="/analysis">`；
- 全站只剩 4 处 `bg-sev-critical-bg` 的**文字徽章**——`/analysis` 结论表（`:1024`）、`/analysis` 抽屉（`:1462`）、`/behavior` 处置记录（`:1299`）、`/config/mcp` 写回结论（`:772`）——且每一处都能在**同一视线内**读到归属：前两处有「结论人」列/字段（`analysis-panel.tsx:1044`、`:1466`），第四处有区块说明「智能体写回的结论」（`mcp-panel.tsx:733`），第三处需补一句「智能体/运维标记」的前缀（`behavior-panel.tsx:1296-1301` 目前只有列表标题）；
- `grep -rn "toFixed(3)" ndr/frontend/components/analysis-panel.tsx` 为空。

---

## 7. 不要改的地方（明确判为"对的"）

写这一节是为了防止实现方"顺手统一"把好不容易攒对的东西改掉。

| 位置 | 用法 | 为什么是对的 |
|---|---|---|
| `status-panel.tsx:90-95` `LIGHT_CLS` | 组件呼吸灯 `bg-sev-ok-fg` / `bg-sev-medium-fg` / `bg-sev-critical-fg` | 系统健康（L4），红=不可用是全世界通用语义，且用圆点不用徽章，不会与判定混淆 |
| `status-panel.tsx:622-630` | 「已暂停消费」`critical`、「覆盖告警」`high` | 平台自身状态，不是关于流量的判断 |
| `status-panel.tsx:116` `Kpi danger→tone` | 覆盖率 warn / 未投递 / 丢包率 / 队列超 80% | 全部是 L4；`danger` 的语义就是"这件事需要你处理" |
| `suppressions-panel.tsx:812-830` | 两列 mode 对照带（红/琥珀整带 + 左侧 3px 竖条 + 图标 + 长文案） | L5 后果语义的**范本**，四重编码，且明确写了「后果」二字 |
| `suppressions-panel.tsx:924` | `modeVariant()` 徽章 | 与 812-830 同一语义，实心正确 |
| `lib/analysis.ts:157-161` `MODE_VARIANT` | `suppress→critical`、`record_only→medium` | 同上 |
| `analysis-panel.tsx:663-703` 首屏六格 | 全 `md`、全中性、只有覆盖率 <0.2 用 `medium` | **事实优先的范本**，本文 §5 就是照它推的 |
| `analysis-panel.tsx:200-241` `PressureBar` | `ratio>=1 → bg-sev-critical-fg`、`>=0.8 → medium` | 容量是 L4 状态（"满了"是客观事实 + 需要动作），且只画条不画字 |
| `analysis-panel.tsx:1219-1225` | 覆盖率空表用 `border-sev-ok-bd bg-sev-ok-bg` | "没有盲区"确实是好消息，且是一整块空态容器，不是数据徽章 |
| `analysis-panel.tsx:1044,1462-1466` | 结论 + 置信度 + 结论人同行 | 归属做得最对的地方 |
| `event-charts.ts:69-71` | 命中趋势用 `t.series[0]`（`chart-1`） | 趋势是量，不是等级 —— 正确 |
| `events-panel.tsx:99-122` `SRC_TONE` / `SourceChip` | 紫 / 青 / 品红三类来源 | `globals.css:95-98` 已刻意避开严重度色相；用于**分类**不用于**程度**，正确 |
| `events-panel.tsx:256,1136,1141` | 「已忽略」「已加白」用 `outline` | 流程态，无色正确 |
| `events-panel.tsx:553-554,1012` | 消息条 / 错误用 `sev-ok` / `sev-critical` | 操作反馈，不是数据 |
| `traffic-panel.tsx:368-378` | 错误/警告条 | 同上 |
| `assets-panel.tsx:409-419,473-483` | 读取失败/空态提示条 | 同上 |
| 全站 `border-border-subtle` / `text-muted-foreground` / `bg-surface-1` | 表格边框、次要文字、内联格 | 与"谁下判断"无关，中性层不需要动 |
| `rule-tree.tsx` 全文 | 只有树干/肘线用 `bg-border-subtle` | 纯布局原语，零语义色 |
| `TailwindConfig` 的 `sev-*` 定义本身 | 6 档三件套 | **保留**，只是限制使用范围（只允许 `-bd`/`-fg` 出现在事实层） |

---

## 8. 后端待办登记（本任务不改代码，只登记，供后端排期）

这三条前端**修不了**，只能如实标注。写在这里是为了避免实现方以为"界面改了就等于修好了"。B1 决定"哪些历史图根本不该存在"，B2 决定"级别那一列能诚实到什么程度"，B3 决定"派工态势能不能画趋势"。

| # | 位置 | 问题 | 建议动作 | 约束 |
|---|---|---|---|---|
| B1 | `detector/runner.py:324-332` | `mark_digest(stats, digest)` 与 `stats["digest"] += 1` 写在 `analysis.enabled` 的 `continue` **之后**，默认配置下永不执行 → `d_digest`、`d_digest_sev_*`、`by_rule` 全部恒 0/空 | **本期不做**（三张图已按 §6.0 撤掉）。若后端日后要救「规则 TOP 15」：把 `mark_digest()` 里的 `rule` 累加单独抽出来、在 `continue` **之前**调用即可（它只累加内存 Counter，不做 I/O）。整块前移也行，但会连带复活 `digest_sev_*` | 前移是**一对二**的联体操作：`digest_sev_*` 与 `digest_rule_*` 在同一个函数里（`history.py:41-51`）。**规则名分布是事实，可以复活；严重度分布不行**（D4 不用 `rule_severity`）。谁要复活必须重新评审，且**不许沿用「24h 严重度分布」原名** |
| B2 | `detector/hits.py:572,609,643` | `save_baseline_deviations` 把**画像风险分**换算成 `rule_severity`（`_severity_of_risk`），数值 2σ 偏离直接写死 `"high"` → `hit_events.rule_severity` 混进了三种产地，且违反 D2「NDR 只排客观强度，不写威胁语义」 | 优先方案：`hit_events` 增加**独立的 `label_level` 字段**承载"数据自带等级"，`rule_severity` 只留给真正的规则命中；若暂不改表，至少把数值 2σ 的写死 `"high"` 改成按 `z` 值分档并在 `source_kind` 上再细分（如 `baseline_numeric`），让前端能诚实标注 | 前端只能靠 `source_kind` 区分"规则命中"与"基线偏离"两类；**同一 `baseline_deviation` 里的画像行与数值行前端无法区分**，所以 §6.1 的 title 只能把两种情况都写出来。写死 `high` 的实际后果已量化在 §1.2：聚合主徽章与首屏「级别：高危以上」的**计数**都偏高，而行顺序不受影响（`SORTS` 里没有级别） |
| B3 | `analysis/tasks` 队列历史 | 派工队列的 pending/claimed/throughput **只有当前快照**（`/api/analysis/stats`），没有时间序列 | 若要给「线索与派工」块加趋势图，需给 `task_stats` 落周期性采样（复用 `detector/history` 的 append 约定：定长 LTRIM + TTL） | **本期不做，也不留占位**。没有采样就只放当前快照 + 数字（"没画"比"画一条假平线"好）。这一条不排期也没关系——总览的「线索与派工」块按 §1.1 的三行表实现即可，与 B3 解耦 |

---

## 9. 一页速查

```
有人在下判断吗？
├─ 是：智能体（verdict）
│    └─ 实心徽章 + COLUMN「智能体结论」/「判定」 + 同行给结论人
│       true_positive 红实心 · suspicious 琥珀实心 · benign 绿实心
│       false_positive 灰实心 · inconclusive 灰虚线空心 + terminal_reason
└─ 否：只是资料
     ├─ 量（strength / 次数 / 规模 / 暴露面）→ 等宽数字 + bg-intensity-1..3 条
     ├─ 级别标注（命中事件的 rule_severity 三源混合 / 签名级别 / 资产级别）
     │  → 空心徽章（只用 -bd + -fg）；列名只能叫「级别」，不能叫「严重度」或「规则标注」
     │    产地要**看得见**：`~` 按强度折算 · `*` 含推算 · 签名不加符号（上标 8px）+ 表脚图例 + title 全解
     └─ 分类（来源三类）→ src-* 不动
平台自身状态（健康 / 流程态 / 容量）→ 保持现状，圆点或实心流程徽章
动作后果（抑制 mode）→ 保持现状，整带 + 竖条 + 图标 + 长文案
"这一项在新架构里根本不会产生" → 显示「—」+ 明确标注，绝不用 0
"这个统计已停更" → 撤图 + 回收版面，**禁止改名保留**（空图改中性名比原名更误导）
```
