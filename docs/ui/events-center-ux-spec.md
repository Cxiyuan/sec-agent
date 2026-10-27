# 事件中心 · 体验规范（Phase 2）

> **角色**：体验设计（UX/UI）专家。本文把「事件中心」这个新一级页面落成可编码的交互规范。
>
> **上游依据**
> - `docs/api/README.md` 第 71–85 行（事件中心契约 `/api/detector/*`）、第 299–307 行（前端对接要点）、第 317–324 行（四个必读的坑）
> - `docs/ui/config-layout-visual-spec.md`（Phase 1 视觉规范，本文不推翻其中任何视觉决策）
> - `docs/ui/config-layout-ux-spec.md`（配置管理页 Phase 2，本文沿用它的纪律：状态显式化、不做乐观更新、空态三态分治、口径必须标注）
>
> **迁移源**：`ndr/frontend/components/status-panel.tsx` 第 670–910 行（运营中心「威胁事件」区块里的「命中事件（最近）」卡片：9 列表格 + 来源下拉 + 详情 Dialog + 忽略/加白名单）。
>
> **一致性基准**：`ndr/frontend/components/logs-panel.tsx`（日志检索页）。用户与 team-lead 的口径都是「与日志检索页交互一致性优先」——两页是同一类「重筛选工作台」，用户在它们之间切换时，肌肉记忆不能断。本文所有「与日志页一致」的论断都指向这份源码的既有写法。
>
> **硬约束**（与配置管理页任务相同）：不新增依赖；不改接口、请求体、localStorage key；不本地构建；只写文档、不改代码。文中所有代码块是给 Phase 3 的规格，不是本次改动。

---

## 0. 先说四个必须修的既有缺陷

迁移不是「把卡片搬过去」。运营中心的命中事件卡有四个缺陷，其中三个在新页面会直接变成事故。这四个缺陷的修法贯穿全文，先立在这里：

### B1 详情里的操作失败，错误消息渲染在用户看不见的地方

`status-panel.tsx` 第 695 行把 `hitMsg` 渲染在**表格上方**（`<CardContent>` 开头），而详情 Dialog 在第 781 行才打开。在弹窗里点「忽略这条」失败时，红字出现在弹窗背后的表格上方——用户盯着弹窗，看到的是「点了没反应」，于是重复点击、重复 POST。

新页面修法：处置失败的消息必须渲染在 **Drawer 内部、footer 上方**，`role="alert"`（§6.3、§7.4）。

### B2 忽略/加白成功后，行会消失，且没有任何解释

后端 `attach_whitelist`（`ndr/backend/app/detector/hits.py` 第 730–744 行）在建立排除过滤器的同时，把该行 `ignored` 置 True、`ignored_reason` 写成「已加白名单（filter_id）」。而默认列表（`include_ignored=false`）的服务端条件写死 `HitEvent.ignored.is_(False)`（同文件第 528–529 行）——**加白不仅建过滤器，还顺手让这一行从默认列表里消失**。

运营中心对成功的处理是 `setHitDetail(null); await load()`（第 399–400 行）：弹窗关了，表格重取了，那一行凭空不见。用户第一反应是「我把它删了？还能找回吗？」

新页面修法：操作成功后必须有一条明确的消息，说清行去哪了、怎么查回（§6.4）。这不是文案润色，是防错。

### B3 概览与列表的口径会分裂，且没有任何标注

`hits_stats`（`hits.py` 第 616–699 行）的 `base` 条件写死 `HitEvent.ignored.is_(False)`，所以概览的 `total` **恒为「未忽略」口径**；而列表勾选「包含已忽略」后 `total` 会把已忽略算进去。两个数字同屏不同源，运维会把概览当「系统总共这么多事件」、把列表当「符合筛选的全部」，排查时对不上。

新页面修法：两个数字旁都必须写口径，缺一个就没修（§2.4）。

### B4 日志检索页的行点击没有键盘入口

`logs-panel.tsx` 第 492–495 行的表格行只有 `onClick`，没有 `tabIndex`、没有 `onKeyDown`——键盘用户永远打不开详情。事件中心要与其保持「整行可点」的一致性，但必须补键盘入口；并建议日志页回填（§13 差异清单 D2）。

---

## 1. 信息架构

### 1.1 导航位置、路由与侧边栏

| 项 | 值 | 为什么 |
| --- | --- | --- |
| 一级菜单 | 「事件中心」，插在 `NAV_SECTIONS` 的 `analysis` 与 `assets` **之间** | 用户原话：「它在资产中心之前」 |
| 路由 | `/events`，`match: "/events"` | 与 `/logs`、`/behavior` 同级的单页路由 |
| 侧边栏 | **无** | 单页，没有子页要导航。侧边栏服务的是「同一分区多个子页」（配置管理 8 个、资产中心 4 个），单页挂侧边栏只会多一条空的「事件中心 / 事件中心」 |
| icon | `Siren`（lucide 既有，新增一个 import 不构成新依赖） | `AlertTriangle` 已被 `CONSOLE_SHORTCUTS` 占用；`Siren` 与「事件/告警」语义对齐且未占用 |
| desc | 「命中事件 · 检索 · 详情 · 处置」 | 页头菜单悬停/读屏用，说清这页能干什么 |

`nav-config.ts` 插入位置与代码规格（第 141–151 行 `assets` 之前）：

```ts
{
  key: "events",
  href: "/events",
  label: "事件中心",
  desc: "命中事件 · 检索 · 详情 · 处置",
  icon: Siren,
  match: "/events",
},
```

`sectionOf` / `sidebarOf` / `sectionActive` 三个函数都按 `match` 前缀归属（`nav-config.ts` 第 179–228 行），`/events` 会自动高亮、且 `sidebarOf("/events")` 返回空数组 = 不显示侧边栏，正文占满宽度。**不需要改这三个函数**——这是 nav-config 既有设计的红利，写在这里是为了让 Phase 3 别去动它。

**页头一级菜单项不加角标数字**（design-architect 补充的反模式理由）：`hits/stats` 是 24h 口径、且 `ignored` 计数随处置操作跳动——一个不随页面交互刷新的角标会比没有更糟（用户按它做决策，它却是旧的）。「有多少新事件」的答案在页面内：数据时间戳 + 概览 Stat，不在菜单上。NavItem 类型（`nav-config.ts` 第 38–51 行）也没有 badge 字段，不为此扩展。

### 1.2 页面骨架

```
/events ── PageShell title="事件中心" width="full"（无侧边栏，正文铺满）
│
├─ PanelError（既有组件：任一接口失败时的红条，role="alert"）
├─ 消息槽（成功/失败，role="status" / role="alert"，与 PanelError 同区互斥）——§6.4
│
├─ L1 Section「事件概览」                ← /api/detector/hits/stats（§5）
│   ├─ description：统计口径 + 数据时间（formatClock）
│   ├─ 3 个 Stat（总数 / 高危及以上 / 已忽略）
│   ├─ 来源三类 chips（可点击钻取筛选）——§2.5
│   └─ grid lg:3：命中趋势图（col-span-2）+ 事件归类 TOP 10 卡
│
├─ L1 Section「筛选条件」                ← extra：数据时间 + 刷新按钮（§8.3）
│   └─ Card
│       ├─ 主行：时间范围 select + 关键字 Input（flex-1）
│       ├─ 字段网格（sm:2 / lg:4）：来源 / 严重度 / 事件归类 / IP
│       └─ 操作行：搜索 / 重置 / 排序 / 每页 / 包含已忽略 + 右侧「共 N 条」
│
├─ L1 Section「事件列表」                ← extra：第 X / Y 页 + 上一页 / 下一页（§3）
│   └─ Card（p-0）
│       ├─ 首帧：TableSkeleton rows=10 cols=8
│       └─ 表格 8 列（§7.2）或四象限空态之一（§8.1）
│
├─ Drawer「事件详情」                    ← /api/detector/hits/{id}（§7）
│   └─ footer：忽略这条 / 白名单 scope / 加入白名单
│
└─ Dialog「确认忽略」                    ← 不可逆操作的二次确认（§6.2）
```

区块职责：

| 区块 | 数据源 | 职责 | 明确不负责 |
| --- | --- | --- | --- |
| 事件概览 | `GET /hits/stats?minutes=` | 回答「这段时间 overall 什么情况」：总量、高危、已忽略、三类来源、趋势、TOP 归类 | 不做成第二个列表；不做处置入口（只有钻取筛选） |
| 筛选条件 | 无（纯表单态） | 收敛查询参数；显式提交 | 不自己发请求以外的职责；不做折叠（六维度一屏放得下，折叠反而多一步） |
| 事件列表 | `GET /hits?…` | 逐条呈现、翻页、进入详情 | 不做行内编辑/删除（契约只有 ignore/whitelist 两个写端点，都走详情） |
| 详情 Drawer | `GET /hits/{id}` | 完整字段 + 证据样例 + 两个处置动作 | 不做「下一条」导航（翻页在列表做；要做须先定义跨行预取，本期不做） |

### 1.3 与周边页面的关系

| 页面 | 关系 | 具体动作 |
| --- | --- | --- |
| 运营中心 `/console` | **迁出方** | 删命中事件卡；三张趋势图保留；区块加跳转链接（§10） |
| 日志检索 `/logs` | 并列工作台 | 交互同构（§2.3、§3、§7.1）；4 处已知差异（§13） |
| 配置管理 → 过滤规则 `/config/filters` | 白名单的落地处 | 加白成功消息里指明「配置管理 → 过滤规则可停用/删除」（§6.4） |
| 检测规则 `/config/rules` | 归类名的来源 | 列表「事件归类」列显示 `rule` 字段；筛选框 `rule` 与规则页名称同口径（`ruleText` 不迁移改名） |
| 铃铛（TopBar） | **不加条目** | `noticesOf`（`topbar.tsx` 第 37–84 行）只收「需要马上处理的运行告警」（检测器暂停、隔离队列、Redis、推送），全部指向 `/console`；命中事件不属于这一类，不改铃铛 |

---

## 2. 筛选交互模型

### 2.1 六维度契约表

契约来自 `hits.py` 的 `_hit_conditions`（第 511–566 行）。**每维度的后端匹配方式不同，UI 的 placeholder/hint 必须照此写**，否则用户会得出「搜索坏了」的结论：

| 维度 | 参数 | 控件 | 后端语义（源码） | UI 必须写清的 |
| --- | --- | --- | --- | --- |
| 时间范围 | `minutes` | select：1h/6h/24h/7d（**四档，无「不限」**——Q-A 裁决，§4.3） | `>0` 才加条件，按 `coalesce(last_seen, created_at) >= now-minutes`（536–539 行） | 概览与列表同窗口（§4.2）；stats 表达不了不限，故不设该档 |
| 来源 | `source_kind` | select：全部/特征匹配/行为分析/基线偏离 | **精确匹配**，且只认三个 key（530–532 行 `if kind in SOURCE_LABELS`） | 值传英文 key（`feature_match` 等），标签显中文；来源中文名后端已给（`source_label`） |
| 严重度 | `severity` | select：全部/严重/高危/中危/低危/信息 | **精确匹配**（533–535 行 `== sev`，先 `.lower()`） | 值必须小写英文（`critical/high/medium/low/info`）。库里出现这五个值以外的严重度时，只有「全部」看得到——**不造「其它」选项**（造了也筛不出来） |
| 事件归类 | `rule` | Input 文本 | **子串** `ilike %…%`（540–542 行） | placeholder 写「事件归类名，如：Web 应用攻击」；只匹配归类名，不搜证据 |
| IP | `ip` | Input 文本 | **子串**，四字段 or：`src_ip / client / via / dst_ips`（543–553 行） | placeholder 写「请求方 / 中继 / 目的 IP 片段」；证据里的 IP 搜不到——用「关键字」 |
| 关键字 | `q` | Input 文本 | **子串**，五字段 or：`rule / src_ip / client / via / **evidence**`（554–565 行） | placeholder 写「IP / 账号 / URI / UA / 证据全文」；唯一能搜进证据的维度 |

三个文本维度的分工（`rule` / `ip` / `q`）是用户最容易混淆的地方，**hint 文案逐字采用上表右列**。这不是啰嗦：搜 IP 搜不到证据里的 IP时，没有 hint 的用户会去怀疑接口，而不是换 `q`。

### 2.2 表单态与查询态分离

与日志页同构：`form` state 是「用户正在填的」，已生效的查询是「屏幕上这些行的来源」。两者分离的理由：

- 六个维度 + 分页，任何一次键入都重查，会让 `offset` 归 0、表格狂闪；
- 文本维度（rule/ip/q）必须允许「打完再提交」——`ilike` 子串匹配下，打一半的字符串会查出半张表。

提交规则：

| 控件 | 变更后行为 | 理由 |
| --- | --- | --- |
| 时间范围 / 来源 / 严重度 / 排序 / 每页 / 包含已忽略 | **立即重查**（`run(0)`） | 离散选择没有「打一半」问题；日志页「改完不点搜索不生效」是 bug（§13 D1） |
| 关键字 / 事件归类 / IP | Enter 或点「搜索」提交 | 文本维度，防闪烁 |
| 「搜索」按钮 | 始终可点，按当前表单重查 | 用户改了文本又改了离散项时的一键同步 |
| 「重置」 | 表单回默认值 + 立即重查 | 默认值见 §2.4 表；重置后必须立刻有结果，不能留一张旧表 |

### 2.3 控件排放（与日志页逐字一致）

筛选区结构照抄 `logs-panel.tsx` 第 244–443 行的三段式，控件 class 也照抄，**一处都不新造**：

- 主行：时间范围 `select`（`h-9 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground`）+ 关键字 `Input`（`min-w-[260px] flex-1`）
- 字段网格：`grid gap-3 sm:grid-cols-2 lg:grid-cols-4`，四个 `Field` 位（来源/严重度/事件归类/IP）
- 操作行：搜索（`Button size="sm"` + `Search` 图标）、重置（`variant="outline"` + `RotateCcw` 图标）、排序 select、每页 select、包含已忽略 checkbox；右侧 `ml-auto` 是「共 N 条」

**不用 `Field` / `FieldGrid`**（`packages/ui/src/components/ui/field.tsx`）：那两个组件服务的是配置管理页的表单（span 档位、hint 说明、校验错误），事件中心的筛选区是「即填即走的工作台条」。两页控件长得不一样，用户在两个工作台之间切换时要重新适应位置——一致性优先的硬要求下，这里刻意不复用。已与 design-architect 的口径：配置页的 `FieldGrid` 推广范围**不含**本页与日志页。

label 关联方式与日志页一致：`<label className="text-xs text-muted-foreground">` **包裹**控件（隐式关联，无需 id/htmlFor 配对）。

### 2.4 `include_ignored` 状态机（本页最容不得错的开关）

契约：默认不返回已忽略（后端默认 `include_ignored=False`，`detector.py` 第 393 行；`docs/api/README.md` 坑 5）。勾选 = 请求带 `include_ignored=true`。

| # | 状态 | 请求 | 列表 | 概览 | 消息/标注 |
| --- | --- | --- | --- | --- | --- |
| 1 | 默认（未勾选） | 不带该参数 | 只有未忽略事件 | `total` 与列表 `total` 同口径 | 概览 Stat hint「不含已忽略」 |
| 2 | 勾选 | `include_ignored=true` | 多出带「已忽略 / 已加白」徽章的行 | **不变**（stats 服务端写死未忽略口径，B3） | 「共 N 条」必须变成「共 N 条（含已忽略）」 |
| 3 | 勾选状态下忽略一条 | 同 2 | 行**留驻**，徽章由无 → 「已忽略」 | 不变 | 成功消息照常（§6.4） |
| 4 | 未勾选状态下忽略一条 | 同 1 | 行**消失** | `ignored` +1 | 成功消息必须解释「默认列表不再显示；勾选『包含已忽略』可查回」（B2） |
| 5 | 由勾选切回未勾选 | 同 1 | 带徽章的行消失 | 不变 | 无消息（用户主动操作）；「共 N 条」口径标注同步收回 |
| 6 | 刷新时 | 保持当前勾选态重取 | — | — | 刷新不清表单（§8.2） |
| 7 | 离开页面再进入 | 回默认未勾选 | — | — | **不持久化**：默认口径必须可预期；持久化会让「默认看不到已忽略」这个安全默认漂移，且本页没有为此引入 localStorage key 的理由（硬约束：不改/不加 key） |

口径标注（B3 的修法，两个都要，缺一个等于没修）：

- 概览 Stat「事件总数」hint 固定写「窗口内 · 不含已忽略」——**任何时候都在**，不随勾选变化；
- 列表「共 N 条」在勾选时追加「（含已忽略）」。

### 2.5 概览钻取（chips / TOP 规则点击）

与日志页第 425–442 行的 `log_types` chips 同构：

- **来源 chip**：点击 = `form.source_kind = key` 并 `run(0)`；**再点同一 chip = 清空该维度**（回「全部」）。当前选中的 chip 高亮（`border-primary text-primary bg-brand-50`），未选中 `border-border-subtle text-muted-foreground`。
- **TOP 规则行**：点击 = `form.rule = rule` 并 `run(0)`。
- 钻取后面板上的筛选条件**同步可见**（表单态与查询态一起变）——「状态可见」原则：用户从概览钻进来后，抬头就能看到筛选区已经填好了，能改、能重置。
- chip 的三类**全量渲染**（`count=0` 也渲染、置灰但仍可点）：让用户知道「系统有三类来源，不是只有出数据的这类」。

---

## 3. 分页模型

### 3.1 offset 分页，不用页码按钮

与日志页第 448–472 行一致：`上一页 / 下一页 + 第 X / Y 页`，放在「事件列表」Section 的 `extra` 里。

- `page = Math.floor(offset / size) + 1`，`pages = Math.max(1, Math.ceil(total / size))`（照抄日志页第 223–224 行的算法）。
- 不引页码条的理由：事件总数可能上千，1…40 的页码条占一整行且深翻页成本与「下一页×N」相同；运维的真实动作是「看最新几页」和「按条件收窄」，不是跳到第 23 页。
- `limit` 上限 200（后端 `cap = max(1, min(int(limit or 50), 200))`，`hits.py` 第 588 行）。每页选项 `[20, 50, 100, 200]`，默认 50（与日志页 `PAGE_SIZES` 逐字一致）。

### 3.2 联动规则

| 动作 | offset | 是否重取 |
| --- | --- | --- |
| 翻页（上/下） | ±size | 是（只重取列表，stats 不变） |
| 每页条数变更 | 归 0 | **是**（§13 D1：日志页只改 state 不重查，分页器数字与内容错位） |
| 任一筛选维度变更 | 归 0 | 是（§2.2） |
| 刷新 | 保持 | 是（重取当前页 + stats） |
| 忽略/加白成功 | 保持 | 是（§6.3；若该行从当前页消失，行数自然收缩，不强行跳页） |

offset 归 0 的理由：用户停在「第 3 页 + 刚改的筛选」时，看到的既不是新筛选的第一页、也不是任何一页的完整语义——是一个随机横截面。

### 3.3 禁用态与越界态

- 上一页禁用：`offset <= 0`；下一页禁用：`offset + size >= total`（与日志页第 458、466 行一致）。
- **越界态（第五空态）**：查询成功、`total > 0`、`items.length === 0`。真实触发路径：翻到第 3 页后，另一路值班（或本页的忽略操作）把第 3 页的事件处置掉了；或 two-tab 并发。文案：
  - title：「这一页的事件已不在当前口径内」
  - hint：「可能刚被忽略或清理。回到第一页重新看。」
  - action：按钮「回到第一页」（`run(0)`）
- **不要说「没有符合条件的事件」**——那是真无（第四象限）的文案。把越界说成「没有」，用户会去放宽筛选，而问题根本不在筛选。

---

## 4. 时间范围与 stats 联动

### 4.1 四档与默认值（Q-A 已裁决：无「不限」）

| 档位 | `minutes` 值 | 请求 |
| --- | --- | --- |
| 最近 1 小时 | 60 | `minutes=60` |
| 最近 6 小时 | 360 | `minutes=360` |
| 最近 24 小时（**默认**） | 1440 | `minutes=1440` |
| 最近 7 天 | 10080 | `minutes=10080` |

默认 24h 的理由：与 stats 接口的默认值（1440）一致；打开页面就有东西看，符合「默认即有用」。

### 4.2 联动规则（列表与概览同窗口）

- 概览的 stats 请求与列表用**同一个 `minutes` 值**：`GET /api/detector/hits/stats?minutes=<同值>`。
- 改时间范围 = 离散筛选变更 → 立即重取两者（§2.2）。
- 概览标题随窗口变：「近 1 小时命中」「近 6 小时命中」……Section description 里写口径：「统计窗口随下方时间范围变化；总数不含已忽略；点来源或规则可按它筛选」。
- **刷新同时重取两者**（§8.3），保持同窗口。

### 4.3 裁决记录：「不限」档砍掉（Q-A，主理人 2026-10 裁决）

**最终档位就是 §4.1 的四档，任何位置不出现「不限」选项，也不出现它的降级声明文案。**

裁决理由（保留备查，不再是实现指引）：`hits_stats` 的第一行是 `window = max(1, int(minutes or 1440))`（`hits.py` 第 621 行）——`minutes=0` 会被静默改成 1440。若 UI 提供「不限」，会出现「列表全量、概览 24h」的口径分裂：用户把概览的 TOP 规则当成「历史全量 TOP」，而它只是最近 24 小时的 TOP。这比数字小更糟——是可信度问题。当时讨论过两个处理：方案甲（保留 + 概览显式声明「不限时按最近 24 小时统计」）与方案乙（砍掉）。**裁决取乙**：stats 契约表达不了「不限」；列表与概览同源同窗口是事件中心可信度的底线；真要翻全量，7d + 排序 + 翻页已经覆盖，而「全量趋势图」（168+ 桶起步、SQL 全表 group by）对读图也没有意义。

对 Phase 3 的硬要求：

- 时间范围下拉**只有 4 个 option**；没有第 5 档，没有「不限」相关的任何 hint/description/空态文案；
- `minutes` 恒 > 0，`buildHitsQuery` 里 `if (form.minutes > 0)` 的分支永远走真（保留防御性写法，但不为 0 造 UI）；
- 该裁决已同步 design-architect（视觉规范 §4.1 同口径）与 fe-engineer（实施规格明确「任何位置不出现『不限』选项或其降级文案」）。

### 4.4 趋势图的实现点（写在这里，前端不用再推）

- 桶大小：窗口 ≤6h → `bucket_seconds=600`（10 分钟）；否则 3600（小时）。后端直出（`hits.py` 第 623 行），前端不自己算。
- **`trend[]` 只包含有数据的桶**（第 678–689 行只收集出现过的 key）——前端必须按 `bucket_seconds` 从窗口起点**补零**画连续折线，否则 7d 图会裂成散点。这是最容易漏的一处。
- 桶数：1h=6、6h=36、24h=24、7d=168。168 桶时 X 轴标签抽稀（约每 12 桶一个）。
- `trend[].ts` 是 UTC ISO（`…Z`）——X 轴标签一律转北京时间（`Asia/Shanghai`，与 `packages/ui/src/lib/format.ts` 的 `TIME_ZONE` 同源）。
- 图表本体（折线/柱、配色、高度）归视觉规范；Phase 1 已定 `ChartCard` 三档高度 176/224/288，趋势图用 224 档、占 `lg:col-span-2`，与运营中心「24h 命中与摘要趋势」同构。

---

## 5. 概览区规格（stats 落地）

### 5.1 三个 Stat（`grid-cols-1 sm:grid-cols-3`）

| Stat | 值 | tone | hint（逐字） |
| --- | --- | --- | --- |
| 事件总数 | `stats.total` | default | 「窗口内 · 不含已忽略」 |
| 高危及以上 | `by_severity` 中 `high + critical` 求和 | `high` | 「严重 X · 高危 Y」（按实际数填，0 也写） |
| 已忽略 | `stats.ignored` | default | 「默认列表不显示 · 勾选『包含已忽略』可查」 |

为什么是这三个数（不是四个）：契约只给了 `total / ignored / by_source_kind / by_severity / top_rules / trend`。**没有「受影响请求方数」「平均处置时长」这类维度——不造数**。高危及以上单独拎出来，因为值班的第一眼问题是「有没有要马上看的」。

### 5.2 来源 chips 行

`by_source_kind[]` = `[{key, label, count}]`（后端已给中文 label，`hits.py` 第 652–656 行）。渲染三类全量 chip（§2.5），行首一个 `text-xs text-muted-foreground` 的「按来源：」引导词。

### 5.3 趋势图 + TOP 10（`grid-cols-1 lg:grid-cols-3`）

- 趋势图 Card：`lg:col-span-2`，`ChartCard height={224}`，数据 `trend[]`（§4.4）。
- 「事件归类 TOP 10」Card：`top_rules[]` = `[{rule, count}]`，后端 `limit(10)`（`hits.py` 第 660–670 行）。卡片内 10 行紧凑列表：规则名 `truncate` + count `text-right tabular-nums`；行可点击钻取（§2.5）。
  - 容器语言（视觉规范取值，已对齐）：`divide-y divide-border-subtle` 分隔，不套二级边框卡片。
  - **每行用原生 `<button>`（`w-full text-left`）而不是 `div + tabIndex`**：键盘可达性免费获得（Enter/Space 原生触发、焦点环原生可见），不必像表格行那样为表格语义付代价（对比 §11.3）。hover `bg-brand-50` 与 Table 行同色，同一套「可点」语言。
- TOP 卡空态：`EmptyState size="compact" tone="muted"`「窗口内没有事件」。

### 5.4 概览区的三态

| 态 | 判定 | 渲染 |
| --- | --- | --- |
| 首帧 | stats 未返回且未失败 | `StatSkeleton count={3}` + 趋势位 `ChartSkeleton height={224}` + TOP 卡 10 行 `h-3` 骨架 |
| 空 | stats 成功且 `total === 0` | Stat 显示 **0**（不是「—」）；TOP 卡 compact 空态；趋势图空态归视觉规范 |
| 失败 | stats 失败 | Stat 显示「—」+ PanelError 红条已挂；**不画 0**（`docs/api/README.md` 坑 3：把故障画成「没有数据」是本项目最大的既有坑） |

stats 失败时趋势图与 TOP 卡：保留骨架不如显示错误——按 `emptyOrFailed(errs, SRC.stats, …)` 的口径给一句「读取失败（见上方错误条）」，与既有用法一致（`panel-error.tsx` 第 109–111 行）。

---

## 6. 处置流程（忽略 / 白名单）

### 6.1 契约边界：只有单条接口，不设计批量

契约是两个单条端点（`detector.py` 第 449–476 行）：

- `POST /api/detector/hits/{hit_id}/ignore`，body `{reason: string}`（`HitIgnoreIn`，reason ≤200 字符）
- `POST /api/detector/hits/{hit_id}/whitelist`，body `{scope: "src" | "src_dst", note: string}`（`HitWhitelistIn`）

**批量（勾选 N 条一起忽略）不做**：契约没有批量端点，本规范不造。批量忽略的真实需求（「这 200 条扫描告警一次性消掉」）应该由「白名单 scope=src」满足——一条规则的一个来源，正是批量的正确形态。这个引导要写进白名单的 hint（§6.4）。

后端两个必须知道的行为：

1. **加白 = 建过滤器 + 把行标记为已忽略**（`attach_whitelist`，`hits.py` 第 730–744 行）。所以加白成功后行同样从默认列表消失（B2）。
2. **白名单条件 = 真实请求方 + 命中规则**（`scope=src_dst` 时再加第一个目的 IP:端口，第 485–495 行）。只放行「这条规则的这个来源」，**不是把整个 IP 全放掉**——这句话（后端注释原话）必须出现在 UI 上，否则用户会以为加白=给该 IP 开全局通道，风险完全不对等。

### 6.2 为什么忽略要二次确认，白名单不要

| 操作 | 可逆性 | 对策 |
| --- | --- | --- |
| 忽略 | **不可逆**：接口只有 ignore，没有取消端点。「可撤回」仅指行还在库里、`include_ignored=true` 能查回、改数据库能改回 | **必须过确认 Dialog**。Nielsen 防错原则：不可逆操作要确认 |
| 加白 | 可逆：落在排除过滤器里，「配置管理 → 过滤规则」可停用/删除 | 不确认，但 scope 选错（`src_dst` 比 `src` 宽）要从成功消息里能看出条件（§6.4） |

确认必须轻（值班要快）：一个 480px 的共享 `Dialog`，一句话后果 + 两个按钮。重确认会逼出「闭着眼点确认」的惯性，那比不确认更糟。

### 6.3 状态机（逐步，含失败分支）

```
S0  详情 Drawer 已打开（§7.3 两段式数据已渲染）
│
├─ 用户点「忽略这条」
│   └─ S1  打开确认 Dialog（480px）；背景 Drawer 的按钮全部 disabled
│       └─ S2  「确认忽略」→ confirmBusy=true（确认按钮 disabled + aria-busy）
│           └─ S3  POST /hits/{id}/ignore  body {"reason": ""}
│               ├─ S4a 成功 {ok:true}
│               │     → 关确认 Dialog → 关详情 Drawer
│               │     → 页面级成功消息（role=status，§6.4）
│               │     → 重取列表 + stats（run() 全量重查）
│               └─ S4b 失败（{error} 或 400/404/409）
│                     → 关确认 Dialog，**详情 Drawer 不关**
│                     → 错误渲染在 Drawer 内 footer 上方（role=alert）——B1 修法
│                     → 重取列表（404 = 行真的没了，让列表说真话）
│
└─ 用户选 scope（默认 src）+ 点「加入白名单」
    └─ S5  busy=true（两个按钮 disabled + aria-busy）
        └─ S6  POST /hits/{id}/whitelist  body {"scope": …}
            ├─ S7a 成功 → 关 Drawer → 成功消息（含白名单名与条件）→ 重取列表 + stats
            └─ S7b 失败 → **不关 Drawer** + 内联错误（同 S4b）+ 重取
```

连点防护：`busy` 期间 Drawer footer 两个按钮 + 确认 Dialog 的确认按钮同时 disabled；确认 Dialog 打开时焦点陷阱在其内（`useModalBehavior` 既有），背景 Drawer 按钮禁用只是双保险。

错误码映射（`docs/api/README.md` 坑 6：写操作 400/404/409）：

| 码 | 含义 | 文案 |
| --- | --- | --- |
| 400 | 参数错（scope 非法等） | 「操作失败：参数不被接受（{detail}）」 |
| 404 | 事件不存在（别处已处理/已清理） | 「这条事件已经不在了（可能刚在别处被处理）。列表已刷新。」 |
| 409 | 重名（白名单 upsert 实际不触发，防御性保留） | 「操作失败：已存在同名记录（{detail}）」 |
| 5xx / 网络 | — | 「操作失败：服务暂时不可用，可稍后再试」 |

### 6.4 消息文案（逐字规格，避免各写各的）

页面级消息槽（筛选区与列表之间，与 PanelError 同区、互斥）：

- **忽略成功**：「已忽略事件 {id.slice(0,8)}。默认列表不再显示它；勾选『包含已忽略』可查回，处理记录见详情。」
- **加白成功**：「已加白名单『{name}』：{client} + 规则『{rule}』{scope=src_dst 时追加「 + 目的 {第一个 dst_pair}」}。只放行该规则的这一来源，不是全放行；落在 配置管理 → 过滤规则，可停用/删除。该事件同时标记为已忽略。」
- **失败（Drawer 内联）**：「操作失败：{errorText}」+ 若 404 追加「列表已刷新」。

为什么成功消息要这么长：B2 的修法。行消失 + 白名单「到底放了什么」是本页两个最高的误解风险，消息是唯一的解释位。

### 6.5 不做乐观更新

与配置管理页规范同一条纪律：写操作的真相只能来自重取。忽略/加白的「行消失/徽章出现」如果先画后验，失败时回滚的复杂度高于收益，且本页两个写操作都**必须重取**（列表 + stats 的 `ignored` 计数都要变）。busy 期间按钮 disabled + `aria-busy` 即可，不做行级假状态。

---

## 7. 详情呈现

### 7.1 容器：Drawer，不用 Dialog（一致性优先的裁定）

| 候选 | 结论 | 理由 |
| --- | --- | --- |
| 右侧 Drawer | **采用** | 日志检索页用 `Drawer widthClass="w-[560px]"`（`logs-panel.tsx` 第 541–567 行）；事件详情内容长（字段网格 + 多条证据样例），居中 Dialog 会遮掉列表一半，用户无法「看着列表比对着读」。共享组件的分工注释（`dialog.tsx` 头部）写明：抽屉=浏览详情，对话框=聚焦操作 |
| 居中 Dialog | 不采用 | 运营中心现用（`status-panel.tsx` 第 781 行）。迁移时改抽屉：本页是列表工作台，不是「停下来填一个值」 |

确认忽略用回 `Dialog`（480px）——这正是共享组件分工里「聚焦操作」的那一格。

### 7.2 入口：整行可点 + 键盘补齐；行尾不放「详情」按钮

- 整行 `onClick` 打开详情，与日志页第 492–495 行同构。
- **补键盘**（B4 的修法）：行 `tabIndex={0}` + `onKeyDown`（Enter / Space → 打开，Space 要 `e.preventDefault()` 防滚动）+ `aria-label`。
- **行尾不放「详情」按钮**：运营中心的 9 列（含操作列）迁移后变 8 列。一致性优先是硬要求，整行可点是日志页的既有语言；键盘/读屏入口由行的 `tabIndex` + `aria-label` 承担。残余风险与缓解见 §11.3。

`aria-label` 规格（行获得焦点时读屏念的是什么）：

```tsx
<TableRow
  key={row.id}
  tabIndex={0}
  className="cursor-pointer"
  onClick={() => void openDetail(row)}
  onKeyDown={(e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      void openDetail(row);
    }
  }}
  aria-label={`事件详情：${ruleText(row.rule)}，请求方 ${row.client || row.src_ip || "未知"}，${severityText(row.severity)}，${row.count} 次`}
>
```

**焦点环（与 §13 D2 同批回填，design-architect 复核后记入视觉规范 9.2 改项）**：行 `tabIndex={0}` 之后，键盘焦点必须可见——`TableRow` 加 `focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-inset`（只加 class、不改组件 API）。没有焦点环，键盘用户 Tab 到行上看不出停在哪一行，`tabIndex` 反而变成陷阱。本页不单独改组件，改动项统一记录在视觉规范，Phase 3 一并落地。

### 7.3 打开时的数据流：两段式（硬约束）

1. 点行 → **立即用行内已有字段渲染 Drawer**（不空白等待；运营中心第 355–372 行的现式保留）
2. 同时 `detailLoading = true` → `GET /api/detector/hits/{id}` → 用返回值**整体替换**（补上 `evidence`）→ loading 结束

为什么必须再取一次：列表接口**不带证据**——`_rows_to_dict` 只在 `detail=True` 时输出 `evidence`（`hits.py` 第 296–298 行）。直接把列表行塞进抽屉，每条都会显示「这条命中没有留下样例事件」。运营中心第 351–354 行的注释记录了 2026-10 用户反馈，迁移时**连同注释一起搬**，别让下一个人再踩。

loading 指示（运营中心现有代码有 `hitBusy` 但 UI 上没有任何指示——迁移要补）：证据区在 `detailLoading` 时画 `Skeleton`（3–5 行 `h-3`），Drawer 根节点 `aria-busy`；字段网格区先用行内字段渲染（已有值），不画骨架。

### 7.4 内容结构（从上到下）

```
Drawer w-[560px] max-w-[94vw]
├─ header
│   └─ title（span flex-col，不用 div——Drawer 把 title 放进 <h2>，块级元素套标题里不合语法）
│       ├─ 主标题：事件归类（ruleText(row.rule)）
│       └─ 副标题：font-mono text-xs text-muted-foreground = 事件 ID 全量 + " · " + source_label
├─ body（flex-1 overflow-y-auto）
│   ├─ 错误消息槽（role="alert"）——B1 修法：处置失败渲染在这里，footer 上方
│   ├─ 字段网格 grid-cols-1 sm:grid-cols-2 text-xs（标签 text-muted-foreground + 值）
│   │    事件 ID（mono 全量）/ 规则 / 来源 / 首次 / 最近 / 次数 /
│   │    请求方（client 优先；client_source==="xff" 时 title「来自可信代理头」）/
│   │    经 {via}（有才显示）/ 目的（dst_pairs join "、"）/ 事件类型 /
│   │    连接状态 / 真实客户端（real_client_ips，有才显示）/ 处理记录（ignored_reason，有才显示）
│   ├─ 「事件内容」证据区
│   │    ├─ evidence[] 逐条卡片：样例 N · 时间 · 来源 + 字段网格 + other_fields
│   │    └─ 空：「这条命中没有留下样例事件」
│   └─ （可选）复制：footer 左侧「复制事件 JSON」——§7.5
└─ footer（border-t）
    ├─ 「忽略这条」（Button size="sm" variant="outline"）
    ├─ scope select（h-8 text-xs）+ hint「只放行该规则的这一来源，不是全放行」
    └─ 「加入白名单」（Button size="sm"）
```

字段网格与运营中心第 810–868 行**逐行对齐**（同一个 `grid grid-cols-1 gap-1 sm:grid-cols-2` + `text-xs`），包括两个特殊分支：

- 连接状态：`conn_states` 空且 `log_types` 含 `suricata` 时显示「不适用（签名引擎告警不带连接状态）」（第 849–854 行现式）；
- 请求方：`client || src_ip`，`via` 拼「（经 {via}）」，`client_source === "xff"` 时给 `title`（第 738–750 行现式）。

证据区渲染**原样迁移** `status-panel.tsx` 的 `FIELD_LABELS`（第 185–208 行，几十个 Zeek 字段中文名）、`HIDDEN_FIELDS`（第 212–227 行）、`fieldLabel`（第 230–232 行）、`eventTime`（第 236–240 行，Zeek 的 `ts` 可能是数字或字符串化秒级时间戳的特殊处理）到 `lib/hits.ts`。**不要重写**——这些中文名和踩坑分支是攒出来的，重写必丢。

### 7.5 复制（建议项，可裁）

日志页 Drawer footer 有「复制 JSON」。事件中心加一个「复制事件 JSON」（`JSON.stringify(detail, null, 2)`）放 footer 左侧：值班要把事件丢进工单/群里是高频动作。标为建议——若视觉规范认为 footer 三个控件太挤，可移到 body 底部。

### 7.6 关闭行为

- Esc / 点遮罩 / 点关闭：关闭 Drawer；焦点归还触发行（`useModalBehavior` 既有）。
- **处置成功后**：代码里 `setDetail(null)` 主动关。此时没有「触发行」可归还（刚被点的那行可能已消失）——焦点落到列表容器（`tabIndex={-1}` + 聚焦），让键盘用户从列表继续，而不是被打回页面顶部。
- Drawer 打开期间，背景表格不响应点击（遮罩拦截，既有行为）；翻页按钮在 Drawer 打开时不可达——这是可接受的（处置完自然回到列表）。

---

## 8. 四象限空态/失败态 + 刷新模型

### 8.1 四象限判定顺序（与配置管理页规范同序，代码里就是这个 if 链）

```
① firstLoad（列表未返回 && 概览未返回 && 无失败）
      → TableSkeleton rows={10} cols={8} + StatSkeleton count={3}（§8.4）
② errs.isFailed(SRC.list)
      → PanelError 红条 + EmptyState tone="danger"（§8.5）
③ result && total > 0 && items.length === 0
      → 越界空态（§3.3）
④ result && items.length === 0
      → EmptyState tone="muted"「没有符合条件的事件」+ action「清除筛选」
⑤ 否则 → 表格
```

判定顺序不能换：把 ① 放到 ② 后面，首次加载失败会闪一下骨架；把 ③ 漏掉，越界会被 ④ 接住说成「没有符合条件的事件」（§3.3 的误导）。`firstLoad` 的定义必须是「列表与概览都未返回且无失败」——刷新时两者必有一个在，永不走骨架。

### 8.2 刷新中（已有数据）

- 旧表格 + 旧概览**原样保留**，不清空、不闪。
- 刷新按钮 loading（文字「刷新中…」），`disabled` 防连点。
- 表格容器 `aria-busy="true"`（读屏知道内容在变）。
- 数据时间戳更新为本次成功时刻（`formatClock`，北京时间——`docs/api/README.md` 坑 2：接口给 UTC，界面一律北京时间）。

### 8.3 刷新模型：手动刷新，不做 5 秒强制轮询

运营中心「5 秒强制轮询、无刷新按钮」的口径（`status-panel.tsx` 第 438–444 行：用户口径「不给刷新/关闭按钮，避免有人关掉后看到陈旧数据」）**不迁移到事件中心**。三条理由：

1. **两个页面的根本节奏不同**。运营中心是盯屏仪表（「现在链路好不好」），事件中心是处置工作台（「这一行是什么、要不要处理」）。处置需要停下来读；5 秒一次的无预告重取会在用户读一行的过程中把行序冲掉（`sort=recent` 下新事件插到首页，正在读的那行往下跑），叠加忽略成功后行消失 + 重取，体验是「页面在跟我抢」。
2. **翻页状态会被冲掉**。`offset=100` 时一次轮询回来，`total` 变了，用户停在一个既不是他想去的页、内容也换了横截面的地方。
3. **陈旧数据的风险用显式控制对冲**：刷新按钮 + 数据时间戳（「数据时间 14:32:05」）把新鲜度判断权还给用户——这是 Nielsen 的「状态可见」，比「不让你关」更尊重操作者。

替代方案（本页规格）：

- **刷新按钮**放「筛选条件」Section 的 `extra`（与数据时间戳并排）：`RotateCw` 图标 + 「刷新」；点击 = 按当前查询态重取列表 + stats（不清 offset、不清表单）。
- **数据时间戳**：每次成功重取更新；`text-xs tabular-nums text-muted-foreground`。
- **不提供「自动刷新」开关**（明确不做）：想要盯新事件的用户留在运营中心（那里的 5 秒轮询为其余 11 个接口保留，§10.1）；真要做应是「自动刷新 30s + 翻页/打开 Drawer 时自动暂停 + 显式倒计时」，那是另一个页面节奏，本期不设计。

### 8.4 首帧骨架（与真实结构同形）

- 列表：`TableSkeleton rows={10} cols={8}`（既有组件，`skeleton.tsx` 第 33–59 行；列宽按比例分，像「正在填这张表」）。
- 概览：`StatSkeleton count={3}` + 趋势位 `ChartSkeleton height={224}` + TOP 卡内 10 行 `h-3`。
- 为什么强调同形：骨架比真实内容高或矮一样是跳版（配置页规范的 `lastGroupTall` 教训）。10 行表格 vs 默认 50 条一页——首屏只画 10 行占位，数据到达后表格变长是正常增长，不是跳版。

### 8.5 失败态文案（逐字）

- PanelError（既有组件自动拼接口名）：「以下接口读取失败：事件列表（/api/detector/hits）、事件概览（/api/detector/hits/stats）—— 页面显示的可能不是最新状态（后端异常或网络不通，不是「没有数据」」。
- 列表 danger 空态（照抄日志页第 520–533 行结构）：
  - title：「事件列表读取失败」
  - hint：「点『重试』重新读取；后端异常或网络不通时，页面上的数字可能不是最新状态」
  - action：`Button size="sm" variant="outline"`「重试」（`run(0)`）
- 真无（第四象限）：
  - title：「没有符合条件的事件」
  - hint：「放宽时间范围，或清除部分筛选条件」
  - action：「清除筛选」（表单回默认 + `run(0)`）

---

## 9. 响应式矩阵

### 9.1 容器与宽度口径

- `PageShell width="full"`（不传 `fluid`）：宽表工作台，越宽越好；与日志检索页同档（日志页传的是已废弃的 `fluid`，内部同样映射 `width="full"`——本页用新 API，**唯一差别是左右内边距 `px-4 md:px-6` 而非日志页的 `px-3`**，即 ≥768 时本页内容窄 24px；这是刻意选择，`fluid` 已标注 deprecated，不为了一致性把废弃 prop 传给新页面）。**无侧边栏**，所以宽度口径比配置管理页简单——没有 `--sidebar-w` 要减：
  - `W = 视口 − 48`（≥768，`px-6`）；`W = 视口 − 32`（<768，`px-4`）
  - `full` 档没有 `max-w` 收口，所以 **2560 上表格区 2512px 宽**——列宽不拉（表格自然分配 + 目的列 `min-w-0 max-w-[24rem] truncate`，`min-w-0` 不可省，理由见 §9.3），这是「单元格常态空白」不是「被拉长的控件」（配置管理页规范的同一结论）。
- 页面区块间距沿用 Phase 1：`Section` 之间 `space-y-6`（PageShell 容器），卡片内 `p-2`/行 `px-2` 的紧凑规格不引入本页（本页表格用 `Card` + `CardContent p-0`，与日志页第 474–476 行一致）。

### 9.2 表格列可见性（`sr-only` 不用 `hidden`）

窄屏藏列用 `max-lg:sr-only` / `max-md:sr-only`，**不用 `hidden`**——理由与配置管理页规范的 Q8 相同：`hidden` 会让读屏整列丢失，`sr-only` 保留语义与可达性且不占布局。

| 列 | ≥1024 | 768–1023 | <768 |
| --- | --- | --- | --- |
| 最近时间 | 显 | 显 | 显 |
| 事件 ID | 显 | `max-lg:sr-only` | `max-lg:sr-only` |
| 事件归类 | 显 | 显 | 显 |
| 来源 | 显 | `max-lg:sr-only` | `max-lg:sr-only` |
| 严重度 | 显 | 显 | 显 |
| 请求方 | 显 | 显 | 显 |
| 次数 | 显 | 显 | 显 |
| 目的（IP:端口） | 显 | 显 | `max-md:sr-only` |

768–1023 藏「事件 ID + 来源」：ID 是 8 位 mono 短码（有 `title` 全量，藏了不丢信息），来源 4 字且概览 chips 已按来源可筛——这两列是窄屏性价比最低的。<768 再藏「目的」：`dst_pairs` 是长字符串，`truncate` 后在 343px 里只剩一小条，不如藏了让「请求方」呼吸。

**藏列类必须同时写在 `th` 与 `td` 上**（design-architect 复核的落点缺口，两份文档的矩阵此前都只写了类名）：`sr-only` 是 `position: absolute`，把自己抽离文档流——只给 `<TableCell>` 写 `max-lg:sr-only` 的话，`<TableHead>` 还占着那一列，窄屏会看到**一列有头无数据**的空列。实现规格：

```tsx
{COLUMNS.map(([key, label, hideCls]) => (
  <TableHead key={key} scope="col" className={hideCls}>{label}</TableHead>
))}
{COLUMNS.map(([key, , hideCls]) => (
  <TableCell key={key} className={hideCls}>…</TableCell>
))}
```

即列定义里每个隐藏档位一个类名常量，表头单元格与数据单元格**同一个值**（`max-lg:sr-only` / `max-md:sr-only`）。这与 §9.3 的 `min-w-0` 是同一类坑：类名的落点写错，断点行为看起来对、实际错。

横向滚动是兜底不是策略：`Table` 自带 `overflow-auto` 容器（`table.tsx` 第 15 行），5 列在 375px 仍可读；**不为此做卡片式折叠**（那是另一个组件体系，本期不做）。

### 9.3 六档矩阵

| 视口 | W（内容宽） | 筛选网格 | 概览 | 表格列 | 备注 |
| --- | --- | --- | --- | --- | --- |
| 375（移动） | 343 | 1 列 | Stat 1 列 / 趋势+TOP 1 列 | 5 列 | 触控主路径：整行点击 + chips + 分页按钮 |
| 768 | 720 | 2 列（`sm:`） | Stat 3 列（`sm:`）/ 趋势+TOP 1 列（`lg:` 未到） | 6 列 | 筛选字段网格两行；操作行换行 |
| 1024 | 976 | 4 列（`lg:`） | 同上 | 8 列 | 全列回归的起点 |
| 1280 | 1232 | 4 列 | Stat 3 列 / 趋势+TOP 3 列（`lg:`） | 8 列 | 单列净宽约 154px，归类/请求方/目的靠 `truncate` 兜 |
| 1600 | 1552 | 4 列 | 3 列 | 8 列 | 富余开始出现在「事件归类」列（最长中文归类名约 10 字） |
| 1920 | 1872 | 4 列 | 3 列 | 8 列 | — |
| 2560 | 2512 | 4 列 | 3 列 | 8 列 | 目的列 `max-w-[24rem]`；其余列不拉宽（§9.1） |

「事件归类」列宽上限：`max-w-[20rem] truncate`（与运营中心目的列同规格），`title` 给全量——归类名来自 `event_title_of`（`hits.py` 第 343–352 行），最长约 10 个中文字，1600+ 才不截断。

**`min-w-0` 必须与宽度类写在同一个 `<TableCell>` 上**（design-architect 复核的技术细节，容易漏）：表格单元格默认 `min-width: auto`，光有 `max-w-[20rem] truncate` **不咬**——长归类名/长目的串会把列顶宽，截断形同不存在。事件归类、请求方、目的三列的 `<td>` 一律 `min-w-0 max-w-[…] truncate` 三件套；`th` 上只放列名宽度类，`min-w-0` 放 `td` 才是生效的那一个。

### 9.4 触控与指针差异

| 元素 | 规格 | 说明 |
| --- | --- | --- |
| 表格行 | 行高约 37px（`TableCell py-2` + `text-13`） | 整行可点补偿了高度不足；iOS 44px 建议对「大目标行点击」不苛刻 |
| chips | `py-0.5 text-xs`（约 22px 高） | 与日志页一致；chips 是**捷径不是唯一路径**（select 永远可达），不为它单独放大 |
| 分页/刷新/搜索按钮 | `h-8` / `h-9` | 全站既有规格，本页不破例 |
| Drawer | `w-[560px] max-w-[94vw]` | 375px 上 94vw ≈ 352px，字段网格退 1 列（`sm:` 未到） |

hover 反馈（`hover:bg-brand-50`）只服务指针设备；触屏没有 hover 不损失信息（点击直接开详情）。

---

## 10. 运营中心迁移影响

### 10.1 从 `status-panel.tsx` 删掉的部分（精确到行）

| 内容 | 位置（当前） | 处置 |
| --- | --- | --- |
| 「命中事件（最近）」整张 Card（含 9 列表格、来源 select、详情 Dialog、footer 动作） | 第 670–910 行 | **删** |
| `hits` / `hitDetail` / `hitBusy` / `hitMsg` / `whitelistScope` state | 第 318、322–325 行 | 删 |
| `hitKind` / `hitKindRef` / `changeHitKind` | 第 331–343 行 | 删 |
| `openHitDetail` / `hitAction` | 第 355–406 行 | 删 |
| `load()` 里的 hits 请求 | 第 416–421 行 | 删 |
| `FIELD_LABELS` / `HIDDEN_FIELDS` / `fieldLabel` / `eventTime` | 第 135–240 行 | **搬到 `lib/hits.ts`**（事件中心还要用；§7.4） |
| `severityBadge` | 第 246–249 行 | 搬（或在新页用共享 `severityVariant` + `severityText` 现拼，二选一，推荐搬以保留注释口径） |
| `SRC.hits` 常量 | 第 90 行 | 删 |
| import 清理 | `Badge` / `Dialog` / `Table*` 等若仅命中卡使用 | 删；`HitEventItem` / `HitEventList` 类型 import 删（`lib/api.ts` 的类型定义本身不动） |

**保留不动**：5 秒轮询定时器（第 440–444 行，其余 11 个接口还要）、「威胁事件」区块的三张图（第 641–667 行，数据来自 `/detector/history` 与 `/stats/overview`，不依赖 hits）、`firstLoad` 判定（第 519–528 行本就没列 `hits`，不用改）。

**加一行跳转**：「威胁事件」Section 的 `description`（或最后一张图下方）加「完整列表与处置 → 事件中心」，`<Link href="/events">`。理由：迁移后运营中心只剩图，值班从图上看到异常时的下一步动作必须有着落。

### 10.2 新增文件（Phase 3 规格）

| 文件 | 内容 |
| --- | --- |
| `ndr/frontend/app/events/page.tsx` | `PageShell title="事件中心" desc="…" width="full"` + `<EventsPanel />`（与 `app/logs/page.tsx` 同构） |
| `ndr/frontend/components/events-panel.tsx` | 本规范 §2–§8 的全部交互；命名与 `logs-panel.tsx` 对齐 |
| `ndr/frontend/lib/hits.ts` | 类型再导出（`HitEventItem` / `HitEventList` from `@/lib/api`）+ `buildQuery`（§12.1）+ 迁来的 helper（§10.1）+ `SRC` 常量（`{ list: "事件列表（/api/detector/hits）", stats: "事件概览（/api/detector/hits/stats）" }`）+ 消息文案（§6.4） |

### 10.3 明确不动的东西

- `/console` 路由（`console/page.tsx` 直接承载实现；旧地址 `/admin/status` 由 `next.config.mjs` 的 307 别名兜住，书签与文档引用仍可用）；
- `/api/detector/*` 全部契约（硬约束）；
- 运营中心的 5 秒轮询（§8.3 的不迁移只针对事件中心）；
- `CONSOLE_SHORTCUTS` **不新增**「事件中心」（§1.3：一级菜单已可达，shortcuts 保持 4 个）；
- TopBar 铃铛 notices 不改（§1.3）。

---

## 11. 可访问性与键盘

### 11.1 焦点顺序（Tab 一次走完主路径）

```
筛选控件（DOM 序：时间范围 → 关键字 → 来源 → 严重度 → 事件归类 → IP）
→ 搜索 → 重置 → 排序 → 每页 → 包含已忽略 → 刷新
→ 表格行（每行一个 tab stop，Enter/Space 开详情）
→ 上一页 → 下一页
→ （Drawer 打开）焦点入抽屉 → 关闭后归还触发行
```

### 11.2 表格语义

- `<TableHead scope="col">`：`TableHead` 透传 `ThHTMLAttributes`（`table.tsx` 第 61–64 行），页面直接传 `scope="col"` 即可，**不需要改组件**。日志页与配置页都没传——本页传，并建议回填（§13 D2 同批）。
- 行焦点与 `aria-label`：§7.2 的规格。焦点环：`focus-visible:ring-2 ring-ring/40 ring-inset`（视觉规范 9.2 改项，§7.2）。
- 「共 N 条 / 第 X / Y 页」包一层 `aria-live="polite"` 的容器：翻页后数字变了，读屏用户需要被告知。只给这一个 live 区，避免全页播报轰炸。

### 11.3 已知残余风险：行焦点的代价

`<tr tabIndex={0}>` 在部分「读屏 + 浏览器」组合里，表格模式的单元格导航优先于行焦点，可能出现「Tab 停得到行、但读屏不念 aria-label」。缓解（两道）：① 焦点环 `focus-visible:ring-2 ring-ring/40 ring-inset` 保证键盘用户至少「停得住、看得见」（视觉规范 9.2 改项）；② 行首「事件归类」单元格本身就含归类名，读屏走单元格导航也能知道这一行是什么。彻底解法是行内真 `<button>`，但与「整行可点、无操作列」的一致性裁定冲突——**记录为已知取舍，本期不破例**；若 a11y 评审要求升级，加回行尾按钮列即可，其余规范不变（§15 Q-E）。

### 11.4 颜色与对比

- 严重度徽章：`Badge variant={severityVariant(sev)}` + `severityText(sev)`——共享库唯一来源。`status-panel.tsx` 第 242–245 行的注释口径（同一条告警不能两页两个名）随迁移保留。
- 「已忽略 / 已加白」徽章：`Badge variant="outline"`（运营中心现式，第 723–731 行）——描边中性，不与严重度语义色抢。
- chip 选中态：`border-primary text-primary bg-brand-50`；未选中 `border-border-subtle text-muted-foreground`。**选中不能只靠颜色**——边框色 + 文字色 + 底色三信号，色弱用户可辨。
- `text-muted-foreground`（213 14% 40%）在 `--surface-1`（#f6f7f9）上约 7.4:1，AA 正文通过（Phase 1 已核，本页不引入新的灰阶）。
- 操作失败用 `text-sev-critical-fg` + `role="alert"`；成功用 `text-sev-ok-fg` + `role="status"`——与 `PanelError` / `Badge` 同一套语义变量，不引 Tailwind 原色。

### 11.5 动效与 `prefers-reduced-motion`

- 骨架 `animate-pulse` 已带 `motion-reduce:animate-none`（`skeleton.tsx` 第 27 行）。
- `Drawer` / `Dialog` 无位移动画（既有实现就是无 transition 的显隐）——不为本页新增滑入动画；确认 Dialog 出现不加 scale。
- 图表动效归视觉规范（Phase 1 已有 `.st-pulse` + `prefers-reduced-motion` 的先例）。

### 11.6 读屏播报清单

| 事件 | 机制 |
| --- | --- |
| 首帧加载 | 骨架自带 `aria-busy` |
| 刷新中 | 表格容器 `aria-busy="true"` |
| 查询结果数变化 | 「共 N 条 / 第 X / Y 页」容器 `aria-live="polite"` |
| 处置成功 | 页面级消息槽 `role="status"` |
| 处置失败 | Drawer 内消息槽 `role="alert"` |
| 任一接口失败 | `PanelError` `role="alert"`（既有） |

---

## 12. 任务流程图与关键代码规格

### 12.1 主任务流（一次「发现 → 筛选 → 研判 → 处置」的完整走位）

```
进入 /events
  │
  ├─ 并发：GET /hits/stats?minutes=1440   +   GET /hits?limit=50&offset=0&sort=recent
  │     （默认 24h / 不含已忽略 / 最近在前）
  │
  ├─ 首帧：概览骨架 + 表格骨架（§8.4）
  │
  ├─ 数据到达：概览三 Stat + 来源 chips + 趋势 + TOP10；表格 8 列
  │
  ├─ ① 筛选：改表单 → （离散项立即 / 文本项 Enter）→ run(0)
  │     → offset 归 0，列表 + 概览同窗口重取
  │     → 或从概览钻取：点来源 chip / TOP 规则行 → 表单同步 → run(0)
  │
  ├─ ② 翻页：上/下页 → 只重取列表（offset ±size）；禁用态见 §3.3
  │
  ├─ ③ 研判：点行 → Drawer 两段式（先用行内字段渲染 → 再取 /hits/{id} 补证据）
  │
  ├─ ④ 处置：
  │     ├─ 忽略 → 确认 Dialog → POST ignore → 关两个浮层 + 成功消息 + 全量重取
  │     └─ 加白 → 选 scope → POST whitelist → 关 Drawer + 成功消息 + 全量重取
  │           （失败：不关 Drawer，错误内联在 footer 上方——B1）
  │
  └─ ⑤ 刷新：按当前查询态重取（不清 offset/表单）+ 数据时间戳更新
```

### 12.2 查询构造（`lib/hits.ts`，Phase 3 照此实现）

```tsx
/** 命中事件查询串：与日志页 buildQuery 同构，参数集按 /api/detector/hits 契约。
 *  时间范围只有四档（Q-A 砍掉「不限」，§4.3），minutes 恒 > 0。 */
export function buildHitsQuery(form: HitForm, nextOffset: number): string {
  const params = new URLSearchParams();
  const put = (key: string, value: string) => {
    if (value.trim()) params.set(key, value.trim());
  };
  put("q", form.q);                    // 跨字段关键字（含 evidence）
  put("rule", form.rule);              // 事件归类子串
  put("ip", form.ip);                  // src_ip/client/via/dst_ips 子串
  put("source_kind", form.sourceKind); // 值 = 英文 key（feature_match/…），标签显中文
  put("severity", form.severity);      // 值 = 小写英文（后端 == 精确匹配，先 lower）
  params.set("minutes", String(form.minutes)); // 四档之一：60/360/1440/10080，恒 >0
  if (form.includeIgnored) params.set("include_ignored", "true"); // 不传 = 默认 false
  params.set("sort", form.sort);       // recent | oldest | count
  params.set("limit", String(form.size)); // 20/50/100/200，后端上限 200
  params.set("offset", String(nextOffset));
  return params.toString();
}

// 概览与列表同窗口：直接用同一个 form.minutes，不需要降级函数（「不限」档已砍，§4.3）
// GET /api/detector/hits/stats?minutes=${form.minutes}
```

### 12.3 三个必须写对的判定（代码级规格）

```tsx
// 首帧：列表与概览都未返回且无失败才算首帧；刷新时两者必有一个在，永不走骨架
const firstLoad = !list && !stats && !errs.has;

// 越界态（第五空态）：查询成功、total>0、本页空 —— 别说成「没有符合条件的事件」
const items = list?.items ?? [];
const total = list?.total ?? 0;
const outOfRange = !!list && total > 0 && items.length === 0;

// 消息槽：成功/失败同一个位置、互斥；失败 additionally 内联到 Drawer（B1）
const [msg, setMsg] = React.useState<{ kind: "ok" | "err"; text: string } | null>(null);
// 渲染：<p role={msg.kind === "ok" ? "status" : "alert"} className="text-xs …">{msg.text}</p>
```

### 12.4 与 `logs-panel.tsx` 的对应关系（Phase 3 对照着抄的部分）

| 本规范 | 日志页对应实现 |
| --- | --- |
| 筛选区三段式 | 第 244–445 行（Section + Card + 三行控件） |
| `buildQuery` / `run(nextOffset)` | 第 164–205 行 |
| 分页 extra | 第 448–472 行 |
| 首帧骨架 / 四象限 | 第 227、476–534 行 |
| Drawer 详情（title 用 span、footer、复制） | 第 541–610 行 |
| `PanelError` / `emptyOrFailed` / `usePanelErrors` | `components/panel-error.tsx` 全部 |

---

## 13. 与日志检索页的差异清单（4 处，需 team-lead 背书）

「一致性优先」是硬要求。以下 4 处事件中心**故意**与日志页不同——每一处都是日志页的 bug，事件中心按正确做法实现，并建议后续回填日志页（回填不在本任务范围）：

| # | 日志页现状 | 事件中心做法 | 为什么 |
| --- | --- | --- | --- |
| D1 | 改「每页 / 排序 / 日志类型」只改 state，**不点搜索不生效**（第 275–416 行各 `onChange` 只 `setForm`） | 离散筛选（时间范围/来源/严重度/排序/每页/包含已忽略）变更**立即 `run(0)`** | 改完「每页 100」看到的是旧 50 条内容 + 新分页器数字，用户会以为页面坏了。这是 bug 不是设计 |
| D2 | 表格行只有 `onClick`，无键盘入口（第 492–495 行）；`TableHead` 无 `scope="col"` | 行 `tabIndex + onKeyDown + aria-label`；`TableHead scope="col"` | 键盘用户打不开详情；读屏表格行列关联弱（B4） |
| D3 | 查询失败 = 页面级 PanelError + danger 空态（第 520–533 行） | **处置**失败 = Drawer 内 footer 上方内联 `role="alert"` | 查询失败与处置失败是两个时刻的事：后者用户正盯着 Drawer，页面级红字在背后看不见（B1） |
| D4 | offset 越界时显示「没有命中日志」（第 521 行，误导） | 第五空态「这一页的事件已不在当前口径内」+ 「回到第一页」 | 把越界说成「没有」，用户会去放宽筛选，而问题不在筛选（§3.3） |

> 口径声明：以上 4 处不构成「推翻一致性」——筛选区结构、控件 class、分页算法、Drawer 容器、骨架与空态组件全部与日志页同源。差异只在「变更后是否立即生效」「键盘入口」「错误位置」「越界文案」四个 bug 点上。

---

## 14. 高风险交互与降级表

| # | 风险 | 触发路径 | 设计对策（本文规格） | 实现不了时的降级 |
| --- | --- | --- | --- | --- |
| R1 | **忽略不可逆**：无取消端点，行从默认列表消失 | Drawer → 忽略 → 确认 | 确认 Dialog + 成功消息解释查回路径（§6.2/§6.4） | 按钮二次点击确认：第一次点变红字「再点一次确认」，3 秒恢复——仍保留「停一下」的摩擦 |
| R2 | **加白 scope 选宽**：`src_dst` 比 `src` 多放行一个目的 | Drawer → 选 scope → 加白 | select 旁 hint「只放行该规则的这一来源，不是全放行」+ 成功消息写明生成的条件（§6.4） | scope 默认 `src` + select 的 `title` 说明（文案不能省） |
| R3 | **概览/列表口径分裂**：stats 恒为未忽略，列表可含已忽略 | 勾选「包含已忽略」 | 双标注：概览 Stat hint「不含已忽略」+ 列表「共 N 条（含已忽略）」（§2.4） | 无降级——这是文案，必须做 |
| R4 | **「不限」时 stats 静默变 24h**（`max(1, minutes or 1440)`） | 选「不限」 | §4.3：方案甲显式声明 / 方案乙砍档 | 直接砍「不限」（Q-A 裁决为乙时） |
| R5 | **offset 越界**：翻页后事件被处置掉 | 翻到第 N 页 → 忽略 → 刷新 | 第五空态 + 「回到第一页」（§3.3） | 空态 hint 里写「可能已被忽略或清理，点搜索重查」 |
| R6 | **写操作 404**：事件在另一标签页已被处理 | two-tab 并发处置 | 不关 Drawer + 内联错误 + 重取列表让列表说真话（§6.3 S4b/S7b） | 错误消息 + 关 Drawer + 重取（行没了用户能看见） |
| R7 | 刷新连点 | 快速点刷新 | busy 禁用 + `aria-busy`（§8.2） | 无 |
| R8 | 首帧 12 个骨架被当成「页面坏了」 | 慢网络首屏 | 骨架与真实结构同形（§8.4）+ `firstLoad` 单一定义 | 无 |
| R9 | 深翻页后改每页 | offset=100 → 每页 200 | size 变更归 0 + 立即重查（§3.2） | 无 |
| R10 | 「详情」两段式期间用户看到半份数据 | 点行 → 详情接口在飞 | 先渲染行内字段 + 证据区骨架 + `aria-busy`（§7.3） | 只画骨架（放弃「不空白等待」） |

---

## 15. 需主理人裁决的问题

**Q-A 「不限」时间档何去何从**（§4.3）。我的建议：**砍掉**，最大 7d。stats 契约表达不了「不限」（`minutes=0` 静默变 1440），列表与概览同源同窗口是事件中心可信度的底线；方案甲（保留 + 概览显式声明）也能用，但把一个契约缺陷永久留在 UI 里。若裁「砍」，§2.1/§4.1 的表格删一行即可，其余不动。

**Q-B §13 的 4 处差异是否背书**。尤其 D1：它改变了「一致性优先」的字面执行（离散筛选立即重查 vs 日志页的显式提交）。我的立场：这 4 处都是修日志页的 bug，事件中心先做对；是否回填日志页由你定。

**Q-C 忽略必须过确认 Dialog**（§6.2）。运营中心没有确认；这是新增的一道步骤，与值班速度有真实冲突。我的立场：忽略不可逆（无取消端点），这道摩擦必须保留；白名单不确认（可撤）。

**Q-D 概览区范围**（§5）：3 Stat + 来源 chips + 趋势图 + TOP10。stats 契约给的数据就这些，我没有造数；若视觉规范对首页密度另有裁断，以视觉为准，UX 只坚持两件：口径标注（§2.4）与联动（§4.2）。

**Q-E 行尾是否保留「详情」按钮**（§7.2/§11.3）。我的裁定：不保留，靠行 `tabIndex + aria-label`。若 a11y 评审认为 `<tr tabindex>` 不够，加回按钮列（其余规范不变）。

---

## 16. 验收清单（Phase 3 前端落地对照）

### 16.1 查询与筛选

- [ ] 六维度全部接通，参数名/取值与 `buildHitsQuery` 一致（`source_kind`/`severity` 用英文小写值）
- [ ] 「不限」不传 `minutes`；stats 按 `statsMinutes()` 降级且 UI 有声明（或已按 Q-A 砍档）
- [ ] 离散筛选变更立即 `run(0)`；文本筛选 Enter/按钮提交；offset 归 0
- [ ] 重置回默认值（24h / recent / 不含已忽略 / 50 条）并立即重查
- [ ] 来源 chip 与 TOP 规则行点击钻取，表单同步可见；再点同一 chip 取消
- [ ] 筛选控件 class 与日志页逐字一致；不使用 `Field`/`FieldGrid`

### 16.2 分页

- [ ] 每页 20/50/100/200，默认 50；limit 不超过 200
- [ ] 上/下一页禁用态正确（`offset<=0` / `offset+size>=total`）
- [ ] 「第 X / Y 页」算法与日志页一致
- [ ] 越界时有第五空态，不说「没有符合条件的事件」

### 16.3 概览联动

- [ ] stats 与列表同 `minutes`；改时间范围两者同刷
- [ ] Stat 三格数值正确（`total` / `high+critical` / `ignored`），hint 口径常在
- [ ] 「包含已忽略」勾选时列表「共 N 条（含已忽略）」；概览 `total` 不变且 hint 仍写「不含已忽略」
- [ ] 趋势图按 `bucket_seconds` 补零；X 轴北京时间；桶大小不自己算
- [ ] stats 失败时 Stat 显示「—」不画 0

### 16.4 处置

- [ ] 忽略走确认 Dialog；确认期间所有相关按钮 disabled + `aria-busy`
- [ ] 成功后：关两个浮层 + 页面级 `role="status"` 消息（含查回路径）+ 重取列表与 stats
- [ ] 失败时：Drawer 不关，错误内联在 footer 上方 `role="alert"`；400/404/409/5xx 文案分流
- [ ] 加白成功后消息含白名单名、生成条件、「配置管理 → 过滤规则 可停用/删除」
- [ ] `scope` 默认 `src`；hint 写明「只放行该规则的这一来源」
- [ ] 无批量操作入口（契约没有批量端点）

### 16.5 详情

- [ ] Drawer `w-[560px] max-w-[94vw]`；title 用 span（主标题归类 + 副标题 mono ID + 来源）
- [ ] 两段式：行内字段先渲染 → `/hits/{id}` 补证据；证据区有 loading 骨架 + `aria-busy`
- [ ] 字段网格含运营中心全部字段与两个特殊分支（suricata 连接状态、xff 请求方）
- [ ] `FIELD_LABELS`/`HIDDEN_FIELDS`/`fieldLabel`/`eventTime` 原样迁移到 `lib/hits.ts`
- [ ] 处置成功后焦点落列表容器（不回页面顶部）

### 16.6 三态与刷新

- [ ] 四象限判定顺序与 §8.1 一致（firstLoad → 失败 → 越界 → 真无）
- [ ] 无 5 秒轮询；有刷新按钮 + 数据时间戳（`formatClock`）
- [ ] 刷新保留旧数据 + 按钮 loading + `aria-busy`；不清 offset/表单

### 16.7 响应式

- [ ] `PageShell width="full"`，无侧边栏
- [ ] 列可见性三档（≥1024 全列 / 768–1023 藏 ID+来源 / <768 再藏目的），全部 `sr-only` 不用 `hidden`；**隐藏类 th 与 td 同时写**（只藏 td 会剩一列有头无数据——§9.2）
- [ ] 筛选网格 `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4`；Stat `sm:grid-cols-3`；趋势+TOP `lg:grid-cols-3`
- [ ] 事件归类/请求方/目的三列 `<td>` 带 `min-w-0`（缺它 `max-w`/`truncate` 不生效，长内容会把列顶宽——§9.3）

### 16.8 可访问性

- [ ] `TableHead scope="col"`；行 `tabIndex + onKeyDown(Enter/Space) + aria-label`；行焦点环 `focus-visible:ring-2 ring-ring/40 ring-inset`（§7.2/视觉规范 9.2）
- [ ] TOP 10 行用原生 `<button>`（键盘与焦点环免费获得，§5.3）
- [ ] 分页信息容器 `aria-live="polite"`；成功 `role="status"` / 失败 `role="alert"`
- [ ] 骨架 `aria-busy`；无新增 Tailwind 原色；对比度沿用 Phase 1 token
- [ ] 键盘全主路径可达（§11.1 顺序）

### 16.9 迁移

- [ ] `status-panel.tsx` 删除项精确到 §10.1 表格；helper 搬到 `lib/hits.ts` 而非重写
- [ ] 运营中心「威胁事件」区块保留三张图 + 新增「完整列表与处置 → 事件中心」链接
- [ ] `nav-config.ts` 插入 events section（§1.1）；不改 `sectionOf`/`sidebarOf`/`sectionActive`
- [ ] `/console` 路由与 `/admin/status` 307 别名、`/api/detector/*` 契约、运营中心 5 秒轮询均不动

### 16.10 建议回填（不在本任务范围，记录备查）

- [ ] 日志页 D1/D2/D4 三处（§13）——与 fe-engineer 确认后排期

---

*本文与 `config-layout-ux-spec.md` 同源纪律：状态显式化、空态三态分治、失败不说成「没有」、写操作不乐观。事件中心新增的两条专有纪律：**口径必须标注**（stats 与列表的 include_ignored 分裂）与**不可逆操作必须停一下**（忽略无取消端点）。*




