# Phase 1 · 视觉设计规范：派工队列（/api/analysis）+ 精准抑制（/api/suppressions）

> 来源：design-architect-2（Phase 1 视觉方向）。由 team-lead 落盘，供 ux-designer（Phase 2）与 fe-engineer（Phase 3）沿用。
> **口径：以源码为准，不以旧文档为准。** 本文所有 token / 类名 / 字段名 / 默认值均已逐一核对 `globals.css`、`tailwind.config.ts` 与后端源码（清单见 §0），与代码冲突时改本文、不改代码。

---

## 0. 实际读过的文件（结论依据）

**视觉语言**
- `ndr/frontend/app/globals.css`（设计语言「钢蓝仪表台」全部 token）
- `ndr/frontend/tailwind.config.ts`（token→类名映射、`text-13`/`text-28`、`shadow-1..3`）
- `packages/ui/src/components/ui/{section,settings-board,settings-grid,stat,badge,table,empty-state,pagination,panel-toolbar,drawer,dialog,button,field,skeleton,switch}.tsx`
- `packages/ui/src/lib/format.ts`（北京时间、severityText/statusText）
- `ndr/frontend/components/page-shell.tsx`（三档宽度；**h1 已 sr-only**，页面不再显示标题段落）
- `ndr/frontend/lib/nav-config.ts`

**既有页面（版式先例）**（下列路径已于 2026-10 从 `app/admin/*` 整体搬到新地址，`app/admin/` 目录已删除）
- `app/config/rules/page.tsx`（Section + 卡片内工具栏 + 树 + 抽屉表单 + Dialog 删除确认）
- `app/behavior/page.tsx` + `components/behavior-panel.tsx`（**最贴近本次**：多 Section + Stat 行 + 表 + 参数 Drawer w-[720px] + `overridden` 标记 + `field_errors`）
- `app/config/health/page.tsx`（Stat 行 + SettingsGrid 主列/侧列 + 三态写法；原 `app/admin/config`）
- `app/config/filters/page.tsx`、`components/ingest-filters-panel.tsx`（SettingsBoard/SettingsBlock + 条件树 + **试运行结果块**）
- `components/exclusions-panel.tsx`（同一族过滤器的列表/统计写法）
- `components/condition-editor.tsx`（`ConditionEditor`、`condsToRules`、`conditionsToConds`、`EMPTY_COND`，并**导出 `SELECT_CLS`（:37）**，`rules/page.tsx:33` 已在用）

**后端契约（字段与状态取真实实现）**
- `ndr/backend/app/api/routes/analysis.py`（`/tasks` `/tasks/{id}` `/results` `/stats` `/coverage` `/inventory` `POST /tasks` `/config`）
- `ndr/backend/app/analysis/{queue,params,subjects,verdicts}.py`
- `ndr/backend/app/api/routes/suppressions.py`（`GET /` `/preview` `POST /` `PUT /{id}` `/{id}/revoke` `/{id}/restore` `/config`）
- `ndr/backend/app/detector/suppression.py`、`ndr/backend/app/db/models.py`

> 注：`docs/api/README.md` 尚未包含这两节（自动生成早于这两个路由），且其中「四元含 payload」「counters 含 doorbell_*」两处与代码不符——**一律以代码为准**。

---

## 1. 视觉方向与原则（5 条）

一句话方向：**「数据是冷的，判断是热的」** —— 客观线索/覆盖率/影响面一律中性色 + 等宽数字；只有「判定」(verdict) 与「代价」(mode/卡住/超容量) 才允许上语义色。整页彩色元素 ≤ 5 处。

1. **强度即秩序**：队列顺序、首列位置、数字字重全部由 `strength` 驱动；**不做「按严重度上色」的列表**（新页面没有 severity 概念）。
2. **提示与结论分家**：`hint`（客观线索）用中性 KV + mono；`verdict`（结论）才用 sev-* 徽章。
3. **抑制的「狠」必须看得见**：mode 用「颜色 + 图标 + 长文案(4-6字) + 整带底色」四重编码；且 **mode 不可手选**，只能由试算给出 —— 表单里出现 mode 单选就是设计错误。
4. **风险用「压力」表达**：容量/预算/覆盖率用 3 条 6px 进度条 + 数字，不靠堆红点。
5. **只读在右、可改在左**（沿用 SettingsGrid 约定）；每行状态徽章 ≤ 2 个。

---

## 2. 色板与状态语义（**0 新增变量**，全部复用现有 token）

### 2.1 基础面（globals.css 已有，不要硬编码 hex）

| 用途 | CSS 变量 | 值 | Tailwind 类 |
|---|---|---|---|
| 页面底 L0 | `--canvas` | hsl(210 24% 94%) ≈ `#ecf0f3` | `bg-background` |
| 内联格/表头 L1 | `--surface-1` | hsl(210 22% 97%) ≈ `#f5f7f9` | `bg-surface-1` |
| 卡片 L2 | `--surface-2` | `#ffffff` | `bg-card` |
| 主文字 | `--foreground` | hsl(214 32% 13%) ≈ `#17202c` | `text-foreground` |
| 二级文字 | `--muted-foreground` | hsl(213 16% 32%) | `text-muted-foreground` |
| 容器描边 | `--border` | hsl(213 22% 84%) ≈ `#cdd5df` | `border-border` |
| 行分隔 | `--border-subtle` | hsl(213 18% 90%) | `border-border-subtle` |
| 品牌（**只表示可操作/选中/焦点**） | `--primary` | hsl(214 76% 32%) = `#144990` | `bg-primary` |
| 行 hover | `--brand-50` | hsl(214 90% 96%) | `bg-brand-50` |

语义色六档（底/字/边三件套，AA 已校）：

| 档 | 底 | 字 | 边 | Badge variant |
|---|---|---|---|---|
| 严重 | `--sev-critical-bg` ≈`#fdf1f2` | `--sev-critical-fg` ≈`#c2243a` | `--sev-critical-bd` | `critical` |
| 高危 | `--sev-high-bg` ≈`#fef5eb` | `--sev-high-fg` ≈`#a85000` | `--sev-high-bd` | `high` |
| 中危 | `--sev-medium-bg` ≈`#fcf6dc` | `--sev-medium-fg` ≈`#8a6903` | `--sev-medium-bd` | `medium` |
| 低危 | `--sev-low-bg` ≈`#edf1ff` | `--sev-low-fg` ≈`#2b4ff0` | `--sev-low-bd` | `low` |
| 信息 | `--sev-info-bg` ≈`#f2f4f7` | `--sev-info-fg` ≈`#525f70` | `--sev-info-bd` | `info` |
| 正常 | `--sev-ok-bg` ≈`#e7f7f0` | `--sev-ok-fg` ≈`#06694a` | `--sev-ok-bd` | `success` |

> **铁律**：`primary` 不用于状态；`success` 只给 ok，不给「低危」。

### 2.2 队列状态（后端 state 真实取值只有 6 个：`pending / claimed / deferred / done / stuck / expired`）

| state | 中文 | variant | 图标(lucide) | 理由 |
|---|---|---|---|---|
| `pending` | 待派 | `info` | `Clock` | 量大、不需人动手 → 最安静 |
| `claimed` | 已派·在跑 | `low` | `Loader2`（不加动画） | 「有智能体在处理」，蓝=进行中 |
| `done` | 已完成 | `success` | `Check` | — |
| `deferred` | 已推迟 | `medium` | `PauseCircle` | 被主动延后 → 需关注 |
| `stuck` | 卡住 | `high` | `AlertTriangle` | 租约反复过期/不交回，**必须人工介入** |
| `expired` | 已过期 | `outline` + `text-muted-foreground` | `CalendarX` | 死状态，不抢色 |

- **排序事实**：`/tasks` 无 `sort` 参数，后端固定 `ORDER BY priority DESC, created_at DESC`，而 `priority = round(strength * 100)`（`queue.py:138/174`）。所以「按强度降序」= 后端已排好，**前端不要做客户端二次排序**，也不要自己造「按时间排」下拉。
- **`state` 是精确单值、不支持多选**；`state=""` 会把历史 `done` 按 priority 混排进来（会淹没待派）。→ **默认筛 `pending`**，提供「全部 / 单状态」切换，不提供多选复选。
- 「超容量」**不是 state**（见 §8 坑 4）：只体现为 `expired` 行第二行小字「被更强线索挤掉」+ 计数器 `superseded` / `dropped_overflow`。**不要造第七种徽章**，用「容量压力条」表达。

### 2.3 verdict（结论，真实取值见 `verdicts.py:18`）

| verdict | 中文 | variant | 理由 |
|---|---|---|---|
| `true_positive` | 确认攻击 | `critical` | 唯一「真出事」 |
| `suspicious` | 可疑 | `medium` | — |
| `benign` | 正常 | `success` | — |
| `false_positive` | 误报 | `secondary` | 与 behavior 处置记录口径一致 |
| `inconclusive` | 不确定 | `info` | 灰蓝，与误报的扁灰可区分 |

> `pending` / `done` 是**任务状态**，不是 verdict（`STATUS_VALUES = VERDICT_VALUES + (pending, done)`），不要混进结划分段。

### 2.4 抑制 mode（**全页最重要的一处强区分**）

| mode | 列表徽章（本地短词） | variant | 图标 | 结构编码 |
|---|---|---|---|---|
| `suppress` | **完全抑制 · 不生成事件** | `critical` | `Ban` | 徽章 + 抽屉内整带 `bg-sev-critical-bg` + 左 3px `bg-sev-critical-fg` 实心条 |
| `record_only` | **仅记录 · 事件仍生成** | `medium` | `BellOff` | 徽章 + 整带 `bg-sev-medium-bg` + 左 3px `bg-sev-medium-fg` 实心条 |

- **徽章文案必须用前端本地 map**（`suppress → 完全抑制`、`record_only → 仅记录`）。后端 `mode_label` 的原值只有两句、且长：`完全不生成事件`（9 字） / `只不派工（事件保留）`（11 字），塞进 `w-44` 列会换行破版；`mode_label` **只进抽屉正文与 tooltip**。
- 抽屉内两行副文案（前端自己写，不是接口值）：`完全抑制` → 「不再派工、不再推送，这条流量从系统里消失（原始数据仍在 ES）」；`仅记录` → 「事件仍生成，只是不派工、不推送；影响面过大时的降级档」。
- 理由：`suppress` 让事件从系统里消失（只能回 ES 原始数据回溯），代价最高→红；`record_only` 是降级档（事件还在），不是错误→金。
- **禁止**：两个 mode 同色不同文案；`suppress` 用绿/蓝；mode 做成行内小字或 tooltip；`suppress`/`record_only` 直接显示英文枚举。

### 2.5 抑制状态（3 档，优先级：已撤销 > 已过期 > 生效中）

| 判定顺序 | 徽章 | variant | 第二行小字（成因，12px） | 字色 |
|---|---|---|---|---|
| 1 | 已撤销 | `secondary`（留档、不生效） | `被真实事件推翻（{kind} 判为真阳性），自动失效` | `text-sev-critical-fg` |
| 1 | 已撤销 | `secondary` | `熔断：累计抑制 {hits} 条事件，超过上限 {hit_cap}`（默认 20000） | `text-sev-high-fg` |
| 1 | 已撤销 | `secondary` | 人工撤销原因原文 / `超出活跃上限 {max_active}，按最早到期淘汰` | `text-muted-foreground` |
| 2 | 已过期 | `outline` + muted 字 | `{expires_at}` 已过 | `text-muted-foreground` |
| 3 | 生效中 | `success` | —（正常不写第二行） | — |

- **成因四种**（`revoke_reason` 只有这四类）：① 人工撤销（`RevokeIn.reason`，≤200 字）；② 超上限淘汰（`create_item` 满 `max_active` 时按最早到期淘汰）；③ 熔断（`hits > hit_cap`，**严格大于**）；④ 被真实事件推翻（智能体判 `true_positive` 时自动撤销覆盖它的抑制）。
- **不做**「近 7 天被推翻 N 条」这类顶部汇总：`/stats` 不分成因，前端只能统计当前页 = 假口径。
- 剩余 ≤ 3 天：**不加第三枚徽章**，在「到期」列用 `text-sev-medium-fg` 写「剩 2 天」。
- 命中数列**不标「实时」**：`hits` 是内存攒批、每 30 秒 flush 一次（`flush_hits`），表头 title 写「约 30 秒内更新」。
- 「体积/幅度」类强调（命中数接近 `hit_cap` 的 80%）**只做单元格字色加重，不新增状态**。

---

## 3. 字号阶梯 / 间距 / 栅格

| 层级 | 字号/行高 | 类 | 用在 |
|---|---|---|---|
| 主 KPI | 28/34，`-0.01em`，tabular | `text-28` | 队列/覆盖率主数字 |
| 次指标 | 20/28 | `text-xl` | Stat size="md" |
| 分区标题 L1 | 16/24 + 3px `bg-primary` 竖条 | `text-base`（`Section`） | 全页分区 |
| 卡片/板内分区 L2 | 13/20 + 竖条 | `text-13`（`SettingsBlock`） | 抽屉内分组 |
| 正文/表格 | 13/20 | `text-13` | 表格、表单值 |
| 标签/说明/表头 | 12/16 | `text-xs` | Stat label、hint、Badge 内 |
| IP/ID/JSON | 12/16 mono | `font-mono text-xs` | subject、evidence_refs、match JSON |

- 行高：表头 `h-8`(32px)，数据行 `py-2`+20 = 36px；Section 间距 `space-y-4`，块内 `space-y-3`；卡片内边距 `px-3 py-2`（表格）/`px-4 py-3`（SettingsBlock）。
- 栅格：`SettingsGrid` = `grid xl:grid-cols-[minmax(0,1fr)_19rem] gap-4`（**不要改这个模板**）。页宽：两页都 `PageShell width="wide"`。

---

## 4. 页面 A：派工队列 `/analysis`

### 4.1 布局（**单页 + 抽屉，无侧边栏**）

```
PageShell width="wide"（h1 sr-only = 派工队列）
┌─ PanelError ─────────────────────────────────────────────────┐
├─ Section ①「队列总览」
│  Stat × 6（grid-cols-2 lg:grid-cols-3 xl:grid-cols-6）
│   待派 / 已派在跑 / 卡住 / 已过期 / 累计结论 / 覆盖率
│  第二行： [容量压力条 240px] 待派+推迟 1834/2000 │ [预算徽章组] [队列已启用] [参数…]
├─ Section ②「任务队列」（主体，全幅 Card）
│  Card > PanelToolbar(搜索 | 状态分段[默认待派] | 类型 select | 自动刷新 | 刷新 | ＋人工派工)
│        > Table（8 列，后端按 strength 降序，整行可点）
│        > Pagination（共 N 条 · 每页 20/50/100）
├─ Section ③「任务结论」（全幅 Card）
│  toolbar（结论分段 | 对象精确筛 | 只看某任务）+ Table + Pagination
├─ Section ④「覆盖率与盲区」（Stat 行 + SettingsGrid）
│  Stat × 4（对象总数 / 已分析 / 覆盖率 / 盲区 n）
│  SettingsMain: 盲区清单 Table（从未分析 / 久未分析）
│  SettingsRail: 只读卡「验收口径」
├─ Section ⑤「对象清单（数据地图）」（全幅，低频）
│  类型切换（Button 组，非 Tabs）+ Table（5 列）
└──────────────────────────────────────────────────────────────┘
   Drawer「任务详情」720px  ← 点行/点「查看」
   Drawer「派工参数」720px  ← 点「参数…」
   Dialog「人工派工」560px  ← 点「＋人工派工」
```

- **为什么单页不拆 5 个子路由**：队列页是「盯屏 + 偶尔深挖」，拆开会让「队列」与「验收指标」分离。演进路径：结论量 > 5k 再拆 `/analysis/results`。
- **不做侧边栏**（设计 / 体验 / 前端三方一致，已冻结）：单页 + 3 个浮层（详情 / 参数 / 人工派工），与 `/behavior` 同构。
- **主列 vs 侧列**：只有 ④ 用双列（主列=盲区表，侧列=只读口径说明）；①②③⑤ 全幅（宽表塞进 19rem 会变竖排省略号，`SettingsRail` 白名单也禁止列数>3）。

### 4.2 关键组件与视觉权重

- **指标卡（Stat，不描边、只有 `bg-surface-1`）**：`tone` 只用三处——卡住→`medium`、覆盖率<阈值→`medium`、其余 `default`。**没读到数据显示 `—` 而非 `0`**。
- **容量压力条**（全页唯一自绘图元，6px 高，`rounded-full`）：
  `track = bg-border-subtle`，`fill` 按 `(pending+deferred)/queue_policy.queue_capacity`：<80% `bg-primary`；80–99% `bg-sev-medium-fg`；≥100% `bg-sev-critical-fg` + 右侧 `text-sev-critical-fg` 写「已满，新线索会被丢弃（dropped_overflow）」。旁永远带 `tabular-nums` 的「1834 / 2000」。
- **容量与丢线索的唯一落点**：压力条 + `counters.dropped_overflow` / `counters.superseded` 两个数字（12px，`text-muted-foreground`，在压力条右侧竖排两行，title 解释）。**不要**把它们做成 Stat 卡（会发生「6 张卡里 2 张永远 0」）。
- **`counters` 是 Redis 哈希、可能整体为空对象**（`read_stats` 在 `client is None` 或异常时返回 `{}`）→ counters 区整块显示 `—`，不要渲染一排 0。
- **`counters` 只有这些键**：`enqueued / merged / superseded / dropped_overflow / expired / reclaimed / stuck / claimed / deferred / done / followup_accepted / candidate_error / suppression_rebound`。**没有 `doorbell_*`**（README 写错）→ 门铃状态只能从 `budget` 与参数抽屉读，不在总览放「门铃冷却剩余」。
- **表格**：用共享 `Table`（全边框、表头 `bg-surface-1` + `text-foreground`）。整行可点需 `tabIndex={0}` + `focus-visible` 环（`TableRow` 已内置），且必须落在白底 `Card` 上。
- **抽屉**：任务详情（长 hint + 历史结论）、参数（23 knob）。**不用表格内联展开**。
- **对话框**：人工派工（5 字段、可连续派下一个）、撤销抑制（不可逆 + 原因）。

### 4.3 任务队列表：列与优先级

| # | 列 | 宽 | 内容 | 理由 |
|---|---|---|---|---|
| 1 | **强度** | `w-16` | `0.842` tabular，右侧 12px muted 显示 `priority`（可选） | 客观强度唯一数值，放首列；排序由后端 `priority` 决定，列头**不做**可点排序 |
| 2 | **对象** | `min-w-0` | `subject`(13 medium) + `subject_kind` 小徽章（`asset/port/peer/protocol/signature/account`） | 识别锚点 |
| 3 | 类型 | `w-24` | kind 中文：新现象/漂移/结构/覆盖/命中（`outline`） | — |
| 4 | **状态** | `w-24` | §2.2 徽章（**全表唯一彩色列**）；`expired` 行下方 12px muted 写「被更强线索挤掉」 | 唯一需颜色扫描的维度 |
| 5 | 线索摘要 | `min-w-0` | 从 `hint` 抽一条最能区分的，`truncate`+`title` 全文 | 全量在抽屉 |
| 6 | 合并/尝试 | `w-20` | `coalesced / attempts`（如 `7/2`），title 解释 | 「同现象反复 7 次」 |
| 7 | 时效 | `w-32` | `formatDateTime(created_at)` + 「剩 42h」（按 `queue_policy.pending_ttl_hours` 推算，<6h 用 `text-sev-medium-fg`） | 过期要能提前看到 |
| 8 | 详情 | `w-12` | ghost 图标按钮，aria-label 带对象名 | 键盘真焦点目标 |

**明确不做**：不提供「领取」按钮、不做「派工给我」、不做批量状态变更（领取/交回/延后是智能体 MCP 通道职责，界面不绕过领取流程）；不做「结束原因 note」列（接口不返回，见 §4.6）。

### 4.4 结论列表（③）列

`结论(badge)` → `对象` → `类型` → `置信度(0.82 tabular)` → `摘要(truncate+title)` → `工具·耗时（4 工具 · 12.4s）` → `交回（claimed_by，mono 12）` → `时间` → `关联任务（"查看"打开任务详情抽屉）`。

- 筛选只有三个：**结论分段(verdict) + 对象精确输入(subject) + 任务 ID(`task_id`)**。**不要放关键词搜索框**（`/api/analysis/results` 只接受 `task_id/subject/verdict/limit/offset`，无 `q`，见坑 6）。
- `subject` 是**精确匹配**（`==`，非 ILIKE）→ 输入框 label 必须写「对象（精确）」，占位符给一个完整示例（`10.1.2.3`），不要写「搜索」。
- 后端固定 `created_at DESC`，无排序参数。

### 4.5 覆盖率与盲区（④）

- Stat × 4：`subjects_total` / `analyzed` / `coverage_ratio（×100，1 位小数）` / 盲区 `never_analyzed + stale`，hint 写口径「近 N 天 · 只看 last_seen 在窗口内的对象」。
- 盲区表列：`对象类型` → `对象(mono)` → `原因`（`从未分析`=`medium`；`久未分析`=`outline`）→ `首见` → `最近出现` → `出现次数` → `已分析次数` → `最近分析`。
- 工具条：`days` 分段(7/14/30) + `kind` select + 刷新。**天数切换要重取**（`/coverage?days=`）。
- **接口三个坑（照着写，别照直觉）**：
  1. `items[].kind` 被后端硬编码成 `"asset"`（`subjects.py:194`），真实类型在 `items[].subject_kind` → **列渲染一律用 `subject_kind`**，`kind` 不要用。
  2. `returned` 是「切片前长度」（`len(never)+len(stale)`，最多 2×cap），而 `items` 被 `items[:cap]` 截断 → 渲染条数用 `items.length`，`returned` 只在调试时看。
  3. `never_analyzed` / `stale` 都是**被 `cap` 截断后的条数**，且 `items` 是 `never` 在前、`stale` 在后再切前 `cap` 条 → 盲区表里 stale 行可能一条都看不见。→ 盲区表上方必须给「从未分析 / 久未分析」两个筛选项（对应 `items[].why`），并在 Stat 的 hint 里注明「计数为截断值，明细以筛选后为准」。
- `items[].why` 只有两个值：`从未分析` / `久未分析`，直接当文案用，不要自己按时间重算。
- 「从未分析」用 `medium` 不用红：欠账不是事故（红留给 stuck/超容量）。

### 4.6 任务详情抽屉（720px）

顺序（只读事实，`Section divided={false}` 分组，**不套 Card**）：
1. 头部：`subject` 大字 + `state` 徽章 + `strength` + `kind`；
2. 「时间窗」：`window_start → window_end`、`created_at`、`coalesced`、`attempts`、`depth`、`parent_id`（可点回父任务）；
3. 「线索（hint 全量）」：KV 两列只读，`suggested_tools` 渲染 `outline` 徽章组；未知键走 `max-h-56 overflow-auto` 的 `<pre>`（mono 12，`tabIndex={0}`）；
4. 「该任务的历史结论（≤10）」：每条 `verdict` 徽章 + `confidence` + `claimed_by` + 时间 + `summary`（两行 clamp）；
5. footer 两个：`关闭`(outline)、`在结论页查看该任务`(ghost 链接)。

- **`_task_dict` 不返回 `note` 与 `claimed_by`**（`queue.py:553`）→ 详情里**没有**「结束原因 / 交回给谁」区块，也不要写「为什么 expired/deferred」的解释块；状态与时间就是全部表达。历史结论里的 `claimed_by` 来自 `results[]`，可以显示（那是另一张表）。
- 详情不存在时后端**返回 HTTP 200 + `{error:"任务不存在"}`** → 必须判 `data.error` 走 danger 态，不能当空任务渲染。
- `lease_until` 只在 `claimed=True` 时才有值（详情给空串）→ 无值时整行不渲染。

### 4.7 派工参数抽屉（18 knob，分 5 组）

复用 behavior-panel 的参数渲染模式（draft / `已改`·`默认`·`未保存` 三徽章 / 范围与默认值说明 / 逐字段 `field_errors` / 单键与全部恢复默认）。按 `analysis.*` 前缀分组，**共 18 项**（`params.py`）：

| 组 | 键 | 项 |
|---|---|---|
| 开关与线索 | `enabled`、`candidate_kinds` | 2 |
| 租约与卡住 | `lease_seconds`、`stuck_after_attempts`、`followup_depth`、`followup_max_per_task` | 4 |
| 容量与时效 | `queue_capacity`、`pending_ttl_hours`、`dedupe_bucket_minutes`、`flush_seconds` | 4 |
| 门铃 | `doorbell_enabled`、`doorbell_cooldown_seconds` | 2 |
| 覆盖率与反馈 | `coverage_stale_days`、`subject_retention_days`、`feedback_enabled`、`feedback_days`、`fp_decay_days`、`feedback_tp_factor` | 6 |

- **当前值的取法（最容易错的一处）**：`/config` 的 `items[]` 只有 `{key,label,kind,default,low,high,unit,note,overridden}`，**没有 `value`**；当前生效值在**顶层** `effective[item.key]`。渲染式：`const value = effective[item.key] ?? item.default;`。→ 新建 `KnobItem` 类型，**不要复用 `BaselineConfigItem`**，也**不要照抄 `behavior-panel.tsx:1150` 的 `item.value`**（那会让整列渲染成 `undefined`）。
- **控件按 `kind` 分支，只有 4 种**：`bool` → `Switch size="sm"`（`checked/onCheckedChange/label` 三个 props，**不接受 children**）；`int`/`float` → `Input type="number"`（`step` 由 `kind` 决定：int 用 `1`，float 用 `0.01`），右侧 12px muted 显示 `unit`，下方 12px muted 写「默认 {default} · 范围 {low}–{high}」；`text` → **只有 `candidate_kinds` 一个**，用 checkbox 组，其余 text 走 `Input` + `font-mono`。**没有 `regex` 这个 kind**（照抄 behavior-panel 的 `item.kind === "regex"` 分支永远不会命中）。
- **`candidate_kinds` 专属交互**：5 个 checkbox（`novelty/shift/structure/coverage/hit`，默认值 `"novelty,shift,coverage,hit"`，structure 默认关），**不让人手敲逗号串**；提交前拼成逗号串。**5 个全不勾时不要灰掉保存按钮**，点击时拦下并提示：「至少保留 1 类线索。要整体停掉派工，请关『启用派工队列』」——因为该键是 `text` 型，空串会被后端 400「不能为空」。
- **`queue_capacity` 的说明文案**必须写「只影响后续入队，已入队任务不受影响」（`note` 原文）。
- 生效文案：**「改完 30 秒内生效」**（`analysis.py:33` HINT 原文），不要写「立即」。
- `field_errors` 的 `field` 就是裸键名（`analysis.enabled` 这种全名，不是去前缀的短名）→ 回填时**不要** strip 前缀。
- 重启入口：抽屉 footer 左「全部恢复默认」（`POST /config/reset` 空 `keys`），右「取消 / 保存」；保存成功不关抽屉，就地刷新 `effective` 与三徽章。

### 4.8 人工派工对话框（560px）

- 字段 5 个：`subject_kind`（select，默认 `asset`）、`subject`（必填，≤128）、`kind`（select，默认 `hit`）、`strength`（number，默认 `0.6`，0–1，step 0.01）、`note`（textarea，≤500）。
- 前端 clamp：`subject` 必填（空则不发请求，后端也 400）、`strength` 0–1、`note` ≤500。
- **返回值是 `{ok, result, subject}`，`result` 有 6 种**（`queue.py:846`），每种给不同提示（`ok` 仅 `new`/`merged` 为 true）：

| `result` | 提示 | 语义 |
|---|---|---|
| `new` | 已入队：{subject} | 新建成功 |
| `merged` | 已并入同族线索（同现象已存在，计数 +1） | 去重命中 |
| `superseded` | 已入队，并顶掉了一条更弱的待派线索 | 队列满但够强 |
| `dropped` | 队列已满且该线索强度不足，未入队 | 队列满且不够强 |
| `skipped` | 未入队：派工队列已关闭，或该线索类型未开启 | `enabled=false` 或 kind 不在 `candidate_kinds` |
| `error` | 生成线索失败（详见服务端日志） | 异常 |

- `ok=false` 的三种（`dropped`/`skipped`/`error`）用 `text-sev-medium-fg` 提示且**不关对话框**（让用户改强度/换类型再试）；`new`/`merged`/`superseded` 用 `text-sev-ok-fg`，并提供「继续派下一个」（清空 subject/note，保留 kind/strength）。
- **`note` 不会被原样存储**：后端拼成 `{备注}（by {username}）` 塞进 `hint.备注`。→ 不要在界面上承诺「备注会原样展示给智能体」；hint 里本来就带 `事实: 人工派工` 与 `客观强度`。

---

## 5. 页面 B：精准抑制 `/config/suppressions`

### 5.1 布局（**SettingsBoard 三块 + 列表主体 + 抽屉表单**）

```
PageShell width="wide"（h1 = 精准抑制）
┌─ PanelError ─────────────────────────────────────────────────┐
├─ SettingsBoard
│ ① SettingsBlock「抑制总览」
│    Stat × 4（生效中 / 仅记录中 / 累计命中 / 条目总数）
│    下方：两列对照（核心认知）
│    ┌ 完全抑制 suppress ─────────┬ 仅记录 record_only ────────┐│
│    │[Ban] 事件不再生成          │[BellOff] 事件仍生成         ││
│    │不再派工、不再推送          │只是不派工、不推送           ││
│    │= 这条流量从系统里消失      │= 影响面过大时的降级档        ││
│    │（红底带，左3px红条）        │（金底带，左3px金条）         ││
│    └────────────────────────────┴────────────────────────────┘│
│ ② SettingsBlock「抑制清单」（主体，bodyClassName 去内边距）
│    PanelToolbar（搜索 | 仅启用 | 刷新 | ＋新建抑制）
│    Table（7 列，按命中数降序）+ Pagination
│ ③ SettingsBlock「参数与门槛」（折叠说明 + [改参数…]）
└──────────────────────────────────────────────────────────────┘
   Drawer「新建/编辑抑制」720px（含试算卡）
   Drawer「抑制参数」720px
   Dialog「撤销抑制」+ 原因
```

- **为什么列表用 SettingsBlock 而非 Card**：与 `/config/filters` 同族语言（用户会横向对照）。**为什么表单用抽屉**：抑制表单有「试算」中间步骤，内嵌会把列表推出首屏。
- **总览 4 张 Stat 的字段绑定（`stats()` 真实键，别自己推）**：生效中=`active`、仅记录中=`by_mode.record_only`、累计命中=`suppressed_total`、条目总数=`total`；第四张的 hint 写「其中已过期 {expired} · 已撤销 {revoked}」。
  - **`expired` 与 `revoked` 会重叠**（一条可同时已过期且已撤销），**绝不能相加**成一个「已过期·已撤销」数字——所以第 4 张卡用 `total` 而不是合计数。
  - `by_mode` **只统计「当前生效且未过期」的条目**（`stats()` 只在 `enabled and not is_expired` 时累加）→ 「仅记录中」是**当下状态分布**，不是历史累计，label 不要写「累计仅记录」。
  - `limits` 里也带全部门槛（含 `trial_max_hits` 等），但**试算卡的门槛说明只读 `/preview` 的 `thresholds`**（那才是本次试算用的值），两处不要混用。
- **工具条只有 4 个元素：搜索 / 仅启用 / 刷新 / ＋新建抑制。没有「含过期」开关**（见坑 2：`include_expired=false` 会让 `total` 与可见行数不一致，复现「共 100 条 / 本页 30 条 / 空页」）。
- **前端必须显式携带 `include_expired=true`**：后端签名 `list_suppressions(include_expired: bool = False)`（`routes/suppressions.py:87`）默认是 `False`，不传就落坑。→ 每次请求都写死 `?include_expired=true`，**不要依赖默认值**。
- 「仅启用」是**正向开关**（勾上 = `enabled_only=true`，SQL 层过滤、计数与行数一致），默认关。文字用「仅启用」不用「隐藏已撤销」（后者是负语义，且会与过期口径打架）。
- `SettingsRail` 侧列若有：只放只读「口径说明」卡，**不放表单、不放 >3 列的表**。

### 5.2 抑制清单：列与优先级

| # | 列 | 宽 | 内容 | 理由 |
|---|---|---|---|---|
| 1 | **名称** | `min-w-0` | 名称(13 medium)；第二行 12px muted：`理由 reason_label · 界面/智能体 · 置信度 0.82 · 证据 3 条` | 主锚点；元数据压一行 |
| 2 | **模式** | `w-44` | §2.4 徽章（icon + 本地短词） | **紧贴名称**：先知道「多狠」 |
| 3 | **条件** | `min-w-0` | `match` 摘要（mono 12，`truncate`，title 全文）+ `{dims} 维` 徽章（`dims < 2` 时该徽章 `medium`） | 条件是合规底线（`min_match_dims` 硬下限 2） |
| 4 | **命中数** | `w-20` | `hits` tabular，表头 title「按命中数降序：吞得多的最需要复核；约 30 秒内更新」 | 排序键=复核优先级 |
| 5 | **状态** | `w-24` | §2.5（含第二行成因） | — |
| 6 | **到期** | `w-36` | `剩 6 天`（≤3 天 `text-sev-medium-fg`）/`已过期`/`—`，title 给完整 `expires_at`；**无论状态如何这一列都保留** | TTL 是兜底机制，撤销后也可能已过期 |
| 7 | **操作** | `w-40` | `编辑`(outline) + `撤销`(ghost + `text-sev-critical-fg`) 或 `恢复`(outline) | **没有删除接口**（坑 7） |

- `dims` 的口径：`len(match_fields(match))`，即**条件树里不同的、值非空的叶子 `field` 数**（`match_fields` 去重，不是叶子条数）。同一 field 写两条也只算 1 维——所以「`src_ip` in [a,b] + `dst_port` eq 443」= 2 维。
- **不做**：「优先级」列（无字段）、「创建人」独立列（已并入名称第二行）、「`match` JSON」列（抽屉给 `<pre>`）、排序下拉（接口无排序参数，后端固定 `hits DESC, created_at DESC`）。
- `mode` 筛选：接口没有 `mode` 参数 → **只能前端过滤当前页**，且必须标注「仅当前页」。更稳的做法：不做 mode 筛选，靠总览两块 Stat 的跳转（点「仅记录中」= 前端过滤当前页 + 提示）。
- 状态扫描靠徽章，第二行成因是本页唯一允许的「两行单元格」；成因文案用 `truncate` + title 全文。

### 5.3 新建/编辑抽屉（720px）：顺序与「试算卡」

表单顺序（**不能颠倒**）：
```
① 条件树（复用 ConditionEditor，fields = allowed_fields）
② ★ 试算结果卡（自动 + 手动 + 重新试算）
③ 名称 / 理由码 / 备注
④ 证据引用(chips) / 置信度 / 有效期 ttl_days
⑤ 底部动作条（取消 / 重新试算 / 保存）
```
理由：试算决定「还要不要继续写」，必须在名称之前。

**条件树字段源**：`allowed_fields` 共 **12 个**（`suppression.py:61`）——`src_ip, dst_ip, dst_port, segment, protocol, rule, signature_id, http.uri, http.hostname, user_agent, ja3, fuid`。**`payload/body/content` 不在白名单**（README「四元含 payload」过时，代码为准）。`condition-editor.tsx` 的 `RULE_FIELDS` 只有 5 个交集 → **按 `allowed_fields` 另配字段下拉**，并对 `dst_port` 强制 `Number()`（必须 int）、`protocol` 强制 `toLowerCase()`、`src_ip` 不收网段（网段用 `segment`）。

**理由码**：7 值枚举、**必填**（空串也报 400）：`known_service`(已知的自家服务/客户端行为) / `internal_scanner`(内部授权扫描器/漏扫平台) / `vendor_heartbeat`(厂商组件心跳/升级/探测) / `business_normal`(业务正常行为) / `duplicate_of_task`(与既有任务/结论重复) / `repeated_after_analysis`(分析后重复出现的同类流量) / `manual`(人工创建)。→ 下拉用 `reason_label` 中文，值传 key，**默认选 `manual`**。

**试算结果卡（本页最重组件）**：

- 顶部**结论带**（48px，`rounded-xs`，1px 同色描边 + 左 3px 同色实心条）：
  `[Ban] 完全抑制 · 不生成事件`（`bg-sev-critical-bg` / `text-sev-critical-fg` / `border-sev-critical-bd`）或 `[BellOff] 仅记录 · 事件仍生成`（`bg-sev-medium-bg` 同色系）。带内右上角 12px 显示接口原文 `mode_label`（「完全不生成事件」/「只不派工（事件保留）」），仅作佐证。
- 三个 `Stat size="sm"`：`近 N 天同类命中 trial.events` / `涉及源 IP trial.srcs` / `涉及网段 trial.segments`，hint 写阈值；**超阈值那格数字用 `text-sev-critical-fg`**。
- 一行 12px muted 门槛说明（**键名照抄，别自己拼**）：
  `判定口径：命中 ≤{trial.max_events ?? thresholds.max_hits} · 源 ≤{trial.max_srcs ?? thresholds.max_srcs} · 网段 ≤{trial.max_segments ?? thresholds.max_segments} · 试算 {thresholds.trial_days} 天 · 最少 {thresholds.min_match_dims} 维`
- **`thresholds` 的 5 个键是 `trial_days / max_hits / max_srcs / max_segments / min_match_dims`**（`routes/suppressions.py:168`）。**`thresholds` 里没有 `trial_max_*`**（那是 knob 名）—— 写 `thresholds.trial_max_hits` 会渲染成「≤undefined」。knob 侧的 `trial_max_hits` 只用于参数抽屉。
- 默认值（**从接口读，不硬编码**）：命中 5000 / 源 200 / 网段 8 / 试算 7 天 / 最少维度 2（硬下限 2，可调 2–6）。
- 触发时追加 warning（`bg-sev-medium-bg` 行内条）：`命中 6,120 超过阈值 5,000，保存后只会降级为「仅记录」，事件仍会生成。`
- **`trial` 的字段是 `events / srcs / segments`**（成功时另带 `days/phenomenon/max_events/max_srcs/max_segments`）：**没有 `hits` 字段**，读 `trial.hits` 恒 `undefined`。
- **`-1` 必须当「未知」渲染成 `—`**：试算内部失败时 `events/srcs/segments` 都是 `-1`。
- 交互：`match` 变更后 600ms debounce 自动试算；试算中 `Skeleton` + 「试算中…」并**清空上次结果**（防按旧结果保存）；失败(400 `field_errors`)红字在条件树下方，`field === "match"`。
- **编辑态特例**：同时显示「当前：仅记录 → 试算后：完全抑制」，方向用 `ArrowRight`。`record_only → suppress` 是**变狠**，结论带必须补一句「影响面缩小，保存后将不再生成事件」（`text-sev-critical-fg`）；`suppress → record_only` 是**变保守**，不警告。

**⑤ 保存按钮的四出口（一表定死，别自己发挥）**：

| `/preview` 结果 | 形态 | `trial` | 保存按钮 |
|---|---|---|---|
| `success` | 200 | `events/srcs/segments` 真实数字 | **可点**，结论带按 `mode` 上色 |
| `degraded`（试算内部失败） | **仍是 200** + `trial.error` | `events/srcs/segments = -1`，`mode = record_only` | **必须可点**：影响面未知 → 自动按保守档只记录，这是合法结果 |
| `invalid` | 400 + `field_errors` 含 `field === "match"` | 无 | 置灰（`aria-disabled`），条件树下方红字 |
| `netfail` | 网络异常 / 5xx | 无 | 置灰（`aria-disabled`），卡内红字「试算失败，网络或服务异常」，**「重新试算」入口常驻** |

- `degraded` 态三格显示 `—`（**不渲染 `-1`**），结论带补一行：「影响面未知（试算失败），已按保守档降级为仅记录」。
- 判据是 `trial.error` 是否存在 / `events < 0`，**不是**看 `mode`——`mode` 在两种情况下都可能是 `record_only`。

**两段式提交（唯一能「静默掉一整类流量」的交互路径，必守）**：

1. 第 1 段：首次试算成功（`success` 或 `degraded`）→ 底部主按钮从「保存」变为「**确认保存（{完全抑制|仅记录}）**」，按钮 variant 随 `mode` 走（`suppress` → `destructive` 实心红，`record_only` → `default`），上方结论带同步。**这是 §8「只有 Dialog 用 destructive」的唯一例外**：这个按钮会静默掉一整类流量，红色是为了让手指停一下；除它以外全站抽屉里不得出现 `destructive`。
2. 第 2 段点「确认保存」才真正 `POST/PUT`。**两个入口共用同一个 `runPreview()`**：「重新试算」成功后也直接进第 2 段——否则「重新试算刷新了正文、footer 还在第 1 段」会让下一次「保存」走「已有有效结果则直接提交」的捷径，**等于绕过二次确认**。
3. **`match` 一旦变更，立即退回第 1 段并清空 `trial`**；`name` / `reason_code` / `evidence_refs` / `confidence` / `ttl_days` 变更**不**复位（它们不影响影响面）。
4. **请求序号守卫**：并发/竞速的两次 `/preview` 可能乱序返回，让用户按**过时的影响面**确认。→ 每次发起 `const seq = ++seqRef.current`，回来时 `if (seq !== seqRef.current) return;`。这条**不能**用 `aria-disabled` 替代（那是渲染态，不是时序）。
5. `trialing` 用 **`aria-disabled` + `aria-busy`**，**不要**用原生 `disabled`（原生 disabled 会把按钮移出 Tab 顺序，读屏宣布「已禁用」，且用户看不到按钮上的原因）。

**反例（禁止）**：表单出现 `mode` 单选/开关；mode 做成 tooltip；两 mode 仅靠颜色区分；试算结果用 toast（必须常驻表单内）；`degraded` 态把保存画成 disabled。

### 5.4 撤销 / 恢复

- `撤销` → `Dialog`(560px)：标题「撤销抑制「名称」？」，正文写后果：「撤销后，命中该条件的流量会重新生成事件并重新派工；**已抑制的历史事件不会补回**（原始数据仍在 ES，可用日志检索回溯）」，+ 原因 textarea（≤200 字，写进 `RevokeIn.reason`），+ 4 个常见原因 chip（`误判 / 条件写错 / 业务已变更 / 临时放行结束`，点击填入 textarea，可再编辑）。footer：`取消` / `撤销`(`destructive`)。
- **`revoke` 必须带 body**：`RevokeIn` 是必填 body（`reason` 有默认空串），**空 body 会 422**。→ 至少发 `{}`；用户不填原因也发 `{"reason": ""}`。原因**可空**（后端默认空串，不强制）。
- `恢复` → 直接 `POST /{id}/restore`（低风险），成功后行内提示 + 重取列表；**不再弹窗**。
- **`restore` 不校验是否已过期**：恢复一条 `expires_at` 已过的条目后，返回的是 `enabled=true` 且 `expired=true` —— 实际**仍不生效**。→ 若行状态是「已过期」，先弹轻确认：「该条目已过期，恢复后需同时延长有效期才生效」，并在编辑抽屉里把 `ttl_days` 放在最上面提示延长。

### 5.5 抑制参数抽屉（15 knob）

- **共 15 项**（`suppression.py:130-274`）：`enabled`、`auto_apply`、`min_match_dims`、`min_refs`、`min_tools`、`min_confidence`、`default_ttl_days`、`max_active`、`hit_cap`、`trial_days`、`trial_max_srcs`、`trial_max_hits`、`trial_max_segments`、`newcomer_hours`、`cache_seconds`。
- 渲染与 §4.7 **完全同构**：`value = effective[item.key] ?? item.default`（`items[]` 同样**没有 `value`**）；`kind` 只有 `bool/int/float/text`；`field_errors.field` 是 `suppression.*` 全名。
- 分组建议（4 组）：**门槛**（`min_match_dims/min_refs/min_tools/min_confidence/newcomer_hours`）· **试算**（`trial_days/trial_max_srcs/trial_max_hits/trial_max_segments`）· **兜底**（`max_active/hit_cap/default_ttl_days`）· **开关与缓存**（`enabled/auto_apply/cache_seconds`）。
- 4 条必须写进 `note` 的既有语义（照后端 note，不自己编）：
  - `auto_apply` 关掉 = 「只抑制派工，事件仍生成」（灰度/回滚用，不删条目）；
  - `min_match_dims` = 「下限锁 2，界面也不能调低」（后端 `max(2, …)` 硬兜底）；
  - `hit_cap` = 「某条抑制累计吞掉这么多事件即自动撤销」；
  - `cache_seconds` = 「匹配集合的进程内缓存；新增/撤销会立刻失效」。
- 生效文案：参数抽屉写**「30 秒内生效」**（与 `/analysis` 参数完全同一机制，见 §8 坑 11）。**不要写 45 秒**——`cache_seconds=45` 管的是「抑制**条目**匹配集合」的进程内缓存，不是参数生效时间（两者常被混为一谈，此处以 `runtime_config.py:20 _CACHE_TTL_SECONDS = 30.0` 为准）。
- `min_confidence` 的 note 必须带「仅对智能体自动提交生效，界面人工创建不受此限」——否则运维会以为自己在界面上建不了条目。

### 5.6 抑制的两处接口硬约束（前端必须绕开，不是后端 bug 清单）

1. **`PUT /{id}` 只写 4 个字段**：`match` / `reason_code` / `evidence_refs` / `ttl_days`（`update_item` 只 `set` 这 4 项）。`name` / `note` / `confidence` 改了**会静默丢弃（200 但值不变）**。→ 编辑态：**`name` 只读并标注「创建后不可改」，`note` / `confidence` 不给编辑**（要么只读展示，要么整块隐藏）；只开放 `match / reason_code / evidence_refs / ttl_days`。新建态可填全部。后端补字段不在本次范围。
2. **重名会 500**：`name` 是 `unique=True`（`models.py:110`），`IntegrityError` 未捕获。→ 新建/改名提交前用列表数据本地查重，命中则前置提示「名称已存在」且不发请求；仍遇 5xx 时提示「服务异常，若名称重复请更换」。

**另外三条小契约**（写实现时容易漏）：
- 界面**人工**建抑制不走 `min_tools / min_confidence / min_refs` 门槛（后端只在 `if is_agent:` 时校验）→ 界面上不要显示「置信度低于 0.85 会被拒」的阻断文案，只给非阻断提示「低于 0.85 的结论建议补证据」。
- 真正会 400 的**只有 5 类**：`name`（必填 ≤128）、`match`（维度 < `min_match_dims` / 字段不在白名单 / 条件过宽）、`reason_code`（必填，7 值）、`ttl_days`（1–30）、`evidence_refs`（必须是数组，≤20 条）。
- `evidence_refs` 格式是 `es:<index>/<id>`（或 `ev:<uuid>`），单条 ≤200 字符 → chip 里用 mono 12，超长 `truncate`+title。

**4 种错误形状与渲染落点**：

| 形状 | 例子 | 渲染 |
|---|---|---|
| 400 `{conflict:"field_error", detail, field_errors?}` | 抑制参数保存 | `field_errors` 回填控件；`field==="match"` 显示在条件树下方 |
| 400 `{detail}` | `POST /tasks` subject 空 | 顶部/表单内联红字 |
| 404 `{detail}` | `revoke`/`restore` 条目不存在 | `Dialog` 内红字「条目不存在，请刷新」 |
| **422 `{detail:[{loc,msg,type}]}`** | 空 body 调 `revoke`、`ttl_days` 越界没被前端拦住 | **必须解析数组取 `msg` 拼接**；`errorText()` 会渲染成 `[object Object]` |

→ 提交前统一 clamp：`ttl_days` 1–30、`evidence_refs` ≤20、`confidence` 0–1、`strength` 0–1、`subject` ≤128、`note` ≤500、`name` ≤128。

---

## 6. 三态：空态 / 错误态 / 加载态（「真没有」与「读取失败」必须分开）

| 场景 | tone | 标题 | hint / action |
|---|---|---|---|
| 队列首次加载 | `loading` | — | ① `StatSkeleton count={6}`；② `TableSkeleton rows={8} cols={8}`；**禁止先渲染 0 值或「队列为空」** |
| 队列为空（真没有） | `muted` | 队列里没有待派线索 | 「线索由检测器按候选规则生成，每个节拍（`flush_seconds` 默认 60s）评估一次」+ `刷新` + 次链接「检查候选规则是否开启」 |
| 队列读取失败 | `danger` | 任务队列读取失败 | 「见上方错误条：后端或 Redis 不可用，不能当成『没有线索』」+ `重新读取` |
| 总览 stats 失败 | `danger` | — | Stat 值显示 `—`（不是 0）；counters 整块显示 `—` |
| 结论为空 | `muted` | 还没有交回的结论 | 「智能体领走任务并 complete_task 后才出现；先看队列里已派的任务」 |
| 盲区为空（好消息） | `Card bg-sev-ok-bg border-sev-ok-bd` | 全部对象都在窗口内分析过，没有盲区 | 空≠不显示 |
| 抑制清单为空（真没有） | `muted` | 还没有抑制条目 | 「抑制由智能体带证据自动创建，也可人工新建」+ `＋新建抑制` |
| 抑制读取失败 | `danger` | 抑制清单读取失败 | 后端异常或库不可用，不是「没有抑制」 |
| 试算中（`trialing`） | `loading` | 试算中… | Skeleton + 清空旧结果；保存按钮 `aria-disabled` + `aria-busy`（**不是原生 disabled**） |
| 试算 `degraded` | `warning` | 影响面未知（试算失败） | 已按保守档降级为仅记录；三格 `—`；**保存可点** |
| 试算 `invalid` | `danger` | — | 条件树下方红字（`field === "match"`）；保存置灰 |
| 试算 `netfail` | `danger` | 试算失败 | 「网络或服务异常」+ 常驻 `重新试算`；保存置灰 |
| 抽屉保存中 | — | — | 按钮 `保存中…` + `disabled`，**不做乐观更新** |

- 统一机制：`usePanelErrors` + `loadInto` + `PanelError` + `emptyOrFailed`，**不要自己 catch 成 null 再渲染空态**。
- 判空**先判 `data.error`**：列表接口失败都是 **HTTP 200 + `{error, items:[], total:0}`**，「`items.length === 0` 且无 error」才是真空。
- **已删除的历史话术**：「抑制清单空但 `total>0` → 共 N 条不在当前视图内」。在 `include_expired=true` 恒定的前提下 `total === returned`，不存在该场景；若真出现 `total !== items.length`，说明有人传了 `include_expired=false`，去查代码，不要加空态分支。

---

## 7. 菜单归属与中文命名

```ts
// nav-config.ts · 分析中心 dropdown 追加第 3 项（无侧边栏——单页+抽屉）
{ href: "/analysis", label: "派工队列",
  desc: "客观线索队列 · 结论 · 覆盖率 · 预算", icon: ClipboardList }

// nav-config.ts · CONFIG_ITEMS 的「检测与过滤」组末尾追加（第 3 位）
{ href: "/config/suppressions", label: "精准抑制",
  desc: "按命中数复核 · 影响面试算 · 撤销", icon: ShieldOff, group: "检测与过滤" }
```

- **`ShieldOff` 当前未 import**（`nav-config.ts` 只 import 了 `ClipboardList / Filter / Radar / ScanSearch / Siren` 等）。→ 二选一：**补 `ShieldOff` 进 import**（语义最准，推荐），或改用已 import 的 `Filter`。不补就编译失败。
- 路由：直接实现 `app/analysis/page.tsx` 与 `app/config/suppressions/page.tsx`。**不要再建 `app/admin/*` 镜像 + 薄壳**（那是 2026-10 迁移期存量模式，现已整体撤销、`app/admin/` 目录已删除）；新页直接落地。
- `/analysis` 在 dropdown 里靠 `sectionOf()` / `sidebarOf()` 自动归属：有高亮、**不出侧边栏**，不需要额外 `match` 字段。
- 命名：「派工队列」比「分析机制」好（用户找的是「活在哪」）；「分析机制」留给首块 Section 副标题。
- 「精准抑制」保留（安全运营通用词），desc 点出复核/试算/撤销。
- 顺序：`降噪过滤 → 排除过滤 → 精准抑制` = 由轻到重三档拦截（精准抑制最狠）。配置管理侧栏 8→9 项（4 组）。

---

## 8. 一致性要点 + 必须避开的坑

### 与现有页面保持一致（照抄）

1. `PageShell width="wide"`；**h1 已 sr-only**，第一屏直接 Section，不要自己加标题段落。
2. 分区只用 `Section`；`SettingsBoard/SettingsBlock` 只用于「一整块配置板」；**不要 Section 里套 Card 再套 Card**。
3. `Stat` 不描边、只有 `bg-surface-1`；`lg` 主指标、`md` 次级、`sm` 一句时间预期。
4. 表格不自定义样式（表头 `h-8`+`bg-surface-1`+`text-foreground`、全边框、行 hover `bg-brand-50`）；必须落在白底 `Card`/`SettingsBoard`。
5. 数字 `tabular-nums`；时间 `formatDateTime`（北京时间）；ID/IP `font-mono`。
6. 按钮 `size="sm"`；主操作 `default`、次要 `outline`；行内危险 `ghost + text-sev-critical-fg`；只有 Dialog 用 `destructive` 实心红。
7. 抽屉/对话框用共享 `Drawer`(640/720) 与 `Dialog`；关闭靠 `useModalBehavior`。
8. 开关类筛选用 `Switch size="sm"` + 12px 文字（`Switch` 只吃 `checked/onCheckedChange/label`，**不吃 children**）。
9. 工具条控件统一 `h-8`：select 用 `cn(SELECT_CLS, "h-8 w-28")`（`SELECT_CLS` 从 `components/condition-editor.tsx` 导入，别复制一份到面板里）。

### 坑（按严重度，全部已在代码核实）

1. **列表接口失败返回 HTTP 200 + `{error, items:[], total:0}`。** 只看 `items.length` 会把「后端挂了」渲染成「今天很安静」。必须 `if (data?.error)` 走 danger 态。`/tasks` `/results` `/coverage` `/inventory` `/suppressions` 同理；`/tasks/{id}` 与 `/coverage`、`/inventory` 的 `error` 也都在 200 里。
2. **抑制清单 `total` 与可见行数不一致。** `list_items` 先 SQL 分页（`total` 不过滤过期）再 Python filter 掉 expired。**恒传 `include_expired=true` 直接消坑**（后端默认 `False`，必须显式传）。
3. **不提供「领取任务」入口。** 领取/交回/延后只走智能体 MCP。界面加一个「派工给我」会绕过智能体自己的领取流程。
4. **没有 `state="overflow"`。** 超容量只有 `dropped_overflow` / `superseded` 计数器 + `expired` 行小字「被更强线索挤掉」。不要造第七种徽章。
5. **抑制清单没有 `mode` / 排序参数**（只有 `q` / `enabled_only` / `include_expired` / `limit` / `offset`）。不要放排序下拉；mode 筛选只能前端过滤当前页并标注。
6. **结论列表没有关键词搜索**（只有 `task_id` / `subject` / `verdict`），且 `subject` 是精确等值。
7. **抑制没有 DELETE**，只有 `/{id}/revoke` 与 `/{id}/restore`；`revoke` 必带 body，`restore` 不校验过期。
8. **`mode` 不可手选**，由 `choose_mode(trial)` 决定；前端任何地方都不出现 mode 控件。
9. **`ttl_days` 1–30（默认 14）、`confidence` 0–1（不是 0–100）、`evidence_refs` ≤20 条且格式 `es:<index>/<id>`。**
10. **`match` 至少 2 个独立维度**（`min_match_dims` 硬下限 2），单维会被 400 拒绝。
11. **生效时间只有两类，别混成一句**（两个不同的缓存，别互相顶替）：
    - **参数**（`analysis.*` 与 `suppression.*` 走同一套 `runtime_config`，`_CACHE_TTL_SECONDS = 30.0`）→ 保存请求的那个进程立即（`invalidate()`），**其他进程 ≤30 秒**。→ 文案统一「30 秒内生效」，两页一致。
    - **抑制条目**（新增/撤销/改条件）→ 保存进程立即（`invalidate_cache()`），**其他进程 ≤ `cache_seconds`（默认 45 秒）**。→ 文案「本机立即生效，采集/判定侧最迟 45 秒」。
    - 常见误写：把抑制**参数**写成 45 秒（那是条目缓存）、把参数写成「立即」（跨进程要等 30 秒）。
12. **`primary` 不能当状态色**（品牌蓝=可操作/选中/焦点）。
13. **自动刷新会打断正在编辑的抽屉**：`if (modalOpen) return`，否则填一半行对象换新、表单错位。
14. **徽章 ≤ 2 个/行**（抑制行 3 枚时第二行不再加）。
15. **`items[]` 没有 `value`。** 参数抽屉当前值取 `effective[item.key] ?? item.default`；照抄 `behavior-panel.tsx:1150` 的 `item.value` 会整列 `undefined`（不报错、不白屏，最难发现）。
16. **`errorText()` 遇 422 数组会渲染 `[object Object]`。** 单写一个 `formatApiError()`：数组取 `msg` 拼接，对象取 `detail`，字符串直出。
17. **`ShieldOff` 未 import** → 导航编译失败（见 §7）。
18. **`candidate_kinds` 空串会 400「不能为空」**：5 个 checkbox 全不勾时拦在点击，不要灰按钮、不要发请求。

---

## 9. 交接

- **给 ux-designer**：三条交互状态机 —— ①队列行→详情抽屉→回列表焦点归位；②抑制抽屉「条件变更→debounce 试算→mode 可能翻转→两段式确认→保存」（含 `degraded` / `invalid` / `netfail` 三分支，`degraded` 必须可保存）；③撤销 Dialog 原因可空 + 4 个常见原因 chip。
- **给 fe-engineer**：按 §8 的 18 条坑实现（尤其 1、2、11、15、16）；类型新建 `KnobItem`（无 `value`）与 `SuppressionItem`（26 字段），运行时常量/中文映射放新建 `lib/analysis.ts`（照 `lib/hits.ts` 先例），**不塞 `api.ts`**；参数抽屉复用 `behavior-panel.tsx` 的 draft/`overridden`/`field_errors` 渲染骨架（但**不要**照抄 `item.value` 与 `kind === "regex"` 两行）；条件树复用 `components/condition-editor.tsx`（`condsToRules`/`conditionsToConds` 已处理 `in`→数组、数值转换、`exists` 不带值），字段源换成 `allowed_fields` 12 项。
- **已拍板口径**：①抑制清单恒 `include_expired=true` + 只留「仅启用」开关；②派工队列**不做侧边栏**（单页 + 3 浮层）；③`/analysis` 与 `/config/suppressions` 直接落地，不建 `app/admin/*` 镜像（该模式已整体撤销）。

---

> 变更记录：2026-10-25 将 v2–v6 勘误并入正文并删除追加块（主编：design-architect-2）。
