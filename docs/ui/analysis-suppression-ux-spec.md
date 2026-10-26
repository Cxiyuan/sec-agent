# 派工队列 + 精准抑制 · Phase 2 体验规范

> 版本：v2（2026-10-25）｜ 作者：ux-designer ｜ 状态：待 team-lead 复核
>
> 本文是**体验/交互规范**：任务流程图、状态机、三态、响应式、无障碍、高风险降级、验收清单。**不含实现代码、不改依赖、不改后端**。
> **视觉 token / 版式唯一来源**：`docs/ui/analysis-suppression-visual-spec.md`（design-architect-2，v1–v6）。本规范只引用其组件态速览（附录 A），冲突以视觉规范文件为准。
> **后端契约依据**（逐字段核对）：`ndr/backend/app/api/routes/analysis.py`、`api/routes/suppressions.py`、`app/analysis/queue.py`、`app/detector/suppression.py`。行号见附录 C。
> 三方已对齐：与 design-architect-2（视觉）、fe-engineer-2（实现）收敛一致；对「交互契约备忘 v0」的两处收紧见 §10.2，**以本规范为准**。

---

## 0. 范围与硬红线

**两页**
- **派工队列** `/analysis`（分析中心下拉，**无侧边栏**；首块 Section 副标题写「分析机制」口径）。
- **精准抑制** `/config/suppressions`（配置管理侧栏「检测与过滤」组）。

**红线 1｜派工队列只读浏览，不开放领/交/延**
「领取 / 交回 / 延后」走 MCP（带令牌配额），界面**不提供**这些按钮。界面只做：浏览队列 + 人工派工 + 看结论/覆盖率/对象清单 + 参数读写。

**红线 2｜抑制「新建/改条件」必须过试算**
`mode=suppress` 会让该类现象**不再生成事件**。任何新增/修改条件树都必须在提交前完成一次试算并回显影响面；影响面未知时按 `record_only` 保守降级，且不得"蒙眼"保存。

**三条贯穿全文的数据真相**
1. 列表接口**失败也返回 200**：`{error, items:[], total:0}`（`/tasks`、`/results`、`/coverage`、`/inventory`、`/suppressions` 同理）。`items 为空 ≠ 没有数据` → 三态必须三选一（§4）。
2. 抑制列表 `total` **含过期项**；`include_expired=false` 是"分页之后再过滤"（§3.3）。
3. `enabled` 与 `expired` **正交**：过期不把 `enabled` 置 False，一行可同时"已撤销 + 已过期"（§3.4）。

---

## 1. 信息架构与导航

| 页面 | 路由 | 侧边栏 | 宽度 | 入口 |
|---|---|---|---|---|
| 派工队列 | `/analysis` | 无 | `PageShell width="wide"` | 分析中心下拉 |
| 精准抑制 | `/config/suppressions` | 配置管理·检测与过滤组 | `PageShell width="wide"` | 配置管理 |

- 命名：菜单/页标题「派工队列」「精准抑制」；「分析机制」只作首块 Section 副标题。
- 直接实现 `app/analysis/page.tsx` 与 `app/config/suppressions/page.tsx`，**不建 `app/admin/*` 薄壳镜像**（该迁移期模式现已整体撤销，`app/admin/` 目录已删除）。
- 骨架（两页 h1 `sr-only`，第一屏直接 Section）：派工队列 5 块（①队列总览 ②任务队列 ③任务结论 ④覆盖率与盲区 ⑤对象清单）；精准抑制 3 块（①抑制总览 ②抑制清单 ③参数与门槛）。

---

## 2. 页面 A：派工队列 `/analysis`

### 2.1 六状态（没有第 7 种）

后端只有 6 个 `state`（`pending/claimed/deferred/done/stuck/expired`）。**禁止**造第 7 个徽章/筛选项。

| state | 中文徽章 | variant | 含义 |
|---|---|---|---|
| `pending` | 待派 | `info` | 已入队、待智能体领取 |
| `claimed` | 已派·在跑 | `low` | 已被某令牌领取、租约内 |
| `deferred` | 已推迟 | `medium` | 主动延后，`lease_until` 前不可领 |
| `done` | 已完成 | `success` | 已交回结论 |
| `stuck` | 卡住 | `high` | 连续领取未交回达上限，停止派发 |
| `expired` | 已过期 | `outline`+灰字 | 超有效期未领取，或被更强线索挤掉 |

- 状态徽章是**该行唯一彩色列**；状态筛选**单选**（后端 `state` 精确单值，不支持多选）：选项 = 全部 + 6。
- **默认筛 `pending`**（不是"全部"）：`state=""` 会把历史 `done` 按 `priority DESC` 混排、首屏被已完成占满；「全部」作显式选项。

### 2.2 容量压力条（"超容量"的唯一载体）

**「超容量」不是状态**。满队列时 `enqueue`：新线索强度高于队尾 `pending` 就挤掉那条（置 `expired`+note「被更强线索挤掉」并 `bump("superseded")`），否则 `bump("dropped_overflow")` 直接丢弃（**不产生行**）。

- 取值：`(stats.pending + stats.deferred) / stats.budget.queue_capacity`。
- 形态：240px × 6px `rounded-full`；`<80%` `bg-primary`；`80–99%` `bg-sev-medium-fg`；`≥100%` `bg-sev-critical-fg` + 右侧 `text-sev-critical-fg`「已满，新线索会被丢弃（dropped_overflow）」。
- 永远配 `tabular-nums` 的「{used} / {cap}」；旁挂 `text-xs muted`：`丢弃 {counters.dropped_overflow} · 挤出 {counters.superseded}`。这俩是计数器，位置固定、**不随筛选、不升徽章**。
- `queue_capacity` 从 `stats.budget.queue_capacity` 读，不写死。

### 2.3 任务队列列表

- 容器：全幅 `Card`；`PanelToolbar`（搜索 `q` / 状态分段（默认 pending）/ 类型 `select`（`/config.kinds`）/ 自动刷新 / 刷新 / `＋人工派工`）+ Table 8 列 + `Pagination`。
- 列序（附录 A）：`强度(w-16) → 对象(+kind 徽章, min-w-0) → 类型(w-24) → 状态(w-24, 唯一彩色) → 线索摘要(min-w-0,truncate+title) → 合并/尝试(w-20) → 时效(w-32,formatDateTime+剩 Nh) → 详情(w-12,ghost 图标 + aria-label)`。
- 数字 `tabular-nums`；对象/IP `font-mono`；时效 `pending` 用 `created_at + pending_ttl_hours` 推算，`<6h` 用 `text-sev-medium-fg`；无 `lease_until` 时 `claimed/deferred` 的剩余显示「—」。
- 分页：`Pagination`，**文案用 `total`、行数用 `items.length`**（`list_tasks.returned = items.length`）。
- 三态 §4。

### 2.4 人工派工（Dialog 560，`result` 六值各给不同提示）

- 入口：工具栏 `＋人工派工`；可连续派下一个。
- 表单：`subject`（必填，空则前端拦截）、`subject_kind`（默认 ip）、`kind`（默认 hit）、`note`（≤500）、`strength`（0–1，默认 0.6）。提交前 clamp（§3.11）。
- 语义提示：`人工派工走同一套去重与容量规则，不插队；满队列时同样可能被挤掉或丢弃。`
- 接口返回 **HTTP 200 + `{ok, result}`**（失败不是 404）。`ok` 仅在 `new/merged` 为 true；`superseded` 若出现视为**成功**（已顶掉更弱线索并入队），不要按 `ok` 判成失败：

| `result` | 含义 | 提示文案 | tone |
|---|---|---|---|
| `new` | 新入队 | 已入队（{subject}） | success |
| `merged` | 并入同现象 | 已并入同现象的既有线索（不重复派工） | success |
| `superseded` | 顶掉更弱线索后入队（后端挤出后通常返回 `new`，此处兜底） | 已入队（顶替了更弱的待派线索） | success |
| `dropped` | 队列满且不够强 | 队列已满，本条被丢弃（强度低于队尾） | `text-sev-medium-fg` |
| `skipped` | 队列关闭/类型未启用 | 派工已关闭，或该线索类型未启用 | muted |
| `error` | 失败 | 派工失败，见页面上方错误条 | danger |

### 2.5 任务结论列表

- 全幅 `Card`；筛选**只有三个**：结论分段(`verdict`) + 对象精确(`subject`) + 任务 ID —— **无关键词搜索框**（`/results` 无 `q`）。
- 列（附录 A）：`结论(badge) → 对象 → 类型 → 置信度(tabular) → 摘要(truncate+title) → 工具·耗时 → 交回(claimed_by, mono) → 时间 → 关联任务(「查看」开详情抽屉)`。
- 结论值用中文本地 map（`verdicts` 词表）；计数/分页同 §2.3。

### 2.6 覆盖率与盲区

- `Section` + `SettingsGrid`：`Stat × 4`（对象总数 / 已分析 / 覆盖率 / 盲区）+ 主列盲区表 + 右栏"验收口径"只读卡。
- **计数口径硬约束**：`returned` 是切片前长度 → 一律用 `items.length`；覆盖率 `items[].kind` 恒为 `"asset"`（后端 bug）→ **类别用 `subject_kind`**，不要用 `kind`；`stale` 常被切片挤掉，需带 `kind` 或调大 `limit`。
- 工具条：`days` 分段(7/14/30) + `kind` select + 刷新；天数切换要重取。
- 「从未分析」用 `medium` 不用红（欠账不是事故）；盲区为空 = 好消息，用 `bg-sev-ok-bg` 卡片，不显示成"无数据"。

### 2.7 对象清单（数据地图）

- `Section`；类型切换用 **Button 组**（仓库无 `Tabs`）。5 列：`对象 → 类型 → 最近出现 → 次数 → 详情`；计数用 `items.length`。

### 2.8 派工参数（Drawer 720，**23 knob，6 组**）

- 入口：总览区「参数…」；复用 `behavior-panel.tsx` 的参数渲染（draft / `已改`·`默认`·`未保存` 三徽章 / 范围与默认值 / 逐字段 `field_errors` / 单键与全部恢复默认）。
- **当前值取 `effective[item.key]`**；config item 只有 `{key,label,kind,default,low,high,unit,note,overridden}`，**没有 `value`**（照抄 `item.value` 会整列 undefined）。
- `candidate_kinds` 是 text 型、空串会 400「不能为空」→ 5 个 checkbox **全不勾必须禁止保存**，并引导「要停就关 `enabled`」（不让人手敲逗号串）。
- 保存提示：**30 秒内生效**（analysis 侧）。

### 2.9 任务详情（Drawer 720）

- 打开：点行「详情」。只读、无操作按钮（红线 1）。
- 内容：`subject` 大字 + `state` 徽章 + `strength` + `kind`；时间窗（`window_start→end`、`created_at`、`coalesced`、`attempts`、`depth`、`parent_id` 可点回父任务）；`hint` 全量（KV + `suggested_tools` 徽章组 + 未知键走 `max-h-56 overflow-auto` 的 `<pre tabIndex={0}>`）；历史结论（≤10，`verdict` 徽章 + `confidence` + `claimed_by` + 时间 + `summary` 两行 clamp）。
- **tasks 列表/详情不返回 `note` / `claimed_by`** → **不要设计「结束原因」区块**；"为什么 expired/deferred" 当前无法展示，只用 `state` + 时间表达。详情不存在返回 **200 + `{error}`**（不是 404），按 danger 呈现。

### 2.10 队列行 → 详情抽屉：焦点与键盘路径（状态机）

**状态**：`rowIdle` → `rowFocused` → `drawerOpen` → `drawerClosing` → `rowRestored`。

| 步骤 | 触发 | 焦点落点 | 键盘/读屏 |
|---|---|---|---|
| 1 | `Tab` 进表格 | 首个可交互行 | 行 `tabIndex={0}`，`focus-visible:ring-2 ring-ring/40 ring-inset` 可见 |
| 2 | 行上 `Enter`/`Space` | — | `preventDefault()` 开抽屉；整行 `aria-label`=「{对象}，{类型}，{状态}，查看详情」 |
| 3 | 抽屉打开 | 标题（`h2` `tabIndex={-1}`）或首个只读控件 | `role="dialog" aria-modal="true"`；读屏播报标题 |
| 4 | 抽屉内 `Tab`/`Shift+Tab` | 循环（焦点陷阱） | 末尾→首个；首部 Shift+Tab→末尾 |
| 5 | `Esc` 或关闭 | — | 关闭抽屉 |
| 6 | 关闭后 | **回第 2 步触发的那一行**（记 `rowId`） | 行被刷新移除则回落表格容器/工具栏，不丢到 `body` |

- 纯键盘可完成"浏览→看详情→返回"；行内不放大按钮（整行即入口）。

---

## 3. 页面 B：精准抑制 `/config/suppressions`

### 3.1 mode 文案三层（禁裸英文）

| 位置 | 取值 | 说明 |
|---|---|---|
| 徽章（清单列 `w-44`） | 本地短词：「**完全抑制**」/「**仅记录**」 | 4 字，配 `Ban`/`BellOff` + `critical`/`medium` |
| 结论带 / 抽屉整带 | 本地长文案：「**完全抑制 · 不生成事件**」/「**仅记录 · 事件仍生成**」 | 4–6 字，`bg-sev-*-bg` + 左 3px 实心条 |
| 抽屉正文 | **后端 `mode_label` 原文**：「完全不生成事件」/「只不派工（事件保留）」 | 接口原值，照抄，不改造 |

- **任何位置不出现英文 `suppress`/`record_only`**。
- 注意：`mode_label` 接口原值只有那两句短句，**没有长解释**；长解释是前端副行文案。别让实现者以为接口会返回长句。
- `stats.by_mode` 是**裸计数** `{suppress, record_only}`（无标签），前端用本地 map 出中文与颜色。

### 3.2 抑制总览（`SettingsBlock`）

- `Stat × 4`：`active`（生效中）/ `by_mode.record_only`（仅记录中）/ `suppressed_total`（累计抑制量）/ `total`（条目总数）。**第 4 张不要写成"已过期·已撤销"或它们的和**——`expired` 与 `revoked` 会重叠（一条可同时已过期且已撤销），相加即重复计数；正确做法是值用 `total`、hint 写「其中已过期 {expired} · 已撤销 {revoked}」。
- 两列 mode 对照带（左 `suppress` 红底带、右 `record_only` 金底带，各带 icon + 4–6 字，见附录 A）。
- **占比口径**：`by_mode` 只统计 **active 条目**（`enabled && !expired`），故 `by_mode.suppress + by_mode.record_only === stats.active`，**不等于 `stats.total`**；`expired` 与 `revoked` 两个计数**可重叠**（一条可既过期又撤销），不能相加当总数。画占比时**分母只用 `active`**；状态三档之和 ≠ total，差值是 active（§3.4 自洽）。

### 3.3 抑制清单（`SettingsBlock`，卡片去内边距）

- `PanelToolbar`（搜索 `q` / **仅启用** / 刷新 / `＋新建抑制`）+ Table 7 列 + `Pagination`。

**计数与过期口径（硬约束）**
- **`GET /api/suppressions?include_expired=true` 固定显式携带**，不随后端默认值变化（后端默认 `False`，不传就落"total 含过期、items 被过滤"的坑）。
- `enabled_only=true` **只在「仅启用」打开时传**（SQL 层过滤，计数一致）。**唯一完全一致的组合 = `include_expired=true` + 可选 `enabled_only`**。
- **不做「隐藏已过期」**（`include_expired=false` 会复现"共 100 / 本页 30 / 空页"）。"只看未过期且计数干净"需后端 SQL 加 `expires_at > now`（后续项 §10.1）。
- 分页文案用 `total`、行数用 `items.length`，不承诺"显示 total 行"。

**列序（7 列，附录 A）**：`名称(min-w-0；第二行 12px muted：理由 · 界面/智能体 · 置信度 · 证据 n 条) → 模式(w-44) → 条件(min-w-0,truncate+n 维徽章) → 命中数(w-20,tabular,表头 title「按命中数降序：吞得多的最需要复核」) → 状态(w-24) → 到期(w-36) → 操作(w-40)`。

- 条件列 `n 维 < min_match_dims` 时徽章 `medium`。
- 操作：`编辑`(outline) + `撤销`(ghost+`text-sev-critical-fg`)；已撤销给 `恢复`(outline)。**无删除接口**。
- 无「优先级」「创建人」「match JSON」独立列（并入名称第二行 / 抽屉）。

### 3.4 状态列：三档 + 优先级 + 成因 + 到期列独立

`enabled` 与 `expired` 正交，一行可同时"已撤销 + 已过期"。状态列取唯一值，优先级：

> **已撤销（`enabled=false`） > 已过期（`expired`） > 生效中**

| 唯一状态 | 徽章 | 判定 |
|---|---|---|
| 已撤销 | `secondary` | `enabled===false` |
| 已过期 | `outline`+灰 | `enabled===true` 且 `expired===true` |
| 生效中 | `success` | `enabled===true` 且 `expired===false` |

- 剩余 ≤ 3 天：**不加第三徽章**，在「到期」列用 `text-sev-medium-fg` 写「剩 2 天」。
- **成因小字（同行第二行）**：按 `revoke_reason` **`startsWith`** 匹配（保留原标点/空格，勿 trim、勿用等号）：

| 前缀 | 成因 | 色 |
|---|---|---|
| `被真实事件推翻（` | 真阳推翻（抑制挡错了的强信号） | `text-sev-critical-fg` |
| `熔断：` | 熔断 | `text-sev-high-fg` |
| `超出活跃上限 ` | 超上限淘汰（注意"上限"后是**半角空格、无逗号**） | `text-muted-foreground` |
| 其余 / 空串 | 人工撤销（空串写「人工撤销（未填原因）」） | `text-muted-foreground` |

- 抽屉给完整 `revoke_reason`。**不做**顶部"近 7 天被推翻 N 条"汇总（`/stats` 不分因，只能统计当前页=假口径）。
- **「到期」列独立**：即便状态是「已撤销」也照常显示日期/「已过期」，不藏 —— 否则用户把"撤销时间"误读成"到期时间"。

### 3.5 新建 / 编辑（Drawer 720）

顺序（**不能颠倒**）：**① 条件树 → ② 试算卡 → ③ 名称 / 理由 / 备注 → ④ 证据 / 置信度 / TTL → ⑤ 保存**（试算决定"还要不要继续写"，必须在名称之前）。

**① 条件树**（复用 `condition-editor.tsx` 四列网格：字段/操作符/值/删除）
- 字段下拉来自 `/config.allowed_fields`（**12 项唯一来源**）：`src_ip, dst_ip, dst_port, segment, protocol, rule, signature_id, http.uri, http.hostname, user_agent, ja3, fuid`。**`payload/body/content` 不在白名单**（不投毒）；不复用规则页的 5 项字段表。
- 值控件按类型：`dst_port` 强制 `Number()`（数字输入）；`protocol` 强制小写（枚举下拉）；`src_ip` **不接受网段**（用 `segment`）；其余文本。
- 维度计数实时显示「已填 {dims} 维（至少 {N} 维）」，`N = thresholds.min_match_dims`，不写死 2。

**③④ 字段与编辑态只读（关键）**
- **`PUT` 只写 4 个字段**：`match` / `reason_code` / `evidence_refs` / `expires_at`(ttl_days)。
- **编辑态 `name` / `note` / `confidence` 三项全部只读**（不是一个）：`update_item`（`suppression.py:1039-1047`）从头到尾只赋值 `match`/`reason_code`/`evidence_refs`/`expires_at`，**这三项既不写库、也不报错、也不返回提示**——`merged["name"]` 甚至参与了 `validate_item`（`:1036` 传的是 `str(row.name)` 旧名），但 `row.name` 从未被赋值。后果：运维改完备注、保存成功、刷新一看没变，会怀疑是缓存问题反复重试。
- **抽屉里给一行 12px `muted` 说明**：「创建后不可修改：名称、备注、置信度（后端更新接口不落这三项）」；三项控件置只读态（`readOnly`/无编辑入口），**不要做成"可编辑但保存无效"**。**新建态三项均可填。**
- TTL `ttl_days` 1–30（默认取 `effective.default_ttl_days`，默认 14）；`confidence` 0–1（不是 0–100）；`evidence_refs` ≤20 且格式 `es:<index>/<id>`。
- 界面人工创建（`origin=ui`）**不校验** evidence 条数/工具种类/置信度/新现象保护期（这些只对 `origin=agent`）。真正会 400 的只有 5 项：`name`(必填≤128)、`match`(维度<`min_match_dims`/字段不在白名单/过宽)、`reason_code`(∈7 值)、`ttl_days`(1–30)、`evidence_refs`(必须数组)。

**新建重名**
- `name` 唯一冲突未捕获 → 直接 500。**新建前用列表本地查重**（同名提示「名称已存在，换一个」）；遇 5xx 文案「服务异常，若名称重复请更换」。

### 3.6 试算状态机（四出口 + 两段式提交）

**触发**：条件树（`match`）变更 → **debounce 600ms** →（本地维度 < `thresholds.min_match_dims` 则**不发请求**，内联提示「至少 {N} 个独立维度」）→ `POST /preview`（**只校验 `match`**，不校验 name/reason/ttl，所以无需等用户填完名称）。

**状态**：`idle → debouncing(600ms) → trialing → success | degraded | invalid | netfail`

| 出口 | 判定 | 影响面展示 | 结论带 | 保存 |
|---|---|---|---|---|
| `success` | 200，无 `trial.error` | `近 {days} 天 {events} 条命中 · {srcs} 源 · {segments} 网段`；超阈值的格用 `text-sev-critical-fg` | 按 mode | 可点 |
| `degraded` | 200，有 `trial.error`（`events=-1`） | 三格显示「**—**」（**不渲染 `-1`**） | `record_only` 金带 + 警告 | 可点 |
| `invalid` | 400 且 `field_errors[].field==="match"` | 红字挂**条件树下方** | — | 置灰 |
| `netfail` | 网络/5xx | 「试算未能完成，请重试」 | — | 置灰 |

**判据只认 `trial.error` / `events<0`，不要用 `mode` 区分 `success` 与 `degraded`**：`success` 也可能落在 `record_only`（影响面超阈值但试算本身成功），此时结论带是 `record_only` 金带、**但没有警告句**；`degraded` 的金带**必须带**警告句「影响面未知」。两者靠 `mode` 区分一定会判错。

**阈值/字段名（v6 勘误）**：`preview.thresholds` 的键是 `{trial_days, max_hits, max_srcs, max_segments, min_match_dims}`（**不是** `thresholds.trial_max_*`）；`trial`（成功）带 `{days, phenomenon, events, srcs, segments, max_events, max_srcs, max_segments}`，`trial`（失败）只有 `{days, error, events:-1, srcs:-1, segments:-1}`（**无 max_***）。降级态阈值回退 `trial.max_events ?? thresholds.max_hits`。阈值默认 5000/200/8/7 天/2 维（全部从 `thresholds` 读，不硬编码）。

**结论带与变狠**：编辑态显示「当前：{old} → 试算后：{new}」（`ArrowRight`）；仅 `record_only → suppress` 判"变狠"，补后果句「影响面缩小，保存后将不再生成事件」（`text-sev-critical-fg`）；`suppress → record_only` 是变保守，不警告。

**两段式提交（防"旧试算 + 新条件"静默掉流量）**
- **两段定义**：第一段按钮 `保存`（`default` 蓝）＝当前无有效试算结果（未试算 / 变更后未回 / 失败）；第二段按钮 `确认保存 · 完全抑制`（`destructive` 红）或 `确认保存 · 仅记录`（`default` 蓝），**色随 mode**（`suppress` 是 destructive 动作）、`min-w-[10rem]` 防跳动。`trialing` 文案「试算中…」、提交中「保存中…」。
- **提交只发生在第二段**：第一段「保存」点击**只触发试算、不提交**，成功即进第二段，用户再点「确认保存」才写库。**有有效试算结果 ⇒ 一律显示第二段**（无论 auto-trial 还是手点），因此提交永远是一次显式的「确认保存」，不存在"看到结果顺手保存就静默提交"。
- **「重新试算」与「保存」共用同一个 `runPreview()`**（不合并会破掉两段式：只刷 body、footer 停在第一段，用户再点「保存」会按"已有有效结果直接提交"，把最该二次确认的高频路径绕过去）：
  1. 任何一次成功试算（footer「保存」或 Section ②「重新试算」）——`success` 与 `degraded` 都算成功——**一律 `setStage(2)`**；
  2. **`setStage(2)` 幂等**：已在第 2 段时再点「重新试算」→ 成功后**只刷新结论带与按钮文案**，不回退成「保存」（不逼用户再点一次）、不重复滚动定位、不清空已填的名称/理由/证据/TTL；
  3. **mode 翻转三处同帧更新**：`suppress ↔ record_only` 变化时，footer 按钮 `variant`（`destructive` 红 / `default` 蓝）、按钮文案、**footer 左侧 12px mode 小字**必须在同一次渲染里一起更新（只改文案不改色 = 用户按颜色记动作，会把"完全抑制"点成蓝色）。`record_only → suppress`（变狠）时后果句照常出现；
  4. `invalid`/`netfail` 解除后按钮**自动变**「确认保存 · …」，用户一眼看出"现在能提交"。
- **不留例外**：由「重新试算」触发的 `invalid`/`netfail`，footer 保存按钮**同样置灰**——即使 footer 上显示的是上一次成功的结果也不放行（`matchVersion` 已变，那份结果已失效，见下条）。置灰用 `aria-disabled` + 点击守卫，非原生 `disabled`。
- **`match.changed → resetToStage1()`（最关键一条）**：进入第二段后，**只要 `match` 再变更，立即退回第一段并清空 trial**。否则用户看到旧条件结论、却提交新条件 = 本页唯一能"静默掉一整类流量"的路径。名称/理由/证据/置信度/TTL 变更**不**复位（不影响影响面）。
- **"有效试算结果"判定用 `matchVersion`**：`trial.matchVersion !== currentMatchVersion ⇒ 无有效结果`（**不要用 `JSON.stringify` 比较对象**，会误判）；并发 preview 用请求序号守卫（`const seq = ++seqRef.current; … if (seq !== seqRef.current) return;` 丢弃旧响应）。**这是结果错乱的兜底，不是连点问题**——先发的请求可能后到并覆盖新结果，用户会看着过期的影响面点「确认保存」（见 R15）。
- **提交结果与收尾（成功 / 失败两条路，别都落回空表单）**
  - **成功（200）**：关闭抽屉 → 重取清单（保持当前筛选/分页与「仅启用」状态）→ `toast`「已创建 / 已保存」→ **焦点归位到触发元素**（新建回「＋新建抑制」，编辑回该行的操作按钮）。**不是** `resetToStage1()` 停在空表单——那会让用户以为失败。
  - **落库的 `mode` 是服务端重算的，不是你试算看到的那个**：`create_item`（`suppression.py:874-875`）与 `update_item`（`:1042-1044`）都会**自己再跑一遍 `estimate_trial`+`choose_mode`**，**不采用**前端试算结果。所以：
    1. **Toast/成功提示必须报实际档位**，不能只写「已创建」——用响应的 `mode_label`（`_item` 已返回 `mode`+`mode_label`，`:772-777`）：「已创建，按当前影响面为「仅记录」」。
    2. **响应 `mode` ≠ 提交时预览的 `mode` ⇒ 不关抽屉，改常驻警示条**（Toast 会消失，运维看不到等于没提示）：抽屉顶部警示条「**服务端按最新流量重判：实际为「完全抑制」，与你试算的「仅记录」不同**」。此时列表已在后台重取，**初始焦点落在主按钮「接受并关闭」上**。这是本页唯一能让用户"以为按了保守档、实际按了最狠档"的路径，不能用自动消失的提示兜。
       - **`接受并关闭`**（`default`，主按钮、初始焦点）：关抽屉 → 焦点归位到触发元素（新建回「＋新建抑制」）。
       - **`撤销这条`**（**`outline`，不用 `destructive`**——本页 `destructive` 只留给撤销 Dialog 内的确认按钮，见 §3.8）：**打开已有的撤销 Dialog**（`revokeTarget` = 本条，`reason` 预填「服务端重判档位不符，撤销」），复用 `doRevoke()`，**不新增第二个撤销路径**。这样 reason 落库、二次确认、失败提示、焦点归位全走已测代码；撤销成功后与普通撤销完全同一条路径（关抽屉 + 重取）。
       - 不在警示条上做"一键直接撤销"：这一刻用户的预期刚被打破一次（"我以为按了保守档"），警示条上再放一个点一下就生效的破坏性动作，误触概率高于平时。
  - **失败（400）不改变段位**：stage 不是由"失败"驱动的，而是由"**错误是否否定了 `match`**"驱动的，按 `field_errors[].field` 分流：
    1. 错在 **非 `match`** 字段（`name` / `reason_code` / `ttl_days` / `evidence_refs`）→ **留在第 2 段**，错误挂到对应 `Field` 的 `error`（`aria-invalid`+`aria-describedby`、焦点到首个出错字段），`trial` 与 `match` 仍一一对应、**不清空**；用户修正这些字段**不触发** `resetToStage1()`（它们不影响影响面）。
    2. 错在 **`match`**（后端复验比前端严：宽域值、非白名单字段、维度不足）→ 条件树下方红条 + **回第 1 段并清 `trial`**。理由：此时"已展示的影响面"对应的是一份被后端判定为非法的条件，继续挂在第 2 段会让用户以为「这个结果算数」。**语义上等同 `match` 变更**，所以走同一个 `resetToStage1()`，不要新写一套。
  - **5xx / 网络失败**：留第 2 段、**不**清 `trial`，按钮回到「确认保存 · …」可**立即重试、无冷却**（与 `netfail` 同口径）；文案「保存未完成，请重试」。
  - **422 数组**：按 §3.11 第 4 条解析取 `msg`，**不要** `errorText()` 直接渲染（会出 `[object Object]`）。
- **`netfail` 允许无限重试、不加冷却**（规范不设"连续失败 N 次后禁用"之类规则；提交侧 5xx 同上）。
- **degraded 在第二段仍要可见原因**：结论带「影响面未知（试算失败），已按保守档降级为「仅记录」」必须保持可见；抽屉高于视口时在 footer 左侧用 12px 小字重复 mode 文案。
- **trial 过期标记**：抽屉打开期间不自动失效（避免填一半被重算打断），只在 `match` 变更时重算；若"当前 trial 与 match 不同步"（如超过 N 分钟未变但需提示），结论带右上角给 `12px muted`「基于 {N} 分钟前的条件」。
- **`trialing` 语义**：用 `aria-disabled="true"` + `aria-busy="true"` + 点击守卫，**不用原生 `disabled`**（原生 disabled 会把按钮移出 Tab 顺序、读屏宣布"已禁用"）；视觉保持当前 variant 不灰、只换文案；不加 spinner（仓库约定动画只给 degraded/down 状态灯）。**注意**：`trialing` 期间对「重新试算」加 `aria-disabled` 只是**顺带**防连点，竞态正解是上面「`matchVersion` + `seq` 守卫」那条，不能拿它替代。
- **重试入口常驻**：`invalid`/`netfail` 下「重新试算」按钮**必须常驻可见可点**（`netfail` 不是死路）；`invalid` 时点它若维度不足则本地拦截不发请求。

### 3.7 理由（两套，别混）

**新建 `reason_code`：必选、无默认、单选 chip**
- 7 chip 全不预选，顺序同后端 `REASON_CODES`，`manual` 最后。label 吃 `/config.reason_codes`。
- `manual`：chip 文案用短词「**人工创建**」，完整 label「人工创建（界面）」放 `title`（"（界面）"是给智能体看的，直接展示会怪）。
- 未选**不置灰**；点提交**前端先本地校验**：chip 组 `aria-invalid` + 组下红字「请选择一条理由（必选）」+ 焦点到首个 chip；服务端 400（`field==="reason_code"`）只作兜底。

**撤销 `reason`：自由文本可空 + 4 chip 一键填入**
- chip：`误判` / `影响面评估有误` / `证据不足` / `到期后继续抑制`；点 chip 填入（可再编辑），不阻断提交（可空）。

### 3.8 撤销 / 恢复

**撤销 Dialog 560（状态机 `closed → open → submitting → closed`）**
- 标题「撤销抑制「{name}」？」；后果句：「撤销后，命中该条件的流量会重新生成事件并重新派工；**已抑制的历史事件不会补回**（原始数据仍在 ES，可用日志检索回溯）」。
- 原因 `textarea`（≤200，可空，写进 `RevokeIn.reason`）+ 4 chip（§3.7 下半）。
- footer：`取消`(outline) / `撤销`(`destructive`)；`submitting` 时按钮「保存中…」+ 禁用；成功 Toast「已撤销，立即生效」并关闭，焦点回列表行。
- **`revoke` 必须带 body**（`RevokeIn` 无默认）→ **至少发 `{}`**；空 body 会 422。
- **`reason` 对任何条目都能写**：`set_enabled`（`suppression.py:999-1019`）只判行是否存在，**不校验 `expired`、也不校验 `enabled`**，写进去就落库（`revoke_reason` 长度截断 200）。所以**不要**把原因输入框做成"仅生效中条目可填"，也不要按状态禁用/隐藏——已过期、已撤销的条目同样能补记原因。
- 撤销生效：**本机立即、采集/判定侧最迟 45s**（`cache_seconds`；**参数**是 30s，见 §3.9，别混）。
- `destructive` 在本页的用法：**唯一例外**是 §3.6 第二段「确认保存 · 完全抑制」（必须实心红，它就是"要静默掉一整类流量"的那一下，改 `default` 会抹掉风险提示）；其余破坏性动作（本 Dialog 确认按钮）用它，**行内撤销**用 `ghost + text-sev-critical-fg`，警示条上的「撤销这条」用 `outline`（见 §3.6 / R16）。

**恢复**：行内「恢复」直接 `POST /restore`（无 Dialog，低风险可逆），成功 Toast「已恢复，立即生效」。
- **`restore` 不校验是否已过期** → 恢复一条已过期条目后 `enabled=true` 但 `expired=true`、**实际不生效** → 必须提示「该条目已过期，恢复后需同时延长有效期」。

### 3.9 参数与门槛（`SettingsBlock` + Drawer 720，**15 knob**）

- 说明区：`近 {trial_days} 天命中 ≤ {max_hits}、源 ≤ {max_srcs}、网段 ≤ {max_segments} 才会自动「完全不生成事件」；任一超限自动降为「仅记录」。`（键用 `thresholds.max_*`，来自 `/preview` 或 `/config.effective`）
- 参数改 15 项（**当前值取 `effective[key]`**，item 无 `value`），保存提示 **30 秒内生效**（参数走 `runtime_config`，`_CACHE_TTL_SECONDS=30`；**不是** `cache_seconds=45`——45 是条目匹配集合的进程内缓存，见下条）。
- **保存成功提示必须是两句**：「已保存 N 项 —— 参数改动 30 秒内生效（条目增删改是立即生效）」+「**不会自动重判存量抑制条目；但下次编辑某条时会按新门槛重算它的档位**（上调 `trial_max_*` 会让它更容易变成「完全抑制」）」。后半句不是客套：`choose_mode()` 默认返回 `suppress`（`:566`），而 `mode` 只在 `create_item`(`:875`)/`update_item`(`:1044`) 两处写入、**没有批量重算路径**——所以"改了门槛"既不回溯旧条目，又会埋伏在下一次编辑里。三方向后果见 §10.1。
- **生效时间两类（别写成三类，也别把参数算成 45 秒）**：
  1. **抑制条目**（`match`/`enabled`/`expires_at`）增删改 → `invalidate_cache()` 只清**本进程**（`suppression.py:647-649`），采集/判定是**另一进程**、靠 `cache_seconds`（默认 45）TTL 收敛 → 文案「**本机立即生效，采集/判定侧最迟 45 秒收敛**」。
  2. **所有参数**（`suppression.*` 与 `analysis.*`）→ 走 `app/runtime_config.py`，`_CACHE_TTL_SECONDS = 30.0`（:20），`save_config` 调 `invalidate()`（`suppression.py:1198`）→ 保存进程立即，**其他进程 ≤30 秒**。派工参数同样 30 秒，两页口径一致。

### 3.10 命中列熔断预警（单元格强调，非状态）

- 数据源：列表响应顶层 `limits.hit_cap`（默认 20000，逐行可算，不依赖 stats）。
- **熔断是 `hits > hit_cap`（严格大于）** → title 写「**超过**上限 {hit_cap} 将自动撤销」，不写"达上限"。
- 预警：`hits >= 0.8 * hit_cap` → 命中列 `text-sev-medium-fg` + title「接近熔断上限 {hits}/{hit_cap}，超过将自动撤销」。
- **`hits` 是异步计数**：内存累加、每 30 秒 `flush_hits()` 才落库（`_FLUSH_SECONDS=30`）→ 命中列/`last_hit_at` 最多滞后 ~30s，**标注「约 30 秒内更新」，不写"实时"**（否则运维拿它对账会差）。过期行不再参与匹配，`hits` 不再增长，可放心显示静态值。
- **提示载体只用一个：表格正下方一行 12px `muted` 脚注**（列表非空时显示，空态不显示）——「命中数每 30 秒落库一次，约 30 秒内更新」。**不做逐行小字**（30 秒是全列同一个事实，逐行重复 20–50 次会破坏 `tabular-nums` 数字列的对齐与扫读）；**不靠列头 `title`**（hover-only，触屏与键盘不可达，等于不存在）。熔断话术不放脚注，留在命中列 `title`（见上两条）。无障碍关联：脚注给 `id`，命中列头加 `aria-describedby` 指向它，读屏在列头处播报一次。选择依据见 §10.2-4。

### 3.11 表单校验回填 / 错误格式 / 自动刷新暂停

**错误形状四种，分别处理**
1. 400 `{conflict:"field_error", detail, field_errors?}` → 有 `field_errors` 逐字段回填；`field==="match"` 显示在条件树下方。
2. 400 `{detail}` → 顶部/表单内联红字。
3. 404 `{detail}` → `{detail}` 文案。
4. **422 FastAPI `{detail:[{loc,msg,type}]}` 数组** → 解析取 `msg` 拼接中文，**不要 `errorText()` 直接渲染成 `[object Object]`**。

**提交前 clamp**（减少 422）：`ttl_days` 1–30、`evidence_refs` ≤20、`confidence` 0–1、`strength` 0–1、`subject` ≤128、`note` ≤500。

**校验回填**：按 `field` 映射控件（`match`→条件树、`reason_code`→chip 组、`name`→名称、`evidence_refs`→证据区、`ttl_days`→有效期、`confidence`→置信度），红字挂控件下方、`aria-invalid`+`aria-describedby`、焦点移到**第一个**出错字段；**保留已填内容**，修正后即时清除。本地能判的（理由未选、维度不足）**不发请求**，服务端 400 只兜底。

**自动刷新暂停**（防冲掉输入，仅 `/analysis`；抑制页无自动刷新，不涉及）：派工队列的定时重取在下列条件**暂停，恢复后立即补一次且只补一次**：① 任一 Drawer/Dialog 打开；② 抑制新建/编辑处于 `debouncing`/`trialing`；③ 表单 `dirty` 且焦点在表单内。暂停时工具栏显示「自动刷新已暂停（编辑中）」；**手动刷新始终可用**（不受暂停影响）。

**自动刷新周期：`/analysis` 15 秒；`/config/suppressions` 不做列表自动刷新**
- 抑制页**只手动刷新 + 动作后即时重取**（新建/编辑/撤销/恢复成功后 `loadList()`）。**这是设计选择，不是遗漏**，三条理由：① 配置页用户会选行、点撤销、开抽屉，列表在背后自己重排、行位置跳动比"数据旧 60 秒"危险得多——本节暂停条件（抽屉打开/`dirty`/`trialing`）拦不住"鼠标停在一行上准备点撤销"这种情形；② `hits` 本身滞后 ~30 秒落库，60 秒自动刷新的边际收益接近零；③ 参数是 30 秒 TTL 收敛（`runtime_config`），期间自动刷新反而让人误以为"怎么还没变"。
- `/analysis` 15 秒（理由见 §10.2-3）。页签不可见（`document.hidden`）时一并停。
- **恢复必须"立即"补一次、且只补一次**：`setTimeout` 链 + `pendingTickRef` 布尔，**暂停期间不累计**。反例：`setInterval` + `if (modalOpen) return;` 只是"跳过这一拍"，抽屉关掉后还要**再等满 15 秒**才刷——用户看到的是"关了抽屉数据还是旧的"。`setTimeout` 链在恢复时立刻补发并重置计时。
- 距上次成功取数不足半个周期（如提交成功刚重取过）则跳过本次补偿，避免双请求。
- **不做自适应提速**（如"压力 ≥80% 缩到 5 秒"）：节奏抖动 + "为什么这次刷得快"的疑问，收益小于不确定性；要快就点手动刷新。

---

## 4. 三态与错误（两页通用）

两个列表接口失败都返回 200 + `{error, items:[], total:0}`，必须三选一：

| 态 | 判定 | 展示 |
|---|---|---|
| 真没有 | 请求成功、`data` 存在且 `items.length===0` | `EmptyState tone="muted"`（带放宽条件引导） |
| 读取失败 | `data?.error` 存在，或 `PanelError` 捕获失败 | `EmptyState tone="danger"` + 重试；顶部 `PanelError` 错误条 |
| 首屏加载 | 首次请求未回且尚无失败 | `StatSkeleton`(总览) + `TableSkeleton`(列表，列数=真实列数)；**禁止先渲染 0 或"队列为空"** |

- 判失败看 `data?.error`（200 带 error），不要只看 HTTP 状态。
- 分页失败保留上一页数据 + 顶部错误条，不清空已有列表。
- 统一机制：`usePanelErrors` + `loadInto` + `PanelError` + `emptyOrFailed`；不要自己 catch 成 null 再渲染空态。
- 关键空态文案（示例）：队列为空「队列里没有待派线索」（hint 提"线索由检测器按候选规则生成"）；队列读取失败「见上方错误条：后端或 Redis 不可用，不能当成『没有线索』」；抑制清单读取失败「后端异常或库不可用，不是『没有抑制』」；盲区为空 = `bg-sev-ok-bg` 好消息卡。

---

## 5. 响应式矩阵

两页 `width="wide"`，断点 `sm 640 / md 768 / lg 1024 / 2xl 1536 / 1920 / 2200`。

| 区域 | ≥1280 | 768–1279 | <768 |
|---|---|---|---|
| 页面内边距 | `px-6` | `px-4` | `px-4` |
| 总览 `Stat` | 一行 6 / 一行 4 | 两行（3+3） | 单列堆叠 |
| 容量压力条 | 240px、与徽章同行 | 换行第二行 | 独占一行 100% |
| PanelToolbar | 单行 | `flex-wrap` 换行 | 纵向堆叠，主按钮最后 |
| 表格 | 全列 | `overflow-auto` 横滚 | 横滚 + 关键列在左，不隐藏列 |
| Drawer(720) | 720px | 720 / `max-w-[94vw]` | `w-[94vw]` |
| Dialog(560) | 560px | 560 / `max-w-[94vw]` | `max-w-[94vw]` |
| 抑制「名称第二行」 | 同行小字 | 同行 | 折第二行 `text-xs` |

- 触控目标 ≥ 24×24；抽屉 <768 全宽避免溢出。

---

## 6. 无障碍清单

**键盘与焦点**
- 表格整行可点 → `tabIndex={0}` + `focus-visible:ring-2 ring-ring/40 ring-inset`（共享 `TableRow` 已带，勿删）；`Enter`/`Space` 打开（§2.10）。
- Drawer/Dialog：打开焦点入标题/首控件；关闭焦点**回触发元素**；`Esc` 关闭；焦点陷阱。抽屉 `role="dialog" aria-modal="true"`。
- 状态分段/类型 Button 组：`role="radiogroup"`（单选）/`role="tablist"`（视图切换），方向键移动，`aria-checked`/`aria-selected` 正确。

**表单（抑制新建）**
- 理由 chip 组：`role="radiogroup"` + `aria-required="true"` + `aria-labelledby`；未选提交 `aria-invalid="true"` + `aria-describedby` 关联错误。
- 维度不足：`aria-live="polite"` 播报「至少 N 个独立维度」。
- 试算结论带：`aria-live="polite"` 播报 mode 与影响面（避免"保存了才知道结果"）。
- `trialing`：`aria-busy`/`aria-disabled`，不用原生 disabled（§3.6）。
- 值输入 `inputMode`：端口 `numeric`。

**语义与对比度**
- 页 h1 `sr-only` 保留；Section 用 `h2`。
- 颜色不是唯一信息载体：状态/模式徽章都带文字（色弱可辨）。
- 文本对比度 ≥4.5:1（正文）/≥3:1（大字、图标）；表头 `text-foreground` 达标，勿回退 muted；`primary` 不用于状态色。
- 图标按钮（刷新/参数/关闭）`aria-label`；装饰图标 `aria-hidden`。

**动效**：debounce/试算尊重 `prefers-reduced-motion`（沿用 `.st-pulse`）；不持续闪烁。

---

## 7. 高风险交互与降级

| # | 风险 | 触发 | 降级/兜底 | 可见性 |
|---|---|---|---|---|
| R1 | 影响面过大被静默掉一整类流量 | 试算 events/srcs/segments 任一超阈 | `choose_mode` 自动降 `record_only` | 结论带金带 + "降为只不派工" |
| R2 | 试算失败、影响面未知 | preview 异常 `events=-1` | 保守按 `record_only`，**仍可保存** | 三格「—」+「未知」文案（禁写 0） |
| R3 | 抑制挡错（真阳被抑制） | 智能体判 true_positive | 自动撤销覆盖它的抑制 | 状态「已撤销」+ 红字「被真实事件推翻」 |
| R4 | 单条吞量异常（投毒/误配） | `hits > hit_cap`(20000) | 熔断自动撤销 | 命中列 80% 预警 + 撤销成因「熔断」 |
| R5 | 抑制面过大不可复核 | active > `max_active`(200) | 淘汰最早到期 | 撤销成因「超出活跃上限」；新建满额前置红条警告 |
| R6 | 队列满，线索被丢 | pending+deferred ≥ capacity | `superseded`（挤出）或 `dropped_overflow`（丢弃） | 压力条 + 小字计数；人工派工 `dropped` 明确 |
| R7 | "共 N 条但翻页空页" | `include_expired=false` 分页后过滤 | **强制 `include_expired=true` 显式携带** | 分页文案 total / 行数 items.length |
| R8 | 覆盖率计数虚高 | `returned` 是切片前长度 | 一律 `items.length` | — |
| R9 | 把失败当没数据 | 200+`{error,items:[]}` | 三态三选一 | danger 态 + 错误条 |
| R10 | 改名/备注/置信度"保存成功但没变" | `PUT` 只赋值 4 字段，`name`/`note`/`confidence` **三项**静默丢（`:1039-1047`；`validate_item` 用的还是旧名 `:1036`） | **编辑态三项全只读** + 12px 说明「创建后不可修改：名称、备注、置信度」 | 控件只读态 + 说明行 |
| R11 | 新建重名 500 | name unique 未捕获 | 新建前本地查重 + 5xx 文案 | 「名称可能已存在」 |
| R12 | 恢复已过期条目"假成功" | restore 不校验 expiry | 提示「已过期，恢复后需同时延长有效期」 | 行内提示 |
| R13 | 旧试算+新条件 → 静默错压 | 第二段后 match 变更 | `match.changed → resetToStage1()` | 退回第一段、清空 trial |
| R14 | 自动刷新冲掉输入 | 抽屉编辑中触发重取 | 抽屉/试算/dirty 时暂停，手动刷新可用 | 「自动刷新已暂停（编辑中）」 |
| R15 | **旧试算结果覆盖新结果**（"先发后到"） | 两次 preview 并发 | 请求序号守卫：`const seq = ++seqRef.current; const p = await preview(match); if (seq !== seqRef.current) return;`——只认最后一次 | 结论带只反映最新一次条件 |
| R16 | **以为按了保守档、实际按了最狠档** | 服务端 `create_item`/`update_item` **自己重算** `estimate_trial`+`choose_mode`（`:874-875`/`:1042-1044`），不采用前端试算；流量分布或 `thresholds` 已变即翻档 | 用响应 `mode` 与预览 `mode` 比对；**不一致不关抽屉**，改**常驻警示条**（红/金）+ 主按钮 `接受并关闭` / `撤销这条`（后者走**已有撤销 Dialog**，`outline`，非一键）；Toast 一律报实际 `mode_label` | 抽屉顶部警示条（非自动消失的 Toast） |

**原则**：宁可多生成一条事件、多一次提示，也不静默丢数据、不静默抑制。所有"被丢弃/撤销/降级"都要有可见痕迹。

---

## 8. 附录 A：视觉规范引用 + 组件态速览

> **视觉唯一来源**：`docs/ui/analysis-suppression-visual-spec.md`（合并后 528 行；v2–v6 勘误已折进正文、文末勘误表与「按文末为准」的说法均已删除）。**视觉取值（色 token / 字号 / 间距 / 徽章样式）以该文件为准；两者冲突时「行为与状态机」以本规范为准。** 需要跳转时：人工派工 6 种 `result` 提示表见其 §4.8、抑制参数 15 knob 见其 §5.5、字段级错误形状（400/422/重名）见其 §5.6——字段错误形状**以视觉稿 §5.6 表格为准**，本规范 §3.11 只规定"怎么呈现、怎么回填"。

- **布局**：两页 `PageShell width="wide"`、h1 `sr-only`；派工队列 5 Section（②③ 全幅 Card、④ SettingsGrid 双列）、精准抑制 SettingsBoard 3 Block。
- **浮层**：任务详情 Drawer 720 / 派工参数 Drawer 720 / 人工派工 Dialog 560；抑制新建编辑 Drawer 720 / 抑制参数 Drawer 720 / 撤销 Dialog 560。
- **队列状态徽章**：`pending`info・`claimed`low・`done`success・`deferred`medium・`stuck`high・`expired`outline+灰（唯一彩色列，无第 7 种）。
- **mode 三层**：徽章「完全抑制/仅记录」、结论带「完全抑制 · 不生成事件 / 仅记录 · 事件仍生成」、抽屉正文后端 `mode_label`。
- **两段式按钮**：`保存`(default) → `试算中…` → `确认保存 · 完全抑制`(destructive) / `确认保存 · 仅记录`(default)，`min-w-[10rem]` → `保存中…`。
- **共用**：表头 `h-8`+`bg-surface-1`+`text-foreground`、行 36px、hover `bg-brand-50`、全边框、必须落白底；数字 `tabular-nums`、时间 `formatDateTime`、ID/IP `font-mono`；按钮 `size="sm"`，行内危险 `ghost+text-sev-critical-fg`；`destructive` 只用于 Dialog 确认按钮**与 §3.6 第二段「确认保存 · 完全抑制」**（视觉稿 §8 已声明这个唯一例外，别按"仅 Dialog"把它改成 `default`）。

---

## 9. 验收清单

**派工队列**
- [ ] 菜单「派工队列」`/analysis` 无侧边栏、width=wide、h1 sr-only；状态筛选**默认 pending**、单选无第 7 状态。
- [ ] 总览 `Stat × 6` 对应 `stats.by_state`；压力条按 `(pending+deferred)/queue_capacity` 取色；满时文案正确；旁挂 `dropped_overflow`/`superseded` 计数器、不作筛选项。
- [ ] 队列表 8 列顺序正确、状态列唯一彩色、`items.length` 渲染。
- [ ] 人工派工 six 出口文案正确（`dropped/skipped/error` 不冒充"已派工"；`superseded` 不作失败）；失败按 200+`result` 处理。
- [ ] 结论表三筛选（无关键词框）、覆盖率计数用 `items.length`、类别用 `subject_kind`、`kind` bug 已避。
- [ ] 详情抽屉无「结束原因」区块（无 note/claimed_by）；详情不存在按 200+error 呈现；`parent_id` 可点回父。
- [ ] 参数抽屉 **23 knob**、当前值取 `effective[key]`、`candidate_kinds` 全不勾禁止保存；提示「30 秒内生效」。
- [ ] 无「领取/交回/延后」任何入口。

**精准抑制**
- [ ] 清单**显式带 `include_expired=true`**；「仅启用」打开才带 `enabled_only=true`；无「隐藏已过期」；分页 total/items.length。
- [ ] mode 三层文案正确、无裸英文；`by_mode` 分母用 `active`、三档之和≠total 已说明。
- [ ] 状态列三档 + 优先级（已撤销>已过期>生效中）；成因按前缀上色（含"超出活跃上限 "半角空格）；「到期」列已撤销也显示；≤3 天「剩 N 天」。
- [ ] 新建/编辑：条件树字段来自 `allowed_fields`(12)、`payload` 不在内、`dst_port` 数字、`protocol` 小写、`src_ip` 不收网段；**编辑态 `name`/`note`/`confidence` 三项全只读** + 12px 说明「创建后不可修改：名称、备注、置信度」；新建态三项可填；只写 4 字段。
- [ ] **落库 mode 与预览 mode 比对**：Toast 报实际 `mode_label`（不只「已创建」）；**两者不一致时不关抽屉**、改常驻警示条 + 主按钮 `接受并关闭`（初始焦点）/ `撤销这条`（`outline`，走**已有撤销 Dialog** 并预填 reason，非一键直撤）（R16）。
- [ ] 新建重名：本地查重 + 5xx「名称可能已存在」。
- [ ] 试算四出口正确（success/degraded 可保存、invalid/netfail 置灰）；degraded 三格「—」不渲染 -1；阈值键 `thresholds.max_*`、回退 `trial.max_events ?? thresholds.max_hits`。
- [ ] 两段式：第一段 `保存`（只试算不提交）、第二段色随 mode + `min-w-[10rem]`（点它才提交）；**「重新试算」与「保存」共用 `runPreview`，`success`/`degraded` 一律进第二段、已在第二段再试算只刷结论带（幂等，不回退不重滚不清表单）**；**第二段后 `match` 变更立即退回第一段并清空 trial**；mode 翻转时 footer `variant`/文案/左侧 mode 小字**同帧更新**；"有效结果"用 `matchVersion` 判等、并发用 `seq` 守卫（R15）；重算触发的 `invalid`/`netfail` **不留例外**、footer 同样置灰；`netfail` 无限重试不加冷却；degraded 第二段原因可见；`trialing` 用 aria-disabled/aria-busy 非原生 disabled；`invalid/netfail` 下「重新试算」常驻。
- [ ] 理由 7 chip 必选无默认、`manual` chip 短词「人工创建」+ title 全称；未选提交前端拦截。
- [ ] 提交收尾：成功 → **关抽屉 + 重取清单（保留筛选/分页/仅启用）+ toast + 焦点回触发元素**，不停在空表单；400 错在**非 `match`** 字段 → **留第 2 段**、trial 不清、修正不触发复位；错在 **`match`** → 回第 1 段清 trial（复用 `resetToStage1()`，不另写一套）；5xx/网络 → 留第 2 段、可立即重试；422 数组已解析。
- [ ] 撤销：body 至少 `{}`、后果含"历史事件不补回"、4 chip；**原因输入框对任何状态都可用**（`set_enabled` 不校验 `expired`/`enabled`，已过期/已撤销也能补记）；恢复已过期条目给出"需延长有效期"提示。
- [ ] 参数 **15 knob**、当前值取 `effective[key]`、提示两句：「参数改动 **30 秒**内生效（`runtime_config`）；条目本机立即、采集侧最迟 45 秒」+「**不会自动重判存量条目；下次编辑某条时按新门槛重算档位**」；**不把参数写成 45 秒、也不写成立即**。
- [ ] 命中列熔断预警取 `limits.hit_cap`、"超过上限"措辞、"约 30 秒内更新"标注；无第 4 状态。
- [ ] 30 秒滞后提示落在**表格下方 12px 脚注**（非逐行小字、非列头 `title`），列头 `aria-describedby` 指向脚注 `id`；列表空时不显示该脚注。
- [ ] 422 数组错误不渲染 `[object Object]`；提交前 clamp；400 field_errors 逐字段回填 + 焦点首错。

**通用**
- [ ] 三态齐全（200+error 不当空数据）；骨架列数=真实列数。
- [ ] 键盘可完成筛选/翻页/开抽屉/试算提交/理由选择；焦点环可见、抽屉关闭焦点归位。
- [ ] `/analysis` 自动刷新 **15s**（`setTimeout` 链 + `pendingTickRef`，**非 `setInterval`**）：抽屉/试算/dirty 时暂停、页签隐藏时停、**暂停不累计、恢复"立即"补一次且只补一次**；`/config/suppressions` **不做自动刷新**（手动刷新 + 动作后即时重取），且暂停态小字不出现。
- [ ] 状态/模式不只靠颜色；窄屏表格横滚、抽屉 `max-w-[94vw]`、工具栏换行。

---

## 10. 后续项 / 待决

### 10.1 后续（本次不做，需后端）
- 抑制分页 SQL 加 `expires_at > now` 过滤 → 才可提供"只看未过期且计数干净"的筛选。
- `/stats` 给 `revoked` 分因计数 → 才可做"近 7 天被推翻 N 条"真口径汇总。
- PUT 允许改 `name/note/confidence`（需后端补字段）。
- `/coverage` 的 `items[].kind` bug 修正；`/tasks` 补 `note`/`claimed_by`。
- **门槛/回看窗口调整的方向性风险（必读，三个方向三种后果，别写成同一类）**。`choose_mode()`（`suppression.py:552-566`）**默认返回 `suppress`**，只有「试算失败 `events<0`」或「任一维度超限」才降 `record_only`。且 `mode` **只在两处写入**：`create_item`（`:875`）与 `update_item`（`:1044`）——**没有任何批量重算路径**（全仓无 revalidate）。于是：

  | 方向 | 后果 | 需要警告吗 |
  |---|---|---|
  | **上调** `trial_max_hits`/`trial_max_srcs`/`trial_max_segments` | ① 之后**新建**的条目更易落到默认的 `suppress`；② **下一次编辑某存量条目**（哪怕只改理由/有效期）会按新门槛重算，把 `record_only` 翻成 `suppress` | **要**（见下） |
  | **下调**同三项，或**上调** `trial_days`（回看更久 → 计数变大） | 更容易超限 → 更多条目降 `record_only` | 不必，保守方向 |
  | 上调 `newcomer_hours` | 只在 `create_item` 的 G6 门槛用、**只对 `origin=agent`** | 不必，不影响存量 |

- **两条必须写进文案/后续项的事实**：
  1. **改参数不回溯存量条目**：它们的 `mode` 冻结在创建/上次编辑那一刻。"我把门槛放宽了"不会让旧条目自动变化——旧条目**仍按旧门槛继续完全抑制**，这是最容易让人误判系统没生效的地方。
  2. **翻档发生在"下一次编辑"，不是"改参数那一刻"**：用户可能只是来改个理由，保存后档位就变了。编辑抽屉的结论带「当前 → 试算后」+ §3.6 的 `mode` 比对能把这件事**显示出来**，但不能靠用户自己想到去检查。
- **后续项（需后端）**：提供"按当前门槛**重算全部条目**档位"的能力（可选 dry-run）。没有它，"调门槛"这个动作在运维心里和系统实际行为永远对不上：要么以为放宽了其实没生效，要么以为没动却被下一次编辑悄悄翻档。

### 10.2 与「交互契约备忘 v0」的差异 + 2 项定值（均以本规范为准）
1. **mode 文案**：备忘写"只显示 mode_label"；本规范拆三层（徽章本地短词 / 结论带本地长文案 / 抽屉正文后端 mode_label 原文），都禁裸英文。
2. **提交按钮**：备忘曾把"维度不足/试算在途"也算置灰；本规范按视觉口径——结果态**只** `invalid/netfail` 置灰；`trialing` 是 `aria-disabled`+`aria-busy` 的加载态（非原生 disabled）；维度不足"点击提示、不置灰"；未试算点击先试算→二次确认。
3. **自动刷新：`/analysis` 15 秒；`/config/suppressions` 不做自动刷新**（team-lead 终裁，改规范不改代码）。
   - 派工队列是**运营盯屏页**，`pending→claimed→done` 由智能体随时迁移，"积压涨起来了"要能在屏内被看见；15 秒接近人扫一眼压力的感知下限。
   - 抑制页**不做自动刷新**（三条理由写在 §3.11）：配置页的行会被人选中/撤销/开抽屉，背后重排比"旧 60 秒"更危险；`hits` 已滞后 30 秒，自动刷新边际收益近零；参数 30 秒 TTL 收敛期刷新鲜反而造成"怎么还没变"的误解。**手动刷新 + 动作后即时重取**是设计选择。
   - **暂停恢复必须"立即"补一次、只补一次**（`setTimeout` 链 + `pendingTickRef`，暂停期不累计）；`setInterval + if(modalOpen) return` 会把恢复推到下一拍、等于没补——实现现状待 fe-engineer-2 修。
   - **不做自适应**（"压力 ≥80% 提速"）：节奏抖动 + "为什么这次刷得快"，收益小于不确定性。
4. **`hits` 约 30 秒滞后的提示载体：表格正下方一行 12px `muted` 脚注**，文案「命中数每 30 秒落库一次，约 30 秒内更新」；脚注给 `id`，命中列头 `aria-describedby` 指向它；空列表不渲染。
   - 否掉列头 `title`：hover-only，触屏与键盘都不可达，等于不存在。
   - 否掉逐行 12px 小字：这是**全列同一个事实**，逐行重复 20–50 次会把"扫一列数字"变成"扫一列文字"，破坏 `tabular-nums` 对齐，噪音成本 > 提醒收益。
   - 选脚注：一处、常驻可见、与分页/合计同区（运维对账时视线本来就落在那里）；漏读的代价只是"数字偏小 30 秒内的增量"，不会引发错误操作——熔断阈值 `hit_cap` 是万级、命中通常是百级，差两个数量级，看错不会误判熔断。
   - 实现成本：一行 DOM + 一个 `id`，不触及行渲染。

---

## 附录 C：源码依据（勿在实现里硬编码数字）

| 事实 | 位置 |
|---|---|
| `choose_mode`：`events<0`（试算失败）或 `>trial_max_hits`/`srcs>`/`segments>` → `record_only`；**否则默认 `suppress`**（这就是"上调 `trial_max_*` 反而更狠"的根因） | `suppression.py:552-566` |
| `mode` **只在两处写入**：`create_item:875` / `update_item:1044`；routes 的另两处调用（`:164/:167`）是 preview 只读 → **改参数不会批量重判存量条目** | `suppression.py` + `routes/suppressions.py` |
| `estimate_trial` 成功 `events/srcs/segments+max_*`；失败 `{days,error,events:-1,srcs:-1,segments:-1}`（无 max_*） | `suppression.py:540-549 / :538` |
| KNOBS 默认：`trial_max_hits=5000, trial_max_srcs=200, trial_max_segments=8, trial_days=7, min_match_dims=2(floor), hit_cap=20000, max_active=200, cache_seconds=45, default_ttl_days=14` | `suppression.py:130-274` |
| `REASON_CODES` 7 值 | `suppression.py:77-85` |
| `reason_code` 校验字段名 | `suppression.py:820-821` |
| `revoke_reason` 前缀：`熔断：` / `被真实事件推翻（` / `超出活跃上限 `（半角空格无逗号） | `suppression.py:704 / :749 / :898` |
| `hits > hit_cap`（严格大于）触发熔断 | `suppression.py:700` |
| `hits` 攒批 `_FLUSH_SECONDS=30` | `suppression.py:613` |
| **参数生效 = 30 秒**（`runtime_config._CACHE_TTL_SECONDS=30.0`；`save_config` 调 `invalidate()`）→ 抑制参数与派工参数同口径，**不是** `cache_seconds=45` | `runtime_config.py:20 / :76`、`suppression.py:1198` |
| `cache_seconds=45` 只管**抑制条目匹配集合**的进程内缓存（`_active_rows`），与参数 TTL 无关 | `suppression.py:610-618`、`KNOBS` |
| `expired` 动态判定，不置 `enabled=False`（正交） | `suppression.py:792` |
| `list_items`：`enabled_only` SQL 过滤、`include_expired` 分页后过滤、`total` 含过期；`limits.hit_cap` 在顶层 | `suppression.py:934-984` |
| `by_mode` 只统计 active（enabled && !expired）；`expired`/`revoked` 可重叠 | `suppression.py:1064-1074` |
| 抑制 `invalidate_cache` 只清本进程；采集侧靠 `cache_seconds` TTL | `suppression.py:647-649` |
| `update_item` 只写 match/reason/evidence/expires_at，name/note/confidence 丢弃 | `suppression.py:1022-1052` |
| `update_item` **无条件**重算 `trial`/`mode`（改门槛/改条件都会翻档）；`validate_item` 用的是旧名 `str(row.name)` | `suppression.py:1036-1044` |
| `create_item` **自己重算** `estimate_trial`+`choose_mode`，不采用前端试算 | `suppression.py:874-875` |
| `_item` 返回 `mode` + `mode_label`（「完全不生成事件」/「只不派工（事件保留）」） | `suppression.py:772-777` |
| `set_enabled` 不校验 `expired`/`enabled` → 撤销原因对任何条目都能写并落库（截断 200） | `suppression.py:999-1019` |
| 6 状态与容量判满 `pending+deferred >= queue_capacity` | `queue.py:35-42 / :148-168` |
| `enqueue`：挤出 `superseded`（仍返回 new）/ 丢弃 `dropped_overflow` | `queue.py:156-168` |
| `stats`：`budget.queue_capacity`、`counters`（无 doorbell_*）、`by_state` | `queue.py:595-651` |
| `manual_task` 返回 `{ok,result}`，`ok=result∈(new,merged)` | `queue.py:846-865` |
| 列表接口失败 200 `{error,items:[],total:0}` | `analysis.py:129-130` |
| 抑制列表 `include_expired` 默认 `False` | `suppressions.py:87` |
| `preview.thresholds` 键 `{trial_days,max_hits,max_srcs,max_segments,min_match_dims}` | `suppressions.py:170-176` |
| config item 无 `value`（当前值 `effective[key]`）；analysis 23 / suppression 15 knob | `params.py` / `suppression.py:130-274` |
| `coverage.items[].kind` 恒 `"asset"`（bug）→ 用 `subject_kind`；`returned` 切片前长度 | `subjects.py`（fe 核对） |
| `allowed_fields` 12 字段；`payload` 不在白名单 | `suppression.ALLOWED_FIELDS` |
