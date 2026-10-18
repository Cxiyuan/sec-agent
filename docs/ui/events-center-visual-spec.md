# 事件中心 · 视觉规范（Phase 1）

> 适用：新页面 `/events`（一级菜单「事件中心」，位于资产中心之前）
> 分工：**交互与信息架构以 `docs/ui/events-center-ux-spec.md`（Phase 2）为准**；本规范只规定视觉层——颜色、字号、间距、列宽、图表本体、组件容器语言、以及 Phase 2 留白处的视觉取值。凡两文档冲突，改本规范，不改 Phase 2。
> 约束：不新增依赖（图标只用 `lucide-react@0.446` 已有导出）、不改业务逻辑、颜色只用既有 token、图表只用 ECharts。
> 迁移源：`ndr/frontend/components/status-panel.tsx` 第 668–910 行的「命中事件（最近）」卡片。
> 数据契约：`GET /api/detector/hits`、`GET /api/detector/hits/stats?minutes=…`、`/hits/{id}`、`/hits/{id}/ignore`、`/hits/{id}/whitelist`（`docs/api/README.md` + 后端 `ndr/backend/app/detector/hits.py` 已逐行核对）。
> 阅读顺序：第 0 章先纠正四个容易踩的事实，再往下看。

---

## 0. 先对齐四个事实

写规范前把后端实现和前端类型逐行对了一遍，有四处和「看接口文档想当然」不一样。这四条 Phase 2 规范已独立发现（互证关系见每条末尾），本规范把它们作为视觉方案的地基。

### 0.1 迁移的只是「命中事件」卡片，不是整个「威胁事件」区块

`status-panel.tsx` 的「威胁事件」Section 里有**四**张卡片：

| 卡片 | 数据来源 | 迁移？ |
|---|---|---|
| 24h 命中与摘要趋势 | `/api/detector/history?limit=288` | 不动 |
| 24h 严重度分布 | 同上 | 不动 |
| 规则 TOP 15 | 同上 | 不动 |
| **命中事件（最近）** | `/api/detector/hits?limit=50` | **迁走** |

前三张图读的是 `DetectorHistory`（检测器自己的 5 分钟采样），和命中事件表（PG 里的 `HitEvent`）是两套数据。运营中心的「威胁事件」区块**保留三张图、只删一张表**。（与 Phase 2 §10.1「保留不动」互证。）

### 0.2 `hits/stats` 四个数组的真实字段名（三个坑）

后端 `hits.py:641-698` 的返回：

```
{ minutes, bucket_seconds, total, ignored,
  by_source_kind: [{ key, label, count }],
  by_severity:   [{ key, label, count }],
  top_rules:     [{ rule, count }],        ← 字段名是 rule，不是 key/label
  trend:         [{ ts, count }] }
```

**坑一：`by_severity[].label` 不是中文。** `group_by()` 里 `label` 走的是 `SOURCE_LABELS.get(key, key)`，而 `SOURCE_LABELS` 只收录三个来源类别（`hits.py:306-310`）。严重度的 key（`critical`/`high`…）不在表里，所以 `label` 回落成**原始英文 key**。前端必须用 `severityText(key)`，不能用 `label`。（与 Phase 2 §2.1 的契约表同源，那边是从筛选角度写的，这边是从概览角度写的。）

**坑二：`top_rules[]` 的字段名是 `rule`。** 展示要过 `ruleText()` 剥掉「内置-」前缀（`packages/ui/src/lib/format.ts:70`），否则同一页会出现「内置-高频扫描连接」和「高频扫描连接」两个名字。

**坑三：`trend[]` 有断桶，不是等距连续序列。** 后端只把**有事件的桶**放进字典（`hits.py:678-689`），没有补零。直接喂给 ECharts 的类目轴，安静的一个小时会「消失」、左右两根柱子贴到一起，折线形状是假的。**前端必须自己按 `bucket_seconds` 补零**（见 4.1）。（Phase 2 §4.4 已列为「最容易漏的一处」。）

### 0.3 `bucket_seconds` 的边界在 360 分钟，不在「6 小时整」

```python
bucket_seconds = 3600 if window >= 360 else 600   # hits.py:623
```

`>= 360` 是**小时桶**。所以「最近 6 小时」= 360 分钟 = **36 个小时桶**；「最近 3 小时」= 180 分钟 = 18 个 10 分钟桶。文档里「≤6 小时按 10 分钟」这句话在恰好 6 小时时不成立。趋势图的 X 轴标签格式必须由 `bucket_seconds` 决定，不能由用户选的时间范围反推（见 4.1）。

### 0.4 本页没有侧边栏 → Tailwind 视口断点 = 内容断点（全站唯一）

`/events` 是单页一级菜单（和 `/console`、`/behavior` 一样没有 `sidebar`），`PageShell` 走 `ml-0`。**本页的 `lg:` / `xl:` 断点直接等于内容宽度断点**，不需要像配置页那样在心里减掉 240px 侧栏。Phase 2 §9.1 的六档矩阵就是按这个口径算的，本规范的列宽测算沿用同一口径。

---

## 1. 设计原则（本页 5 条）

1. **交互找 Phase 2，视觉找本规范，两边不重复造轮子。** 本规范不重新定义筛选模型、分页、空态四象限、处置流程——那些已有逐字规格。本规范只回答「用哪个 token、多大字号、多宽、什么容器语言」。
2. **与日志检索页同构是硬要求，控件 class 一处都不新造。** 事件中心是并列工作台，用户在 `/logs` 和 `/events` 之间切换时不应重新适应控件长相。筛选区三段式、控件 class、分页算法、Drawer 容器、骨架与空态组件全部与 `logs-panel.tsx` 同源。
3. **颜色只用既有语义 token，本页不新增一个变量。** 严重度 = `sev-*` 三件套，图表主系列 = `chart-1`，来源 chip 选中 = `brand-50` + `primary`。禁用 Tailwind 原色（`bg-red-500` 之类）——原色与主色不在同一明度层级，贴上去像贴纸。
4. **数字一律 `tabular-nums`，时间一律北京时间。** `body` 已全局 `font-variant-numeric: tabular-nums`（`globals.css:212`），表格数字列仍**显式再写一次**——不靠继承，读代码的人看得见这是刻意的；时间全部走 `@shentong/ui` 的 `format*` 系列，不自己 `new Date().toLocaleString()`。
5. **空态、加载态、失败态三句话分开说。** 「窗口内没有命中」= `EmptyState tone="muted"`；「正在读」= 骨架 + `aria-busy`；「读取失败」= `PanelError` + `tone="danger"`。把「正在读」画成「暂无数据」是这个项目以前最大的体验坑，本页不重复。

---

## 2. 信息架构与布局网格

### 2.1 路由与导航（Phase 2 §1.1 已定，此处只补视觉取值）

| 项 | 值 | 视觉侧说明 |
|---|---|---|
| 路由 | `/events`，`match: "/events"` | 单页，无侧边栏 → `PageShell` 走 `ml-0`，正文吃满视口 |
| 页头 icon | `Siren` | `AlertTriangle` 已被 `CONSOLE_SHORTCUTS` 占用、`Radar` 被资产扫描与外连流量占用；`Siren` 当前全项目零使用 |
| 页头 desc | 「命中事件 · 检索 · 详情 · 处置」 | 照 Phase 2 逐字采用 |
| 插入位置 | `NAV_SECTIONS` 第 2 项（`console` 之后、`assets` 之前） | 用户原话「它在资产中心之前」 |

页头一级菜单项**不加角标数字**（如「事件中心 12」）：`hits/stats` 每 24h 变一次、且未忽略口径的数字会随忽略操作跳动，一个不刷新的角标比没有角标更糟。真要有，走铃铛（Phase 2 §1.3 已裁定铃铛不加命中事件条目）。

### 2.2 页面骨架（照 Phase 2 §1.2，本规范补间距与容器语言）

```
/events ── PageShell title="事件中心" width="full"（无侧边栏，正文铺满）
│
├─ PanelError（role="alert"）
├─ 消息槽（成功 role="status" / 失败 role="alert"，与 PanelError 同区互斥）
│
├─ L1 Section「事件概览」      ← /api/detector/hits/stats
│   ├─ description：统计口径 + 数据时间（formatClock）
│   ├─ 3 个 Stat（grid-cols-1 sm:grid-cols-3 gap-3）
│   ├─ 来源三类 chips（可点击钻取）
│   └─ grid grid-cols-1 gap-3 lg:grid-cols-3
│       ├─ 命中趋势 Card（lg:col-span-2，Chart height=224）
│       └─ 事件归类 TOP 10 Card（10 行紧凑列表）
│
├─ L1 Section「筛选条件」      ← extra：数据时间 + 刷新按钮
│   └─ Card：主行 / 字段网格 / 操作行（三段式，照抄 logs-panel）
│
├─ L1 Section「事件列表」      ← extra：第 X / Y 页 + 上一页 / 下一页
│   └─ Card（CardContent p-0）：Table 8 列 或 四象限空态之一
│
├─ Drawer「事件详情」（w-[560px] max-w-[94vw]）
└─ Dialog「确认忽略」（480px）
```

### 2.3 内容宽度：`width="full"`

跟 Phase 2 §9.1 的裁定：宽表工作台，越宽越好，与日志检索页同档。

| 视口 | 可用宽 | 说明 |
|---|---|---|
| 768 | 720 | `px-4`（<768 是 −32） |
| 1920 | 1872 | 无 `max-w` 收口 |
| 2560 | 2512 | 表格区铺满；列宽由内容与 `max-w-*` 决定，不强行拉宽 |

**宽屏上的视觉后果（必须知道，不是 bug）**：`table` 是 `w-full` + 自动布局，2560 上多出的 640px 会按内容权重分给各列。`事件归类` 与 `目的` 两列有 `max-w` 上限（20rem / 24rem）不会被拉长，**富余主要落进时间 / ID / 来源 / 严重度 / 请求方 / 次数六列的单元格尾部空白**。这是「单元格常态空白」，不是「被拉长的控件」——与配置管理页规范的同一结论。不要为了消它去给这些列写 `text-center` 或加分隔线，那会让窄屏更乱。

### 2.4 间距标尺

| 关系 | 值 | 说明 |
|---|---|---|
| 页面段与段 | `space-y-6`（24px） | `PageShell` 子容器默认，不改 |
| Section 标题 → 内容 | `space-y-3`（12px） | `Section` 内置 |
| Stat 卡之间 | `gap-3`（12px） | |
| 概览：chips → 图组 | `space-y-3`（12px） | 同组内图与图的间距也是 `gap-3` |
| 筛选区三段之间 | `space-y-2`（8px） | 照抄 `logs-panel.tsx:245`（`CardContent className="space-y-2 pt-4"`） |
| 表格单元格 | `px-3 py-2` | `TableCell` 默认，行高约 37px |

本页间距只有 **4 / 8 / 12 / 24 四档**，不引入 16px 档——档位一多，间距就失去节奏感，读的人再也说不清"为什么这里松一点"。

### 2.5 字号阶梯（本页全部用到的档位）

| 用途 | 类 | 值 |
|---|---|---|
| Section 标题 | `text-base font-medium`（`Section` 内置） | 16 |
| 卡片标题 | `text-sm font-medium`（`CardTitle` 内置） | 14 |
| 表格正文 | `text-13`（`Table` 内置） | 13 |
| Stat 数值 | `text-28`（`Stat size="lg"` 内置） | 28 |
| 表头 / 标签 / hint / chips | `text-xs` | 12 |
| 筛选控件（Input / select） | `text-sm` | 14 |
| 证据字段 / 抽屉字段网格 | `text-xs` | 12 |

**没有 `text-11`、`text-14`、`text-15`、`text-16`**——这几个不是合法 Tailwind 类名（14px 一律写 `text-sm`，13px 用配置里自定义的 `text-13`，28px 用 `text-28`）。这是配置管理页规范踩过一次的坑，核对表里单列一条。

---

## 3. KPI 卡片组（Phase 2 §5.1 已定 3 个，此处补视觉取值）

```tsx
<div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
  <Stat label="事件总数" value={fmt(stats?.total ?? 0)} hint="窗口内 · 不含已忽略" />
  <Stat label="高危及以上" value={fmt(highUp)} tone="high" hint={`严重 ${fmt(crit)} · 高危 ${fmt(high)}`} />
  <Stat label="已忽略" value={fmt(stats?.ignored ?? 0)} hint="默认列表不显示 · 勾选『包含已忽略』可查" />
</div>
```

| 项 | 规定 |
|---|---|
| `tone` | 「高危及以上」固定 `high`（Phase 2 §5.1 逐字）。**不随数据改 `critical`**——tone 描述这一项的性质，不是当前警铃；真有严重事件时数字本身和列表里的红色徽章已经够响 |
| hint | 逐字照 Phase 2 §5.1，不自己改写。两条 hint 分别是 R3（口径分裂）和 B2（行消失误解）的修法，改一个字就失效 |
| 空值 | stats 未返回时 value 显示 `—`（不是 `0`）——「没读到」和「真的是 0」是两件事 |
| `fmt` | `(n) => n.toLocaleString("zh-CN")`；千分位让 4 位以上的数字可读 |
| 骨架 | `<StatSkeleton count={3} />`（内置 `grid-cols-1 sm:grid-cols-3`，与真实行同构，出数不跳版） |

**「中危 / 低危 / 信息」在概览区不可见**：`by_severity` 里这三级只进筛选下拉，不进任何卡片和图。这是 Phase 2 的刻意取舍（三个数说清"有没有事"就够），本规范遵从；如果后续要补，正确位置是来源 chips 行旁边加一行严重度 chips（同构、可钻取），**不是再加一张饼图**——饼图和 chips 是同一数据的两种画法，多一个就多一处要同步的口径。

---

## 4. 图表规范（本页只有一张图）

Phase 2 §5.3 已定：概览区一张趋势图 + 一个 TOP 10 **列表卡**（不是图）。本规范只规定趋势图的本体，以及 TOP 10 卡的视觉语言。

### 4.0 文件归属：新建 `event-charts.ts`，只放一个工厂

```ts
// ndr/frontend/components/event-charts.ts
import type { EChartsOption } from "echarts";
import { chartTokens, formatClock, formatDateTime, formatHourSlot } from "@shentong/ui";
import { AXIS, GRID, valueAxis } from "@/components/status-charts";
// 类型定义在 lib/api.ts，lib/hits.ts 再导出（Phase 2 §10.2）；import 哪个都行，这里取定义处
import type { HitTrendPoint } from "@/lib/api";

export function hitTrendOption(points: HitTrendPoint[], bucketSeconds: number): EChartsOption
```

| 决定 | 理由 |
|---|---|
| 新建文件，不塞进 `status-charts.ts` | `status-charts.ts` 文件头把自己定义为「总览页的图表选项」（922 行）；且面板与图表文件 1:1 配对（`status-panel` ↔ `status-charts`，`events-panel` ↔ `event-charts`），读的人不用跳 |
| 共享常量从 `status-charts.ts` **加 `export`** 后 import | 只加 `AXIS` / `GRID` / `valueAxis` 三个（本页一张图用不到图例和横条栅格）。「栅格/图例/字号只有一套」是 `status-charts.ts:31-32` 立的规矩，新文件遵守而不是绕过 |
| 不抽 `chart-kit.ts` | 一个调用方不值得为它动 15 张图依赖的文件；出现第二个消费方再抽 |
| 只有**一个**工厂 | Phase 2 只规定一张图。别为了"以后可能加图"预写 `severityShareOption` / `sourceKindOption` —— 死代码比缺代码更贵 |

### 4.1 命中趋势（`lg:col-span-2`，`Chart height={224}`）

| 项 | 规定 |
|---|---|
| 图表类型 | `line` + `areaStyle: { opacity: 0.12 }`，`lineStyle.width: 1.8`，颜色 `t.series[0]`（= `--chart-1`，与运营中心「24h 命中与摘要趋势」同色同形） |
| **补零** | 见下，必须做 |
| X 轴标签 | `bucketSeconds >= 3600` → `formatHourSlot(ts)`（`09-25 21:00`）；否则 → `formatClock(ts)`（`21:30`）。**由 `bucket_seconds` 决定，不由用户选的范围决定**（0.3 节） |
| X 轴其他 | `boundaryGap: false`、`axisLabel: { interval: "auto" }`（7 天 = 168 个小时桶，让 ECharts 自己抽稀；Phase 2 §4.4 建议约每 12 桶一个，`auto` 会给出接近的结果，不手写 `interval: 12`） |
| 数据点 | `showSymbol: xs.length < 40`、`symbolSize: 4`（沿用 `status-charts.ts:294` 的同一阈值） |
| Y 轴 | `valueAxis({ name: "条", nameTextStyle: { color: t.axis } })` |
| tooltip | `trigger: "axis"`，formatter 三行：桶起点全精度时间（`formatDateTime`）、`{n} 条`、`桶长 1 小时 / 桶长 10 分钟` |
| grid | `GRID`（单系列不挂图例——`severityOption:328` 已立过这个先例：图例是重复信息） |
| **不用 `smooth`** | `smooth: true` 会让折线在峰谷之间鼓起来，10 分钟桶下尤其明显。安全趋势里"突然掉到 0"和"缓慢下降"是两件事，视觉上必须可分辨 |

**补零实现契约**（0.2 坑三的修法）：

```ts
const step = Math.max(60, bucketSeconds) * 1000;
const first = Date.parse(points[0].ts);
const last = Date.parse(points[points.length - 1].ts);
const byBucket = new Map(points.map((p) => [Date.parse(p.ts), p.count]));
const filled: Array<{ ts: number; count: number }> = [];
for (let t = first; t <= last; t += step) filled.push({ ts: t, count: byBucket.get(t) ?? 0 });
```

`points` 已由后端按 `ts` 升序排好（`hits.py:698` 的 `sorted`），前端不再排序。`trend` 为空数组时调用方走空态，不进这个函数（约定与 `status-charts.ts:26` 一致：空数据由调用方判断）。

**「不限」档不实现**（team-lead Q-A 裁决；初稿曾保留、Phase 2 §4.3 曾按方案甲留了口子）：后端 `hits.py:621` 会把 `minutes=0` 静默改写成 1440——用户选了「不限」，看到的仍是 24 小时口径，UI 上却承诺了「全部历史」，这是口径分裂。最终档位 **1h / 6h / 24h / 7d，默认 24h**，stats 与列表同一个 `minutes`，概览标题随窗口变（Phase 2 §5.1）。Phase 3 不写「不限」option，也不写它的降级文案。

### 4.2 事件归类 TOP 10（1/3 宽，`Card` + 10 行紧凑列表）

Phase 2 §5.3 已定它是**列表卡不是横条图**，理由（可点击钻取 + 规则名是中文长名、横条图的类目轴要截断）成立，本规范遵从并补视觉语言：

```tsx
<Card>
  <CardHeader className="pb-2">
    <CardTitle className="flex flex-wrap items-center gap-2">
      事件归类 TOP 10
      <span className="text-xs font-normal text-muted-foreground">点一行按它筛选</span>
    </CardTitle>
  </CardHeader>
  <CardContent>
    {(stats?.top_rules?.length ?? 0) > 0 ? (
      <div className="divide-y divide-border-subtle">
        {stats.top_rules.map((it) => (
          <button
            key={it.rule}
            type="button"
            onClick={() => { setField("rule", it.rule); void run(0); }}
            className="flex w-full items-center gap-2 px-1 py-1.5 text-left transition-colors hover:bg-brand-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 motion-reduce:transition-none"
          >
            <span className="min-w-0 flex-1 truncate text-13" title={ruleText(it.rule)}>
              {ruleText(it.rule)}
            </span>
            <span className="shrink-0 text-13 tabular-nums text-muted-foreground">{fmt(it.count)}</span>
          </button>
        ))}
      </div>
    ) : (
      <EmptyState size="compact" tone="muted" title="窗口内没有事件" />
    )}
  </CardContent>
</Card>
```

| 项 | 规定 |
|---|---|
| 行元素 | 原生 `<button type="button">`（不是 `div` + onClick——键盘可达是 B4 的修法，见 Phase 2 §7.2 同款纪律） |
| 分隔 | `divide-y divide-border-subtle`（行分隔用 subtle，不用 `border`） |
| hover | `hover:bg-brand-50`，与 `TableRow` 的 hover 同色——同一套「可点」语言 |
| 规则名 | `ruleText()` + `truncate` + `title` 全量；`flex-1 min-w-0` 保证它收缩、数字不缩 |
| count | `shrink-0 tabular-nums text-muted-foreground`，右对齐由 flex 的天然顺序承担 |
| 空态 | `EmptyState size="compact" tone="muted"`（Phase 2 §5.3 逐字） |
| 卡片标题右侧 | 「点一行按它筛选」`text-xs font-normal text-muted-foreground`——钻取能力必须被说出来，否则没人发现这卡可点 |

**不用 ECharts 画这张**：`Chart` 的 `onEvents` 点击拿到的是 `params.data`，要回传筛选值得给每个数据项挂 `key`；而列表卡的 `<button>` 天然带 `onClick`、键盘、focus ring，一分钱额外成本都没有。同一数据两种可点实现，选便宜的那个。

### 4.3 来源三类 chips（Phase 2 §2.5 / §5.2 已定，此处补视觉取值）

```tsx
<div className="flex flex-wrap items-center gap-1.5">
  <span className="text-xs text-muted-foreground">按来源：</span>
  {SOURCE_KINDS.map(([key, label]) => {
    const n = countOf(by_source_kind, key);
    const active = form.sourceKind === key;
    return (
      <button
        key={key}
        type="button"
        aria-pressed={active}
        onClick={() => { setField("source_kind", active ? "" : key); void run(0); }}
        className={cn(
          "rounded-full border px-2 py-0.5 text-xs transition-colors motion-reduce:transition-none",
          active
            ? "border-primary bg-brand-50 text-primary"
            : "border-border-subtle text-muted-foreground hover:border-primary/50 hover:text-foreground",
          n === 0 && !active && "opacity-60",
        )}
      >
        {label} · {fmt(n)}
      </button>
    );
  })}
</div>
```

| 项 | 规定 |
|---|---|
| 形状 | `rounded-full border px-2 py-0.5 text-xs`（约 22px 高）——与 `logs-panel.tsx:436` 的 `log_types` chips 逐字一致 |
| 选中三信号 | `border-primary` + `bg-brand-50` + `text-primary`。**不能只靠颜色**（色弱用户），边框/底色/文字三处同时变 |
| 未选中 | `border-border-subtle text-muted-foreground`；hover 只加深边框和文字，**不换底色**（避开 `--accent` 与 `--brand-50` 同值的「悬停=选中」老问题） |
| 三类全量渲染 | `count=0` 也渲染（Phase 2 §2.5），用 `opacity-60` 置灰但仍可点——让用户知道系统有三类来源，不是只有出数据的这类 |
| 标签 | 用后端给的 `by_source_kind[].label`（这三个**是**中文，与严重度相反，见 0.2 坑一）；值仍传英文 key |
| 引导词 | 行首「按来源：」`text-xs text-muted-foreground`，与 chips 同一行 |

---

## 5. 筛选条件区（Phase 2 §2 已定三段式，此处只补 class 与视觉纪律）

### 5.1 结构与控件 class：照抄 `logs-panel.tsx` 第 244–443 行

```tsx
<Section
  title="筛选条件"
  extra={/* 数据时间 + 刷新按钮，见 5.4 */}
>
  <Card>
    <CardContent className="space-y-2 pt-4">
      {/* 主行 */}
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-muted-foreground">
          时间范围
          <select className="mt-1 block h-9 rounded-sm border border-input bg-surface-2 px-2 text-sm text-foreground" …>
            <option value={60}>最近 1 小时</option>
            <option value={360}>最近 6 小时</option>
            <option value={1440}>最近 24 小时</option>
            <option value={10080}>最近 7 天</option>
            {/* 时间范围最终四档：1h/6h/24h/7d，默认 24h；「不限」已按 Q-A 裁决砍掉（后端 minutes=0 会被静默改成 1440） */}
          </select>
        </label>
        <label className="min-w-[260px] flex-1 text-xs text-muted-foreground">
          关键字（IP / 账号 / URI / UA / 证据全文）
          <Input className="mt-1" placeholder="唯一能搜进证据的维度" … />
        </label>
      </div>
      {/* 字段网格：四个筛选位（不是 `Field` 组件，见 5.2） */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        …来源 / 严重度 / 事件归类 / IP 四个筛选位…
      </div>
      {/* 操作行 */}
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={() => void run(0)}><Search … />搜索</Button>
        <Button size="sm" variant="outline" onClick={reset}><RotateCcw … />重置</Button>
        <label>排序<select … /></label>
        <label>每页<select … /></label>
        <label>包含已忽略<input type="checkbox" … /></label>
        <span className="ml-auto text-xs tabular-nums text-muted-foreground">共 {total} 条{includeIgnored ? "（含已忽略）" : ""}</span>
      </div>
    </CardContent>
  </Card>
</Section>
```

**一处都不新造**：控件 class、label 包裹式关联（`<label>` 包控件，隐式关联无需 id/htmlFor）、`mt-1` 的间距、`min-w-[260px] flex-1` 的关键字框，全部与日志页同源。Phase 2 §2.3 已逐字规定，本规范不重复，只强调**执行时对着抄，不要"顺手统一一下"**——两页控件长得不一样，用户切换工作台时要重新适应位置。

### 5.2 本页不用的东西（明确记录，防返工）

| 不用 | 原因 |
|---|---|
| `Field` / `FieldGrid` 组件 | Phase 2 §2.3 已裁定：那两个服务配置管理页的表单（span 档位、hint、校验错误），事件中心是「即填即走的工作台条」，用 `<label>` 包裹式 |
| `PanelToolbar` | 同上；工具条是配置页卡片内的语言 |
| `Segmented`（分段控件） | 本规范初稿曾提议用它做时间范围，**已撤回**：日志页用 select，一致性优先是硬要求。不为一个控件在全站造出第二种"离散选择"的语言 |
| 页面级粘性筛选条 | 初稿曾提议，**已撤回**：Phase 2 的三段式 + Section 分区更符合"筛选条件也是一块内容"的心智，且与日志页同构 |
| 高级筛选折叠 | 初稿曾提议把事件归类/IP 藏起来，**已撤回**：六个维度一屏放得下（Phase 2 §1.2），折叠反而多一步 |

### 5.3 「包含已忽略」用 checkbox 还是 Switch

**用 `<input type="checkbox">`**（日志页现式，Phase 2 §2.3 逐字照抄），**不用共享的 `Switch` 组件**。

`Switch` 的语义边界写在它自己的注释里（`switch.tsx:16-19`）：「表达控件状态，不表达业务状态」。而「包含已忽略」切的是**查询口径**——勾上之后列表内容、`共 N 条` 的口径标注都会变，这是业务语义不是控件开合。checkbox 打勾 = "给这次请求加一个参数"，读起来更准。

### 5.4 刷新按钮与数据时间戳（Phase 2 §8.3 已定，此处补 class）

放在「筛选条件」Section 的 `extra`（与数据时间戳并排）：

```tsx
extra={
  <div className="flex flex-wrap items-center gap-2">
    <span className="text-xs tabular-nums text-muted-foreground">数据时间 {formatClock(updatedAt)}</span>
    <Button size="sm" variant="outline" disabled={loading} onClick={() => void run(offset)}>
      <RotateCw className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
      {loading ? "刷新中…" : "刷新"}
    </Button>
  </div>
}
```

| 项 | 规定 |
|---|---|
| 时间戳 | `text-xs tabular-nums text-muted-foreground`；等宽数字让每次刷新的跳变不抖 |
| 按钮 loading | 文字变「刷新中…」+ `disabled` 防连点（Phase 2 §8.2） |
| **不做自动轮询** | Phase 2 §8.3 的三条理由成立（处置工作台不是盯屏仪表 / 翻页状态会被冲掉 / 状态可见比"不让你关"更尊重操作者）。本规范初稿的 30 秒轮询方案**已撤回**。想看新事件的人留在运营中心，那儿的 5 秒轮询为其余 11 个接口保留 |
| 刷新不清 offset / 表单 | 按当前查询态重取 |

---

## 6. 事件表格（Phase 2 §7.2 / §9.2 已定 8 列 + 整行可点，此处补列宽与单元格视觉）

### 6.1 列定义（顺序即 Phase 2 §9.2 的顺序，与运营中心原表一致）

| # | 列名 | 字段 | 宽度类落点 | 对齐 | 说明 |
|---|---|---|---|---|---|
| 1 | 最近时间 | `last_seen ‖ created_at` | `w-[6rem]` → `<TableHead>` | 左 | `formatShort`（`09-25 21:30`），`title` 给 `formatDateTime` 全精度，`whitespace-nowrap` |
| 2 | 事件 ID | `id` | `w-[5.5rem]` → `<TableHead>`；`max-lg:sr-only` **同时给** `<TableHead>` 与 `<TableCell>` | 左 | `id.slice(0,8)` + `font-mono text-xs` + `title` 全值 |
| 3 | 事件归类 | `rule` | `max-w-[20rem]` + `min-w-0` → **同一批** `<TableCell>`，`th` 只放列名 | 左 | `ruleText()` + 状态徽章，`truncate` |
| 4 | 来源 | `source_label` | `w-[5.5rem]` → `<TableHead>`；`max-lg:sr-only` **同时给** `th` 与 `td` | 左 | 后端直出中文 |
| 5 | 严重度 | `severity` | `w-[4.5rem]` → `<TableHead>` | 左 | `severityBadge()` |
| 6 | 请求方 | `client ‖ src_ip` | `max-w-[9rem]` + `min-w-0` → **同一批** `<TableCell>` | 左 | 含「经 {via}」标注 |
| 7 | 次数 | `count` | `w-[4rem]` → `<TableHead>` | **右** | `tabular-nums` |
| 8 | 目的 | `dst_pairs` | `max-w-[24rem]` + `min-w-0` → **同一批** `<TableCell>`；`max-md:sr-only` **同时给** `th` 与 `td` | 左 | `slice(0,3)` + 「等 N 个」，`truncate` + `title` |

**固定列（最近时间/事件 ID/来源/严重度/次数）的宽度类写在 `<TableHead>` 上，不写在 `<TableCell>` 上**：`table` 是自动布局，`td` 上的 `w-*` 会被内容优先权覆盖、只有 `th` 上的宽度能稳定成立。表头还要传 `scope="col"`（Phase 2 §11.2；`TableHead` 透传 `ThHTMLAttributes`，不需要改组件）。

**三个截断列（事件归类/请求方/目的）走另一套：`min-w-0` 与 `max-w-*` 必须写在同一个 `<TableCell>` 上，`th` 只放列名、不放宽度类**。table 单元格默认 `min-width: auto`，一条长字符串会把列顶得比上限还宽，`truncate` 看着写了却不生效——这是"截断为什么不截"的头号原因。`min-w-0` 去掉这条默认值，同一元素上的 `max-w-*` 才真正咬得住；分居 `th`/`td` 时，`td` 的 max-content 贡献照样把列顶宽，上限形同不存在。**此规则与 Phase 2 §9.3 逐字同源**，实现以那边为准，本规范不另立说法。

### 6.2 单元格内容规则

```tsx
{/* 1 最近时间 */}
<TableCell className="whitespace-nowrap" title={formatDateTime(row.last_seen || row.created_at)}>
  {formatShort(row.last_seen || row.created_at)}
</TableCell>

{/* 2 事件 ID：max-lg:sr-only 必须同时写在 th 与 td 上，只藏 td 表头还在 */}
<TableCell className="max-lg:sr-only font-mono text-xs text-muted-foreground">
  <span title={row.id}>{row.id.slice(0, 8)}</span>
</TableCell>

{/* 3 事件归类 + 状态徽章：名字与徽章同一行，名字可截断、徽章不缩；min-w-0 与 max-w 同在 td 上（6.1） */}
<TableCell className="min-w-0 max-w-[20rem]">
  <span className="flex min-w-0 items-center gap-1">
    <span className="truncate" title={ruleText(row.rule)}>{ruleText(row.rule) || "—"}</span>
    {row.ignored ? <Badge variant="outline" className="shrink-0">已忽略</Badge> : null}
    {row.whitelist_id ? <Badge variant="outline" className="shrink-0">已加白</Badge> : null}
  </span>
</TableCell>

{/* 5 严重度 */}
<TableCell>{severityBadge(row.severity)}</TableCell>

{/* 6 请求方：真实请求方优先，经中继要标注；min-w-0 与 max-w 同在 td 上（6.1） */}
<TableCell className="min-w-0 max-w-[9rem]">
  <span className="block truncate" title={row.client_source === "xff" ? "来自可信代理头（XFF/X-Real-IP）" : "直连对端"}>
    {row.client || row.src_ip || "—"}
  </span>
  {row.via ? (
    <span className="block truncate text-xs text-muted-foreground" title={`这一跳经过 ${row.via}（代理/中继），它不是发起方`}>
      经 {row.via}
    </span>
  ) : null}
</TableCell>

{/* 7 次数 */}
<TableCell className="text-right tabular-nums">{row.count}</TableCell>

{/* 8 目的：min-w-0 与 max-w 同在 td 上（6.1）；max-md:sr-only 也要给对应的 th */}
<TableCell className="max-md:sr-only min-w-0 max-w-[24rem] truncate text-muted-foreground" title={row.dst_pairs?.join("、")}>
  {row.dst_pairs?.length
    ? row.dst_pairs.slice(0, 3).join("、") + (row.dst_pairs.length > 3 ? ` 等 ${row.dst_pairs.length} 个` : "")
    : "—"}
</TableCell>
```

四条从迁移源**保留**的既有逻辑，不许在重写时丢：

1. `client || src_ip` —— 中继链路上 `src_ip` 是代理/WAF 自己，真实请求方优先（`status-panel.tsx:740`）。
2. `经 {via}` 两行结构 —— 「这一跳经过谁」和「谁发起的」必须分开，否则会把代理当成攻击源。
3. `dst_pairs.slice(0, 3)` + 「等 N 个」 —— `dst_pairs` 是 `IP:端口` 成对存的，分开的 `ips`/`ports` 看不出谁配谁；超过 3 个时给总数，不无限撑宽列。
4. `severityBadge` 走 `severityText` + `severityVariant`（共享库唯一来源）—— `status-panel.tsx:242-245` 记录了「紧急 vs 严重」那次跨页不一致，别再发明一套。

### 6.3 整行可点（Phase 2 §7.2 已定，此处补 hover 与焦点视觉）

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

| 项 | 规定 |
|---|---|
| 行 hover | `TableRow` 内置 `hover:bg-brand-50`（`table.tsx:43`），直接用，不另写 |
| 焦点环 | 行 `tabIndex={0}` 必须配 `focus-visible` 环，否则键盘用户看不到焦点在哪行。**这是要改 `table.tsx` 的一处**：给 `TableRow` 的基础 class 加 `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-inset`（与 `Input`/`Switch` 同一款 ring）。全站表格行一起受益，`logs-panel` 的行也会因此获得焦点环（Phase 2 §13 D2 同批回填） |
| 无操作列 | 行尾不放「详情」按钮——运营中心的 9 列迁移后变 8 列。本规范初稿曾保留操作列，**已撤回**（一致性优先，整行可点是日志页的既有语言） |
| `cursor-pointer` | 只在整行可点的表格上用；不可点的表格（配置页那些）不要加 |

### 6.4 窄屏藏列：`sr-only` 不用 `hidden`

照 Phase 2 §9.2 的矩阵（`max-lg:sr-only` / `max-md:sr-only`）。`hidden` 会让读屏整列丢失，`sr-only` 保留语义与可达性且不占布局——与配置管理页规范的 Q8 同款理由。

**藏列类必须同时写在 `<TableHead>` 与 `<TableCell>` 上，实现规格以 Phase 2 §9.2 为准**（列定义里每个隐藏档位一个类名常量，`th` 与 `td` 用同一个值）：`sr-only` 是 `position: absolute` 把自己抽离文档流，只藏 `td` 的话表头单元格还占着那一列，窄屏看到的是一列没有头的数据。本规范不另立写法。

| 列 | ≥1024 | 768–1023 | <768 |
|---|---|---|---|
| 最近时间 | 显 | 显 | 显 |
| 事件 ID | 显 | `max-lg:sr-only` | `max-lg:sr-only` |
| 事件归类 | 显 | 显 | 显 |
| 来源 | 显 | `max-lg:sr-only` | `max-lg:sr-only` |
| 严重度 | 显 | 显 | 显 |
| 请求方 | 显 | 显 | 显 |
| 次数 | 显 | 显 | 显 |
| 目的 | 显 | 显 | `max-md:sr-only` |

横向滚动是兜底不是策略（`Table` 自带 `overflow-auto`，`table.tsx:15`），**不做卡片式折叠**。

### 6.5 分页条（Phase 2 §3 已定，此处补 class）

放「事件列表」Section 的 `extra`，与 `logs-panel.tsx:448-472` 逐字一致：

```tsx
extra={
  <div className="flex flex-wrap items-center gap-2 text-xs tabular-nums text-muted-foreground" aria-live="polite">
    <span>共 {total} 条{includeIgnored ? "（含已忽略）" : ""}</span>
    <label className="flex items-center gap-1">
      每页
      <select className="h-8 rounded-sm border border-input bg-surface-2 px-2 text-sm text-foreground" …>
        {[20, 50, 100, 200].map((n) => <option key={n} value={n}>{n} 条</option>)}
      </select>
    </label>
    <span>第 {page} / {pages} 页</span>
    <Button size="sm" variant="outline" disabled={offset <= 0 || loading} onClick={…}>上一页</Button>
    <Button size="sm" variant="outline" disabled={offset + size >= total || loading} onClick={…}>下一页</Button>
  </div>
}
```

- `aria-live="polite"` 只给这一个容器（Phase 2 §11.6）：翻页后数字变了，读屏用户需要被告知；全页播报会轰炸。
- 「每页」放这里**不放筛选条**——它只作用于列表，和页码是同一组决策。

---

## 7. 详情与处置（Phase 2 §6 / §7 已定流程，此处补视觉语言）

### 7.1 两个浮层的分工

| 浮层 | 容器 | 宽度 | 用途 |
|---|---|---|---|
| 事件详情 | `Drawer` | `w-[560px] max-w-[94vw]` | 浏览：字段网格 + 证据样例 + 处置入口 |
| 确认忽略 | `Dialog`（默认 480px） | 480 | 聚焦操作：一句话后果 + 两个按钮 |

**跟日志页一致用 560**（本规范初稿的 760px 已撤回）：一致性优先。560 − 32（`p-4`）= 528px，字段网格两列各 252px，URL / JA3 / payload 靠 `break-all` 换行，不放横向滚动。375px 视口上 94vw ≈ 352px，`sm:grid-cols-2` 不生效，自然退单列。

`Drawer` / `Dialog` 本身无入场动画（既有实现就是无 transition 的显隐），`prefers-reduced-motion` 天然满足，本页不新增任何动效。

### 7.2 抽屉标题（Phase 2 §7.4 已定，此处补 class）

```tsx
title={
  /* 标题节点用 span：Drawer 把 title 放进 <h2>，块级元素套在标题里不合语法
     （logs-panel.tsx:546 的同一处注释） */
  <span className="flex min-w-0 flex-col">
    <span className="truncate text-sm font-medium">{ruleText(row.rule)}</span>
    <span className="truncate font-mono text-xs font-normal text-muted-foreground">
      {row.id} · {row.source_label}
    </span>
  </span>
}
```

主标题是**事件归类**（规则名）不是「命中事件详情」——运维扫一眼标题就知道是哪一类；副标题给完整 ID（引用键，要整段复制走）+ 来源。

### 7.3 字段网格（摘要区）

```tsx
<div className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
  {rows.map(([label, value, mono]) => (
    <p key={label} className="flex gap-1">
      <span className="shrink-0 text-muted-foreground">{label}：</span>
      <span className={cn("min-w-0 break-all", mono && "font-mono")}>{value}</span>
    </p>
  ))}
</div>
```

| 项 | 规定 |
|---|---|
| `break-all` 不 `truncate` | 560px 抽屉放得下两列 × 252px；运维要拿 URL / JA3 / 哈希去查别的系统，截断 + 悬停看是没法复制的 |
| `font-mono` 只给技术值 | IP、事件 ID、端口、哈希、JA3、URL 用等宽；规则名 / 来源 / 事件类型 / 连接状态用正文字体——中文进等宽字体会掉 fallback，一行里两种字重看着糊 |
| 条目 | 照 Phase 2 §7.4 的清单（事件 ID / 规则 / 来源 / 首次 / 最近 / 次数 / 请求方 / 经 via / 目的 / 事件类型 / 连接状态 / 真实客户端 / 处理记录），一条不增一条不减 |
| 「不适用（签名引擎告警不带连接状态）」 | 保留迁移源的三分支判断（`status-panel.tsx:850-854`）：`conn_states` 空且 `log_types` 含 `suricata` 时说"不适用"，否则说"未记录"——两者不是一回事 |

### 7.4 事件内容（证据区）

```tsx
<div>
  <p className="mb-2 text-13 font-medium">事件内容</p>
  {detail.evidence?.length ? (
    <div className="space-y-2">
      {detail.evidence.map((ev, i) => (
        /* L1 内联格：底色成组，不描边 */
        <div key={i} className="rounded-xs bg-surface-1 px-3 py-2">
          <div className="mb-1.5 text-xs text-muted-foreground">
            样例 {i + 1}
            {at ? ` · ${eventTime(at)}` : ""}
            {ev.source ? ` · 来源 ${String(ev.source)}` : ""}
          </div>
          <div className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
            {Object.entries(ev).filter(([k]) => !HIDDEN_FIELDS.has(k)).map(([k, v]) => (
              <div key={k} className="flex gap-1 text-xs">
                <span className="shrink-0 text-muted-foreground">{fieldLabel(k)}：</span>
                <span className="min-w-0 break-all font-mono">{String(v)}</span>
              </div>
            ))}
          </div>
          {Array.isArray(ev.other_fields) && ev.other_fields.length ? (
            <div className="mt-1.5 text-xs text-muted-foreground">
              其它字段：{(ev.other_fields as string[]).map((k) => fieldLabel(k)).join("、")}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  ) : (
    <p className="text-xs text-muted-foreground">这条命中没有留下样例事件</p>
  )}
</div>
```

与迁移源的两处差异，都是有意的：

1. **`rounded-md border` → `rounded-xs bg-surface-1`**。迁移源的样例卡是「白对话框里一个描边框」，改成 L1 内联格（`bg-surface-1` 无描边），与 `Stat`、呼吸灯格同一种容器语言。
2. **`truncate` → `break-all`**。迁移源用 `truncate` + `title` 是因为 Dialog 只有 480px 宽；560px 抽屉 + 单列时 528px 够放，长值换行完整可读可复制。

证据字段的值**全部 `font-mono`**（与迁移源一致），和 7.3 的"只给技术值"不矛盾：证据是原始日志字段，等宽有助于同一字段在多条样例间纵向对齐；摘要区是给人读的结论。

`FIELD_LABELS` / `HIDDEN_FIELDS` / `fieldLabel` / `eventTime` 四个辅助**搬到 `lib/hits.ts`**（Phase 2 §10.2 已定文件归属），包括 `eventTime` 处理 Zeek 秒级时间戳的那个分支（实测有 `"1791816302.15616"` 这种字符串化秒数）。

### 7.5 处置操作区（Drawer footer + 确认 Dialog）

```tsx
footer={
  <div className="flex flex-wrap items-center gap-2">
    <Button size="sm" variant="outline" disabled={busy} onClick={() => setConfirmOpen(true)}>
      忽略这条
    </Button>
    <select aria-label="白名单范围" className="h-7 rounded-md border bg-transparent px-2 text-xs"
            value={scope} onChange={…}>
      <option value="src">白名单：同源 + 同规则</option>
      <option value="src_dst">白名单：同源 + 同规则 + 同目的</option>
    </select>
    <Button size="sm" disabled={busy} onClick={() => void act("whitelist")}>加入白名单</Button>
  </div>
}
```

| 项 | 规定 |
|---|---|
| 忽略**必须**过确认 Dialog | Phase 2 §6.2：不可逆（无取消端点），Nielsen 防错原则。确认要轻——480px 共享 Dialog，一句话后果 + 两个按钮 |
| 加白不确认 | 可逆（落在排除过滤器，配置管理 → 过滤规则可停用/删除） |
| scope select | 放两个按钮中间，紧贴它作用的那个按钮；`h-7 rounded-md bg-transparent text-xs` 是紧凑操作区方言（与迁移源一致） |
| scope 的 hint | 「只放行该规则的这一来源，不是全放行」必须出现在 UI 上（Phase 2 §6.1 / R2）——这是风险完全不对等的一句话 |
| **不画忽略理由输入框** | 本规范初稿曾提议（`reason` 字段后端收、落 `ignored_reason`、详情以「处理记录」显示）。**已撤回**：Phase 2 §6.3 的状态机按 `body {"reason": ""}` 设计，加一个控件会改流程。`reason` 字段先闲置，后续要做得先过 Phase 2 |
| 失败错误位置 | 渲染在 **Drawer 内 footer 上方**（`role="alert"`），不是页面级——用户正盯着抽屉，页面级红字在背后看不见（Phase 2 B1） |
| 连点防护 | `busy` 期间 footer 两按钮 + 确认 Dialog 的确认按钮同时 disabled + `aria-busy`（Phase 2 §6.3） |
| 已忽略/已加白的行 | 徽章照常显示（`Badge variant="outline"`，描边中性，不与严重度语义色抢）；不做行级假状态（Phase 2 §6.5：不做乐观更新） |

---

## 8. 迁移后运营中心的变化（Phase 2 §10 已定，此处只做视觉核对）

### 8.1 删除清单（精确到符号）

`ndr/frontend/components/status-panel.tsx`：

| 删什么 | 位置 |
|---|---|
| 「命中事件（最近）」整张 Card | 668–910 行 |
| `SRC.hits` 键 | 90 行 |
| state：`hits` / `hitDetail` / `hitBusy` / `hitMsg` / `whitelistScope` / `hitKind` / `hitKindRef` | 318–332 行 |
| 函数：`changeHitKind` / `openHitDetail` / `hitAction` | 334–406 行 |
| `load()` 里的 `/api/detector/hits?limit=50…` 那次 `loadInto` | 416–421 行 |
| imports：`HitEventItem` / `HitEventList` / `Dialog`（删完后若不再用） | 42–43、12 行 |
| 常量搬到 `lib/hits.ts`：`FIELD_LABELS` / `HIDDEN_FIELDS` / `fieldLabel` / `eventTime` / `severityBadge` | 133–249 行 |

`severityBadge` 全文件只有 737 行一个调用点，**整组搬走而不是重写**——`severityText`/`severityVariant` 的映射已在共享库统一过（`status-panel.tsx:242-245` 记录了「紧急 vs 严重」那次不一致）。

**接口并发数 12 → 11**：`load()` 少一个 `/api/detector/hits`，其余 11 个的 5 秒轮询定时器不动。

### 8.2 保留清单（明确不动）

| 保留 | 说明 |
|---|---|
| 「威胁事件」Section 本体（id=`threats`）+ 三张图 | 数据来自 `/api/detector/history` 与 `/api/stats/overview`，不依赖 hits |
| 「态势总览」的 24h 命中 KPI（`hit24h`） | 读 `historyItems` 增量求和，不是 hits；删了总览页就没有命中量了 |
| 强制 5 秒轮询 | 总览页口径不变；「不迁移到事件中心」只针对事件中心 |
| `firstLoad` 判定 | 本就没列 `hits`（`status-panel.tsx:519-528`），不用改 |

### 8.3 新增入口（只加一处，不引新接口）

「威胁事件」Section 的 `description`（或最后一张图下方）加一行跳转：

```tsx
description={
  <>
    统计口径：24 小时 · 增量求和。
    <Link href="/events" className="ml-1 text-primary hover:underline">
      完整列表与处置 → 事件中心
    </Link>
  </>
}
```

| 项 | 规定 |
|---|---|
| `CONSOLE_SHORTCUTS` **不新增**「事件中心」 | Phase 2 §10.3：一级菜单已可达，shortcuts 保持 4 个。本规范初稿曾提议加一条，**已撤回** |
| 铃铛 notices 不改 | Phase 2 §1.3：`noticesOf` 只收「需要马上处理的运行告警」，全部指向 `/console` |
| 链接样式 | `text-primary hover:underline`——内联链接用品牌色 + 下划线悬停，不用 Button（一段话里的跳转不该长得像个按钮） |

没有这处入口，运维会以为命中事件"没了"——迁移必须留路标。

---

## 9. 原语复用与新增清单

### 9.1 复用（`@shentong/ui` + `ndr/frontend`，零改动直接用）

| 原语 | 用在哪 |
|---|---|
| `PageShell width="full"` | 页面外壳 |
| `Section`（`title` / `description` / `extra`） | 三个区块 |
| `Card` / `CardHeader` / `CardTitle` / `CardContent` | 趋势图卡、TOP 10 卡、筛选条件卡、列表卡 |
| `Stat` | 概览三张卡 |
| `Chart`（`option` / `height`） | 命中趋势 |
| `Table` / `TableHeader` / `TableRow` / `TableHead` / `TableBody` / `TableCell` | 事件列表 |
| `Badge` + `severityVariant` / `severityText` | 严重度、已忽略、已加白 |
| `Button`（`sm` / `outline` / `default`） | 搜索、重置、刷新、翻页、处置 |
| `Input` | 关键字、事件归类、IP |
| `Drawer` / `Dialog` | 详情 / 确认忽略 |
| `EmptyState`（`muted` / `danger`，`compact` / `default`） | 图表位、TOP 卡、表格空态 |
| `Skeleton` / `StatSkeleton` / `ChartSkeleton` / `TableSkeleton` | 首屏 |
| `PanelError` / `usePanelErrors` / `loadInto` / `emptyOrFailed` | 分区报错 |
| `apiFetch` / `ApiError` / `errorText` | 详情与处置的写操作 |
| `formatDateTime` / `formatShort` / `formatClock` / `formatHourSlot` | 全部时间显示（北京时间） |
| `ruleText` / `severityText` / `severityVariant` | 规则名、严重度中文 |
| `chartTokens` | 图表取色 |
| `cn` | chips / 行的条件 class |

### 9.2 需要**小改**的既有组件（两处，都影响全站表格）

| 组件 | 改动 | 理由 |
|---|---|---|
| `packages/ui/src/components/ui/table.tsx` | `TableRow` 基础 class 追加 `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-inset` | 本页行 `tabIndex={0}`（Phase 2 §7.2），没有焦点环键盘用户看不到在哪行。日志页的行一起受益（Phase 2 §13 D2 同批回填） |

改动只加 class、不动结构与 API，`logs-panel` / `traffic-panel` 等既有用法零回归。

### 9.3 新增文件

| 文件 | 内容 |
|---|---|
| `ndr/frontend/app/events/page.tsx` | `PageShell title="事件中心" width="full"` + `<EventsPanel />`（与 `app/logs/page.tsx` 同构） |
| `ndr/frontend/components/events-panel.tsx` | Phase 2 §2–§8 的全部交互 + 本规范的视觉取值 |
| `ndr/frontend/components/event-charts.ts` | **一个**工厂 `hitTrendOption`（4.1 节） |
| `ndr/frontend/lib/hits.ts` | Phase 2 §10.2 已定：类型再导出 + `buildHitsQuery` + `statsMinutes` + 迁来的四个 helper + `SRC` 常量 + 消息文案 |

### 9.4 修改文件

| 文件 | 动作 |
|---|---|
| `ndr/frontend/lib/nav-config.ts` | `NAV_SECTIONS` 插第 2 项（`Siren`）+ import |
| `ndr/frontend/lib/api.ts` | 加 stats 的类型（见 9.5）；`HitEventItem` 定义本身不动 |
| `ndr/frontend/components/status-charts.ts` | `AXIS` / `GRID` / `valueAxis` 三个加 `export`，**值不动** |
| `ndr/frontend/components/status-panel.tsx` | 按 8.1 删 |
| `packages/ui/src/components/ui/table.tsx` | 按 9.2 加 focus ring |
| `ndr/frontend/app/globals.css` | **不改**（本页不新增 token） |

### 9.5 `lib/api.ts` / `lib/hits.ts` 新增类型

```ts
/** `GET /api/detector/hits/stats` 的一分组组成员（来源三类 / 严重度通用） */
export interface HitStatsGroup {
  key: string;
  /** 注意：severity 分组的这个字段是**原始英文 key**（后端 SOURCE_LABELS 不含严重度），
      界面一律用 severityText(key)；只有 source_kind 分组的 label 是中文 */
  label: string;
  count: number;
}

/** TOP 规则：字段名是 rule（不是 key/label） */
export interface HitTopRule { rule: string; count: number }

/** 趋势桶：ts 是 UTC ISO8601，界面一律转北京时间 */
export interface HitTrendPoint { ts: string; count: number }

export interface HitEventStats {
  minutes: number;
  bucket_seconds: number;
  total: number;
  ignored: number;
  by_source_kind: HitStatsGroup[];
  by_severity: HitStatsGroup[];
  top_rules: HitTopRule[];
  trend: HitTrendPoint[];
  /** 失败时后端只回 { error, total: 0 }，上面这些字段全部缺失 —— 读取点一律写 ?? [] */
  error?: string;
}
```

同时给 `HitEventItem` 补一个已有但未声明的字段：`proxied?: boolean`（后端 `_rows_to_dict` 一直在返，`hits.py:282`，前端类型没跟上）。本页不强依赖它，补上免得后面有人猜。

---

## 10. 本规范相对初稿的改动记录（5 处，供 review 时对照）

这一份是改写版。初稿按「新建一页、自由设计」的思路写了页面级粘性筛选条、4 张 KPI、4 张图、9 列表格、760px 抽屉、30 秒轮询；Phase 2 体验规范定稿后，以下 4 处已按 Phase 2 撤回；第 5 处按 team-lead Q-A 裁决落地。记在这里是因为**它们是本页最容易被"顺手优化回去"的地方**。

| # | 初稿做法 | 现行做法 | 为什么撤回 |
|---|---|---|---|
| 1 | 页面级粘性筛选条 + 时间范围用 `Segmented` 分段控件 + 高级筛选折叠 | 筛选条件 Section + Card 三段式，时间范围用 select，六维度全展开 | 「与日志页逐字一致」是硬要求；分段控件会造出全站第二种离散选择语言；六维度一屏放得下 |
| 2 | 4 张 KPI（含「最热规则」）+ 4 张图（趋势 + 严重度饼 + 来源三横条 + 规则 TOP 横条） | 3 张 KPI + 1 张趋势图 + TOP 10 列表卡 + 来源 chips | 同一数据的多种画法是重复口径；TOP 10 用列表卡才能可点击钻取；饼图/横条图在 560px 卡片里都挤 |
| 3 | 9 列表格（含操作列）+ 「不做整行点击」+ 窄屏 `hidden` 藏列 | 8 列 + 整行可点 + `sr-only` 藏列 | 一致性优先；整行可点是日志页既有语言，键盘入口由 `tabIndex` + `aria-label` 承担；`hidden` 会让读屏丢列 |
| 4 | 30 秒静默轮询 + 手动刷新 | 只手动刷新 + 数据时间戳 | 处置工作台不是盯屏仪表；轮询会冲掉翻页与阅读位置；状态可见比"不让你关"更尊重操作者 |
| 5 | 时间范围保留「不限」档（stats 降级 `minutes=1440`，靠 Section description 声明口径） | 四档 1h/6h/24h/7d，默认 24h，stats 与列表同分钟数 | team-lead Q-A 裁决：后端 `hits.py:621` 把 `minutes=0` 静默改成 1440，「不限」是骗人的选项；Phase 2 §2.1/§4.3 的方案甲文字同步不实现 |

另外撤回的两处小方案：忽略理由输入框（会改 Phase 2 §6.3 状态机）、`CONSOLE_SHORTCUTS` 加一条（一级菜单已可达）。

---

## 11. 全局约束核对表（Phase 3 提交前逐条打勾）

**设计语言**

- [ ] 无渐变、无玻璃拟态（`backdrop-blur`）、无发光、无彩色阴影；材质只由「表面底色差 + 1px 描边 + 极浅投影」构成
- [ ] 无 `font-weight: 700`；层级一律靠字号 + `font-medium`
- [ ] 颜色只用语义 token（`surface-*` / `sev-*` / `chart-*` / `brand-*` / `border*`），无 Tailwind 原色、无 hex
- [ ] `globals.css` 未改（本页不新增 token）

**字号**

- [ ] 只用 `text-xs`(12) / `text-13`(13) / `text-sm`(14) / `text-base`(16) / `text-28`(28)
- [ ] **没有** `text-11` / `text-14` / `text-15` / `text-16`（都不是合法类名）

**暗色分支**（agent 前端共用 `packages/ui`）

- [ ] chips 选中态 `border-primary bg-brand-50 text-primary` 在 `.dark` 下可辨（`--brand-50: 214 60% 16%` + `--primary: 212 82% 58%`）
- [ ] 表格行 hover `bg-brand-50` 在 `.dark` 下是 `214 60% 16%`，与 `surface-1`（220 26% 10%）有色相 + 明度双重差异
- [ ] 图表颜色全部来自 `chartTokens()`，切 `.dark` 自动跟随
- [ ] 证据样例卡 `bg-surface-1` 在 `.dark` 下（220 26% 10%）与抽屉底 `surface-2`（220 24% 12%）差得少，靠 `rounded-xs` 的形状差补；不为暗色加描边

**响应式**

- [ ] Stat 行 `grid-cols-1 sm:grid-cols-3`；图组 `grid-cols-1 lg:grid-cols-3`（趋势 `lg:col-span-2`）
- [ ] 筛选字段网格 `sm:grid-cols-2 lg:grid-cols-4`；关键字框 `min-w-[260px] flex-1`
- [ ] 窄屏藏列用 `max-lg:sr-only` / `max-md:sr-only`，**不用 `hidden`**
- [ ] 抽屉 `w-[560px] max-w-[94vw]`；375px 上字段网格自然退单列
- [ ] `TableRow` 的 focus ring 已加（9.2），键盘 Tab 能看见在哪行

**无障碍**

- [ ] 筛选控件用 `<label>` 包裹式关联（不用 id/htmlFor 手工配对）
- [ ] `TableHead` 传 `scope="col"`
- [ ] 事件归类/请求方/目的三列 `<td>` 带 `min-w-0 max-w-[…]`（`min-w-0` 与宽度类在**同一个** `<td>` 上；缺 `min-w-0` 时 `max-w`/`truncate` 不生效，长内容会把列顶宽——Phase 2 §9.3 同款验收）
- [ ] 窄屏藏列的 `max-lg:sr-only` / `max-md:sr-only` 同时写在 `th` 与 `td` 上（只藏 `td` 表头还在；实现规格见 Phase 2 §9.2 的 `COLUMNS` map，验收见 Phase 2 §16.7）
- [ ] 行 `tabIndex={0}` + `onKeyDown`（Enter/Space，Space 要 `preventDefault`）+ `aria-label`（Phase 2 §7.2 逐字）
- [ ] TOP 10 行是原生 `<button>`，不是 div
- [ ] 「共 N 条 / 第 X / Y 页」容器 `aria-live="polite"`
- [ ] 处置失败渲染在 Drawer 内 footer 上方（`role="alert"`），不是页面级
- [ ] 首屏骨架 `aria-busy`；刷新中表格区 `aria-busy` 且**不清空**
- [ ] 「暂无数据」「读取失败」「越界」是三种文案，不混（Phase 2 §3.3 / §8.1 四象限 + 第五空态）

**数据正确性**

- [ ] `by_severity` 用 `severityText(key)`，**不用 `label`**
- [ ] `top_rules` 读 `item.rule` 并过 `ruleText()`
- [ ] `trend` 按 `bucket_seconds` 补零；X 轴标签由 `bucket_seconds` 决定（`>=3600` → `formatHourSlot`，否则 `formatClock`）
- [ ] `source_kind` 只发三个合法值（后端 `if kind in SOURCE_LABELS`，非法值静默忽略 = 不过滤）
- [ ] stats 失败时（只有 `{error, total: 0}`）所有数组读取写 `?? []`
- [ ] 时间全部走 `format*`（北京时间）；`eventTime` 处理 Zeek 秒级时间戳的分支保留
- [ ] `limit` 不超过 200（后端 `cap` 截断），每页选项 `[20, 50, 100, 200]`
- [ ] 时间范围只有四档：1h / 6h / 24h / 7d，默认 24h；**没有**「不限」选项（Q-A 裁决：后端 `minutes=0` 会被静默改成 1440，保留即口径分裂）；stats 与列表同一个 `minutes`

**迁移**

- [ ] 8.1 删除清单逐项打勾，`/api/detector/hits` 在 `status-panel.tsx` 里零残留
- [ ] 「威胁事件」三张图与 24h 命中 KPI 未动；5 秒轮询定时器未动
- [ ] 「威胁事件」Section 有去事件中心的 `<Link>`
- [ ] `CONSOLE_SHORTCUTS` **没有**新增条目（保持 4 个）
- [ ] `nav-config.ts` 的 `events` 项带 `match: "/events"`，`sectionOf` / `sidebarOf` / `sectionActive` 三个函数未改

**动效**

- [ ] 无新增动画；chips / 行的 `transition-colors` 带 `motion-reduce:transition-none`
- [ ] `Drawer` / `Dialog` 无入场动画，`prefers-reduced-motion` 天然满足
- [ ] 骨架 `animate-pulse` 已带 `motion-reduce:animate-none`（`skeleton.tsx:27`）

**纪律**

- [ ] 未新增依赖；未新增 CSS 变量；未改业务逻辑
- [ ] 本地未执行 `npm run build` / `next build` / `docker build`（只 `npx tsc --noEmit`）
- [ ] 图表只用已注册类型（Line / Bar / Pie / Graph / Gauge，`packages/ui/src/lib/echarts.ts:51-63`）——本页一张折线，**不需要动装配表**
- [ ] 与 Phase 2 体验规范无冲突；本规范第 10 章的 5 处撤回未被"优化回去"
