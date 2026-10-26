# 配置管理 · 布局编排与检测规则树视觉规范

> 适用：`/config/*` 八个二级页（collect / networks / rules / filters / storage / agent / health / account）
> 阶段：Phase 1（视觉方向）产出，供 Phase 2（体验）与 Phase 3（工程）直接消费。
> 约束：不新增依赖（图标只用 `lucide-react@0.446` 已有导出，分类只用 `cn`）、不改业务逻辑、只改布局与视觉。
> 阅读顺序：第 0 章先纠正几个诊断数字，再往下看。

---

## 0. 先纠正诊断里的三个数字

写规范前先量了一遍真实代码，有三处和口头诊断不一样，后面的方案建立在更正后的数字上。

### 0.1 1920 屏上的外槽是 90px，不是 210px

`page-shell.tsx` 的结构是 **侧边栏先吃掉 240px，剩下的区域再 `mx-auto`**：

```
<main class="ml-60 px-4 md:px-6">        // 240 + 24×2
  <div class="mx-auto w-full max-w-[1500px]">
```

所以可用宽 `W = 视口 − 240 − 48`，内容宽 `C = min(W, 1500)`，外槽 `g = (W − C) / 2`。

| 视口 | W | C | 外槽 g |
|---|---|---|---|
| 1366 | 1078 | 1078 | 0 |
| 1600 | 1312 | 1312 | 0 |
| 1920 | 1632 | 1500 | **90** |
| 2560 | 2272 | 1500 | **410** |

`210 = (1920 − 1500) / 2` 是忘了减侧边栏的结果。**真正的痛点在 2560（410px 外槽）**，1366/1600 上外槽本来就是 0。

### 0.2 "左右大量空白"的主因在卡片内部，不在页面外

`SettingsGrid` 在 1920 上的主列宽 `M = 1500 − 304(19rem rail) − 16(gap) = 1180px`。
`zeek-panel.tsx:168` 的表单是 `grid gap-3 sm:grid-cols-2` → **单个输入框宽 566px**；
`account-panel.tsx:155` 三个密码框排两列 → 第二行还空一半。

一个"监听网卡"下拉框做 566px 宽，里面躺着 4 个字。**这才是用户看到的那片空白**：不是页面边距，是被拉长的控件。

结论：**外槽问题只在 ≥1920 暴露，卡内问题在所有宽度都暴露。** 两个都要治，但治法不同（第 1 章治外槽，第 2.3 节治卡内）。

### 0.3 断点不是"断档在 1280"，而是"Tailwind 断点是视口断点，侧边栏把它平移了 240px"

Tailwind 默认 screens（`tailwind.config.ts` 只用了 `theme.extend`，没覆盖 screens）：

```
sm 640   md 768   lg 1024   xl 1280   2xl 1536
```

带侧边栏时，`xl:1280` 视口 = **1040px 正文**。所有 `xl:` 判定的真实含义是"正文 1040"，不是"视口 1280"。现状 `xl:grid-cols-[minmax(0,1fr)_19rem]` 在正文 1040 时拆两列，主列 720px —— 这个选择本身**是对的**。

真正的问题不是阈值定错，而是 **`xl` 以下直接塌成一列后，`SettingsRail` 里的只读卡被拉到 991px 宽**（1279 视口时正文 = 991）。一张只有两行内容的"当前账号"卡横向铺满 991px，右侧 700px 是空的。

所以"断档"的解法不是改断点阈值，是 **给堆叠态下的 rail 加一个最大宽度**（第 4.2 节，一行 class 解决）。

---

## 1. 内容宽度与留白体系

### 1.1 决策：`PageShell` 增加 `width` 三档，`fluid` 保留为兼容别名

```tsx
// components/page-shell.tsx
export function PageShell({
  title, desc, children,
  /** @deprecated 用 width="full" */
  fluid = false,
  fill = false,
  width = fluid ? "full" : "standard",
}: {
  title: string;
  desc?: React.ReactNode;
  children: React.ReactNode;
  fluid?: boolean;
  fill?: boolean;
  /** standard = 表单/混合页（默认）；wide = 宽表页；full = 拓扑图与规则树 */
  width?: "standard" | "wide" | "full";
})
```

内容容器的 class（`!fluid` 分支）：

| 档位 | class |
|---|---|
| `standard` | `mx-auto w-full max-w-[1440px] 2xl:max-w-[1600px] min-[1920px]:max-w-[1800px] min-[2200px]:max-w-[2080px]` |
| `wide` | `mx-auto w-full max-w-[1600px] 2xl:max-w-[1800px] min-[1920px]:max-w-[2080px] min-[2200px]:max-w-none` |
| `full` | `w-full`（不加 `mx-auto`、不加 `max-w-*`） |

**为什么用 `min-[2200px]` 而不是新增 `3xl` screen**：Tailwind 3.4 原生支持 `min-[…]` / `max-[…]` 任意媒体查询变体，不需要动 `tailwind.config.ts`，也就不用同步改 `agent/frontend/tailwind.config.ts`（两个前端各有一份配置，改配置是两份改动 + 一次漏改的风险）。

**为什么仍然保留 `mx-auto` 而不是左对齐**：左对齐会把所有空白堆到右边，读起来像"布局坏了"；居中让两侧留白等宽，读起来像"刻意留的"。侧边栏存在时内容中心会相对屏幕中心右移约 120px，这是所有带固定侧栏的控制台（Grafana / Datadog）的通行做法，用户已习惯。

**为什么不给 `standard` 直接 `max-w-none`**：表单的舒适宽度有上限。主列到 1760px 时，两列字段各 872px —— 填完"监听网卡"要把眼睛从标签（左）扫到输入框（右）再扫回来，800px 的横向往返是真实的阅读成本。所以我们**用列数而不是列宽去吃多余宽度**（第 2.3 节）。

### 1.2 四档屏宽实测（有侧栏，`px-6`）

| 视口 | 可用宽 W | standard 内容 C | 外槽 g | 主列 M（`C − 320`） | 字段列数 | 单字段净宽 |
|---|---|---|---|---|---|---|
| 1366 | 1078 | 1078 | 0 | 758 | 2 | 371 |
| 1600 | 1312 | 1312 | 0 | 992 | 3 | 320 |
| 1920 | 1632 | 1632 | **0** | 1312 | 4 | 316 |
| 2560 | 2272 | 2080 | **96** | 1760 | 4 | 424 |

（`M` 已扣除 rail 19rem=304 与 gap 16；单字段净宽 = `(M − gap×(n−1)) / n`，gap=16）

对照现状：1920 外槽 90 → 0；2560 外槽 410 → **96**（减少 77%）。

### 1.3 八个子页的档位分配

| 路由 | 内容形态 | `width` | 理由 |
|---|---|---|---|
| `/config/collect` | 1 张表单卡（抓包口 2 字段） | `standard` | 字段少，必须补 rail，否则右侧 304px 空着 |
| `/config/networks` | 表单（网段 textarea + 6 字段）+ **10 列**中继节点表 | `wide` | 中继表 10 列在 1040 主列里会横向滚动 |
| `/config/rules` | 树形列表 | `full` | 树 + 签名面板嵌套 2 层缩进，要吃满宽度 |
| `/config/filters` | 表单 + 5 列过滤表 ×2 | `wide` | 过滤表含 `max-w-[380px]` 的表达式列 |
| `/config/storage` | 只读状态卡 + Logstash 管道表单 | `standard` | 管道是 textarea，不需要更宽 |
| `/config/agent` | MCP 表单 + 推送表单 | `standard` | 纯表单 |
| `/config/health` | 5 列配置项表（含长说明列） | `wide` | 说明列在 1040 里会被挤成 3 行 |
| `/config/account` | 3 个密码框 | `standard` | 字段最少，全靠 rail 撑住版面 |

**为什么 `/config/rules` 用 `full` 不加 max-w**：树形有 2 层缩进（共 40px），叶子行是 7 列网格（第 3 节），再叠一层 rail 或外槽就没有余量了。规则页是这一组里唯一"越宽越好"的页面。

### 1.4 侧边栏宽度改成 CSS 变量（一个真 bug）

现状 `w-60`（nav.tsx:52）和 `ml-60`（page-shell.tsx:48）是**两处独立的硬编码**。任何一边改动都会导致正文错位或被侧边栏压住。

在 `app/globals.css` 的 `:root` 里加（**只加 `:root`，不放 `.dark`** —— 这是布局尺寸不是主题色，两个前端共用同一份变量即可）：

```css
:root {
  /* 常驻侧边栏宽度：nav 的 w- 与 main 的 ml- 必须同源，改一处即可 */
  --sidebar-w: 15rem; /* 240px */
}

/* <1024：侧栏收成图标轨，把 184px 还给正文 */
@media (max-width: 1023.98px) {
  :root {
    --sidebar-w: 3.5rem; /* 56px */
  }
}
```

消费方：

```tsx
// nav.tsx
<aside className="fixed left-0 top-14 flex h-[calc(100vh-3.5rem)] w-[var(--sidebar-w)] flex-col border-r border-border bg-card">
// page-shell.tsx
hasSidebar ? "ml-[var(--sidebar-w)]" : "ml-0",
```

**为什么不直接写 `w-60 max-lg:w-14`**：那样 `ml-` 侧还要再写一遍 `ml-60 max-lg:ml-14`，仍然是两处。用变量是一处定义两处引用。

**为什么阈值取 1024 而不是 1280**：1024 视口下侧栏收起后正文 = 1024 − 56 − 48 = 920px，两列字段各 452px，可用；1280 才收的话 1024–1279 这一段的正文只有 736–991px，侧栏占比 24%~30%，是"侧栏比内容还显眼"的比例。

---

## 2. 配置页布局编排规范

### 2.1 布局模式清单

所有配置页的正文只准用下面 6 种模式。模式名直接对应 `SettingsGrid` 的组合方式，Phase 3 照抄即可。

| # | 模式 | 栅格公式 | 适用条件 | 卡片内字段列数 |
|---|---|---|---|---|
| M1 | **单列窄表单** | `max-w-[46rem]`（736px）单独一张卡 | 字段 ≤ 4 个且没有 rail 内容（本组**没有这种页**，仅作兜底） | 1（标签在上） |
| M2 | **主 + 侧栏** | `xl:grid-cols-[minmax(0,1fr)_19rem]` | 默认模式：有可编辑内容 + 只读事实 | 见 2.3 |
| M3 | **主 + 侧栏 + 整幅** | M2 之上，整幅块放在 `SettingsGrid` **外面**当 `Section` 的兄弟节点 | 一个 Section 里既有表单又有 ≥4 列的表 | 表整幅不受 rail 挤压 |
| M4 | **双列等宽** | `xl:grid-cols-2` | 两块**同类型同权重**的可编辑内容（本组无；`agent` 前端的 cloud/edge 面板是这个形态） | 每列内 1–2 |
| M5 | **整幅宽表** | 不套 `SettingsGrid` | 列数 ≥ 6 或行内含 `font-mono` 长表达式 | — |
| M6 | **整幅树** | 不套 `SettingsGrid`，外层一张 `Card` | 层级 ≥ 2 的嵌套列表（只有 `/config/rules`） | — |

**M3 是本组用得最多的模式**，写法：

```tsx
<Section title="抓包范围">
  {/* 表单走 M2 */}
  <SettingsGrid>
    <SettingsMain><Card>…字段…</Card></SettingsMain>
    <SettingsRail><Card>…当前生效值…</Card></SettingsRail>
  </SettingsGrid>

  {/* 宽表整幅：放在 SettingsGrid 外面，宽度 = 整幅 */}
  <Card>
    <CardContent className="pt-4">
      <Table>…</Table>
    </CardContent>
  </Card>
</Section>
```

**为什么整幅块必须放在 `SettingsGrid` 外面**：塞进主列的话，一张 10 列的表在 1040px 主列里会横向滚动；横向滚动 + 右侧还有一列只读卡，用户会以为表格被"截断"了。整幅块放在外面，读者一眼看出"这张表就是整页宽"，滚动条出现时也不会怀疑是布局错了。

### 2.2 每个配置页都必须有 rail

这是解决"卡片右侧大片空"的**结构性**手段 —— 空的地方要放东西，不是把剩下的拉长。

| 页面 | rail 内容（只读） | 来源 |
|---|---|---|
| collect | 采集器运行状态：`detected[].state` + `last_reload` + `detected.length` + `suricata.alive` | `ZeekPanel` 已有 `status`（`ZeekStatus`，`lib/api.ts:122-144`）|
| networks | BPF 过滤器预览 + `Site::local_nets` 预览（由网段清单自动生成）+ 已识别网段数 | `ZeekPanel` 已有 |
| filters | 命中统计 / 生效范围说明 | `IngestFiltersPanel` 已有 |
| storage | ES 接入状态（只读，本来就在 rail 位） | 已有 |
| agent | MCP 取数范围说明 / 推送最近状态 | 已有 |
| account | 当前账号（已有） | 已有 |
| health | 需要处理清单（已有） | 已有 |
| rules | 无 rail —— 整幅树 | — |

**rail 里放什么（白名单，超出即违规）**：

- ✅ 当前生效值的 key/value（一行一条，`divide-y divide-border-subtle`）
- ✅ 运行状态徽章组（≤ 4 个 `Badge`）
- ✅ `Stat size="sm"` 小格，最多 4 个（2×2）
- ✅ `sev-*` 三件套提示条
- ✅ **至多一个**按钮，且必须是"作用于整页"的动作（刷新 / 立即检查更新），**不能是表单提交按钮**

**rail 里不放什么（黑名单，沿用并细化 `settings-grid.tsx` 的注释）**：

- ❌ **列数 > 3 的表**（中继节点 10 列、配置体检 5 列、过滤规则 5 列）—— 304px 里放 3 列表格，每列 90px，单元格内容全变成竖排省略号
- ❌ **代码编辑器 / textarea / 长样本**：logstash 管道、网段清单（`TEXTAREA_CLS`）。304px 宽的 textarea 里一行 CIDR 要折两次
- ❌ **长样本列表**：行数 > 8 且行内含 `font-mono` 或 > 20 字中文
- ❌ **任何需要横向滚动的内容**：横向滚动条出现在 304px 容器里时，滚动区域只有半指宽，几乎拖不动
- ❌ **表单控件**：出现一个输入框，"右侧 = 只读"这个约定就废了（原注释已写明，继续遵守）

> **写 rail 内容时必须对着 `ndr/frontend/lib/api.ts` 的类型校字段**（Q2 教训）：
> 初稿在 collect 的 rail 里写了"PID"，而 `ZeekStatus`（`lib/api.ts:122-144`）根本没有这个字段 ——
> 规范里一旦出现不存在的字段，Phase 3 要么编一个假值、要么空着，两种都是 bug。
> 本表每一行的字段都来自真实接口类型；新增 rail 内容时请照此核对。

**rail 卡片数量上限：3 张。** 超过就合并成一张"当前状态"卡，内部用 `divide-y divide-border-subtle` 分 3 段。理由：4 张以上时 rail 高度超过主列，视觉上变成"右栏才是主内容"，和"主列放能改的"这个编排名矛盾。

### 2.3 卡片内字段排布 —— 治"卡右侧大片空"

这是本次改动收益最大的一块。核心是**列数随宽度增长，而不是列宽随宽度增长**。

#### 列数阶梯

```tsx
// 短字段组（端口 / 开关 / 数量 / 下拉 / 口令）
"grid gap-x-4 gap-y-3 grid-cols-1 md:grid-cols-2 min-[1600px]:grid-cols-3 min-[1920px]:grid-cols-4"
```

阈值推导（`M` = 主列宽，见 1.2）：

| 断点 | 视口 | M | 列数 | 单字段宽 | 判定 |
|---|---|---|---|---|---|
| 默认 | <768 | <480 | 1 | 全宽 | 手机上不并排 |
| `md` | 768–1599 | 480–992 | 2 | 232–488 | 下限 232 偏窄但可接受（≥1024 时侧栏已收成 56px，实际 M ≥ 664） |
| `min-[1600px]` | 1600–1919 | 992–1312 | 3 | 320–427 | ✅ 舒适区 |
| `min-[1920px]` | ≥1920 | 1312–1760 | 4 | 316–424 | ✅ 舒适区 |

**下限 232px 为什么接受**：1024–1279 时侧栏已收成图标轨（1.4 节），正文 = 1024−56−48 = 920px 起，两列各 452px。真正落到 480px 正文的只有 768–1023（平板），这类屏不是本产品的主战场，且 1 列 → 2 列的切换点选在 `md`(768) 时正文 664px（已收侧栏），两列各 324px，是够的。

#### 字段宽度档位（新 `Field` 组件的 `span`）

| 档 | 宽度 | 用于 | 例 |
|---|---|---|---|
| `sm` | `min-w-0`（跟随网格列） | 端口、数量、开关、级别下拉、优先级 | 请求正文上限(KB) |
| `md` | `min-w-0 min-[1600px]:max-w-[30rem]` | 网卡名、主机名、单值文本 | 监听网卡、分组键 |
| `lg` | `col-span-2`（在 4 列网格里占 2 列） | URL、令牌、邮箱 | MCP 地址、推送 Token |
| `full` | `col-span-full` | textarea、网段清单、代码、条件编辑器 | 监控网段、Logstash 管道 |

**为什么 `md` 档要 `max-w-[30rem]`（480px）**：一个输入框里 4 个中文字符却宽 872px 时，眼睛从标签扫到输入框的落点会在空白处丢失。480px 约等于 40 个中文字符，是"不用横向扫描就能读完整条值"的上限。超过这个长度的值（URL / 令牌）本来就应该换行或者给 `lg` 档。

**为什么长字段用 `col-span-2` 而不是让它独占一行**：`full` 会把一行里剩下的 2/3 列留空，正是要消灭的空白；`col-span-2` 让长字段吃掉两列的宽度，行内还能再放一个短字段。

#### 标签位置：一律在上，不做左右分栏

现状（`zeek-panel.tsx:170`、`account-panel.tsx:157`）已经是 `<label class="mb-1 block text-xs text-muted-foreground">` + 控件在下，**保持不变**。

**为什么不做"标签在左、控件在右"**：左标签要求一列固定的标签宽（通常 8rem），在 4 列网格里标签列要重复 4 次，吃掉 4×128 = 512px；而且标签右对齐后，"监听网卡"和"附加 BPF 条件（可选，如 not port 22）"这种长短差异会让控件起点参差。上标签在窄列里也能读全，且列宽变化时不需要重新设计标签列宽。

#### 分组标题跨度

卡片内用 `fieldset` 分段时（现状 `rules/page.tsx:660` 已用）：

```tsx
<fieldset className="min-w-0 space-y-3">
  <legend className="mb-2 w-full border-b border-border-subtle pb-1 text-xs font-medium text-foreground">
    匹配条件
  </legend>
  <FieldGrid>…</FieldGrid>
</fieldset>
```

**`legend` 一律 `w-full`**（现状已如此，保持）—— 否则它不会撑满，`border-b` 只画到文字宽度，看起来像漏了一半。

**分组跨度规则**：一个 `fieldset` 内的字段网格独立计算列数；如果分组内只有 1–2 个字段，用 `span="lg"` 让它们占 2 列，不要用 `full`。

### 2.4 rail 的粘性

```tsx
// SettingsRail
<div className="min-w-0 space-y-3 xl:sticky xl:top-[4.25rem] max-xl:max-w-[34rem]" …>
```

- **`xl:sticky xl:top-[4.25rem]`**：`4.25rem` 与 `page-shell.tsx` 的 `pt-[4.25rem]` 同值（页头 3.5rem + 0.75rem 呼吸）。滚动长表单时"当前生效值"一直在视野里，填字段时不用滚上去对。
  - 前置条件：`SettingsGrid` 必须保持 `items-start`（现状已有），否则 `align-items: stretch` 会让 rail 和主列等高，sticky 失效。
- **`max-xl:max-w-[34rem]`**：修 0.3 节说的断档。堆叠态下只读卡不再被拉到 991px，而是收到 544px（约等于主列两列字段的宽度），右半边的空白消失。

**为什么是 34rem**：它是"两列字段（2×~16rem）+ 一个 gap"的宽度，堆叠时 rail 卡宽度和上方表单卡里的字段块宽度对得上，视觉上像同一套栅格而不是两个随意的盒子。

---

## 3. 常驻功能菜单（侧边栏）视觉规范

`components/nav.tsx`。**只改视觉与结构，不动 `sidebarOf` / `sidebarSectionOf` 的归属逻辑，不动 `nav-config.ts` 的 href/group 数据。**

### 3.1 条目结构：砍掉描述行，改成"图标 + 单行标题"

现状每个条目是 `图标 + 标题 + 描述` 的三行结构，8 条 + 4 个分组标题 ≈ 620px 高，1080p 屏上要滚动。

```tsx
<Link
  href={it.href}
  title={it.desc}                    /* ← 描述搬到这里（原生 tooltip） */
  aria-current={active ? "page" : undefined}
  data-active={active ? "" : undefined}
  className={cn(
    "group flex h-8 items-center gap-2 rounded-sm px-3 text-13 transition-colors",
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
    active
      ? "bg-brand-50 font-medium text-primary"
      : "text-muted-foreground hover:bg-surface-1 hover:text-foreground",
  )}
>
  <it.icon className="h-4 w-4 shrink-0" />   {/* 颜色继承 currentColor，不单独染色 */}
  <span className="truncate">{it.label}</span>
</Link>
```

改动点：

| 项 | 现状 | 改为 | 为什么 |
|---|---|---|---|
| 条目高度 | ~52px（两行文字） | **32px**（`h-8`，单行） | 8 条从 416px 降到 256px，1080p 上不需要滚动；单行标题一行扫完，两行要眼睛停两次 |
| 描述行 | 常驻第二行 + `truncate` | **移除**，移到 `title` | `truncate` 后描述通常是"抓包网卡与监听参…"，既占 16px 高度又没传达完整信息 —— 花的空间没换来信息 |
| 图标垂直对齐 | `mt-0.5`（配合两行文字） | 去掉，`items-center` | 单行后不需要手动偏移 |
| 条目间距 | `mb-0.5` | 保留 | 8 条之间 2px 分隔足以区分 |

**信息损失的补偿**：描述去了 `title`，鼠标悬停 1 秒出原生提示。这是零成本的兜底。若上线后有人反馈"不知道某个页面干什么"，**降级方案**是只给当前项恢复描述行：

```tsx
{active && it.desc ? (
  <span className="block truncate text-xs font-normal text-muted-foreground/80">{it.desc}</span>
) : null}
```

注意这个降级方案会让导航时下方条目位移 16px —— 只有在投诉真实出现时才启用，不要预防性地加。

**为什么不保留描述**：用户原话是"更美观简洁"。8 条配置项的标签（采集接入 / 监控网段 / 检测规则 / 过滤规则 / 数据存储 / 智能体对接 / 配置体检 / 账户）对运维人员是自解释的；描述的价值主要在首次上手，而它换来的是每个用户每天都多滚 200px。

### 3.2 分组标题：文字 + 上方 1px 分隔线

```tsx
{groupHead ? (
  <p
    className={cn(
      "px-3 pb-1.5 text-xs font-medium text-muted-foreground/70",
      i === 0 ? "pt-0" : "mt-2 border-t border-border-subtle pt-3",
    )}
  >
    {it.group}
  </p>
) : null}
```

**为什么加 1px 分隔线、同时把 `pt-4` 降到 `pt-3`**：分组是"隔断"语义，1px 描边是本设计语言承认的表达方式（"表面底色差 + 1px 描边 + 极浅投影"）。原来只用 16px 间距表达分组，在 32px 的密集条目之间这个间距会被读成"一条特别宽的空隙"而不是"分组边界"。加了线之后间距可以收小，总高度反而更低。

**为什么不用底色块或大写字母spacing**：4 个分组标题都加底色块 = 侧边栏里出现 4 个盒子，和"零装饰"冲突；中文没有大小写，`uppercase tracking-wide` 无效。

### 3.3 选中态：从 5 个信号减到 2 个

现状同时开了 5 个信号：底色 `bg-primary/10` + 左侧 2px 竖条 `border-l-2 border-primary` + 文字染色 `text-primary` + 图标染色 + `font-medium`。

**改为 2 个信号：`bg-brand-50` + `text-primary`**（图标继承 `currentColor`，算同一个信号；`font-medium` 不改变颜色不算独立信号）。**去掉左侧 2px 竖条。**

**为什么去掉竖条**：
1. 32px 单行条目下，竖条位于 `x = 0..2`，而条目文字在 `x = 12..`。扫描时眼睛落在文字上，不在最左边缘 —— 竖条在两行条目里是有用的位置锚点，在单行条目里基本看不见。
2. 竖条 + 底色 + 双色文字 = 一处状态三种颜色变化，在亮色主题上读起来"重"，和旁边密集表格的安静感打架。
3. 页头一级菜单（`topbar.tsx:154`）用的正是 `bg-primary/10 + font-medium + text-primary` 这 2 个信号。二级菜单沿用同一套语言，一级/二级的一致性比"多一个锚点"值钱。

**顺带修一个真 bug：hover 和选中现在是同一个颜色。**

globals.css 里 `--accent: 214 90% 96%` 与 `--brand-50: 214 90% 96%` **是同一个值**；而现状的选中色 `bg-primary/10`（`#144990` @10% 叠在 `#fff` 上 ≈ `#e9f0f7`）与 `bg-accent`（≈ `#e6f1fc`）的差距小到看不出来。结果是：**鼠标扫过侧边栏时，当前页那一条会"消失"在其余 7 条里**，扫完一遍还得回来找。

修法：**把 hover 从"色相差"改成"表面差"**，让两个状态分属不同视觉通道：

```
静止  = 透明（卡片底 #fff）
hover = bg-surface-1（#f5f7f9，L1 表面）—— "材质"信号
选中  = bg-brand-50（#e6effb）+ 主色字     —— "语义色"信号
```

hover 与选中因此分属两个不同的视觉通道（表面层级 vs 品牌色），不可能混淆，也符合"材质只由表面底色差 + 1px 描边构成"的原则。

**逃生口**：如果团队坚持要位置锚点，用 `border-l-2 border-primary` 但同时把条目恢复成 `h-9`（36px）—— 不要维持 32px + 竖条，那个组合下竖条是纯噪音。

### 3.4 窄屏（<1024）：收成图标轨

```tsx
<aside className="… w-[var(--sidebar-w)] …">   // 已在 1.4 定义
```

在图标轨状态（`--sidebar-w: 3.5rem`）下：

```tsx
<Link
  title={`${it.label}${it.desc ? ` · ${it.desc}` : ""}`}   /* 图标轨时 title 必须带标签名 */
  className={cn(
    "group flex h-9 items-center rounded-sm transition-colors",
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
    isIconRail ? "justify-center px-0" : "gap-2 px-3",
    …
  )}
>
  <it.icon className="h-4 w-4 shrink-0" />
  {isIconRail ? null : <span className="truncate">{it.label}</span>}
</Link>
```

- **一切"图标轨下看不见"的文字一律用 `sr-only`，绝不用 `hidden`**（Phase 2 复核后修正）：
  `hidden`（`display:none`）会把元素**从无障碍树里一起摘掉**。图标轨下 8 个菜单项只剩图标，
  如果标签用 `hidden`，读屏会念出 8 个没有名字的"链接" —— 侧边栏对读屏用户等于整个消失。
  改用 `sr-only`（视觉隐藏但仍可被读屏读到），链接的可访问名由标签 `<span>` 提供，完好无损。
  - 标签：`<span className="max-lg:sr-only truncate">{it.label}</span>`
  - 分组标题：`<p className="max-lg:sr-only …">{it.group}</p>` —— 同理，分组信息也要留给读屏，
    不能只留一条 `aria-hidden` 分隔线
  - 分区名（顶部"配置管理"）：同样 `max-lg:sr-only`
  - 分隔线保持 `aria-hidden`（它本来就是纯装饰）
- **是否需要 JS 判断 `isIconRail`**：不用。`Link` 的 padding 用 `px-3 max-lg:px-0 max-lg:justify-center`，
  文字用 `max-lg:sr-only`。`max-lg:` 是 Tailwind 3.4 原生变体，零 JS、零 hydration 抖动。
  - 唯一需要 JS 的是 `title` 内容（图标轨下要带标签名）。简化处理：**`title` 一律写成 `${it.label} · ${it.desc}`**，两种状态下都合理。

**为什么不改成"点击汉堡按钮弹出抽屉"**：多一个状态、多一个焦点陷阱、多一份 keyboard 处理。56px 图标轨在 1024 以下够用（8 个图标 + 4 条分隔线 ≈ 380px，一次看全），且它保持"菜单常驻"这个用户明确要求过的性质。

### 3.5 侧边栏底部告警条（出厂口令）

现状（`nav.tsx:111-121`）保持不动，只改两处：
- 图标轨下改成纯图标 + `title`（文字在 56px 里会挤成竖排）
- `h-3.5 w-3.5` 的 `ShieldAlert` 保持

---

## 4. 检测规则树形列表视觉规范（本次重点）

`app/config/rules/page.tsx`（原 `app/admin/rules/page.tsx`，2026-10 已搬到新地址）。**业务状态机一律不改**：`expanded` / `openIds` / `showDisabled` / `busy` / localStorage key `shentong.rules.tree` / 三个接口调用全部保持原样。

### 4.0 容器：整棵树装在一张 `Card` 里，内部不再出现任何盒子

```
<Section title="规则来源">
  <Card>                                    ← 全树唯一的盒子（L2）
    <PanelToolbar>                          ← 工具栏，border-b
    <ul>  L1 网络
      <li> L1 行（h-11, text-14 medium, 图标）
        <ul> L2 内置/自定义/签名
          <li TreeRow> L2 行（h-10, text-13 medium）
            <ul> L3 规则
              <li TreeRow> L3 行（h-12, 两行：名称 + 描述）
                <div> 详情面板（bg-surface-1，无描边）
```

**为什么整树要一张 Card**：树的行要 hover 高亮（`bg-brand-50`），行必须落在 `surface-2`（白）上才能看见高亮；落在 `canvas`（#ecf0f3）上时 `bg-brand-50`（#e6effb）比它更亮，"高亮"会变成"变白"，层级倒挂。

**为什么树内部禁止再出现 Card**：`section.tsx` 的层级约定写明"别把 Card 套在 Card 里"。树内的详情面板、签名面板一律降级为**内联格（L3）**：`bg-surface-1` + `rounded-sm` + `p-3` + **无描边**。

> 这条规则导致 `SuricataRulesPanel` 需要改：见 5.9。

### 4.1 树线（纯 CSS，1px，`--border-subtle`）

**几何常量**（每一级缩进 20px）：

| 名称 | 值 | 含义 |
|---|---|---|
| 缩进步长 | `pl-5`（20px） | 每级缩进 |
| 树干 x | `left-2`（8px） | 相对本行左边缘 |
| 肘线 | `w-3`（12px） | 从 x=8 画到 x=20，正好接到内容起点 |
| 行中线 | L2 行 `top-5`（20px）／L3 行 `top-[22px]`（22px） | 肘线的 y，= 行高的一半（40/2、44/2） |

**画法**（`TreeRow` 组件每行的两个 `aria-hidden` 元素）：

```tsx
<li className="relative pl-5">
  {/* 树干：非末行贯穿整行（含展开的详情）；末行只画到肘线 */}
  <span
    aria-hidden
    className={cn(
      "absolute left-2 w-px bg-border-subtle",
      last ? "top-0 h-5" : "top-0 h-full",      // h-5 = 20px（L2 子级）；L3 子级用 h-[22px]
    )}
  />
  {/* 肘线：树干 → 内容起点 */}
  <span
    aria-hidden
    className={cn(
      "absolute left-2 h-px w-3 bg-border-subtle",
      "top-5",                                   // L3 子级用 top-[22px]
    )}
  />
  {/* 行内容 */}
</li>
```

**为什么用"每行自画一段"而不是"容器画一根通长竖线"**：
容器画通长线时，末行的线会一直画到容器底部（超过最后一个子项的中线 20px），出现一段"悬空的线头"；而且线长要按最后一个子项的高度反算，一旦最后一项展开详情就会错位。每行自画一段，末行 `h-5` 自然收在肘线处，天然对齐，且对变高行（展开详情）完全免疫。

**为什么缩进 20px 而不是更深（24/32）**：树最深 3 层（L1→L2→L3），累计缩进 40px。40px 在 1600+ 的主列里只占 3%，同时足够让三级结构一眼分得开；超过 24px 时 L3 的叶子行起点会被推到 48px 外，和右侧的列信息挤在一起。

**为什么不用 `border-l` + `pl-4`（现状）**：`border-l` 只能画在容器上，画不出肘线，也就看不出"这条属于上面那一行的哪一个"；而且 `border-l` 会和行 hover 的 `bg-brand-50` 交叉，出现一段被高亮截断的线。

### 4.2 展开/收起图标：`ChevronRight` 旋转，不用 `▸/▾`

```tsx
<ChevronRight
  aria-hidden
  className={cn(
    "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-150",
    "motion-reduce:transition-none",
    open && "rotate-90",
  )}
/>
```

- `ChevronRight` 在 `lucide-react@0.446` 已确认导出。
- **为什么用图标旋转而不是换字符**：`▸/▾` 是 U+25B8 / U+25BE，属于几何图形区，很多中文字体（PingFang / 思源黑体）里没有或字形不一致，在不同机器上会掉进 fallback 字体、基线偏移；而且这两个字符的宽度和汉字不同，展开/收起切换时整行会左右抖 2px。`ChevronRight` 是 SVG，尺寸固定、基线稳定，旋转靠 `transform` 不触发重排。
- **`motion-reduce:transition-none`**：`globals.css` 里已有 `prefers-reduced-motion` 先例（`.st-pulse`），保持一致。

**可点区域**：L1/L2 用整行按钮；L3 用行首独立的 20px 按钮（见 4.5）。

```tsx
// L1 / L2 节点行
<button
  type="button"
  onClick={onToggle}
  aria-expanded={open}
  aria-controls={panelId}
  className={cn(
    "flex min-w-0 flex-1 items-center gap-2 rounded-sm text-left",
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
  )}
>
```

`aria-expanded` + `aria-controls` 现状只写了 `aria-expanded`，补上 `aria-controls` 指向子列表的 `id`。

### 4.3 三级视觉权重

| 级 | 行高 | 字号 / 字重 | 文字色 | 图标 | 底色 |
|---|---|---|---|---|---|
| L1 网络（根） | `h-11`（44px） | `text-sm font-medium` | `text-foreground` | `Radio` h-4 `text-muted-foreground` | 透明 |
| L2 内置/自定义/签名 | `h-10`（40px） | `text-13 font-medium` | `text-foreground` | 无 | 透明，hover `bg-brand-50` |
| L3 规则（叶） | `min-h-11 py-1`（44px，两行） | 名称 `text-13 font-medium`；描述 `text-xs font-normal` | 名称 `text-foreground`；描述 `text-muted-foreground` | 无 | 透明，hover `bg-brand-50`；停用 `bg-surface-1` |

**为什么 L1 与 L2 只差 1px 字号（14 vs 13）**：禁止 `font-weight:700`（globals.css 约定，中文 700 会发糊），能用的层级手段只有字号和颜色。`text-sm`(14px) ↔ `text-13`(13px) 的差在密集列表里足够分辨，再加一行 `h-11`(44px) ↔ `h-10`(40px) 的高度差，两级不会混。

> **字号档位与 Tailwind 类名的对应（写码时照抄，不要自造类名）**：
> `text-11` **不存在**（用 `text-xs` 或加 `text-[11px]`）｜12px = `text-xs`｜13px = `text-13`（自定义）｜14px = **`text-sm`**（不是 `text-14`，Tailwind 默认没有这个键）｜16px = `text-base`｜28px = `text-28`（自定义）。

> ## ✅ 最终裁定：**B —— 恒定两行**
>
> 主理人在 A（阈值提到 `min-[1700px]`，≥1280 走单行）与 B（恒定两行）之间**裁定 B，A 不做**。
> 依据：1280（③=472px）单行只有 26 字，比现状 `slice(0, 60)` 的 60 字**净降 34 字**；
> 而 1280～1699 正好覆盖 1366 与 1600 两档最常见的企业分辨率，A 会让最主流的两档继续倒退。
> B 在 1024（3 列模板，③=592px）就有 98 字，任何档位都不低于现状。
>
> **实现口径（以此为准）**：
> - 叶子行**所有屏宽都是两行**：第 1 行名称（+ 命中高亮 + 停用徽章），第 2 行描述（`line-clamp-2`）+ 规则 ID。
> - `xl:`(1280) 这个断点**只决定 ④⑤⑥⑦ 是留在列上还是移到第三行**，不决定行数。
> - 行高恒 44px（`min-h-11 py-1`），`MID` 用 22。
> - 描述一律 `line-clamp-2`（不是 `line-clamp-1`）。
>
> 4.5 节已按此口径写死。下面的实测数据是裁定的依据，不是待议项。

#### 叶子行的行数（实测数据 —— 裁定 B 的依据）

> **⚠ 本节的实测数字改过两次，中间那次是错的。以这一版为准（第三次，用 AST/导入模块取值，不是正则）。**
>
> | 版本 | 条数 | 最长描述 | >60 的条数 | 怎么取的 |
> |---|---|---|---|---|
> | 初稿 | （未测，按"40 条"估） | — | — | 拍脑袋 |
> | 第二次 | **19** | **54** | **0** | 单行正则 `"description":\s*"([^"]*)"` —— **漏了跨行隐式拼接的字符串字面量** |
> | **第三次（现行）** | **22** | **90** | **2**（90 / 74） | `importlib` 直接导入 `app/rules/builtin.py` 取 `BUILTIN_RULES` |
>
> 第二次那版数字让我得出"`slice(0, 60)` 从不截断、我的前提不成立"，**这个结论是错的，已撤回。**
> 教训：数源码里的数据结构不要写正则，直接导入模块或走 AST —— 隐式字符串拼接会让正则静默少算。

**现行实测数据（`BUILTIN_RULES`）**：22 条，全部带 `description`；
描述最短 14 / **中位 37 / 最长 90** 字符；规则名最短 4 / 中位 8 / 最长 11 字符。

最长的一条（90 字符）：
> 内网漏洞利用探测 —— 同源 30 分钟内对 ≥10 个不同内网目的发起带利用特征的请求（Shellshock/Log4Shell 类载荷头、Nacos/Solr/Tomcat 管理页等被批量利用的端点）

**于是 4.3 初稿的论证重新成立**：现状 `slice(0, 60)`（rules/page.tsx:417）**确实会截断**，
22 条里有 2 条被切（90 字切成 60、74 字切成 60），而且切掉的正好是"载荷头/端点清单"这类最有信息量的尾巴。

③ 列宽度随视口在 **472px（1280）～ 1112px（1920）之间波动 2.4 倍**；`<1280` 走 3 列模板时回到 592px。
单行排版下名称与描述共享 ③ 列，描述实际只能拿到 `③ − 名称宽(151px)`：

| 视口 | ③ 列 | 单行下描述可得 | 两行下描述可得（`line-clamp-2`） | 单行 vs 现状 60 字 |
|---|---|---|---|---|
| 1024 | 592px（3 列模板） | 441px ≈ 36 字 | **98 字** ✅ 全放得下 | ❌ 36 < 60 |
| 1280 | 472px（7 列） | 321px ≈ 26 字 | **78 字** ⚠ 90 字那条被 clamp | ❌ 26 < 60 |
| 1366 | 558px | 407px ≈ 33 字 | **93 字** ✅ | ❌ 33 < 60 |
| 1440 | 632px | 481px ≈ 40 字 | **105 字** ✅ | ❌ 40 < 60 |
| 1600 | 792px | 641px ≈ 53 字 | **132 字** ✅ | ❌ **53 < 60** |
| **1700** | 892px | 741px ≈ **61 字** | **148 字** ✅ | ✅ **61 ≥ 60 回平** |
| 1920 | 1112px | 961px ≈ 80 字 | **185 字** ✅ | ✅ 80 ≥ 60 |

计算口径（与 ux-designer 对过，两边独立算得一致）：
`T = 视口 − 240(侧栏) − 48(main padding) − 32(ul p-2 + 行 px-2)`，`③ = T − 40(两级缩进) − 448(固定列+gap)`；
单行下描述可得宽 = `③ − 151`（最长规则名 11 字 × 13px + `ml-2` 8px），两行下描述独占 ③ 整宽；
12px 中文按 12px/字折算。**两行的容量是"每行字数 × 2"，不是 ③/12** —— 我第一版表把两行写成"每行字数"，少算一半，已修正。

**最关键的一条（比"只有 1920 才够"更强）**：90 字符在单行下需要

```
③ ≥ 90 × 12px(字宽) + 151px(名称占位) = 1231px
```

而 ③ 列在全项目最宽的档位（1920 视口）也只有 **1112px** ——
也就是说 **90 字符在任何屏宽下单行都放不下**，连 1920 都不够（差 119px）。

> 我上一条给团队的消息里写的是"90 字符需要 1080px、只有 1920 才够"，**漏加了 151px 的名称占位**，
> 因此把结论说弱了。正确结论是：**单行在任何档位都放不下最长描述，两行是内容本身的要求，
> 不是"窄屏降级"**。这也是主理人最终裁定 B（恒定两行）的直接依据。

**代价**：22 条 × 8px = 176px（初稿"40 条 → 480px"、第二次"19 条 → 152px"都是错的）。

**`line-clamp-2` 必须加**（第二次基于 54 字符撤回过，现撤回撤回）：
`line-clamp-2` 的作用不是治空白（治不了），而是**守住 44px 行高的契约** ——
不给 clamp，1280 下那条 90 字符的描述会折到第三行，该行涨到 60px，整列行高基准就散了。
被 clamp 的实际只有 1 条（90 字符）且只在 1280～1599 这两档；`title` + 详情面板兜底。

```tsx
<span
  className="line-clamp-2 text-xs leading-4 text-muted-foreground"
  title={r.description}
>
  {r.description || "—"}
</span>
```

`line-clamp-2` 是 Tailwind 3.3+ 内置工具类（`tailwindcss@3.4.19`，无需插件）。

### 4.4 节点行上的聚合信息

```tsx
<span className="ml-auto flex shrink-0 items-center gap-3 pl-3 text-xs tabular-nums text-muted-foreground">
  <span>{count} 条</span>
  {disabledCount > 0 ? (
    <span className="text-muted-foreground/70">停用 {disabledCount}</span>
  ) : null}
  {actions}
</span>
```

| 行 | 聚合信息 |
|---|---|
| L1 网络 | `{启用数} / {总数}`（如 `42 / 47`）+ 签名条数另计 |
| L2 内置规则 | `{netBuiltin.length} 条` + `停用 {hiddenBuiltin}`（仅 >0 时） |
| L2 自定义规则 | `{netCustom.length} 条` + `停用 {hiddenCustom}`（仅 >0 时） |
| L2 签名规则 | 引擎状态 Badge + `生效 {rule_count} 条` |

**为什么"停用数"用文字不用 Badge**：8 个节点行如果每行挂 2 个 Badge，侧边栏式的徽章密度会让树看起来像表格。停用数是次要信息，用 `text-xs text-muted-foreground/70` 表达，扫一眼能读到、但不抢主信息。

**为什么放右端（`ml-auto`）**：节点行的左侧是"这是什么"（图标 + 标题），右侧是"有多少"。左读语义、右读数量，和表格的列约定一致，不需要重新学习。

### 4.5 规则行（叶子）的列分配

用 CSS Grid 而不是 `Table` —— 现状把 `TableRow` 塞进树容器里，`<table>` 的 `display: table-row` 无法参与 flex/grid 布局，缩进和树线都挂不上去，这也是现状层级弱的技术原因。

**统一 7 列模板**（内置/自定义共用，保证列头对齐）：

```
grid-cols-[1.25rem_1.75rem_minmax(0,1fr)_7rem_5.5rem_3.5rem_4.5rem]
   ①         ②        ③            ④    ⑤     ⑥     ⑦
```

| # | 列 | 宽 | 内容 |
|---|---|---|---|
| ① | 展开 | `1.25rem`（20px） | `ChevronRight` 按钮，20×20 |
| ② | 启用 | `1.75rem`（28px） | `Switch size="sm"` |
| ③ | 名称 / 描述 / 规则 ID | `minmax(0,1fr)` | **恒定两行**（裁定 B）：第 1 行名称（+ 命中高亮 + 停用徽章）；第 2 行 `flex`：「描述 `line-clamp-2 flex-1`」+「规则 ID 前 8 位 `shrink-0 font-mono text-xs text-muted-foreground/60`」。描述配 `title={r.description}` |
| ④ | 类型 | `7rem`（112px） | `逐条` / `频率（src_ip ≥ 10）`，`text-xs text-muted-foreground truncate` |
| ⑤ | 级别 | `5.5rem`（88px） | `Badge variant={severityVariant(sev)}` |
| ⑥ | 优先级 | `3.5rem`（56px） | `text-right tabular-nums text-13` |
| ⑦ | 操作 | `4.5rem`（72px） | 自定义：`Pencil` + `Trash2` 图标按钮（h-7 w-7）；内置：空 |

固定列合计 `20+28+112+88+56+72 = 376px` + 6×gap(12px)=72px → `448px`。
③ 列净宽 = `视口 − 240(侧栏) − 48(main padding) − 32(ul p-2 + 行 px-2) − 40(两级缩进) − 448`：

| 视口 | ③ 列 |
|---|---|
| 1280 | 472px |
| 1600 | 792px |
| 1920 | **1112px** |

（我第一版写的"1920 → 1140px"是错的，差 28px —— 把 main 的 padding 数重了一次。以本表为准。）

**为什么内置组也留 72px 的操作列（空着）**：内置规则没有编辑/删除，但列头要和外面对齐。空列比"两组的列错位"好 —— 错位的列头会让人以为看错了列。

#### 2560 上 ③ 列的富余空间：不填

1920 上 ③ 列 1112px，而最长描述 90 字符 ≈ 1080px —— 两行排版下第二行只占约 540px，
右边仍有约 570px 富余。**这个富余不处理**（不设 `max-w`）：它是"文本自然结束后的空白"，
不是用户抱怨的"被拉长的控件"—— 输入框被拉长会让人找不到落点，文字提前结束不会。

#### 「≥2200 加第 8 列规则 ID」—— 最终裁定：不加

主理人曾短暂批准，后**撤回，最终按否决执行**。字段 `r.id` 真实存在，但不做常驻列：

1. 规则 ID 是"排查/对工单时"才用的字段（页面自己写着"自动生成、不可编辑"），
   做常驻列是给 22 行各加一段 UUID 前缀噪音，价值密度远低于类型 / 级别 / 优先级。
2. `LEAF_COLS` 会因此变成三套模板，而它被列头行、数据行、窄屏行**三处**引用 ——
   多一套就多三个失配点，而"列头错位"正是本节要防的问题。
3. 有零成本替代：见下一节，③ 列描述行末尾用 `flex` 放 ID，不需要任何断点、不动 `LEAF_COLS`。

**因此 `LEAF_COLS` 保持两套**（不是三套）：

```ts
export const LEAF_COLS =
  "grid-cols-[1.25rem_1.75rem_minmax(0,1fr)_7rem_5.5rem_3.5rem_4.5rem]";
export const LEAF_COLS_NARROW = "grid-cols-[1.25rem_1.75rem_minmax(0,1fr)]";
```

用法：`<div className={cn("grid items-center gap-x-3", LEAF_COLS_NARROW, "xl:" + …)}>` ——
**不要写运行时字符串拼接**，把两套模板各写成完整字面量、用变体 class 直接切换（见下条 JIT 提醒）。

> **Tailwind JIT 提醒**：任意值 class（如 `grid-cols-[1.25rem_…]`、`min-[1920px]:…`）必须是
> **源码里的完整字面量**，不能由 `.split().join()` 之类的运行时拼接生成 —— JIT 扫不到就不产出 CSS，
> 而且这类问题在本地 `tsc --noEmit` 下**完全看不出来**（AGENTS.md 禁止本地 build，只能靠 CI 发现）。
> 两个模板写成两个 `const` 字面量即可。

**规则 ID 放在 ③ 列描述行末尾（`flex` 方案，替代第 8 列）**：

```tsx
{/* ③ 列第二行：描述 + 规则 ID 前 8 位 */}
<div className="flex min-w-0 items-baseline gap-2">
  <span className="line-clamp-2 min-w-0 flex-1 text-xs leading-4 text-muted-foreground" title={r.description}>
    {r.description || "—"}
  </span>
  <span className="shrink-0 font-mono text-xs text-muted-foreground/60">{r.id.slice(0, 8)}</span>
</div>
```

`truncate` 会优先挤掉 `shrink-0` 之外的描述，窄屏下 ID 自然消失、宽屏自然出现 ——
不需要任何断点，也不需要第三套模板。

**为什么操作用图标按钮而不是文字按钮**：现状「编辑」「删除」两个 `Button size="sm"` 加起来 116px + gap，占掉 130px。图标按钮 28×2 + 8 = 64px。必须有 `aria-label` 和 `title`：

```tsx
<Button size="sm" variant="ghost" className="h-7 w-7 p-0"
        aria-label={`编辑规则 ${r.name}`} title="编辑"
        disabled={busy === r.id} onClick={() => openEdit(r)}>
  <Pencil className="h-3.5 w-3.5" />
</Button>
<Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-sev-critical-fg hover:bg-sev-critical-bg"
        aria-label={`删除规则 ${r.name}`} title="删除"
        disabled={busy === r.id} onClick={() => setAskDel(r)}>
  <Trash2 className="h-3.5 w-3.5" />
</Button>
```

`Pencil` / `Trash2` 已确认在 lucide 0.446 导出。**删除按钮用 `text-sev-critical-fg` + `hover:bg-sev-critical-bg`**，保持"删除是 destructive"这个既有语义，不用 `variant="destructive"`（实心红块在密集列表里太响）。

**列头行**（每个 L2 展开时显示一次）：

```tsx
<div className="grid grid-cols-[1.25rem_1.75rem_minmax(0,1fr)_7rem_5.5rem_3.5rem_4.5rem] items-center gap-x-3 bg-surface-1 px-2 text-xs font-medium text-muted-foreground h-8">
  <span /><span />
  <span>规则</span>
  <span>类型</span>
  <span>级别</span>
  <span className="text-right">优先级</span>
  <span className="text-right">操作</span>
</div>
```

放在 L3 `<ul>` 的**前面**作为兄弟节点，用 `pl-5` 对齐到叶子缩进。

**描述一律 `line-clamp-2`（裁定 B 下无单行档位，不存在 `line-clamp-1`）**：
`line-clamp` 的作用不是治空白（治不了），而是**守住 44px 行高的契约** ——
最长描述 90 字符，在 1280（③=472px）下两行只能放 78 字、1024（③=592px）下放 98 字，
不给 clamp 的话 1280 那条会折到第三行，该行从 44px 涨到 60px，而列头行与其它行的基准是按 44px 算的，
整列行高就散了。被 clamp 的只有最长的 1 条且只在 1280～1599，由 `title` 与展开详情面板兜底。

> **（原「已知风险 / A-B 二选一」段落已随裁定 B 生效而作废，保留决策过程以便追溯。）**
> 曾有两个选项：A = 阈值提到 `min-[1700px]`（≥1280 仍走单行）、B = 恒定两行。
> 主理人**裁定 B，A 不做**，理由是 A 只在 ≥1700 回平，而 1280～1699 覆盖 1366 与 1600 两档
> 最常见的企业分辨率，等于让最主流的两档继续倒退（1280 单行 26 字 vs 现状 60 字，净降 34 字）。
> 现按 B 执行，本段不再构成风险项。

**窄屏（<xl，即视口 < 1280）塌成 3 列**

```
grid-cols-[1.25rem_1.75rem_minmax(0,1fr)]
```

**为什么列模板的塌陷阈值是 `xl`(1280) 不是 `lg`(1024)**（Phase 2 复核后修正，初稿写的 `lg` 是错的）：
7 列模板的固定部分 = `376px(列) + 72px(6×gap) = 448px`。视口 1024 时 ③ 列只剩 **约 216px**，
连"名称 + 类型"都排不下（类型列本身就要 112px）。
塌成 3 列后 ③ 列回到 **592px（两行 98 字）**，与 1280 档位的 472px（两行 78 字）方向一致，
不会出现"屏幕变宽反而看得更少"。

> 注意：在**裁定 B** 下，`xl` 这个断点**只决定 ④⑤⑥⑦ 是留成列还是移到第三行，不决定行数**
> —— 两行是恒定的。上面"216px 只放得下 18 字"是按旧的单行口径算的，现在 `<1280` 走 3 列模板，
> ③ 列是 592px 而不是 216px。

类型 / 级别 / 优先级 / 操作 移到第三行（名称行、描述行之后）：

```tsx
<div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground xl:hidden">
  {ruleType(r)} · <Badge …/> · 优先级 {r.priority} · {操作按钮}
</div>
```

> 注意：`xl:hidden` / `xl:grid-cols-[…]` 是**视口**断点，而规则页 `width="full"` 且没有 rail，
> 所以这里视口断点与容器宽度的偏移只有 `240(侧栏) + 32(内边距)`，是本项目里少数可以直接用视口断点的地方。

### 4.6 展开详情面板（不再用 `TableRow` 内嵌）

```tsx
<div
  id={panelId}
  role="region"
  aria-labelledby={`${panelId}-label`}   /* ← 指向名称 span，不是整行 */
  className="mb-1 ml-5 mt-1 rounded-sm bg-surface-1 px-3 py-2"
>
  <p className="text-xs text-muted-foreground">
    规则 ID <span className="font-mono">{r.id}</span>
    {r.source === "builtin" ? " · 内置规则：描述/条件/级别/优先级每次启动会被内置定义覆盖，只有启用状态会保留" : null}
  </p>
  <p className="mt-1 text-13 leading-relaxed">{r.description || "（无描述）"}</p>
  <pre className="mt-2 max-h-56 overflow-auto rounded-xs border border-border-subtle bg-surface-2 p-2 font-mono text-xs leading-4">
    {JSON.stringify(r.conditions || {}, null, 2)}
  </pre>
</div>
```

**为什么用 `bg-surface-1` 无描边**：这是 L3 内联格的定义（"无标题、底色块"）。它落在 Card 的 `surface-2` 上，靠一层表面差就分得开，不需要再画一条边 —— 每多一条描边，树里就多一个盒子，第 4.0 节的规则就破了。

**为什么 `ml-5`**：和叶子的缩进对齐，让详情面板看起来"属于这一行"而不是浮在中间。

**为什么 `<pre>` 允许加 `border`**：代码块是"零装饰"原则的既定例外 —— 等宽字体 + 长行 + 可滚动，没有边界时滚动区域的范围不可知。这是全站已有的做法（现状 rules/page.tsx:435 就是 `border border-border-subtle bg-surface-2`），继续沿用。

**为什么补 `role="region"` + `aria-labelledby`**：`aria-expanded` 指向 `aria-controls` 后，读屏需要一个可命名的目标区域；没有 `role` 的 `div` 不会被宣布为区域，展开后读屏用户不知道内容出现在哪。

**`aria-labelledby` 必须指向名称 `<span>`，不能指向整行**（Phase 2 复核后修正，初稿写的 `rowId` 指向整行是错的）：
L3 行是 7 列 grid 的 `div`，可访问名会把 5 个单元格的文本全部拼起来，读屏会念成
"规则名 描述 逐条 高危 100 区域" —— 类型、级别、优先级被当成标题的一部分念出来。
正确做法：给名称 `<span>` 加 `id={`${panelId}-label`}`，详情面板 `aria-labelledby={`${panelId}-label`}`。
名称是这一行唯一能代表"展开的是哪条规则"的文本。

```tsx
{/* L3 行内 */}
<span id={`${panelId}-label`} className="truncate text-13 font-medium">{r.name}</span>
```

### 4.7 停用规则的视觉区分

现状是 `line-through` + `text-muted-foreground`（rules/page.tsx:413）。改为：

```tsx
<div className={cn(
  "grid items-center gap-x-3 rounded-sm px-2",
  "grid-cols-[1.25rem_1.75rem_minmax(0,1fr)_7rem_5.5rem_3.5rem_4.5rem]",
  r.enabled ? "hover:bg-brand-50" : "bg-surface-1 hover:bg-brand-50",
)}>
  …
  <span className={cn("truncate text-13 font-medium", r.enabled ? "text-foreground" : "text-muted-foreground")}>
    {r.name}
  </span>
  {!r.enabled ? <Badge variant="info">已停用</Badge> : null}
```

三处信号：**整行 `bg-surface-1`（退回一层表面）+ 名称 `text-muted-foreground` + `Badge variant="info"`。**

**为什么去掉 `line-through`**：中文笔画密度高，12–13px 下的删除线会和横笔画糊在一起（"重"字有 5 横），实际效果是"这条字变脏了"而不是"这条划掉了"；而且删除线在运维语境里强烈指向"已删除"，和"停用（还在库里、随时能开回来）"是相反的语义。

**为什么整行用 `bg-surface-1` 而不是只改文字色**：停用规则默认被 `showDisabled` 收起，勾上开关后会一次性放出几十条。只改文字色的话，几十条灰字混在黑字里要靠逐行读才能分辨；整行底色差让"这一片是停用的"变成一次扫视就能得到的信息 —— 这正是 L0/L1/L2/L3 表面分层存在的意义。

**严重度徽章不随启用状态变**：`critical` 的规则停用后仍然显示 `critical` 徽章。严重度是这条规则的事实属性，不是它的运行状态；把它一起变灰会让"这条曾经判严重"这个信息丢失。

### 4.8 工具栏

放在 Card 内、树的上方，`border-b border-border-subtle`。

```tsx
<PanelToolbar
  search={
    <div className="relative w-full sm:max-w-[20rem]">
      <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="搜索规则名称 / 描述 / ID"
        aria-label="搜索规则"
        className="h-8 pl-7 text-13"
      />
    </div>
  }
>
  <Button size="sm" variant="outline" onClick={expandAll}>
    <ChevronsDownUp className="mr-1 h-3.5 w-3.5" /> 全部展开
  </Button>
  <Button size="sm" variant="outline" onClick={collapseAll}>
    <ChevronsUpDown className="mr-1 h-3.5 w-3.5" /> 全部收起
  </Button>
  <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
    <Switch size="sm" checked={showDisabled} onCheckedChange={setShowDisabled}
            label="显示已停用" />
    显示已停用（<span className="tabular-nums">{disabledRules.length}</span>）
  </label>
  <Button size="sm" variant="outline" onClick={() => void load()}>刷新</Button>
  <Button size="sm" onClick={openCreate}>新建规则</Button>
</PanelToolbar>
```

`Search` / `ChevronsDownUp` / `ChevronsUpDown` 已确认在 lucide 0.446 导出。

**布局**：`flex flex-wrap items-center gap-2 px-3 py-2`，搜索框 `flex-1 min-w-0 sm:max-w-[20rem]`，按钮组在右（`ml-auto`）。

**"显示已停用" 为什么从 `Section.extra` 搬到工具栏**：现状它在 `Section` 的 `extra` 里（rules/page.tsx:545），和"刷新""新建"挤在区块标题行的右端，而它控制的是**树里显示什么** —— 控件离它作用的对象隔着一个标题行。搬进工具栏后，所有"作用于这棵树"的控件（搜索、展开、过滤）在同一个条上，形成一组。

**全部展开/收起**：

> **初稿这段有 bug，已被 Phase 2 指出，下面是用 effect 门闩的正确写法。**
> 初稿的 `setAll` 在同一处既调 `setExpanded((prev) => ({...prev, ...next}))` 又用闭包里的 `expanded` 拼 localStorage ——
> `expanded` 是本次渲染的快照，两次连续点击（或点击后有其它状态更新）会写出**过期内容**，
> 刷新后展开状态被回写丢失。

**localStorage 的写入统一收口到一个 effect，任何地方都不再手写 `setItem`**：

```tsx
/**
 * 只有读过一次本地存档之后才允许回写，否则首帧会用默认值把存档冲掉。
 *
 * **必须用 useState 不能用 useRef**（Phase 2 复核后修正）：同一帧内 effect 按声明顺序执行，
 * 若「读」在前、「写」在后，首帧会是「读（门闩置 true）→ 写（门闩已 true，但闭包里的
 * `expanded` 仍是默认值）」—— 默认值立刻覆盖刚读出来的存档，刷新后展开状态丢失。
 * useState 的门闩会触发重渲染，写 effect 在重渲染后才带着合并后的 `expanded` 跑，与声明顺序无关。
 * （两种都能 work，但不要混用。）
 */
const [hydrated, setHydrated] = React.useState(false);

// 写（唯一入口）
React.useEffect(() => {
  if (!hydrated) return;
  try { window.localStorage.setItem("shentong.rules.tree", JSON.stringify(expanded)); } catch {}
}, [expanded, hydrated]);

// 读（保持现状，key 与解析逻辑一字不改）
React.useEffect(() => {
  try {
    const raw = window.localStorage.getItem("shentong.rules.tree");
    if (raw) setExpanded((prev) => ({ ...prev, ...(JSON.parse(raw) as Record<string, boolean>) }));
  } catch { /* 隐私模式：用默认展开状态 */ }
  finally { setHydrated(true); }
}, []);

// 于是 toggle / setAll 都退化成纯 state 更新
function toggleNode(id: string) {
  setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
}

function setAll(open: boolean) {
  setExpanded((prev) => ({
    ...prev,
    network: open,
    "network:builtin": open,
    "network:custom": open,
    "network:signature": open,
  }));
}
```

注意**：不要把 `openIds`（叶子详情展开）一并开合** —— 每条规则的详情都带一个 `<pre>` 条件块，
全部展开会让页面瞬间长到几万像素。全部展开只作用于三层节点。

**搜索行为**（新增纯展示层 state，不改接口）：

```ts
const [q, setQ] = React.useState("");
const needle = q.trim().toLowerCase();
const match = (r: RuleItem) =>
  !needle ||
  r.name.toLowerCase().includes(needle) ||
  (r.description || "").toLowerCase().includes(needle) ||
  r.id.toLowerCase().includes(needle);
```

- 过滤只作用于 **L3 叶子**；祖先节点只要有一个后代命中就保持可见。
- **命中时祖先自动展开**：渲染时用 `needle ? true : !!expanded[id]` 覆盖展开状态，不改 `expanded` 本身（清空搜索后恢复原状）。
- **命中片段高亮**：

```tsx
<mark className="rounded-[2px] bg-brand-50 px-0.5 font-medium text-primary">{命中片段}</mark>
```

`<mark>` 的浏览器默认样式是黄底黑字，必须覆盖 —— 黄底在钢蓝主题里是唯一一处"外来色"，会立刻显得脏。

**底色只是框边界，字色才是主信号**（Phase 2 复核后修正，初稿只给了 `bg-brand-50` 是不够的）：
`--brand-50` 在亮色下是 `#ecf4fe`，它与**停用行的 `bg-surface-1`（`#f6f7f9`）亮度比只有约 1.03:1**，
与白卡也只有 1.11:1 —— 也就是说，搜索命中的停用时，高亮底色**肉眼完全看不见**。
改为 `text-primary`（`#144990` 在 `#ecf4fe` 上对比度 **8.03:1**）之后：

- 字色承担信号，底色只负责勾出命中片段的边界；
- 在停用行（`bg-surface-1`）里也照样看得见，因为字色不依赖底色；
- `font-medium` 而不是 `font-bold`（守住"禁止 700"）。

暗色分支不需要单独处理：`text-primary` / `bg-brand-50` 在 `.dark` 下分别是 `212 82% 58%` 与 `214 60% 16%`，
与页头一级菜单的选中态（`bg-primary/10` + `text-primary`）是同一对组合，全站已验证过。

- 命中数为 0 时，在树下方（不是每个分组下）给一条 `EmptyState size="compact"`：`没有匹配「{q}」的规则` + 一个「清空搜索」按钮。

### 4.9 空态与骨架

**加载骨架**：现状是 `TableSkeleton rows={5} cols={5}` —— 在树里它画不出缩进和层级。新增 `TreeSkeleton`：

```tsx
<TreeSkeleton rootRows={1} groupRows={2} leafRows={5} />
```

结构（照树形几何画）：

```tsx
<div className="space-y-1 p-3" aria-busy="true">
  {/* L1 */}
  <Skeleton className="h-11 w-full" />
  {/* L2 + L3，各带 pl-5 缩进 */}
  <div className="pl-5 space-y-1">
    <Skeleton className="h-10 w-full" />
    <div className="pl-5 space-y-1">
      {Array.from({ length: leafRows }).map((_, i) => (
        <Skeleton key={i} className="h-11 w-full" />   {/* L3 行高 44px（4.3 修正后） */}
      ))}
    </div>
  </div>
</div>
```

`Skeleton` 已有 `motion-reduce:animate-none`。

**`groupRows` 默认值是 3 不是 2**（Phase 2 复核后修正）：L2 实际有**三组** ——
内置规则 / 自定义规则 / 签名规则（rules/page.tsx:575-605），画两组会让签名组在加载完成时"凭空出现"。

**签名组的骨架高度是 `h-40`（160px），不是 `h-10`**（Phase 2 复核后修正）：
签名组的子级是 `SuricataRulesPanel`（实测量级 300–400px），给 `h-10` 差一个数量级，
加载完成后页面会突然长高一大截 —— 这正是骨架屏要消灭的跳版。

```tsx
{isSignatureGroup ? <Skeleton className="h-40 w-full" /> : <Skeleton className="h-10 w-full" />}
```

**但签名组默认收起**（`expanded` 初值只有 `network` 与 `network:builtin`），
所以首屏**不画**签名组的 `h-40` —— 只在 `expanded["network:signature"]` 为真时才画。
否则骨架会比真实首屏高一倍，"加载中"比"加载完"还长，反而制造了跳版。

**为什么骨架要照树形画**：加载态的形状预告了内容的形状。一个平的表格骨架后面接一棵树，内容到达时版式会跳；树形骨架让"这里将出现三层结构"提前 200ms 被识别，跳版感消失。

**空态**：沿用现状 `EmptyState size="compact"` 与"N 条已停用，当前已收起"的分支（rules/page.tsx:356-375），只加一条 —— **空态要缩进到叶子的位置**：

```tsx
<div className="pl-5">
  <EmptyState size="compact" … />
</div>
```

理由：空态出现在 L2 分组下面，不缩进的话它会从 L2 的标题位置开始，看起来像"这一组没有子节点"而不是"这一组没有规则"。

### 4.10 无障碍基线（明确不做 ARIA tree）

- 每个展开按钮：`aria-expanded` + `aria-controls`（指向子 `<ul id>`）。
- 子列表：`<ul>` 包 `<li>`，读屏会宣布"列表，N 项"。
- 详情面板：`role="region"` + `aria-labelledby`。
- 焦点：所有可交互元素 `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40`（`Button` 基类已有，手写 `<button>` / `<Link>` 要补）。
- `Switch`：`role="switch"` + `aria-checked` + `aria-label`。

**明确不做 `role="tree"` / `role="treeitem"` / 方向键导航。**

为什么：完整的 ARIA tree 要求 `aria-level`、`aria-setsize`、`aria-posinset`、`aria-selected`、roving `tabindex`（容器内只有一个 `tabindex=0`）、以及 ← → ↑ ↓ Home End 全部实现。做一半的 tree role 比不做更糟 —— 读屏会宣布"树，3 项"，但用户按方向键没反应、Tab 又跳不到子项。本项目现有页面没有一处用了 tree role，引入它会让规则页成为唯一的"键盘行为不一致"的页面。用 `<ul>/<li>` + 原生 Tab 顺序，行为可预测，也满足"键盘可达、焦点可见"的基线要求。

### 4.11 检测规则页装配后的完整结构

```tsx
<PageShell title="检测规则" width="full">
  <Section
    title="规则来源"
    description="按来源分组：内置定义 / 自建规则 / 签名文件。默认只列生效中的规则，停用的收在开关里。"
  >
    <Card>
      <PanelToolbar search={…}>…</PanelToolbar>
      <ul className="p-2">
        <li> {/* L1 网络 */}
          <button aria-expanded aria-controls className="flex h-11 items-center gap-2 px-2 …">
            <Radio className="h-4 w-4 text-muted-foreground" />
            <ChevronRight className={cn("h-3.5 w-3.5 …", open && "rotate-90")} />
            <span className="text-sm font-medium">网络（网络采集器）</span>
            <span className="ml-auto …">{启用数} / {总数}</span>
          </button>
          <ul id="…">
            <TreeRow last={false} mid={20}>   {/* L2 内置规则 */}
              <button className="flex h-10 items-center gap-2 …">…</button>
              <div className="pl-5"> {/* 列头 */} </div>
              <ul>
                <TreeRow last={false} mid={24}> {/* L3 规则行，7 列 grid */} </TreeRow>
                …
              </ul>
            </TreeRow>
            <TreeRow last={false} mid={20}>   {/* L2 自定义规则 */} </TreeRow>
            <TreeRow last={true}  mid={20}>   {/* L2 签名规则 */}
              <SuricataRulesPanel variant="inline" />
            </TreeRow>
          </ul>
        </li>
      </ul>
    </Card>
  </Section>
</PageShell>
```

---

## 5. 需要新增 / 修改的组件清单

### 5.1 `packages/ui/src/components/ui/switch.tsx`（新增）

为什么放共享包：agent 前端的 `cloud-panel` / `rebuild-panel` 也有开关需求，是通用控件。

```tsx
export interface SwitchProps {
  checked: boolean;
  onCheckedChange: (next: boolean) => void;
  /** 必填：作为 aria-label 与 title，图标轨/图标按钮场景下读屏与悬停都靠它 */
  label: string;
  disabled?: boolean;
  size?: "sm" | "md";
  className?: string;
  id?: string;
}
export function Switch(props: SwitchProps): JSX.Element;
```

实现要点：

```tsx
<button
  type="button"
  role="switch"
  aria-checked={checked}
  aria-label={label}
  title={label}
  disabled={disabled}
  onClick={() => onCheckedChange(!checked)}
  className={cn(
    "relative inline-flex shrink-0 items-center rounded-full border transition-colors",
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
    "disabled:cursor-not-allowed disabled:opacity-50 motion-reduce:transition-none",
    size === "sm" ? "h-4 w-7" : "h-5 w-9",
    checked ? "border-primary bg-primary" : "border-border bg-surface-1",
    className,
  )}
>
  <span
    aria-hidden
    className={cn(
      "absolute rounded-full bg-surface-2 shadow-1 transition-transform motion-reduce:transition-none",
      size === "sm" ? "left-0.5 h-3 w-3" : "left-0.5 h-4 w-4",
      checked ? (size === "sm" ? "translate-x-3" : "translate-x-4") : "translate-x-0",
    )}
  />
</button>
```

**为什么"开"用 `bg-primary`**：globals.css 约定品牌蓝表示"可操作、选中、焦点"，且"绝不用来画数据或状态"。开关的开合是**控件状态**（用户做出的选择），不是业务状态；业务状态（启用/停用）已经由 4.7 节的行底色 + 「已停用」徽章表达。这条界线要写进组件注释，避免后面有人拿开关去画别的语义。

**暗色分支**：`--primary` 在 `.dark` 下是 `212 82% 58%`（亮蓝），`--surface-2` 是 `220 24% 12%`（深），滑块深、轨道亮，对比足够，不需要为 `.dark` 单独写分支。

### 5.2 `packages/ui/src/components/ui/field.tsx`（新增）

```tsx
export interface FieldProps {
  label: React.ReactNode;
  /** 对应控件的 id；不传则用 React.useId() 生成 */
  htmlFor?: string;
  /** 控件下方的口径说明，一行 */
  hint?: React.ReactNode;
  /** 校验失败文案：出现时 label 与 hint 让位，整块转语义红 */
  error?: React.ReactNode;
  required?: boolean;
  /** 宽度档位，见 2.3：sm 跟随列 / md 上限 480 / lg 占 2 列 / full 占满 */
  span?: "sm" | "md" | "lg" | "full";
  className?: string;
  children: React.ReactNode;
}
export function Field(props: FieldProps): JSX.Element;
```

渲染：

```tsx
<div className={cn("min-w-0", SPAN[span], className)}>
  <label htmlFor={id} className="mb-1 block text-xs text-muted-foreground">
    {label}
    {required ? <span aria-hidden className="ml-0.5 text-sev-critical-fg">*</span> : null}
  </label>
  {children}
  {error ? (
    <p role="alert" className="mt-1 text-xs text-sev-critical-fg">{error}</p>
  ) : hint ? (
    <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{hint}</p>
  ) : null}
</div>
```

`SPAN` 常量：

```ts
const SPAN = {
  sm:   "",
  md:   "min-[1600px]:max-w-[30rem]",
  lg:   "col-span-2",
  full: "col-span-full",
} as const;
```

为什么需要它：现状每个面板里 `<label class="mb-1 block text-xs text-muted-foreground">` 这行重复了 60+ 次，改一次要改 10 个文件。而且 `htmlFor` / `id` 的手工配对很容易漏（rules 抽屉里已有 `rule-id` 在三处重复使用的隐患）。

### 5.3 `packages/ui/src/components/ui/field.tsx` 同文件导出 `FieldGrid`（新增）

```tsx
export function FieldGrid({
  children,
  /** 最宽处（min-[1920px]）的列数；窄处自动降级 */
  maxCols = 3,
  className,
}: {
  children: React.ReactNode;
  maxCols?: 2 | 3 | 4;
  className?: string;
}): JSX.Element;
```

```ts
const COLS = {
  2: "grid-cols-1 md:grid-cols-2",
  3: "grid-cols-1 md:grid-cols-2 min-[1600px]:grid-cols-3",
  4: "grid-cols-1 md:grid-cols-2 min-[1600px]:grid-cols-3 min-[1920px]:grid-cols-4",
} as const;
// 容器：cn("grid gap-x-4 gap-y-3", COLS[maxCols], className)
```

为什么把列数阶梯封进组件：这个 class 串有 4 个断点、20 个单词，让每个面板自己写一定会写错或写漏。

**适用范围（2026-10 补，与 ux-designer 对齐）**：`Field` / `FieldGrid` 只服务**配置管理页的表单段**——那里的字段带口径说明、可能带校验错误，且一屏 8–14 个字段，值得用列数阶梯吃掉宽屏。**两个工作台页明确排除**：

- `/logs`（日志检索）与 `/events`（事件中心）：筛选区是「即填即走的工作台条」，用 `<label>` 包裹控件 + `mt-1` 的平铺写法（`logs-panel.tsx:244-443`），且事件中心的筛选区与日志页逐字一致是硬要求（`docs/ui/events-center-ux-spec.md` §2.3）。

排除的理由不是「FieldGrid 不好」，而是两类页面的字段密度不同：配置页一屏十几个字段，列数阶梯是刚需；工作台页一屏六个筛选维度，`flex-wrap` 平铺更直白，套 FieldGrid 会让控件长得比它作用的内容还高。**别把「配置页用了新原语」推广成「全站表单都用新原语」**——那正是两页控件长相分裂的来源。

### 5.4 `packages/ui/src/components/ui/panel-toolbar.tsx`（新增）

**适用范围同 5.3**：只进配置管理页的卡片第一条。日志检索与事件中心的筛选区不用它——那两页的筛选区是整个 Section 的主体（`Section` + `Card` 三段式），不是卡片内的一条工具带。

```tsx
export function PanelToolbar({
  search,
  children,
  className,
}: {
  /** 左侧检索区；不传则不渲染左侧 */
  search?: React.ReactNode;
  /** 右侧操作组 */
  children?: React.ReactNode;
  className?: string;
}): JSX.Element;
```

```tsx
<div className={cn(
  "flex flex-wrap items-center gap-2 border-b border-border-subtle px-3 py-2",
  className,
)}>
  {search ? <div className="min-w-0 flex-1 sm:max-w-[20rem]">{search}</div> : null}
  <div className="ml-auto flex flex-wrap items-center gap-2">{children}</div>
</div>
```

为什么需要它：8 个配置页里 6 个有"搜索/过滤 + 刷新 + 新建"的条，现状各写在 `Section.extra` 里，宽度、间距、换行规则各写各的。

### 5.5 `packages/ui/src/components/ui/settings-grid.tsx`（修改）

```tsx
// SettingsGrid：不变（保留 xl:grid-cols-[minmax(0,1fr)_19rem] items-start gap-4）

// SettingsMain：不变

// SettingsRail：加两处
export function SettingsRail({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "min-w-0 space-y-3",
        // 堆叠态（<xl）收窄：只读卡不被拉满整幅
        "max-xl:max-w-[34rem]",
        // 两列态粘在页头下方，长表单滚动时"当前生效值"不消失
        "xl:sticky xl:top-[4.25rem]",
        className,
      )}
    >
      {children}
    </div>
  );
}
```

同步更新组件顶部的注释（把 0.3 节的断档说明与 2.2 节的白/黑名单写进去）。

### 5.6 `packages/ui/src/components/ui/skeleton.tsx`（修改，追加 `TreeSkeleton`）

```tsx
export function TreeSkeleton({
  rootRows = 1,
  groupRows = 3,
  leafRows = 5,
  /** true = 最后一个分组按"大面板"画骨架（h-40）；false = 按普通行画（h-10） */
  lastGroupTall = false,
  className,
}: {
  rootRows?: number;
  /** L2 组数：规则树是 3（内置 / 自定义 / 签名），见 4.9 */
  groupRows?: number;
  leafRows?: number;
  lastGroupTall?: boolean;
  className?: string;
}): JSX.Element;
```

实现见 4.9。为什么放共享包：`agent` 前端的 `cases` / `skills` 列表也是树形，将来可复用。

### 5.7 `packages/ui/src/index.ts`（修改）

追加三条导出：

```ts
export * from "./components/ui/switch";
export * from "./components/ui/field";
export * from "./components/ui/panel-toolbar";
```

### 5.8 `ndr/frontend/components/page-shell.tsx`（修改）

- 新增 `width?: "standard" | "wide" | "full"` prop，`fluid` 保留为 deprecated 别名（1.1 节）
- `ml-60` → `ml-[var(--sidebar-w)]`（1.4 节）
- 顶部注释补一段：说明外槽为什么在 1920/2560 上分别是 0 / 96px，以及 `width` 三档的选择依据

### 5.9 `ndr/frontend/components/nav.tsx`（修改）

- `w-60` → `w-[var(--sidebar-w)]`
- 条目结构：三行 → 单行 `h-8`，描述移到 `title`（3.1 节）
- 分组标题加 `border-t`、收 `pt-4` → `pt-3`（3.2 节）
- 选中态：去掉 `border-l-2 border-primary`，改 `bg-brand-50` + `text-primary`；hover 从 `bg-accent` 改 `bg-surface-1`（3.3 节）
- 窄屏：标签/分组标题/分区名一律 `max-lg:sr-only`（**不是 `max-lg:hidden`**，否则读屏丢名字），链接 `max-lg:justify-center max-lg:px-0`，分隔线 `aria-hidden`（3.4 节）
- 出厂口令告警条在图标轨下只留图标 + `title`

### 5.10 `ndr/frontend/components/rule-tree.tsx`（新增）

树形原语放 NDR 前端而不是共享包：树形在本项目里只有规则页一处使用，放进 `packages/ui` 会要求它同时服务 agent 前端，而 agent 没有同样的层级结构 —— 通用化会引入用不到的 props 与分支。

```tsx
import type { LucideIcon } from "lucide-react";

/** 子级列表容器。渲染为 <ul>，读屏会宣布"列表，N 项"。 */
export function TreeChildren({
  id, children, className,
}: {
  id?: string;                 // 供父级按钮的 aria-controls 引用
  children: React.ReactNode;
  className?: string;
}): JSX.Element;
// <ul id={id} className={cn("relative", className)}>

/** 一行（L2 / L3 通用）。自动画树干与肘线。 */
export function TreeRow({
  last = false,
  mid = 20,
  className,
  children,
}: {
  /** 是否本组最后一行：决定树干只画到肘线（└）还是贯穿（├） */
  last?: boolean;
  /** 行中线 y（px）：L2 子级 20（行高 40）、L3 子级 22（行高 44） */
  mid?: 20 | 22;
  className?: string;
  children: React.ReactNode;
}): JSX.Element;

/** 展开/收起 chevron，供节点行与叶子行共用 */
export function TreeChevron({ open, className }: { open: boolean; className?: string }): JSX.Element;

/** 规则叶子行的 7 列网格模板（宽/窄两套），列头与数据行共用保证对齐 */
export const LEAF_COLS =
  "grid-cols-[1.25rem_1.75rem_minmax(0,1fr)_7rem_5.5rem_3.5rem_4.5rem]";
export const LEAF_COLS_NARROW = "grid-cols-[1.25rem_1.75rem_minmax(0,1fr)]";
```

`TreeRow` 实现：

```tsx
const MID = {
  20: { line: "h-5", elbow: "top-5" },                 // L2 行高 40 的中线
  22: { line: "h-[22px]", elbow: "top-[22px]" },       // L3 行高 44 的中线（4.3 修正后 48→44）
} as const;

export function TreeRow({ last = false, mid = 20, className, children }: TreeRowProps) {
  const m = MID[mid];
  return (
    <li className={cn("relative pl-5", className)}>
      <span aria-hidden className={cn("absolute left-2 top-0 w-px bg-border-subtle", last ? m.line : "h-full")} />
      <span aria-hidden className={cn("absolute left-2 h-px w-3 bg-border-subtle", m.elbow)} />
      {children}
    </li>
  );
}
```

### 5.11 `ndr/frontend/app/config/rules/page.tsx`（修改；原 `app/admin/rules/page.tsx`）

- 删掉本地 `TreeNode`（rules/page.tsx:66-106），改用 `TreeChildren` / `TreeRow` / `TreeChevron`
- `builtinTable` / `customTable` 从 `<Table>` 改为 7 列 `grid` 行（4.5 节）
- 启用控件 `checkbox` → `Switch`（语义不变，`onCheckedChange` 里调同一个 `toggle(r)`）
- 展开详情从 `<TableRow><TableCell colSpan={4}>` 改为 `role="region"` 的 `div`（4.6 节）
- 新增 `q` 搜索 state + 命中高亮（4.8 节）；**`openIds` / `showDisabled` 逻辑不变**，`expanded` 的读写改为
  "一处 effect 读 + 一处 effect 写"（4.8 节），key `shentong.rules.tree` 与 payload 形状一字不改
- 新增 `setAll(open)` 接"全部展开/收起"，只动三层节点，不动 `openIds`
- `PageShell` 改传 `width="full"`
- 抽屉里的表单改用 `FieldGrid` + `Field`（3 个 `fieldset` 的结构不变）

### 5.12 `ndr/frontend/components/suricata-rules-panel.tsx`（修改）

新增 `variant` prop：

```tsx
export function SuricataRulesPanel({
  variant = "card",
}: { variant?: "card" | "inline" }): JSX.Element;
```

- `variant="card"`：现状行为，直接被某个页面独立使用时用（保留默认，避免影响其它引用方）
- `variant="inline"`：在规则树里使用。**内部所有 `Card` 降级为内联格**：

```tsx
// 卡片：
<div className="rounded-sm bg-surface-1 p-3">        {/* 无 border */}
// 卡片标题：
<div className="mb-2 flex items-center justify-between gap-2 text-13 font-medium text-foreground">
```

**为什么必须改**：第 4.0 节规定整树装在一张 Card 里，内部禁止再出现 Card。签名面板是 L2 节点的子内容，它现有的 3 张 Card 会成为"Card 套 Card"，破坏全站层级约定。同时它内部的 `SettingsGrid`（1fr + 19rem）在树里会再拆一次列，加上树的 20px 缩进，主列只剩 ~700px。

**`variant="inline"` 下的 `SettingsGrid` 保留**（它管的是"主列能改 / 侧栏只读"这个语义，与盒子层级无关），但把 rail 从 19rem 降到 `min-[1600px]` 以下不拆列 —— 直接用 `xl:grid-cols-[minmax(0,1fr)_16rem]`。

### 5.13 `ndr/frontend/app/globals.css`（修改）

只加 `--sidebar-w` 与它的 `<1024` 覆盖（1.4 节）。**不新增任何颜色 token** —— 本规范用到的全部是既有语义变量（`surface-1/2`、`border-subtle`、`brand-50`、`primary`、`sev-*`、`muted-foreground`），两个前端（NDR 亮 / agent 暗）自动各自生效。

### 5.14 八个 `app/config/*/page.tsx` 与对应面板（修改）

| 文件 | 改动 |
|---|---|
| `admin/collect/page.tsx` | `PageShell` 加 `width="standard"`（默认，可不写） |
| `admin/networks/page.tsx` | `width="wide"` |
| `admin/filters/page.tsx` | `width="wide"` |
| `admin/storage/page.tsx` | `width="standard"` |
| `admin/agent/page.tsx` | `width="standard"` |
| `admin/account/page.tsx` | `width="standard"` |
| `admin/config/page.tsx`（health） | `width="wide"`（现状是默认 1500 上限） |
| `admin/rules/page.tsx` | `width="full"` |

面板侧（只改布局，不动接口与状态）：

- `zeek-panel.tsx`：卡片内 `sm:grid-cols-2` → `<FieldGrid maxCols={4}>`；字段包 `<Field>`；为 `section="iface"` 补 rail（采集器运行状态）
- `account-panel.tsx`：密码表单 → `<FieldGrid maxCols={2}>`（4 列对 3 个密码框太散，2 列 + `lg` 档宽度）
- `ingest-filters-panel.tsx` / `exclusions-panel.tsx`：表单段改 `FieldGrid`；5 列表格提出来做整幅块（M3）
- `logstash-panel.tsx` / `mcp-panel.tsx` / `agent-push-panel.tsx`：表单段改 `FieldGrid`；`TEXTAREA_CLS` / 代码编辑器用 `span="full"`
- `relay-nodes-panel.tsx`：10 列表格已经是整幅，只确认它没有包在 `SettingsGrid` 里
- `es-panel.tsx`：只读卡，确认 rail 位

---

## 6. 全局约束核对表（Phase 3 提交前逐条打勾）

- [ ] 没有 `import` 任何新包；图标全部来自 `lucide-react` 且已在本机 `node_modules/lucide-react/dist/lucide-react.d.ts` 里核对过导出名
- [ ] 没有出现 `font-weight:700` / `font-bold`；层级只用 `font-medium` + 字号，且字号类名只从这张表取：`text-xs`(12) ／ `text-13`(13) ／ `text-sm`(14) ／ `text-base`(16) ／ `text-28`(28)。**`text-14` 与 `text-11` 都不是合法的 Tailwind 类名**（`tailwind.config.ts` 的 `fontSize.extend` 只加了 `13` 和 `28`）
- [ ] 没有硬编码色值（`#xxx` / `bg-red-950` / `text-blue-500`）；颜色一律走 `tailwind.config.ts` 里的语义键
- [ ] 新增组件的每个颜色都能在 `.dark` 分支下取到对应变量（不新增 `.dark` 分支 = 说明用对了既有 token）
- [ ] 没有渐变（`bg-gradient-*`）、玻璃拟态（`backdrop-blur`）、发光（`shadow-*` 带颜色）、彩色投影
- [ ] 新增的 `transition-*` 都配了 `motion-reduce:transition-none`；骨架的 `animate-pulse` 配了 `motion-reduce:animate-none`
- [ ] 所有可点击元素有 `focus-visible:ring-2 focus-visible:ring-ring/40`（`Button` 基类自带；手写 `<button>` / `<Link>` 要补）
- [ ] 树里没有 `role="tree"` / `role="treeitem"`（4.10 节）
- [ ] 图标按钮都有 `aria-label` + `title`
- [ ] `<mark>` 覆盖了默认黄底，**且同时给了 `text-primary font-medium`**（只给 `bg-brand-50` 在停用行上看不见，4.8 节）
- [ ] 图标轨下隐藏文字一律用 `max-lg:sr-only`，**没有出现 `max-lg:hidden`**（否则读屏拿到 8 个无名链接，3.4 节）
- [ ] 详情面板的 `aria-labelledby` 指向**名称 `<span>` 的 id**，不是整行（4.6 节）
- [ ] `TreeSkeleton` 的 `groupRows` 默认 3，签名组骨架 `h-40` 且只在展开时画（4.9 节）
- [ ] `localStorage` 的 `setItem` 全页只有一处（effect），`setAll` / `toggleNode` 里没有手写 `setItem`（4.8 节）
- [ ] 没有 `npm run build` / `next build` / `docker build`；只跑了 `npx tsc --noEmit`（AGENTS.md 硬性要求）
- [ ] 接口路径、请求体字段、`openIds` / `showDisabled` 状态机、`localStorage` key 与 payload 形状一个都没改
- [ ] 描述 `<span>` 配 `line-clamp-2` + `title={r.description}`；**没有 `line-clamp-1`**（裁定 B 恒定两行，无单行档位）
- [ ] 叶子行恒定两行、行高 44px、行模板只有 `LEAF_COLS` 与 `LEAF_COLS_NARROW` 两套（`xl:` 只切列不切行数）
- [ ] **规范里凡是"实测数据"，都是直接导入模块或 AST 取的值，不是正则数的**（4.3 节踩过：单行正则漏掉跨行隐式拼接，19/54 与真实 22/90 差了一个量级）
- [ ] **rail / 表格里写的每一个字段都对着 `ndr/frontend/lib/api.ts` 的类型核过**（Q2 教训：初稿在 collect 的 rail 里写了 `PID`，`ZeekStatus` 根本没有这个字段 —— 规范里只能出现真实存在的字段）
- [ ] `LEAF_COLS` 的三套模板都是**源码里的完整字面量**，没有用字符串拼接生成（否则 Tailwind JIT 扫不到，4.5 节）
