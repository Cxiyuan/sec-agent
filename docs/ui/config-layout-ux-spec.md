# 配置管理 · 体验规范（Phase 2）

> 适用：`/config/*` 八个二级页（collect / networks / rules / filters / storage / agent / health / account）
> 前置：必须先读 `docs/ui/config-layout-visual-spec.md`（Phase 1，视觉方向）。本文**不推翻**它的任何视觉决策；有分歧的部分单列在第 5 节「对 Phase 1 的质疑」，不直接改 Phase 1 的章节。
> 硬约束：不新增依赖（图标只用 `lucide-react@0.446` 已确认导出的 `ChevronRight` / `ChevronsUpDown` / `ChevronsDownUp` / `Search` / `Pencil` / `Trash2` / `Radio`）；不改接口路径、请求体字段、`localStorage` key；本阶段只写文档。
> 读者：照着写代码的工程师。每条给具体数值、状态迁移与理由。

---

## 0. 本文的边界与三个已确认的缺陷

### 0.1 本文管什么、不管什么

| 管 | 不管 |
|---|---|
| 交互时序与状态迁移（点击 → 反馈 → 落地） | 颜色 / 字号 / 间距 / 树线几何（Phase 1 已定） |
| 响应式各断点"用户看到什么" | 断点阈值的视觉理由（Phase 1 1.2 已算） |
| 空 / 加载 / 错误三态的形状与文案 | 卡片层级与 box 语言（Phase 1 2.x / 4.0） |
| rail 里放哪些真实字段、空值显示什么 | rail 的白/黑名单（Phase 1 2.2，本文沿用在 4.0） |
| 键盘、焦点、ARIA 落点 | 是否用 `role="tree"`（Phase 1 4.10 已定：不用） |

### 0.2 读代码读出来的三个缺陷（Phase 1 未覆盖，本文修）

| # | 缺陷 | 位置 | 修法 |
|---|---|---|---|
| B1 | **搜索永远搜不到停用规则**。`shown = showDisabled ? rules : rules.filter(r => r.enabled)`，`match` 若作用于 `shown`，则未勾「显示已停用」时停用规则不在候选池里。运维搜一条规则名想确认它是否还在 → 搜不到 → 判定"规则没了" → 重复新建或误判检测盲区 | `rules/page.tsx:188-191` | 1.5.2 |
| B2 | **图标轨下导航项对读屏完全无名**。`max-lg:hidden` 把 `<span>{label}</span>` 从无障碍树里一起移除，`<Link>` 内只剩一个无 `aria-hidden` 的 SVG → 读屏宣读"链接" | Phase 1 3.4 | Q8 |
| B3 | **localStorage 写入在 state updater / 闭包里**。现状 `toggleNode` 在 `setExpanded` 的 updater 内写（React 18 StrictMode 下 updater 会被调用两次）；Phase 1 4.8 的 `setAll` 用闭包 `expanded` 拼接（同一 tick 内连点两次会丢一次）。两者写法还不一致 | `rules/page.tsx:176-186`、Phase 1 4.8 | 1.2 |

B3 的修法**不改 `localStorage` key 与 payload 结构**（仍是 `shentong.rules.tree` → `JSON.stringify(expanded)`），只换写入时机与幂等写法。

---

## 1. 检测规则树交互规范

### 1.1 状态清单与所有权

| state | 类型 | 持久化 | 写入方 | 本文是否新增 |
|---|---|---|---|---|
| `rules` | `RuleItem[]` | 否 | `load()`（`/api/rules`） | 否 |
| `expanded` | `Record<string, boolean>`，key ∈ 4 个白名单 | **是** `shentong.rules.tree` | `toggleNode` / `setAll` / mount 读取 | 否（持久化时机改，见 1.2） |
| `openIds` | `Record<string, boolean>`，key = 规则 id | 否 | L3 chevron | 否 |
| `showDisabled` | `boolean` | 否 | 工具栏 Switch | 否 |
| `busy` | `string`（规则 id） | 否 | `toggle` / `remove` | 否 |
| `loading` | `boolean` | 否 | `load()` | 否 |
| `q` | `string` | 否 | 搜索框 | **新增（纯展示层）** |
| `collapsedDuringSearch` | `React.MutableRefObject<Set<string>>` | 否 | 搜索中收起节点 | **新增（纯展示层）** |
| `hydrated` | `boolean` | 否 | mount effect | **新增（纯展示层）** |

三个新增 state 都不进 `localStorage`、不影响任何接口请求体。

`expanded` 的 key 白名单（**唯一合法集合**）：

```
"network" | "network:builtin" | "network:custom" | "network:signature"
```

读取 localStorage 时只保留这 4 个 key —— 主机监控那条线已下线，老浏览器里可能残留 `host*` / `host:builtin` 之类的键，它们不影响渲染但是脏数据，未来若新增/删除节点还会被"复活"。

### 1.2 `expanded` 状态迁移表（表 A）

| # | 触发 | 前置条件 | 动作 | `expanded` 结果 | 写 localStorage | 备注 |
|---|---|---|---|---|---|---|
| A1 | 组件挂载 | — | `useState({ network: true, "network:builtin": true })` | 默认值 | **不写**（`hydrated=false`） | 门闩必须先关 |
| A2 | mount effect | 读到合法 JSON | `setExpanded(prev => ({ ...prev, ...pick(saved) }))` | 默认 ∪ 存档 | — | 之后 `setHydrated(true)` |
| A3 | mount effect | 无值 / `JSON.parse` 抛错 / `localStorage` 不可用 | 不变 | 默认值 | — | `try/catch` 静默，与现状一致 |
| A4 | 点 L1 / L2 行的 chevron | 任意 | `toggleNode(id)` 翻转该 key | 该 key 翻转 | 写（effect） | 搜索中点击见 A8 |
| A5 | 点「全部展开」 | 任意 | 4 个 key 全 `true` | 全 true | 写（effect） | **不动 `openIds`** |
| A6 | 点「全部收起」 | 任意 | 4 个 key 全 `false` | 全 false | 写（effect） | **不动 `openIds`** |
| A7 | 输入搜索词 | — | **不修改** `expanded` | 不变 | 不写 | 展开与否由渲染期覆盖（1.3） |
| A8 | 搜索中收起某节点 | `needle` 非空 | `toggleNode(id)` + `collapsed.add(id)` | 该 key false | 写（effect） | 没有它搜索期就收不起来 |
| A9 | 清空搜索 / 改 `q` 任意一个字符 | — | `collapsed.clear()` | 不变（A8 写过的保留） | 不写 | 清空后回到 `expanded` 语义 |
| A10 | `toggle()` / `save()` / `remove()` 后的 `load()` | — | **不修改** `expanded` | 不变 | 不写 | 刷新不能重置树 |
| A11 | 点工具栏「刷新」 | — | **不修改** `expanded` | 不变 | 不写 | 同上 |

**为什么 A5/A6 不得连带 `openIds`**（Phase 1 4.8 已提，这里给数字）：规则详情面板最小高度 ≈ 120px（ID 行 16 + 描述 20 + `<pre>` 最小 80 + padding 16）。内置规则实测 **22 条**（`ndr/backend/app/rules/builtin.py:167` 的 `BUILTIN_RULES`），全展开 ≈ 2640px；再加现场自建的自定义规则（按 5 条估）≈ 3240px。滚动条从约 1/4 屏缩到 1/30 屏，用户失去位置感。代价远大于收益。

**持久化写法（替换现状 `toggleNode` 内的副作用与 Phase 1 4.8 的 `setAll`）**：

```tsx
const TREE_KEY = "shentong.rules.tree";
const TREE_KEYS = ["network", "network:builtin", "network:custom", "network:signature"] as const;

// 读：mount 一次
React.useEffect(() => {
  try {
    const raw = window.localStorage.getItem(TREE_KEY);
    if (raw) {
      const saved = JSON.parse(raw) as Record<string, boolean>;
      const next: Record<string, boolean> = {};
      for (const k of TREE_KEYS) if (typeof saved[k] === "boolean") next[k] = saved[k];
      setExpanded((prev) => ({ ...prev, ...next }));
    }
  } catch {
    /* 隐私模式 / 存储不可用：用默认展开状态 */
  }
  setHydrated(true);
}, []);

// 写：hydrate 之后才写，且只依赖 state 本身
React.useEffect(() => {
  if (!hydrated) return;
  try {
    window.localStorage.setItem(TREE_KEY, JSON.stringify(expanded));
  } catch {
    /* 存不了就算了，只是不记忆 */
  }
}, [expanded, hydrated]);

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

`hydrated` 门闩是**必须**的：没有它，mount 时写 effect 会用默认值（A1）覆盖掉用户上次「全部收起」的存档 —— 这是把持久化改成 effect 之后最容易踩的坑。

### 1.3 渲染期展开判定（表 B）

```ts
const isOpen = (id: string) =>
  needle ? !collapsed.current.has(id) : !!expanded[id];
```

| `needle` | `collapsed.has(id)` | `expanded[id]` | 渲染结果 | 场景 |
|---|---|---|---|---|
| `""` | （忽略） | `true` | 展开 | 正常浏览 |
| `""` | （忽略） | `false` | 收起 | 正常浏览 |
| 非空 | `false` | `true` / `false` | **强制展开** | 命中时祖先自动展开（Phase 1 4.8） |
| 非空 | `true` | 任意 | **收起** | 用户在搜索中手动收起了这一组（A8） |

**为什么需要 `collapsedDuringSearch` 这个额外集合**：Phase 1 只写了「命中时祖先自动展开、不改 `expanded`」，但那样一来搜索期间的 chevron 点击会被渲染期覆盖吃掉 —— 点了收起没反应，控件失灵（违反"用户控制与自由"）。加一个只在搜索期有效的"显式收起"集合，`expanded` 全程保持干净，清空搜索即恢复。用 `useRef` 而不是 `useState`：它不参与渲染（只在事件里写、在渲染里读同一份），用 state 会多一次无意义的重渲染。

**签名分组（`network:signature`）特殊处理**：它不是规则列表，没有可匹配的叶子。

```ts
const isSignatureOpen = !!expanded["network:signature"];  // 不受 needle 覆盖
```

理由：签名面板是一个 ~300px 高的表单（更新来源 + 版本 + 历史），把它塞进搜索结果里会占掉半屏；而且它在语义上是"一整包文件"，用户不会指望"搜规则名"能搜到它。

### 1.4 `openIds` 状态迁移表（表 C）

| 触发 | 动作 | 理由 |
|---|---|---|
| 点 L3 的 20px chevron | 翻转 `openIds[r.id]` | 现状行为 |
| 搜索把该行过滤掉 | **不动**（DOM 卸载、state 保留） | 清空搜索后用户展开过的详情还在，属于"用户意图"而非"当前视图" |
| 取消「显示已停用」导致该行卸载 | **不动** | 同上 |
| 全部展开 / 全部收起 | **不动** | 1.2 A5/A6 的硬约束 |
| `load()` 刷新 | **不动** | 刷新不该重置用户展开的详情 |
| 删除规则成功 | 建议 `delete openIds[r.id]`（可选清理） | id 已不存在，留着不影响渲染；清掉避免 `openIds` 无界增长 |

### 1.5 搜索交互

#### 1.5.1 不防抖（明确结论）

`q` 一输入即更新，`needle` 直接派生，不做 debounce。

理由：
1. 数据在客户端。规则总量 = 内置 **22 条**（实测 `BUILTIN_RULES`）+ 现场自建的自定义规则（个位数），过滤是 `O(n)` 的字符串 `includes`，单次 < 0.1ms。**防抖省不了一次网络请求，只让输入反馈变迟钝。**
2. `<Input>` 是受控组件。防抖意味着 value 与 state 不同步，会出现丢字符、光标跳位。
3. 防抖的收益场景（每次输入触发请求 / 上万行重排）在这里都不成立。

**未来降级方案（现在不做）**：若规则数超过 500（`O(n)` 单次 > 5ms 且重渲染可见卡顿），用 `React.useDeferredValue(q)` —— React 18 内置、零依赖，比手写 debounce 更贴合并发渲染。**不要**引入虚拟滚动库（违反"不新增依赖"，且 47 行不需要）。

#### 1.5.2 匹配字段与候选池（修 B1）

```ts
const needle = q.trim().toLowerCase();

const match = (r: RuleItem) =>
  !needle ||
  r.name.toLowerCase().includes(needle) ||
  (r.description || "").toLowerCase().includes(needle) ||
  r.id.toLowerCase().includes(needle);

// 搜索时停用规则也必须进候选池：搜不到 ≠ 不在库里
const pool = showDisabled || needle ? rules : rules.filter((r) => r.enabled);
const shown = needle ? pool.filter(match) : pool;

const builtin = shown.filter((r) => r.source === "builtin");
const custom = shown.filter((r) => r.source !== "builtin");
const hitCount = needle ? shown.length : 0;
const hitDisabled = needle ? shown.filter((r) => !r.enabled).length : 0;

// 这两个沿用现状（基于全量 rules，不受 needle 影响），只服务空态文案
const disabledRules = rules.filter((r) => !r.enabled);
const hiddenBuiltin = showDisabled ? 0 : disabledRules.filter((r) => r.source === "builtin").length;
const hiddenCustom = showDisabled ? 0 : disabledRules.filter((r) => r.source !== "builtin").length;
```

**为什么搜索必须包含停用规则**（这是本节最重要的一条）：规则页回答的是"现在在跑什么"，而停用规则**仍在库里**（后端刻意不删，见 `rules/page.tsx:125-134` 的注释）。运维的典型动作是"搜一条规则名，确认它还在、看它是开着还是关着"。如果搜索跳过停用规则，这个动作的结果就是"搜不到"—— 用户会读成"规则被删了"，可能重复新建，也可能误判"这个攻击手法现在没有检测覆盖"。**误判成本在检测口径上是最贵的一类**。

命中停用规则时，该行照常渲染，并带上 Phase 1 4.7 的三件套（`bg-surface-1` + 灰名 + `Badge variant="info"` 已停用），同时在计数条上用 `text-sev-medium-fg` 标出"含 N 条已停用"。

#### 1.5.3 祖先可见性与分组计数

```ts
const showRoot    = !needle || shown.length > 0;
const showBuiltin = !needle || builtin.length > 0;
const showCustom  = !needle || custom.length > 0;
// signature 恒可见（1.3）
```

`showRoot === false` → 整个 `<ul>` 不渲染，走 0 命中空态（1.5.6）。**不要渲染"网络 › 内置规则（0 条）› 空态"这种三层空壳** —— 用户要读三层才知道没有结果。

**分组计数在搜索时切换口径**（否则用户会以为"这一组只有 3 条"）：

| 状态 | L2 行右端文案 |
|---|---|
| 未搜索 | `{n} 条` + （`hidden > 0` 时）`停用 {hidden}` |
| 搜索中 | `命中 {n} / 共 {total} 条` + （命中里有停用时）`停用 {d}` |

`total` = 该组在未搜索口径下的条数（即 `(showDisabled ? rules : rules.filter(enabled)).filter(同组).length`）。

#### 1.5.4 命中片段高亮

新增纯函数文件 `ndr/frontend/lib/highlight.ts`（无依赖、可单测）：

```ts
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * 把 text 按 needle 切成片段数组；命中片段包一层 <mark>。
 * needle 为空时直接返回 [text]（不进正则，省一次编译）。
 */
export function highlightParts(text: string, needle: string): Array<{ s: string; hit: boolean }> {
  if (!needle || !text) return [{ s: text, hit: false }];
  const out: Array<{ s: string; hit: boolean }> = [];
  const re = new RegExp(escapeRegExp(needle), "gi");
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push({ s: text.slice(last, m.index), hit: false });
    out.push({ s: m[0], hit: true });
    last = m.index + m[0].length;
    if (m[0].length === 0) re.lastIndex++; // 兜底：避免空匹配死循环
  }
  if (last < text.length) out.push({ s: text.slice(last), hit: false });
  return out;
}
```

渲染：

```tsx
<span className="truncate text-13 font-medium">
  {highlightParts(r.name, needle).map((p, i) =>
    p.hit ? (
      <mark key={i} className="rounded-[2px] bg-brand-50 px-0.5 font-medium text-primary">{p.s}</mark>
    ) : (
      <React.Fragment key={i}>{p.s}</React.Fragment>
    ),
  )}
</span>
```

要点与理由：

- **必须 `escapeRegExp`**：运维会搜 `dns (txt)`、`10.0.0.*` 这类带正则元字符的串，不转义会抛 `SyntaxError` 让整页崩。
- **必须用 `split` 产出 ReactNode，不能 `dangerouslySetInnerHTML`**：规则名/描述来自后端，是外部数据。
- **`<mark>` 必须覆盖默认黄底**（Phase 1 4.8 已写）。本文补一条：**同时给 `font-medium text-primary`**。
  - 实测对比度：brand-50 `#ecf4fe` 对白卡 `#ffffff` 的亮度比约 **1.11:1**，对停用行的 `surface-1` `#f6f7f9` 约 **1.03:1** —— 后者作为背景差**肉眼几乎不可见**。
  - 主色字 `#144990` 在 brand-50 上的对比度约 **8.05:1**。所以真正让高亮"被看见"的是**字色**不是底色；底色只负责把命中片段的边界框出来。
- **ID 命中不在行内高亮**：叶子行没有 ID 列，行内无处高亮。ID 命中时这一行照样显示（它确实命中了），并在计数里计入；用户在展开的详情面板里能看到 `规则 ID` 那一行高亮。**不要**为了显示 ID 命中而在行内加一行 —— 那会让所有行高不齐。
- **描述行同样高亮**。描述在 1280 及以上都能一行放完（实测最长 54 字符）；1280 以下（③ 列 488px = 40 字符）超长的会被 `truncate` 收尾，命中片段若落在被截断的部分，用户展开详情面板能看到全文并看到高亮。
- **不做自动滚动到第一个命中**（没有 `scrollIntoView`）：滚动会抢走用户的视口控制权，且树里的命中是分布式的，不存在"第一个命中"这个明确目标。

#### 1.5.5 结果计数条

位置：`PanelToolbar` 之后、`<ul>` 之前（Card 内第二条）。

```tsx
{needle ? (
  <div
    id="rules-search-count"
    className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-muted-foreground"
  >
    <span>
      匹配 <span className="tabular-nums text-foreground">{hitCount}</span> 条规则（共{" "}
      <span className="tabular-nums">{rules.length}</span> 条）
    </span>
    {hitDisabled > 0 ? (
      <span className="text-sev-medium-fg">含 {hitDisabled} 条已停用</span>
    ) : null}
    <button
      type="button"
      onClick={() => setQ("")}
      className="ml-auto rounded-sm text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
    >
      清空搜索
    </button>
  </div>
) : null}
```

- **为什么紧贴树上方而不是塞进工具栏**：计数是被计数对象的属性，放在它描述的那堆内容正上方，扫视成本最低；工具栏里已经有 5 个按钮，再挤一条计数会让它换行。
- **分母用 `rules.length`（全量）不用 `shown.length`**：`shown` 受「显示已停用」影响，会随开关变化；分母必须稳定，否则"匹配 3 条（共 3 条）"这种算式会让用户以为库里只有 3 条。
- **不加 `aria-live`**。`role="status"` 隐含 `aria-live="polite"`，每次按键都播报会非常吵。改用搜索框上的 `aria-describedby="rules-search-count"`：只在用户聚焦搜索框时读一次，零噪音（见 1.7.4）。

#### 1.5.6 0 命中空态

位置：**树下方 / 代替整棵树**（Card 内容区），Phase 1 4.8 已定"不是每个分组下"，本文补一条：**连分组行也不渲染**（1.5.3）。

```tsx
{!showRoot ? (
  <div className="px-3 py-2">
    <EmptyState
      size="compact"
      tone="muted"
      title={`没有匹配「${q}」的规则`}
      hint="只匹配规则名称、描述与 ID；已停用的规则也会参与匹配。"
      action={
        <Button size="sm" variant="outline" onClick={() => setQ("")}>
          清空搜索
        </Button>
      }
    />
  </div>
) : (
  <ul className="p-2">…</ul>
)}
```

`hint` 里必须写"已停用的规则也会参与匹配" —— 它把这版的行为和用户的旧预期（搜不到 = 没有）区分开，也是 B1 修法对用户的交代。

#### 1.5.7 Esc 清空

```tsx
<Input
  onKeyDown={(e) => { if (e.key === "Escape" && q) { e.preventDefault(); setQ(""); } }}
  ...
/>
```

焦点保留在输入框（不移动、不关闭任何东西）。理由：输入框内按 Esc 清空是跨平台通用预期；本页 Esc 不与任何弹层冲突（Drawer / Dialog 关闭时搜索框不可达）。

#### 1.5.8 不做的事

- 不自动展开命中的第一条详情。
- 不在命中时自动切换「显示已停用」。
- 不记忆搜索词（不进 `localStorage`）—— 搜索是一次性动作，下次进来带着上次的过滤词会让人以为列表坏了。

### 1.6 启用开关（Switch）反馈时序

#### 1.6.1 结论：不做乐观更新，做"待定态"

现状 `toggle()` 是「先请求 → 再 `load()` 全量刷新」，点击后 0.3–1.5s 内 UI 完全不变（只有 checkbox 变 disabled）。这是"系统状态可见性"的真实缺失，但**不能用乐观更新补**。

**为什么不做乐观更新（四条理由）**：

1. **误判成本不对称，且方向相反**。UI 显示「已启用」而服务端实际未启用 = **漏检**（安全产品最贵的一类错，攻击发生了没人告警）；UI 显示「已停用」而服务端实际仍在检测 = 多告警（可容忍，最坏是噪音）。乐观更新把"显示"提前于"事实"，等于把最贵的那个错误从"不可能"变成"可能"。
2. **请求很短**。内网 `PUT /api/rules/{id}` P50 ≈ 120ms、`GET /api/rules`（22 条 + 自定义）P50 ≈ 150ms，合计 P50 ≈ 270ms、P95 ≈ 1.2s。这个量级下"待定态 + 结果提示"已经满足状态可见性，不需要赌。
3. **与全量刷新打架**。乐观更新需要持有"回滚快照"，但 `toggle()` 成功后立刻 `load()` 覆盖整个 `rules` 数组 —— 失败时该回滚到快照还是回滚到 `load()` 的结果？两条路径会让代码出现两套真相。
4. **可审计**。规则启停是检测口径变更，界面状态必须恒等于服务端状态。同一个原则也解释了为什么签名规则切版本要走 `Dialog` 二次确认（现状已如此，`suricata-rules-panel.tsx:267`）。

**被否决的方案（写出来供追溯）**：只在「停用」方向做乐观（低风险方向）、「启用」方向保持悲观。否决理由：同一控件在两个方向上的反馈不同，用户会学到"有时候立刻变、有时候要等"，然后开始怀疑"刚才那次到底生效了没"—— 引入的不确定性比 320ms 的等待更贵。

#### 1.6.2 时序表（表 D）

| 时刻 | `busy` | Switch | 整行 | 消息条 | 说明 |
|---|---|---|---|---|---|
| t0 点击 | `r.id` | `checked = 旧值` + `disabled` + `aria-busy` | `bg-brand-50` 常亮（不依赖 hover），名称后加 `切换中…`（`text-xs text-primary`）；`Pencil`/`Trash2` `disabled` | 清空 | 待定态 |
| t1 PUT 失败 | `""` | 旧值、可点 | 恢复 | `role="alert"` + 语义红：`更新失败：{errorText}` | 不自动重试 |
| t2 PUT 成功 → `load()` 成功 | `""` | **新值**、可点 | 恢复（新值对应的底色） | `role="status"` + 主色：`已{旧值 ? "禁用" : "启用"}「{name}」` | 现状文案保留（`r.enabled` 是旧值，"已禁用"是对的） |
| t3 PUT 成功 → `load()` 失败 | `""` | **旧值**、可点（`rules` 没更新） | 恢复 | `role="alert"` + 语义红：`已{…}「{name}」；但列表刷新失败，请点刷新确认` | **接口失败不能画成成功** |

t3 是现状的一个洞：现在 `setMsg("已禁用")` 在前、`await load()` 在后，`load()` 挂了消息条仍然是绿的"已禁用"。修法（`loadInto` 本来就返回 boolean）：

```ts
async function toggle(r: RuleItem) {
  setBusy(r.id);
  setMsg("");
  setMsgErr(false);
  const verb = r.enabled ? "禁用" : "启用";
  try {
    await apiFetch(`/api/rules/${r.id}`, {
      method: "PUT",
      body: JSON.stringify({
        name: r.name, description: r.description, conditions: r.conditions,
        severity: r.severity, enabled: !r.enabled, priority: r.priority,
      }),
    });
    const ok = await loadInto(errs, SRC.list, "/api/rules", (d: { items: RuleItem[] }) => setRules(d.items));
    if (ok) {
      setMsg(`已${verb}「${r.name}」`);
    } else {
      setMsgErr(true);
      setMsg(`已${verb}「${r.name}」；但列表刷新失败，请点刷新确认`);
    }
  } catch (e) {
    setMsgErr(true);
    setMsg(e instanceof ApiError ? errorText(e.body) : "更新失败");
  } finally {
    setBusy("");
  }
}
```

（请求体字段、接口路径、`SRC.list` 名称与现状完全一致。）

**待定态的行 class**：

```tsx
<div
  className={cn(
    LEAF_COLS,
    "grid items-center gap-x-3 rounded-sm px-2",
    busy === r.id
      ? "bg-brand-50"                                   // 待定：常亮，不用 hover
      : r.enabled
        ? "hover:bg-brand-50"
        : "bg-surface-1 hover:bg-brand-50",
  )}
>
```

**`busy` 期间必须禁止第二次点击**（`disabled={busy === r.id}`）。现状 checkbox 已有，换成 `Switch` 后要保留。理由：检测口径的开关连点两次会让最终状态不可预测（两次 PUT 的目标值都基于同一个旧值，服务端收到两次相同的翻转请求，最终状态取决于时序）。

**强化条件（现在不做）**：若 Phase 3 实测 P95 > 2s，在待定态上追加"已等待 N 秒"的计时文字。**不做 spinner**（无图标依赖、且与品牌蓝主题里的 `.st-pulse` 语义冲突 —— `.st-pulse` 是给"服务在线"用的）。

### 1.7 键盘与焦点

#### 1.7.1 Tab 顺序与停靠点

DOM 顺序 = 视觉顺序，树用嵌套 `<ul>/<li>` 天然满足。**不用 `tabIndex` 手工调整**（不引入 roving tabindex，理由同 Phase 1 4.10）。

停靠点清单（默认展开 `network` + `network:builtin`）：

| 区域 | 元素 | 数量 |
|---|---|---|
| 工具栏 | 搜索 Input | 1 |
| 工具栏 | 全部展开 / 全部收起 / 显示已停用 Switch / 刷新 / 新建规则 | 5 |
| L1 | 「网络（网络采集器）」整行 button | 1 |
| L2 | 「内置规则」/「自定义规则」/「签名规则」整行 button | 3 |
| L3 内置叶子 | chevron + Switch | 2 × n |
| L3 自定义叶子 | chevron + Switch + Pencil + Trash2 | 4 × m |
| 详情面板 | `<pre>`（`tabIndex={0}`） | 1 × 展开条数 |

估算（内置 22 + 自定义 5，全部展开）：`6 + 1 + 3 + 44 + 20 = 74`。默认展开（仅内置）：**54**。搜索命中 3 条时：**16**。

这个数量不小，但**不做 roving tabindex**（会与"不用 tree role"的决策冲突，且做一半比不做更糟）。减免措施有两条，都要落地：

1. **搜索框在 Tab 顺序第一位**（工具栏最左、DOM 最前）—— 键盘用户先把列表缩到 3 条，是唯一有效的缩减手段。这也是 1.5 必须存在的理由之一。
2. **详情面板的 `<pre>` 加 `tabIndex={0}`** —— 否则键盘用户无法滚动被 `max-h-56` 截断的条件 JSON。

#### 1.7.2 焦点可见

统一 `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40`（`Button` 基类自带；手写的 `<button>` / `<Link>` / `Switch` 必须补）。

树行内按钮要 `rounded-sm`：ring 画在圆角半径 0 的元素上会显得像一条断线。

行 hover 的 `bg-brand-50` 与 focus ring 可以共存（ring 画在按钮上，不是行上）—— 不冲突，因为 L3 行本身不是 button，L1/L2 的行 button 继承行底色。

#### 1.7.3 详情面板展开后：**不移动焦点**（结论）

三条理由：

1. `aria-expanded` + `aria-controls` 已经把关系交给读屏，读屏用户可以主动跳到那个 region；移焦不是必需的。
2. **"连续展开 3–4 条对比条件"是真实场景**。每次展开都把焦点吸进面板，用户要先 Tab 出来才能点下一条，重复 4 次 = 8 次多余按键。
3. 面板里第一个可聚焦元素只能是没有语义的容器本身（`tabIndex={-1}`），移进去后读屏会把整块 JSON 一次性读完 —— 噪音远大于信息。

**例外**：`Drawer`（新建 / 编辑规则）打开时焦点必须移入第一个输入框 —— 那是模态，不是展开。

#### 1.7.4 ARIA 落点表

| 元素 | 属性 |
|---|---|
| 搜索 `<Input>` | `aria-label="搜索规则"` `aria-describedby="rules-search-count"` `type="text"` `autoComplete="off"` `spellCheck={false}` |
| 结果计数条 | `id="rules-search-count"`；**无 `role`**（避免 live 播报） |
| `PanelToolbar` | **不加 `role="toolbar"`**（`toolbar` role 隐含方向键导航义务，做了 tree 的教训不再重演） |
| L1 行 button | `id="tree-network"` `aria-expanded={isOpen("network")}` `aria-controls="tree-network-children"` |
| L1 子列表 `<ul>` | `id="tree-network-children"` |
| L2 行 button | `id="tree-{id}"`（如 `tree-network-builtin`）`aria-expanded={isOpen(id)}` `aria-controls="tree-{id}-children"` |
| L2 子列表 `<ul>` | `id="tree-{id}-children"` |
| 列头行 | **保留可读**（不 `aria-hidden`）：读屏读一次"规则 / 类型 / 级别 / 优先级 / 操作"后逐行读值，比隐藏后读到一串裸数字好 |
| L3 chevron button | `aria-expanded={!!openIds[r.id]}` `aria-controls={panelId}` `aria-label={`${openIds[r.id] ? "收起" : "展开"}规则「${r.name}」的条件详情`}` |
| L3 Switch | 组件内 `role="switch"` `aria-checked`；调用侧 `aria-label={`${r.enabled ? "停用" : "启用"}规则「${r.name}」`}` `title` 同 `disabled={busy === r.id}` `aria-busy={busy === r.id}` |
| L3 名称 `<span>` | `id={`${panelId}-label`}` |
| 详情面板 `<div>` | `id={panelId}` `role="region"` `aria-labelledby={`${panelId}-label`}` |
| 详情 `<pre>` | `tabIndex={0}` `role="group"` `aria-label={`规则「${r.name}」的条件 JSON`}` |
| `Pencil` / `Trash2` | `aria-label={`编辑规则 ${r.name}`}` / `aria-label={`删除规则 ${r.name}`}` + `title` + `disabled={busy === r.id}` |
| 树的 loading 容器 | `aria-busy="true"` |

`panelId` = `rule-panel-${r.id}`。

**对 Phase 1 4.6 的一处落点细化**：Phase 1 写 `aria-labelledby={rowId}`。但 L3 行是一个 7 列 grid `<div>`，它的可访问名计算会把**所有列的文本拼起来**（"规则名 描述 逐条 高危 100"）。改为 `aria-labelledby` 指向行内**名称 `<span>` 的 id**，读屏宣读"规则名 区域"，准确且短。见 Q4。

#### 1.7.5 交互元素嵌套约束

L1 / L2 用整行 `<button>`。HTML 禁止交互元素嵌套，所以：

- L1 / L2 行内的**文本**（计数、"停用 N"）可以放在 button 内（非交互）。
- L2 行若将来要放按钮型 `action`（例如"新建"），**必须是 `<button>` 的兄弟节点**，用外层 `flex` 包住（现状 `TreeNode` 的结构就是这样，保持）。当前规则页不需要（"新建规则"在工具栏）。
- L3 行本身**不是** button，只有 chevron / Switch / 图标按钮可聚焦 → 无嵌套问题。

### 1.8 工具栏按钮行为表

| 控件 | 点击后 | 焦点 | disabled 条件 | 二次确认 |
|---|---|---|---|---|
| 搜索 Input | 立即过滤（不防抖） | 保留 | — | — |
| 全部展开 | A5：4 key = true | **保留在按钮** | **永不** | 否 |
| 全部收起 | A6：4 key = false | **保留在按钮** | **永不** | 否 |
| 显示已停用 Switch | 翻转 `showDisabled` | 保留 | `disabledRules.length === 0` 时整组不渲染（现状） | 否 |
| 刷新 | `load()` | 保留 | `loading` 期间 | 否 |
| 新建规则 | 打开 Drawer | **移入 Drawer 首个输入框** | 否 | 否 |

- **全部展开 / 收起永不 disabled**：两个按钮都是幂等的，重复点击零副作用；做成 disabled 需要在每次渲染里比较 4 个 key，且会在两次点击之间闪变，反而让人不确定"现在是不是全展开了"。
- **刷新不能清空 `rules`**：现状 `loadInto` 只在成功时 `setRules`，失败保留旧数据 —— 保持。**刷新按钮不加 spinner**（无图标依赖），用 `disabled` 表达"正在读"。
- **全部展开会顺带展开签名分组**（`"network:signature"` 也在 4 key 里）—— 用户点"全部展开"就是要看全部，不要自作聪明地排除。它会在展开时才 mount `SuricataRulesPanel` 并首次请求 `/api/suricata/rules`，这是可接受且正确的（按需加载）。

---

## 2. 响应式矩阵

### 2.1 计算口径

| 量 | 公式 |
|---|---|
| 侧栏宽 | 视口 ≥ 1024 → `15rem`(240px)；< 1024 → `3.5rem`(56px)（Phase 1 1.4） |
| 可用宽 `W` | 视口 − 侧栏 − 48（`px-4 md:px-6`，≥768 时两侧各 24） |
| 内容宽 `C` | `min(W, max-w)`，三档见 Phase 1 1.1 |
| 主列宽 `M` | ≥1280（`xl` 视口断点，拆两列）：`C − 304(rail 19rem) − 16(gap)`；< 1280（堆叠）：`M = C`，rail 另受 `max-w-[34rem]`(544px) 约束 |
| 字段列数 | `md:grid-cols-2`(≥768) → `min-[1600px]:grid-cols-3` → `min-[1920px]:grid-cols-4` |
| 单字段净宽 | `(M − 16 × (n−1)) / n` |
| 树可用宽 `T` | `C − 32`（Card `p-2` 16 + 叶子行 `px-2` 16） |
| L3 缩进 | `20(L2 pl-5) + 20(L3 pl-5) = 40` |
| 叶子 7 列固定宽 | `20+28+112+88+56+72 = 376` + `6 × 12(gap-x-3) = 72` → **448** |
| ③ 列（名称+描述） | 7 列模板：`T − 40 − 448`；3 列模板（<1280）：`T − 40 − 20 − 28 − 24 = T − 112` |
| 名称/描述排版 | **恒定两行**（名称行 + 描述行），与断点无关。断点只决定 ④⑤⑥⑦ 留在列上还是下移到第三行 |

注意：Tailwind 的断点是**视口**断点。`xl`(1280) 在带侧栏时意味着正文只有 992px —— 这是 Phase 1 0.3 已经讲清楚的平移效应。

**③ 列宽度与描述容量的实测对照**（决定 2.4 的 clamp 结论）：内置规则描述**最长 90 字符**（`内网漏洞利用探测`）、中位 37、**2 条超过 60**（90 / 74）。12px 中文字宽 12px，两行容量 = `2 × ③ / 12` 字：

| 视口 | ③ 列 | 两行可放字数 | 最长那条（90 字） |
|---|---|---|---|
| 768（3 列模板） | 520 | 86 | ❌ 差 4 字 |
| 1024（3 列模板） | 592 | 98 | ✅ |
| 1280（7 列） | 472 | 78 | ❌ 差 12 字 |
| 1600（7 列） | 792 | 132 | ✅ |
| 1920（7 列） | 1112 | 185 | ✅ |
| 2560（7 列） | 1752 | 292 | ✅ |

> 上表的字数来自 `BUILTIN_RULES`（`ndr/backend/app/rules/builtin.py:167`）逐条解析：**22 条**，全部带 `description`，最长 90、中位 37。**注意**：正则粗数会漏掉跨行隐式拼接的字符串字面量，得 19 条 / 最长 54 —— 这个错值会让 `slice(0, 60)` 看起来"从不截断"，实际它确实截断（90 与 74 两条）。跨端核对请按上面的口径取值。

### 2.2 主矩阵

| 屏宽 | 侧栏 | `W` | `C` standard | `C` wide/full | `M`（主列） | rail | 字段列数 | 单字段宽 | ③ 列（7 列） | ③ 列（3 列模板） | 叶子行结构 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **768** | 图标轨 56 | 664 | 664 | 664 | 664（堆叠） | 544（堆叠在下） | 2 | 324 | 144 | **520** | 3 列 + ④⑤⑥⑦ 下移第三行 |
| **1024** | 完整 240 | 736 | 736 | 736 | 736（堆叠） | 544 | 2 | 360 | 216 | **592** | 3 列 + ④⑤⑥⑦ 下移第三行 |
| **1280** | 完整 240 | 992 | 992 | 992 | 672 | 304 | 2 | 328 | **472** | 848 | 7 列（两行） |
| **1600** | 完整 240 | 1312 | 1312 | 1312 | 992 | 304 | 3 | 320 | **792** | — | 7 列（两行） |
| **1920** | 完整 240 | 1632 | 1632 | 1632 | 1312 | 304 | 4 | 316 | **1112** | — | 7 列（两行） |
| **2560** | 完整 240 | 2272 | 2080 | 2272 | 1760 / 1952 | 304 | 4 | 428 / 476 | **1752** | — | 7 列（两行，富余不动） |

（2560 行的 `M / 字段宽` 两个数依次是 standard 与 wide；rules 页是 `full` 档、无 rail，树宽 = `C` = 2272。）

**「两行」是恒定的，不是断点行为**（design-architect 复核后定稿，见 Q1）：名称行 + 描述行在任何宽度下都堆叠；`xl:`(1280) 只决定 ④⑤⑥⑦（类型 / 级别 / 优先级 / 操作）是留在 grid 列上，还是下移到第三行。768 / 1024 那两行的 ③ 列取 **3 列模板**的值（520 / 592），**不取**"7 列"列的 144 / 216 —— 后者是假设断点没生效时的反事实值，写出来是为了说明为什么 3 列模板必须存在。

### 2.3 每个断点上"用户看到什么"

**768（平板 / 分屏）**
侧栏收成 56px 图标轨（8 个图标 + 4 条分隔线 ≈ 380px，一次看全）。正文 664px。所有配置页的 `SettingsGrid` 塌成一列：主列表单在上（全宽 664），rail 卡在下（收到 544px）。字段 2 列各 324px。规则页走 **3 列模板**（`[chevron, Switch, minmax(0,1fr)]`）：③ 列 **520px**、两行可放 86 字；④⑤⑥⑦ 下移到第三行（`flex flex-wrap`，操作 `ml-auto` 右对齐）。最长的那条描述（90 字）差 4 字被 clamp，`title` + 详情面板兜底。

**1024（小笔记本）**
侧栏**展开** 240px（1024 > 1023.98）。正文 736。仍是一列堆叠，rail 544。字段 2 列各 360。规则页仍走 **3 列模板**：③ 列 **592px**、两行 98 字 —— 比 7 列模板下的 216px（18 字）宽 2.7 倍，最长描述完整可见。这是 3 列模板必须存在的直接理由。

**1280（主流办公屏，也是 `xl` 的起点）**
第一次出现左右分栏：主列 672、rail 304 且 sticky。字段 2 列各 328（尚未到 `min-[1600px]`）。规则页切到 **7 列模板**，③ 列 **472px**、两行 78 字 —— 这是全区间里 ③ 列最窄的一档（固定列吃掉 448px 后剩余最少），22 条里最长的那条（90 字）差 12 字，靠 `line-clamp-2` 收口（见 2.4a）。

**1600**
主列 992，字段 3 列各 320（Phase 1 2.3 的舒适区下限）。规则页 ③ 列 792px、两行 132 字 —— 全部描述完整可见。

**1920（本产品主力屏）**
外槽 = 0（Phase 1 1.2）。主列 1312，字段 4 列各 316。规则页 ③ 列 1112px、两行 185 字。这是设计的目标态。

**2560**
standard 档仍有 96px 外槽（Phase 1 的设计意图，不质疑）。主列 1760（wide 1952），字段 4 列各 428/476。规则页 ③ 列 1752px、两行 292 字，而实测最长描述 90 字只占 1080px —— 列内富余约 670px。这段富余怎么处理见 2.4。

### 2.4 描述行的 clamp：保留；③ 列的富余：不动（两个结论）

**（a）描述行保留 `line-clamp-2`（Tailwind 3.4.13 内置）** —— 我最初因为读数错了（以最长 54 字）撤回了它，实测最长 **90 字**之后撤回撤回：

```
2 行容量 ≥ 90 字  ⇔  ③ 列 ≥ 540px
```

1280 的 ③ 列 472px（78 字）与 768 的 520px（86 字）都不够，最长的 1–2 条会被截断。不 clamp 的话描述会自然折到第三行，而"恒定两行 + 行高 44px"的契约靠的就是 clamp —— 一旦某一行涨到 60px，整列的行高基准就散了。所以：

```tsx
<p className="line-clamp-2 text-xs text-muted-foreground" title={r.description}>
  {r.description || "（无描述）"}
</p>
```

`title` 兜底鼠标悬停；**详情面板里的描述不加 clamp**（那里要读全文）。

**（b）③ 列富余不动：不设 `max-w`、不加列。** 理由（这条要写清楚，因为它是"用户抱怨的空白"最容易误伤的地方）：

- 用户抱怨的空白是**被拉长的控件**——一个 566px 的下拉框里躺着 4 个字（Phase 1 0.2）。那类空白是控件宽度与内容量的错配。
- ③ 列的富余是**文本自然结束后的空白**，是所有表格单元格的常态（Excel、Grafana 的表格都一样）。读者不会去那里找东西，也不会觉得"这里本该有什么"。
- 给 ③ 列设 `max-w` 会把这段空白从"单元格内的余量"变成"列与列之间的断口"，反而更显眼。
- **加第 8 列（规则 ID）已被 design-architect 否决**（Q6 三条理由）：ID 是"排查 / 对工单时才用"的字段，做成常驻列等于给每一行都加一段 UUID 前缀噪音；`min-[2200px]` 加列会让 `LEAF_COLS` 变成三套模板，而它被列头行 / 数据行 / 窄屏行三处引用，多一套就多三个失配点。

**（c）零成本替代（采纳 design-architect 的方案）**：③ 列第二行用 `flex` 排「描述 `min-w-0 flex-1`」+「ID `shrink-0`」。窄屏描述把 ID 挤掉、宽屏自然出现，**不需要任何断点**，也不动 `LEAF_COLS`：

```tsx
<div className="flex min-w-0 items-baseline gap-2">
  <p className="line-clamp-2 min-w-0 flex-1 text-xs text-muted-foreground" title={r.description}>
    {r.description || "（无描述）"}
  </p>
  <span className="shrink-0 font-mono text-xs text-muted-foreground/60">{r.id.slice(0, 8)}</span>
</div>
```

### 2.5 rail 高度预算与 sticky 安全

Phase 1 2.4 给 rail 加了 `xl:sticky xl:top-[4.25rem]`。`position: sticky` 的元素若**高于视口**，底部永远滚不到 —— 这是个静默失效，用户不会报错，只会发现"右下角那块内容我看不到"。

预算（1080p，页头 3.5rem = 56px）：

```
可用高 = 1080 − 56(页头) − 68(top 4.25rem) − 24(底部呼吸) = 932px
```

约束（写进 rail 的验收）：

- **最多 3 张卡**（Phase 1 2.2 已定）。
- **单张 rail 卡最多 6 行 key/value + 4 个 Badge**。一行 key/value ≈ 20px（12px 文字 + `divide-y` 分隔），6 行 ≈ 136px + 卡头 40 + padding 32 ≈ 208px。3 张 = 624px < 932 ✓。
- **不加 `overflow-auto`**：rail 内部滚动条 + 页面滚动条 = 双重滚动，且在 304px 宽里拖不动（Phase 1 2.2 黑名单的同源理由）。超预算就合并卡片或删行，不靠滚动解决。
- 前置条件（Phase 1 已写）：`SettingsGrid` 必须保持 `items-start`，否则 sticky 失效。

---

## 3. 三态规范（空 / 加载 / 错误）

### 3.1 唯一判定顺序

所有面板的所有区块，判定顺序固定为：

```
1. loading && !errs.has  → 骨架
2. errs.isFailed(SRC.x)  → danger 空态 / 错误条（见 3.4）
3. 有数据                → 内容
4. 无数据（且是"被收起"） → muted 空态 + 「显示已停用」提示
5. 无数据（真的没有）     → muted 空态 + 创建入口
```

**顺序 1 里 `&& !errs.has` 是关键**：MCP 面板已经是这个写法（`!ready && !errs.has`，`mcp-panel.tsx:273`）；`zeek` / `es` / `logstash` / `account` 现状是 `loading ? 骨架 : …`，失败时要等 Promise 结束才跳出骨架。差别只有几百毫秒，但统一成 MCP 的写法能让错误条更早可见。**不改任何接口逻辑**，只调整判定的与条件。

### 3.2 加载：骨架形状表

原则：**骨架形状 = 加载完的形状**（行数、块高、底色块都要对上）。下面逐个面板给高度与理由；`Skeleton` 已自带 `motion-reduce:animate-none` 与 `aria-hidden`。

| 面板 / 区块 | 加载完的形状 | 骨架（本文给定） | 现状 | 差异 |
|---|---|---|---|---|
| **rules** 树 | L1(44) + 3×L2(40) + 每 L2 下 5×L3(48) | `<TreeSkeleton rootRows={1} groupRows={3} leafRows={5} />`，签名分组的子级给 `h-40` | Phase 1 写 `groupRows={2}`、签名子级 `h-10` | 见 Q5 |
| **zeek** · iface 主列 | 1 个 Field（label 16 + 控件 36 = 52） | `<div className="grid gap-3 sm:grid-cols-2"><Skeleton className="h-14"/></div>` | `h-14` ✓ | — |
| **zeek** · networks 主列 | textarea(min-h-28=112 + label 16) + 2 短字段 + TLS 字段 + 说明 | `h-32` + `grid gap-3 sm:grid-cols-2` 内 3×`h-14` + `h-8` | 只有 textarea 有骨架，短字段用 `disabled` 渲染空 Input | **统一为骨架** |
| **zeek** · rail「当前生效」 | 卡头(40) + Badge 组(20) + 3 行 key/value(3×20) + 路径行 | `h-4 w-20` + `h-5 w-4/5` + `space-y-1` 内 3×`h-3` | `h-16` 一块 | 改成分行骨架 |
| **es** · 主列「索引与保留」 | 2 个 Field + 3 个按钮 | `grid gap-3 sm:grid-cols-2` 内 2×`h-14` + `h-8 w-40` | **无骨架**（空白） | **补齐** |
| **es** · rail「连接」 | 3 行（地址/用户名/密码），行高 36，`gap-2` | `space-y-2` 内 3×`h-9` | 3×`h-10` 无 gap | 微调 |
| **es** · 「集群状态」 | 3 个 `Stat` 底色块(h-14/56) + 索引表 5 行 | `<StatSkeleton count={3} className="sm:grid-cols-3" />` + `<TableSkeleton rows={5} cols={4} />` | 3×`h-14` + `h-32` | **用 `StatSkeleton`**（骨架要连 `bg-surface-1` 底色块一起画，才是"同形"） |
| **logstash** · 主列 | 3 项（说明块 / ES 地址 / 索引名） | `grid gap-3 sm:grid-cols-2` 内 3×`h-14` + `h-8 w-32` | `h-24` 一块 | 改成分格骨架 |
| **logstash** · rail | 4 个 `Stat` | `<StatSkeleton count={4} className="grid-cols-2" />` | 4×`h-14` | 同上 |
| **logstash** · 运行明细 | `bg-surface-1` 块内 4–6 行文本 ≈ 130px | `Skeleton className="h-32 w-full"` | `h-16`(64) | **差 66px，会跳版** |
| **logstash** · 管道全文 | `rows={14}` 的 textarea：`text-xs leading-relaxed` → 行高 19.5px × 14 + `p-2`(16) + border(2) ≈ **291px** | `Skeleton className="h-72 w-full"`（288） | `h-56`(224) | **差 67px** |
| **mcp** | 主列 + rail + 4 张整幅卡 | 现有骨架 + 补第 3 张（`rows={3} cols={5}`，结论表 5 列）+ 第 4 张（`h-3 w-40` + `h-8 w-16`） | 只画了 2 张表 | 补齐避免跳版 |
| **relay** | 10 列表格 | `<TableSkeleton rows={5} cols={6} />` | 同 ✓ | 保留 6 列：骨架按 flex 比例分宽，10 列会全挤成细条反而失真；行数对就行 |
| **ingest-filters** · 主列 | 4 字段 + ConditionEditor + 按钮行 | `grid gap-3 sm:grid-cols-2` 内 3×`h-14` + `h-24` + `h-8 w-24` | **无骨架** | **补齐** |
| **exclusions** · 主列 | 同 | 同上 | **无骨架** | **补齐** |
| **filters** · rail 样例卡 | M 条 `SampleLine`（12px 单行 ≈ 16px）×3 + 时间行 | `space-y-1` 内 3×`h-3` + `h-3 w-32` | `h-12`(48) | 基本对（3×12+2×4=44） |
| **suricata**(inline) · 生效规则 | 2 个 `Stat` + 一行文本 | `<StatSkeleton count={2} className="grid-cols-2" />` + `h-8` | 2×`h-14` + `h-8` | 用 `StatSkeleton` |
| **suricata** · rail 历史 | 5 行 `font-mono text-xs` ≈ 76px | `Skeleton className="h-20 w-full"`(80) | `h-16`(64) | 微调 |
| **health** | 3 个 `Stat`(md) + 5 列表 + rail | `<StatSkeleton count={3} className="md:grid-cols-3" />` + `<TableSkeleton rows={8} cols={5} />` + rail `h-3.5 w-20` + 3×`h-3` | 现状 ✓ | 合规，保持 |
| **account** · 主列 | 3 个密码框（2 列 → 2 行）+ 提交按钮 | `grid gap-3 sm:grid-cols-2` 内 3×`h-14` + `h-8 w-28` | `h-3 w-24` + `h-9` + `h-9 w-2/3` + `h-8 w-28` | 骨架只画了 2 个框，实际 3 个 |
| **account** · rail | 卡头 + Badge + username/role 行 ≈ 88px | `h-4 w-16` + `h-9 w-full` | `h-3 w-16` + `h-7 w-40` | 微调 |

通用规则：

- 骨架**外层容器**加 `aria-busy="true"`，**不加 `role="status"`**（避免读屏为骨架播报一次、为内容再播报一次）。`role="status"` 只留给 `EmptyState` 的 `tone="loading"`。
- 骨架块之间用与真实内容相同的容器（`grid` / `space-y`）与 gap，不要一块到底。

### 3.3 空：三态判定矩阵与文案表

**规则页树（5 分支，按 3.1 顺序）**

| 顺序 | 条件 | tone | title | hint | action |
|---|---|---|---|---|---|
| 1 | `loading && !errs.has` | — | （骨架） | — | — |
| 2 | `errs.isFailed(SRC.list) && !rules.length` | `danger` | `检测规则读取失败（见上方错误条）` | `后端异常或网络不通，不是「没有规则」` | 重新读取 |
| 3 | `needle && hitCount === 0` | `muted` | `没有匹配「{q}」的规则` | `只匹配规则名称、描述与 ID；已停用的规则也会参与匹配。` | 清空搜索 |
| 4 | `!needle && !items.length && hidden > 0` | `muted` | `{hidden} 条{内置\|自定义}规则已停用，当前已收起` | `勾选上方「显示已停用」可查看停用原因并重新启用` | — |
| 5 | `!needle && !items.length && hidden === 0` | `muted` | `这一组还没有规则` / `这一组还没有自定义规则` | 自定义组：`内置规则不满足现场口径时，新建一条自己的检测条件` | 自定义组：新建规则 |

分支 3 与分支 4 的顺序不能颠倒：**有搜索词时不显示"被收起"空态** —— 搜索时的候选池已含停用规则（1.5.2），再提示"被收起"会自相矛盾。

分支 4 / 5 的空态**缩进到叶子位置**（`pl-5`，Phase 1 4.9 已定）；分支 3 的 0 命中空态**不缩进**（它代替整棵树，不是某一组的子节点）。

**其余面板（沿用现状文案，补齐判定）**

| 位置 | 条件 | 文案 | 现状 |
|---|---|---|---|
| zeek rail | `!status` + 失败 | `读取失败（见上方错误条）` ✓ | 有 |
| zeek 网卡下拉 | `detected.length === 0` | 退化成手填 Input 时，字段下方补 `hint`：`没探测到网卡清单（采集器未运行或权限不足），可手填` | **缺** —— 现状静默退化，用户不知道为什么没有下拉 |
| es 连接卡 | `!cfg` | `还没有读到接入配置` / 失败 → `读取失败（见上方错误条）` ✓ | 有 |
| es 索引表 | `indices.length === 0` | `暂无匹配索引（检查索引模式或数据是否已入 ES）` ✓ | 有 |
| logstash 参数卡 | `!params` | `还没有读到参数` / 失败 → `读取失败（见上方错误条）` ✓ | 有 |
| mcp 令牌表 | `tokens.length === 0` | `还没有令牌 —— 智能体现在连不上（先在上面生成一个）` ✓ | 有 |
| mcp 调用表 | `calls.length === 0` | `最近没有调用（智能体还没查过数据，或刚重启过）` ✓ | 有 |
| mcp 结论表 | `conclusions.length === 0` | `还没有结论写回` ✓ | 有 |
| mcp 工具表 | `tools.length === 0` | `工具清单为空` ✓ | 有 |
| agent-push 配置卡 | `!cfg` | `还没有读到推送配置` ✓ | 有 |
| agent-push 积压卡 | `!st` | `还没有读到送达状态` + `计数来自 /api/agent-push；读不到时这里不做任何推断。` ✓ | 有 |
| relay 表 | `!nodes.length` | 三分支（失败 / `configured` 但无流量 / 未配置）✓ | 有 |
| ingest 表 | `!items.length` | `暂无降噪过滤（检测器会看到全部事件）` ✓ | 有 |
| exclusions 表 | `!items.length` | `暂无排除过滤` ✓ | 有 |
| exclusions「已排除」列 | `stats === null` | `—`（**不要用 0 冒充"一条没命中"**）✓ | 有，保持 |
| health 表 | `!items.length` | `配置项读取失败` / `没有配置项数据` ✓ | 有 |
| health rail | `warnings.length === 0 && !errs.has && !data.error` | 「正常」卡（`border-sev-ok-bd bg-sev-ok-bg`）✓ | 有 |
| account rail | `!me` | `还没有读到账号信息` + `左边照样可以改密（改密本身会校验原口令）。` ✓ | 有 |
| suricata rail | `history.length === 0` | `还没有更新记录` + `点「立即检查更新」会留下一条记录。` ✓ | 有 |

### 3.4 错误：三条硬规则

**规则 1：接口失败不能被画成"没有数据"。**
所有 `items.length === 0` 的空态必须走 `emptyOrFailed(errs, SRC.x, "…")`，`tone` 必须是 `danger`，`action` 必须是"重新读取"。3.3 表里已逐处核对，唯一新增的是 zeek 网卡下拉的 `hint`。

**规则 2：读取失败与操作失败走不同通道。**

| 类型 | 通道 | 位置 | 语义 |
|---|---|---|---|
| 读取失败（`loadInto`） | `PanelError`（`role="alert"`，列出失败接口） | `Section` **之前**、面板最顶端 | 顶部条 |
| 操作失败（保存/切换/删除） | 卡片内提示条 `role="alert"` + `border-sev-critical-bd bg-sev-critical-bg` | 产生它的那张卡片内（`msgScope` 机制，logstash 已有） | 就近 |

两者不得混用：`PanelError` 不说"保存失败"，卡片内提示条不说"接口读取失败"。

**`PanelError` 的位置必须是最顶端。** 现状 `suricata-rules-panel.tsx:170-173` 把它放在说明段落**之后** —— 统一提到最前（它现在是 `<div className="space-y-4">` 的第一个子节点之前）。

**规则 3：数据没读到 → 禁用保存，并给一行红字说明。**

| 面板 | 现状 | 结论 |
|---|---|---|
| zeek | `disabled={busy \|\| !status}` + 红字 ✓ | 保持 |
| es | `disabled={busy \|\| !cfg}` + 红字 ✓ | 保持 |
| agent-push | `disabled={busy \|\| !data}` + 红字 ✓ | 保持 |
| logstash | `params === null` 时不渲染表单（等价） ✓ | 保持 |
| suricata | `busy !== ""` 控制，无 `!status` 判断 | `status === null` 时 disable「保存配置」（避免空 url 覆盖现有来源） |
| mcp | 「生成令牌」无 disable | **不禁用**：生成令牌不依赖已读数据（不需要回显），禁用反而阻塞恢复 |
| relay | `dirty` 在 `data === null` 时为 false → 自动禁用 ✓ | 保持 |

理由统一：空表单点保存会把现有配置覆盖成空值 —— 这是配置页最贵的一类误操作，且不可逆（zeek 会立刻下发重载、logstash 会覆盖管道全文）。

**规则 4：错误条出现时不得同时出现骨架。** 见 3.1 的顺序 1。

---

## 4. 八个配置页的 rail 内容映射表

### 4.0 通用规则

沿用 Phase 1 2.2 的白名单（key/value 行、≤4 个 Badge、≤4 个 `Stat size="sm"`、`sev-*` 提示条、至多一个"作用于整页"的按钮）与黑名单（>3 列的表、textarea / 代码编辑器、长样本列表、横向滚动、任何表单控件）。本文补两条：

1. **每张 rail 卡最多 6 行 key/value + 4 个 Badge**（2.5 的高度预算）。
2. **空值一律有文案**，不允许出现空白行或裸 `-`。下表"空值"列即为该字段为 `null` / `""` / `undefined` 时显示什么；数字字段缺值显示 `—`（**不要用 0 冒充**，与 `exclusions-panel.tsx:370` 的现有做法一致）。

字段全部取自 `ndr/frontend/lib/api.ts` 的真实类型，无编造。

### 4.1 `/config/collect`（`ZeekPanel section="iface"`，`/api/zeek/status`）

**rail 卡 1「当前生效」**（现状已有，补 2 行）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 监听网卡 | `status.interface` | `—` |
| BPF 过滤器 | `status.bpf_filter` | `无 BPF 过滤（抓全部）` |
| 本地网段 | `status.local_nets` | `（空，用采集器默认判定）` |
| 配置路径 | `status.config_path` | `—` |
| 最近重载 | `status.last_reload` → `formatDateTime` | `从未重载` |
| 探测网卡 | `status.detected.length` → `探测到 {n} 张` | `未探测到网卡（可手填）` |

Badge 组（现状 3 个，保持）：`轮转 {status.rotation_hours}h` · `本地保留 {status.retention_days_local} 天` · `正文上限 {body_max_bytes/1024} / {resp_body_max_bytes/1024} KB`。

> Phase 1 2.2 写 collect 的 rail 含"PID"—— `ZeekStatus` **没有 pid 字段**（见 Q2）。用上表的「最近重载 + 探测网卡数 + `suricata.alive`」替代。

**rail 卡 2「签名引擎」**（可选，`status.suricata` 为 null 时整卡不渲染）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 状态 | `status.suricata.alive` → Badge `运行中` / `未运行` | 整卡不渲染（未部署） |
| 网卡 | `status.suricata.iface` | `—` |
| 生效签名 | `status.suricata.rule_count` | `0` |
| 引擎版本 | `status.suricata.suricata` | `—` |

### 4.2 `/config/networks`（`ZeekPanel section="networks"` + `RelayNodesPanel`）

**rail 卡 1「抓包范围预览」**（`ZeekPanel`，新增）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 已识别网段 | `nets.length`（前端 `parseNets(netsText)` 的结果，非接口字段） | `未填（无法保存）` |
| BPF 过滤器 | `status.bpf_filter` | `（保存后由网段清单生成）` |
| Site::local_nets | `status.local_nets` | `（空，用采集器默认判定）` |
| 附加 BPF 条件 | `status.bpf_extra` | `无附加条件` |
| 正文上限 | `status.body_max_bytes` / `resp_body_max_bytes` → KB | `—` |
| 签名引擎 | `status.suricata.alive` + `rule_count` | `未部署（没有收到状态上报）` |

**rail 卡 2「链路概览」**（`RelayNodesPanel`，新增；该面板目前没有 rail）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 中继条目 | `data.nodes.length` | `未配置` |
| 推算时间 | `data.detected_at` → `formatDateTime` | `—` |
| 链路层级 | `Object.keys(data.topology.levels \|\| {}).length` → `{n} 级` | `—` |
| 检出链路 | `data.topology.chains?.length` → `{n} 条` | `0` 时显示 `—` |
| 打断的环 | `data.topology.cycle_broken?.length` → `text-sev-medium-fg` | `0` 时**整行不渲染** |
| 剔除的边 | `data.topology.pruned` → `已剔除 {n} 条不在清单内的边` | `0` 时整行不渲染 |

`RelayNodesPanel` 的 10 列宽表按 Phase 1 2.1 的 M5 **保持整幅**，不放进 rail。

### 4.3 `/config/rules`

**无 rail**（整幅树，Phase 1 1.3 / 2.2 已定）。

数值理由：1920 上主列 1312，若叠 rail（304 + 16）则树宽降到 992，③ 列从 1128 → 808（−28%）；2560 上从 1768 → 1448。规则页是这一组里唯一"越宽越好"的页面。

### 4.4 `/config/filters`

**`IngestFiltersPanel` rail 卡「最近被挡下的事件」**（现状已有，补 2 行）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 生效过滤器 | `items.filter(f => f.enabled).length` / `items.length` → `生效 {a} / 共 {b} 条` | `还没有过滤器` |
| 累计挡下 | `items.reduce((s, f) => s + (f.hit_count ?? 0), 0)` | `0` |
| 最近命中 | `lastHitAt`（接口 `last_hit_at`）→ `formatDateTime` | `—` |
| 样例行 ×N | `f.samples[]`（`IngestFilterSample`）：`[{ts}] {source_system} · {event_type} · {src_ip}[:{src_port}] → {dst_ip}[:{dst_port}] · {summary.slice(0,120)}` | 全部为空 → 空态 |

**`ExclusionsPanel` rail 卡「最近被排除的样例」**（现状已有，补 2 行）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 生效规则 | `items.filter(f => f.enabled).length` / `items.length` | `还没有排除规则` |
| 累计排除 | `Object.values(stats.counts \|\| {}).reduce((a, b) => a + b, 0)` | `stats === null` → `—`（**不用 0**） |
| 最近命中 | `stats.last_hit_at` → `formatDateTime` | `—` |
| 样例行 ×N | `stats.samples[name][]`（`ExclusionSample`）：`[{at}] {ruleText(rule)} · {src_ip} → {dst_ip} · {event_type} · {summary.slice(0,120)}` | 全部为空 → 空态 |

### 4.5 `/config/storage`

**`EsPanel` rail 卡「连接（部署环境固定）」**（现状已有，补 2 行）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 地址 | `cfg.url` | `-` |
| 用户名 | `cfg.username` | `（免认证）` |
| 密码 | `cfg.password_set` → `已设置` / `未设置` | — |
| 保留天数 | `cfg.retention_days` | `—` |
| 保留下限 | `cfg.retention_min_days` → `不得小于 {n} 天`（**新增**） | `—` |
| ILM 策略 | `cfg.ilm_policy` | `—` |

**`LogstashPanel` rail 卡 1「运行状态」**（现状已有）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 引擎 | `data.logstash.alive` → Badge `运行中` / `不可达` | — |
| 入队 | `data.logstash.events_in` | `-` |
| 出队 | `data.logstash.events_out` | `-` |
| 待归一化积压 | `data.queue_depth` | `-` |
| 重载 成功/失败 | `data.logstash.reloads_successes` / `reloads_failures` | `-` / `-` |

**`LogstashPanel` rail 卡 2「管道状态」**（新增）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 生效来源 | `params_applied ? "参数生成" : params_stored ? "自定义内容" : "与默认模板不一致"` | `—` |
| 最近下发 | `data.updated_at` → `formatDateTime` | `—` |
| 配置路径 | `data.config_path` | `—` |
| 备份路径 | `data.backup_path` | `—` |
| 采集接入 | `data.http.hint` + `data.http.port` | `—` |

### 4.6 `/config/agent`

**`McpPanel` rail 卡「服务状态」**（现状已有，补 2 行）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 可达 | `status.service.reachable` → Badge `服务在线` / `服务不可达` | — |
| 服务地址 | `status.service.url` | `—` |
| HTTP 码 | `status.service.status_code`（**新增**，仅 `!reachable` 时显示） | 不显示 |
| 探测错误 | `status.service.error` | 不显示 |
| 工具 | `status.tools.count` → `工具 {n} 个` | `—` |
| 令牌 | `status.tokens.enabled` / `status.tokens.total`（+ `tokens.expired` 个已过期） | — |
| 调用留存 | `status.calls.kept`（失败 `status.calls.errors`） | — |
| 最近调用 | `status.calls.last_at` → `formatDateTime`（**新增**） | `—` |
| 结论 | `status.conclusions.total` | `—` |

**`AgentPushPanel` rail 卡 1「当前配置」**（现状已有，补 2 行）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 推送地址 | `cfg.url` | `(未填地址)` |
| 令牌 | `cfg.token_set` → `已设置（{cfg.token_masked}）` | `未设置` |
| 环境默认 | `data.env.url` | 不显示 |
| 生效 | `cfg.active` → Badge `推送已启用` / `未启用（走旧队列）` | — |
| 超时 | `cfg.timeout_seconds` → `{n} 秒`（**新增**） | `—` |
| 单批上限 | `cfg.max_per_push` → `{n} 条`（**新增**） | `—` |

**`AgentPushPanel` rail 卡 2「送达与积压」**（现状已有）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 已送达 | `st.sent` | — |
| 失败待重发 | `backlog(st)` = `retry_backlog_batches ?? queue_depth + processing_depth` | — |
| 重发成功 | `st.retried` | — |
| 重发失败 | `st.retry_failed` | — |
| 最近成功 / 失败 | `st.last_success_at` / `st.last_error_at`（+ `st.last_error`） | `—` |
| 状态不可读 | `st.error` | 不显示 |

### 4.7 `/config/health`（`app/admin/config/page.tsx`，`/api/config/audit`）

**rail 卡「需要处理」/「正常」**（现状已有）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 需要处理数 | `data.warnings.length` → Badge + 卡标题 | — |
| 警告清单 | `data.warnings[]` 每条一个 `<li>`（`list-disc pl-4 text-sev-medium-fg`） | `0` → 换成「正常」卡 |
| 逐项提示数 | `items.filter(it => it.warn).length` → `其余 {n} 项带提示`（**新增**，与主列的「逐项正常」Stat 呼应） | `0` → 整行不渲染 |
| 检查时间 | `data.checked_at` → `formatDateTime`（现状在 `Section.extra`，保留原处即可） | — |
| 智能体地址 | `data.default_agent_host`（现状在 `Section.extra`） | 不显示 |
| 接口错误 | `data.error` | 不显示（走 `PanelError` + danger 空态） |

### 4.8 `/config/account`（`/api/auth/me`）

**rail 卡「当前账号」**（现状已有，补 2 行）

| 行 | 字段 | 空值显示 |
|---|---|---|
| 用户名 | `me.username` | 整卡走空态 |
| 角色 | `me.role` | `admin` |
| 口令状态 | `me.default_password_in_use` → Badge `仍在使用出厂口令` / `口令已修改` | — |
| 最短长度 | `me.password_min_chars` → `新口令最短 {n} 位`（**新增**） | — |
| 后端说明 | `me.note`（**新增**，现状未展示） | 不显示 |
| 出厂口令警告 | `me.default_password_in_use` → 红条 `role="alert"`（现状已有，保持） | — |

---

## 5. 对 Phase 1 的质疑

逐条给理由与替代方案。**不改动 Phase 1 的章节**，Phase 3 按本文执行。
标记为 ✅ 的 6 条已由 design-architect 拍板，结论写在这里（他已在自己的文档里标注「Phase 2 复核后修正」）。

### Q1 ⏳ 待 team-lead 裁决｜当前口径：叶子行**恒定两行**，断点只决定 ④⑤⑥⑦ 的去留

- Phase 1 4.5 原文：`<lg` 塌成两行（隐含"≥1024 是一行"）。
- **我的质疑**：1024 视口下 7 列模板的 ③ 列只有 **216px**（`T=704 − 40 − 448`），12px 字号下描述只能放 18 字，还不如现状"硬切 60 字符"，却多付行高。
- **design-architect 复核后加强**：不是"塌两行"，而是**所有宽度都是两行**（名称行 + 描述行恒定堆叠），`xl:`(1280) 只决定 ④⑤⑥⑦（类型 / 级别 / 优先级 / 操作）留在 grid 列上还是下移到第三行。
- **定稿数值**（2.2 / 2.3 已同步）：<1280 走 3 列模板 `[1.25rem_1.75rem_minmax(0,1fr)]`，③ 列 768=**520px** / 1024=**592px**；≥1280 走 7 列，③ 列 1280=472 / 1600=792 / 1920=1112 / 2560=1752。两行容量见 2.1 的对照表。
- **配套**：行高 48px → **44px**（`min-h-11 py-1`），Phase 1 4.2 的 `MID` 常量 24 → **22**（`h-[22px]` / `top-[22px]`）。
- **高度代价**（修正 Phase 1 的估算）：内置规则 **22 条**，两行相对单行的增量是 `22 × 8px = 176px`，不是按"40 条"估的 480px。
- **⚠️ 给 Phase 3 的提醒**：不要把 768/1024 读成"这两档才两行、≥1280 变一行"。两行是恒定的。
- **⏳ 待 team-lead 最终裁决**：design-architect 已把 Q1 交回主理人，他另裁了一版「≥1280 单行、<1280 才塌多行」，依据是「1280 时 41 字达标」。那个数字是按 ③ 列**全宽**算的，漏了名称占位。补正后的对照：

  | 视口 | ③ 列 | 单行描述可用宽（`③ − 151px` 名称） | 单行字数 | 两行字数 |
  |---|---|---|---|---|
  | 1280 | 472 | 321 | **26** ❌ | 78 ✅ |
  | 1366 | 558 | 407 | **33** ❌ | 93 ✅ |
  | 1440 | 632 | 481 | **40** ❌ | 105 ✅ |
  | 1600 | 792 | 641 | **53** ❌ | 132 ✅ |
  | **1700** | 892 | 741 | **61** ✅ | 148 ✅ |
  | 1920 | 1112 | 961 | **80** ✅ | 185 ✅ |

  名称占位 = 最长规则名 11 字 × 13px + `ml-2` 8px = **151px**（实测最长 11 字符、中位 8）。基准线是现状 `slice(0, 60)` 的 60 字。
  **结论**：单行排版要到 **视口 ≥ 1700px** 才不劣于现状；1280–1600 这三档（企业环境最常见）描述可见长度会从 60 字掉到 26 / 33 / 40 / 53 字。两行排版在每一档都 ≥ 78 字。
  **两个可选裁决**：① 维持恒定两行（无阈值、不存在下降档）；② 改单行但阈值抬到 `min-[1700px]`（design-architect 提的 `min-[1600px]` 只有 53 字，仍差 7 字）。

### Q2 collect 的 rail 里没有"PID"这个字段

- Phase 1 2.2：collect rail = "采集器运行状态（运行中/未运行、**PID**、最近重载时间）+ 探测到的网卡数"。
- **实测**：`ZeekStatus`（`lib/api.ts:122-144`）的字段是 `interface / networks / bpf_extra / bpf_filter / local_nets / last_reload / config_path / detected / body_max_bytes / resp_body_max_bytes / tls_ports / suricata / rotation_hours / retention_days_local` —— **没有 pid，也没有任何"是否运行中"的布尔**。
- **理由**：不能为了填满 rail 编一个接口字段。
- **替代**：用 `status.detected.find(i => i.name === status.interface)?.state`（`ZeekIfaceInfo.state`）表达网卡状态、`status.last_reload` 表达"最近重载"、`status.detected.length` 表达"探测到 N 张"、`status.suricata.alive` 表达签名引擎是否在跑。见 4.1。若要真正的进程状态，需要后端在 `/api/zeek/status` 增字段 —— 属于业务变更，本阶段不做。

### Q3 ✅ 采纳：`<mark>` 补字色；且搜索应包含停用规则

- Phase 1 4.8 给 `<mark>` 只写了 `bg-brand-50`。
- **实测对比度**：brand-50 `#ecf4fe` vs 白卡 `#ffffff` ≈ **1.11:1**；vs 停用行的 `surface-1` `#f6f7f9` ≈ **1.03:1** —— 后者作为背景差**肉眼不可见**。而搜索命中停用规则的场景必然存在（1.5.2）。
- **定稿**：`<mark className="rounded-[2px] bg-brand-50 px-0.5 font-medium text-primary">`。主色字 `#144990` on `#ecf4fe` = **8.03:1**（design-architect 独立复核，与我算的 8.05 一致）。暗色不单独处理 —— 这对组合与页头一级菜单选中态（`bg-primary/10` + `text-primary`）是同一对，全站已验证。
- **附加（更重要）**：Phase 1 4.8 的 `match` 若作用于 `shown`，则停用规则永远搜不到（B1）。候选池改为 `showDisabled || needle ? rules : rules.filter(enabled)`。

### Q4 ✅ 采纳：`aria-labelledby` 指向名称 `<span>`，不是整行

- Phase 1 4.6：`aria-labelledby={rowId}`，`rowId` 指向 L3 行。
- **问题**：L3 行是 7 列 grid `<div>`，可访问名计算会拼上**所有列文本**（"规则名 描述 逐条 高危 100"），读屏宣读的是一串无结构文本。
- **定稿**：给行内名称 `<span>` 加 `id={`${panelId}-label`}`，`aria-labelledby` 指向它 → 宣读"规则名 区域"。零成本、更准确。

### Q5 ✅ 采纳（加门闩）：`groupRows` = 3，签名子级骨架只在展开时画

- Phase 1 4.9 / 5.6：`groupRows={2}`。
- **实测**：L2 有三个分组 —— 内置 / 自定义 / **签名**（`rules/page.tsx:575-605`）。骨架画 2 行会在内容到达时多出一行，跳版。
- **附加**：签名分组的子级是 `SuricataRulesPanel`（两张卡 + 表单，展开后 ≈ 300–400px），骨架给 `h-10`（40px）差一个数量级。
- **定稿**：`rootRows={1} groupRows={3} leafRows={5}`，签名子级 `h-40`（160px）—— 不追求精确，只要"这里将出现一大块"的形状对。
- **门闩（design-architect 补）**：签名分组**默认收起**（`expanded` 初值只有 `network` 与 `network:builtin`），所以首屏**不画** `h-40` —— 否则骨架比真实首屏高一倍，反而制造跳版。API 上加 `lastGroupTall?: boolean`，只在 `expanded["network:signature"]` 为真时传。

### Q6 ✅ 已定稿：③ 列富余不动、不加第 8 列；`line-clamp-2` **保留**

- Phase 1 1.3 给 rules 定 `full`（不加 max-w），本文照单接受。
- **实测（我自己更正两次）**：最初以「最长 54 字符」撤回了 `line-clamp-2`；逐条解析 `BUILTIN_RULES` 后确认实际是 **22 条、描述最长 90 字符、中位 37、2 条超过 60**（90 / 74）。所以：
  - `line-clamp-2` **保留**（2.4a）：1280 的 ③ 列 472px 两行只有 78 字、768 的 520px 只有 86 字，都放不下 90 字；不 clamp 会折到第三行，破坏「恒定两行 + 行高 44px」的契约。
  - **③ 列富余不动**：不设 `max-w`。这段富余是表格单元格里文本自然结束后的空白，不是用户抱怨的那类「被拉长的控件」空白。
- **加第 8 列（规则 ID）被 design-architect 否决**，三条理由：① ID 是排查 / 对工单时才用的字段，常驻列等于给每行加一段 UUID 前缀噪音；② `min-[2200px]` 加列会让 `LEAF_COLS` 变成三套模板，而它被列头行 / 数据行 / 窄屏行三处引用，多一套就多三个失配点（4.5 那一整段就是为了防列头错位）；③ 有零成本替代。
- **替代（采纳）**：③ 列第二行 `flex` 排「描述 `min-w-0 flex-1`」+「ID `shrink-0 font-mono text-xs text-muted-foreground/60`」，窄屏描述把 ID 挤掉、宽屏自然出现，不需要任何断点（代码见 2.4c）。

### Q7 ✅ 采纳（design-architect 认领为他的 bug）：localStorage 改 effect + 门闩

- Phase 1 4.8：`setExpanded((prev) => ({...prev, ...next}))` 之后，用**闭包里的 `expanded`** 拼 `JSON.stringify({...expanded, ...next})` 写 localStorage。
- **问题**：① 闭包 `expanded` 可能是过期值（同一 tick 内连点两次按钮 → 第二次基于旧值，丢一次状态）；② 与现状 `toggleNode` 的「在 updater 内写」是两种不一致的写法，而在 updater 内做副作用在 StrictMode 下会被调用两次。
- **定稿**：一处 effect 读 + 一处 effect 写，`toggleNode` / `setAll` 退化成纯 state 更新，门闩防首帧冲掉存档。key 与 payload 形状**一字未改**。
- **⚠️ 用 `useRef` 做门闩时的顺序约束（给 fe-engineer）**：React 按声明顺序执行 effect。若门闩用 ref，**写 effect 必须声明在读 effect 之前** —— 否则首帧顺序是「读（ref 置 true）→ 写（ref 已是 true）」，默认值会立刻覆盖掉存档。若用 `useState` 做门闩（1.2 的写法）则无此约束（写 effect 依赖 `[expanded, hydrated]`，首帧 `hydrated=false` 直接 return）。两种都行，别混。

### Q8 ✅ 采纳并扩大范围：`sr-only` 覆盖标签 + 分组标题 + 分区名

- Phase 1 3.4：标签 `<span>` 加 `max-lg:hidden`。
- **问题**：`hidden` 是 `display:none`，会把标签从**无障碍树**一起移除。此时 `<Link>` 内只剩一个 SVG（lucide 默认不输出 `<title>`，也没有 `aria-hidden`），读屏宣读「链接」 —— 8 个菜单项全是「链接」，导航完全不可用。鼠标用户有 `title` 兜底，键盘 / 读屏用户没有。
- **定稿**：`className="truncate max-lg:sr-only"`。`sr-only` 是 `position:absolute` + `clip`，脱离 flex 布局（视觉上等于隐藏），但保留可访问名。零 JS、零 hydration 抖动。
- **扩大（design-architect 补）**：不只标签，**分组标题（接入与范围 / 检测与过滤…）和顶部分区名（配置管理）也必须 `sr-only` 不能 `hidden`** —— 只留一条 `aria-hidden` 分隔线的话，读屏用户同时丢掉分组信息，8 个链接既无名字又无分组。分隔线本身保持 `aria-hidden`（它本来就是装饰）。
- **同一条理由的推广**：Phase 1 3.1 把描述移入 `title` 后，**键盘聚焦不会触发原生 tooltip**（Chrome / Safari 的 `title` 只在鼠标 hover 时弹出，读屏对 `title` 的支持也不一致）。补一行 `<span className="sr-only">{it.desc}</span>`：可见文本仍是单行（符合「更美观简洁」），读屏读到「采集接入 抓包网卡与监听参数」。成本一行，收益是让信息损失真正归零。

### Q9 `main` 的 `transition-[margin]` 缺 `motion-reduce`（Phase 1 未涉及）

- `page-shell.tsx:47` 有 `transition-[margin] duration-150`，侧栏宽度在 1024 断点变化时会有 150ms 动画。
- **问题**：`prefers-reduced-motion` 用户会看到一次无意义的横向位移动画（拖拽窗口跨过 1024 时触发）。
- **替代**：`transition-[margin] duration-150 motion-reduce:transition-none`。与 `globals.css` 里 `.st-pulse` 的既有先例一致。

---

## 6. 验收清单（Phase 3 提交前逐条打勾）

### 6.1 无障碍与交互基线

- [ ] `expanded` 持久化走 effect + 门闩（1.2）；key 仍是 `shentong.rules.tree`，payload 结构未变
- [ ] **门闩顺序**（Q7）：若用 `useRef` 做门闩，写 effect 必须声明在读 effect 之前；用 `useState` 则无约束。二选一，别混
- [ ] 「全部展开 / 收起」只写 4 个 key，**`openIds` 一行代码都没动**（1.2 A5/A6）
- [ ] 搜索候选池含停用规则（1.5.2）；0 命中空态在树下方且**不渲染 L1/L2 空壳**（1.5.3 / 1.5.6）
- [ ] 搜索期间 chevron 可点（有 `collapsedDuringSearch`），清空搜索恢复（1.3 / A8-A9）
- [ ] `<mark>` 带 `font-medium text-primary`，且 `highlightParts` 有 `escapeRegExp`（1.5.4）
- [ ] `toggle()` 失败与 `load()` 失败分别落到 `role="alert"` 的两条不同文案（1.6.2 表 D）
- [ ] `busy === r.id` 期间：整行 `bg-brand-50` 常亮 + 「切换中…」+ Switch/图标按钮 `disabled`（1.6.2）
- [ ] 详情面板 `role="region"` + `aria-labelledby` 指向**名称 span**；`<pre>` 有 `tabIndex={0}`（1.7.4）
- [ ] 结果计数条无 `role`、搜索框有 `aria-describedby`（1.5.5）
- [ ] 所有手写 `<button>` / `<Link>` / `Switch` 有 `focus-visible:ring-2 focus-visible:ring-ring/40`
- [ ] `main` 的 `transition-[margin]` 有 `motion-reduce:transition-none`（Q9）
- [ ] 图标轨用 `max-lg:sr-only` 不是 `hidden`；导航项补 `sr-only` 描述（Q8）
- [ ] **分组标题与顶部分区名也用 `sr-only` 不是 `hidden`**；分隔线本身 `aria-hidden`（Q8）
- [ ] **叶子行恒定两行**：名称行 + 描述行在任何宽度都堆叠；`xl:`(1280) 只切 ④⑤⑥⑦ 的去留，不切行数（Q1，**待 team-lead 最终裁决**，见 Q1 的对照表）
- [ ] 行高 `min-h-11`(44px)、`MID` = 22（Q1 配套）
- [ ] 描述行有 `line-clamp-2` + `title`；**详情面板里的描述不加 clamp**（2.4a）
- [ ] ③ 列第二行的 ID 用 `flex` + `shrink-0`，**没有**新增第 8 列（Q6）
- [ ] `TreeSkeleton` 用 `groupRows={3}`，且 `h-40` 只在 `expanded["network:signature"]` 为真时画（`lastGroupTall`）（Q5）
- [ ] 树里没有 `role="tree"` / `role="treeitem"` / roving `tabindex`
- [ ] 无新增依赖；`package.json` 未改动；未跑 `npm run build` / `next build` / `docker build`

### 6.2 手工验收（浏览器里点一遍）

1. 首屏：骨架形状与加载完一致（3.2 表），不出现"先空白后跳版"
2. 展开 3 个 L2、勾开「显示已停用」→ F5 刷新 → 树状态与开关一致（`showDisabled` 不持久化、`expanded` 持久化）
3. 「全部展开」连点两次 → `network:signature` 仍展开（无状态丢失，验证 Q7 修法）
4. 搜一个停用规则的名字 → **能搜到**（验证 B1），行上带「已停用」Badge，计数条显示"含 N 条已停用"
5. 搜索中手动收起「内置规则」→ 收得起来；清空搜索 → 回到收起前的 `expanded` 状态
6. 搜 `(` → 不崩（验证 `escapeRegExp`）
7. 搜一个不存在的词 → 整棵树消失、只留一条空态（不是三个空分组）
8. 断网后点启用开关 → 红字"更新失败"，开关回到旧值
9. 断网后点「刷新」→ 顶部 `PanelError`，列表保留旧数据（不空白）
10. 1024 与 1280 视口：叶子行**都是两行**（名称 + 描述堆叠）；1024 时 ④⑤⑥⑦ 在第三行、1280 时在列上（验证 Q1 的恒定两行，不是"窄屏才两行"）
10b. 1280 视口看最长的那条规则（`内网漏洞利用探测`，描述 90 字）：描述被 clamp 成两行、行高仍是 44px，没有第三行
11. 键盘从搜索框 Tab 到底：不出现焦点丢失、不出现无 ring 的按钮
12. 展开一条规则的详情 → 焦点**没有**跳进面板（1.7.3）
13. 系统设置开启"减少动态效果"→ chevron 无旋转动画、骨架不闪烁、侧栏宽度变化无动画

---

## 7. 主理人裁决（Phase 2 → Phase 3 生效）

> **本节已按 design-architect 复核结论 + 规则描述实测更正过两处**（Q1、Q6），更正原因写在每行里。以本节为最终执行口径；若与第 5 节的早期表述冲突，以本节为准。

第 5 节的 9 条质疑**全部采纳**，Phase 3 按第 5 节的「替代」方案执行，不按 Phase 1 的原写法。逐条确认理由与边界：

| # | 裁决 | 补充约束 |
|---|---|---|
| Q1 | ✅ 采纳，**结论已升级**：不是「`lg:`→`xl:` 的阈值调整」，而是**叶子行恒定两行**（名称行 + 描述行始终堆叠），`xl:`(1280) 只决定 ④⑤⑥⑦ 留在列上还是下移第三行 | 计算口径以 2.1 为准（树宽 `T = C − 32`，含 Card `p-2` + 行 `px-2`）：1024 在 7 列模板下 ③ 列 = **216px**（约 18 字），3 列模板下 = **592px**（约 49 字）。<1280 走 3 列模板，所以 216px **不会出现**。行高 44px、`MID`=22。两行相对单行的高度增量 = `22 条 × 8px = 176px`。 |
| Q2 | ✅ 采纳。collect 的 rail **不出现 PID** | 只用 `ZeekStatus` 真实字段：所选网卡 `detected[].state`、`last_reload`、`detected.length`、`suricata.alive`。**禁止为填满版面向后端要新字段** —— 真要进程状态属业务变更，本轮不做。 |
| Q3 | ✅ 采纳。`<mark>` 补 `font-medium text-primary`；搜索候选池含停用规则 | 候选池写死为 `showDisabled || needle ? rules : rules.filter(r => r.enabled)`。这条不只是样式修正，是修一个会让运维误判「规则被删了」的真 bug，**优先级最高**。 |
| Q4 | ✅ 采纳。`aria-labelledby` 指向行内名称 `<span>` | 面板 id 与 label id 用同一前缀派生（`${panelId}-label`），别再手工编两套。 |
| Q5 | ✅ 采纳。`groupRows` 2 → **3**；签名子级骨架 `h-10` → **`h-40`**，但**只在签名组展开时画**（`lastGroupTall`） | 骨架只求「形状数量级对」，不追求像素精确。门闩是 design-architect 补的：签名组默认收起，首屏画 `h-40` 会让骨架比真实首屏高一倍，反而制造跳版。 |
| Q6 | ✅ 采纳「③ 列不设 `max-w`」；**但 `line-clamp-2` 保留、第 8 列取消**（原因见下） | 我最初报「描述最长 54 字符」是错的（正则漏掉跨行隐式拼接的字面量）。逐条解析 `BUILTIN_RULES`：**22 条、最长 90 字符、中位 37、2 条超过 60**。90 字需要两行容量 ≥ 90 ⇔ ③ 列 ≥ 540px，而 1280 只有 472px（78 字）、768 只有 520px（86 字）→ 不 clamp 会折第三行，破坏「恒定两行 + 44px」契约。第 8 列由 design-architect 否决：ID 是低频字段、常驻列是噪音；`LEAF_COLS` 变三套模板会引入三个列头失配点。改用零成本替代（2.4c：描述 + ID 同一行 `flex`，窄屏自然挤掉 ID）。 |
| Q7 | ✅ 采纳。localStorage 改 effect 持久化 + 门闩 | **key 与 payload 结构一字不改**（`shentong.rules.tree`）。`toggleNode` 里的 updater 内副作用一并移除。**门闩用 ref 时写 effect 必须声明在读 effect 之前**（顺序反了首帧就会冲掉存档）。 |
| Q8 | ✅ 采纳。**范围扩大**：标签 + 分组标题 + 顶部分区名一律 `sr-only` 不能 `hidden`；导航项补 `<span className="sr-only">{it.desc}</span>` | `title` 一律写成 `${it.label} · ${it.desc}`，两种状态都合理。分隔线本身保持 `aria-hidden`（装饰）。扩大是 design-architect 补的：只留分隔线的话，读屏用户 8 个链接既无名字又无分组。 |
| Q9 | ✅ 采纳。`main` 补 `motion-reduce:transition-none` | — |

### 7.1 对 Q3「搜索候选池」的补充判定

`needle` 非空时**必须**能搜到停用规则，且行上要带「已停用」Badge、计数条要写明「含 N 条已停用」。理由：停用规则默认收起，如果搜索也搜不到，运维在排查「为什么没有某类告警」时会得出「规则不存在」的错误结论，进而重复新建规则或误判存在检测盲区 —— 这两者在安全运营里都是要付真实代价的。

### 7.2 对 Q6「2560 富余」的边界（已更正）

- **不加第 8 列**（原裁决批准过，已被 design-architect 否决，原因见 Q6 行）。
- **③ 列不设 `max-w`**：1920–2560 之间保持 7 列 + 富余。这段富余是表格单元格里文本自然结束后的空白，不是被拉长的控件。
- **描述行加 `line-clamp-2`**：不是为治空白，而是为保证「恒定两行 + 行高 44px」的契约 —— 最长 90 字的描述在 1280（78 字）与 768（86 字）会折到第三行。被 clamp 的只有最长的 1–2 条，`title` + 详情面板兜底。
- **ID 的呈现走 2.4c 的 `flex` 方案**：与描述同一行、右端、`shrink-0`，宽屏自然出现、窄屏被描述挤掉。无断点、不动 `LEAF_COLS`。

### 7.3 给 Phase 3 的执行顺序

1. `packages/ui` 新增原语（Switch / Field / FieldGrid / PanelToolbar / TreeSkeleton）+ `index.ts` 导出
2. `page-shell.tsx` + `globals.css`（`--sidebar-w`、Q9）
3. `nav.tsx`（Q8、Q1 无关于此）
4. `rule-tree.tsx` 新增 + `rules/page.tsx` 改造（Q1/Q3/Q4/Q5/Q7）
5. `suricata-rules-panel.tsx` 加 `variant="inline"`
6. 其余 7 个配置页与面板的 `width` 与 `FieldGrid` 收尾
7. `npx tsc --noEmit`（NDR 与 agent 双端）
