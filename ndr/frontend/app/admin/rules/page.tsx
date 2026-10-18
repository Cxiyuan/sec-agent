"use client";

import * as React from "react";
import { ChevronsDownUp, ChevronsUpDown, Pencil, Radio, Search, Trash2 } from "lucide-react";
import { PageShell } from "@/components/page-shell";
import {
  Badge,
  Button,
  Card,
  Dialog,
  Drawer,
  EmptyState,
  Field,
  FieldGrid,
  Input,
  PanelToolbar,
  Section,
  Switch,
  TreeSkeleton,
  ApiError,
  apiFetch,
  cn,
  errorText,
  severityText,
  severityVariant,
} from "@shentong/ui";

import type { RuleItem } from "@/lib/api";
import { SuricataRulesPanel } from "@/components/suricata-rules-panel";
import { PanelError, emptyOrFailed, loadInto, usePanelErrors } from "@/components/panel-error";
import {
  ConditionEditor,
  RULE_FIELDS,
  SELECT_CLS,
  condsToRules,
  type Cond,
} from "@/components/condition-editor";
import {
  LEAF_CELL_XL,
  LEAF_COLS,
  LEAF_ROW_NARROW,
  TreeChevron,
  TreeChildren,
  TreeRow,
} from "@/components/rule-tree";
import { highlightParts } from "@/lib/highlight";

/**
 * 检测规则页：树型展开/收缩（检测规则 → 特征匹配 / 行为分析 / 基线偏离 / 签名规则集）。
 *
 * 规则只有网络一侧：条件引用网络侧字段（http/ssl/dns/conn…）与签名引擎告警，
 * 检测器只在网络事件上求值。主机监控那条线已随对应日志源一起下线。
 *
 * 2026-10 改版一（用户反馈「列表菜单太简陋」）：三级树 + 树线 + 7 列网格叶子行，
 * 接口路径、请求体字段、`expanded` / `openIds` / `showDisabled` / `busy` 的语义与
 * localStorage key 一律保持原样 —— 只排版版式与视觉。
 *
 * 2026-10 改版二（对齐后端 API 契约）：分组口径从「内置定义 / 自建规则」换成后端
 * `rules.py` 直出的**事件来源三类**（source_kind）—— 特征匹配 / 行为分析 / 基线偏离。
 * 「是不是内置」不再占一个分组，改在叶子行挂「内置」徽章（它决定可编辑性，不决定分组）。
 * 签名规则集（引擎规则文件）不是 /api/rules 的规则，仍单独一个节点。
 */

const SRC = { list: "检测规则（/api/rules）" } as const;

/** `expanded` 的持久化 key 与 payload 结构一字未改，只换了写入时机（见 Q7 与下面的 effect）。 */
const TREE_KEY = "shentong.rules.tree";
/**
 * `expanded` 的合法 key 白名单（唯一的合法集合）。
 * 读取时只保留这 5 个 —— 老浏览器里可能残留 `network:builtin` 之类的旧键（分组口径
 * 2026-10 换成来源三类），它们不影响渲染但是脏数据，未来若新增/删除节点还会被"复活"。
 */
const TREE_KEYS = [
  "root",
  "kind:feature_match",
  "kind:behavior_analysis",
  "kind:baseline_deviation",
  "signature",
] as const;

/**
 * 事件来源三类（与后端 `rules.py::_source_kind_of` / `_SOURCE_LABELS` 一一对应）。
 * 顺序即界面顺序：特征匹配（签名引擎命中）→ 行为分析（流量判据）→ 基线偏离（自身基线）。
 * key 同时是 `expanded` 的持久化键与 DOM id 前缀。
 */
const KIND_GROUPS = [
  {
    key: "kind:feature_match",
    kind: "feature_match",
    label: "特征匹配",
    hint: "签名引擎按报文特征命中：Web 攻击、扫描器指纹、C2…",
  },
  {
    key: "kind:behavior_analysis",
    kind: "behavior_analysis",
    label: "行为分析",
    hint: "流量日志上的规模/时序判据：横向移动、慢速枚举、TLS 异常…",
  },
  {
    key: "kind:baseline_deviation",
    kind: "baseline_deviation",
    label: "基线偏离",
    hint: "与自身历史基线的偏离：新来源地址、认证失败激增、连接数 2σ…",
  },
] as const;

/** 规则的来源归类：后端没给（老数据/异常）时按行为分析收拢，规则不丢。 */
function kindOf(r: RuleItem): string {
  return KIND_GROUPS.some((g) => g.kind === r.source_kind) ? r.source_kind : "behavior_analysis";
}

function ruleType(r: RuleItem): string {
  const c = (r.conditions || {}) as {
    mode?: string;
    key?: string[];
    min_count?: number;
    distinct?: string;
    min_distinct?: number;
  };
  if (c.mode === "count") {
    const key = (c.key || []).join("+") || "src_ip";
    const distinct = c.distinct && c.min_distinct ? ` 且 ≥${c.min_distinct} 个不同 ${c.distinct}` : "";
    return `频率（${key} ≥ ${c.min_count ?? 1}${distinct}）`;
  }
  return "逐条";
}

/** 严重度徽章：**每一级一个独立变体**。
 *  原来 high 与 critical 都映射到 `critical`（同一个红底徽章），列表里"严重"和"高危"
 *  看起来完全一样 —— 严重度这一列等于白给。文案也统一走共享的 severityText
 *  （这里原来叫"紧急"、共享库叫"严重"，同一条规则两个页面两个叫法）。 */
function severityBadge(sev: string): React.ReactElement {
  return <Badge variant={severityVariant(sev)}>{severityText(sev)}</Badge>;
}

export default function RulesPage() {
  const errs = usePanelErrors();
  const [rules, setRules] = React.useState<RuleItem[]>([]);
  const [expanded, setExpanded] = React.useState<Record<string, boolean>>({
    root: true,
    // 行为分析是最大的一组（内置 19 条），默认展开；其余收起来，需要时自己点开
    "kind:behavior_analysis": true,
  });
  const [openIds, setOpenIds] = React.useState<Record<string, boolean>>({});
  const [busy, setBusy] = React.useState("");
  const [msg, setMsg] = React.useState("");
  /** 提示语气：读取/保存失败用语义红，成功用主色（同一处提示条，别让失败看起来像成功） */
  const [msgErr, setMsgErr] = React.useState(false);
  /** 首次加载：规则还没回来时画骨架，不要先显示「这一组还没有规则」 */
  const [loading, setLoading] = React.useState(true);
  /** 待删除的自定义规则：删除不可逆，走共享 Dialog 二次确认（原生 confirm 与全站弹层材质对不上） */
  const [askDel, setAskDel] = React.useState<RuleItem | null>(null);
  /**
   * 停用规则默认收起。
   *
   * 这个页面回答的是「现在在跑什么」，而退役/停用的规则会一直留在库里——后端刻意不删
   * （`main.py::_retire_builtin_rules`：留着运维能看到它为什么没了、也随时能开回来）。
   * 几十条停用规则混在生效规则里，会把真正干活的那批淹掉。需要核对原因或重新启用时
   * 用标题行的开关放出来。
   *
   * 注意别改成「删掉停用规则」：内置规则是按名 upsert 的，删行后下次启动 `exists is None`
   * 会按种子重新建行，连启用状态一起复位——等于把已退役的规则复活。
   */
  const [showDisabled, setShowDisabled] = React.useState(false);
  /** 搜索词（纯展示层：不进 localStorage、不影响任何请求 —— 搜索是一次性动作） */
  const [q, setQ] = React.useState("");
  /**
   * localStorage 回填完了没。没有它，mount 时写 localStorage 的 effect 会用默认展开值
   * 覆盖掉用户上次「全部收起」的存档 —— 这是把持久化改成 effect 之后最容易踩的坑。
   */
  const [hydrated, setHydrated] = React.useState(false);
  /**
   * 搜索期间的「用户显式收起」集合。
   *
   * 命中时祖先会自动展开（渲染期覆盖，不改 `expanded`），那样一来搜索期间的 chevron 点击
   * 会被覆盖吃掉 —— 点了收起没反应，控件失灵。加这个只在搜索期有效的集合，
   * `expanded` 全程保持干净，清空搜索即恢复。
   * 用 ref 而不是 state：它不参与渲染判定之外的事，用 state 会多一次无意义的重渲染。
   */
  const collapsed = React.useRef<Set<string>>(new Set());

  // 自定义规则表单（抽屉）：editId 为空 = 新增
  const [drawer, setDrawer] = React.useState(false);
  const [editId, setEditId] = React.useState("");
  const [name, setName] = React.useState("");
  const [desc, setDesc] = React.useState("");
  const [sev, setSev] = React.useState("medium");
  const [priority, setPriority] = React.useState("100");
  const [enabled, setEnabled] = React.useState(true);
  const [logic, setLogic] = React.useState("and");
  const [conds, setConds] = React.useState<Cond[]>([{ field: "event_type", op: "eq", value: "" }]);
  const [mode, setMode] = React.useState<"single" | "count">("single");
  const [keys, setKeys] = React.useState("src_ip");
  const [minCount, setMinCount] = React.useState("10");
  const [minDistinct, setMinDistinct] = React.useState("");
  const [distinct, setDistinct] = React.useState("dst_port");

  async function load() {
    await loadInto(errs, SRC.list, "/api/rules", (d: { items: RuleItem[] }) => setRules(d.items));
    setLoading(false);
  }

  React.useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 树的展开状态记到浏览器本地：切页/刷新后保持原样（读不到就用默认值，不影响功能）。
  // 只读一次、只认白名单 key —— 写得再勤也救不了一份脏存档。
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
      /* 隐私模式/存储不可用：用默认展开状态 */
    }
    setHydrated(true);
  }, []);

  // 写：等hydrate 之后再写，且只依赖 state 本身 —— 不在 updater 里做副作用
  // （React 18 StrictMode 下 updater 会被调用两次），也不用闭包里的旧值拼字符串
  // （同一 tick 内连点两次「全部展开」会丢一次状态）。
  React.useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(TREE_KEY, JSON.stringify(expanded));
    } catch {
      /* 存不了就算了，只是不记忆 */
    }
  }, [expanded, hydrated]);

  function toggleNode(id: string) {
    if (needle) {
      // 搜索期间的展开与否由渲染期覆盖（isOpen），这里要把"用户显式收起"记下来，
      // 否则这一次点击会被渲染期盖掉，控件看起来是失灵的。
      if (collapsed.current.has(id)) collapsed.current.delete(id);
      else collapsed.current.add(id);
    }
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  /** 全部展开 / 全部收起：只动这 5 个 key —— `openIds`（叶子详情）一个字都不碰。
   *  规则详情面板最小高度约 120px，全部展开 22 条 ≈ 2640px，页面会长 3 屏，
   *  滚动条从约 1/4 屏缩到 1/30 屏，用户失去位置感。 */
  function setAll(open: boolean) {
    setExpanded((prev) => ({
      ...prev,
      root: open,
      "kind:feature_match": open,
      "kind:behavior_analysis": open,
      "kind:baseline_deviation": open,
      signature: open,
    }));
  }

  const disabledRules = rules.filter((r) => !r.enabled);
  const needle = q.trim().toLowerCase();

  const match = (r: RuleItem) =>
    !needle ||
    r.name.toLowerCase().includes(needle) ||
    (r.description || "").toLowerCase().includes(needle) ||
    r.id.toLowerCase().includes(needle);

  /** 未搜索口径下的候选池（分组计数的分母用），受「显示已停用」影响 */
  const basePool = showDisabled ? rules : rules.filter((r) => r.enabled);
  // 搜索时停用规则也必须进候选池：搜不到 ≠ 不在库里（详见下面 UI 里的那句 hint）
  const pool = showDisabled || needle ? rules : basePool;
  const shown = needle ? pool.filter(match) : pool;

  /**
   * 三个来源分组（契约：`GET /api/rules` 每条带 source_kind/source_label，按三类分组展示）。
   * items = 当前可见（受搜索与「显示已停用」影响）；total = 该组全量（未搜索口径，计数分母）；
   * hidden = 被「显示已停用」收起来的条数（空态文案用）；hitDisabled = 搜索命中里的停用条数。
   */
  const groups = KIND_GROUPS.map((g) => {
    const items = shown.filter((r) => kindOf(r) === g.kind);
    return {
      ...g,
      items,
      total: basePool.filter((r) => kindOf(r) === g.kind).length,
      hidden: showDisabled ? 0 : disabledRules.filter((r) => kindOf(r) === g.kind).length,
      hitDisabled: needle ? items.filter((r) => !r.enabled).length : 0,
    };
  });

  const hitCount = needle ? shown.length : 0;
  const hitDisabled = needle ? shown.filter((r) => !r.enabled).length : 0;

  /** 命中 0 条时不渲染「检测规则 › 特征匹配（0 条）› 空态」这种三层空壳 —— 用户要读三层才知道没有结果 */
  const showRoot = !needle || shown.length > 0;
  const showGroup = (key: string) => !needle || groups.some((g) => g.key === key && g.items.length > 0);

  /**
   * 渲染期的展开判定。
   * 搜索时祖先默认展开（命中即钻到这里），除非用户在搜索中手动收起过。
   * 签名分组例外：它不是规则列表，没有可匹配的叶子，放进搜索结果里会占掉半屏。
   */
  const isOpen = (id: string) => (needle ? !collapsed.current.has(id) : !!expanded[id]);
  const isSignatureOpen = !!expanded["signature"];
  const rootOpen = isOpen("root");
  const groupOpen = (key: string) => isOpen(key);

  function setCond(i: number, patch: Partial<Cond>) {
    setConds((cs) => cs.map((c, idx) => (idx === i ? { ...c, ...patch } : c)));
  }

  function buildConditions() {
    const base: Record<string, unknown> = { logic, rules: condsToRules(conds) };
    if (mode === "count") {
      base.mode = "count";
      base.key = keys.split(",").map((s) => s.trim()).filter(Boolean);
      base.min_count = Number(minCount) || 1;
      if (distinct.trim() && Number(minDistinct) > 0) {
        base.distinct = distinct.trim();
        base.min_distinct = Number(minDistinct);
      }
    }
    return base;
  }

  function resetForm() {
    setEditId("");
    setName("");
    setDesc("");
    setSev("medium");
    setPriority("100");
    setEnabled(true);
    setLogic("and");
    setConds([{ field: "event_type", op: "eq", value: "" }]);
    setMode("single");
    setKeys("src_ip");
    setMinCount("10");
    setMinDistinct("");
    setDistinct("dst_port");
  }

  function openCreate() {
    resetForm();
    setMsg("");
    setMsgErr(false);
    setDrawer(true);
  }

  function openEdit(r: RuleItem) {
    const c = (r.conditions || {}) as {
      mode?: string;
      key?: string[];
      min_count?: number;
      distinct?: string;
      min_distinct?: number;
    };
    setEditId(r.id);
    setName(r.name);
    setDesc(r.description || "");
    setSev(r.severity);
    setPriority(String(r.priority));
    setEnabled(r.enabled);
    setLogic(String((r.conditions || {}).logic || "and"));
    setConds(
      (((r.conditions || {}) as { rules?: Array<{ field?: string; op?: string; value?: unknown }> })
        .rules || []).map((x) => ({
        field: String(x.field || ""),
        op: String(x.op || "eq"),
        value: Array.isArray(x.value) ? x.value.join(",") : String(x.value ?? ""),
      })),
    );
    setMode(c.mode === "count" ? "count" : "single");
    setKeys((c.key || ["src_ip"]).join(","));
    setMinCount(String(c.min_count ?? 10));
    setDistinct(String(c.distinct || "dst_port"));
    setMinDistinct(c.min_distinct ? String(c.min_distinct) : "");
    setMsg("");
    setMsgErr(false);
    setDrawer(true);
  }

  /**
   * 勾选启用/禁用：内置规则只有 enabled 会保留（描述/条件/级别/优先级每次启动被内置定义覆盖）。
   *
   * 不做乐观更新：UI 显示「已启用」而服务端实际未启用 = **漏检**，是安全产品最贵的一类错。
   * 这个方向的错误不能从"不可能"变成"可能"。等待期间用整行底色 + 「切换中…」表达待定态。
   */
  async function toggle(r: RuleItem) {
    setBusy(r.id);
    setMsg("");
    setMsgErr(false);
    const verb = r.enabled ? "禁用" : "启用";
    try {
      await apiFetch(`/api/rules/${r.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name: r.name,
          description: r.description,
          conditions: r.conditions,
          severity: r.severity,
          enabled: !r.enabled,
          priority: r.priority,
        }),
      });
      const ok = await loadInto(errs, SRC.list, "/api/rules", (d: { items: RuleItem[] }) =>
        setRules(d.items),
      );
      if (ok) {
        setMsg(`已${verb}「${r.name}」`);
      } else {
        // 列表刷新失败不能画成成功：开关回到旧值（rules 没更新），消息走红条
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

  async function save() {
    setMsg("");
    setMsgErr(false);
    if (!name.trim()) {
      setMsgErr(true);
      setMsg("请填写规则名称");
      return;
    }
    if (conds.filter((c) => c.field && c.op).length === 0) {
      setMsgErr(true);
      setMsg("至少需要一个触发条件（空条件规则不生效）");
      return;
    }
    const payload = {
      name: name.trim(),
      description: desc,
      conditions: buildConditions(),
      severity: sev,
      enabled,
      priority: parseInt(priority, 10) || 100,
    };
    try {
      if (editId) {
        await apiFetch(`/api/rules/${editId}`, { method: "PUT", body: JSON.stringify(payload) });
        setMsg(`已更新「${name.trim()}」`);
      } else {
        const created = await apiFetch<RuleItem>("/api/rules", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        setMsg(
          `已添加「${created?.name || name.trim()}」（ID ${String(created?.id || "").slice(0, 8)}… 自动生成）`,
        );
      }
      setDrawer(false);
      await load();
    } catch (e) {
      setMsgErr(true);
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    }
  }

  async function remove(r: RuleItem) {
    setBusy(r.id);
    setMsgErr(false);
    try {
      await apiFetch(`/api/rules/${r.id}`, { method: "DELETE" });
      setMsg(`已删除「${r.name}」`);
      // id 已不存在，留着不影响渲染；清掉避免 openIds 无界增长
      setOpenIds((m) => {
        const next = { ...m };
        delete next[r.id];
        return next;
      });
      await load();
    } catch (e) {
      setMsgErr(true);
      setMsg(e instanceof ApiError ? errorText(e.body) : "删除失败");
    } finally {
      setBusy("");
      setAskDel(null);
    }
  }

  /** 命中片段包一层 `<mark>`：字色（`text-primary`）才是主要信号 ——
   *  brand-50 对停用行的 surface-1 只有 1.03:1 的亮度差，底色几乎看不出来，
   *  主色字在自己的淡蓝底上约 8.05:1。底色只负责把命中片段的边界框出来。 */
  function hl(text: string): React.ReactNode {
    return highlightParts(text, needle).map((p, i) =>
      p.hit ? (
        <mark key={i} className="rounded-[2px] bg-brand-50 px-0.5 font-medium text-primary">
          {p.s}
        </mark>
      ) : (
        <React.Fragment key={i}>{p.s}</React.Fragment>
      ),
    );
  }

  /** 叶子行的「编辑 / 删除」图标按钮：自定义规则才有。图标按钮必须有 aria-label + title。 */
  function rowActions(r: RuleItem) {
    return (
      <>
        <Button
          size="sm"
          variant="ghost"
          className="h-7 w-7 p-0"
          aria-label={`编辑规则 ${r.name}`}
          title="编辑"
          disabled={busy === r.id}
          onClick={() => openEdit(r)}
        >
          <Pencil className="h-3.5 w-3.5" />
        </Button>
        {/* 删除是 destructive，但不用 variant="destructive"：实心红块在密集列表里太响 */}
        <Button
          size="sm"
          variant="ghost"
          className="h-7 w-7 p-0 text-sev-critical-fg hover:bg-sev-critical-bg"
          aria-label={`删除规则 ${r.name}`}
          title="删除"
          disabled={busy === r.id}
          onClick={() => setAskDel(r)}
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </>
    );
  }

  /** 一条规则（叶子行 + 它的详情面板）。写成普通函数而不是组件：避免在 map 里每次渲染都新建一个
   *  组件类型（那会让 React 认为换了一整棵树，22 行全部重挂载、详情展开态丢失）。 */
  function leafRow(r: RuleItem, last: boolean) {
    // 可编辑性按行判定：内置规则（后端按名 upsert，启动即覆盖）不可改，自定义规则可改。
    // 分组口径换成来源三类后，一组里同时有内置和自定义 —— 组级开关会误伤另一批。
    const editable = r.source !== "builtin";
    const panelId = `rule-panel-${r.id}`;
    const openRow = !!openIds[r.id];
    // 待定态用常亮的 brand-50（不依赖 hover）：请求在飞的时候鼠标不一定在行上，
    // 「它正在改」这件事要自己看得见。停用行整行退回 surface-1。
    const rowBg =
      busy === r.id
        ? "bg-brand-50"
        : r.enabled
          ? "hover:bg-brand-50"
          : "bg-surface-1 hover:bg-brand-50";
    return (
      <TreeRow key={r.id} last={last} mid={22}>
        <div className={cn(LEAF_COLS, "grid items-center gap-x-3 rounded-sm px-2", rowBg)}>
          {/* ① 详情展开 */}
          <button
            type="button"
            className="flex h-5 w-5 items-center justify-center rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
            aria-expanded={openRow}
            aria-controls={panelId}
            aria-label={`${openRow ? "收起" : "展开"}规则「${r.name}」的条件详情`}
            title={openRow ? "收起条件详情" : "展开条件详情"}
            onClick={() => setOpenIds((m) => ({ ...m, [r.id]: !m[r.id] }))}
          >
            <TreeChevron open={openRow} />
          </button>
          {/* ② 启用开关 */}
          <Switch
            size="sm"
            checked={r.enabled}
            disabled={busy === r.id}
            busy={busy === r.id}
            onCheckedChange={() => void toggle(r)}
            label={`${r.enabled ? "停用" : "启用"}规则「${r.name}」`}
            title={r.enabled ? "点击停用" : "点击启用"}
          />
          {/* ③ 名称 + 描述（+ 窄屏时折下来的第二行）
              行高账：py-1(4×2) + 名称行 text-13(20) + 描述行 text-xs(16) = 44px，
              与 TreeRow 的 mid={22}（中线）严格对齐。 */}
          <div className="min-w-0 py-1">
            <div className="flex min-w-0 items-center gap-1.5">
              {/* Q4：aria-labelledby 指向名称 span，不是整行 —— 整行是 7 列 grid，
                  可访问名会把所有列文本拼成"规则名 描述 逐条 高危 100"这样一串。 */}
              <span
                id={`${panelId}-label`}
                className={cn(
                  "truncate text-13 font-medium",
                  r.enabled ? "text-foreground" : "text-muted-foreground",
                )}
              >
                {hl(r.name)}
              </span>
              {!r.enabled ? <Badge variant="info">已停用</Badge> : null}
              {/* 「是不是内置」原来靠分组表达；分组换成来源三类后挪到行内徽章 */}
              {r.source === "builtin" ? <Badge variant="outline">内置</Badge> : null}
              {busy === r.id ? (
                <span className="shrink-0 text-xs text-primary">切换中…</span>
              ) : null}
            </div>
            {/* 描述行同样高亮。clamp 是**行高守卫**不是空白治理：内置描述开发者手写有界
                （实测最长 90 字符），自定义描述由用户填写、无界 —— 不 clamp 会把行撑到
                三行以上、破坏「恒定两行 + 44px」契约。≥xl 收 1 行、<xl 收 2 行（③ 列
                在窄屏是 592px 全宽，两行 ≈ 98 字），都配 title 兜底。
                严重度徽章不随启用状态变：严重度是这条规则的事实属性，不是它的运行状态。 */}
            {/* 规则 ID 不放独立列（排查才用的低频字段，且会让 LEAF_COLS 多一套模板、
                列头行/数据行/窄屏 meta 行三处引用多三个失配点）：放描述行末尾，
                宽屏自然出现，窄屏被描述挤掉。 */}
            <div className="flex min-w-0 items-baseline gap-2">
              <p
                className={cn(
                  "min-w-0 flex-1 truncate text-xs text-muted-foreground",
                  "line-clamp-1 xl:line-clamp-1 max-xl:line-clamp-2",
                )}
                title={r.description || "（无描述）"}
              >
                {hl(r.description || "（无描述）")}
              </p>
              <span
                className="shrink-0 font-mono text-xs text-muted-foreground"
                title={`规则 ID ${r.id}`}
              >
                {r.id.slice(0, 8)}
              </span>
            </div>
            <div
              className={cn(
                "mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground",
                LEAF_ROW_NARROW,
              )}
            >
              <span className="truncate">{ruleType(r)}</span>
              <span aria-hidden>·</span>
              {severityBadge(r.severity)}
              <span>
                <span aria-hidden>· </span>优先级 <span className="tabular-nums">{r.priority}</span>
              </span>
              {editable ? <span className="ml-auto flex items-center gap-1">{rowActions(r)}</span> : null}
            </div>
          </div>
          {/* ④ 类型 */}
          <span className={cn("truncate text-xs text-muted-foreground", LEAF_CELL_XL)}>
            {ruleType(r)}
          </span>
          {/* ⑤ 级别 */}
          <span className={cn("min-w-0", LEAF_CELL_XL)}>{severityBadge(r.severity)}</span>
          {/* ⑥ 优先级 */}
          <span className={cn("text-right text-13 tabular-nums", LEAF_CELL_XL)}>{r.priority}</span>
          {/* ⑦ 操作：内置规则也留空列 —— 列头要和自定义组对齐，错位的列头会让人以为看错了列 */}
          <span className="hidden items-center justify-end gap-1 xl:flex">
            {editable ? rowActions(r) : null}
          </span>
        </div>

        {/* 详情面板：不用 TableRow 内嵌 `<table>` 里的 display:table-row 无法参与 grid/flex，
            缩进与树线都挂不上去。这里降级为树内的「内联格」（bg-surface-1、无描边）。
            始终渲染容器（收起时为空）—— 让 chevron 的 aria-controls 永远指向真实存在的元素。 */}
        <div
          id={panelId}
          role="region"
          aria-labelledby={`${panelId}-label`}
          className={cn("mb-1 ml-5 mt-1 rounded-sm bg-surface-1 px-3 py-2", !openRow && "hidden")}
        >
          {openRow ? (
            <>
              <p className="text-xs text-muted-foreground">
                规则 ID <span className="font-mono">{r.id}</span>
                {r.source === "builtin"
                  ? " · 内置规则：描述/条件/级别/优先级每次启动会被内置定义覆盖，只有启用状态会保留"
                  : null}
              </p>
              <p className="mt-1 text-13 leading-relaxed">{r.description || "（无描述）"}</p>
              {/* tabIndex：否则键盘用户无法滚动被 max-h-56 截断的条件 JSON */}
              <pre
                tabIndex={0}
                role="group"
                aria-label={`规则「${r.name}」的条件 JSON`}
                className="mt-2 max-h-56 overflow-auto rounded-xs border border-border-subtle bg-surface-2 p-2 font-mono text-xs leading-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
              >
                {JSON.stringify(r.conditions || {}, null, 2)}
              </pre>
            </>
          ) : null}
        </div>
      </TreeRow>
    );
  }

  /** 叶子区的列头：与数据行共用 LEAF_COLS，保证一列对齐。 */
  function leafHeader() {
    return (
      <div
        className={cn(
          LEAF_COLS,
          "grid h-8 items-center gap-x-3 rounded-sm bg-surface-1 px-2 text-xs font-medium text-muted-foreground",
        )}
      >
        <span />
        <span />
        <span>规则</span>
        <span className={LEAF_CELL_XL}>类型</span>
        <span className={LEAF_CELL_XL}>级别</span>
        <span className={cn("text-right", LEAF_CELL_XL)}>优先级</span>
        <span className={cn("hidden text-right xl:block")}>操作</span>
      </div>
    );
  }

  /** 分组列表体：有行 → 列头 + 叶子列表；空 → 说清是「被收起」还是「真没有」。 */
  function groupBody(items: RuleItem[], hidden: number) {
    if (!items.length) {
      if (hidden > 0) {
        return (
          <div className="pl-5">
            <EmptyState
              size="compact"
              tone="muted"
              title={`${hidden} 条规则已停用，当前已收起`}
              hint="勾选上方「显示已停用」可查看停用原因并重新启用"
            />
          </div>
        );
      }
      return (
        <div className="pl-5">
          <EmptyState
            size="compact"
            title={emptyOrFailed(errs, SRC.list, "这一组还没有规则")}
            hint="内置规则不满足现场口径时，新建一条自己的检测条件"
            tone={errs.isFailed(SRC.list) ? "danger" : "muted"}
            action={
              <Button size="sm" onClick={openCreate}>
                新建规则
              </Button>
            }
          />
        </div>
      );
    }
    return (
      <>
        <div className="pl-5">{leafHeader()}</div>
        <TreeChildren>
          {items.map((r, i) => leafRow(r, i === items.length - 1))}
        </TreeChildren>
      </>
    );
  }

  /** 分组右端的聚合信息。搜索时切换口径（命中 n / 共 total），否则用户会以为"这一组只有 3 条"。 */
  function groupCount(n: number, total: number, hidden: number, hitDisabledInGroup: number) {
    return (
      <span className="ml-auto flex shrink-0 items-center gap-3 pl-3 text-xs tabular-nums text-muted-foreground">
        {needle ? (
          <>
            <span>
              命中 <span className="text-foreground">{n}</span> / 共 {total} 条
            </span>
            {hitDisabledInGroup > 0 ? (
              <span className="text-sev-medium-fg">停用 {hitDisabledInGroup}</span>
            ) : null}
          </>
        ) : (
          <>
            <span>{n} 条</span>
            {/* 停止数用文字不用 Badge：8 个节点行每行挂 2 个 Badge 会把树读成表格 */}
            {hidden > 0 ? <span className="text-muted-foreground/70">停用 {hidden}</span> : null}
          </>
        )}
      </span>
    );
  }

  return (
    <PageShell title="检测规则" width="full">
      <div className="space-y-4">
        {msg && (
          <p
            role={msgErr ? "alert" : "status"}
            className={msgErr ? "text-sm text-sev-critical-fg" : "text-sm text-primary"}
          >
            {msg}
          </p>
        )}
        <PanelError errors={errs} />

        {/* 树型结构：顶层是「检测规则」，子节点按事件来源三类 + 签名规则集（引擎规则文件）。
            整棵树装在一张 Card 里：树的行要 hover 高亮（bg-brand-50），行必须落在
            surface-2（白）上才看得见；落在 canvas 上时 bg-brand-50 比它更亮，
            「高亮」会变成「变白」，层级倒挂。 */}
        <Section
          title="规则来源"
          description="按来源分组：特征匹配 / 行为分析 / 基线偏离。默认只列生效中的规则，停用的收在开关里。"
        >
          <Card>
            <PanelToolbar
              search={
                <div className="relative w-full">
                  <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={q}
                    onChange={(e) => {
                      // 改任意一个字符就把「搜索期显式收起」擦掉：清空后要回到 expanded 语义
                      collapsed.current.clear();
                      setQ(e.target.value);
                    }}
                    onKeyDown={(e) => {
                      // 输入框内按 Esc 清空是跨平台通用预期；本页 Esc 不与任何弹层冲突
                      if (e.key === "Escape" && q) {
                        e.preventDefault();
                        collapsed.current.clear();
                        setQ("");
                      }
                    }}
                    placeholder="搜索规则名称 / 描述 / ID"
                    aria-label="搜索规则"
                    aria-describedby="rules-search-count"
                    autoComplete="off"
                    spellCheck={false}
                    className="h-8 pl-7 text-13"
                  />
                </div>
              }
            >
              <Button size="sm" variant="outline" onClick={() => setAll(true)}>
                <ChevronsDownUp className="mr-1 h-3.5 w-3.5" />
                全部展开
              </Button>
              <Button size="sm" variant="outline" onClick={() => setAll(false)}>
                <ChevronsUpDown className="mr-1 h-3.5 w-3.5" />
                全部收起
              </Button>
              {disabledRules.length > 0 ? (
                <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <Switch
                    size="sm"
                    checked={showDisabled}
                    onCheckedChange={setShowDisabled}
                    label="显示已停用"
                    title="显示已停用"
                  />
                  显示已停用（<span className="tabular-nums">{disabledRules.length}</span>）
                </label>
              ) : null}
              <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
                刷新
              </Button>
              <Button size="sm" onClick={openCreate}>
                新建规则
              </Button>
            </PanelToolbar>

            {/* 结果计数条：紧贴树上方而不是塞进工具栏 —— 计数是被计数对象的属性。
                不加 aria-live：每次按键都播报会很吵；改成挂在搜索框的 aria-describedby 上，
                只在聚焦搜索框时读一次。
                分母用 rules.length（全量）：shown 随「显示已停用」变化，分母必须稳定。 */}
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
                  onClick={() => {
                    collapsed.current.clear();
                    setQ("");
                  }}
                  className="ml-auto rounded-sm text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
                >
                  清空搜索
                </button>
              </div>
            ) : null}

            {loading && !errs.has ? (
              <TreeSkeleton rootRows={1} groupRows={3} leafRows={5} lastGroupTall={false} />
            ) : errs.isFailed(SRC.list) && !rules.length ? (
              <div className="px-3 py-2">
                <EmptyState
                  size="compact"
                  tone="danger"
                  title="检测规则读取失败（见上方错误条）"
                  hint="后端异常或网络不通，不是「没有规则」"
                  action={
                    <Button size="sm" variant="outline" onClick={() => void load()}>
                      重新读取
                    </Button>
                  }
                />
              </div>
            ) : !showRoot ? (
              /* 0 命中：整棵树让位给一条空态，不渲染 L1/L2 空壳 */
              <div className="px-3 py-2">
                <EmptyState
                  size="compact"
                  tone="muted"
                  title={`没有匹配「${q}」的规则`}
                  hint="只匹配规则名称、描述与 ID；已停用的规则也会参与匹配。"
                  action={
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        collapsed.current.clear();
                        setQ("");
                      }}
                    >
                      清空搜索
                    </Button>
                  }
                />
              </div>
            ) : (
              <ul className="p-2">
                <li>
                  <button
                    type="button"
                    id="tree-root"
                    aria-expanded={rootOpen}
                    aria-controls="tree-root-children"
                    className={cn(
                      "flex h-11 w-full items-center gap-2 rounded-sm px-2 text-left transition-colors",
                      "hover:bg-brand-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
                    )}
                    onClick={() => toggleNode("root")}
                  >
                    <Radio className="h-4 w-4 shrink-0 text-muted-foreground" />
                    <TreeChevron open={rootOpen} />
                    <span className="truncate text-sm font-medium text-foreground">
                      检测规则
                    </span>
                    {/* 左读语义、右读数量 —— 和表格的列约定一致，不需要重新学习 */}
                    <span className="ml-auto shrink-0 pl-3 text-xs tabular-nums text-muted-foreground">
                      {rules.filter((r) => r.enabled).length} / {rules.length}
                    </span>
                  </button>

                  <TreeChildren id="tree-root-children" className={!rootOpen ? "hidden" : undefined}>
                    {rootOpen ? (
                      <>
                        {/* 三个来源分组：map 出来而不是手写三份 —— 分组口径来自契约，
                            顺序/键名/标签只此一处定义（KIND_GROUPS）。
                            全部 last={false}：签名规则集节点永远排在它们后面，
                            树干必须穿过每组通到最后一个节点（末行才收线）。 */}
                        {groups.map((g) =>
                          showGroup(g.key) ? (
                            <TreeRow key={g.key} last={false} mid={20}>
                              <button
                                type="button"
                                id={`tree-${g.key}`}
                                aria-expanded={groupOpen(g.key)}
                                aria-controls={`tree-${g.key}-children`}
                                title={g.hint}
                                className={cn(
                                  "flex h-10 w-full items-center gap-2 rounded-sm px-2 text-left transition-colors",
                                  "hover:bg-brand-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
                                )}
                                onClick={() => toggleNode(g.key)}
                              >
                                <TreeChevron open={groupOpen(g.key)} />
                                <span className="truncate text-13 font-medium text-foreground">
                                  {g.label}
                                </span>
                                {groupCount(g.items.length, g.total, g.hidden, g.hitDisabled)}
                              </button>
                              <div
                                id={`tree-${g.key}-children`}
                                className={!groupOpen(g.key) ? "hidden" : undefined}
                              >
                                {groupOpen(g.key)
                                  ? groupBody(g.items, needle ? 0 : g.hidden)
                                  : null}
                              </div>
                            </TreeRow>
                          ) : null,
                        )}

                        {/* 签名规则集：不是规则列表，没有可匹配的叶子，所以不受 needle 的展开覆盖；
                            展开时才 mount 面板并首次请求 /api/suricata/rules（按需加载）。 */}
                        <TreeRow last mid={20}>
                          <button
                            type="button"
                            id="tree-signature"
                            aria-expanded={isSignatureOpen}
                            aria-controls="tree-signature-children"
                            className={cn(
                              "flex h-10 w-full items-center gap-2 rounded-sm px-2 text-left transition-colors",
                              "hover:bg-brand-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
                            )}
                            onClick={() => toggleNode("signature")}
                          >
                            <TreeChevron open={isSignatureOpen} />
                            <span className="truncate text-13 font-medium text-foreground">
                              签名规则集
                            </span>
                            <span className="ml-auto shrink-0 pl-3 text-xs text-muted-foreground">
                              规则文件由开发人员维护：在线 manifest（文件列表 + sha256）更新，
                              校验通过后人工确认才生效
                            </span>
                          </button>
                          <div
                            id="tree-signature-children"
                            className={cn("pl-5", !isSignatureOpen && "hidden")}
                          >
                            {isSignatureOpen ? <SuricataRulesPanel variant="inline" /> : null}
                          </div>
                        </TreeRow>
                      </>
                    ) : null}
                  </TreeChildren>
                </li>
              </ul>
            )}
          </Card>
        </Section>

        {/* 删除确认：标题带对象名，正文只写后果（「不可撤销」在按钮上体现为 destructive） */}
        <Dialog
          open={!!askDel}
          title={askDel ? `删除自定义规则「${askDel.name}」？` : ""}
          onClose={() => setAskDel(null)}
          footer={
            <div className="flex items-center justify-end gap-2">
              <Button size="sm" variant="outline" onClick={() => setAskDel(null)}>
                取消
              </Button>
              <Button
                size="sm"
                variant="destructive"
                disabled={!!busy}
                onClick={() => {
                  if (askDel) void remove(askDel);
                }}
              >
                删除
              </Button>
            </div>
          }
        >
          <p className="text-13 leading-relaxed text-muted-foreground">
            这条规则会从检测链路上移除，之后新到的事件不再按它判定。已产生的事件与判定结果不受影响。
          </p>
        </Dialog>

        <Drawer
          open={drawer}
          title={editId ? "编辑自定义规则" : "添加自定义规则"}
          onClose={() => setDrawer(false)}
          footer={
            <div className="flex items-center gap-2">
              <Button size="sm" onClick={() => void save()}>
                {editId ? "保存修改" : "添加"}
              </Button>
              <Button size="sm" variant="outline" onClick={() => setDrawer(false)}>
                取消
              </Button>
            </div>
          }
        >
          <div className="space-y-4">
            {msg && (
              <p className={msgErr ? "text-xs text-sev-critical-fg" : "text-xs text-primary"}>{msg}</p>
            )}

            {/* 表单按「填什么 → 匹配什么 → 判成什么」分三段，避免一路竖着堆控件 */}
            <fieldset className="space-y-3">
              <legend className="mb-2 w-full border-b border-border-subtle pb-1 text-xs font-medium text-foreground">
                基本信息
              </legend>
              <FieldGrid maxCols={2}>
                <Field label="规则 ID（自动生成，不可编辑）" htmlFor="rule-id">
                  <Input
                    id="rule-id"
                    value={editId || "（保存后自动生成）"}
                    readOnly
                    disabled
                    className="font-mono text-xs"
                  />
                </Field>
                <Field label="规则名称" required>
                  <Input
                    id="rule-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="例如：内网可疑账号登录"
                  />
                </Field>
                <Field label="描述（可选）" span="full">
                  <Input
                    id="rule-desc"
                    value={desc}
                    onChange={(e) => setDesc(e.target.value)}
                    placeholder="这条规则是干什么的"
                  />
                </Field>
              </FieldGrid>
            </fieldset>

            <fieldset className="space-y-3">
              <legend className="mb-2 w-full border-b border-border-subtle pb-1 text-xs font-medium text-foreground">
                匹配条件
              </legend>
              <ConditionEditor
                fields={RULE_FIELDS}
                conds={conds}
                logic={logic}
                onLogic={setLogic}
                onChange={setCond}
                onRemove={(i) => setConds((cs) => cs.filter((_, idx) => idx !== i))}
                onAdd={() => setConds((cs) => [...cs, { field: "dst_port", op: "in", value: "" }])}
              />

              <div className="flex flex-wrap items-end gap-3 rounded-xs bg-surface-1 px-3 py-2">
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="h-4 w-4 accent-brand-500"
                    checked={mode === "count"}
                    onChange={(e) => setMode(e.target.checked ? "count" : "single")}
                  />
                  频率规则（同源在窗口内达到次数才告警）
                </label>
                {mode === "count" && (
                  <FieldGrid maxCols={2} className="w-full">
                    <Field label="分组键（逗号分隔）" htmlFor="rule-keys">
                      <Input
                        id="rule-keys"
                        value={keys}
                        onChange={(e) => setKeys(e.target.value)}
                      />
                    </Field>
                    <Field label="最少次数" htmlFor="rule-min-count">
                      <Input
                        id="rule-min-count"
                        className="tabular-nums"
                        value={minCount}
                        onChange={(e) => setMinCount(e.target.value)}
                      />
                    </Field>
                    <Field label="去重字段（可选）" htmlFor="rule-distinct">
                      <Input
                        id="rule-distinct"
                        value={distinct}
                        onChange={(e) => setDistinct(e.target.value)}
                      />
                    </Field>
                    <Field label="最少去重数" htmlFor="rule-min-distinct">
                      <Input
                        id="rule-min-distinct"
                        className="tabular-nums"
                        value={minDistinct}
                        onChange={(e) => setMinDistinct(e.target.value)}
                      />
                    </Field>
                  </FieldGrid>
                )}
              </div>
            </fieldset>

            <fieldset className="space-y-3">
              <legend className="mb-2 w-full border-b border-border-subtle pb-1 text-xs font-medium text-foreground">
                动作
              </legend>
              <FieldGrid maxCols={2}>
                <Field label="级别" htmlFor="rule-sev">
                  <select
                    id="rule-sev"
                    className={SELECT_CLS}
                    value={sev}
                    onChange={(e) => setSev(e.target.value)}
                  >
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                    <option value="info">信息</option>
                  </select>
                </Field>
                <Field label="优先级（越小越先）" htmlFor="rule-priority">
                  <Input
                    id="rule-priority"
                    className="tabular-nums"
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                  />
                </Field>
                <Field label="状态">
                  <label className="flex h-9 items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-brand-500"
                      checked={enabled}
                      onChange={(e) => setEnabled(e.target.checked)}
                    />
                    启用
                  </label>
                </Field>
              </FieldGrid>
            </fieldset>
          </div>
        </Drawer>
      </div>
    </PageShell>
  );
}
