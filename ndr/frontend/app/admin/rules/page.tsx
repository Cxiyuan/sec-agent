"use client";

import * as React from "react";
import { PageShell } from "@/components/page-shell";
import {
  Badge,
  Button,
  Dialog,
  Drawer,
  EmptyState,
  Input,
  Section,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
  ApiError,
  apiFetch,
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

/**
 * 检测规则页：树型展开/收缩（网络采集器 → 内置规则 / 自定义规则 / 签名规则）。
 *
 * 规则只有网络一侧：条件引用网络侧字段（http/ssl/dns/conn…）与签名引擎告警，
 * 检测器只在网络事件上求值。主机监控那条线已随对应日志源一起下线。
 */

const SRC = { list: "检测规则（/api/rules）" } as const;

function ruleType(r: RuleItem): string {
  const c = (r.conditions || {}) as { mode?: string; key?: string[]; min_count?: number; distinct?: string; min_distinct?: number };
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

/** 树节点：可展开/收缩的容器（顶层是 网络/主机 两个分类，子节点是规则来源）。 */
function TreeNode(props: {
  id: string;
  title: string;
  hint?: string;
  count?: number;
  action?: React.ReactNode;
  expanded: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <div data-node={props.id}>
      <div className="flex flex-wrap items-center gap-2 rounded-sm border border-border-subtle bg-surface-1 px-3 py-2">
        <button
          type="button"
          className="flex items-center gap-2 text-left"
          onClick={props.onToggle}
          aria-expanded={props.expanded}
          title={props.expanded ? "点击收起" : "点击展开"}
        >
          <span aria-hidden className="text-xs text-muted-foreground">
            {props.expanded ? "▾" : "▸"}
          </span>
          <span className="text-13 font-medium text-foreground">{props.title}</span>
          {typeof props.count === "number" && (
            <Badge variant="outline" className="tabular-nums">
              {props.count} 条
            </Badge>
          )}
        </button>
        {props.hint && (
          <span className="text-xs font-normal text-muted-foreground">{props.hint}</span>
        )}
        {props.action}
      </div>
      {props.expanded && (
        <div className="mt-2 border-l border-border-subtle pl-4">{props.children}</div>
      )}
    </div>
  );
}

export default function RulesPage() {
  const errs = usePanelErrors();
  const [rules, setRules] = React.useState<RuleItem[]>([]);
  const [expanded, setExpanded] = React.useState<Record<string, boolean>>({
    network: true,
    "network:builtin": true,
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

  // 树的展开状态记到浏览器本地：切页/刷新后保持原样（读不到就用默认值，不影响功能）
  React.useEffect(() => {
    try {
      const raw = window.localStorage.getItem("shentong.rules.tree");
      if (raw) {
        const saved = JSON.parse(raw) as Record<string, boolean>;
        setExpanded((prev) => ({ ...prev, ...saved }));
      }
    } catch {
      /* 隐私模式/存储不可用：用默认展开状态 */
    }
  }, []);

  function toggleNode(id: string) {
    setExpanded((prev) => {
      const next = { ...prev, [id]: !prev[id] };
      try {
        window.localStorage.setItem("shentong.rules.tree", JSON.stringify(next));
      } catch {
        /* 存不了就算了，只是不记忆 */
      }
      return next;
    });
  }

  const disabledRules = rules.filter((r) => !r.enabled);
  const shown = showDisabled ? rules : rules.filter((r) => r.enabled);
  const builtin = shown.filter((r) => r.source === "builtin");
  const custom = shown.filter((r) => r.source !== "builtin");
  // 规则只有网络一侧（主机监控线已下线）
  const netBuiltin = builtin;
  const netCustom = custom;
  // 分组各自的「被收起条数」：用来把空态说清楚是被收起还是真没有
  const hiddenBuiltin = showDisabled ? 0 : disabledRules.filter((r) => r.source === "builtin").length;
  const hiddenCustom = showDisabled ? 0 : disabledRules.filter((r) => r.source !== "builtin").length;

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
    const c = (r.conditions || {}) as { mode?: string; key?: string[]; min_count?: number; distinct?: string; min_distinct?: number };
    setEditId(r.id);
    setName(r.name);
    setDesc(r.description || "");
    setSev(r.severity);
    setPriority(String(r.priority));
    setEnabled(r.enabled);
    setLogic(String((r.conditions || {}).logic || "and"));
    setConds(
      (((r.conditions || {}) as { rules?: Array<{ field?: string; op?: string; value?: unknown }> }).rules || []).map(
        (x) => ({
          field: String(x.field || ""),
          op: String(x.op || "eq"),
          value: Array.isArray(x.value) ? x.value.join(",") : String(x.value ?? ""),
        }),
      ),
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

  /** 勾选启用/禁用：内置规则只有 enabled 会保留（描述/条件/级别/优先级每次启动被内置定义覆盖）。 */
  async function toggle(r: RuleItem) {
    setBusy(r.id);
    setMsg("");
    setMsgErr(false);
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
      setMsg(`已${r.enabled ? "禁用" : "启用"}「${r.name}」`);
      await load();
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
        setMsg(`已添加「${created?.name || name.trim()}」（ID ${String(created?.id || "").slice(0, 8)}… 自动生成）`);
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
      await load();
    } catch (e) {
      setMsgErr(true);
      setMsg(e instanceof ApiError ? errorText(e.body) : "删除失败");
    } finally {
      setBusy("");
      setAskDel(null);
    }
  }

  /** 内置规则表（不含外层卡片：树节点自己就是容器）。 */
  function builtinTable(items: RuleItem[], hidden: number) {
    // 首次加载画骨架：接口还没回来就显示「这一组还没有规则」，会被当成规则丢了
    if (loading) return <TableSkeleton rows={5} cols={5} />;
    if (!items.length) {
      // 有规则、只是全被「显示已停用」收起来了：不能报「还没有规则」
      if (hidden > 0) {
        return (
          <EmptyState
            size="compact"
            tone="muted"
            title={`${hidden} 条内置规则已停用，当前已收起`}
            hint="勾选上方「显示已停用」可查看停用原因并重新启用"
          />
        );
      }
      return (
        <EmptyState
          size="compact"
          title={emptyOrFailed(errs, SRC.list, "这一组还没有规则")}
          tone={errs.isFailed(SRC.list) ? "danger" : "muted"}
        />
      );
    }
    return (
      <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">启用</TableHead>
                <TableHead>规则</TableHead>
                <TableHead className="w-40">类型</TableHead>
                <TableHead className="w-20">级别</TableHead>
                <TableHead className="w-20 text-right">优先级</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((r) => (
                <React.Fragment key={r.id}>
                  <TableRow>
                    <TableCell>
                      <input
                        type="checkbox"
                        className="h-4 w-4 accent-brand-500"
                        checked={r.enabled}
                        disabled={busy === r.id}
                        onChange={() => void toggle(r)}
                        aria-label={`${r.enabled ? "禁用" : "启用"}规则 ${r.name}`}
                        title={r.enabled ? "勾选=启用（取消勾选即禁用）" : "勾选即启用"}
                      />
                    </TableCell>
                    <TableCell>
                      <button
                        type="button"
                        className="flex w-full items-start gap-2 text-left"
                        onClick={() => setOpenIds((m) => ({ ...m, [r.id]: !m[r.id] }))}
                        aria-expanded={!!openIds[r.id]}
                      >
                        <span aria-hidden className="mt-0.5 text-xs text-muted-foreground">
                          {openIds[r.id] ? "▾" : "▸"}
                        </span>
                        <span>
                          <span className={r.enabled ? "font-medium text-foreground" : "font-medium text-muted-foreground line-through"}>
                            {r.name}
                          </span>
                          <span className="ml-2 text-xs text-muted-foreground">
                            {(r.description || "").slice(0, 60)}
                          </span>
                        </span>
                      </button>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{ruleType(r)}</TableCell>
                    <TableCell>{severityBadge(r.severity)}</TableCell>
                    <TableCell className="text-right tabular-nums">{r.priority}</TableCell>
                  </TableRow>
                  {openIds[r.id] && (
                    <TableRow key={`${r.id}-detail`}>
                      <TableCell />
                      <TableCell colSpan={4} className="bg-surface-1">
                        <p className="mb-1 text-xs text-muted-foreground">
                          规则 ID <span className="font-mono">{r.id}</span>（内置规则：描述/条件/级别/优先级
                          每次启动会被内置定义覆盖，<b className="font-medium text-foreground">只有启用状态会保留</b>）
                        </p>
                        <p className="mb-1 text-xs">{r.description || "（无描述）"}</p>
                        <pre className="max-h-56 overflow-auto rounded-sm border border-border-subtle bg-surface-2 p-2 font-mono text-xs leading-4">
                          {JSON.stringify(r.conditions || {}, null, 2)}
                        </pre>
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              ))}
            </TableBody>
          </Table>
    );
  }

  /** 自定义规则表（同样不含外层卡片）；「添加规则」按钮在区块标题行上。 */
  function customTable(items: RuleItem[], hidden: number) {
    if (loading) return <TableSkeleton rows={5} cols={6} />;
    if (!items.length) {
      // 有规则、只是全被「显示已停用」收起来了
      if (hidden > 0) {
        return (
          <EmptyState
            size="compact"
            tone="muted"
            title={`${hidden} 条自定义规则已停用，当前已收起`}
            hint="勾选上方「显示已停用」可以查看并重新启用"
          />
        );
      }
      return (
        <EmptyState
          size="compact"
          title={emptyOrFailed(errs, SRC.list, "这一组还没有自定义规则")}
          hint="内置规则不满足现场口径时，新建一条自己的检测条件"
          tone={errs.isFailed(SRC.list) ? "danger" : "muted"}
          action={
            <Button size="sm" onClick={openCreate}>
              新建规则
            </Button>
          }
        />
      );
    }
    return (
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>名称</TableHead>
            <TableHead className="w-40">类型</TableHead>
            <TableHead className="w-20">级别</TableHead>
            <TableHead className="w-20 text-right">优先级</TableHead>
            <TableHead className="w-20">状态</TableHead>
            <TableHead className="w-32">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((r) => (
            <TableRow key={r.id}>
              <TableCell>
                <span className="font-medium text-foreground">{r.name}</span>
                <span className="ml-2 text-xs text-muted-foreground">
                  {(r.description || "").slice(0, 50)}
                </span>
              </TableCell>
              <TableCell className="text-muted-foreground">{ruleType(r)}</TableCell>
              <TableCell>{severityBadge(r.severity)}</TableCell>
              <TableCell className="text-right tabular-nums">{r.priority}</TableCell>
              <TableCell>
                <Badge variant={r.enabled ? "success" : "medium"}>
                  {r.enabled ? "启用" : "禁用"}
                </Badge>
              </TableCell>
              <TableCell>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" disabled={busy === r.id} onClick={() => openEdit(r)}>
                    编辑
                  </Button>
                  {/* 删除是不可逆操作：独立用 destructive，和「编辑」不在同一层级 */}
                  <Button size="sm" variant="destructive" disabled={busy === r.id} onClick={() => setAskDel(r)}>
                    删除
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  }

  return (
    <PageShell title="检测规则" fluid>
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

        {/* 树型结构：顶层按 网络/主机 分类，子节点是规则来源。
            签名规则（Suricata）归网络类 —— 它只看网络流量，与内置/自定义规则并列。 */}
        <Section
          title="规则来源"
          description="按来源分组：内置定义 / 自建规则 / 签名文件。默认只列生效中的规则，停用的收在开关里。"
          extra={
            <>
              {/* 停用规则默认收起；有停用规则时才出现开关，没有就不占位置 */}
              {disabledRules.length > 0 ? (
                <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 accent-brand-500"
                    checked={showDisabled}
                    onChange={(e) => setShowDisabled(e.target.checked)}
                  />
                  显示已停用（<span className="tabular-nums">{disabledRules.length}</span>）
                </label>
              ) : null}
              <Button size="sm" variant="outline" onClick={() => void load()}>
                刷新
              </Button>
              <Button size="sm" onClick={openCreate}>
                新建规则
              </Button>
            </>
          }
        >
          <div className="space-y-2">
            <TreeNode
              id="network"
              title="网络（网络采集器）"
              hint="规则条件引用网络侧字段（http/ssl/dns/conn…）—— 检测器只在网络事件上求值"
              count={netBuiltin.length + netCustom.length}
              expanded={!!expanded.network}
              onToggle={() => toggleNode("network")}
            >
              <div className="space-y-3">
                <TreeNode
                  id="network:builtin"
                  title="内置规则"
                  hint="版本内置定义；只有启用状态会保留（描述/条件/级别/优先级每次启动被内置定义覆盖）"
                  count={netBuiltin.length}
                  expanded={!!expanded["network:builtin"]}
                  onToggle={() => toggleNode("network:builtin")}
                >
                  {builtinTable(netBuiltin, hiddenBuiltin)}
                </TreeNode>

                <TreeNode
                  id="network:custom"
                  title="自定义规则"
                  hint="自己添加/修改的规则；ID 自动生成、不可编辑"
                  count={netCustom.length}
                  expanded={!!expanded["network:custom"]}
                  onToggle={() => toggleNode("network:custom")}
                >
                  {customTable(netCustom, hiddenCustom)}
                </TreeNode>

                <TreeNode
                  id="network:signature"
                  title="签名规则（Suricata）"
                  hint="规则文件由开发人员维护：在线 manifest（文件列表 + sha256）更新，校验通过后人工确认才生效"
                  expanded={!!expanded["network:signature"]}
                  onToggle={() => toggleNode("network:signature")}
                >
                  <SuricataRulesPanel />
                </TreeNode>
              </div>
            </TreeNode>
          </div>
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
              <div>
                <label htmlFor="rule-id" className="mb-1 block text-xs text-muted-foreground">
                  规则 ID（自动生成，不可编辑）
                </label>
                <Input
                  id="rule-id"
                  value={editId || "（保存后自动生成）"}
                  readOnly
                  disabled
                  className="font-mono text-xs"
                />
              </div>
              <div>
                <label htmlFor="rule-name" className="mb-1 block text-xs text-muted-foreground">
                  规则名称
                </label>
                <Input
                  id="rule-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="例如：内网可疑账号登录"
                />
              </div>
              <div>
                <label htmlFor="rule-desc" className="mb-1 block text-xs text-muted-foreground">
                  描述（可选）
                </label>
                <Input
                  id="rule-desc"
                  value={desc}
                  onChange={(e) => setDesc(e.target.value)}
                  placeholder="这条规则是干什么的"
                />
              </div>
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
                  <>
                    <div>
                      <label htmlFor="rule-keys" className="mb-1 block text-xs text-muted-foreground">
                        分组键（逗号分隔）
                      </label>
                      <Input id="rule-keys" className="w-40" value={keys} onChange={(e) => setKeys(e.target.value)} />
                    </div>
                    <div>
                      <label htmlFor="rule-min-count" className="mb-1 block text-xs text-muted-foreground">
                        最少次数
                      </label>
                      <Input
                        id="rule-min-count"
                        className="w-24 tabular-nums"
                        value={minCount}
                        onChange={(e) => setMinCount(e.target.value)}
                      />
                    </div>
                    <div>
                      <label htmlFor="rule-distinct" className="mb-1 block text-xs text-muted-foreground">
                        去重字段（可选）
                      </label>
                      <Input
                        id="rule-distinct"
                        className="w-32"
                        value={distinct}
                        onChange={(e) => setDistinct(e.target.value)}
                      />
                    </div>
                    <div>
                      <label htmlFor="rule-min-distinct" className="mb-1 block text-xs text-muted-foreground">
                        最少去重数
                      </label>
                      <Input
                        id="rule-min-distinct"
                        className="w-24 tabular-nums"
                        value={minDistinct}
                        onChange={(e) => setMinDistinct(e.target.value)}
                      />
                    </div>
                  </>
                )}
              </div>
            </fieldset>

            <fieldset className="space-y-3">
              <legend className="mb-2 w-full border-b border-border-subtle pb-1 text-xs font-medium text-foreground">
                动作
              </legend>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label htmlFor="rule-sev" className="mb-1 block text-xs text-muted-foreground">
                    级别
                  </label>
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
                </div>
                <div>
                  <label htmlFor="rule-priority" className="mb-1 block text-xs text-muted-foreground">
                    优先级（越小越先）
                  </label>
                  <Input
                    id="rule-priority"
                    className="tabular-nums"
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                  />
                </div>
                <div>
                  <span className="mb-1 block text-xs text-muted-foreground">状态</span>
                  <label className="flex h-9 items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-brand-500"
                      checked={enabled}
                      onChange={(e) => setEnabled(e.target.checked)}
                    />
                    启用
                  </label>
                </div>
              </div>
            </fieldset>
          </div>
        </Drawer>
      </div>
    </PageShell>
  );
}
