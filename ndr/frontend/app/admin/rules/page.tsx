"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { TopBar } from "@/components/topbar";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Drawer,
  Input,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  ApiError,
  apiFetch,
  errorText,
} from "@shentong/ui";

import type { RuleItem } from "@/lib/api";
import { PanelError, emptyOrFailed, loadInto, usePanelErrors } from "@/components/panel-error";
import {
  ConditionEditor,
  RULE_FIELDS,
  SELECT_CLS,
  condsToRules,
  type Cond,
} from "@/components/condition-editor";

/**
 * 检测规则页：内置规则（按 网络/主机 两组，可展开、可勾选启停）+ 自定义规则（可增改删）。
 *
 * 「网络」= 网络采集器（Zeek 事件），「主机」= 主机监控（Wazuh 事件）—— 这个划分由后端
 * `rules/builtin.py::rule_scope()` 按规则条件自动判定并存在 `Rule.scope` 上；检测器也按它过滤
 * （主机规则只在主机事件上求值，反之亦然）。界面上分组就是读这个字段，不做二次猜测。
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

function scopedLabel(scope: string): string {
  return scope === "host" ? "主机" : "网络";
}

function severityBadge(sev: string): React.ReactElement {
  const map: Record<string, { variant: "critical" | "medium" | "low" | "outline"; text: string }> = {
    critical: { variant: "critical", text: "紧急" },
    high: { variant: "critical", text: "高危" },
    medium: { variant: "medium", text: "中危" },
    low: { variant: "low", text: "低危" },
    info: { variant: "outline", text: "提示" },
  };
  const it = map[sev] || { variant: "outline" as const, text: sev || "-" };
  return <Badge variant={it.variant}>{it.text}</Badge>;
}

export default function RulesPage() {
  const errs = usePanelErrors();
  const [rules, setRules] = React.useState<RuleItem[]>([]);
  const [tab, setTab] = React.useState<"builtin" | "custom">("builtin");
  const [openIds, setOpenIds] = React.useState<Record<string, boolean>>({});
  const [busy, setBusy] = React.useState("");
  const [msg, setMsg] = React.useState("");

  // 自定义规则表单（抽屉）：editId 为空 = 新增
  const [drawer, setDrawer] = React.useState(false);
  const [editId, setEditId] = React.useState("");
  const [name, setName] = React.useState("");
  const [desc, setDesc] = React.useState("");
  const [scope, setScope] = React.useState("network");
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
  }

  React.useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const builtin = rules.filter((r) => r.source === "builtin");
  const custom = rules.filter((r) => r.source !== "builtin");
  const netBuiltin = builtin.filter((r) => (r.scope || "network") !== "host");
  const hostBuiltin = builtin.filter((r) => (r.scope || "network") === "host");

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
    setScope("network");
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
    setDrawer(true);
  }

  function openEdit(r: RuleItem) {
    const c = (r.conditions || {}) as { mode?: string; key?: string[]; min_count?: number; distinct?: string; min_distinct?: number };
    setEditId(r.id);
    setName(r.name);
    setDesc(r.description || "");
    setScope(r.scope || "network");
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
    setDrawer(true);
  }

  /** 勾选启用/禁用：内置规则只有 enabled 会保留（描述/条件/级别/优先级每次启动被内置定义覆盖）。 */
  async function toggle(r: RuleItem) {
    setBusy(r.id);
    setMsg("");
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
          scope: r.scope || "network",
        }),
      });
      setMsg(`已${r.enabled ? "禁用" : "启用"}「${r.name}」`);
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "更新失败");
    } finally {
      setBusy("");
    }
  }

  async function save() {
    setMsg("");
    if (!name.trim()) {
      setMsg("请填写规则名称");
      return;
    }
    if (conds.filter((c) => c.field && c.op).length === 0) {
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
      scope,
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
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    }
  }

  async function remove(r: RuleItem) {
    if (!window.confirm(`删除自定义规则「${r.name}」？`)) return;
    setBusy(r.id);
    try {
      await apiFetch(`/api/rules/${r.id}`, { method: "DELETE" });
      setMsg(`已删除「${r.name}」`);
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "删除失败");
    } finally {
      setBusy("");
    }
  }

  function builtinGroup(title: string, hint: string, items: RuleItem[]) {
    return (
      <Card className="mb-4">
        <CardHeader className="pb-2">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            {title}
            <Badge variant="outline">{items.length} 条</Badge>
            <span className="text-xs font-normal text-muted-foreground">{hint}</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">启用</TableHead>
                <TableHead>规则</TableHead>
                <TableHead className="w-40">类型</TableHead>
                <TableHead className="w-20">级别</TableHead>
                <TableHead className="w-20">优先级</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((r) => (
                <React.Fragment key={r.id}>
                  <TableRow>
                    <TableCell>
                      <input
                        type="checkbox"
                        className="h-4 w-4 accent-current"
                        checked={r.enabled}
                        disabled={busy === r.id}
                        onChange={() => void toggle(r)}
                        title={r.enabled ? "勾选=启用（取消勾选即禁用）" : "勾选即启用"}
                      />
                    </TableCell>
                    <TableCell>
                      <button
                        type="button"
                        className="flex w-full items-start gap-2 text-left"
                        onClick={() => setOpenIds((m) => ({ ...m, [r.id]: !m[r.id] }))}
                      >
                        <span className="mt-0.5 text-xs text-muted-foreground">
                          {openIds[r.id] ? "▾" : "▸"}
                        </span>
                        <span>
                          <span className={r.enabled ? "text-sm font-medium" : "text-sm font-medium text-muted-foreground line-through"}>
                            {r.name}
                          </span>
                          <span className="ml-2 text-xs text-muted-foreground">
                            {(r.description || "").slice(0, 60)}
                          </span>
                        </span>
                      </button>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{ruleType(r)}</TableCell>
                    <TableCell>{severityBadge(r.severity)}</TableCell>
                    <TableCell className="text-xs">{r.priority}</TableCell>
                  </TableRow>
                  {openIds[r.id] && (
                    <TableRow key={`${r.id}-detail`}>
                      <TableCell />
                      <TableCell colSpan={4} className="bg-muted/30">
                        <p className="mb-1 text-xs text-muted-foreground">
                          规则 ID <span className="font-mono">{r.id}</span>（内置规则：描述/条件/级别/优先级
                          每次启动会被内置定义覆盖，**只有启用状态会保留**）
                        </p>
                        <p className="mb-1 text-xs">{r.description || "（无描述）"}</p>
                        <pre className="max-h-56 overflow-auto rounded-md border p-2 font-mono text-[11px] leading-4">
                          {JSON.stringify(r.conditions || {}, null, 2)}
                        </pre>
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              ))}
              {items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    这一组还没有规则
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="min-h-screen">
      <TopBar />
      <Nav />
      <main className="ml-56 px-6 pb-6 pt-20">
        <h1 className="mb-4 text-2xl font-bold">检测规则</h1>
        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}
        <div className="mb-3">
          <PanelError errors={errs} />
        </div>

        <div className="mb-4 flex items-center gap-2">
          <Button
            size="sm"
            variant={tab === "builtin" ? "default" : "outline"}
            onClick={() => setTab("builtin")}
          >
            内置规则（{builtin.length}）
          </Button>
          <Button
            size="sm"
            variant={tab === "custom" ? "default" : "outline"}
            onClick={() => setTab("custom")}
          >
            自定义规则（{custom.length}）
          </Button>
        </div>

        {tab === "builtin" ? (
          <>
            {builtinGroup(
              "网络（网络采集器）",
              "规则条件引用网络侧字段（http/ssl/dns/conn…）—— 检测器只在网络事件上求值",
              netBuiltin,
            )}
            {builtinGroup(
              "主机（主机监控）",
              "规则条件引用主机侧字段（主机监控事件）—— 检测器只在主机事件上求值",
              hostBuiltin,
            )}
          </>
        ) : (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
                自定义规则
                <span className="text-xs font-normal text-muted-foreground">
                  自己添加/修改的规则；ID 自动生成，不可编辑。「规则内容」选网络或主机，决定它跑在哪一侧。
                </span>
                <Button size="sm" className="ml-auto" onClick={openCreate}>
                  添加规则
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>名称</TableHead>
                    <TableHead className="w-24">规则内容</TableHead>
                    <TableHead className="w-40">类型</TableHead>
                    <TableHead className="w-20">级别</TableHead>
                    <TableHead className="w-20">优先级</TableHead>
                    <TableHead className="w-20">状态</TableHead>
                    <TableHead className="w-32">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {custom.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell>
                        <span className="text-sm font-medium">{r.name}</span>
                        <span className="ml-2 text-xs text-muted-foreground">
                          {(r.description || "").slice(0, 50)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{scopedLabel(r.scope || "network")}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{ruleType(r)}</TableCell>
                      <TableCell>{severityBadge(r.severity)}</TableCell>
                      <TableCell className="text-xs">{r.priority}</TableCell>
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
                          <Button size="sm" variant="outline" disabled={busy === r.id} onClick={() => void remove(r)}>
                            删除
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {custom.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center text-muted-foreground">
                        {emptyOrFailed(errs, SRC.list, "还没有自定义规则，点右上「添加规则」新建一条")}
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}

        <Drawer
          open={drawer}
          title={editId ? "编辑自定义规则" : "添加自定义规则"}
          onClose={() => setDrawer(false)}
          footer={
            <div className="flex items-center gap-3">
              <Button onClick={() => void save()}>{editId ? "保存修改" : "添加"}</Button>
              <Button variant="outline" onClick={() => setDrawer(false)}>
                取消
              </Button>
            </div>
          }
        >
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                规则 ID（自动生成，不可编辑）
              </label>
              <Input value={editId || "（保存后自动生成）"} readOnly disabled className="font-mono text-xs" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">规则名称</label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="例如：内网可疑账号登录" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">描述（可选）</label>
              <Input value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="这条规则是干什么的" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">规则内容（跑在哪一侧）</label>
              <div className="flex items-center gap-4 text-sm">
                <label className="flex items-center gap-2">
                  <input type="radio" name="scope" checked={scope === "network"} onChange={() => setScope("network")} />
                  网络规则（网络采集器）
                </label>
                <label className="flex items-center gap-2">
                  <input type="radio" name="scope" checked={scope === "host"} onChange={() => setScope("host")} />
                  主机规则（主机监控）
                </label>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">级别</label>
                <select className={SELECT_CLS} value={sev} onChange={(e) => setSev(e.target.value)}>
                  <option value="critical">紧急</option>
                  <option value="high">高危</option>
                  <option value="medium">中危</option>
                  <option value="low">低危</option>
                  <option value="info">提示</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">优先级（越小越先）</label>
                <Input value={priority} onChange={(e) => setPriority(e.target.value)} />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">状态</label>
                <label className="flex h-9 items-center gap-2 text-sm">
                  <input type="checkbox" className="h-4 w-4" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                  启用
                </label>
              </div>
            </div>

            <ConditionEditor
              fields={RULE_FIELDS}
              conds={conds}
              logic={logic}
              onLogic={setLogic}
              onChange={setCond}
              onRemove={(i) => setConds((cs) => cs.filter((_, idx) => idx !== i))}
              onAdd={() => setConds((cs) => [...cs, { field: "dst_port", op: "in", value: "" }])}
            />

            <div className="flex flex-wrap items-end gap-3 rounded-md border p-3">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="h-4 w-4"
                  checked={mode === "count"}
                  onChange={(e) => setMode(e.target.checked ? "count" : "single")}
                />
                频率规则（同源在窗口内达到次数才告警）
              </label>
              {mode === "count" && (
                <>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">分组键（逗号分隔）</label>
                    <Input className="w-40" value={keys} onChange={(e) => setKeys(e.target.value)} />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">最少次数</label>
                    <Input className="w-24" value={minCount} onChange={(e) => setMinCount(e.target.value)} />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">去重字段（可选）</label>
                    <Input className="w-32" value={distinct} onChange={(e) => setDistinct(e.target.value)} />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">最少去重数</label>
                    <Input className="w-24" value={minDistinct} onChange={(e) => setMinDistinct(e.target.value)} />
                  </div>
                </>
              )}
            </div>
          </div>
        </Drawer>
      </main>
    </div>
  );
}
