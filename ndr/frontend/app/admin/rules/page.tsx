"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { TopBar } from "@/components/topbar";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@shentong/ui";
import { ApiError, apiFetch, errorText, type RuleItem } from "@/lib/api";
import { PanelError, emptyOrFailed, loadInto, usePanelErrors } from "@/components/panel-error";
import {
  ConditionEditor,
  RULE_FIELDS,
  SELECT_CLS,
  condsToRules,
  type Cond,
} from "@/components/condition-editor";

/** 读取失败的接口名（错误条用）。 */
const SRC = { list: "规则列表（/api/rules）" } as const;

function ruleType(r: RuleItem): string {
  const c = (r.conditions || {}) as { mode?: string; key?: string[]; min_count?: number };
  if (c.mode === "count") {
    return `频率（${(c.key || []).join("+") || "src_ip"} ≥ ${c.min_count ?? 1}）`;
  }
  return "逐条";
}

export default function RulesPage() {
  const errs = usePanelErrors();
  const [rules, setRules] = React.useState<RuleItem[]>([]);
  const [msg, setMsg] = React.useState("");
  const [deleting, setDeleting] = React.useState("");
  const [name, setName] = React.useState("");
  const [severity, setSeverity] = React.useState("medium");
  const [priority, setPriority] = React.useState("100");
  const [logic, setLogic] = React.useState("and");
  const [conds, setConds] = React.useState<Cond[]>([{ field: "event_type", op: "eq", value: "" }]);
  const [mode, setMode] = React.useState<"single" | "count">("single");
  const [keys, setKeys] = React.useState("src_ip");
  const [minCount, setMinCount] = React.useState("10");

  async function load() {
    await loadInto(errs, SRC.list, "/api/rules", (d: { items: RuleItem[] }) => setRules(d.items));
  }

  React.useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function setCond(i: number, patch: Partial<Cond>) {
    setConds((cs) => cs.map((c, idx) => (idx === i ? { ...c, ...patch } : c)));
  }

  function buildConditions() {
    const base: Record<string, unknown> = { logic, rules: condsToRules(conds) };
    if (mode === "count") {
      base.mode = "count";
      base.key = keys.split(",").map((s) => s.trim()).filter(Boolean);
      base.min_count = Number(minCount) || 1;
    }
    return base;
  }

  async function create() {
    setMsg("");
    if (!name.trim()) {
      setMsg("请填写规则名");
      return;
    }
    if (conds.filter((c) => c.field && c.op).length === 0) {
      setMsg("至少需要一个条件（空条件规则不生效）");
      return;
    }
    try {
      await apiFetch("/api/rules", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          description: "",
          conditions: buildConditions(),
          severity,
          enabled: true,
          priority: parseInt(priority, 10) || 100,
        }),
      });
      setName("");
      setConds([{ field: "event_type", op: "eq", value: "" }]);
      setMsg("已添加");
      void load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "添加失败");
    }
  }

  async function toggle(r: RuleItem) {
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
      void load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "更新失败");
    }
  }

  /** 删除用户自建规则（内置规则后端会拒，界面直接不给按钮）。 */
  async function remove(r: RuleItem) {
    if (r.source === "builtin") return;
    if (!window.confirm(`删除规则「${r.name}」？删掉就没了，不能撤销（只想临时停用请点「禁用」）。`)) {
      return;
    }
    setMsg("");
    setDeleting(r.id);
    try {
      await apiFetch(`/api/rules/${r.id}`, { method: "DELETE" });
      setMsg(`已删除「${r.name}」`);
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "删除失败");
    } finally {
      setDeleting("");
    }
  }

  return (
    <div className="min-h-screen">
      <TopBar />
      <Nav />
      <main className="ml-56 px-6 pb-6 pt-20">
        <h1 className="mb-4 text-2xl font-bold">规则配置</h1>
        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}
        <div className="mb-3">
          <PanelError errors={errs} />
        </div>

        <Card className="mb-4">
          <CardHeader>
            <CardTitle className="text-sm">新建规则</CardTitle>
            <p className="text-xs text-muted-foreground">
              字段与操作符见下；<b>空条件规则不会生效</b>，必须至少一个条件。频率规则用于扫描/爆破等「次数」特征。
            </p>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-4 gap-3">
              <div className="col-span-2">
                <label className="mb-1 block text-xs text-muted-foreground">规则名 *</label>
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="如：拦截内网到公网 4444 端口"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">级别</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  className={`${SELECT_CLS} w-full`}
                >
                  <option value="critical">紧急</option>
                  <option value="high">高危</option>
                  <option value="medium">中危</option>
                  <option value="low">低危</option>
                  <option value="info">提示</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  优先级（越小越先）
                </label>
                <Input value={priority} onChange={(e) => setPriority(e.target.value)} />
              </div>
            </div>

            <ConditionEditor
              fields={RULE_FIELDS}
              conds={conds}
              logic={logic}
              onLogic={setLogic}
              onChange={setCond}
              onRemove={(i) => setConds((cs) => cs.filter((_, idx) => idx !== i))}
              onAdd={() =>
                setConds((cs) => [...cs, { field: "dst_port", op: "in", value: "" }])
              }
            />

            <div className="flex items-end gap-3 rounded-md border p-3">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">规则类型</label>
                <select
                  value={mode}
                  onChange={(e) => setMode(e.target.value as "single" | "count")}
                  className={SELECT_CLS}
                >
                  <option value="single">逐条（每条命中即报）</option>
                  <option value="count">频率（窗口内达到次数才报）</option>
                </select>
              </div>
              {mode === "count" && (
                <>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">
                      分组字段（逗号分隔）
                    </label>
                    <Input value={keys} onChange={(e) => setKeys(e.target.value)} className="w-48" />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">最少次数</label>
                    <Input
                      value={minCount}
                      onChange={(e) => setMinCount(e.target.value)}
                      className="w-24"
                    />
                  </div>
                </>
              )}
              <Button onClick={create}>添加规则</Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">规则列表（{rules.length}）</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>类型</TableHead>
                  <TableHead>级别</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>优先级</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="max-w-[320px] truncate" title={r.description || r.name}>
                      {r.name}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{ruleType(r)}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{r.severity}</Badge>
                    </TableCell>
                    <TableCell>{r.source === "builtin" ? "内置" : "用户"}</TableCell>
                    <TableCell>{r.priority}</TableCell>
                    <TableCell>{r.enabled ? "启用" : "禁用"}</TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button size="sm" variant="outline" onClick={() => toggle(r)}>
                          {r.enabled ? "禁用" : "启用"}
                        </Button>
                        {r.source !== "builtin" && (
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-destructive"
                            disabled={deleting === r.id}
                            onClick={() => void remove(r)}
                          >
                            {deleting === r.id ? "删除中…" : "删除"}
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {rules.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground">
                      {emptyOrFailed(errs, SRC.list, "还没有规则（上面可以新建一条）")}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
