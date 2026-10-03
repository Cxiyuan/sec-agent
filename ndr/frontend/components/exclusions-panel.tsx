"use client";

import * as React from "react";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@shentong/ui";
import {
  ConditionEditor,
  EMPTY_COND,
  RULE_FIELDS,
  condsToRules,
  conditionsToConds,
  type Cond,
} from "@/components/condition-editor";
import {
  ApiError,
  apiFetch,
  errorText,
  type ExclusionConditions,
  type ExclusionFields,
  type ExclusionFilterItem,
  type ExclusionStats,
} from "@/lib/api";
import { emptyOrFailed, loadInto, PanelError, usePanelErrors } from "@/components/panel-error";
import { condValueLabel } from "@/lib/qtype";

/** 读取失败的接口名（错误条与空态用）。 */
const SRC = {
  list: "排除过滤列表（/api/exclusions）",
  stats: "命中统计（/api/exclusions/stats）",
  fields: "可选字段（/api/exclusions/fields）",
} as const;

/** 条件摘要文本（嵌套条件组用文字标出，避免“看着像扁平条件”的误解）。 */
function condSummary(c: ExclusionConditions | undefined): string {
  const logic = c?.logic === "or" ? " 或 " : " 且 ";
  const rules = c?.rules || [];
  if (!rules.length) return "-";
  return rules
    .map((r) => {
      if (r.logic || r.rules) return "（嵌套条件组）";
      // qtype 落库是数字码，摘要里翻成人读（16 → TXT（16））
      return `${r.field ?? "-"} ${r.op ?? "-"} ${condValueLabel(r.field, r.value)}`.trim();
    })
    .join(logic);
}

export function ExclusionsPanel() {
  const [items, setItems] = React.useState<ExclusionFilterItem[]>([]);
  const [stats, setStats] = React.useState<ExclusionStats | null>(null);
  const [fields, setFields] = React.useState<string[]>(RULE_FIELDS);
  const [msg, setMsg] = React.useState("");

  const [editId, setEditId] = React.useState<string | null>(null);
  const [name, setName] = React.useState("");
  const [desc, setDesc] = React.useState("");
  const [priority, setPriority] = React.useState("100");
  const [enabled, setEnabled] = React.useState(true);
  const [logic, setLogic] = React.useState("and");
  const [conds, setConds] = React.useState<Cond[]>([EMPTY_COND]);
  const [nested, setNested] = React.useState(false);
  const errs = usePanelErrors();

  async function load() {
    await Promise.all([
      loadInto(errs, SRC.list, "/api/exclusions", (list: { items: ExclusionFilterItem[] }) =>
        setItems(list.items),
      ),
      loadInto(errs, SRC.stats, "/api/exclusions/stats", (st: ExclusionStats) => setStats(st)),
    ]);
  }

  React.useEffect(() => {
    void (async () => {
      errs.reset();
      await Promise.all([
        load(),
        loadInto(errs, SRC.fields, "/api/exclusions/fields", (f: ExclusionFields) => {
          // 日志字段 + 规则元数据（hit_rule / rule_source / rule_severity）
          const merged = [...f.fields, ...f.rule_fields];
          setFields(merged.length ? merged : RULE_FIELDS);
        }),
      ]);
    })();
    // 只在挂载时读一次；load 内部自己收错误
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function reset() {
    setEditId(null);
    setName("");
    setDesc("");
    setPriority("100");
    setEnabled(true);
    setLogic("and");
    setConds([EMPTY_COND]);
    setNested(false);
  }

  function setCond(i: number, patch: Partial<Cond>) {
    setConds((cs) => cs.map((c, idx) => (idx === i ? { ...c, ...patch } : c)));
  }

  function startEdit(f: ExclusionFilterItem) {
    const parsed = conditionsToConds(f.conditions);
    setEditId(f.id);
    setName(f.name);
    setDesc(f.description);
    setPriority(String(f.priority));
    setEnabled(f.enabled);
    setLogic(parsed.logic);
    setConds(parsed.conds);
    setNested(parsed.nested);
    setMsg("");
  }

  async function save() {
    setMsg("");
    if (!name.trim()) {
      setMsg("请填写名称");
      return;
    }
    const rules = condsToRules(conds);
    if (!rules.length) {
      setMsg("至少需要一个条件（不允许无条件排除一切）");
      return;
    }
    const body = {
      name: name.trim(),
      description: desc.trim(),
      conditions: { logic, rules },
      enabled,
      priority: parseInt(priority, 10) || 100,
    };
    try {
      if (editId) {
        await apiFetch(`/api/exclusions/${editId}`, { method: "PUT", body: JSON.stringify(body) });
        setMsg("已保存（30 秒内全链路生效）");
      } else {
        await apiFetch("/api/exclusions", { method: "POST", body: JSON.stringify(body) });
        setMsg("已添加（30 秒内全链路生效）");
      }
      reset();
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    }
  }

  async function toggle(f: ExclusionFilterItem) {
    try {
      await apiFetch(`/api/exclusions/${f.id}`, {
        method: "PUT",
        body: JSON.stringify({ ...f, enabled: !f.enabled }),
      });
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "更新失败");
    }
  }

  async function remove(f: ExclusionFilterItem) {
    try {
      await apiFetch(`/api/exclusions/${f.id}`, { method: "DELETE" });
      if (editId === f.id) reset();
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "删除失败");
    }
  }

  const sampleEntries = Object.entries(stats?.samples || {});

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">排除过滤（命中仍记事件，但不跑模型）</CardTitle>
        <p className="text-xs text-muted-foreground">
          被排除的事件<b>仍会进事件列表</b>（状态“已排除”，默认折叠）、可回溯，但跳过边缘研判、深度分析、定级、处置、
          报告与记忆写入。条件可引用日志字段与命中规则元数据（hit_rule / rule_source / rule_severity）。
          配置最多 30 秒生效；读配置失败时按“不排除”处理（宁可多分析，不漏报）。
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {msg && <p className="text-sm text-primary">{msg}</p>}
        <PanelError errors={errs} />

        <div className="space-y-3 rounded-md border p-3">
          <div className="grid grid-cols-4 gap-3">
            <div className="col-span-2">
              <label className="mb-1 block text-xs text-muted-foreground">名称 *</label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="如：排除内网健康检查噪声"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                优先级（越小越先）
              </label>
              <Input value={priority} onChange={(e) => setPriority(e.target.value)} />
            </div>
            <div className="flex items-end gap-2">
              <label className="flex items-center gap-1 text-sm">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                />
                启用
              </label>
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">说明（可选）</label>
            <Input
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              placeholder="为什么排除它（便于以后判断能不能删）"
            />
          </div>

          {nested && (
            <p className="text-xs text-destructive">
              该过滤器含<b>嵌套条件组</b>，界面只支持编辑顶层条件。请先在上方补齐条件再保存；直接保存会丢失嵌套部分。
            </p>
          )}

          <ConditionEditor
            fields={fields}
            conds={conds}
            logic={logic}
            onLogic={setLogic}
            onChange={setCond}
            onRemove={(i) => setConds((cs) => cs.filter((_, idx) => idx !== i))}
            onAdd={() => setConds((cs) => [...cs, { field: "hit_rule", op: "eq", value: "" }])}
          />

          <div className="flex items-center gap-2">
            <Button onClick={save}>{editId ? "保存修改" : "添加"}</Button>
            {editId && (
              <Button variant="outline" onClick={reset}>
                取消编辑
              </Button>
            )}
          </div>
        </div>

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead>条件</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>已排除</TableHead>
              <TableHead>操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((f) => (
              <TableRow key={f.id}>
                <TableCell className="max-w-[200px] truncate" title={f.description || f.name}>
                  {f.name}
                  <span className="ml-2 text-xs text-muted-foreground">#{f.priority}</span>
                </TableCell>
                <TableCell className="max-w-[380px] truncate font-mono text-xs" title={condSummary(f.conditions)}>
                  {condSummary(f.conditions)}
                </TableCell>
                <TableCell>
                  <Badge variant={f.enabled ? "default" : "outline"}>
                    {f.enabled ? "启用" : "禁用"}
                  </Badge>
                </TableCell>
                {/* 统计没读到就显示 “—”，不要用 0 冒充「一条没命中」 */}
                <TableCell>{stats ? (stats.counts?.[f.name] ?? 0) : "—"}</TableCell>
                <TableCell className="space-x-2">
                  <Button size="sm" variant="outline" onClick={() => startEdit(f)}>
                    编辑
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => toggle(f)}>
                    {f.enabled ? "禁用" : "启用"}
                  </Button>
                  <Button size="sm" variant="destructive" onClick={() => remove(f)}>
                    删除
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {!items.length && (
              <TableRow>
                <TableCell colSpan={5} className="text-sm text-muted-foreground">
                  {emptyOrFailed(errs, SRC.list, "暂无排除过滤")}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>

        {sampleEntries.length > 0 && (
          <div>
            <h3 className="mb-1 text-sm font-medium">最近被排除的样例</h3>
            {sampleEntries.map(([fname, samples]) => (
              <div key={fname} className="mb-1">
                <p className="text-xs text-muted-foreground">{fname}</p>
                {samples.map((s, i) => (
                  <p key={i} className="font-mono text-xs text-muted-foreground">
                    [{String(s.at || "").slice(0, 19).replace("T", " ")}] {s.rule} · {s.src_ip} →{" "}
                    {s.dst_ip} · {s.event_type} · {String(s.summary || "").slice(0, 120)}
                  </p>
                ))}
              </div>
            ))}
            {stats?.last_hit_at && (
              <p className="text-xs text-muted-foreground">
                最近命中：{String(stats.last_hit_at).slice(0, 19).replace("T", " ")}
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
