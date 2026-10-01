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
  type IngestDryRunResult,
  type IngestFilterExample,
  type IngestFilterFields,
  type IngestFilterItem,
  type IngestFilterSample,
  type RuleConditions,
} from "@/lib/api";

/** 条件摘要文本（嵌套条件组用文字标出，避免“看着像扁平条件”的误解）。 */
function condSummary(c: RuleConditions | undefined): string {
  const logic = c?.logic === "or" ? " 或 " : " 且 ";
  const rules = c?.rules || [];
  if (!rules.length) return "-";
  return rules
    .map((r) => {
      if (r.logic || r.rules) return "（嵌套条件组）";
      const value = Array.isArray(r.value) ? r.value.join(",") : (r.value ?? "");
      return `${r.field ?? "-"} ${r.op ?? "-"} ${String(value)}`.trim();
    })
    .join(logic);
}

const SOURCE_TEXT: Record<string, string> = {
  es: "Elasticsearch 历史事件",
  detector_queue: "检测器待处理队列（刚采集、还没落库）",
  collect_queue: "采集队列（还没归一化）",
  none: "哪里都没取到",
};

function SampleLine({ s }: { s: IngestFilterSample }) {
  return (
    <p className="font-mono text-xs text-muted-foreground" title={s.ref ? `事件引用 ${s.ref}` : ""}>
      [{String(s.ts || s.at || "").slice(0, 19).replace("T", " ")}] {s.source_system} ·{" "}
      {s.event_type} · {s.src_ip}
      {s.src_port ? `:${s.src_port}` : ""} → {s.dst_ip}
      {s.dst_port ? `:${s.dst_port}` : ""} · {String(s.summary || "").slice(0, 120)}
    </p>
  );
}

export function IngestFiltersPanel() {
  const [items, setItems] = React.useState<IngestFilterItem[]>([]);
  const [fields, setFields] = React.useState<string[]>(RULE_FIELDS);
  const [examples, setExamples] = React.useState<IngestFilterExample[]>([]);
  const [hint, setHint] = React.useState("");
  const [lastHitAt, setLastHitAt] = React.useState<string | null>(null);
  const [msg, setMsg] = React.useState("");

  const [editId, setEditId] = React.useState<string | null>(null);
  const [name, setName] = React.useState("");
  const [desc, setDesc] = React.useState("");
  const [priority, setPriority] = React.useState("100");
  const [enabled, setEnabled] = React.useState(true);
  const [logic, setLogic] = React.useState("and");
  const [conds, setConds] = React.useState<Cond[]>([EMPTY_COND]);
  const [nested, setNested] = React.useState(false);

  const [hours, setHours] = React.useState("24");
  const [limit, setLimit] = React.useState("200");
  const [dry, setDry] = React.useState<IngestDryRunResult | null>(null);
  const [dryBusy, setDryBusy] = React.useState(false);

  async function load() {
    const list = await apiFetch<{
      items: IngestFilterItem[];
      last_hit_at: string | null;
    }>("/api/ingest-filters");
    setItems(list.items);
    setLastHitAt(list.last_hit_at);
  }

  React.useEffect(() => {
    load().catch(() => {});
    apiFetch<IngestFilterFields>("/api/ingest-filters/fields")
      .then((f) => {
        setFields(f.fields.length ? f.fields : RULE_FIELDS);
        setExamples(f.examples || []);
        setHint(f.hint || "");
      })
      .catch(() => {});
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
    setDry(null);
  }

  function setCond(i: number, patch: Partial<Cond>) {
    setConds((cs) => cs.map((c, idx) => (idx === i ? { ...c, ...patch } : c)));
  }

  function startEdit(f: IngestFilterItem) {
    const parsed = conditionsToConds(f.conditions);
    setEditId(f.id);
    setName(f.name);
    setDesc(f.description);
    setPriority(String(f.priority));
    setEnabled(f.enabled);
    setLogic(parsed.logic);
    setConds(parsed.conds);
    setNested(parsed.nested);
    setDry(null);
    setMsg("");
  }

  function applyExample(ex: IngestFilterExample) {
    const parsed = conditionsToConds(ex.conditions);
    setLogic(parsed.logic);
    setConds(parsed.conds);
    setNested(parsed.nested);
    if (!name.trim()) setName(ex.name);
    if (!desc.trim() && ex.description) setDesc(ex.description);
    setDry(null);
    setMsg(`已套用示例「${ex.name}」，记得先试运行看一眼再保存`);
  }

  function currentConditions(): RuleConditions | null {
    const rules = condsToRules(conds);
    if (!rules.length) {
      setMsg("至少需要一个条件（不允许无条件挡下一切）");
      return null;
    }
    return { logic, rules };
  }

  async function save() {
    setMsg("");
    if (!name.trim()) {
      setMsg("请填写名称");
      return;
    }
    const conditions = currentConditions();
    if (!conditions) return;
    const body = {
      name: name.trim(),
      description: desc.trim(),
      conditions,
      enabled,
      priority: parseInt(priority, 10) || 100,
    };
    try {
      if (editId) {
        await apiFetch(`/api/ingest-filters/${editId}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
        setMsg("已保存（最多 30 秒生效）");
      } else {
        await apiFetch("/api/ingest-filters", { method: "POST", body: JSON.stringify(body) });
        setMsg("已添加（最多 30 秒生效）");
      }
      reset();
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    }
  }

  async function dryRun() {
    setMsg("");
    setDry(null);
    const conditions = currentConditions();
    if (!conditions) return;
    setDryBusy(true);
    try {
      const res = await apiFetch<IngestDryRunResult>("/api/ingest-filters/dry-run", {
        method: "POST",
        body: JSON.stringify({
          conditions,
          hours: parseInt(hours, 10) || 0,
          limit: parseInt(limit, 10) || 0,
        }),
      });
      setDry(res);
      if (res.errors?.length) setMsg(res.errors.join("；"));
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "试运行失败");
    } finally {
      setDryBusy(false);
    }
  }

  async function toggle(f: IngestFilterItem) {
    try {
      await apiFetch(`/api/ingest-filters/${f.id}`, {
        method: "PUT",
        body: JSON.stringify({ ...f, enabled: !f.enabled }),
      });
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "更新失败");
    }
  }

  async function remove(f: IngestFilterItem) {
    try {
      await apiFetch(`/api/ingest-filters/${f.id}`, { method: "DELETE" });
      if (editId === f.id) reset();
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "删除失败");
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">降噪过滤（命中不进检测器，但仍进事件库）</CardTitle>
        <p className="text-xs text-muted-foreground">
          命中的事件<b>照样完整落进 Elasticsearch</b>（事件列表里查得到、可回溯），只是
          <b>不再投给检测器</b>，因此不会产生告警与报告。适合挡掉扫描器日常噪声、监控探活、心跳域名这类
          “看着像攻击、其实每天都有”的流量。条件只能引用地址/端口与协议内容字段，不允许拿 raw 全字段匹配。
          保存前请先<b>试运行</b>：它会拿最近的历史事件跑一遍，告你这个条件会挡下多少条、分别是哪些。
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {msg && <p className="text-sm text-primary">{msg}</p>}
        {hint && !msg && <p className="text-xs text-muted-foreground">{hint}</p>}

        <div className="space-y-3 rounded-md border p-3">
          <div className="grid grid-cols-4 gap-3">
            <div className="col-span-2">
              <label className="mb-1 block text-xs text-muted-foreground">名称 *</label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="如：挡掉内网漏洞扫描噪声"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                优先级（越小越先匹配）
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
              placeholder="为什么挡它（便于以后判断能不能删）"
            />
          </div>

          {examples.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted-foreground">现成示例：</span>
              {examples.map((ex) => (
                <Button
                  key={ex.name}
                  size="sm"
                  variant="outline"
                  title={ex.description || ""}
                  onClick={() => applyExample(ex)}
                >
                  {ex.name}
                </Button>
              ))}
            </div>
          )}

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
            onAdd={() => setConds((cs) => [...cs, { field: "src_ip", op: "eq", value: "" }])}
          />

          <div className="flex flex-wrap items-end gap-2">
            <Button onClick={save}>{editId ? "保存修改" : "添加"}</Button>
            <Button variant="outline" onClick={dryRun} disabled={dryBusy}>
              {dryBusy ? "试运行中…" : "试运行（不保存）"}
            </Button>
            <div className="flex items-end gap-1">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">回看小时</label>
                <Input
                  className="w-20"
                  value={hours}
                  onChange={(e) => setHours(e.target.value)}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">最多取样</label>
                <Input
                  className="w-24"
                  value={limit}
                  onChange={(e) => setLimit(e.target.value)}
                />
              </div>
            </div>
            {editId && (
              <Button variant="outline" onClick={reset}>
                取消编辑
              </Button>
            )}
          </div>

          {dry && (
            <div className="space-y-2 rounded-md bg-muted/40 p-3">
              <p className="text-sm">
                试运行结果：取样自{" "}
                <b>{SOURCE_TEXT[String(dry.source || "none")] || String(dry.source || "-")}</b>
                {typeof dry.scanned === "number" && (
                  <>
                    ，共看了 <b>{dry.scanned}</b> 条，命中 <b>{dry.matched ?? 0}</b> 条
                    {dry.ratio !== undefined && `（${(Number(dry.ratio) * 100).toFixed(1)}%）`}
                  </>
                )}
              </p>
              {dry.hint && <p className="text-xs text-muted-foreground">{dry.hint}</p>}
              {dry.errors?.length ? (
                <p className="text-xs text-destructive">{dry.errors.join("；")}</p>
              ) : null}
              {(dry.samples || []).map((s, i) => (
                <SampleLine key={i} s={s} />
              ))}
            </div>
          )}
        </div>

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead>条件</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>已挡下</TableHead>
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
                <TableCell
                  className="max-w-[380px] truncate font-mono text-xs"
                  title={condSummary(f.conditions)}
                >
                  {condSummary(f.conditions)}
                </TableCell>
                <TableCell>
                  <Badge variant={f.enabled ? "default" : "outline"}>
                    {f.enabled ? "启用" : "禁用"}
                  </Badge>
                </TableCell>
                <TableCell>{f.hit_count ?? 0}</TableCell>
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
                  暂无降噪过滤（检测器会看到全部事件）
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>

        {items.some((f) => f.samples?.length) && (
          <div>
            <h3 className="mb-1 text-sm font-medium">最近被挡下的事件（每条例最多留 3 条）</h3>
            {items
              .filter((f) => f.samples?.length)
              .map((f) => (
                <div key={f.id} className="mb-1">
                  <p className="text-xs text-muted-foreground">{f.name}</p>
                  {f.samples.map((s, i) => (
                    <SampleLine key={i} s={s} />
                  ))}
                </div>
              ))}
            {lastHitAt && (
              <p className="text-xs text-muted-foreground">
                最近命中：{String(lastHitAt).slice(0, 19).replace("T", " ")}
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
