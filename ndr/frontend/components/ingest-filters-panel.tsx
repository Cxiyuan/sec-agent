"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Dialog,
  EmptyState,
  Field,
  FieldGrid,
  Input,
  Section,
  SettingsGrid,
  SettingsMain,
  SettingsRail,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
  cn,
  formatDateTime,
} from "@shentong/ui";
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
import { emptyOrFailed, loadInto, PanelError, usePanelErrors } from "@/components/panel-error";
import { condValueLabel } from "@/lib/qtype";

/** 读取失败的接口名（错误条与空态用）。 */
const SRC = {
  list: "降噪过滤列表（/api/ingest-filters）",
  fields: "可选字段与示例（/api/ingest-filters/fields）",
} as const;

/** 条件摘要文本（嵌套条件组用文字标出，避免“看着像扁平条件”的误解）。 */
function condSummary(c: RuleConditions | undefined): string {
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

const SOURCE_TEXT: Record<string, string> = {
  es: "Elasticsearch 历史事件",
  detector_queue: "检测器待处理队列（刚采集、还没落库）",
  collect_queue: "采集队列（还没归一化）",
  none: "哪里都没取到",
};

function SampleLine({ s }: { s: IngestFilterSample }) {
  return (
    <p
      className="break-words font-mono text-xs text-muted-foreground"
      title={s.ref ? `事件引用 ${s.ref}` : ""}
    >
      [{formatDateTime(s.ts || s.at)}] {s.source_system} ·{" "}
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
  /** 结果提示的语义：成功绿条 / 失败红条 / 中性说明（套用示例这类） */
  const [msgKind, setMsgKind] = React.useState<"ok" | "err" | "info">("info");

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
  /** 首次读取列表：先画骨架，别把「正在读」显示成「暂无降噪过滤」 */
  const [loading, setLoading] = React.useState(true);
  /** 删除 / 禁用都要二次确认：用 Dialog，不用 window.confirm */
  const [pending, setPending] = React.useState<
    { item: IngestFilterItem; action: "delete" | "disable" } | null
  >(null);
  const errs = usePanelErrors();

  async function load() {
    await loadInto(
      errs,
      SRC.list,
      "/api/ingest-filters",
      (list: { items: IngestFilterItem[]; last_hit_at: string | null }) => {
        setItems(list.items);
        setLastHitAt(list.last_hit_at);
      },
    );
  }

  React.useEffect(() => {
    void (async () => {
      errs.reset();
      await Promise.all([
        load(),
        loadInto(errs, SRC.fields, "/api/ingest-filters/fields", (f: IngestFilterFields) => {
          setFields(f.fields.length ? f.fields : RULE_FIELDS);
          setExamples(f.examples || []);
          setHint(f.hint || "");
        }),
      ]);
      setLoading(false);
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
    setMsgKind("info");
    setMsg(`已套用示例「${ex.name}」，记得先试运行看一眼再保存`);
  }

  function currentConditions(): RuleConditions | null {
    const rules = condsToRules(conds);
    if (!rules.length) {
      setMsgKind("err");
      setMsg("至少需要一个条件（不允许无条件挡下一切）");
      return null;
    }
    return { logic, rules };
  }

  async function save() {
    setMsg("");
    if (!name.trim()) {
      setMsgKind("err");
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
        setMsgKind("ok");
        setMsg("已保存（最多 30 秒生效）");
      } else {
        await apiFetch("/api/ingest-filters", { method: "POST", body: JSON.stringify(body) });
        setMsgKind("ok");
        setMsg("已添加（最多 30 秒生效）");
      }
      reset();
      load();
    } catch (e) {
      setMsgKind("err");
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
      if (res.errors?.length) {
        setMsgKind("err");
        setMsg(res.errors.join("；"));
      }
    } catch (e) {
      setMsgKind("err");
      setMsg(e instanceof ApiError ? errorText(e.body) : "试运行失败");
    } finally {
      setDryBusy(false);
    }
  }

  async function toggle(f: IngestFilterItem) {
    try {
      await apiFetch(`/api/ingest-filters/${f.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name: f.name,
          description: f.description,
          conditions: f.conditions,
          enabled: !f.enabled,
          priority: f.priority,
        }),
      });
      void load();
    } catch (e) {
      setMsgKind("err");
      setMsg(e instanceof ApiError ? errorText(e.body) : "更新失败");
    }
  }

  async function remove(f: IngestFilterItem) {
    try {
      await apiFetch(`/api/ingest-filters/${f.id}`, { method: "DELETE" });
      if (editId === f.id) reset();
      void load();
    } catch (e) {
      setMsgKind("err");
      setMsg(e instanceof ApiError ? errorText(e.body) : "删除失败");
    }
  }

  const notice = msg ? (
    <p
      role={msgKind === "err" ? "alert" : "status"}
      className={cn(
        "rounded-xs border px-3 py-2 text-xs",
        msgKind === "err"
          ? "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg"
          : msgKind === "ok"
            ? "border-sev-ok-bd bg-sev-ok-bg text-sev-ok-fg"
            : "border-border-subtle bg-surface-1 text-muted-foreground"
      )}
    >
      {msg}
    </p>
  ) : null;

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />
      <Section
        title="降噪过滤（命中不进检测器，但仍进事件库）"
        description={
          <>
            命中的事件<b>照样完整落进 Elasticsearch</b>（事件列表里查得到、可回溯），只是
            <b>不再投给检测器</b>，因此不会产生告警与报告。适合挡掉扫描器日常噪声、监控探活、心跳域名这类
            “看着像攻击、其实每天都有”的流量。条件只能引用地址/端口与协议内容字段，不允许拿 raw 全字段匹配。
            保存前请先<b>试运行</b>：它会拿最近的历史事件跑一遍，告你这个条件会挡下多少条、分别是哪些。
          </>
        }
      >
        {hint && !msg && <p className="text-xs text-muted-foreground">{hint}</p>}

        {/* 主列＝表单（唯一能改的）；侧栏＝被挡下的样例（只读）。已配置过滤器 5 列，
            19rem 侧栏放不下，整幅排在 grid 之后，避免把表单区推走。 */}
        <SettingsGrid>
          <SettingsMain>
            <Card>
              <CardHeader>
                <CardTitle>{editId ? "编辑过滤器" : "新建过滤器"}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <FieldGrid maxCols={4}>
                  <Field label="名称" htmlFor="ingest-name" required>
                    <Input
                      id="ingest-name"
                      value={name}
                      aria-required="true"
                      onChange={(e) => setName(e.target.value)}
                      placeholder="如：挡掉内网漏洞扫描噪声"
                    />
                  </Field>
                  <Field label="优先级（越小越先匹配）" htmlFor="ingest-priority">
                    <Input
                      id="ingest-priority"
                      className="tabular-nums"
                      value={priority}
                      onChange={(e) => setPriority(e.target.value)}
                    />
                  </Field>
                  <Field label="说明（可选）" htmlFor="ingest-desc">
                    <Input
                      id="ingest-desc"
                      value={desc}
                      onChange={(e) => setDesc(e.target.value)}
                      placeholder="为什么挡它（便于以后判断能不能删）"
                    />
                  </Field>
                  <div className="flex items-end pb-2">
                    <label className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        className="h-4 w-4"
                        checked={enabled}
                        onChange={(e) => setEnabled(e.target.checked)}
                      />
                      启用
                    </label>
                  </div>
                </FieldGrid>

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
                  <p className="rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg">
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

                {notice}

                <div className="flex flex-wrap items-end gap-2">
                  <Button size="sm" onClick={save}>
                    {editId ? "保存修改" : "添加"}
                  </Button>
                  <Button size="sm" variant="outline" onClick={dryRun} disabled={dryBusy}>
                    {dryBusy ? "试运行中…" : "试运行（不保存）"}
                  </Button>
                  <FieldGrid maxCols={4} className="items-end">
                    <Field label="回看小时" htmlFor="ingest-hours">
                      <Input
                        id="ingest-hours"
                        className="tabular-nums"
                        value={hours}
                        onChange={(e) => setHours(e.target.value)}
                      />
                    </Field>
                    <Field label="最多取样" htmlFor="ingest-limit">
                      <Input
                        id="ingest-limit"
                        className="tabular-nums"
                        value={limit}
                        onChange={(e) => setLimit(e.target.value)}
                      />
                    </Field>
                  </FieldGrid>
                  {editId && (
                    <Button size="sm" variant="outline" onClick={reset}>
                      取消编辑
                    </Button>
                  )}
                </div>

                {dry && (
                  <div className="space-y-2 rounded-xs bg-surface-1 p-3">
                    <p className="text-sm">
                      试运行结果：取样自{" "}
                      <b>{SOURCE_TEXT[String(dry.source || "none")] || String(dry.source || "-")}</b>
                      {typeof dry.scanned === "number" && (
                        <>
                          ，共看了 <b className="tabular-nums">{dry.scanned}</b> 条，命中{" "}
                          <b className="tabular-nums">{dry.matched ?? 0}</b> 条
                          {dry.ratio !== undefined && (
                            <span className="tabular-nums">
                              （{(Number(dry.ratio) * 100).toFixed(1)}%）
                            </span>
                          )}
                        </>
                      )}
                    </p>
                    {dry.hint && <p className="text-xs text-muted-foreground">{dry.hint}</p>}
                    {dry.errors?.length ? (
                      <p className="text-xs text-sev-critical-fg">{dry.errors.join("；")}</p>
                    ) : null}
                    {(dry.samples || []).map((s, i) => (
                      <SampleLine key={i} s={s} />
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </SettingsMain>

          <SettingsRail>
            <Card>
              <CardHeader>
                <CardTitle>最近被挡下的事件（每条例最多留 3 条）</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {/* 汇总三行（生效条数 / 累计挡下 / 最近命中）：样例行只回答"挡的是不是想挡的"，
                    这几行回答"到底挡了多少" —— 两者都是只读事实，都放侧栏。 */}
                {!loading && (
                  <div className="divide-y divide-border-subtle rounded-xs bg-surface-1 px-3 py-2 text-xs">
                    <p className="pb-1">
                      <span className="text-muted-foreground">生效过滤器</span>
                      <span className="mt-0.5 block tabular-nums">
                        {items.length ? `${items.filter((f) => f.enabled).length} / ${items.length} 条` : "还没有过滤器"}
                      </span>
                    </p>
                    <p className="py-1">
                      <span className="text-muted-foreground">累计挡下</span>
                      <span className="mt-0.5 block tabular-nums">
                        {items.reduce((s, f) => s + (f.hit_count ?? 0), 0)}
                      </span>
                    </p>
                    <p className="pt-1">
                      <span className="text-muted-foreground">最近命中</span>
                      <span className="mt-0.5 block tabular-nums">
                        {lastHitAt ? formatDateTime(lastHitAt) : "—"}
                      </span>
                    </p>
                  </div>
                )}
                {/* 3 条样例行（每行 16px）+ 一行时间：原来是 h-12（48px），基本对齐，保持 */}
                {loading ? (
                  <div className="space-y-1">
                    <Skeleton className="h-3 w-full" />
                    <Skeleton className="h-3 w-4/5" />
                    <Skeleton className="h-3 w-2/3" />
                    <Skeleton className="h-3 w-32" />
                  </div>
                ) : items.some((f) => f.samples?.length) ? (
                  <>
                    {items
                      .filter((f) => f.samples?.length)
                      .map((f) => (
                        <div key={f.id} className="space-y-1">
                          <p className="text-xs text-muted-foreground">{f.name}</p>
                          {f.samples.map((s, i) => (
                            <SampleLine key={i} s={s} />
                          ))}
                        </div>
                      ))}
                    {lastHitAt && (
                      <p className="text-xs text-muted-foreground">
                        最近命中：{formatDateTime(lastHitAt)}
                      </p>
                    )}
                  </>
                ) : (
                  <EmptyState
                    size="compact"
                    tone={errs.isFailed(SRC.list) ? "danger" : "muted"}
                    title={emptyOrFailed(errs, SRC.list, "还没有被挡下的事件")}
                    hint="过滤器命中后会在这里留一条样例，便于确认它挡的是不是想挡的东西。"
                  />
                )}
              </CardContent>
            </Card>
          </SettingsRail>
        </SettingsGrid>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
            <CardTitle>已配置过滤器</CardTitle>
            <Badge variant="outline">
              共 <span className="tabular-nums">{items.length}</span> 条
            </Badge>
          </CardHeader>
          <CardContent>
            {/* 列表的骨架：原来只在上方的表单卡里画了骨架，这张表的位置是空白 ——
                接口慢的时候会先看到「暂无降噪过滤」的错觉位置。 */}
            {loading ? (
              <TableSkeleton rows={5} cols={5} />
            ) : (
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
                        <span className="ml-2 text-xs tabular-nums text-muted-foreground">
                          #{f.priority}
                        </span>
                      </TableCell>
                      <TableCell
                        className="max-w-[380px] truncate font-mono text-xs"
                        title={condSummary(f.conditions)}
                      >
                        {condSummary(f.conditions)}
                      </TableCell>
                      <TableCell>
                        <Badge variant={f.enabled ? "success" : "outline"}>
                          {f.enabled ? "启用" : "禁用"}
                        </Badge>
                      </TableCell>
                      <TableCell className="tabular-nums">{f.hit_count ?? 0}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-2">
                          <Button size="sm" variant="outline" onClick={() => startEdit(f)}>
                            编辑
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() =>
                              f.enabled
                                ? setPending({ item: f, action: "disable" })
                                : void toggle(f)
                            }
                          >
                            {f.enabled ? "禁用" : "启用"}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => setPending({ item: f, action: "delete" })}
                          >
                            删除
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {!items.length && (
                    <TableRow>
                      <TableCell colSpan={5} className="p-0">
                        <EmptyState
                          size="compact"
                          tone={errs.isFailed(SRC.list) ? "danger" : "muted"}
                          title={emptyOrFailed(errs, SRC.list, "暂无降噪过滤（检测器会看到全部事件）")}
                          hint="上面填好条件后点「添加」，最多 30 秒生效。"
                        />
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Dialog
          open={pending !== null}
          title={pending?.action === "disable" ? "禁用这条降噪过滤？" : "删除这条降噪过滤？"}
          onClose={() => setPending(null)}
          footer={
            <div className="flex items-center justify-end gap-2">
              <Button size="sm" variant="outline" onClick={() => setPending(null)}>
                取消
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onClick={() => {
                  const p = pending;
                  setPending(null);
                  if (!p) return;
                  if (p.action === "delete") void remove(p.item);
                  else void toggle(p.item);
                }}
              >
                {pending?.action === "disable" ? "禁用" : "删除"}
              </Button>
            </div>
          }
        >
          <p className="text-xs leading-relaxed text-muted-foreground">
            {pending?.action === "disable" ? (
              <>「{pending.item.name}」禁用后不再挡下事件，命中的事件会重新投给检测器（可随时再启用）。</>
            ) : (
              <>「{pending?.item.name}」删除后，命中它的事件会重新投给检测器。</>
            )}
          </p>
        </Dialog>
      </Section>
    </div>
  );
}
