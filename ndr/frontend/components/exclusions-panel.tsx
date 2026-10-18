"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
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
  formatDateTime,
  ruleText,
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
  // 首次加载：列表与统计都还没回来、也没有失败 —— 画骨架，先闪一句「暂无」会被当成配置丢了
  const firstLoad = !stats && !errs.has;

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      {/* L1 区块标题交给 Section：原来标题写在 CardTitle 里，和真正的卡片标题混成一层 */}
      <Section
        title="排除过滤（命中仍记事件，但不跑模型）"
        description={
          <>
            被排除的事件<b>仍会进事件列表</b>（状态“已排除”，默认折叠）、可回溯，但跳过边缘研判、深度分析、定级、处置、
            报告与记忆写入。条件可引用日志字段与命中规则元数据（hit_rule / rule_source / rule_severity）。
            配置最多 30 秒生效；读配置失败时按“不排除”处理（宁可多分析，不漏报）。
          </>
        }
      >
        {/* 主列＝新建/编辑表单（唯一能改的）；侧栏＝最近被排除的样例（只读）。
            已配置规则 5 列，19rem 侧栏放不下，整幅排在 grid 之后。 */}
        <SettingsGrid>
          <SettingsMain>
            <Card>
              <CardContent className="space-y-2 pt-4">
                {msg && <p className="text-sm text-primary">{msg}</p>}

                <div className="space-y-3 rounded-xs bg-surface-1 px-3 py-2">
                  <FieldGrid maxCols={4}>
                    <Field label="名称" required span="lg">
                      <Input
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="如：排除内网健康检查噪声"
                      />
                    </Field>
                    <Field label="优先级（越小越先）">
                      <Input value={priority} onChange={(e) => setPriority(e.target.value)} />
                    </Field>
                    <div className="flex items-end gap-2 pb-2">
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
                    <Field label="说明（可选）" span="full">
                      <Input
                        value={desc}
                        onChange={(e) => setDesc(e.target.value)}
                        placeholder="为什么排除它（便于以后判断能不能删）"
                      />
                    </Field>
                  </FieldGrid>

                  {nested && (
                    <p className="text-xs text-sev-critical-fg">
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

                  {/* 同一工具条内按钮统一 sm（原来主操作是默认尺寸，比旁边的次要按钮高一档） */}
                  <div className="flex items-center gap-2">
                    <Button size="sm" onClick={save}>
                      {editId ? "保存修改" : "添加"}
                    </Button>
                    {editId && (
                      <Button size="sm" variant="outline" onClick={reset}>
                        取消编辑
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </SettingsMain>

          <SettingsRail>
            <Card>
              <CardHeader>
                <CardTitle>最近被排除的样例</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {/* 汇总两行（生效条数 / 累计排除）：`stats === null` 时显示 —，
                    不用 0 冒充"一条没命中"（与表格里「已排除」列同一口径）。 */}
                {stats ? (
                  <div className="divide-y divide-border-subtle rounded-xs bg-surface-1 px-3 py-2 text-xs">
                    <p className="pb-1">
                      <span className="text-muted-foreground">生效规则</span>
                      <span className="mt-0.5 block tabular-nums">
                        {items.length
                          ? `${items.filter((f) => f.enabled).length} / ${items.length} 条`
                          : "还没有排除规则"}
                      </span>
                    </p>
                    <p className="pt-1">
                      <span className="text-muted-foreground">累计排除</span>
                      <span className="mt-0.5 block tabular-nums">
                        {Object.values(stats.counts || {}).reduce((a, b) => a + b, 0)}
                      </span>
                    </p>
                  </div>
                ) : null}
                {stats?.last_hit_at && (
                  <p className="text-xs text-muted-foreground">
                    最近命中：{formatDateTime(stats.last_hit_at)}
                  </p>
                )}
                {firstLoad ? (
                  <Skeleton className="h-12 w-full" />
                ) : sampleEntries.length ? (
                  sampleEntries.map(([fname, samples]) => (
                    <div key={fname}>
                      <p className="text-xs text-muted-foreground">{fname}</p>
                      {samples.map((s, i) => (
                        <p key={i} className="break-words font-mono text-xs text-muted-foreground">
                          [{formatDateTime(s.at)}] {ruleText(s.rule)} · {s.src_ip} → {s.dst_ip} ·{" "}
                          {s.event_type} · {String(s.summary || "").slice(0, 120)}
                        </p>
                      ))}
                    </div>
                  ))
                ) : (
                  <EmptyState
                    size="compact"
                    tone={errs.isFailed(SRC.stats) ? "danger" : "muted"}
                    title={emptyOrFailed(errs, SRC.stats, "还没有被排除的样例")}
                    hint="规则命中后会在这里留一条样例，便于确认它排除的是不是想排除的东西。"
                  />
                )}
              </CardContent>
            </Card>
          </SettingsRail>
        </SettingsGrid>

        {/* 列表单独成区块：原来和编辑表单挤在同一个 Card 里，长列表会把表单顶出屏幕 */}
        <Card>
          <CardHeader>
            <CardTitle>已配置的排除规则</CardTitle>
            <p className="text-xs text-muted-foreground">
              按优先级从小到大匹配；命中的事件标为「已排除」但仍保留在事件列表里。
            </p>
          </CardHeader>
          <CardContent className="p-0">
            {firstLoad ? (
              <TableSkeleton rows={4} cols={5} />
            ) : items.length ? (
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
                        <span className="ml-2 text-xs tabular-nums text-muted-foreground">
                          #{f.priority}
                        </span>
                      </TableCell>
                      <TableCell
                        className="max-w-[380px] truncate font-mono"
                        title={condSummary(f.conditions)}
                      >
                        {condSummary(f.conditions)}
                      </TableCell>
                      <TableCell>
                        <Badge variant={f.enabled ? "default" : "outline"}>
                          {f.enabled ? "启用" : "禁用"}
                        </Badge>
                      </TableCell>
                      {/* 统计没读到就显示 “—”，不要用 0 冒充「一条没命中」 */}
                      <TableCell className="tabular-nums">
                        {stats ? (stats.counts?.[f.name] ?? 0) : "—"}
                      </TableCell>
                      <TableCell className="whitespace-nowrap space-x-2">
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
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                title={emptyOrFailed(errs, SRC.list, "暂无排除过滤")}
                hint="被排除的事件仍会记进事件列表；没有规则时所有事件都会走完整分析"
                tone={errs.isFailed(SRC.list) ? "danger" : "muted"}
              />
            )}
          </CardContent>
        </Card>
      </Section>
    </div>
  );
}
