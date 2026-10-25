"use client";

import * as React from "react";
import { ChevronRight } from "lucide-react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Dialog,
  Drawer,
  EmptyState,
  Field,
  Input,
  Pagination,
  PanelToolbar,
  Section,
  SettingsGrid,
  SettingsMain,
  SettingsRail,
  Skeleton,
  Stat,
  StatSkeleton,
  Switch,
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
import { emptyOrFailed, loadInto, PanelError, usePanelErrors } from "@/components/panel-error";
import {
  TASK_STATES,
  TASK_STATE_LABEL,
  apiErrorText,
  clampNumber,
  durationText,
  fieldErrorsOf,
  numText,
  percentText,
  remainingHours,
  remainingText,
  subjectKindLabel,
  taskKindLabel,
  taskStateLabel,
  taskStateVariant,
  verdictLabel,
  verdictVariant,
} from "@/lib/analysis";
import {
  apiFetch,
  type AnalysisConfigPayload,
  type AnalysisCoverage,
  type AnalysisInventory,
  type AnalysisResultItem,
  type AnalysisResultList,
  type AnalysisStats,
  type AnalysisTaskDetail,
  type AnalysisTaskItem,
  type AnalysisTaskList,
  type KnobItem,
  type ManualTaskIn,
  type ManualTaskOut,
} from "@/lib/api";

/**
 * 派工队列（`/analysis`）：队列总览 + 任务队列 + 任务结论 + 覆盖率 + 对象清单 + 三个浮层。
 *
 * 三条不可越的红线（体验规范 §0）：
 * 1. **不提供「领取/交回/延后」** —— 那是 MCP 通道（带令牌配额），界面绕过配额会把成本上限打穿；
 * 2. 列表接口**失败也返回 200** `{error, items:[], total:0}` → 三态必须三选一，不能把故障画成"今天很安静"；
 * 3. `state` 是**精确单值**、不支持多选；`state=""` 会把历史 `done` 混排进来，所以默认筛 `pending`。
 *
 * 口径坑（都核过源码）：
 * - `coverage.returned` 是**切片前**长度 → 计数一律 `items.length`；
 * - `tasks`/`tasks/{id}` **不返回** `note`（结束原因）与 `claimed_by` → 不画"结束原因"区块；
 * - `lease_until` 只有 MCP 领取路径才回带 → 列表里对 `claimed/deferred` 的"剩余 h"多为「—」。
 */

const SRC = {
  stats: "队列总览（/api/analysis/stats）",
  tasks: "任务队列（/api/analysis/tasks）",
  results: "任务结论（/api/analysis/results）",
  coverage: "覆盖率（/api/analysis/coverage）",
  inventory: "对象清单（/api/analysis/inventory）",
  config: "派工参数（/api/analysis/config）",
  detail: "任务详情（/api/analysis/tasks/{id}）",
} as const;

const PAGE_SIZE = 20;
const REFRESH_MS = 15_000;
/** 盲区清单的取数上限：后端 `never`/`stale` 各自截断到这个数，所以**不能**把两者相加当总数 */
const COVERAGE_LIMIT = 100;
const INVENTORY_LIMIT = 100;

/** 对象类型（派工表单的下拉；与 `observed_subjects.kind` + 任务 `subject_kind` 的并集） */
const SUBJECT_KINDS = [
  "ip",
  "segment",
  "account",
  "protocol",
  "signature",
  "cluster",
  "asset",
  "service_port",
  "peer",
];

/** 派工参数抽屉的 6 组分法（键名带 `analysis.` 前缀，顺序按"从总开关到细项"） */
const PARAM_GROUPS: { title: string; hint: string; keys: string[] }[] = [
  {
    title: "开关与线索",
    hint: "总开关关掉后不再生成新任务（已有任务仍可被领取）；线索类型用勾选，不要手敲逗号串",
    keys: ["analysis.enabled", "analysis.candidate_kinds"],
  },
  {
    title: "配额与保留",
    hint: "领取侧的成本上限：单令牌每小时、全局每小时、并发在跑数，以及留给高强度线索的保留名额",
    keys: [
      "analysis.rate_limit_per_hour_per_token",
      "analysis.rate_limit_per_hour_total",
      "analysis.max_inflight_per_token",
      "analysis.reserved_slots_per_hour",
      "analysis.reserved_min_strength",
    ],
  },
  {
    title: "租约与卡住",
    hint: "领取后多久没交回就回收；反复不交回判定为 stuck；追问链的两条硬上限",
    keys: [
      "analysis.lease_seconds",
      "analysis.stuck_after_attempts",
      "analysis.followup_depth",
      "analysis.followup_max_per_task",
    ],
  },
  {
    title: "容量与时效",
    hint: "队列容量只影响后续入队（满了按强度替换或合并计数，绝不静默丢）",
    keys: [
      "analysis.queue_capacity",
      "analysis.pending_ttl_hours",
      "analysis.dedupe_bucket_minutes",
      "analysis.flush_seconds",
    ],
  },
  {
    title: "门铃",
    hint: "只在有新线索时叫醒智能体；队列从空变非空时立即发一次（不受冷却限制）",
    keys: ["analysis.doorbell_enabled", "analysis.doorbell_cooldown_seconds"],
  },
  {
    title: "覆盖率与反馈",
    hint: "盲区判定、首见登记表保留期，以及用交回结论调整客观强度的反馈学习",
    keys: [
      "analysis.coverage_stale_days",
      "analysis.subject_retention_days",
      "analysis.feedback_enabled",
      "analysis.feedback_days",
      "analysis.fp_decay_days",
      "analysis.feedback_tp_factor",
    ],
  },
];

/** 从 `hint` 里抽一条最能区分线索的文本（全量在详情抽屉里）。 */
function hintSummary(hint: Record<string, unknown> | undefined): string {
  for (const [key, value] of Object.entries(hint || {})) {
    if (key === "suggested_tools") continue;
    if (value === null || value === undefined || value === "") continue;
    const text = typeof value === "object" ? JSON.stringify(value) : String(value);
    return `${key}：${text}`;
  }
  return "—";
}

/** 人工派工的五出口文案：**不得一律说"已派工"**（dropped/skipped 都不是成功）。 */
function manualResult(result: ManualTaskOut | null): { text: string; tone: "ok" | "warn" | "info" | "err" } | null {
  if (!result) return null;
  switch (result.result) {
    case "new":
      return { text: `已入队（${result.subject}）`, tone: "ok" };
    case "merged":
      return { text: "已并入同现象的既有线索（不重复派工）", tone: "ok" };
    case "dropped":
      return { text: "队列已满，本条被丢弃（强度低于队尾）", tone: "warn" };
    case "skipped":
      return { text: "派工已关闭，或该线索类型未启用", tone: "info" };
    case "superseded":
      return { text: "已入队，并挤掉了队列里更弱的一条", tone: "ok" };
    default:
      return { text: "派工失败，见页面上方错误条", tone: "err" };
  }
}

/** 容量压力条：全页唯一自绘图元（"超容量"不是状态，只有这条能表达）。 */
function PressureBar({
  used,
  capacity,
  dropped,
  superseded,
}: {
  used: number;
  capacity: number | undefined;
  dropped: number | undefined;
  superseded: number | undefined;
}) {
  const cap = capacity && capacity > 0 ? capacity : 0;
  const ratio = cap ? used / cap : 0;
  const pct = Math.min(100, Math.round(ratio * 100));
  const color =
    ratio >= 1 ? "bg-sev-critical-fg" : ratio >= 0.8 ? "bg-sev-medium-fg" : "bg-primary";
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      <div
        className="h-1.5 w-60 max-w-full overflow-hidden rounded-full bg-border-subtle"
        role="img"
        aria-label={`队列容量 ${used}/${cap || "—"}`}
        title={
          cap
            ? `队列已满（${used}/${cap}）：新线索会按强度挤掉最弱的待派线索，或直接计数丢弃`
            : "队列容量未知"
        }
      >
        <div className={cn("h-full rounded-full transition-colors", color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs tabular-nums text-muted-foreground">
        {numText(used)} / {numText(capacity)}
      </span>
      <span className="text-xs tabular-nums text-muted-foreground">
        丢弃 {numText(dropped)} · 挤出 {numText(superseded)}
      </span>
      {ratio >= 1 ? (
        <span className="text-xs text-sev-critical-fg">已满，新线索会被丢弃（dropped_overflow）</span>
      ) : null}
    </div>
  );
}

/** 参数的一行：左侧标签 + 已改/默认/未保存三徽章，右侧控件 + 恢复默认。 */
function KnobRow({
  item,
  value,
  dirty,
  error,
  onChange,
  onReset,
  disabled,
}: {
  item: KnobItem;
  value: string | number | boolean;
  dirty: boolean;
  error?: string;
  onChange: (next: string | number | boolean) => void;
  onReset?: () => void;
  disabled?: boolean;
}) {
  const inputId = React.useId();
  return (
    <div className="rounded-xs bg-surface-1 px-3 py-2">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <label htmlFor={inputId} className="text-sm font-medium text-foreground">
          {item.label}
        </label>
        {item.overridden ? <Badge variant="secondary">已改</Badge> : <Badge variant="outline">默认</Badge>}
        {dirty ? <Badge variant="high">未保存</Badge> : null}
        <span className="font-mono text-xs text-muted-foreground">{item.key}</span>
      </div>
      <div className="flex items-center gap-2">
        {item.kind === "bool" ? (
          <Switch
            id={inputId}
            label={item.label}
            checked={Boolean(value)}
            disabled={disabled}
            onCheckedChange={(next) => onChange(next)}
          />
        ) : (
          <Input
            id={inputId}
            type={item.kind === "int" || item.kind === "float" ? "number" : "text"}
            step={item.kind === "float" ? "0.05" : undefined}
            min={item.low ?? undefined}
            max={item.high ?? undefined}
            aria-label={item.label}
            value={String(value ?? "")}
            disabled={disabled}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? `${inputId}-err` : undefined}
            className={item.kind === "text" ? "font-mono text-xs" : undefined}
            onChange={(event) => onChange(event.target.value)}
          />
        )}
        {item.unit ? (
          <span className="whitespace-nowrap text-xs text-muted-foreground">{item.unit}</span>
        ) : null}
        {item.overridden && onReset ? (
          <Button size="sm" variant="ghost" disabled={disabled} onClick={onReset}>
            恢复默认
          </Button>
        ) : null}
      </div>
      {error ? (
        <p id={`${inputId}-err`} className="mt-1 text-xs text-sev-critical-fg">
          {error}
        </p>
      ) : null}
      <p className="mt-1 text-xs tabular-nums text-muted-foreground">
        {item.note}
        {item.low !== null && item.high !== null ? `（范围 ${item.low} ~ ${item.high}${item.unit}）` : null}
        {`　默认 ${String(item.default) === "" ? "（空）" : String(item.default)}`}
      </p>
    </div>
  );
}

export function AnalysisPanel() {
  const errs = usePanelErrors();

  const [stats, setStats] = React.useState<AnalysisStats | null>(null);
  const [cfg, setCfg] = React.useState<AnalysisConfigPayload | null>(null);
  const [tasks, setTasks] = React.useState<AnalysisTaskList | null>(null);
  const [results, setResults] = React.useState<AnalysisResultList | null>(null);
  const [coverage, setCoverage] = React.useState<AnalysisCoverage | null>(null);
  const [inventory, setInventory] = React.useState<AnalysisInventory | null>(null);

  // 队列筛选（state 单选；默认 pending —— 全部会把历史 done 混排到首屏）
  const [q, setQ] = React.useState("");
  const [state, setState] = React.useState("pending");
  const [kind, setKind] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(PAGE_SIZE);
  const [auto, setAuto] = React.useState(false);

  // 结论筛选（只有 verdict / subject / task_id 三个维度，后端没有关键词搜索）
  const [verdict, setVerdict] = React.useState("");
  const [rSubject, setRSubject] = React.useState("");
  const [rTaskId, setRTaskId] = React.useState("");
  const [rPage, setRPage] = React.useState(0);
  const [rSize, setRSize] = React.useState(PAGE_SIZE);

  // 覆盖率 / 对象清单
  const [days, setDays] = React.useState(7);
  const [covKind, setCovKind] = React.useState("");
  const [invKind, setInvKind] = React.useState("");

  // 浮层
  const [detailId, setDetailId] = React.useState("");
  const [detail, setDetail] = React.useState<AnalysisTaskDetail | null>(null);
  const [detailBusy, setDetailBusy] = React.useState(false);
  const [paramOpen, setParamOpen] = React.useState(false);
  const [manualOpen, setManualOpen] = React.useState(false);

  // 人工派工表单
  const [mSubject, setMSubject] = React.useState("");
  const [mKind, setMKind] = React.useState("ip");
  const [mTaskKind, setMTaskKind] = React.useState("hit");
  const [mNote, setMNote] = React.useState("");
  const [mStrength, setMStrength] = React.useState("0.6");
  const [mBusy, setMBusy] = React.useState(false);
  const [mError, setMError] = React.useState("");
  const [mResult, setMResult] = React.useState<ManualTaskOut | null>(null);

  // 参数抽屉
  const [draft, setDraft] = React.useState<Record<string, string | number | boolean>>({});
  const [paramErrs, setParamErrs] = React.useState<Record<string, string>>({});
  const [paramMsg, setParamMsg] = React.useState("");
  const [paramBusy, setParamBusy] = React.useState(false);

  const modalOpen = Boolean(detailId) || paramOpen || manualOpen;

  // ---------- 取数 ----------

  const tasksUrl = React.useMemo(() => {
    const params = new URLSearchParams();
    params.set("limit", String(size));
    params.set("offset", String(page * size));
    if (state) params.set("state", state);
    if (kind) params.set("kind", kind);
    if (q.trim()) params.set("q", q.trim());
    return `/api/analysis/tasks?${params.toString()}`;
  }, [size, page, state, kind, q]);

  const resultsUrl = React.useMemo(() => {
    const params = new URLSearchParams();
    params.set("limit", String(rSize));
    params.set("offset", String(rPage * rSize));
    if (verdict) params.set("verdict", verdict);
    if (rSubject.trim()) params.set("subject", rSubject.trim());
    if (rTaskId.trim()) params.set("task_id", rTaskId.trim());
    return `/api/analysis/results?${params.toString()}`;
  }, [rSize, rPage, verdict, rSubject, rTaskId]);

  const coverageUrl = React.useMemo(() => {
    const params = new URLSearchParams();
    params.set("days", String(days));
    params.set("limit", String(COVERAGE_LIMIT));
    if (covKind) params.set("kind", covKind);
    return `/api/analysis/coverage?${params.toString()}`;
  }, [days, covKind]);

  const inventoryUrl = React.useMemo(() => {
    const params = new URLSearchParams();
    params.set("limit", String(INVENTORY_LIMIT));
    if (invKind) params.set("kind", invKind);
    return `/api/analysis/inventory?${params.toString()}`;
  }, [invKind]);

  const loadStats = React.useCallback(async () => {
    await loadInto(errs, SRC.stats, "/api/analysis/stats", setStats);
  }, [errs]);

  const loadTasks = React.useCallback(async () => {
    await loadInto(errs, SRC.tasks, tasksUrl, setTasks);
  }, [errs, tasksUrl]);

  const loadConfig = React.useCallback(async () => {
    await loadInto(errs, SRC.config, "/api/analysis/config", setCfg);
  }, [errs]);

  const loadAll = React.useCallback(async () => {
    await Promise.all([loadStats(), loadTasks()]);
  }, [loadStats, loadTasks]);

  // 首屏：总览与参数（一次并发，别串行成多个 RTT）
  React.useEffect(() => {
    void (async () => {
      errs.reset();
      await Promise.all([loadStats(), loadConfig()]);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    void loadTasks();
  }, [loadTasks]);

  React.useEffect(() => {
    void loadInto(errs, SRC.results, resultsUrl, setResults);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resultsUrl]);

  React.useEffect(() => {
    void loadInto(errs, SRC.coverage, coverageUrl, setCoverage);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [coverageUrl]);

  React.useEffect(() => {
    void loadInto(errs, SRC.inventory, inventoryUrl, setInventory);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inventoryUrl]);

  // 自动刷新：任一浮层打开时**暂停**（避免冲掉正在读/填写的内容），手动刷新不受影响
  React.useEffect(() => {
    if (!auto) return undefined;
    const timer = window.setInterval(() => {
      if (modalOpen) return;
      void loadAll();
    }, REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [auto, modalOpen, loadAll]);

  // 浮层关闭后补一次：暂停期间可能已经变了，"恢复"要立刻看到最新而不是等下一个 tick
  const prevModal = React.useRef(false);
  React.useEffect(() => {
    const wasOpen = prevModal.current;
    prevModal.current = modalOpen;
    if (auto && wasOpen && !modalOpen) void loadAll();
  }, [auto, modalOpen, loadAll]);

  // ---------- 动作 ----------

  async function openDetail(id: string) {
    setDetailId(id);
    setDetail(null);
    setDetailBusy(true);
    await loadInto(errs, SRC.detail, `/api/analysis/tasks/${encodeURIComponent(id)}`, (data: AnalysisTaskDetail) =>
      setDetail(data),
    );
    setDetailBusy(false);
  }

  function resetManual() {
    setMSubject("");
    setMKind("ip");
    setMTaskKind("hit");
    setMNote("");
    setMStrength("0.6");
    setMError("");
    setMResult(null);
  }

  async function submitManual() {
    setMError("");
    setMResult(null);
    const subject = mSubject.trim().slice(0, 128);
    if (!subject) {
      setMError("要派工的对象（subject）不能为空");
      return;
    }
    const body: ManualTaskIn = {
      subject,
      subject_kind: mKind,
      kind: mTaskKind,
      note: mNote.slice(0, 500),
      // 越界会变成 422（body 是数组），提交前先 clamp
      strength: clampNumber(Number(mStrength), 0, 1, 0.6),
    };
    setMBusy(true);
    try {
      const out = await apiFetch<ManualTaskOut>("/api/analysis/tasks", {
        method: "POST",
        body: JSON.stringify(body),
      });
      setMResult(out);
      void loadStats();
      void loadTasks();
    } catch (error) {
      setMError(apiErrorText(error, "派工失败"));
    } finally {
      setMBusy(false);
    }
  }

  function knobValue(item: KnobItem): string | number | boolean {
    const current = cfg?.effective?.[item.key];
    return current === undefined ? item.default : current;
  }

  function knobDraftValue(item: KnobItem): string | number | boolean {
    const raw = draft[item.key];
    if (raw === undefined) return knobValue(item);
    if (item.kind === "int") return Math.trunc(Number(raw));
    if (item.kind === "float") return Number(raw);
    if (item.kind === "bool") return Boolean(raw);
    return raw;
  }

  function knobChanged(item: KnobItem): boolean {
    if (!(item.key in draft)) return false;
    const current = knobValue(item);
    const next = knobDraftValue(item);
    if (item.kind === "bool") return Boolean(current) !== Boolean(next);
    if (item.kind === "int" || item.kind === "float") return Number(current) !== Number(next);
    return String(current) !== String(next);
  }

  const dirtyKeys = (cfg?.items ?? []).filter((item) => knobChanged(item)).map((item) => item.key);

  async function saveParams() {
    setParamErrs({});
    setParamMsg("");
    if (!dirtyKeys.length) {
      setParamMsg("没有改动");
      return;
    }
    const values: Record<string, string | number | boolean> = {};
    for (const item of cfg?.items ?? []) {
      if (!knobChanged(item)) continue;
      values[item.key] = knobDraftValue(item);
    }
    // candidate_kinds 是逗号串，后端对 text 型空串会 400「不能为空」——
    // 但"清空类型"不等于"停用"，所以在这里拦住并给出正确做法。
    if ("analysis.candidate_kinds" in values && !String(values["analysis.candidate_kinds"] ?? "").trim()) {
      setParamErrs({
        "analysis.candidate_kinds": "至少保留 1 类线索；要整体停掉派工请关「启用派工队列」",
      });
      setParamMsg("请先修正参数里的问题");
      return;
    }
    setParamBusy(true);
    try {
      const data = await apiFetch<AnalysisConfigPayload>("/api/analysis/config", {
        method: "PUT",
        body: JSON.stringify({ values }),
      });
      setCfg(data);
      setDraft({});
      setParamMsg(`已保存 ${data.written ?? 0} 项 —— 参数改动 30 秒内生效`);
      void loadStats();
    } catch (error) {
      setParamErrs(fieldErrorsOf(error));
      setParamMsg(apiErrorText(error, "保存失败"));
    } finally {
      setParamBusy(false);
    }
  }

  async function resetParam(keys: string[]) {
    setParamErrs({});
    setParamMsg("");
    setParamBusy(true);
    try {
      const data = await apiFetch<AnalysisConfigPayload>("/api/analysis/config/reset", {
        method: "POST",
        body: JSON.stringify({ keys }),
      });
      setCfg(data);
      setDraft({});
      setParamMsg(`已恢复 ${data.removed ?? 0} 项为代码默认值`);
    } catch (error) {
      setParamMsg(apiErrorText(error, "恢复默认失败"));
    } finally {
      setParamBusy(false);
    }
  }

  // ---------- 派生值 ----------

  const counters = stats?.counters || {};
  const capacity = stats?.budget?.queue_capacity;
  const queueUsed = (stats?.pending ?? 0) + (stats?.deferred ?? 0);
  const kinds = cfg?.kinds?.length ? cfg.kinds : Object.keys(TASK_KIND_LABEL_FALLBACK);
  const verdicts = cfg?.verdicts?.length ? cfg.verdicts : [];
  const taskItems = tasks?.items ?? [];
  const resultItems = results?.items ?? [];
  const coverageItems = coverage?.items ?? [];
  const invKinds = Object.keys(inventory?.kinds ?? {});

  const tasksFailed = errs.isFailed(SRC.tasks) || Boolean(tasks?.error);
  const resultsFailed = errs.isFailed(SRC.results) || Boolean(results?.error);
  const coverageFailed = errs.isFailed(SRC.coverage) || Boolean(coverage?.error);
  const inventoryFailed = errs.isFailed(SRC.inventory) || Boolean(inventory?.error);
  const statsFailed = errs.isFailed(SRC.stats) || Boolean(stats?.error);

  // 失败用 Field 的内联错误（带 aria），这里只放"派工结果"的五出口文案
  const manualNotice = manualResult(mResult);
  const detailResults = detail?.results ?? [];

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      {/* ── ① 队列总览 ─────────────────────────────────────────────── */}
      <Section
        title="队列总览"
        description="队列里是客观线索（首见 / 自身基线偏离 / 盲区 / 规则命中），只含事实与客观强度，不含严重度与结论 —— 判断权在智能体。"
        extra={
          <>
            {stats ? (
              stats.enabled ? (
                <Badge variant="success">队列已启用</Badge>
              ) : (
                <Badge variant="medium">队列已关闭</Badge>
              )
            ) : null}
            <Button size="sm" variant="outline" onClick={() => void loadAll()}>
              刷新
            </Button>
            <Button size="sm" variant="outline" onClick={() => setParamOpen(true)}>
              参数…
            </Button>
          </>
        }
      >
        {!stats && !statsFailed ? (
          <StatSkeleton count={6} className="grid-cols-2 md:grid-cols-3 xl:grid-cols-6" />
        ) : (
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
            <Stat
              label="待派"
              value={stats ? numText(stats.pending) : "—"}
              size="md"
              hint="已入队、等智能体领取"
            />
            <Stat
              label="已派·在跑"
              value={stats ? numText(stats.claimed) : "—"}
              size="md"
              hint="租约内被某个令牌持有"
            />
            <Stat
              label="卡住"
              value={stats ? numText(stats.stuck) : "—"}
              size="md"
              hint="反复领取未交回，已停止派发"
            />
            <Stat
              label="已过期"
              value={stats ? numText(stats.by_state?.expired ?? 0) : "—"}
              size="md"
              hint="超有效期或被更强线索挤掉"
            />
            <Stat
              label="累计结论"
              value={stats ? numText(stats.results_total) : "—"}
              size="md"
              hint={stats ? `平均 ${stats.avg_tools_used} 次工具 · ${durationText(stats.avg_duration_ms)}` : undefined}
            />
            <Stat
              label="覆盖率"
              value={percentText(coverage?.coverage_ratio)}
              size="md"
              tone={
                typeof coverage?.coverage_ratio === "number" && coverage.coverage_ratio < 0.2 ? "medium" : "default"
              }
              hint={coverage ? `近 ${coverage.days} 天被分析过的对象占比` : "见下方「覆盖率与盲区」"}
            />
          </div>
        )}

        <div className="mt-3 flex flex-wrap items-center gap-3 rounded-xs bg-surface-1 px-3 py-2">
          <span className="text-xs text-muted-foreground">容量</span>
          <PressureBar
            used={queueUsed}
            capacity={capacity}
            dropped={counters.dropped_overflow}
            superseded={counters.superseded}
          />
          <span className="ml-auto flex flex-wrap items-center gap-1.5">
            <Badge variant="outline">单令牌 {numText(stats?.budget?.rate_per_token_hour)}/h</Badge>
            <Badge variant="outline">全局 {numText(stats?.budget?.rate_total_hour)}/h</Badge>
            <Badge variant="outline">并发 {numText(stats?.budget?.max_inflight)}</Badge>
            <Badge variant="outline">保留 {numText(stats?.budget?.reserved_slots)} 名</Badge>
            <Badge variant="outline">租约 {numText(stats?.budget?.lease_seconds)}s</Badge>
          </span>
        </div>
        {statsFailed ? (
          <p className="mt-2 text-xs text-sev-critical-fg">
            总览读取失败：数值显示为「—」而不是 0（后端或 Redis 不可用，不能当成「队列很安静」）。
          </p>
        ) : null}
      </Section>

      {/* ── ② 任务队列 ─────────────────────────────────────────────── */}
      <Section
        title="任务队列"
        description="按客观强度降序。界面只做浏览与人工派工 —— 领取/交回/延后是智能体的 MCP 通道（带令牌配额），这里不提供。"
      >
        <Card>
          <PanelToolbar
            search={
              <div className="space-y-1">
                <Input
                  className="h-8"
                  aria-label="按对象或备注搜索"
                  placeholder="搜对象或备注"
                  value={q}
                  onChange={(event) => {
                    setQ(event.target.value);
                    setPage(0);
                  }}
                />
                <p className="text-xs text-muted-foreground">按对象名搜索更准（备注命中时列表里看不出为什么匹配）</p>
              </div>
            }
          >
            <div className="flex flex-wrap items-center gap-1" role="radiogroup" aria-label="按状态筛选">
              <Button
                size="sm"
                variant={state === "" ? "default" : "outline"}
                role="radio"
                aria-checked={state === ""}
                onClick={() => {
                  setState("");
                  setPage(0);
                }}
              >
                全部
              </Button>
              {TASK_STATES.map((value) => (
                <Button
                  key={value}
                  size="sm"
                  variant={state === value ? "default" : "outline"}
                  role="radio"
                  aria-checked={state === value}
                  onClick={() => {
                    setState(value);
                    setPage(0);
                  }}
                >
                  {TASK_STATE_LABEL[value] ?? value}
                </Button>
              ))}
            </div>
            <select
              aria-label="按线索类型筛选"
              value={kind}
              onChange={(event) => {
                setKind(event.target.value);
                setPage(0);
              }}
              className="h-8 rounded-sm border border-input bg-surface-2 px-2 text-13"
            >
              <option value="">全部类型</option>
              {kinds.map((value) => (
                <option key={value} value={value}>
                  {taskKindLabel(value)}
                </option>
              ))}
            </select>
            <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Switch label="自动刷新" checked={auto} onCheckedChange={setAuto} />
              自动刷新
            </span>
            <Button size="sm" variant="outline" onClick={() => void loadAll()}>
              刷新
            </Button>
            <Button size="sm" onClick={() => setManualOpen(true)}>
              ＋人工派工
            </Button>
          </PanelToolbar>

          {auto && modalOpen ? (
            <p className="border-b border-border-subtle bg-surface-1 px-3 py-1.5 text-xs text-muted-foreground">
              自动刷新已暂停（浮层打开中）；关闭后立即刷新一次并恢复计时。
            </p>
          ) : null}

          {tasks === null && !tasksFailed ? (
            <TableSkeleton rows={8} cols={8} />
          ) : taskItems.length ? (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-16">强度</TableHead>
                    <TableHead>对象</TableHead>
                    <TableHead className="w-24">类型</TableHead>
                    <TableHead className="w-24">状态</TableHead>
                    <TableHead>线索摘要</TableHead>
                    <TableHead className="w-20">合并/尝试</TableHead>
                    <TableHead className="w-32">时效</TableHead>
                    <TableHead className="w-12">详情</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {taskItems.map((task: AnalysisTaskItem) => {
                    const rest = remainingHours(task, stats?.budget?.pending_ttl_hours);
                    const soon = rest !== null && rest > 0 && rest < 6;
                    return (
                      <TableRow
                        key={task.id}
                        tabIndex={0}
                        className="cursor-pointer"
                        aria-label={`${task.subject}，${taskKindLabel(task.kind)}，${taskStateLabel(task.state)}，查看详情`}
                        onClick={() => void openDetail(task.id)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            void openDetail(task.id);
                          }
                        }}
                      >
                        <TableCell className="tabular-nums">{task.strength.toFixed(3)}</TableCell>
                        <TableCell className="min-w-0">
                          <span className="font-mono text-xs text-foreground">{task.subject || "—"}</span>
                          <Badge variant="outline" className="ml-1">
                            {subjectKindLabel(task.subject_kind)}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{taskKindLabel(task.kind)}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={taskStateVariant(task.state)}>{taskStateLabel(task.state)}</Badge>
                        </TableCell>
                        <TableCell className="min-w-0">
                          <span className="block truncate text-muted-foreground" title={hintSummary(task.hint)}>
                            {hintSummary(task.hint)}
                          </span>
                        </TableCell>
                        <TableCell
                          className="tabular-nums text-muted-foreground"
                          title={`同族合并 ${task.coalesced} 次 · 被领取 ${task.attempts} 次`}
                        >
                          {task.coalesced}/{task.attempts}
                        </TableCell>
                        <TableCell className={cn("tabular-nums", soon && "text-sev-medium-fg")}>
                          <span className="block text-xs">{formatDateTime(task.created_at)}</span>
                          <span className="block text-xs">{remainingText(rest)}</span>
                        </TableCell>
                        <TableCell>
                          {/* 行本身已是入口（整行 tabIndex=0 + Enter），这里只做鼠标/触摸的显式落点，
                              所以用图标而不是带文字的按钮 —— 免得一屏 8 列里挤进 20 个「查看」 */}
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 w-7 px-0"
                            aria-label={`查看 ${task.subject} 的详情`}
                            onClick={(event) => {
                              event.stopPropagation();
                              void openDetail(task.id);
                            }}
                          >
                            <ChevronRight className="h-4 w-4" aria-hidden />
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              <div className="px-3 py-2">
                <Pagination
                  page={page}
                  pages={Math.max(1, Math.ceil((tasks?.total ?? 0) / size))}
                  total={tasks?.total ?? 0}
                  size={size}
                  onPage={setPage}
                  onSize={(next) => {
                    setSize(next);
                    setPage(0);
                  }}
                />
              </div>
            </>
          ) : (
            <EmptyState
              tone={tasksFailed ? "danger" : "muted"}
              title={emptyOrFailed(errs, SRC.tasks, state ? "该筛选下没有任务" : "队列里没有待派线索")}
              hint={
                tasksFailed
                  ? "见上方错误条：后端读库失败，不能当成「没有线索」"
                  : state
                    ? "换一个状态或清空筛选试试；线索由检测器按候选规则生成"
                    : "线索由检测器按候选规则生成，每个节拍（flush_seconds）评估一次"
              }
              action={
                <Button size="sm" variant="outline" onClick={() => void loadAll()}>
                  重新读取
                </Button>
              }
            />
          )}
        </Card>
      </Section>

      {/* ── ③ 任务结论 ─────────────────────────────────────────────── */}
      <Section
        title="任务结论"
        description="智能体交回的判定（verdict）与成本口径；可按结论/对象/任务精确筛（没有关键词搜索）。"
      >
        <Card>
          <PanelToolbar
            search={
              <div className="flex flex-wrap items-center gap-1" role="radiogroup" aria-label="按结论筛选">
                <Button
                  size="sm"
                  variant={verdict === "" ? "default" : "outline"}
                  role="radio"
                  aria-checked={verdict === ""}
                  onClick={() => {
                    setVerdict("");
                    setRPage(0);
                  }}
                >
                  全部
                </Button>
                {verdicts.map((value) => (
                  <Button
                    key={value}
                    size="sm"
                    variant={verdict === value ? "default" : "outline"}
                    role="radio"
                    aria-checked={verdict === value}
                    onClick={() => {
                      setVerdict(value);
                      setRPage(0);
                    }}
                  >
                    {verdictLabel(value)}
                  </Button>
                ))}
              </div>
            }
          >
            <Input
              className="h-8 w-44"
              aria-label="按对象精确筛选"
              placeholder="对象（精确）"
              value={rSubject}
              onChange={(event) => {
                setRSubject(event.target.value);
                setRPage(0);
              }}
            />
            <Input
              className="h-8 w-44"
              aria-label="按任务 ID 筛选"
              placeholder="任务 ID（精确）"
              value={rTaskId}
              onChange={(event) => {
                setRTaskId(event.target.value);
                setRPage(0);
              }}
            />
            <Button
              size="sm"
              variant="outline"
              onClick={() => void loadInto(errs, SRC.results, resultsUrl, setResults)}
            >
              刷新
            </Button>
          </PanelToolbar>

          {results === null && !resultsFailed ? (
            <TableSkeleton rows={6} cols={9} />
          ) : resultItems.length ? (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">结论</TableHead>
                    <TableHead className="w-16">置信度</TableHead>
                    <TableHead>对象</TableHead>
                    <TableHead>摘要</TableHead>
                    <TableHead className="w-24">证据/工具</TableHead>
                    <TableHead className="w-20">耗时</TableHead>
                    <TableHead className="w-28">结论人</TableHead>
                    <TableHead className="w-36">时间</TableHead>
                    <TableHead className="w-20">关联任务</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {resultItems.map((row: AnalysisResultItem) => (
                    <TableRow key={row.id}>
                      <TableCell>
                        <Badge variant={verdictVariant(row.verdict)}>{verdictLabel(row.verdict)}</Badge>
                      </TableCell>
                      <TableCell className="tabular-nums">{row.confidence.toFixed(2)}</TableCell>
                      <TableCell className="min-w-0">
                        <span className="font-mono text-xs">{row.subject || "—"}</span>
                        <Badge variant="outline" className="ml-1">
                          {subjectKindLabel(row.subject_kind)}
                        </Badge>
                      </TableCell>
                      <TableCell className="min-w-0">
                        <span className="block truncate text-muted-foreground" title={row.summary}>
                          {row.summary || "—"}
                        </span>
                      </TableCell>
                      <TableCell className="tabular-nums text-muted-foreground">
                        {row.evidence_refs.length} 条 · {row.tools_used} 次
                      </TableCell>
                      <TableCell className="tabular-nums text-muted-foreground">
                        {durationText(row.duration_ms)}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {row.claimed_by || "—"}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {formatDateTime(row.created_at)}
                      </TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setRTaskId(row.task_id);
                            setRPage(0);
                          }}
                        >
                          查看
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <div className="px-3 py-2">
                <Pagination
                  page={rPage}
                  pages={Math.max(1, Math.ceil((results?.total ?? 0) / rSize))}
                  total={results?.total ?? 0}
                  size={rSize}
                  onPage={setRPage}
                  onSize={(next) => {
                    setRSize(next);
                    setRPage(0);
                  }}
                />
              </div>
            </>
          ) : (
            <EmptyState
              tone={resultsFailed ? "danger" : "muted"}
              title={emptyOrFailed(errs, SRC.results, "还没有交回的结论")}
              hint={
                resultsFailed
                  ? "见上方错误条：后端读库失败，不能当成「还没结论」"
                  : "智能体领走任务并交回结论后才出现；先看队列里已派的任务"
              }
              action={
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => void loadInto(errs, SRC.results, resultsUrl, setResults)}
                >
                  重新读取
                </Button>
              }
            />
          )}
        </Card>
      </Section>

      {/* ── ④ 覆盖率与盲区 ─────────────────────────────────────────── */}
      <Section
        title="覆盖率与盲区"
        description="验收指标：近 N 天有多少对象被分析过、哪些从来没看过。计数一律用返回的条数（接口的 returned 是切片前长度）。"
        extra={
          <>
            <div className="flex items-center gap-1" role="radiogroup" aria-label="时间窗">
              {[7, 14, 30].map((value) => (
                <Button
                  key={value}
                  size="sm"
                  variant={days === value ? "default" : "outline"}
                  role="radio"
                  aria-checked={days === value}
                  onClick={() => setDays(value)}
                >
                  {value} 天
                </Button>
              ))}
            </div>
            <select
              aria-label="按对象类型筛选"
              value={covKind}
              onChange={(event) => setCovKind(event.target.value)}
              className="h-8 rounded-sm border border-input bg-surface-2 px-2 text-13"
            >
              <option value="">全部类型</option>
              {["asset", "service_port", "peer", "protocol", "signature", "account"].map((value) => (
                <option key={value} value={value}>
                  {subjectKindLabel(value)}
                </option>
              ))}
            </select>
            <Button
              size="sm"
              variant="outline"
              onClick={() => void loadInto(errs, SRC.coverage, coverageUrl, setCoverage)}
            >
              刷新
            </Button>
          </>
        }
      >
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          <Stat label="窗口内对象" value={coverage ? numText(coverage.subjects_total) : "—"} size="md" />
          <Stat label="已分析" value={coverage ? numText(coverage.analyzed) : "—"} size="md" />
          <Stat
            label="覆盖率"
            value={percentText(coverage?.coverage_ratio)}
            size="md"
            tone={
              typeof coverage?.coverage_ratio === "number" && coverage.coverage_ratio < 0.2 ? "medium" : "default"
            }
          />
          <Stat
            label="盲区清单"
            value={coverage ? numText(coverageItems.length) : "—"}
            size="md"
            hint={
              coverage
                ? `从未分析 ${numText(coverage.never_analyzed)} · 久未分析 ${numText(coverage.stale)}（后端各自最多 ${COVERAGE_LIMIT} 条，不可相加当总数）`
                : undefined
            }
          />
        </div>

        <SettingsGrid className="mt-3">
          <SettingsMain>
            <Card>
              <CardContent className="pt-4">
                {coverage === null && !coverageFailed ? (
                  <TableSkeleton rows={6} cols={7} />
                ) : coverageItems.length ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>对象类型</TableHead>
                        <TableHead>对象</TableHead>
                        <TableHead className="w-24">原因</TableHead>
                        <TableHead className="w-36">首见</TableHead>
                        <TableHead className="w-36">最近出现</TableHead>
                        <TableHead className="w-20">出现次数</TableHead>
                        <TableHead className="w-20">已分析</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {coverageItems.map((row, index) => (
                        <TableRow key={`${row.subject_kind}-${row.subject}-${index}`}>
                          <TableCell className="text-muted-foreground">
                            {subjectKindLabel(row.subject_kind)}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{row.subject}</TableCell>
                          <TableCell>
                            <Badge variant={row.why === "从未分析" ? "medium" : "outline"}>{row.why}</Badge>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {formatDateTime(row.first_seen_at)}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {formatDateTime(row.last_seen_at)}
                          </TableCell>
                          <TableCell className="tabular-nums">{row.seen_count}</TableCell>
                          <TableCell className="tabular-nums">{row.analyzed_count}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : coverageFailed ? (
                  <EmptyState
                    tone="danger"
                    size="compact"
                    title={emptyOrFailed(errs, SRC.coverage, "盲区清单读取失败")}
                    hint="见上方错误条：后端读库失败，不能当成「全都覆盖到了」"
                  />
                ) : (
                  // 表空 = 好消息（窗口内对象都看过），别用中性灰画成"没数据"
                  <div className="rounded-sm border border-sev-ok-bd bg-sev-ok-bg">
                    <EmptyState
                      size="compact"
                      title="近几天没有漏掉的对象"
                      hint={`近 ${days} 天出现过的对象都至少被分析过一次（计数口径见右栏）`}
                    />
                  </div>
                )}
              </CardContent>
            </Card>
          </SettingsMain>
          <SettingsRail>
            <Card>
              <CardContent className="space-y-2 pt-4 text-xs leading-relaxed text-muted-foreground">
                <p className="text-sm font-medium text-foreground">验收口径</p>
                <p>
                  分母 = 窗口内 <span className="font-mono">last_seen_at</span> 在近 {days} 天内的登记对象；
                  分子 = 其中 <span className="font-mono">last_analyzed_at</span> 也在窗口内的对象。
                </p>
                <p>「从未分析」优先列出，「久未分析」其次；清单条数受 limit 限制，所以上方计数用返回条数。</p>
                <p>盲区欠账不是事故：它只说明还没轮到，红只留给卡住与超容量。</p>
              </CardContent>
            </Card>
          </SettingsRail>
        </SettingsGrid>
      </Section>

      {/* ── ⑤ 对象清单（数据地图） ─────────────────────────────────── */}
      <Section
        title="对象清单（数据地图）"
        description="NDR 见过的可分析对象（资产 / 端口 / 对端 / 协议 / 签名 / 账号）。这是 novelty 与覆盖率的底层登记表。"
        extra={
          <div className="flex flex-wrap items-center gap-1" role="tablist" aria-label="对象类型">
            <Button
              size="sm"
              variant={invKind === "" ? "default" : "outline"}
              role="tab"
              aria-selected={invKind === ""}
              onClick={() => setInvKind("")}
            >
              全部
            </Button>
            {(inventory?.known_kinds ?? []).map((value) => (
              <Button
                key={value}
                size="sm"
                variant={invKind === value ? "default" : "outline"}
                role="tab"
                aria-selected={invKind === value}
                onClick={() => setInvKind(value)}
              >
                {subjectKindLabel(value)}
              </Button>
            ))}
          </div>
        }
      >
        <Card>
          <CardContent className="pt-4">
            {inventory === null && !inventoryFailed ? (
              <TableSkeleton rows={5} cols={5} />
            ) : invKinds.length ? (
              <div className="space-y-4">
                {invKinds.map((kindKey) => {
                  const group = inventory?.kinds?.[kindKey];
                  if (!group) return null;
                  return (
                    <div key={kindKey} className="space-y-1.5">
                      <p className="text-xs text-muted-foreground">
                        {subjectKindLabel(kindKey)}：共{" "}
                        <span className="tabular-nums text-foreground">{group.count}</span> 个，本次列{" "}
                        <span className="tabular-nums">{group.items.length}</span> 个
                      </p>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>对象</TableHead>
                            <TableHead className="w-24">类型</TableHead>
                            <TableHead className="w-36">最近出现</TableHead>
                            <TableHead className="w-20">出现次数</TableHead>
                            <TableHead className="w-20">已分析</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {group.items.map((row) => (
                            <TableRow key={`${kindKey}-${row.value}`}>
                              <TableCell className="font-mono text-xs">{row.value}</TableCell>
                              <TableCell className="text-muted-foreground">
                                {subjectKindLabel(kindKey)}
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {formatDateTime(row.last_seen_at)}
                              </TableCell>
                              <TableCell className="tabular-nums">{row.seen_count}</TableCell>
                              <TableCell className="tabular-nums">{row.analyzed_count}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  );
                })}
              </div>
            ) : (
              <EmptyState
                tone={inventoryFailed ? "danger" : "muted"}
                size="compact"
                title={emptyOrFailed(errs, SRC.inventory, "还没有登记任何对象")}
                hint={
                  inventoryFailed
                    ? "见上方错误条：后端读库失败，不能当成「没有数据」"
                    : "检测器见到新对象时会自动登记；首见登记表按保留期清理"
                }
              />
            )}
          </CardContent>
        </Card>
      </Section>

      {/* ── 浮层 1：任务详情 ──────────────────────────────────────── */}
      <Drawer
        open={Boolean(detailId)}
        title={
          <span className="flex flex-wrap items-center gap-2">
            任务详情
            {detail ? <Badge variant={taskStateVariant(detail.state)}>{taskStateLabel(detail.state)}</Badge> : null}
          </span>
        }
        widthClass="w-[720px]"
        onClose={() => setDetailId("")}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setDetailId("")}>
              关闭
            </Button>
            {detail ? (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setRTaskId(detail.id);
                  setRPage(0);
                  setDetailId("");
                }}
              >
                在结论页查看该任务
              </Button>
            ) : null}
          </>
        }
      >
        {detailBusy && !detail ? (
          <div className="space-y-2">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-4/5" />
            <Skeleton className="h-24 w-full" />
          </div>
        ) : detail?.error ? (
          <EmptyState
            tone="danger"
            size="compact"
            title="任务不存在或读取失败"
            hint={detail.error}
          />
        ) : detail ? (
          <div className="space-y-4">
            <Section title={detail.subject || "—"} divided={false}>
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <span className="font-mono">{detail.id}</span>
                <Badge variant="outline">{taskKindLabel(detail.kind)}</Badge>
                <Badge variant="outline">{subjectKindLabel(detail.subject_kind)}</Badge>
                <span className="tabular-nums">强度 {detail.strength.toFixed(3)}</span>
                <span className="tabular-nums">优先级 {detail.priority}</span>
              </div>
            </Section>

            <Section title="时间窗与血缘" divided={false}>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
                <dt className="text-muted-foreground">建议窗口</dt>
                <dd className="tabular-nums">
                  {detail.window_start ? formatDateTime(detail.window_start) : "—"} →{" "}
                  {detail.window_end ? formatDateTime(detail.window_end) : "—"}
                </dd>
                <dt className="text-muted-foreground">创建时间</dt>
                <dd className="tabular-nums">{formatDateTime(detail.created_at)}</dd>
                <dt className="text-muted-foreground">同族合并 / 被领取</dt>
                <dd className="tabular-nums">
                  {detail.coalesced} / {detail.attempts}
                </dd>
                <dt className="text-muted-foreground">追问深度</dt>
                <dd className="tabular-nums">{detail.depth}</dd>
                <dt className="text-muted-foreground">父任务</dt>
                <dd className="font-mono">{detail.parent_id || "—"}</dd>
              </dl>
              <p className="mt-2 text-xs text-muted-foreground">
                结束原因（note）当前接口不返回，所以「为什么过期/被延后」只能看状态与时间。
              </p>
            </Section>

            <Section title="线索（hint 全量，客观事实，不含结论）" divided={false}>
              <div className="space-y-1.5">
                <div className="flex flex-wrap gap-1">
                  {Array.isArray(detail.hint?.suggested_tools)
                    ? (detail.hint.suggested_tools as unknown[]).map((tool) => (
                        <Badge key={String(tool)} variant="outline">
                          {String(tool)}
                        </Badge>
                      ))
                    : null}
                </div>
                <dl className="grid grid-cols-[8rem_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
                  {Object.entries(detail.hint || {})
                    .filter(([key]) => key !== "suggested_tools")
                    .map(([key, value]) => (
                      <React.Fragment key={key}>
                        <dt className="truncate text-muted-foreground" title={key}>
                          {key}
                        </dt>
                        <dd className="min-w-0 break-words">
                          {value !== null && typeof value === "object" ? (
                            <pre
                              tabIndex={0}
                              className="max-h-56 overflow-auto rounded-xs bg-surface-1 p-2 font-mono text-xs"
                            >
                              {JSON.stringify(value, null, 2)}
                            </pre>
                          ) : (
                            <span className="font-mono">{String(value ?? "—")}</span>
                          )}
                        </dd>
                      </React.Fragment>
                    ))}
                </dl>
              </div>
            </Section>

            <Section title={`该任务的历史结论（${detailResults.length}）`} divided={false}>
              {detailResults.length ? (
                <ul className="space-y-2">
                  {detailResults.map((row, index) => (
                    <li key={index} className="rounded-xs bg-surface-1 px-3 py-2">
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <Badge variant={verdictVariant(row.verdict)}>{verdictLabel(row.verdict)}</Badge>
                        <span className="tabular-nums text-muted-foreground">
                          置信度 {row.confidence.toFixed(2)}
                        </span>
                        <span className="font-mono text-muted-foreground">{row.claimed_by || "—"}</span>
                        <span className="tabular-nums text-muted-foreground">
                          {formatDateTime(row.created_at)}
                        </span>
                      </div>
                      <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-foreground">{row.summary}</p>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState size="compact" title="这条任务还没有结论" hint="智能体交回结论后会出现在这里" />
              )}
            </Section>
          </div>
        ) : null}
      </Drawer>

      {/* ── 浮层 2：人工派工 ──────────────────────────────────────── */}
      <Dialog
        open={manualOpen}
        title="人工派工"
        widthClass="w-[560px]"
        onClose={() => setManualOpen(false)}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setManualOpen(false)}>
              关闭
            </Button>
            <Button size="sm" onClick={() => void submitManual()} disabled={mBusy}>
              {mBusy ? "派工中…" : "派工"}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="rounded-xs bg-surface-1 px-3 py-2 text-xs leading-relaxed text-muted-foreground">
            人工派工走同一套去重与容量规则，<b>不插队</b>；满队列时同样可能被挤掉或丢弃。
          </p>
          <Field label="对象" required error={mError || undefined} hint="IP / 网段 / 账号；必填">
            <Input
              value={mSubject}
              aria-label="派工对象"
              placeholder="例如 10.0.0.5"
              maxLength={128}
              onChange={(event) => setMSubject(event.target.value)}
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="对象类型">
              <select
                aria-label="对象类型"
                value={mKind}
                onChange={(event) => setMKind(event.target.value)}
                className="h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-sm"
              >
                {SUBJECT_KINDS.map((value) => (
                  <option key={value} value={value}>
                    {subjectKindLabel(value)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="线索类型">
              <select
                aria-label="线索类型"
                value={mTaskKind}
                onChange={(event) => setMTaskKind(event.target.value)}
                className="h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-sm"
              >
                {kinds.map((value) => (
                  <option key={value} value={value}>
                    {taskKindLabel(value)}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="备注" hint="≤500；会记进 hint 的「备注」并附上操作人">
            <Input
              value={mNote}
              aria-label="备注"
              maxLength={500}
              placeholder="为什么想看看这台"
              onChange={(event) => setMNote(event.target.value)}
            />
          </Field>
          <Field label="客观强度" hint="0~1，默认 0.6；越界会被后端拒（422）">
            <Input
              type="number"
              step="0.05"
              min={0}
              max={1}
              value={mStrength}
              aria-label="客观强度"
              onChange={(event) => setMStrength(event.target.value)}
            />
          </Field>

          {manualNotice ? (
            <p
              role={manualNotice.tone === "err" ? "alert" : "status"}
              className={cn(
                "rounded-xs border px-3 py-2 text-xs",
                manualNotice.tone === "err"
                  ? "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg"
                  : manualNotice.tone === "warn"
                    ? "border-sev-medium-bd bg-sev-medium-bg text-sev-medium-fg"
                    : manualNotice.tone === "ok"
                      ? "border-sev-ok-bd bg-sev-ok-bg text-sev-ok-fg"
                      : "border-border-subtle bg-surface-1 text-muted-foreground",
              )}
            >
              {manualNotice.text}
            </p>
          ) : null}

          <div className="flex justify-end">
            <Button size="sm" variant="ghost" onClick={resetManual} disabled={mBusy}>
              清空
            </Button>
          </div>
        </div>
      </Dialog>

      {/* ── 浮层 3：派工参数 ──────────────────────────────────────── */}
      <Drawer
        open={paramOpen}
        title="派工参数"
        widthClass="w-[720px]"
        onClose={() => setParamOpen(false)}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setParamOpen(false)}>
              关闭
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={paramBusy || !dirtyKeys.length}
              onClick={() => setDraft({})}
            >
              撤销改动
            </Button>
            <Button size="sm" onClick={() => void saveParams()} disabled={paramBusy}>
              {paramBusy ? "保存中…" : "保存"}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <p className="rounded-xs bg-surface-1 px-3 py-2 text-xs leading-relaxed text-muted-foreground">
            参数改动 <b>30 秒内生效</b>（不是抑制页的 45 秒）。恢复默认 = 删掉数据库里的覆盖值，
            会落回<b>代码默认值</b>，不是"当前值"。
          </p>
          {paramMsg ? (
            <p
              role="status"
              className={cn(
                "rounded-xs border px-3 py-2 text-xs",
                Object.keys(paramErrs).length
                  ? "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg"
                  : "border-border-subtle bg-surface-1 text-muted-foreground",
              )}
            >
              {paramMsg}
            </p>
          ) : null}

          {!cfg ? (
            <div className="space-y-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : (
            PARAM_GROUPS.map((group) => {
              const items = group.keys
                .map((key) => cfg.items.find((item) => item.key === key))
                .filter((item): item is KnobItem => Boolean(item));
              if (!items.length) return null;
              return (
                <Section key={group.title} title={group.title} description={group.hint} divided={false}>
                  <div className="space-y-2">
                    {items.map((item) => {
                      // candidate_kinds 是逗号串（text 型）：不允许手敲，改成 5 个勾选
                      if (item.key === "analysis.candidate_kinds") {
                        const current = String(knobDraftValue(item) || "");
                        const picked = current
                          .split(",")
                          .map((part) => part.trim())
                          .filter(Boolean);
                        const allKinds = cfg.kinds?.length ? cfg.kinds : Object.keys(KIND_LABEL_FALLBACK);
                        return (
                          <div key={item.key} className="rounded-xs bg-surface-1 px-3 py-2">
                            <div className="mb-1 flex flex-wrap items-center gap-2">
                              <span className="text-sm font-medium text-foreground">{item.label}</span>
                              {item.overridden ? (
                                <Badge variant="secondary">已改</Badge>
                              ) : (
                                <Badge variant="outline">默认</Badge>
                              )}
                              {knobChanged(item) ? <Badge variant="high">未保存</Badge> : null}
                              <span className="font-mono text-xs text-muted-foreground">{item.key}</span>
                            </div>
                            <div className="flex flex-wrap items-center gap-3">
                              {allKinds.map((kindValue) => (
                                <label key={kindValue} className="flex items-center gap-1.5 text-13">
                                  <input
                                    type="checkbox"
                                    className="h-4 w-4"
                                    checked={picked.includes(kindValue)}
                                    onChange={(event) => {
                                      const next = event.target.checked
                                        ? [...picked, kindValue]
                                        : picked.filter((part) => part !== kindValue);
                                      setDraft({ ...draft, [item.key]: next.join(",") });
                                    }}
                                  />
                                  {taskKindLabel(kindValue)}
                                </label>
                              ))}
                            </div>
                            {paramErrs[item.key] ? (
                              <p className="mt-1 text-xs text-sev-critical-fg">{paramErrs[item.key]}</p>
                            ) : null}
                            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                              至少保留 1 类线索。要整体停掉派工，请关「启用派工队列」—— 把类型清空不等于停用
                              （后端会拒空串）。
                            </p>
                          </div>
                        );
                      }
                      return (
                        <KnobRow
                          key={item.key}
                          item={item}
                          value={knobDraftValue(item)}
                          dirty={knobChanged(item)}
                          error={paramErrs[item.key]}
                          disabled={paramBusy}
                          onChange={(next) => setDraft({ ...draft, [item.key]: next })}
                          onReset={() => void resetParam([item.key])}
                        />
                      );
                    })}
                  </div>
                </Section>
              );
            })
          )}

          <div className="flex justify-end">
            <Button
              size="sm"
              variant="ghost"
              disabled={paramBusy}
              onClick={() => void resetParam([])}
            >
              全部恢复默认
            </Button>
          </div>
        </div>
      </Drawer>
    </div>
  );
}

/** `cfg` 未取回时的兜底类型表（与 `analysis/params.py::KINDS` 一致）。 */
const KIND_LABEL_FALLBACK: Record<string, string> = {
  novelty: "新现象",
  shift: "漂移",
  structure: "结构",
  coverage: "覆盖",
  hit: "命中",
};

const TASK_KIND_LABEL_FALLBACK: Record<string, string> = KIND_LABEL_FALLBACK;
