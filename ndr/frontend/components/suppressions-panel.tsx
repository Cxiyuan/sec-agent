"use client";

import * as React from "react";
import { AlertTriangle, Ban, BellOff } from "lucide-react";
import {
  Badge,
  Button,
  Dialog,
  Drawer,
  EmptyState,
  Field,
  Input,
  Pagination,
  PanelToolbar,
  Section,
  SettingsBlock,
  SettingsBoard,
  Skeleton,
  Stat,
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
import { ConditionEditor, type Cond } from "@/components/condition-editor";
import { emptyOrFailed, loadInto, PanelError, usePanelErrors } from "@/components/panel-error";
import {
  ALLOWED_FIELDS_FALLBACK,
  DEFAULT_TTL_DAYS,
  LIMITS,
  PROTOCOL_SUGGESTIONS,
  REASON_CODE_FALLBACK,
  REASON_CODE_ORDER,
  REVOKE_REASON_CHIPS,
  apiErrorText,
  clampNumber,
  condsToMatch,
  fieldErrorsOf,
  matchDims,
  matchSummary,
  matchToConds,
  modeSentence,
  modeShort,
  modeVariant,
  nearHitCap,
  numText,
  revokeCause,
  suppressionState,
  type SuppressionCond,
} from "@/lib/analysis";
import {
  ApiError,
  apiFetch,
  type KnobItem,
  type SuppressionConfigPayload,
  type SuppressionIn,
  type SuppressionItem,
  type SuppressionListPayload,
  type SuppressionMatch,
  type SuppressionPreviewOut,
  type SuppressionStats,
} from "@/lib/api";

/**
 * 精准抑制（`/config/suppressions`）：总览（含两种 mode 对照）+ 清单 + 参数门槛 + 三个浮层。
 *
 * 这个页面最危险的路径是「新建/改条件 → 保存后不再生成事件」，所以：
 * - **任何提交前必须过一次试算**并把影响面回显（未试算则点击时先试算，再点一次才保存）；
 * - 试算内部失败（200 + `events=-1`）**仍可保存**，但影响面必须写"未知"、模式自动按 `record_only`；
 * - 只有 `invalid`（400 field=match）与 `netfail`（网络/5xx）才置灰保存。
 *
 * 口径（都核过源码，别改）：
 * 1. 清单**恒传 `include_expired=true`**：后端默认 false，且是"先分页后过滤" → 会造出「total 含过期、本页变少、翻页空页」；
 * 2. `enabled` 与 `expired` 正交，状态列按 **已撤销 > 已过期 > 生效中** 取唯一值；
 * 3. `hits` 是内存攒批、**每 30 秒** flush → 命中列写「约 30 秒内更新」，不写"实时"；
 * 4. 编辑（PUT）后端只落 `match / reason_code / evidence_refs / expires_at` → `name` 只读、`note`/`confidence` 只读。
 */

const SRC = {
  list: "抑制清单（/api/suppressions）",
  stats: "抑制总览（/api/suppressions/stats）",
  config: "抑制参数（/api/suppressions/config）",
} as const;

const PAGE_SIZE = 20;

/** 参数抽屉的分组（15 个 `suppression.*` 键，按"门槛 → 容量 → 试算 → 缓存"排） */
const PARAM_GROUPS: { title: string; hint: string; keys: string[] }[] = [
  {
    title: "开关与门槛",
    hint: "自动生效总开关，以及自动抑制必须满足的最低维度/证据/置信度（后三道只对智能体生效，界面人工创建不受限）",
    keys: [
      "suppression.enabled",
      "suppression.auto_apply",
      "suppression.min_match_dims",
      "suppression.min_refs",
      "suppression.min_tools",
      "suppression.min_confidence",
    ],
  },
  {
    title: "有效期与容量",
    hint: "默认有效期；活跃条目超上限时淘汰最早到期的一条；单条吞量超熔断阈值会被自动撤销",
    keys: ["suppression.default_ttl_days", "suppression.max_active", "suppression.hit_cap"],
  },
  {
    title: "试算门槛（爆炸半径）",
    hint: "近 N 天命中/源数/网段数任一超限 → 自动降级为「只不派工」，不会静默掉一整类流量",
    keys: [
      "suppression.trial_days",
      "suppression.trial_max_hits",
      "suppression.trial_max_srcs",
      "suppression.trial_max_segments",
      "suppression.newcomer_hours",
    ],
  },
  {
    title: "缓存",
    hint: "匹配集合的进程内缓存；新增/撤销会立刻失效，改参数最迟这么久收敛到采集侧",
    keys: ["suppression.cache_seconds"],
  },
];

type TrialState = "idle" | "debouncing" | "trialing" | "success" | "degraded" | "invalid" | "netfail";

/** 到期列的文案：≤3 天转 medium 字色（不加第三个徽章）。 */
function expiryOf(iso: string | null): { text: string; urgent: boolean } {
  if (!iso) return { text: "—", urgent: false };
  const diff = Date.parse(iso) - Date.now();
  if (!Number.isFinite(diff)) return { text: "—", urgent: false };
  if (diff <= 0) return { text: "已过期", urgent: false };
  const days = diff / 86_400_000;
  if (days <= 3) return { text: `剩 ${Math.max(1, Math.ceil(days))} 天`, urgent: true };
  return { text: `剩 ${Math.ceil(days)} 天`, urgent: false };
}

/** 参数的一行（与派工队列同一套渲染；`value` 来自 `effective[key]`，item 没有 value）。 */
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

export function SuppressionsPanel() {
  const errs = usePanelErrors();

  const [list, setList] = React.useState<SuppressionListPayload | null>(null);
  const [stats, setStats] = React.useState<SuppressionStats | null>(null);
  const [cfg, setCfg] = React.useState<SuppressionConfigPayload | null>(null);

  const [q, setQ] = React.useState("");
  const [enabledOnly, setEnabledOnly] = React.useState(false);
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(PAGE_SIZE);

  // 新建/编辑抽屉
  const [formOpen, setFormOpen] = React.useState(false);
  const [editId, setEditId] = React.useState("");
  const [name, setName] = React.useState("");
  const [matchLogic, setMatchLogic] = React.useState("and");
  const [conds, setConds] = React.useState<SuppressionCond[]>([{ field: "signature_id", op: "eq", value: "" }]);
  const [reasonCode, setReasonCode] = React.useState("");
  const [note, setNote] = React.useState("");
  const [evidenceText, setEvidenceText] = React.useState("");
  const [confidence, setConfidence] = React.useState("0");
  const [ttlDays, setTtlDays] = React.useState("");
  const [ttlTouched, setTtlTouched] = React.useState(false);
  const [formErrs, setFormErrs] = React.useState<Record<string, string>>({});
  const [formMsg, setFormMsg] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [oldMode, setOldMode] = React.useState("");
  const [nestedWarning, setNestedWarning] = React.useState(false);

  // 试算
  const [trialState, setTrialState] = React.useState<TrialState>("idle");
  const [trialOut, setTrialOut] = React.useState<SuppressionPreviewOut | null>(null);
  const [trialKey, setTrialKey] = React.useState("");
  const [matchError, setMatchError] = React.useState("");
  const [confirmStage, setConfirmStage] = React.useState(false);
  const [trialNonce, setTrialNonce] = React.useState(0);

  // 撤销
  const [revokeTarget, setRevokeTarget] = React.useState<SuppressionItem | null>(null);
  const [revokeReason, setRevokeReason] = React.useState("");
  const [revokeBusy, setRevokeBusy] = React.useState(false);
  const [revokeError, setRevokeError] = React.useState("");

  // 参数
  const [paramOpen, setParamOpen] = React.useState(false);
  const [draft, setDraft] = React.useState<Record<string, string | number | boolean>>({});
  const [paramErrs, setParamErrs] = React.useState<Record<string, string>>({});
  const [paramMsg, setParamMsg] = React.useState("");
  const [paramBusy, setParamBusy] = React.useState(false);

  // 页面级提示
  const [notice, setNotice] = React.useState<{ text: string; tone: "ok" | "warn" | "err" | "info" } | null>(null);

  /**
   * 「服务端重判档位」告警。
   *
   * 为什么需要它：`create_item` / `update_item` 拿到 `match` 后**自己再跑一遍**
   * `estimate_trial` + `choose_mode`，不采用前端试算结果。所以用户看到「仅记录」、
   * 点「确认保存」，落库可能是 `suppress`（事件从此不再生成）——本页唯一能让人
   * "以为按了保守档、实际按了最狠档"的路径。
   *
   * 抽屉**不关**：关掉就等于没人看得见这条告警（Toast 会消失）。
   */
  const [mismatch, setMismatch] = React.useState<{ item: SuppressionItem; previewMode: string } | null>(null);

  const allowedFields = cfg?.allowed_fields ?? ALLOWED_FIELDS_FALLBACK;
  const reasonCodes = cfg?.reason_codes ?? REASON_CODE_FALLBACK;
  const effective = cfg?.effective ?? {};
  const minDims = clampNumber(
    Number(effective["suppression.min_match_dims"] ?? stats?.limits?.min_match_dims ?? 2),
    2,
    12,
    2,
  );
  const defaultTtl = clampNumber(
    Number(effective["suppression.default_ttl_days"] ?? DEFAULT_TTL_DAYS),
    LIMITS.ttlMin,
    LIMITS.ttlMax,
    DEFAULT_TTL_DAYS,
  );
  const hitCap = list?.limits?.hit_cap ?? stats?.limits?.hit_cap;

  const currentMatch = React.useMemo(() => condsToMatch(matchLogic, conds), [matchLogic, conds]);
  const matchKey = React.useMemo(() => JSON.stringify(currentMatch), [currentMatch]);
  const dims = matchDims(currentMatch);
  const trialFresh = Boolean(trialKey) && trialKey === matchKey;
  const evidenceRefs = React.useMemo(
    () =>
      evidenceText
        .split(/[\n,]/)
        .map((part) => part.trim())
        .filter(Boolean),
    [evidenceText],
  );

  // ---------- 取数 ----------

  const listUrl = React.useMemo(() => {
    const params = new URLSearchParams();
    // 硬约束：显式携带（后端默认 false，且是"先分页后过滤"）
    params.set("include_expired", "true");
    params.set("limit", String(size));
    params.set("offset", String(page * size));
    if (enabledOnly) params.set("enabled_only", "true");
    if (q.trim()) params.set("q", q.trim());
    return `/api/suppressions?${params.toString()}`;
  }, [size, page, enabledOnly, q]);

  const loadList = React.useCallback(async () => {
    await loadInto(errs, SRC.list, listUrl, setList);
  }, [errs, listUrl]);

  const loadStats = React.useCallback(async () => {
    await loadInto(errs, SRC.stats, "/api/suppressions/stats", setStats);
  }, [errs]);

  const loadConfig = React.useCallback(async () => {
    await loadInto(errs, SRC.config, "/api/suppressions/config", setCfg);
  }, [errs]);

  React.useEffect(() => {
    void (async () => {
      errs.reset();
      await Promise.all([loadStats(), loadConfig()]);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    void loadList();
  }, [loadList]);

  // ---------- 试算 ----------

  const runTrial = React.useCallback(
    async (match: SuppressionMatch): Promise<TrialState> => {
      setTrialState("trialing");
      setTrialOut(null);
      setMatchError("");
      const key = JSON.stringify(match);
      try {
        const out = await apiFetch<SuppressionPreviewOut>("/api/suppressions/preview", {
          method: "POST",
          body: JSON.stringify({ match }),
        });
        setTrialOut(out);
        setTrialKey(key);
        const degraded = Boolean(out.trial?.error) || (out.trial?.events ?? 0) < 0;
        setTrialState(degraded ? "degraded" : "success");
        return degraded ? "degraded" : "success";
      } catch (error) {
        if (error instanceof ApiError && error.status === 400) {
          const map = fieldErrorsOf(error);
          setMatchError(map.match ?? apiErrorText(error, "条件不合法"));
          setTrialState("invalid");
          return "invalid";
        }
        setTrialState("netfail");
        return "netfail";
      }
    },
    [],
  );

  // 条件树变更 → 600ms debounce；维度不足只提示、**不发请求**
  React.useEffect(() => {
    if (!formOpen) return undefined;
    setConfirmStage(false);
    if (dims < minDims) {
      setTrialState("idle");
      setTrialOut(null);
      setTrialKey("");
      setMatchError("");
      return undefined;
    }
    setTrialState("debouncing");
    const timer = window.setTimeout(() => {
      // matchKey 是 JSON.stringify 的产物，理论上一定合法；但定时器回调里抛出的异常
      // 会变成未捕获错误、直接把整个面板带崩，所以这里仍然包一层。
      let parsed: SuppressionMatch;
      try {
        parsed = JSON.parse(matchKey) as SuppressionMatch;
      } catch {
        setTrialState("invalid");
        setMatchError("条件格式异常，请重试");
        return;
      }
      void runTrial(parsed);
    }, 600);
    return () => window.clearTimeout(timer);
  }, [matchKey, dims, minDims, formOpen, trialNonce, runTrial]);

  // ---------- 表单 ----------

  function resetForm() {
    setEditId("");
    setName("");
    setMatchLogic("and");
    setConds([{ field: "signature_id", op: "eq", value: "" }]);
    setReasonCode("");
    setNote("");
    setEvidenceText("");
    setConfidence("0");
    setTtlDays(String(defaultTtl));
    setTtlTouched(false);
    setFormErrs({});
    setFormMsg("");
    setOldMode("");
    setNestedWarning(false);
    setTrialState("idle");
    setTrialOut(null);
    setTrialKey("");
    setMatchError("");
    setConfirmStage(false);
  }

  function openCreate() {
    resetForm();
    setMismatch(null);
    setTtlDays(String(defaultTtl));
    setFormOpen(true);
  }

  function openEdit(item: SuppressionItem) {
    const parsed = matchToConds(item.match);
    setMismatch(null);
    setEditId(item.id);
    setName(item.name);
    setMatchLogic(parsed.logic);
    setConds(
      parsed.conds.length ? parsed.conds : [{ field: "signature_id", op: "eq", value: "" }],
    );
    setReasonCode(item.reason_code);
    setNote(item.note);
    setEvidenceText(item.evidence_refs.join("\n"));
    setConfidence(String(item.confidence));
    setTtlDays(String(parseDays(item.expires_at)));
    setTtlTouched(false);
    setOldMode(item.mode);
    setNestedWarning(parsed.nested);
    setFormErrs({});
    setFormMsg("");
    setTrialState("idle");
    setTrialOut(null);
    setTrialKey("");
    setMatchError("");
    setConfirmStage(false);
    setFormOpen(true);
  }

  function parseDays(iso: string | null): number {
    if (!iso) return defaultTtl;
    const diff = Date.parse(iso) - Date.now();
    if (!Number.isFinite(diff)) return defaultTtl;
    return clampNumber(Math.ceil(diff / 86_400_000), LIMITS.ttlMin, LIMITS.ttlMax, defaultTtl);
  }

  /** 校验失败时把焦点移到第一个出错的控件（`aria-describedby` 已把文案关联上）。 */
  function focusField(field: string) {
    const idMap: Record<string, string> = {
      name: "suppression-name",
      reason_code: "suppression-reason-0",
      ttl_days: "suppression-ttl",
      evidence_refs: "suppression-evidence",
      confidence: "suppression-confidence",
      match: "suppression-match",
    };
    if (typeof document === "undefined") return;
    document.getElementById(idMap[field] ?? "")?.focus();
  }

  async function submitForm() {
    // 试算在途：按钮是加载态（不是 disabled），但不应重复发请求
    if (trialState === "trialing") return;
    setFormMsg("");
    setFormErrs({});
    setMatchError("");

    // ① 本地校验（不发请求）：必填、维度、数值 clamp 前置，避免撞 422 数组
    const nextErrs: Record<string, string> = {};
    if (!name.trim()) nextErrs.name = "名称必填（≤128 字）";
    if (!reasonCode) nextErrs.reason_code = "请选择一条理由（必选）";
    if (dims < minDims) nextErrs.match = `至少 ${minDims} 个独立维度（当前 ${dims} 个）`;
    const ttlNumber = Number(ttlDays === "" ? defaultTtl : ttlDays);
    if (!Number.isFinite(ttlNumber) || ttlNumber < LIMITS.ttlMin || ttlNumber > LIMITS.ttlMax) {
      nextErrs.ttl_days = `有效期 ${LIMITS.ttlMin}~${LIMITS.ttlMax} 天`;
    }
    if (evidenceRefs.length > LIMITS.evidenceMax) {
      nextErrs.evidence_refs = `证据引用最多 ${LIMITS.evidenceMax} 条（当前 ${evidenceRefs.length} 条）`;
    }
    if (Object.keys(nextErrs).length) {
      setFormErrs(nextErrs);
      setFormMsg("请先修正表单里的问题");
      focusField(
        nextErrs.match
          ? "match"
          : nextErrs.reason_code
            ? "reason_code"
            : nextErrs.name
              ? "name"
              : nextErrs.ttl_days
                ? "ttl_days"
                : "evidence_refs",
      );
      return;
    }

    // ② 没有本次变更的有效试算 → 先试算、展示影响面，再点一次才保存
    const hasFresh = trialFresh && (trialState === "success" || trialState === "degraded");
    if (!hasFresh) {
      const result = await runTrial(currentMatch);
      if (result === "invalid" || result === "netfail") {
        setFormMsg(
          result === "invalid"
            ? "条件不合法，已阻止保存（见条件树下方红字）"
            : "试算未能完成，请重试后再保存",
        );
        return;
      }
      setConfirmStage(true);
      setFormMsg("影响面已算出 —— 确认无误后点「确认保存」");
      return;
    }

    // ③ 提交
    const body: SuppressionIn = {
      name: name.trim().slice(0, LIMITS.nameMax),
      match: currentMatch,
      reason_code: reasonCode,
      note: note.slice(0, LIMITS.noteMax),
      evidence_refs: evidenceRefs.slice(0, LIMITS.evidenceMax),
      confidence: clampNumber(Number(confidence), 0, 1, 0),
      // 编辑态未动过有效期就不传：后端只在传了 ttl_days 时重算 expires_at
      ttl_days: editId && !ttlTouched ? undefined : clampNumber(ttlNumber, LIMITS.ttlMin, LIMITS.ttlMax, defaultTtl),
    };
    setSaving(true);
    // 提交前把用户当前看到的档位记下来：下面要拿它和服务端重判结果比
    const previewMode = trialMode;
    try {
      const saved = await apiFetch<SuppressionItem>(editId ? `/api/suppressions/${editId}` : "/api/suppressions", {
        method: editId ? "PUT" : "POST",
        body: JSON.stringify(body),
      });
      // 列表与统计在后台重取（此刻抽屉可能还开着，靠下面的 mismatch 分支决定关不关）
      void loadList();
      void loadStats();
      if (saved?.mode && previewMode && saved.mode !== previewMode) {
        // 服务端按最新流量重判，档位变了 → 抽屉不关，顶部常驻告警
        setMismatch({ item: saved, previewMode });
        setNotice(null);
        return;
      }
      const tag = saved?.mode === "suppress" ? "完全抑制" : "仅记录";
      setNotice({
        text: editId
          ? `已保存，实际生效为「${tag}」`
          : `已创建，实际生效为「${tag}」（采集侧最迟 45 秒收敛）`,
        tone: "ok",
      });
      setFormOpen(false);
      resetForm();
    } catch (error) {
      const map = fieldErrorsOf(error);
      setFormErrs(map);
      if (map.match) setMatchError(map.match);
      setFormMsg(apiErrorText(error, "保存失败"));
      const firstKey = Object.keys(map)[0];
      if (firstKey) focusField(firstKey);
    } finally {
      setSaving(false);
    }
  }

  // ---------- 撤销 / 恢复 ----------

  async function doRevoke() {
    if (!revokeTarget) return;
    setRevokeBusy(true);
    setRevokeError("");
    try {
      // 这个端点 body 必填：至少发 {}（空 body 会 422）
      await apiFetch(`/api/suppressions/${revokeTarget.id}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason: revokeReason.slice(0, LIMITS.reasonMax) }),
      });
      setNotice({ text: "已撤销，立即生效", tone: "ok" });
      setRevokeTarget(null);
      setRevokeReason("");
      void loadList();
      void loadStats();
    } catch (error) {
      setRevokeError(apiErrorText(error, "撤销失败"));
    } finally {
      setRevokeBusy(false);
    }
  }

  async function doRestore(item: SuppressionItem) {
    setNotice(null);
    try {
      await apiFetch(`/api/suppressions/${item.id}/restore`, { method: "POST" });
      setNotice(
        item.expired
          ? {
              text:
                "已恢复，但该条目已过期 —— 后端恢复不校验有效期，需同时延长有效期（编辑里改 TTL）才会重新生效",
              tone: "warn",
            }
          : { text: "已恢复，立即生效", tone: "ok" },
      );
      void loadList();
      void loadStats();
    } catch (error) {
      setNotice({ text: apiErrorText(error, "恢复失败"), tone: "err" });
    }
  }

  // ---------- 参数 ----------

  function knobValue(item: KnobItem): string | number | boolean {
    const current = effective[item.key];
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
    setParamBusy(true);
    try {
      const data = await apiFetch<SuppressionConfigPayload>("/api/suppressions/config", {
        method: "PUT",
        body: JSON.stringify({ values }),
      });
      setCfg(data);
      setDraft({});
      setParamMsg(
        `已保存 ${data.written ?? 0} 项 —— 参数改动 30 秒内生效（runtime_config 缓存）。注意：不会重判已有条目；但下次编辑某条时会按新门槛重算它的档位。`,
      );
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
      const data = await apiFetch<SuppressionConfigPayload>("/api/suppressions/config/reset", {
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

  // ---------- 派生 ----------

  const items = list?.items ?? [];
  const listFailed = errs.isFailed(SRC.list) || Boolean(list?.error);
  const statsFailed = errs.isFailed(SRC.stats) || Boolean(stats?.error);
  const byMode = stats?.by_mode ?? {};
  const trialMode = trialOut?.mode ?? "";
  const trialDegraded = trialState === "degraded" || Boolean(trialOut?.trial?.error);
  const trialEvents = trialOut?.trial?.events;
  const trialMaxEvents = trialOut?.trial?.max_events ?? trialOut?.thresholds?.max_hits;
  const trialMaxSrcs = trialOut?.trial?.max_srcs ?? trialOut?.thresholds?.max_srcs;
  const trialMaxSegments = trialOut?.trial?.max_segments ?? trialOut?.thresholds?.max_segments;
  const overThreshold =
    (typeof trialEvents === "number" && typeof trialMaxEvents === "number" && trialEvents > trialMaxEvents) ||
    (typeof trialOut?.trial?.srcs === "number" &&
      typeof trialMaxSrcs === "number" &&
      (trialOut?.trial?.srcs ?? 0) > trialMaxSrcs) ||
    (typeof trialOut?.trial?.segments === "number" &&
      typeof trialMaxSegments === "number" &&
      (trialOut?.trial?.segments ?? 0) > trialMaxSegments);
  const becomesStricter = Boolean(oldMode) && oldMode === "record_only" && trialMode === "suppress";
  const saveDisabled = trialState === "invalid" || trialState === "netfail";

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      {notice ? (
        <p
          role={notice.tone === "err" ? "alert" : "status"}
          className={cn(
            "rounded-xs border px-3 py-2 text-xs",
            notice.tone === "err"
              ? "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg"
              : notice.tone === "warn"
                ? "border-sev-medium-bd bg-sev-medium-bg text-sev-medium-fg"
                : notice.tone === "ok"
                  ? "border-sev-ok-bd bg-sev-ok-bg text-sev-ok-fg"
                  : "border-border-subtle bg-surface-1 text-muted-foreground",
          )}
        >
          {notice.text}
        </p>
      ) : null}

      <SettingsBoard>
        {/* ── ① 抑制总览 ──────────────────────────────────────────── */}
        <SettingsBlock
          title="抑制总览"
          description="抑制是自动生效的：命中条件后不再派工、不再推送。原始数据（ES）永不受影响 —— 抑制错了也能用日志检索与原始证据事后重建。"
          extra={
            <>
              <Button size="sm" variant="outline" onClick={() => void Promise.all([loadList(), loadStats()])}>
                刷新
              </Button>
              <Button size="sm" onClick={openCreate}>
                ＋新建抑制
              </Button>
            </>
          }
          bodyClassName="space-y-3"
        >
          {!stats && !statsFailed ? (
            <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
              {[0, 1, 2, 3].map((key) => (
                <Skeleton key={key} className="h-16 w-full" />
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
              <Stat label="生效中" value={stats ? numText(stats.active) : "—"} size="md" />
              <Stat
                label="仅记录中（降级档）"
                value={stats ? numText(byMode.record_only ?? 0) : "—"}
                size="md"
                tone={byMode.record_only ? "medium" : "default"}
                hint="影响面过大时自动降为只不派工"
              />
              <Stat
                label="累计抑制量"
                value={stats ? numText(stats.suppressed_total) : "—"}
                size="md"
                hint="所有条目 hits 之和（约 30 秒内更新）"
              />
              <Stat
                label="条目总数"
                value={stats ? numText(stats.total) : "—"}
                size="md"
                hint={
                  stats
                    ? `其中已过期 ${numText(stats.expired)} · 已撤销 ${numText(stats.revoked)}（两者可重叠，不能相加）`
                    : "其中已过期 / 已撤销"
                }
              />
            </div>
          )}

          {/* 两列 mode 对照带：让运维一眼分清两种档位的后果（本页最重的认知） */}
          <div className="grid gap-2 md:grid-cols-2">
            <div className="rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 pl-3 text-sev-critical-fg border-l-[3px]">
              <p className="flex items-center gap-1.5 text-sm font-medium">
                <Ban aria-hidden className="h-4 w-4" />
                完全抑制（事件不再生成）
              </p>
              <p className="mt-0.5 text-xs leading-relaxed">{modeSentence("suppress")}</p>
              <p className="mt-0.5 text-xs leading-relaxed opacity-80">= 这条流量从系统里消失（仅原始日志可查）</p>
            </div>
            <div className="rounded-xs border border-sev-medium-bd bg-sev-medium-bg px-3 py-2 pl-3 text-sev-medium-fg border-l-[3px]">
              <p className="flex items-center gap-1.5 text-sm font-medium">
                <BellOff aria-hidden className="h-4 w-4" />
                仅记录（事件保留·不派工）
              </p>
              <p className="mt-0.5 text-xs leading-relaxed">{modeSentence("record_only")}</p>
              <p className="mt-0.5 text-xs leading-relaxed opacity-80">= 影响面过大时的降级档，不是错误</p>
            </div>
          </div>
          {statsFailed ? (
            <p className="text-xs text-sev-critical-fg">总览读取失败：数值显示为「—」而不是 0。</p>
          ) : null}
        </SettingsBlock>

        {/* ── ② 抑制清单 ──────────────────────────────────────────── */}
        <SettingsBlock
          title="抑制清单"
          description="按命中数降序：吞得多的最需要复核。命中数是攒批写入的，最多滞后约 30 秒。"
          bodyClassName="p-0"
        >
          <PanelToolbar
            search={
              <Input
                className="h-8"
                aria-label="按名称/理由/备注搜索"
                placeholder="搜名称 / 理由 / 备注"
                value={q}
                onChange={(event) => {
                  setQ(event.target.value);
                  setPage(0);
                }}
              />
            }
          >
            <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <Switch
                label="仅启用"
                checked={enabledOnly}
                onCheckedChange={(next) => {
                  setEnabledOnly(next);
                  setPage(0);
                }}
              />
              仅启用
            </span>
            <Button size="sm" variant="outline" onClick={() => void loadList()}>
              刷新
            </Button>
            <Button size="sm" onClick={openCreate}>
              ＋新建抑制
            </Button>
          </PanelToolbar>

          {list === null && !listFailed ? (
            <TableSkeleton rows={8} cols={7} />
          ) : items.length ? (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>名称</TableHead>
                    <TableHead className="w-44">模式</TableHead>
                    <TableHead>条件</TableHead>
                    <TableHead className="w-20">
                      <span title="按命中数降序：吞得多的最需要复核">命中数</span>
                    </TableHead>
                    <TableHead className="w-24">状态</TableHead>
                    <TableHead className="w-36">到期</TableHead>
                    <TableHead className="w-40">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((item) => {
                    const stateBadge = suppressionState(item);
                    const expiry = expiryOf(item.expires_at);
                    const cause = revokeCause(item.revoke_reason);
                    const hot = nearHitCap(item.hits, hitCap);
                    return (
                      <TableRow
                        key={item.id}
                        tabIndex={0}
                        className="cursor-pointer"
                        aria-label={`${item.name}，${modeShort(item.mode)}，${stateBadge.label}，查看/编辑`}
                        onClick={() => openEdit(item)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            openEdit(item);
                          }
                        }}
                      >
                        <TableCell className="min-w-0">
                          <span className="block truncate font-medium text-foreground" title={item.name}>
                            {item.name || "（未命名）"}
                          </span>
                          <span className="mt-0.5 block truncate text-xs text-muted-foreground">
                            {item.reason_label || item.reason_code || "—"} ·{" "}
                            {item.origin === "agent" ? "智能体" : "界面"} · 置信度{" "}
                            {item.confidence.toFixed(2)} · 证据 {item.evidence_refs.length} 条
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge variant={modeVariant(item.mode)} title={modeSentence(item.mode)}>
                            {item.mode === "suppress" ? (
                              <Ban aria-hidden className="h-3 w-3" />
                            ) : (
                              <BellOff aria-hidden className="h-3 w-3" />
                            )}
                            {modeShort(item.mode)}
                          </Badge>
                        </TableCell>
                        <TableCell className="min-w-0">
                          <span
                            className="block truncate font-mono text-xs text-muted-foreground"
                            title={JSON.stringify(item.match)}
                          >
                            {matchSummary(item.match)}
                          </span>
                          <Badge
                            variant={item.dims < minDims ? "medium" : "outline"}
                            className="mt-0.5"
                            title={`至少 ${minDims} 个独立维度（match 的维度门槛）`}
                          >
                            {item.dims} 维
                          </Badge>
                        </TableCell>
                        <TableCell
                          className={cn("tabular-nums", hot ? "text-sev-medium-fg" : undefined)}
                          title={
                            hot
                              ? `接近熔断上限 ${item.hits}/${hitCap ?? "—"}，超过上限将自动撤销`
                              : "约 30 秒内更新"
                          }
                        >
                          {item.hits}
                        </TableCell>
                        <TableCell>
                          <Badge variant={stateBadge.variant}>{stateBadge.label}</Badge>
                          {!item.enabled ? (
                            <span className={cn("mt-0.5 block text-xs", cause.className)}>{cause.label}</span>
                          ) : null}
                        </TableCell>
                        <TableCell title={item.expires_at ? formatDateTime(item.expires_at) : "没有到期时间"}>
                          <span className={cn("text-xs", expiry.urgent ? "text-sev-medium-fg" : "text-muted-foreground")}>
                            {expiry.text}
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={(event) => {
                                event.stopPropagation();
                                openEdit(item);
                              }}
                            >
                              编辑
                            </Button>
                            {item.enabled ? (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="text-sev-critical-fg"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  setRevokeTarget(item);
                                  setRevokeReason("");
                                  setRevokeError("");
                                }}
                              >
                                撤销
                              </Button>
                            ) : (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  void doRestore(item);
                                }}
                              >
                                恢复
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              <div className="px-3 py-2">
                <Pagination
                  page={page}
                  pages={Math.max(1, Math.ceil((list?.total ?? 0) / size))}
                  total={list?.total ?? 0}
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
              tone={listFailed ? "danger" : "muted"}
              title={emptyOrFailed(errs, SRC.list, enabledOnly ? "没有生效中的抑制条目" : "还没有抑制条目")}
              hint={
                listFailed
                  ? "见上方错误条：后端读库失败，不能当成「没有抑制」"
                  : "抑制由智能体带证据自动创建，也可以人工新建；建议人工建之前先看一次影响面"
              }
              action={
                <Button size="sm" onClick={openCreate}>
                  ＋新建抑制
                </Button>
              }
            />
          )}
        </SettingsBlock>

        {/* ── ③ 参数与门槛 ────────────────────────────────────────── */}
        <SettingsBlock
          title="参数与门槛"
          description="改的是判定口径，不是某一条抑制。参数改动 30 秒内生效（下次编辑某条时按新门槛重算它的档位）；条目增删改本机立即、采集侧最迟 45 秒收敛。"
          extra={
            <Button size="sm" variant="outline" onClick={() => setParamOpen(true)}>
              改参数…
            </Button>
          }
        >
          <p className="text-xs leading-relaxed text-muted-foreground">
            最近{" "}
            <span className="tabular-nums text-foreground">
              {numText(Number(effective["suppression.trial_days"] ?? 7))}
            </span>{" "}
            天命中 ≤{" "}
            <span className="tabular-nums text-foreground">
              {numText(Number(effective["suppression.trial_max_hits"] ?? 5000))}
            </span>
            、源 ≤{" "}
            <span className="tabular-nums text-foreground">
              {numText(Number(effective["suppression.trial_max_srcs"] ?? 200))}
            </span>
            、网段 ≤{" "}
            <span className="tabular-nums text-foreground">
              {numText(Number(effective["suppression.trial_max_segments"] ?? 8))}
            </span>{" "}
            才会自动「完全不生成事件」；任一超限自动降为「仅记录」。条件树至少{" "}
            <span className="tabular-nums text-foreground">{minDims}</span> 个独立维度，活跃条目上限{" "}
            <span className="tabular-nums text-foreground">{numText(stats?.limits?.max_active)}</span> 条，单条命中熔断{" "}
            <span className="tabular-nums text-foreground">{numText(hitCap)}</span> 次。
          </p>
        </SettingsBlock>
      </SettingsBoard>

      {/* ── 浮层 1：新建 / 编辑 ─────────────────────────────────────── */}
      <Drawer
        open={formOpen}
        title={editId ? "编辑抑制" : "新建抑制"}
        widthClass="w-[720px]"
        onClose={() => setFormOpen(false)}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setFormOpen(false)}>
              {mismatch ? "接受并关闭" : "取消"}
            </Button>
            {/* 档位不符时把提交按钮摘掉：条目已经写进去了，再点一次「保存」会重复建一条 */}
            {mismatch ? null : (
              <Button
                size="sm"
                aria-disabled={saveDisabled || saving || undefined}
                aria-busy={trialState === "trialing" || undefined}
                className={cn(saveDisabled && "pointer-events-none opacity-50")}
                onClick={() => {
                  if (saveDisabled) return;
                  void submitForm();
                }}
              >
                {saving
                  ? "保存中…"
                  : trialState === "trialing"
                    ? "试算中…"
                    : confirmStage && trialFresh
                      ? "确认保存"
                      : "保存"}
              </Button>
            )}
          </>
        }
      >
        <div className="space-y-4">
          {mismatch ? (
            <div
              role="alert"
              className="rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg"
            >
              <p className="font-medium">
                服务端按最新流量重新判定：实际为「{modeShort(mismatch.item.mode)}」，与你试算时的「
                {modeShort(mismatch.previewMode)}」不同。
              </p>
              <p className="mt-1 leading-relaxed opacity-90">
                条目已写入并生效
                {mismatch.item.mode === "suppress"
                  ? "—— 该条件的流量从此不再生成事件。"
                  : "—— 事件仍生成，只是不派工、不推送。"}
                档位由后端按当前影响面决定，界面上无法指定，也无法在保存时锁定。
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Button
                  size="sm"
                  onClick={() => {
                    setMismatch(null);
                    setFormOpen(false);
                    resetForm();
                    setNotice({ text: "已确认：档位以服务端判定为准", tone: "info" });
                  }}
                >
                  接受并关闭
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    const target = mismatch.item;
                    setMismatch(null);
                    setFormOpen(false);
                    resetForm();
                    // 复用清单上那条撤销路径（含二次确认、reason 落库），不新增第二个撤销入口
                    setRevokeReason("服务端重判档位不符，撤销");
                    setRevokeTarget(target);
                  }}
                >
                  撤销这条
                </Button>
              </div>
            </div>
          ) : null}

          {nestedWarning ? (
            <p className="rounded-xs border border-sev-medium-bd bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium-fg">
              这条抑制含嵌套条件组：界面只展示顶层条件，保存会把嵌套组丢掉。要保留原结构请用 MCP 或先简化条件。
            </p>
          ) : null}

          {/* ① 条件树 */}
          <Section
            title="条件（至少两个独立维度）"
            description="字段白名单由后端给出（不含正文类字段：正文可被投毒）。端口要填数字、协议填小写，否则条件看着对但不命中。"
            divided={false}
          >
            <div id="suppression-match">
              <ConditionEditor
                fields={Object.keys(allowedFields)}
                conds={conds as Cond[]}
                logic={matchLogic}
                onLogic={setMatchLogic}
                onChange={(index, patch) =>
                  setConds((prev) => prev.map((cond, i) => (i === index ? { ...cond, ...patch } : cond)))
                }
                onRemove={(index) => setConds((prev) => prev.filter((_, i) => i !== index))}
                onAdd={() => setConds((prev) => [...prev, { field: "src_ip", op: "eq", value: "" }])}
              />
            </div>
            <p aria-live="polite" className="mt-1 text-xs text-muted-foreground">
              已填 <span className="tabular-nums text-foreground">{dims}</span> 维（至少 {minDims} 维）
              {dims < minDims ? ` —— 还差 ${minDims - dims} 维，试算要等条件补齐` : null}
            </p>
            {matchError || formErrs.match ? (
              <p className="mt-1 text-xs text-sev-critical-fg" role="alert">
                {matchError || formErrs.match}
              </p>
            ) : null}
            <p className="mt-1 text-xs text-muted-foreground">
              可选字段：{Object.keys(allowedFields).map((field) => allowedFields[field]).join("、")}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              协议建议值：{PROTOCOL_SUGGESTIONS.join(" / ")}（后端按小写比对）
            </p>
          </Section>

          {/* ② 试算卡 */}
          <Section title="影响面试算（保存前必看）" divided={false}>
            {dims < minDims ? (
              <p className="rounded-xs bg-surface-1 px-3 py-2 text-xs text-muted-foreground">
                条件不足 {minDims} 维，暂不试算。
              </p>
            ) : trialState === "debouncing" || trialState === "trialing" ? (
              <div className="space-y-2 rounded-xs bg-surface-1 px-3 py-2" aria-busy="true">
                <p className="text-xs text-muted-foreground">试算中…</p>
                <div className="grid grid-cols-3 gap-2">
                  <Skeleton className="h-12 w-full" />
                  <Skeleton className="h-12 w-full" />
                  <Skeleton className="h-12 w-full" />
                </div>
              </div>
            ) : trialState === "invalid" ? (
              <p className="rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg">
                条件不合法，保存已置灰：{matchError || formErrs.match || "见条件树下方提示"}
              </p>
            ) : trialState === "netfail" ? (
              <div className="rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg">
                <p>试算未能完成（网络或服务异常），保存已置灰。</p>
                <Button
                  size="sm"
                  variant="outline"
                  className="mt-2"
                  onClick={() => setTrialNonce((value) => value + 1)}
                >
                  重新试算
                </Button>
              </div>
            ) : trialOut ? (
              <div className="space-y-2" aria-live="polite">
                <div
                  className={cn(
                    "rounded-xs border px-3 py-2 pl-3 border-l-[3px]",
                    trialMode === "suppress"
                      ? "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg"
                      : "border-sev-medium-bd bg-sev-medium-bg text-sev-medium-fg",
                  )}
                >
                  <p className="flex flex-wrap items-center gap-1.5 text-sm font-medium">
                    {trialMode === "suppress" ? (
                      <Ban aria-hidden className="h-4 w-4" />
                    ) : (
                      <BellOff aria-hidden className="h-4 w-4" />
                    )}
                    {modeShort(trialMode)}
                    <span className="text-xs font-normal opacity-80">{modeSentence(trialMode)}</span>
                  </p>
                  {trialDegraded ? (
                    <p className="mt-1 flex items-start gap-1 text-xs">
                      <AlertTriangle aria-hidden className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      影响面未知（试算未能读取，已保守降级为只不派工）—— 不是 0 条命中。
                    </p>
                  ) : null}
                  {becomesStricter ? (
                    <p className="mt-1 text-xs font-medium">
                      影响面收敛：保存后将<b>不再生成此类事件</b>（仅原始日志仍可查）。
                    </p>
                  ) : null}
                  {oldMode && trialMode && oldMode !== trialMode && !becomesStricter ? (
                    <p className="mt-1 text-xs opacity-90">
                      当前 {modeShort(oldMode)} → 试算后 {modeShort(trialMode)}（变保守，不警告）
                    </p>
                  ) : null}
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <Stat
                    label={`近 ${trialOut.thresholds?.trial_days ?? 7} 天同类命中`}
                    size="sm"
                    value={
                      typeof trialEvents === "number" && trialEvents >= 0
                        ? trialEvents === 0
                          ? "0（影响面很小）"
                          : String(trialEvents)
                        : "—"
                    }
                    tone={
                      typeof trialEvents === "number" && typeof trialMaxEvents === "number" && trialEvents > trialMaxEvents
                        ? "critical"
                        : "default"
                    }
                    hint={`阈值 ≤ ${numText(trialMaxEvents)}`}
                  />
                  <Stat
                    label="涉及源 IP"
                    size="sm"
                    value={
                      typeof trialOut.trial?.srcs === "number" && trialOut.trial.srcs >= 0
                        ? String(trialOut.trial.srcs)
                        : "—"
                    }
                    tone={
                      typeof trialOut.trial?.srcs === "number" &&
                      typeof trialMaxSrcs === "number" &&
                      trialOut.trial.srcs > trialMaxSrcs
                        ? "critical"
                        : "default"
                    }
                    hint={`阈值 ≤ ${numText(trialMaxSrcs)}`}
                  />
                  <Stat
                    label="涉及网段"
                    size="sm"
                    value={
                      typeof trialOut.trial?.segments === "number" && trialOut.trial.segments >= 0
                        ? String(trialOut.trial.segments)
                        : "—"
                    }
                    tone={
                      typeof trialOut.trial?.segments === "number" &&
                      typeof trialMaxSegments === "number" &&
                      trialOut.trial.segments > trialMaxSegments
                        ? "critical"
                        : "default"
                    }
                    hint={`阈值 ≤ ${numText(trialMaxSegments)}`}
                  />
                </div>

                <p className="text-xs text-muted-foreground">
                  判定口径：命中 ≤ {numText(trialMaxEvents)} · 源 ≤ {numText(trialMaxSrcs)} · 网段 ≤{" "}
                  {numText(trialMaxSegments)} · 试算 {numText(trialOut.thresholds?.trial_days)} 天 · 最少维度{" "}
                  {numText(trialOut.thresholds?.min_match_dims)}
                </p>
                {overThreshold ? (
                  <p className="text-xs text-sev-medium-fg">
                    影响面超过阈值：保存后只会降级为「仅记录」，事件仍会生成、只是不派工不推送。
                  </p>
                ) : null}
                {trialOut.trial?.phenomenon ? (
                  <p className="text-xs text-muted-foreground">
                    试算现象：<span className="font-mono">{trialOut.trial.phenomenon}</span>
                  </p>
                ) : null}
                {trialOut.trial?.error ? (
                  <p className="text-xs text-muted-foreground">试算说明：{trialOut.trial.error}</p>
                ) : null}
              </div>
            ) : (
              <p className="rounded-xs bg-surface-1 px-3 py-2 text-xs text-muted-foreground">
                改完条件会自动试算（600ms 防抖）；也可以直接点「保存」，会先试算再让你确认。
              </p>
            )}
          </Section>

          {/* ③ 名称 / 理由 / 备注 */}
          <Section title="名称与理由" divided={false}>
            <div className="space-y-3">
              <Field
                label="名称"
                required
                error={formErrs.name}
                hint={editId ? "名称创建后不可改（后端修改接口不落该字段）" : "≤128 字；重名会被后端拒绝"}
              >
                <Input
                  id="suppression-name"
                  value={name}
                  maxLength={LIMITS.nameMax}
                  readOnly={Boolean(editId)}
                  aria-readonly={Boolean(editId)}
                  aria-invalid={formErrs.name ? true : undefined}
                  placeholder="例如：内部漏扫平台对 8080 的探测"
                  onChange={(event) => setName(event.target.value)}
                />
              </Field>

              <div>
                <p className="mb-1 text-xs text-muted-foreground">
                  理由（必选，不预选）<span className="text-sev-critical-fg">*</span>
                </p>
                <div
                  role="radiogroup"
                  aria-required="true"
                  aria-label="抑制理由"
                  aria-invalid={formErrs.reason_code ? true : undefined}
                  aria-describedby={formErrs.reason_code ? "reason-code-err" : undefined}
                  className="flex flex-wrap gap-1.5"
                >
                  {REASON_CODE_ORDER.map((code, index) => (
                    <Button
                      key={code}
                      id={`suppression-reason-${index}`}
                      type="button"
                      size="sm"
                      role="radio"
                      aria-checked={reasonCode === code}
                      variant={reasonCode === code ? "default" : "outline"}
                      title={reasonCodes[code] ?? code}
                      onClick={() => setReasonCode(code)}
                    >
                      {(reasonCodes[code] ?? code).replace("（界面）", "")}
                    </Button>
                  ))}
                </div>
                {formErrs.reason_code ? (
                  <p id="reason-code-err" className="mt-1 text-xs text-sev-critical-fg">
                    {formErrs.reason_code}
                  </p>
                ) : null}
              </div>

              <Field
                label="备注"
                error={formErrs.note}
                hint={editId ? "编辑态备注只读（后端修改接口不落 note）" : "≤500 字，可空"}
              >
                <Input
                  value={note}
                  maxLength={LIMITS.noteMax}
                  readOnly={Boolean(editId)}
                  aria-readonly={Boolean(editId)}
                  placeholder="为什么可以抑制、谁确认过"
                  onChange={(event) => setNote(event.target.value)}
                />
              </Field>
            </div>
          </Section>

          {/* ④ 证据 / 置信度 / TTL */}
          <Section title="证据、置信度与有效期" divided={false}>
            <div className="space-y-3">
              <Field
                label="证据引用"
                error={formErrs.evidence_refs}
                hint={`一行一条，最多 ${LIMITS.evidenceMax} 条（如 es:logs-2026.10.25/abc123）。界面创建不受智能体的证据门槛限制`}
              >
                <textarea
                  id="suppression-evidence"
                  aria-label="证据引用"
                  rows={3}
                  value={evidenceText}
                  className="w-full rounded-sm border border-input bg-surface-2 px-3 py-2 font-mono text-xs focus-visible:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
                  placeholder={"es:logs-2026.10.25/abc123\nev:3f2a…"}
                  onChange={(event) => setEvidenceText(event.target.value)}
                />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field
                  label="置信度"
                  error={formErrs.confidence}
                  hint={editId ? "编辑态只读（后端修改接口不落 confidence）" : "0~1（不是 0~100）"}
                >
                  <Input
                    id="suppression-confidence"
                    type="number"
                    step="0.05"
                    min={0}
                    max={1}
                    value={confidence}
                    readOnly={Boolean(editId)}
                    onChange={(event) => setConfidence(event.target.value)}
                  />
                </Field>
                <Field
                  label="有效期（天）"
                  error={formErrs.ttl_days}
                  hint={`${LIMITS.ttlMin}~${LIMITS.ttlMax} 天；默认 ${defaultTtl} 天，到期后自动失效`}
                >
                  <Input
                    id="suppression-ttl"
                    type="number"
                    min={LIMITS.ttlMin}
                    max={LIMITS.ttlMax}
                    value={ttlDays}
                    onChange={(event) => {
                      setTtlDays(event.target.value);
                      setTtlTouched(true);
                    }}
                  />
                </Field>
              </div>
              {editId ? (
                <p className="text-xs text-muted-foreground">
                  编辑态只提交：条件、理由、证据引用、（改动过的）有效期。名称/备注/置信度按后端事实不可改。
                </p>
              ) : null}
            </div>
          </Section>

          {formMsg ? (
            <p
              role={Object.keys(formErrs).length ? "alert" : "status"}
              className={cn(
                "rounded-xs border px-3 py-2 text-xs",
                Object.keys(formErrs).length
                  ? "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg"
                  : "border-border-subtle bg-surface-1 text-muted-foreground",
              )}
            >
              {formMsg}
            </p>
          ) : null}
        </div>
      </Drawer>

      {/* ── 浮层 2：撤销确认 ───────────────────────────────────────── */}
      <Dialog
        open={Boolean(revokeTarget)}
        title={revokeTarget ? `撤销抑制：${revokeTarget.name}？` : "撤销抑制"}
        widthClass="w-[560px]"
        onClose={() => setRevokeTarget(null)}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setRevokeTarget(null)} disabled={revokeBusy}>
              取消
            </Button>
            <Button size="sm" variant="destructive" onClick={() => void doRevoke()} disabled={revokeBusy}>
              {revokeBusy ? "撤销中…" : "确认撤销"}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="rounded-xs bg-surface-1 px-3 py-2 text-xs leading-relaxed text-muted-foreground">
            撤销后该条件<b>立即失效</b>，命中它的流量会重新生成事件并重新派工；
            <b>已抑制的历史事件不会补回</b>（原始数据仍在 ES，可用日志检索回溯）。
          </p>
          <Field label="撤销原因" hint="≤200 字，可空；会写进审计记录">
            <Input
              value={revokeReason}
              maxLength={LIMITS.reasonMax}
              placeholder="为什么撤销"
              onChange={(event) => setRevokeReason(event.target.value)}
            />
          </Field>
          <div className="flex flex-wrap gap-1.5">
            {REVOKE_REASON_CHIPS.map((chip) => (
              <Button key={chip} size="sm" variant="outline" onClick={() => setRevokeReason(chip)}>
                {chip}
              </Button>
            ))}
          </div>
          {revokeError ? (
            <p role="alert" className="text-xs text-sev-critical-fg">
              {revokeError}
            </p>
          ) : null}
        </div>
      </Dialog>

      {/* ── 浮层 3：抑制参数 ───────────────────────────────────────── */}
      <Drawer
        open={paramOpen}
        title="抑制参数"
        widthClass="w-[720px]"
        onClose={() => setParamOpen(false)}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setParamOpen(false)}>
              关闭
            </Button>
            <Button size="sm" variant="outline" disabled={paramBusy || !dirtyKeys.length} onClick={() => setDraft({})}>
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
            参数改动 <b>30 秒内生效</b>（`runtime_config` 缓存，`_CACHE_TTL_SECONDS=30`）；而抑制条目的
            新增/撤销/改条件是<b>本机立即生效</b>（只在本进程；采集侧靠 `cache_seconds`，默认 45 秒收敛）。
            改门槛 <b>不会重判已有条目</b> —— 只有下次编辑某条（或它到期后重建）才按新门槛算档位。
            恢复默认 = 删掉覆盖值，落回代码默认值。
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
              const knobItems = group.keys
                .map((key) => cfg.items.find((item) => item.key === key))
                .filter((item): item is KnobItem => Boolean(item));
              if (!knobItems.length) return null;
              return (
                <Section key={group.title} title={group.title} description={group.hint} divided={false}>
                  <div className="space-y-2">
                    {knobItems.map((item) => (
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
                    ))}
                  </div>
                </Section>
              );
            })
          )}

          <div className="flex justify-end">
            <Button size="sm" variant="ghost" disabled={paramBusy} onClick={() => void resetParam([])}>
              全部恢复默认
            </Button>
          </div>
        </div>
      </Drawer>
    </div>
  );
}
