import { ApiError, errorText } from "@shentong/ui";
import type { RuleCondition, SuppressionItem, SuppressionMatch } from "@/lib/api";

/**
 * 派工队列（`/analysis`）与精准抑制（`/config/suppressions`）的**共享层**：
 * 中文映射 / 状态语义 / 条件树转换 / 口径与取整 helper。
 *
 * 归属依据沿用 `lib/hits.ts` 的先例：
 * - **类型定义在 `lib/api.ts`**（全站一致），这里只做再导出之外的运行时东西；
 * - 中文名与状态色是「攒出来的口径」（例如 6 个 state 的徽章色、revoke_reason 的成因前缀），
 *   散在各面板里必然漂移 —— 集中一处，将来后端加状态只改这里。
 *
 * 三条口径写死在文件头，改之前先看：
 * 1. **抑制清单必须显式带 `include_expired=true`**（后端默认 false，且是"先分页后过滤"）；
 * 2. **覆盖率/盲区的条数一律用 `items.length`**（`returned` 是切片前长度）；
 * 3. **`hits` 是异步计数**（内存攒批、30 秒 flush）→ 文案写「约 30 秒内更新」，不写"实时"。
 */

// ---------- 徽章色（与 @shentong/ui 的 Badge variant 同一套联合类型） ----------

/** `Badge` 的 variant 取值。单独起名是为了让映射表能拿到字面量类型（否则 `string` 传不进去）。 */
export type BadgeVariant =
  | "default"
  | "secondary"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "success"
  | "outline";

export type Tone = "default" | "critical" | "high" | "medium" | "low" | "ok" | "info";

// ---------- 派工队列：6 状态（没有第 7 种） ----------

/** 展示顺序（筛选分段与图例共用）。后端 `queue.py::_STATE_COUNTER` 只有这 6 个。 */
export const TASK_STATES = [
  "pending",
  "claimed",
  "deferred",
  "done",
  "stuck",
  "expired",
] as const;

export const TASK_STATE_LABEL: Record<string, string> = {
  pending: "待派",
  claimed: "已派·在跑",
  deferred: "已推迟",
  done: "已完成",
  stuck: "卡住",
  expired: "已过期",
};

/** 状态徽章色：状态列是任务表**唯一**的彩色列，其余列用中性色。 */
export const TASK_STATE_VARIANT: Record<string, BadgeVariant> = {
  pending: "info",
  claimed: "low",
  deferred: "medium",
  done: "success",
  stuck: "high",
  expired: "outline",
};

/** 线索类型中文（`analysis/params.py::KINDS` 的 5 种）。 */
export const TASK_KIND_LABEL: Record<string, string> = {
  novelty: "新现象",
  shift: "漂移",
  structure: "结构",
  coverage: "覆盖",
  hit: "命中",
};

/** 对象类型中文。前 6 个是 `observed_subjects.kind`，后 4 个是任务里的 `subject_kind`。 */
export const SUBJECT_KIND_LABEL: Record<string, string> = {
  asset: "资产",
  service_port: "服务端口",
  peer: "对端",
  protocol: "协议",
  signature: "签名",
  account: "账号",
  ip: "IP",
  segment: "网段",
  cluster: "簇",
};

export function taskStateLabel(state: string): string {
  return TASK_STATE_LABEL[state] ?? state ?? "—";
}

export function taskStateVariant(state: string): BadgeVariant {
  return TASK_STATE_VARIANT[state] ?? "outline";
}

export function taskKindLabel(kind: string): string {
  return TASK_KIND_LABEL[kind] ?? kind ?? "—";
}

export function subjectKindLabel(kind: string): string {
  return SUBJECT_KIND_LABEL[kind] ?? kind ?? "—";
}

// ---------- 结论（verdict） ----------

/** 后端 `verdicts.py::VERDICT_VALUES` 的展示顺序；中文名本地维护（写回时后端还认中文别名）。 */
export const VERDICTS = [
  "true_positive",
  "false_positive",
  "benign",
  "suspicious",
  "inconclusive",
] as const;

export const VERDICT_LABEL: Record<string, string> = {
  true_positive: "确认攻击",
  false_positive: "误报",
  benign: "正常",
  suspicious: "可疑",
  inconclusive: "不确定",
};

/** 与行为画像的处置记录同一口径：误报用 `secondary`（扁灰），不确定用 `info`（灰蓝）。 */
export const VERDICT_VARIANT: Record<string, BadgeVariant> = {
  true_positive: "critical",
  suspicious: "medium",
  benign: "success",
  false_positive: "secondary",
  inconclusive: "info",
};

export function verdictLabel(verdict: string): string {
  return VERDICT_LABEL[verdict] ?? verdict ?? "—";
}

export function verdictVariant(verdict: string): BadgeVariant {
  return VERDICT_VARIANT[verdict] ?? "outline";
}

// ---------- 抑制 mode：短标签 / 完整句 / 颜色 ----------

/**
 * 窄列用的 4 字短标签。**不要**把后端 `mode_label`（「完全不生成事件」9~10 字）塞进 `w-44` 列。
 * 这两个 mode 都不能以英文原值出现。
 */
export const MODE_SHORT: Record<string, string> = {
  suppress: "完全抑制",
  record_only: "仅记录",
};

/** 完整句：抽屉 / 结论带 / 悬浮提示用（口径与后端 `mode_label` 一致，但这里是前端文案）。 */
export const MODE_SENTENCE: Record<string, string> = {
  suppress: "完全不生成事件，不再派工、不再推送",
  record_only: "只不派工，事件仍生成、不推送",
};

/** `suppress` 让事件从系统里消失（代价最高）→ 红；`record_only` 是降级档 → 金。 */
export const MODE_VARIANT: Record<string, BadgeVariant> = {
  suppress: "critical",
  record_only: "medium",
};

export function modeShort(mode: string): string {
  return MODE_SHORT[mode] ?? "—";
}

export function modeSentence(mode: string): string {
  return MODE_SENTENCE[mode] ?? "";
}

export function modeVariant(mode: string): BadgeVariant {
  return MODE_VARIANT[mode] ?? "outline";
}

// ---------- 抑制状态（三档 + 优先级）与撤销成因 ----------

export interface SuppressionStateBadge {
  label: string;
  variant: BadgeVariant;
}

/**
 * `enabled` 与 `expired` **正交**（过期不会把 enabled 置 false），一行可能同时"已撤销 + 已过期"。
 * 状态列取唯一值，优先级：**已撤销 > 已过期 > 生效中**。
 */
export function suppressionState(item: Pick<SuppressionItem, "enabled" | "expired">): SuppressionStateBadge {
  if (!item.enabled) return { label: "已撤销", variant: "secondary" };
  if (item.expired) return { label: "已过期", variant: "outline" };
  return { label: "生效中", variant: "success" };
}

export interface RevokeCause {
  label: string;
  className: string;
}

/**
 * 撤销成因：按 `revoke_reason` 的**前缀**判定（后端文案带标点/空格，不能用等号）。
 * 三个前缀的字面值核对过源码：`被真实事件推翻（`（全角括号）、`熔断：`（全角冒号）、
 * `超出活跃上限 `（**上限后是半角空格，没有逗号**，直接跟数字）。
 */
export function revokeCause(reason: string | null | undefined): RevokeCause {
  const text = String(reason || "");
  if (text.startsWith("被真实事件推翻（")) {
    return { label: "真阳推翻", className: "text-sev-critical-fg" };
  }
  if (text.startsWith("熔断：")) {
    return { label: "熔断", className: "text-sev-high-fg" };
  }
  if (text.startsWith("超出活跃上限 ")) {
    return { label: "超上限淘汰", className: "text-muted-foreground" };
  }
  return {
    label: text ? "人工撤销" : "人工撤销（未填原因）",
    className: "text-muted-foreground",
  };
}

/** 命中列熔断预警：`hits >= 0.8 * hit_cap`（真达上限的条目已被后端自动撤销）。 */
export function nearHitCap(hits: number, hitCap: number | undefined): boolean {
  if (!hitCap || hitCap <= 0) return false;
  return hits >= hitCap * 0.8;
}

// ---------- 理由码与撤销原因 chip ----------

/** 新建抑制的理由码声明序（与后端 `REASON_CODES` 一致，`manual` 排最后）。label 用 `/config` 的字典。 */
export const REASON_CODE_ORDER = [
  "known_service",
  "internal_scanner",
  "vendor_heartbeat",
  "business_normal",
  "duplicate_of_task",
  "repeated_after_analysis",
  "manual",
] as const;

/** `/config` 未取回来之前的兜底（值取自后端 `suppression.py::REASON_CODES`）。 */
export const REASON_CODE_FALLBACK: Record<string, string> = {
  known_service: "已知的自家服务/客户端行为",
  internal_scanner: "内部授权扫描器/漏扫平台",
  vendor_heartbeat: "厂商组件心跳/升级/探测",
  business_normal: "业务正常行为（OA/打卡/消息等）",
  duplicate_of_task: "与既有任务/结论重复",
  repeated_after_analysis: "分析后重复出现的同类流量",
  manual: "人工创建（界面）",
};

/** 撤销原因一键填入（自由文本，可空）。 */
export const REVOKE_REASON_CHIPS = ["误判", "影响面评估有误", "证据不足", "到期后继续抑制"];

// ---------- 抑制条件树：字段白名单（`allowed_fields` 未取回时的兜底） ----------

/** 12 项，label 与后端 `suppression.py::ALLOWED_FIELDS` 逐字一致。
 * **不含 payload/body/content**（正文可被投毒，后端刻意禁掉）。 */
export const ALLOWED_FIELDS_FALLBACK: Record<string, string> = {
  src_ip: "请求方 IP（精确）",
  dst_ip: "被访问 IP（精确）",
  dst_port: "被访问端口（eq / gt / lt 等）",
  segment: "请求方所在网段（v4 /24、v6 /64，含操作符 contains）",
  protocol: "协议（tcp/udp/http/dns/tls…）",
  rule: "命中的行为分析规则名（精确）",
  signature_id: "签名 SID（精确）",
  "http.uri": "HTTP 请求 URI（含 contains/regex）",
  "http.hostname": "HTTP Host / DNS 名",
  user_agent: "User-Agent",
  ja3: "TLS 客户端指纹",
  fuid: "文件 id（fuid）",
};

/** 字典里 **不能**用 `contains/regex` 的字段（值是数字）：用它们时值必须是数字，否则"看着对但不命中"。 */
export const NUMERIC_FIELDS = ["dst_port"];

/** 值必须小写的字段（后端 `field_values` 里 `protocol` 走 `.lower()`）。 */
export const LOWERCASE_FIELDS = ["protocol"];

/** `protocol` 的常用值（后端存小写）；用 datalist 提示，允许手填其它值。 */
export const PROTOCOL_SUGGESTIONS = [
  "tcp",
  "udp",
  "icmp",
  "dns",
  "http",
  "https",
  "tls",
  "ssh",
  "smb",
  "ftp",
  "rdp",
  "ldap",
  "smtp",
];

// ---------- 条件树 <-> 界面条件行 ----------

/** 界面里一行条件（与 `components/condition-editor.tsx` 的 `Cond` 结构一致，靠结构类型互通）。 */
export interface SuppressionCond {
  field: string;
  op: string;
  value: string;
}

const NUMERIC_OPS = ["gt", "gte", "lt", "lte"];

function splitValues(raw: string, field: string): (string | number)[] {
  const parts = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (NUMERIC_FIELDS.includes(field)) {
    return parts.map((p) => Number(p)).filter((n) => Number.isFinite(n));
  }
  return parts;
}

/**
 * 界面条件行 → 抑制条件树。
 *
 * 与规则页 `condsToRules` 的差别（这三条是抑制特有的，错了就"条件看着对但不命中"）：
 * - `dst_port` 的 `eq/ne` 也要转数字（后端 `field_values` 给的是 int，"80" ≠ 80）；
 * - `protocol` 的值强制小写（后端 `.lower()` 过）；
 * - `in` 的数字字段拆成数字数组。
 */
export function condsToMatch(logic: string, conds: SuppressionCond[]): SuppressionMatch {
  const rules: RuleCondition[] = conds
    .filter((c) => c.field && c.op)
    .map((c) => {
      if (c.op === "exists") return { field: c.field, op: c.op };
      if (c.op === "in") {
        return { field: c.field, op: c.op, value: splitValues(c.value, c.field) };
      }
      if (NUMERIC_OPS.includes(c.op)) {
        return { field: c.field, op: c.op, value: Number(c.value) };
      }
      if (NUMERIC_FIELDS.includes(c.field) && (c.op === "eq" || c.op === "ne")) {
        return { field: c.field, op: c.op, value: Number(c.value) };
      }
      if (LOWERCASE_FIELDS.includes(c.field)) {
        return { field: c.field, op: c.op, value: String(c.value).trim().toLowerCase() };
      }
      return { field: c.field, op: c.op, value: c.value };
    });
  return { logic: logic === "or" ? "or" : "and", rules };
}

/** 条件树 → 界面条件行（界面只支持顶层扁平条件；含嵌套组时置 `nested` 供调用方提示）。 */
export function matchToConds(match: SuppressionMatch | undefined): {
  logic: string;
  conds: SuppressionCond[];
  nested: boolean;
} {
  const logic = String(match?.logic || "and");
  const raw = match?.rules || [];
  let nested = false;
  const conds: SuppressionCond[] = [];
  for (const rule of raw) {
    if (rule.logic || rule.rules) {
      nested = true;
      continue;
    }
    const value = Array.isArray(rule.value)
      ? rule.value.join(",")
      : rule.value === undefined || rule.value === null
        ? ""
        : String(rule.value);
    conds.push({
      field: String(rule.field || ""),
      op: String(rule.op || "eq"),
      value: rule.op === "exists" ? "" : value,
    });
  }
  return { logic, conds, nested };
}

/** 条件树里出现的字段（去重保序）——维度门槛 `min_match_dims` 就按这个数算。 */
export function matchFields(match: SuppressionMatch | undefined, out: string[] = []): string[] {
  const rules = match?.rules || [];
  for (const rule of rules) {
    if (rule.rules) {
      matchFields({ logic: rule.logic, rules: rule.rules }, out);
      continue;
    }
    const field = String(rule.field || "").trim();
    if (field && !out.includes(field)) out.push(field);
  }
  return out;
}

export function matchDims(match: SuppressionMatch | undefined): number {
  return matchFields(match).length;
}

/** 条件摘要（列表里的一行文本；完整树在抽屉里）。 */
export function matchSummary(match: SuppressionMatch | undefined): string {
  const rules = match?.rules || [];
  if (!rules.length) return "—";
  const joiner = (match?.logic || "and") === "or" ? " 或 " : " 且 ";
  return rules
    .map((rule) => {
      if (rule.rules) return "（嵌套条件组）";
      const value = Array.isArray(rule.value) ? rule.value.join(",") : String(rule.value ?? "");
      return `${rule.field ?? "?"} ${rule.op ?? "eq"} ${value}`.trim();
    })
    .join(joiner);
}

// ---------- 时间 / 数字 / 错误 ----------

/** 时间一律北京时间（`formatDateTime` 已在共享包里做时区换算，这里只算"还剩多久"）。 */
export function remainingHours(
  task: { state: string; created_at: string; lease_until: string },
  pendingTtlHours: number | undefined,
): number | null {
  const now = Date.now();
  const lease = task.lease_until ? Date.parse(task.lease_until) : NaN;
  if ((task.state === "claimed" || task.state === "deferred") && Number.isFinite(lease)) {
    return (lease - now) / 3_600_000;
  }
  if (task.state === "pending" && task.created_at && pendingTtlHours) {
    const created = Date.parse(task.created_at);
    if (Number.isFinite(created)) {
      return (created + pendingTtlHours * 3_600_000 - now) / 3_600_000;
    }
  }
  return null;
}

/** 剩余小时文案：负数 = 已超时（后端下一轮回收前就会是负的）。 */
export function remainingText(hours: number | null): string {
  if (hours === null || !Number.isFinite(hours)) return "—";
  if (hours <= 0) return "已超时";
  if (hours < 1) return `剩 ${Math.max(1, Math.round(hours * 60))}m`;
  return `剩 ${Math.round(hours)}h`;
}

/** 覆盖率百分比（`coverage_ratio` 是 0~1） */
export function percentText(ratio: number | undefined): string {
  if (typeof ratio !== "number" || !Number.isFinite(ratio)) return "—";
  return `${(ratio * 100).toFixed(1)}%`;
}

/** 统计值缺键时显示 `—` 而不是 `0`（"没读到"与"真的是 0"必须分开） */
export function numText(value: number | undefined | null): string {
  return typeof value === "number" && Number.isFinite(value) ? String(value) : "—";
}

/** 成本口径：毫秒 → 「12.4s」 */
export function durationText(ms: number | undefined): string {
  if (!ms || !Number.isFinite(ms) || ms <= 0) return "—";
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms)}ms`;
}

/** 把 400 的 `field_errors` 摊成 `{字段: 文案}`（挂到对应控件下方）。 */
export function fieldErrorsOf(error: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (error instanceof ApiError) {
    for (const item of error.body.field_errors ?? []) out[item.field] = item.msg;
  }
  return out;
}

/**
 * 统一的错误文案。
 *
 * 必须自己处理 **422**：FastAPI 的校验错误 body 是 `{detail:[{loc,msg,type}]}`（数组），
 * 直接走 `errorText()` 会得到 `String([{...}])` = "[object Object]"。
 */
export function apiErrorText(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError)) return fallback;
  const detail = (error.body as { detail?: unknown }).detail;
  if (Array.isArray(detail)) {
    const parts = detail.map((row) => {
      const item = row as { loc?: unknown[]; msg?: string };
      const where = Array.isArray(item.loc)
        ? item.loc.filter((part) => part !== "body").join(".")
        : "";
      const msg = item.msg ?? "不合法";
      return where ? `${where}：${msg}` : msg;
    });
    return parts.filter(Boolean).join("；") || fallback;
  }
  if (error.status >= 500) return "服务异常，若名称重复请更换后重试";
  return errorText(error.body) || fallback;
}

// ---------- 提交前的 clamp（避免撞 422 数组） ----------

export const LIMITS = {
  nameMax: 128,
  noteMax: 500,
  reasonMax: 200,
  evidenceMax: 20,
  ttlMin: 1,
  ttlMax: 30,
  subjectMax: 128,
} as const;

export function clampNumber(value: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, value));
}

/** `suppression.default_ttl_days` 的兜底（后端默认 14） */
export const DEFAULT_TTL_DAYS = 14;
