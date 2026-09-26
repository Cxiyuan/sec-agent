/**
 * 展示层统一格式化：级别/状态中文 + **北京时间**。
 *
 * 为什么固定用北京时间而不是跟随浏览器时区：这是部署在国内的运维后台，
 * 同一条告警在运维、值班、领导三种机器上必须显示成同一个时间，
 * 否则排查时对时间线会对不上（而且容器日志也用北京时间，前端要一致）。
 */

const TIME_ZONE = "Asia/Shanghai";

export const SEVERITY_LABEL: Record<string, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "信息",
};

export const STATUS_LABEL: Record<string, string> = {
  // 事件组
  analyzing: "分析中",
  analyzed: "已分析",
  report_generated: "已出报告",
  pending_confirmation: "待人工确认",
  dismissed: "已忽略",
  excluded: "已排除（不跑模型）",
  // 攻击者案件
  open: "待调查",
  investigating: "调查中",
  investigated: "已调查",
  failed: "失败",
  closed: "已关闭",
  // 调查轮次
  running: "进行中",
  succeeded: "已完成",
  partial: "部分完成",
  budget_exhausted: "预算耗尽",
  // 资产/文档/拓扑索引
  pending: "待处理",
  indexed: "已索引",
};

/** 内外网方向 → 中文（界面上不出现 in→in 这种符号） */
export const DIRECTION_LABEL: Record<string, string> = {
  "in→in": "内→内",
  "in→out": "内→外",
  "out→in": "外→内",
  "out→out": "外→外",
  unknown: "方向未知",
};

/** 级别 → 中文（未知值原样返回，空值显示"未定级"） */
export function severityText(severity?: string | null): string {
  const key = String(severity || "").toLowerCase();
  if (!key) return "未定级";
  return SEVERITY_LABEL[key] ?? String(severity);
}

/** 状态 → 中文（未知值原样返回） */
export function statusText(status?: string | null): string {
  const key = String(status || "").toLowerCase();
  if (!key) return "-";
  return STATUS_LABEL[key] ?? String(status);
}

/** 方向 → 中文（未知值原样返回，空值返回空串） */
export function directionText(value?: string | null): string {
  if (!value) return "";
  return DIRECTION_LABEL[value] ?? value;
}

function toDate(value?: string | Date | null): Date | null {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

const dateTimeFmt = new Intl.DateTimeFormat("zh-CN", {
  timeZone: TIME_ZONE,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const dateFmt = new Intl.DateTimeFormat("zh-CN", {
  timeZone: TIME_ZONE,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
});

const timeFmt = new Intl.DateTimeFormat("zh-CN", {
  timeZone: TIME_ZONE,
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function tidy(text: string): string {
  // zh-CN 默认给 2026/09/25 21:30:00，统一换成 2026-09-25 21:30:00
  return text.replace(/\//g, "-");
}

/** 日期时间（北京时间）：2026-09-25 21:30:00 */
export function formatDateTime(value?: string | Date | null): string {
  const d = toDate(value);
  return d ? tidy(dateTimeFmt.format(d)) : "-";
}

/** 只要日期（北京时间）：2026-09-25 */
export function formatDate(value?: string | Date | null): string {
  const d = toDate(value);
  return d ? tidy(dateFmt.format(d)) : "-";
}

/** 只要时分秒（北京时间）：21:30:00 */
export function formatTime(value?: string | Date | null): string {
  const d = toDate(value);
  return d ? tidy(timeFmt.format(d)) : "-";
}
