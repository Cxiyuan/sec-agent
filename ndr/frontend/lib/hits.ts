import * as React from "react";
import {
  agentVerdictText,
  agentVerdictVariant,
  ApiError,
  Badge,
  formatDateTime,
  ruleText,
  severityText,
  severityVariant,
} from "@shentong/ui";
import type {
  HitEventItem,
  HitEventList,
  HitEventStats,
  HitStatsGroup,
  HitTopRule,
  HitTrendPoint,
} from "@/lib/api";

/**
 * 事件中心（`/events`）的共享层：类型再导出 + 查询构造 + 从运营中心迁来的 helper。
 *
 * 文件归属的依据（视觉规范 9.3 / 体验规范 §10.2）：
 * - 类型定义在 `lib/api.ts`（与全站一致），这里再导出，页面 import 一处即可；
 * - `buildHitsQuery` 与 `logs-panel.tsx` 的 `buildQuery` 同构，参数集按
 *   `/api/detector/hits` 契约（六维度 + 分页 + 排序）；
 * - `FIELD_LABELS` / `HIDDEN_FIELDS` / `fieldLabel` / `eventTime` / `severityBadge`
 *  从 `status-panel.tsx` 原样迁移（不是重写）——这些中文名和踩坑分支是攒出来的。
 */

// ---------- 类型再导出（定义在 lib/api.ts） ----------

export type { HitEventItem, HitEventList, HitEventStats, HitStatsGroup, HitTopRule, HitTrendPoint };

// ---------- 查询表单与构造 ----------

/** 筛选表单态（与查询态分离：文本维度 Enter/按钮提交，离散维度立即重查） */
export interface HitForm {
  /** 关键字：跨字段子串（rule/src_ip/client/via/evidence），唯一能搜进证据的维度 */
  q: string;
  /** 事件归类子串（只匹配归类名，不搜证据） */
  rule: string;
  /** IP 子串：src_ip / client / via / dst_ips 四字段 or */
  ip: string;
  /** 来源三类：值传英文 key（feature_match/…），标签显中文；空 = 全部 */
  sourceKind: string;
  /** 严重度：小写英文精确匹配（critical/high/medium/low/info）；空 = 全部 */
  severity: string;
  /**
   * 智能体口径（2026-10 判定权转移：事件列表默认只看智能体确认为可疑/威胁的）：
   * `confirmed` = true_positive,suspicious；`unanalyzed` = 还没结论；`all` = 不筛。
   */
  agentStatus: "confirmed" | "unanalyzed" | "all";
  /** 时间范围（分钟）：四档 60/360/1440/10080，恒 > 0（Q-A 裁决砍掉「不限」） */
  minutes: number;
  /** 勾选 = 请求带 include_ignored=true；默认 false（不传） */
  includeIgnored: boolean;
  /** 排序：recent 最近在前（默认）/ oldest / count 按命中次数 */
  sort: "recent" | "oldest" | "count";
  /** 每页条数：20/50/100/200，后端上限 200 */
  size: number;
}

/** 表单默认值（体验规范 §2.4 / §4.1）：24h / recent / 不含已忽略 / 50 条 */
export const EMPTY_HIT_FORM: HitForm = {
  q: "",
  rule: "",
  ip: "",
  sourceKind: "",
  severity: "",
  agentStatus: "confirmed",
  minutes: 1440,
  includeIgnored: false,
  sort: "recent",
  size: 50,
};

/**
 * 命中事件查询串：与日志页 `buildQuery` 同构，参数集按 `/api/detector/hits` 契约。
 *  时间范围只有四档（Q-A 砍掉「不限」，体验规范 §4.3），minutes 恒 > 0。
 */
export function buildHitsQuery(form: HitForm, nextOffset: number): string {
  const params = new URLSearchParams();
  const put = (key: string, value: string) => {
    if (value.trim()) params.set(key, value.trim());
  };
  put("q", form.q);                    // 跨字段关键字（含 evidence）
  put("rule", form.rule);              // 事件归类子串
  put("ip", form.ip);                  // src_ip/client/via/dst_ips 子串
  // 智能体口径：默认只看确认的可疑/威胁（判定权在智能体，规则命中只是初判参考）
  if (form.agentStatus === "confirmed") put("agent_status", "true_positive,suspicious");
  else if (form.agentStatus === "unanalyzed") put("agent_status", "unanalyzed");
  put("source_kind", form.sourceKind); // 值 = 英文 key（feature_match/…），标签显中文
  put("severity", form.severity);      // 值 = 小写英文（后端 == 精确匹配，先 lower）
  params.set("minutes", String(form.minutes)); // 四档之一：60/360/1440/10080，恒 >0
  if (form.includeIgnored) params.set("include_ignored", "true"); // 不传 = 默认 false
  params.set("sort", form.sort);       // recent | oldest | count
  params.set("limit", String(form.size)); // 20/50/100/200，后端上限 200
  params.set("offset", String(nextOffset));
  return params.toString();
}

/**
 * 概览与列表同窗口：直接用同一个 `form.minutes`，不需要降级函数（「不限」档已砍，§4.3）。
 * 保留这个命名点，是为了把「stats 与列表同一个 minutes」的契约钉在一处——若将来
 * 重新引入「不限」档，`hits_stats` 的 `max(1, minutes or 1440)` 静默改写在这里降级。
 */
export function statsMinutes(form: HitForm): number {
  return form.minutes > 0 ? form.minutes : 1440;
}

/** 错误条 / 空态里的人话名（含路径）：把「读不到」与「真没有」区分开 */
export const SRC = {
  list: "事件列表（/api/detector/hits）",
  stats: "事件概览（/api/detector/hits/stats）",
};

// ---------- 迁自 status-panel.tsx 的 helper（原样迁移，勿重写） ----------

/** 「事件内容」里字段名的中文名（用户要求：显示出来的字段一律中文）。
 *  覆盖实测出现过的全部字段（Zeek 与 Suricata EVE 两套命名），未收录的按原名显示。 */
const FIELD_LABELS: Record<string, string> = {
  proxy_user: "代理认证账号",
  ts: "事件时间",
  timestamp: "事件时间",
  uid: "连接标识",
  source: "来源",
  app_proto: "应用协议",
  direction: "方向",
  protocol: "协议",
  conn_state: "连接状态",
  signature: "命中签名",
  signature_id: "签名编号（SID）",
  signature_category: "签名类别",
  signature_severity: "签名严重度",
  signature_threat_type: "威胁类型",
  alert_action: "引擎动作",
  payload_printable: "命中载荷",
  summary: "摘要",
  "tls.sni": "TLS 域名（SNI）",
  "tls.version": "TLS 版本",
  tls_version: "TLS 版本",
  "tls.subject": "证书主体",
  "tls.issuerdn": "证书签发者",
  cert_issuer: "证书签发者",
  "tls.serial": "证书序列号",
  "tls.fingerprint": "证书指纹",
  "tls.notbefore": "证书生效时间",
  "tls.notafter": "证书到期时间",
  "tls.session_resumed": "会话复用",
  ja3: "JA3 客户端指纹",
  ja3s: "JA3S 服务端指纹",
  ja4: "JA4 指纹",
  "http.url": "请求 URL",
  "http.hostname": "域名（Host）",
  "http.http_method": "请求方法",
  "http.status": "状态码",
  "http.length": "响应长度",
  "http.protocol": "HTTP 版本",
  "http.http_user_agent": "User-Agent",
  "http.http_content_type": "内容类型",
  "http.http_refer": "来源页（Referer）",
  "http.xff": "代理头（XFF）",
  "http.http_port": "HTTP 端口",
  uri_path: "请求路径",
  query_string: "查询串",
  method: "方法",
  status_code: "状态码",
  user_agent: "User-Agent",
  referer: "来源页",
  content_type: "内容类型",
  body: "请求体",
  resp_body: "响应体",
  req_headers: "请求头",
  account: "账号",
  session_id: "会话 ID",
  query: "DNS 查询名",
  qtype: "查询类型",
  filename: "文件名",
  md5: "MD5",
  sha1: "SHA1",
  sha256: "SHA256",
  // Zeek 原始字段（出现在「其它字段」里）
  client_version: "客户端版本",
  client_ciphers: "客户端密码套件",
  client_comp_methods: "客户端压缩方法",
  client_curves: "客户端曲线",
  client_key_share_groups: "客户端密钥共享组",
  client_supported_versions: "客户端支持版本",
  cipher: "密码套件",
  curve: "椭圆曲线",
  hashalgs: "哈希算法",
  established: "握手完成",
  server_name: "服务器名",
  resumed: "会话复用",
};

/** 不在「事件内容」里重复显示的字段（详情别处已有，或属实现细节）——用户 2026-10 指定。 */
const HIDDEN_FIELDS = new Set([
  "src_ip",
  "src_port",
  "dst_ip",
  "dst_port",
  "dest_ip",
  "dest_port",
  "flow_id",
  "log_type",
  "event_type",
  "timestamp",
  "alert_action",
  "community_id",
  "other_fields",
  "source",
]);

/** 字段名 → 中文名（未收录的按原名，界面其它地方不会出现纯英文标签） */
export function fieldLabel(key: string): string {
  return FIELD_LABELS[key] ?? key;
}

/** 证据区里不重复显示的字段集合（迁自运营中心，筛选口径不变） */
export const hiddenFields = HIDDEN_FIELDS;

/** 事件时间：Zeek 的 `ts` 可能是数字、也可能是字符串化的秒级时间戳（实测 "1791816302.15616"），
 *  统一按北京时间显示；不是时间戳就按原字符串交给共享格式化。 */
export function eventTime(value: unknown): string {
  const num = typeof value === "number" ? value : Number(value);
  if (Number.isFinite(num) && num > 1e9) return formatDateTime(new Date(num * 1000));
  return formatDateTime(String(value));
}

/** 严重度文案统一走 `severityText`（共享库唯一来源）。
 *  运营中心原来自己维护了一份 `{critical:"紧急", info:"提示"}`，和共享库的
 *  `{critical:"严重", info:"信息"}` 不一致 —— 同一条告警在总览页叫"紧急"、
 *  在规则页叫"严重"，运维对不上话。迁移时连同这条注释一起保留。
 *  （本文件是 .ts：用 createElement 而不是 JSX，避免为这一个徽章把文件改成 .tsx。）
 *  `title`：悬停备注（如回退 NDR 初判时注明来源），不传不带。 */
export function severityBadge(sev: string, title?: string): React.ReactElement {
  const key = (sev || "info").toLowerCase();
  return React.createElement(Badge, { variant: severityVariant(key), title }, severityText(key));
}

/** 智能体结论徽章：中文与配色走共享库 `agentVerdictText` / `agentVerdictVariant`。
 *  无结论（variant 为 null）返回 null —— 调用方渲染「—」或空态，不渲染空徽章。 */
export function agentVerdictBadge(status: string | null | undefined): React.ReactElement | null {
  const variant = agentVerdictVariant(status);
  if (!variant) return null;
  return React.createElement(Badge, { variant }, agentVerdictText(status));
}

// ---------- 处置消息文案（体验规范 §6.4 逐字） ----------

/** 忽略成功（页面级 role=status）：行消失的误解（B2）靠这句解释修掉 */
export function ignoreOkText(id: string): string {
  return `已忽略事件 ${id.slice(0, 8)}。默认列表不再显示它；勾选『包含已忽略』可查回，处理记录见详情。`;
}

/** 加白成功（页面级 role=status）：写明白名单到底放了什么（R2），以及去哪撤 */
export function whitelistOkText(
  name: string,
  row: HitEventItem,
  scope: "src" | "src_dst",
): string {
  const client = row.client || row.src_ip || "未知请求方";
  const dst =
    scope === "src_dst" && row.dst_pairs?.length ? ` + 目的 ${row.dst_pairs[0]}` : "";
  return (
    `已加白名单『${name || ""}』：${client} + 规则『${ruleText(row.rule)}』${dst}。` +
    `只放行该规则的这一来源，不是全放行；落在配置管理 → 过滤规则，可停用/删除。该事件同时标记为已忽略。`
  );
}

/** 处置失败（Drawer 内 role=alert + 页面级同文）：错误码分流见体验规范 §6.3 */
export function actionErrorText(e: unknown): string {
  if (e instanceof ApiError) {
    const detail = e.body?.detail || e.message;
    if (e.status === 400) return `操作失败：参数不被接受（${detail}）`;
    if (e.status === 404) return "这条事件已经不在了（可能刚在别处被处理）。列表已刷新。";
    if (e.status === 409) return `操作失败：已存在同名记录（${detail}）`;
    return "操作失败：服务暂时不可用，可稍后再试";
  }
  return "操作失败：服务暂时不可用，可稍后再试";
}

/** 写接口 200 但 body 带 error 时（后端 mark_ignored 的现式）：与 §6.4 同一句式 */
export function bodyErrorText(error: string): string {
  return `操作失败：${error}`;
}

// ---------- IP 中心聚合（事件中心列表：以主机 IP 为主体，而非事件 ID 流水账） ----------

/**
 * 严重度排序：聚合时取该 IP 下最严重的那档做主徽章。
 * 与共享库 `severityText` 同口径（critical > high > medium > low > info）。
 */
export const SEV_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  "": 0,
};

/** 抽屉里「该 IP 的命中事件」子列表每页条数（固定窗口滚动 + 客户端分页） */
export const IP_SUBLIST_PAGE = 20;

/** 打开某 IP 抽屉时一次性拉取的命中数上限（后端上限 200）：够算完整聚合摘要，子列表再客户端分页 */
export const IP_FETCH_LIMIT = 200;

/**
 * 一个 IP 聚合行：同一 `client`（回落 `src_ip`）的多条命中收成一行。
 * `eventTypeCounts` / `sourceCounts` / `ruleCounts` 是「按次数加权」的聚合——
 * 某事件类型这一档的计数 = 该类型下各命中的 `count` 之和，列表里直接以 `（次数）` 呈现。
 * 顺序 = 首次出现顺序（插入序），**不**按聚合计数或时间重排（需求：谁先出现占那个位置）。
 */
export interface IpAggRow {
  ip: string;
  via?: string;
  events: HitEventItem[];
  eventTypeCounts: Array<[string, number]>;
  sourceCounts: Array<[string, number]>;
  ruleCounts: Array<[string, number]>;
  severities: string[];
  maxSeverity: string;
  /** 该 IP 下出现过的智能体结论（去重、首现顺序；空 = 都还没有结论） */
  agentStatuses: string[];
  /** 最近更新的智能体结论摘要正文（判定权威的分析内容，列表直接展示；"" = 无） */
  latestAgentSummary: string;
  /** 上条摘要的结论更新时间（ISO 字符串，用于挑「最新」一条；"" = 无） */
  latestAgentUpdatedAt: string;
  /** 展示口径的严重度：每条事件取 agent_severity ?? severity 后的最高档 */
  effectiveMaxSeverity: string;
  /** 最高档严重度是否来自智能体结论（false = 回退 NDR 初判，界面 title 注明） */
  sevFromAgent: boolean;
  totalHits: number;
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
  ignored: number;
}

/** 聚合构建期用的可变结构（Map 便于累加），最终再转成稳定排序的数组 */
interface IpAggBuilder {
  ip: string;
  via?: string;
  events: HitEventItem[];
  eventTypes: Map<string, number>;
  sources: Map<string, number>;
  rules: Map<string, number>;
  severities: string[];
  maxSeverity: string;
  agentStatuses: string[];
  latestAgentSummary: string;
  latestAgentUpdatedAt: string;
  effectiveMaxSeverity: string;
  maxAgentSeverity: string;
  totalHits: number;
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
  ignored: number;
}

/** 把若干 key 的计数按 `by` 累加进 map（空 key 跳过，避免聚合出空档） */
function bump(map: Map<string, number>, keys: string[], by: number): void {
  for (const k of keys) {
    if (!k) continue;
    map.set(k, (map.get(k) ?? 0) + by);
  }
}

/** Map → 按次数降序的二元组数组（展示稳定、重点在前；次数相同按名字排序兜底） */
function toRanked(map: Map<string, number>): Array<[string, number]> {
  return [...map.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/**
 * 对一批 `HitEventItem` 按主机 IP（`client` 优先）做首现顺序聚合。
 * 后端 `/api/detector/hits` 返的是事件 ID 级明细；聚合在前端做，不新增后端端点。
 */
export function aggregateByIp(items: HitEventItem[]): IpAggRow[] {
  const map = new Map<string, IpAggBuilder>();
  const order: string[] = [];
  for (const it of items) {
    const ip = it.client || it.src_ip || "未知请求方";
    let b = map.get(ip);
    if (!b) {
      b = {
        ip,
        events: [],
        eventTypes: new Map(),
        sources: new Map(),
        rules: new Map(),
        severities: [],
        maxSeverity: it.severity || "",
        agentStatuses: [],
        latestAgentSummary: "",
        latestAgentUpdatedAt: "",
        effectiveMaxSeverity: it.agent_severity || it.severity || "",
        maxAgentSeverity: it.agent_severity || "",
        totalHits: 0,
        eventCount: 0,
        firstSeen: it.first_seen,
        lastSeen: it.last_seen,
        ignored: 0,
      };
      map.set(ip, b);
      order.push(ip);
    }
    b.events.push(it);
    b.totalHits += it.count;
    b.eventCount += 1;
    bump(b.eventTypes, it.event_types, it.count);
    bump(b.sources, [it.source_label], it.count);
    bump(b.rules, [it.rule], it.count);
    if (it.severity && !b.severities.includes(it.severity)) b.severities.push(it.severity);
    if (SEV_RANK[it.severity || ""] > SEV_RANK[b.maxSeverity]) b.maxSeverity = it.severity;
    // 智能体结论：收集去重；展示严重度取 agent_severity ?? severity 的最高档，
    // 并记住最高档是不是智能体给的（决定界面 title 写「NDR 初判」还是「智能体结论」）
    if (it.agent_status && !b.agentStatuses.includes(it.agent_status)) {
      b.agentStatuses.push(it.agent_status);
    }
    // 智能体结论的正文（判定权威的分析内容）：保留更新时间最新的那条，
    // 列表「智能体结论」列直接展示它——主体读的是智能体说了什么，不是规则命中描述
    if (
      it.agent_summary &&
      it.agent_updated_at &&
      it.agent_updated_at >= b.latestAgentUpdatedAt
    ) {
      b.latestAgentSummary = it.agent_summary;
      b.latestAgentUpdatedAt = it.agent_updated_at;
    }
    const effSev = it.agent_severity || it.severity || "";
    if (SEV_RANK[effSev] > SEV_RANK[b.effectiveMaxSeverity]) {
      b.effectiveMaxSeverity = effSev;
    }
    if (it.agent_severity && SEV_RANK[it.agent_severity] > SEV_RANK[b.maxAgentSeverity]) {
      b.maxAgentSeverity = it.agent_severity;
    }
    if (it.last_seen > b.lastSeen) b.lastSeen = it.last_seen;
    if (it.first_seen < b.firstSeen) b.firstSeen = it.first_seen;
    if (it.ignored) b.ignored += 1;
    if (it.via && !b.via) b.via = it.via;
  }
  return order.map((ip) => {
    const b = map.get(ip)!;
    return {
      ip: b.ip,
      via: b.via,
      events: b.events,
      eventTypeCounts: toRanked(b.eventTypes),
      sourceCounts: toRanked(b.sources),
      ruleCounts: toRanked(b.rules),
      severities: b.severities,
      maxSeverity: b.maxSeverity,
      agentStatuses: b.agentStatuses,
      latestAgentSummary: b.latestAgentSummary,
      latestAgentUpdatedAt: b.latestAgentUpdatedAt,
      effectiveMaxSeverity: b.effectiveMaxSeverity,
      sevFromAgent: !!b.maxAgentSeverity && SEV_RANK[b.maxAgentSeverity] >= SEV_RANK[b.effectiveMaxSeverity],
      totalHits: b.totalHits,
      eventCount: b.eventCount,
      firstSeen: b.firstSeen,
      lastSeen: b.lastSeen,
      ignored: b.ignored,
    };
  });
}

/** 抽屉里拉「该 IP 的全部命中」：只按 IP + 时间窗 + 是否含已忽略过滤，不过其它维度 */
export function buildIpEventsQuery(
  form: HitForm,
  ip: string,
  nextOffset: number,
  limit = IP_FETCH_LIMIT,
): string {
  const params = new URLSearchParams();
  params.set("ip", ip.trim());
  params.set("minutes", String(form.minutes));
  if (form.includeIgnored) params.set("include_ignored", "true");
  params.set("sort", form.sort);
  params.set("limit", String(limit));
  params.set("offset", String(nextOffset));
  return params.toString();
}
