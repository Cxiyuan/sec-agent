"use client";

const TOKEN_KEY = "shentong_token";
const LOGIN_PATH = "/login";

export function storage(): Storage | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  return storage()?.getItem(TOKEN_KEY) ?? null;
}

export function setToken(token: string) {
  storage()?.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  storage()?.removeItem(TOKEN_KEY);
}

/** 结构化错误响应体（400/409 时后端返回的字段）。 */
export interface ApiErrorBody {
  detail?: string;
  conflict?: string;
  hint?: string;
  truncated?: boolean;
  field_errors?: { field: string; msg: string }[];
  errors?: { row: number; ip?: string; msg: string }[];
  existing?: ConflictExisting;
  holders?: AssetBrief[];
  ips?: string[];
}

/** 结构化 API 错误：body 里带 conflict / field_errors / errors 等，供界面做提示与决策。 */
export class ApiError extends Error {
  status: number;
  body: ApiErrorBody;

  constructor(status: number, body: ApiErrorBody) {
    super(String(body.detail ?? `请求失败 (${status})`));
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/** 把 field_errors / errors 拼成可读文本。 */
export function errorText(body: ApiErrorBody | undefined): string {
  if (!body) return "请求失败";
  if (body.field_errors?.length) {
    return body.field_errors.map((e) => `${e.field}：${e.msg}`).join("；");
  }
  if (body.errors?.length) {
    const head = body.errors
      .slice(0, 5)
      .map((e) => `第${e.row}行 ${e.msg}`)
      .join("；");
    return body.errors.length > 5 ? `${head} …（共 ${body.errors.length} 处）` : head;
  }
  return String(body.detail ?? "请求失败");
}

async function parseError(res: Response): Promise<ApiError> {
  const text = await res.text();
  let body: ApiErrorBody;
  try {
    body = JSON.parse(text) as ApiErrorBody;
  } catch {
    body = { detail: text };
  }
  return new ApiError(res.status, body);
}

export async function apiFetch<T = unknown>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
  const headers = new Headers({ "Content-Type": "application/json" });
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const extra = options.headers as Record<string, string> | undefined;
  if (extra) {
    for (const [k, v] of Object.entries(extra)) headers.set(k, v);
  }

  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    clearToken();
    redirectToLogin();
    throw new ApiError(401, { detail: "未登录或凭证失效" });
  }
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as T;
}

/** 带认证的文件上传（multipart，不设 Content-Type，由浏览器补边界）。 */
export async function apiUpload<T = unknown>(path: string, form: FormData): Promise<T> {
  const token = getToken();
  const res = await fetch(path, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: form,
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as T;
}

/** 跳回登录页（仅内部固定路径；用 replace 避免历史堆积）。 */
function redirectToLogin() {
  const loc = globalThis.location as Location | undefined;
  if (!loc || loc.pathname.startsWith(LOGIN_PATH)) return;
  loc.replace(LOGIN_PATH);
}

// ---------- 类型定义（与后端对应） ----------

export interface AttackEvidence {
  id?: number | string;
  type?: string;
  src?: string;
  dst?: string;
  summary?: string;
}

export interface AttackStage {
  stage: string;
  description?: string;
  evidence?: AttackEvidence[];
}

export interface AttackChain {
  stages?: AttackStage[];
  summary?: string;
  confidence?: number;
  /** 自主取证调查写入的增量字段（旧数据没有，界面自动跳过） */
  case_id?: string;
  path?: InvestigationStage[];
  timeline?: InvestigationTimelineItem[];
  lateral?: InvestigationLateral[];
  exfil?: InvestigationExfil[];
  iocs?: InvestigationIoc[];
  assets_impacted?: InvestigationAsset[];
  gaps?: InvestigationGap[];
  status?: string;
}

export interface Profile {
  basic?: {
    src_ips?: string[];
    geo?: string;
    tool_stack?: string[];
    assets_targeted?: string[];
  };
  behavior?: {
    ttps?: string[];
    target_preference?: string;
    time_pattern?: string;
    motivation?: string;
  };
}

export interface AnomalyFinding {
  kind?: string;
  reason?: string;
}

export interface Anomaly {
  findings?: AnomalyFinding[];
}

export interface ResponseSuggestion {
  category: string;
  action: string;
  detail: string;
}

/** 聚合规模（实时链路）：命中次数 / 规则分布 / 目标与端口 / 首末时间 */
export interface GroupAggregate {
  hits?: number;
  rules?: Record<string, number>;
  dst_ips?: string[];
  dst_ports?: string[];
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface EventGroupItem {
  id: string;
  fingerprint: string;
  src_ips: string[];
  dst_ips: string[];
  window_start: string | null;
  window_end: string | null;
  event_count: number;
  triage_score: number;
  status: string;
  severity: string | null;
  business_context: BusinessContext | null;
  lookback: LookbackInfo | null;
  memory_hits: MemoryRecall | null;
  profile_hits: ProfileHits | null;
  attack_chain: AttackChain | null;
  profile: Profile | null;
  anomaly: Anomaly | null;
  response_suggestions: ResponseSuggestion[] | null;
  /** 实时链路的聚合规模（实时入口产生；兜底窗口链路为空） */
  aggregate?: GroupAggregate | null;
  /** 被排除过滤命中：可见可回溯，但不参与模型分析与报告 */
  excluded?: boolean;
  created_at: string | null;
}

/** 排除过滤条件（结构与规则一致，另支持命中规则元数据字段） */
export interface ExclusionConditions {
  logic?: string;
  rules?: RuleCondition[];
}

/** 用户自定义排除过滤：命中则事件仍落库，但跳过全部模型调用与报告 */
export interface ExclusionFilterItem {
  id: string;
  name: string;
  description: string;
  conditions: ExclusionConditions;
  enabled: boolean;
  priority: number;
  created_at: string | null;
  updated_at: string | null;
}

/** 排除命中的样例（最多留 3 条，用来核对“到底排掉了什么”） */
export interface ExclusionSample {
  at: string;
  ts: string;
  rule: string;
  src_ip: string;
  dst_ip: string;
  event_type: string;
  summary: string;
}

export interface ExclusionStats {
  counts: Record<string, number>;
  last_hit_at: string | null;
  samples: Record<string, ExclusionSample[]>;
}

export interface ExclusionFields {
  fields: string[];
  rule_fields: string[];
  operators: string[];
}

/** 分析网段组 */
export interface AnalysisScope {
  id: string;
  name: string;
  description: string;
  cidrs: string[];
  enabled: boolean;
  updated_at: string | null;
}

export interface ScopeStatus {
  configured: boolean;
  total: number;
  enabled_count: number;
}

/** 回溯决策与历史行为 */
export interface LookbackInfo {
  hours: number;
  reason: string;
  log_count: number;
  event_count: number;
  summary: string;
}

/** 持续性统计 */
export interface PersistenceInfo {
  count: number;
  first_seen: string | null;
  last_seen: string | null;
  severities: Record<string, number>;
  persistent: boolean;
  window_days: number;
}

export interface MemoryBrief {
  id: string;
  summary: string;
  severity: string | null;
  created_at: string | null;
  ips: string[];
}

/** 历史记忆召回结果（存于 event_groups.memory_hits） */
export interface MemoryRecall {
  memories?: MemoryBrief[];
  persistence?: PersistenceInfo;
}

/** 账号 / 会话画像条目 */
export interface EntityProfileItem {
  id: string;
  kind: string;
  entity_key: string;
  entity_display: string;
  obs_count: number;
  risk_score: number;
  first_seen: string | null;
  last_seen: string | null;
  src_ips: Record<string, number>;
  user_agents: Record<string, number>;
  paths: Record<string, number>;
  hour_hist: Record<string, number>;
  success_count: number;
  fail_count: number;
  anomalies: string[];
}

/** 画像命中的异常（存于 event_groups.profile_hits） */
export interface ProfileHit {
  kind: string;
  key: string;
  display: string;
  risk: number;
  reasons: string[];
  obs_count: number;
  src_ips: string[];
  count: number;
}

export interface ProfileHits {
  entities?: ProfileHit[];
  anomalies?: ProfileHit[];
}

/** Zeek 采集：网卡与状态 */
export interface ZeekIfaceInfo {
  name: string;
  state: string;
  mtu: number;
}

export interface ZeekStatus {
  interface: string;
  bpf_filter: string;
  local_nets: string;
  effective_local_nets: string[];
  last_reload: string | null;
  config_path: string;
  detected: ZeekIfaceInfo[];
  rotation_hours: number;
  retention_days_local: number;
}

/** ES 连接与保留配置 */
export interface EsConfigInfo {
  url: string;
  username: string;
  password_set: boolean;
  zeek_index: string;
  wazuh_index: string;
  retention_days: number;
  retention_min_days: number;
  ilm_policy: string;
}

export interface EsIndexInfo {
  index: string;
  docs?: string;
  store?: string;
  created?: string;
}

export interface EsStatus {
  health: { status?: string; cluster_name?: string; nodes?: number };
  indices: EsIndexInfo[];
  ilm: { policy: string; retention_days: number; exists?: boolean; version?: number };
}

/** 持续性威胁聚合项（驾驶舱） */
export interface PersistentItem {
  ip: string;
  count: number;
  last_seen: string | null;
  severities: Record<string, number>;
}

/** 分析记忆条 */
export interface MemoryItem {
  id: string;
  kind: string;
  fingerprint: string;
  severity: string | null;
  summary: string;
  ips: string[];
  asset_ids: string[];
  detail?: Record<string, unknown>;
  window_start: string | null;
  window_end: string | null;
  created_at: string | null;
}

export interface BusinessContext {
  lan_ips?: string[];
  assets?: AssetBrief[];
  knowledge?: { source_type: string; source_id: string; content: string; score: number }[];
  text?: string;
}

export interface AssetBrief {
  id?: string;
  ip: string;
  asset_name?: string;
  hostname?: string;
  business_system?: string;
  importance?: string;
  asset_type?: string;
  network_zone?: string;
  owner?: string;
  description?: string;
}

/** 409 冲突响应里回带的“已存在”对象：资产或文档都可能。 */
export interface ConflictExisting extends AssetBrief {
  title?: string;
  filename?: string;
  mime_type?: string;
  size?: number;
  status?: string;
  uploaded_at?: string | null;
}

export interface AssetItem {
  id: string;
  ip: string;
  extra_ips: string[];
  hostname: string;
  asset_name: string;
  business_system: string;
  owner: string;
  importance: string;
  asset_type: string;
  network_zone: string;
  os: string;
  services: string;
  tags: string[];
  location: string;
  description: string;
  is_external: boolean;
  allow_ip_share: boolean;
  embedding_status: string;
}

export interface DocumentItem {
  id: string;
  title: string;
  filename: string;
  mime_type: string;
  size: number;
  status: string;
  uploaded_at: string | null;
}

/** Logstash 采集：常用参数 */
export interface LogstashParams {
  es_enabled: boolean;
  es_host: string;
  zeek_index: string;
  wazuh_index: string;
  redis_enabled: boolean;
  redis_host: string;
  redis_port: number;
  redis_db: number;
  redis_key: string;
}

/** Logstash 采集：状态与配置 */
export interface LogstashStatus {
  params: LogstashParams;
  params_applied: boolean;
  pipeline: string;
  default_pipeline: string;
  config_path: string;
  backup_path: string;
  updated_at: string | null;
  beats: { port: number; hint: string };
  logstash: {
    alive: boolean;
    error?: string;
    reloads_successes?: number;
    reloads_failures?: number;
    events_in?: number;
    events_filtered?: number;
    events_out?: number;
  };
  queue_depth: number | null;
}

export interface DetectorStats {
  enabled: boolean;
  queue_raw: number | null;
  queue_digest: number | null;
  queue_processing: number | null;
  delivered_this_minute: number | null;
  rate_limit_per_minute: number;
  queue_max: number;
  digest_max_age_seconds: number;
  dropped: Record<string, number>;
  last_dropped_at: string | null;
  /** 投递前去重：省下的重复 LLM 调用 */
  dedup?: {
    enabled: boolean;
    inflight_ttl_seconds: number;
    skipped_total: number;
    last_skipped_at: string | null;
    inflight: number;
    done: number;
  };
  /** 投递了但分析失败（漏分析可见性） */
  task_failed?: { failed_total: number; last_failed_at: string | null };
  /** 选主状态：谁在消费 */
  leader?: { holder: string | null; ttl_seconds: number } | null;
  error?: string;
}

export interface RuleCondition {
  field?: string;
  op?: string;
  value?: string | number | boolean | (string | number)[];
  logic?: string;
  rules?: RuleCondition[];
}

export interface RuleConditions {
  logic?: string;
  rules?: RuleCondition[];
}

export interface RuleItem {
  id: string;
  name: string;
  description: string;
  conditions: RuleConditions;
  severity: string;
  source: string;
  enabled: boolean;
  priority: number;
}

/** 脚本工具元信息（供技能表单选择） */
export interface SkillTool {
  name: string;
  category: string;
  description: string;
}

/** 安全分析技能（SOP + 关联工具，按事件类型路由） */
export interface SkillItem {
  id: string;
  name: string;
  description: string;
  sop: string;
  event_types: string[];
  tools: string[];
  source: string;
  enabled: boolean;
  priority: number;
}

/** 事件组详情（含关联事件） */
export interface EventItem {
  id: string;
  source_system?: string;
  ts: string | null;
  event_type: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  severity?: string;
  hit_rule?: string | null;
  edge_score?: number;
  summary?: string;
  /** 该事件被排除过滤命中（仍可见，但不参与模型分析） */
  excluded?: boolean;
}

export interface GroupDetail extends EventGroupItem {
  events: EventItem[];
  /** 关键 IP：只突出真正有问题的（外网来源置顶、按命中排序），其余折叠在 other_* */
  key_ips?: KeyIps;
}

/** 详情里的可疑来源 IP（命中事件的源地址） */
export interface KeyIpActor {
  ip: string;
  external: boolean;
  hits: number;
  rules: string[];
  types?: string[];
  first?: string | null;
  last?: string | null;
}

/** 详情里的被打目标 IP（命中事件的目的地址） */
export interface KeyIpTarget {
  ip: string;
  external: boolean;
  hits: number;
  rules: string[];
  ports: number[];
}

export interface KeyIps {
  actors: KeyIpActor[];
  targets: KeyIpTarget[];
  external_actors: KeyIpActor[];
  /** 本组涉及但未命中任何事件的 IP（详情默认折叠） */
  other_src: string[];
  other_dst: string[];
  total_src: number;
  total_dst: number;
}

/** CSV 导入预览报告 */
export interface ImportPreview {
  ok: boolean;
  truncated: boolean;
  total_rows: number;
  errors: { row: number; ip?: string; msg: string }[];
  new_count: number;
  duplicates: { row: number; ip: string; existing: AssetBrief }[];
  ip_conflicts: { row: number; ip: string; holders: AssetBrief[] }[];
  non_lan: { row: number; ip: string }[];
}

/** CSV 导入结果 */
export interface ImportResult {
  created: number;
  updated: number;
  skipped: number;
  external: number;
}

// ---------- 网络拓扑 ----------

export interface TopologyNodeType {
  key: string;
  name: string;
  icon: string;
  color: string;
  builtin: boolean;
  sort: number;
}

export interface NodeTypeList {
  items: TopologyNodeType[];
  icon_candidates: string[];
}

export interface TopoNodeData extends Record<string, unknown> {
  label: string;
  node_type: string;
  asset_ids: string[];
  zone: string;
  note: string;
}

export interface TopoNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data: TopoNodeData;
}

export interface TopoEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  type?: string;
}

export interface TopoGraph {
  nodes: TopoNode[];
  edges: TopoEdge[];
}

export interface TopologyItem {
  id: string;
  name: string;
  description: string;
  node_count: number;
  edge_count: number;
  enabled: boolean;
  status: string;
  indexed_at: string | null;
  updated_at: string | null;
}

export interface TopologyDetail extends TopologyItem {
  graph: TopoGraph;
}

// ---------- 攻击者案件与自主取证调查 ----------

/** 完整路径里的一个阶段（带证据引用） */
export interface InvestigationStage {
  stage: string;
  description?: string;
  start?: string | null;
  end?: string | null;
  assets?: string[];
  evidence_refs?: string[];
}

export interface InvestigationTimelineItem {
  ts?: string | null;
  type?: string;
  src?: string;
  dst?: string;
  summary?: string;
  ref?: string;
}

export interface InvestigationLateral {
  src?: string;
  dst?: string;
  method?: string;
  evidence_refs?: string[];
}

export interface InvestigationExfil {
  dst?: string;
  bytes?: number;
  evidence_refs?: string[];
}

export interface InvestigationIoc {
  type?: string;
  value?: string;
  intel?: Record<string, unknown>;
  evidence_refs?: string[];
}

export interface InvestigationAsset {
  ip?: string;
  asset?: string;
  importance?: string;
  role?: string;
}

export interface InvestigationGap {
  missing?: string;
  why?: string;
  next_action?: string;
}

export interface InvestigationBudget {
  steps?: number;
  queries?: number;
  llm_calls?: number;
  tokens_est?: number;
  elapsed_ms?: number;
  stop_reason?: string;
  limits?: { max_steps?: number; max_queries?: number; max_llm_calls?: number; timeout_seconds?: number };
}

export interface InvestigationQueryItem {
  step?: number;
  tool?: string;
  params?: Record<string, unknown>;
  result_count?: number | null;
  error?: string | null;
  ms?: number;
}

/** 一轮调查的结果（与后端 event_groups.attack_chain 超集同结构） */
export interface InvestigationResult {
  version?: number;
  case_id?: string;
  round?: number;
  kind?: string;
  status?: string;
  confidence?: number;
  summary?: string;
  path?: InvestigationStage[];
  timeline?: InvestigationTimelineItem[];
  lateral?: InvestigationLateral[];
  exfil?: InvestigationExfil[];
  iocs?: InvestigationIoc[];
  assets_impacted?: InvestigationAsset[];
  gaps?: InvestigationGap[];
  dropped?: string[];
  attacker?: {
    identity?: string;
    basic?: Profile["basic"];
    behavior?: Profile["behavior"];
    ttps?: string[];
    src_ips?: string[];
  };
  /** 兼容旧界面/报告的攻击链字段 */
  stages?: AttackStage[];
  query_trail?: InvestigationQueryItem[];
  budget?: InvestigationBudget;
}

/** 攻击者案件（列表项） */
export interface AttackerCaseItem {
  id: string;
  attacker_key: string;
  title: string;
  keys: Record<string, string[]>;
  status: string;
  severity: string | null;
  src_ips: string[];
  dst_ips: string[];
  group_fingerprints: string[];
  group_count: number;
  event_count: number;
  event_types: string[];
  first_seen: string | null;
  last_seen: string | null;
  rounds_total: number;
  rounds_today: number;
  last_dispatched_at: string | null;
  next_allowed_at: string | null;
  last_error: string;
  merge_suggestion: { case_ids?: string[]; reason?: string; at?: string } | null;
  created_at: string | null;
  updated_at: string | null;
  pending_signal: Record<string, unknown>;
  /** 列表接口附加：最新结论摘要 / 置信度 / 阶段名 */
  summary?: string;
  confidence?: number;
  path_stages?: string[];
  investigation?: InvestigationResult | null;
}

/** 案件成员事件组（简表） */
export interface CaseGroupBrief {
  fingerprint: string;
  window_start: string | null;
  window_end: string | null;
  src_ips: string[];
  dst_ips: string[];
  event_count: number;
  severity: string | null;
  status: string;
  triage_score: number;
}

export interface AttackerCaseDetail extends AttackerCaseItem {
  groups: CaseGroupBrief[];
}

/** 调查轮次（含查询轨迹与预算，取证可审计） */
export interface InvestigationRound {
  id: string;
  round: number;
  kind: string;
  instruction: string;
  status: string;
  steps: number;
  llm_calls: number;
  tokens: number;
  elapsed_ms: number;
  error: string;
  query_trail: InvestigationQueryItem[];
  budget: InvestigationBudget;
  result: InvestigationResult | null;
  created_at: string | null;
  finished_at: string | null;
}

/** 调查运行统计 */
export interface InvestigationStats {
  enabled: boolean;
  min_severity: string;
  cases_total: number;
  cases_by_status: Record<string, number>;
  rounds_today: number;
  max_rounds_per_day: number;
  cooldown_minutes: number;
  rounds_by_status: Record<string, number>;
  tokens_est_total: number;
  queue_depth?: number | null;
  reports?: number;
  limits: Record<string, number>;
  queue_error?: string;
}

/** 证据清单条目（含原始证据，已脱敏） */
export interface EvidenceItem {
  ref: string;
  kind?: string;
  ts?: string | null;
  source_system?: string;
  summary?: string;
  raw?: Record<string, unknown>;
  note?: string;
  error?: string;
}

// ---------- 事件组证据链 ----------

/** 一条证据（组内命中日志或调查引用的证据），可用 ref 回指原始记录 */
export interface EvidenceChainItem {
  ref: string;
  kind: string; // event | es_doc | note
  ts?: string | null;
  event_type?: string | null;
  source_system?: string | null;
  src?: string | null;
  dst?: string | null;
  protocol?: string | null;
  severity?: string | null;
  hit_rule?: string | null;
  edge_score?: number | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  /** 阶段证据的出处说明（如"来自攻击链分析"） */
  note?: string;
  summary?: string;
  excluded?: boolean;
  /** 该证据支撑了哪些攻击阶段（证据链的核心：把证据链到结论上） */
  stages?: string[];
  raw?: Record<string, unknown> | { _truncated?: boolean; _preview?: string; _chars?: number };
  error?: string;
}

/** 攻击链阶段及其引用的证据 */
export interface EvidenceChainStage {
  stage: string;
  description?: string;
  evidence_refs: string[];
}

export interface EvidenceChain {
  group_id: string;
  fingerprint: string;
  severity: string | null;
  stages: EvidenceChainStage[];
  items: EvidenceChainItem[];
  investigation: {
    case_id?: string | null;
    status?: string | null;
    round?: number | null;
    confidence?: number | null;
    has_result: boolean;
  };
  counts: {
    events: number;
    investigation_refs: number;
    total: number;
    stages: number;
    linked: number;
    events_truncated: boolean;
    raw_max_chars: number;
    raw_enabled: boolean;
  };
}
