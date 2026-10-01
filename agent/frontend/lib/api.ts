"use client";

// 客户端核心（token / 错误 / 请求封装）与共享类型（AssetBrief/ConflictExisting）来自共享包
import type { AssetBrief } from "@shentong/ui";
export * from "@shentong/ui";

// ---------- 类型定义（与后端对应，agent 侧） ----------

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
  /** 展示用唯一编号：EG-<10 位>（人工沟通/报告引用） */
  display_id?: string;
  /** 所属攻击者案件指针（案件叙事不再覆盖本组攻击链） */
  case_id?: string;
  /** 案件视角副本（summary/path/rounds/superseded）——详情页可折叠查看 */
  case_context?: {
    case_id?: string;
    title?: string;
    severity?: string | null;
    status?: string;
    summary?: string;
    path?: { stage?: string; description?: string; evidence_refs?: string[] }[];
    confidence?: number | null;
    rounds?: number;
    updated_at?: string;
    superseded?: boolean;
    rebuilt_by?: string;
    superseded_from?: Record<string, unknown>;
  } | null;
  /** 误报治理：内外网方向（in→in / in→out / out→in / out→out / unknown） */
  direction?: string;
  /** 为什么跳过（排除过滤器命中，或策略判定为「内网常规流量」） */
  exclude_reason?: string;
  /** 定级被约束的原因（如「内网方向封顶」「无可验证证据链」） */
  severity_cap_reason?: string;
  created_at: string | null;
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
  /** 展示用唯一编号：AC-<8 位> */
  display_id?: string;
  /** 归并依据：真正促成归并的键（凭什么都在一起） */
  merge_basis?: string[];
  /** 自动拆分原因（达规模上限/重建拆分） */
  split_reason?: string;
  /** 被哪个重建批次取代（非空即已退场） */
  superseded_by?: string;
  /** 结论存疑（声称高级行为但缺结构化证据） */
  contradiction?: boolean;
  degraded?: boolean;
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
  /** 空壳案件治理：零轮次案件数与占比（归档后应明显下降） */
  cases_empty?: number;
  cases_empty_perc?: number;
  cases_shelved?: number;
  cases_closed?: number;
  /** 调查护栏计数：invalid_json / truncated / salvaged / no_progress / repeat */
  guards?: Record<string, number>;
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

/** 重建 dry-run 结果（只算不写，先核对再执行） */
export interface RebuildDryRun {
  groups: number;
  old_cases: number;
  new_cases: number;
  old_max_groups: number;
  new_max_groups: number;
  oversized_before: number;
  oversized_after: number;
  junk_keys_before: number;
  sample_new: { attacker_key: string; groups: number; severity: string; merge_basis: string[]; split_reason: string }[];
  sample_old: { id: string; attacker_key: string; groups: number; severity: string | null }[];
}

/** 重建批次 */
export interface RebuildRun {
  id: string;
  dry_run: boolean;
  status: string;
  counts: Record<string, unknown>;
  started_at: string | null;
  finished_at: string | null;
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
