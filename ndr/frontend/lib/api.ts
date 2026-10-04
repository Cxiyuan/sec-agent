"use client";

// 客户端核心（token / 错误 / 请求封装）来自共享包
export * from "@shentong/ui";

// ---------- 规则与排除过滤（NDR 检测配置域） ----------

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

// ---------- 降噪过滤（入库前挡在检测器之外，事件仍进 ES） ----------

/** 降噪命中样例（最多留 3 条，用来核对“到底挡掉了什么”） */
export interface IngestFilterSample {
  at: string;
  ref: string;
  ts: string;
  source_system: string;
  event_type: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  summary: string;
}

/** 降噪过滤：命中则事件仍进 Elasticsearch，但不投检测器（不产生告警） */
export interface IngestFilterItem {
  id: string;
  name: string;
  description: string;
  conditions: RuleConditions;
  enabled: boolean;
  priority: number;
  hit_count: number;
  samples: IngestFilterSample[];
  created_at: string | null;
  updated_at: string | null;
}

export interface IngestFilterExample {
  name: string;
  description?: string;
  conditions: RuleConditions;
}

export interface IngestFilterFields {
  fields: string[];
  address_fields: string[];
  content_fields: string[];
  direction_fields: string[];
  operators: string[];
  examples: IngestFilterExample[];
  hint: string;
}

/** 试运行结果：这条条件会命中多少历史事件（不写任何配置） */
export interface IngestDryRunResult {
  errors?: string[];
  source?: string;
  hours?: number;
  scanned?: number;
  matched?: number;
  ratio?: number;
  samples?: IngestFilterSample[];
  exclude_name?: string;
  hint?: string;
}

/** 监控网段状态（未配置 → 前端强制进首次向导） */
export interface NetworksStatus {
  configured: boolean;
  count: number;
}

/** Zeek 采集：网卡与状态 */
export interface ZeekIfaceInfo {
  name: string;
  state: string;
  mtu: number;
}

export interface ZeekStatus {
  interface: string;
  /** 监控网段清单（一行一条）；bpf_filter 与 local_nets 都由它生成 */
  networks: string[];
  bpf_extra: string;
  bpf_filter: string;
  local_nets: string;
  last_reload: string | null;
  config_path: string;
  detected: ZeekIfaceInfo[];
  /** HTTP 正文落库上限（字节）：Zeek 侧截正文用，后端 normalizer 用同一个数字再截一次 */
  body_max_bytes: number;
  resp_body_max_bytes: number;
  rotation_hours: number;
  retention_days_local: number;
}

/**
 * ES 接入配置：`url` / `username` / `password_set` 是**只读展示**（连接信息由部署环境
 * 固定，见 `.env` 的 `ES_*`）；可写的只有 `events_index` 与 `retention_days`。
 */
export interface EsConfigInfo {
  url: string;
  username: string;
  password_set: boolean;
  events_index: string;
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

/**
 * Logstash 采集：常用参数。`es_host` 是**只读展示**（后端按部署环境的 `ST_ES_URL` 拍定，
 * 提交时不必也不该带）；可改的是 `events_index`。
 */
export interface LogstashParams {
  es_enabled: boolean;
  es_host: string;
  events_index: string;
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
  http: { port: number; hint: string };
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
  /** 判重：第 5 期起下放到智能体（按事件组指纹），这里只报现状与退役前的历史计数 */
  dedup?: {
    enabled: boolean;
    /** enabled=false 时的说明（如「判重已下放到智能体（按事件组指纹）」） */
    note?: string;
    inflight_ttl_seconds: number;
    skipped_total: number;
    last_skipped_at: string | null;
    inflight: number;
    done: number;
  };
  /** 投递了但分析失败（漏分析可见性） */
  task_failed?: { failed_total: number; last_failed_at: string | null };
  /** 误报治理：策略跳过的数量（内网常规流量等）——降噪必须可见 */
  policy?: { internal_routine: number; last_at: string | null };
  /** Redis 体检：内存吃满会让整条分析链静默卡死（真实事故） */
  redis?: { used: number; max: number; perc: number; used_human?: string; policy?: string };
  redis_warn?: boolean;
  /** 已处理登记因单桶超限被丢弃的条数（会被兜底重复分析） */
  handled_skipped?: number;
  /** 选主状态：谁在消费 */
  leader?: { holder: string | null; ttl_seconds: number } | null;
  /** 隔离队列 shentong:detector:failed 的深度（处理失败被隔离的条数） */
  queue_failed?: number | null;
  /** 检测器被关掉（暂停消费）时为 true；界面上必须看得见，否则「没有告警」会被误读成「没攻击」 */
  paused?: boolean;
  /** 什么时候被关的（ISO 串） */
  paused_since?: string | null;
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

// ---------- MCP 接入（智能体取数入口） ----------

/** MCP 令牌：明文只在创建 / 轮换时回一次，列表里只有前缀 */
export interface McpToken {
  id: string;
  name: string;
  prefix: string;
  enabled: boolean;
  call_count: number;
  last_used_at: string;
  created_at: string;
  /** 到期时间（ISO 串）；空串 = 永不过期 */
  expires_at?: string;
  /** 后端算好的「已过期」；过期令牌的调用会被直接拒绝 */
  expired?: boolean;
}

/** MCP 调用记录（放 Redis 有界列表，重启即清；只作运维可见性） */
export interface McpCall {
  ts: number;
  time: string;
  tool: string;
  token: string;
  ok: boolean;
  duration_ms: number;
  /** 参数摘录（截断，够定位问题） */
  detail: string;
  error: string;
}

/** 智能体写回的结论（判重权威仍在智能体侧，这里只做镜像与展示） */
export interface McpConclusion {
  id: string;
  event_id: string | null;
  fingerprint: string | null;
  thread_id: string | null;
  status: string;
  severity: string;
  summary: string;
  detail: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

/** 暴露给智能体的一个工具 */
export interface McpToolSpec {
  name: string;
  desc: string;
  params: Record<string, string>;
}

export interface McpStatus {
  service: {
    url: string;
    health_url: string;
    reachable: boolean;
    status_code?: number;
    error?: string;
  };
  token_prefix: string;
  tokens: { total: number; enabled: number; expired?: number };
  calls: { kept: number; errors: number; last_at: string };
  conclusions: { total: number; purged_expired: number };
  tools: { count: number; names: string[] };
}

// ---------- 智能体推送（第 5 期：检测器命中后经 HTTP 推给智能体） ----------

/** 推送配置（令牌只回显打码后的形态） */
export interface AgentPushConfig {
  url: string;
  token_set: boolean;
  token_masked: string;
  enabled: boolean;
  timeout_seconds: number;
  max_per_push: number;
  /** 真正生效 = 开关打开 且 填了地址；false 时检测器仍走旧的 Redis 队列交接 */
  active: boolean;
  /** 连通性自检地址（由推送地址推出：/digests → /ping） */
  ping_url: string;
}

/** 推送状态（数字来自 Redis，检测器进程写、跨重启可查） */
export interface AgentPushStatus {
  sent: number;
  /**
   * **累计**落过重发队列的批数（自 Redis 计数以来只增不减）。
   * 它不是积压：界面上「失败待重发」要用 `retry_backlog_batches`。
   */
  queued: number;
  retried: number;
  retry_failed: number;
  /** 连试多次仍失败、已判死丢弃的批数（累计） */
  retry_lost?: number;
  /** 重试队列写入失败、当场丢掉的条数（累计） */
  retry_dropped?: number;
  /** 投递失败且没能进重试队列的条数（累计，真丢） */
  undelivered?: number;
  last_success_at: string;
  last_error_at: string;
  last_error: string;
  /** 还在等重发的批数（queue_depth + processing_depth = 真积压） */
  queue_depth: number;
  processing_depth: number;
  /** 真积压批数（后端直接给的口径；老后端没有此字段时用上面两数之和） */
  retry_backlog_batches?: number;
  error?: string;
}

export interface AgentPushPayload {
  config: AgentPushConfig;
  status: AgentPushStatus;
  env: { url: string; enabled: boolean; token_set: boolean };
  hint: string;
}

export interface AgentPushTestResult {
  ok: boolean;
  url: string;
  detail: string;
}

// ---------- Wazuh 4.14 接入（第 6 期：API 管理面 + 归一化入库量） ----------

/** Wazuh API 连接信息：由部署环境固定（`ST_WAZUH_API_*`），界面只读、不可配置 */
export interface WazuhConfig {
  url: string;
  user: string;
  password_set: boolean;
  verify_tls: boolean;
  /** 地址 + 用户名 + 密码齐全才算已配置（缺什么由部署环境补） */
  configured: boolean;
}

export interface WazuhAgentsSummary {
  total: number;
  active: number;
  disconnected: number;
  never_connected: number;
}

export interface WazuhStatus {
  reachable: boolean;
  url: string;
  version: string;
  cluster_enabled: boolean;
  detail: string;
  /** 在线/断开等汇总（reachable 为 false 时全是 0） */
  agents: WazuhAgentsSummary;
}

export interface WazuhAgent {
  id: string;
  name: string;
  ip: string;
  status: string;
  version: string;
  lastKeepAlive: string;
  os?: { name?: string };
}

/** 最近 24 小时 `source_system=wazuh` 的入库量：API 通了但这里全是 0 就是「没接进来」 */
export interface WazuhIngest {
  alerts: number;
  archives: number;
  total: number;
  last_at: string | null;
  error: string;
}

export interface WazuhPayload {
  config: WazuhConfig;
  status: WazuhStatus;
  agents: WazuhAgent[];
  ingest: WazuhIngest;
  hint: string;
}

export interface WazuhRuleFile {
  filename: string;
  relative_dirname?: string;
  description?: string;
}

export interface WazuhRulesPayload {
  files: WazuhRuleFile[];
  /** etc/rules 下的自定义规则文件 */
  local: WazuhRuleFile[];
  total: number;
}

export interface WazuhRuleUploadResult {
  ok: boolean;
  filename: string;
  sent_rules: number;
  rule_ids: string[];
  verified: boolean;
  applied_rules: number;
  detail: string;
}

// ---------- 基线（第 8 期从智能体侧迁来） ----------

/** 数值基线的学习进度：`learning_keys` 还在观测期，不参与判定 */
export interface BaselineStats {
  observe_days: number;
  total_keys: number;
  warmed_keys: number;
  learning_keys: number;
  error?: string;
}

/** 账号/会话画像（跨窗口长期基线），风险分封顶 1.0 */
export interface BaselineProfile {
  id?: string;
  kind: "account" | "session" | string;
  entity_key?: string;
  entity_display?: string;
  obs_count?: number;
  risk_score?: number;
  /** 风险分的**判定时间**（本轮落库时间）。本轮无异常时 risk_score 归零、这里为 null */
  risk_at?: string | null;
  /** 服务端 IP（被访问的监控资产）：界面展示「账号 · 服务端IP」靠它 */
  dst_ips?: Record<string, number>;
  anomalies?: string[];
  src_ips?: Record<string, number>;
  user_agents?: Record<string, number>;
  paths?: Record<string, number>;
  hour_hist?: Record<string, number>;
  success_count?: number;
  fail_count?: number;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface BaselineAnomalies {
  total: number;
  items: BaselineProfile[];
  threshold?: number;
  note?: string;
  error?: string;
}

/** 检测器进程写的基线心跳（进程不在时 `alive=false`，属正常）
 *
 * ⚠️ 字段分两种语义，名字里已区分（2026-10 实机 QA：原来混在一起会被当成累计值读）：
 * - 累计：`observed` / `numeric_samples` / `flushes` / `profiles_*` / `anomalies_total`；
 * - 只反映**上一轮**：`numeric_keys_last_round` / `anomalies_last_round`（会被覆盖）。
 */
export interface BaselineDetector {
  alive: boolean;
  observed?: number;
  numeric_keys_last_round?: number;
  numeric_samples?: number;
  flushes?: number;
  profiles_created?: number;
  profiles_updated?: number;
  anomalies_total?: number;
  anomaly_rounds?: number;
  anomalies_last_round?: number;
  flush_at?: number;
}

export interface BaselinePayload {
  enabled: boolean;
  profile_enabled: boolean;
  observe_days: number;
  zscore: number;
  risk_threshold: number;
  flush_seconds: number;
  stats: BaselineStats;
  anomalies: BaselineAnomalies;
  detector: BaselineDetector;
  note: string;
  /** true = 命中后端 30 秒进程内缓存（总览页 15s 轮询，不该每次穿透到库/Redis） */
  cached: boolean;
}

// ---------- 当前账号（默认口令提示 / 改密） ----------

/** `GET /api/auth/me`：当前登录账号与口令状态 */
export interface AuthMe {
  username: string;
  role: string;
  /** true = 还在用出厂口令 admin123，界面上必须红字提示改密 */
  default_password_in_use: boolean;
  /** 新口令最短长度（后端规则，界面上按它校验） */
  password_min_chars: number;
  note: string;
}

/** `POST /api/auth/change-password` 的结果 */
export interface ChangePasswordResult {
  ok: boolean;
  default_password_in_use: boolean;
  /** 后端说明（无状态 JWT 不做服务端吊销，旧令牌到期前仍有效） */
  note: string;
}

// ---------- 总览页（服务器 / 组件 / 威胁趋势 / 流量与协议 / 速率与覆盖率） ----------

/** `GET /api/system/metrics`：容器内读 /proc + 根分区（未设限额 ⇒ 等于宿主机） */
export interface SystemMetrics {
  cpu_percent: number | null;
  mem_percent: number | null;
  disk_percent: number | null;
  mem_used_bytes: number | null;
  mem_total_bytes: number | null;
  disk_used_bytes: number | null;
  disk_total_bytes: number | null;
  load_1m: number | null;
  cpu_count: number | null;
  disk_path: string;
  sampled_at: string;
  /** 读不到的指标各给一条说明（端点不会 500，字段会是 null） */
  notes: string[];
}

/** 组件灯的四个状态：ok 正常 / degraded 注意 / down 不可用 / unknown 信息不足（如未配置） */
export type ComponentState = "ok" | "degraded" | "down" | "unknown";

export interface ComponentHealthItem {
  key: string;
  name: string;
  state: ComponentState;
  detail: string;
  last_seen: string;
}

/** `GET /api/health/components`：七个组件/服务的连接状态（后端 30 秒缓存一轮） */
export interface ComponentHealthPayload {
  checked_at: string;
  items: ComponentHealthItem[];
  notes: string[];
  cached: boolean;
}

/** 检测器历史采样：一条 = 一个统计区间（默认 5 分钟，24h = 288 条） */
export interface DetectorHistoryPoint {
  ts: number;
  interval_seconds: number;
  /** 本区间增量（算速率用；除以 interval_seconds 得每秒值） */
  d_scanned?: number;
  d_hit?: number;
  d_digest?: number;
  d_delivered?: number;
  d_raw_trimmed?: number;
  d_digest_sev_critical?: number;
  d_digest_sev_high?: number;
  d_digest_sev_medium?: number;
  d_digest_sev_low?: number;
  d_digest_sev_info?: number;
  /** 本区间各规则的摘要数（后端用后即清，所以是区间值） */
  by_rule?: Record<string, number>;
  scanned?: number;
  hit?: number;
  digest?: number;
  delivered?: number;
  queue_raw?: number;
  queue_processing?: number;
  queue_failed?: number;
  agg_pending?: number;
  redis_perc?: number | null;
}

/** `GET /api/detector/history`：时间正序的采样点（检测器没跑时 items 为空） */
export interface DetectorHistory {
  items: DetectorHistoryPoint[];
  count: number;
  max: number;
  interval_hint_seconds: number;
  error?: string;
}

/** `GET /api/detector/rate`：五段速率与队列容量（哪一段窄一眼可见） */
export interface DetectorRate {
  queue_raw?: number;
  queue_digest?: number;
  queue_raw_pct?: number;
  agent_capacity_per_min?: number;
  ingest_per_sec_est?: number;
  scanned_per_sec?: number;
  hits_per_min?: number;
  digests_per_min?: number;
  delivered_per_min?: number;
  undelivered_total?: number;
  failed_total?: number;
  agg_full_total?: number;
  raw_trimmed_total?: number;
  limit_saturated?: number;
  requeued_total?: number;
  over_capacity?: boolean;
  interval_seconds?: number;
  snapshot_age_seconds?: number;
  trimmed_windows?: { at?: string; [k: string]: unknown }[];
  redis_error?: string;
  note?: string;
}

/** `GET /api/detector/coverage`：窗口内事件量 vs 投递量（看趋势突变，不看绝对值） */
export interface DetectorCoverage {
  minutes: number;
  since: string;
  delivered_total: number;
  delivered_interval: number;
  interval_seconds: number | null;
  snapshot_age_seconds: number | null;
  stale: boolean;
  delivered_window_est: number | null;
  es_docs: number | null;
  coverage_ratio: number | null;
  warn: boolean;
  warn_reason?: string;
  dropped?: Record<string, string>;
  es_error?: string;
}

export interface TrafficPoint {
  ts: string;
  docs: number;
  bytes_out: number;
  bytes_in: number;
  bytes_total: number;
  /** 该小时的平均字节/秒（不同小时可比） */
  bytes_per_sec: number;
}

export interface TrafficSeries {
  points: TrafficPoint[];
  total_docs: number;
  total_bytes: number;
  avg_bytes_per_sec: number;
}

export interface ProtocolSlice {
  log_type: string;
  docs: number;
  percent: number;
}

export interface ProtocolShare {
  /** 协议识别类日志的文档总数（= items 之和 + other_docs），百分比的分母 */
  total: number;
  other_docs: number;
  items: ProtocolSlice[];
  /** 未计入这张图的非协议日志量（conn 流记录 / weird 异常 / files 产物 / 主机日志…） */
  excluded_docs: number;
  excluded_percent: number;
}

/** `GET /api/stats/overview`：24h 流量（仅 conn 的字节量）+ 协议占比（仅协议识别类日志；后端 300 秒缓存） */
export interface StatsOverview {
  hours: number;
  since: string;
  until: string;
  traffic: TrafficSeries;
  protocols: ProtocolShare;
  computed_at: string;
  cached: boolean;
  error?: string;
}
