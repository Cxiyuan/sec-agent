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
  /** 按 TLS 解析的端口（逗号分隔）：这些端口不再按 HTTP 解析；空 = 沿用采集器默认端口表 */
  tls_ports: string;
  /**
   * 签名引擎（Suricata）上报的状态：null = 未部署 / 未运行。
   * 它由签名引擎容器写在共享日志卷的 suricata/status.json 里，后端只读转出来。
   */
  suricata: SuricataStatus | null;
  rotation_hours: number;
  retention_days_local: number;
}

/**
 * 签名引擎（Suricata）自报状态（容器写在共享规则卷 /rules/runtime.json，后端只读转出来）。
 * 字段可缺：容器还没写过（未部署/刚启动）时是空对象。
 */
export interface SuricataStatus {
  alive: boolean;
  updated_at: string;
  iface: string;
  home_net: string;
  http_ports: string;
  /** 生效中的规则文件名（入口按 active/ 目录渲染进 rule-files） */
  rule_files?: string[];
  /** 生效规则条数：0 = 当前没有任何签名（不产生告警） */
  rule_count?: number;
  /** 生效版本（取自 active/manifest.json；空 = 空占位规则） */
  active_version?: string;
  /** 引擎版本（suricata -V） */
  suricata?: string;
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
  /** 是否在后台存过参数：区分「真自定义内容」与「只是模板升级后文件过时」 */
  params_stored?: boolean;
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
  /**
   * 事件来源三类（后端 `rules.py::_source_kind_of`，界面按它分组展示）：
   * `feature_match`=特征匹配 / `behavior_analysis`=行为分析 / `baseline_deviation`=基线偏离。
   */
  source_kind: string;
  /** 来源三类的中文名（后端直出，界面直接显示，不自己映射） */
  source_label: string;
  enabled: boolean;
  priority: number;
  /** 适用范围：network = 网络侧（网络采集器）、host = 主机侧（主机监控）；内置规则由后端按条件自动判定 */
  scope: string;
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
  /**
   * 磁盘缓存：超龄（默认 5 分钟）摘要从 Redis 队列挪到磁盘的批数。
   * 它**不占 Redis 内存**，智能体恢复后自动按序补推，推成功即从磁盘删。
   */
  spool_batches?: number;
  /** 磁盘缓存文件占用字节数 */
  spool_bytes?: number;
  /** 磁盘缓存里最老一批已经待了多少秒 */
  spool_oldest_age?: number;
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


// ---------- 基线（第 8 期从智能体侧迁来） ----------

/** 数值基线的学习进度：`learning_keys` 还在观测期，不参与判定 */
export interface BaselineStats {
  observe_days: number;
  total_keys: number;
  warmed_keys: number;
  learning_keys: number;
  /** 最早观测的维度时间（界面用它算「还有多久过观测期」） */
  oldest_first_seen?: string | null;
  /** 最早那批维度过观测期的时刻（= oldest_first_seen + 观测期） */
  next_warm_at?: string | null;
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
  /** 似然比**后验概率**（0~1）：llr 打分方式下列表按它排序；加和分（risk_score）回滚口径下也返回 */
  posterior?: number;
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
  /** 认证失败/成功（只统计认证请求：登录路径、ssh/mysql 这类日志） */
  fail_count?: number;
  /** 错误响应（status ≥ 400 且非 401/403）：404 风暴这类探测痕迹 */
  error_count?: number;
  /** 被观测到的窗口数（冷启动门槛按它算） */
  window_count?: number;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface BaselineAnomalies {
  total: number;
  items: BaselineProfile[];
  threshold?: number;
  /** 「当前风险」的有效期（分钟）：超过这么久没被判过的风险不算数 */
  ttl_minutes?: number;
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
  /** 中继去重计数（都不静默）：前跳、后跳去重、后跳保留、中继内部 */
  relay_front?: number;
  relay_back_dropped?: number;
  relay_back_kept?: number;
  relay_internal_dropped?: number;
  /** 按内容判侧向后新增：被丢掉的客户端侧跳 / 中继内部跳保留 / 链的下游续跳丢弃 */
  relay_front_dropped?: number;
  relay_internal_kept?: number;
  relay_chain_continuation_dropped?: number;
  /** 被访问方基线：本轮观测到的资产数 / 累计 */
  assets_last_round?: number;
  assets_observed?: number;
  /** 被访问方按**连接**（Zeek uid）算：本轮多少条连接 / 累计多少条 / 多少条没进基线 */
  asset_uids_last_round?: number;
  asset_uids_total?: number;
  asset_uids_dropped?: number;
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
  /** 被访问方（内网源站 / 内网 DNS）规模概览 */
  assets?: {
    total_assets: number;
    ready_assets: number;
    learning_assets: number;
    observe_days: number;
    window_seconds: number;
    error?: string;
  };
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

/**
 * `GET /api/detector/recent` 里的一条命中摘要。
 *
 * 由检测器写进 Redis（不依赖推送地址），是「哪条规则、打了谁、多少次」的唯一现场出口。
 * 时间字段是北京时间展示，后端存的是 UTC ISO。
 */
export interface HitEventItem {
  /** **系统唯一事件 ID**（PG 主键）：关联分析、忽略、白名单都引用它 */
  id: string;
  created_at: string;
  first_seen: string;
  last_seen: string;
  rule: string;
  severity: string;
  /**
   * 事件来源三类（契约 1.1，界面按这三类展示与筛选）：
   * `feature_match`=特征匹配 / `behavior_analysis`=行为分析 / `baseline_deviation`=基线偏离。
   */
  source_kind: string;
  /** 来源中文名（后端直出） */
  source_label: string;
  source: string;
  /** 直连对端；中继链路上它是代理/WAF */
  src_ip: string;
  /** 展示用请求方：真实请求 IP（可信代理头）优先，没有才回落 src_ip */
  client: string;
  client_source?: string;
  /** 与 src_ip 不同时表示这一跳经过了谁（中继/反代） */
  via?: string;
  /** true = 这条命中的请求头显示它经过代理（后端 `_rows_to_dict` 一直在返，前端类型没跟上） */
  proxied?: boolean;
  count: number;
  /** 目的 **IP:端口 成对**（分开存 ips/ports 看不出谁配谁） */
  dst_pairs: string[];
  dst_ips: string[];
  dst_ports: string[];
  /**
   * 事件类型（2026-10 起契约：值是**中文具体归类** —— `网络扫描`／`Web 应用攻击`／
   * `账号口令攻击`／`权限提升尝试`／`连接数异常偏离`／`大流量外传`…）。
   *
   * 早期版本返回的是 `signature_hit`／`protocol_anomaly` 这类内部英文码，现在后端
   * （`hits.py::event_types_of`）直接给出具体归类，前端原样展示即可，**不再**需要
   * 任何「英文码 → 中文」的映射表。
   */
  event_types: string[];
  /** 与 `event_types` 一一对应的中文标签（后端 `hits.py` 并列返回，前端可直接使用） */
  event_type_labels?: string[];
  conn_states: string[];
  log_types: string[];
  real_client_ips: string[];
  ignored: boolean;
  ignored_at?: string;
  ignored_reason?: string;
  whitelist_id?: string;
  /** 详情才有：样例事件的关键字段（时间/类型/URI/UA/状态码/账号…） */
  evidence?: Array<Record<string, unknown>>;
  error?: string;
}

export interface HitEventList {
  items: HitEventItem[];
  total: number;
  returned: number;
  error?: string;
}

/**
 * `GET /api/detector/hits/stats` 的一分组组成员（来源三类 / 严重度通用）。
 *
 * ⚠️ `label` 的语义分两种（后端 `group_by` 用同一张 `SOURCE_LABELS` 表）：
 * - `by_source_kind` 分组：label 是中文（「特征匹配」…），界面可直接显示；
 * - `by_severity` 分组：label 回落成**原始英文 key**（SOURCE_LABELS 不含严重度），
 *   界面一律用 `severityText(key)`，不要用 label。
 */
export interface HitStatsGroup {
  key: string;
  label: string;
  count: number;
}

/** TOP 规则分组：字段名是 `rule`（不是 key/label）；展示要过 `ruleText()` 剥「内置-」前缀 */
export interface HitTopRule {
  rule: string;
  count: number;
}

/** 趋势桶：`ts` 是 UTC ISO8601，界面一律转北京时间；
 *  **有断桶**（后端只含有事件的桶），前端按 `bucket_seconds` 补零后再喂图表 */
export interface HitTrendPoint {
  ts: string;
  count: number;
}

/** `GET /api/detector/hits/stats?minutes=…`：事件中心概览区的一次聚合 */
export interface HitEventStats {
  minutes: number;
  bucket_seconds: number;
  total: number;
  ignored: number;
  by_source_kind: HitStatsGroup[];
  by_severity: HitStatsGroup[];
  top_rules: HitTopRule[];
  trend: HitTrendPoint[];
  /** 失败时后端只回 { error, total: 0 }，上面这些字段全部缺失 —— 读取点一律写 ?? [] */
  error?: string;
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
  /** 近 N 小时丢包总数（Zeek stats.log 增量求和） */
  pkts_dropped_total?: number;
  /** 近 N 小时处理包数 */
  pkts_proc_total?: number;
  /** 近 N 小时掉包率（%）——丢包偶发，30 分钟窗口常是 0，看这个长期口径 */
  day_drop_rate?: number;
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

// ---------- 行为分析页（/admin/behavior） ----------

/** `GET /api/baseline/config`：一个可调参数（后端单一定义源，前端只负责渲染） */
export interface BaselineConfigItem {
  key: string;
  label: string;
  kind: "int" | "float" | "bool" | "regex" | "text";
  unit: string;
  note: string;
  low: number | null;
  high: number | null;
  default: string | number | boolean;
  value: string | number | boolean;
  /** true = 后台改过（不是默认值） */
  overridden: boolean;
}

export interface BaselineConfigPayload {
  items: BaselineConfigItem[];
  effective: Record<string, string | number | boolean>;
  /** 保存/恢复接口会回这两个额外字段 */
  written?: number;
  removed?: number;
}

/** `GET /api/baseline/profiles`：画像列表（分页 + 搜索） */
export interface BaselineProfilesPayload {
  total: number;
  items: BaselineProfile[];
  error?: string;
}

/** 告警处置结论（`POST /api/baseline/alerts/{profile_id}/disposition` 写入）。
 * `false_positive` = 误报，降权；`confirm` = 确认，仅留档。 */
export type DispositionVerdict = "false_positive" | "confirm";

/** 单条处置记录（`GET /api/baseline/alerts/dispositions` 返回） */
export interface AlertDisposition {
  id: string;
  kind: string;
  entity_key: string;
  /** 空 = 整条告警级别；非空 = 只降权那一路证据（如 `new_src_ip`） */
  signal: string;
  verdict: DispositionVerdict;
  operator: string;
  note: string;
  created_at: string | null;
}

/** `GET /api/baseline/alerts/dispositions`：最近的处置记录 */
export interface DispositionListPayload {
  items: AlertDisposition[];
  limit: number;
  error?: string;
}

/** `GET /api/baseline/numeric`：数值基线的一行 */
export interface NumericStat {
  key: string;
  feature: string;
  count: number;
  mean: number;
  m2?: number;
  std: number;
  first_seen: string;
  /** true = 已过观测期（可判偏离）；false = 还在学习 */
  warmed: boolean;
}

export interface NumericListPayload {
  total: number;
  returned: number;
  observe_days: number;
  /** key = 一行一个 `源IP:维度`；ip = 一行一个 IP（维度在 features 里） */
  group?: "key" | "ip";
  items: NumericStat[];
  error?: string;
}

/** `GET /api/baseline/numeric?group=ip`：一行 = 一个 IP（页面就按这个模式展示） */
export interface NumericIpGroup {
  ip: string;
  /** 该 IP 各维度里最早的首次观测时间 */
  first_seen: string;
  /** 各维度（含各自的均值/标准差/观测次数/是否生效） */
  features: NumericStat[];
}

export interface NumericGroupedPayload {
  group: "ip";
  /** IP 数（分页总数就是它） */
  total: number;
  /** 同一筛选下的维度数（同一 IP 最多 3 个） */
  total_keys: number;
  returned: number;
  observe_days: number;
  items: NumericIpGroup[];
  error?: string;
}

// ---------- 被访问方（内网源站 / 内网 DNS）基线 ----------

/** `GET /api/baseline/assets`：一行 = 一个被访问方资产 */
export interface AssetRow {
  /** 资产标识：hostname 优先（HTTP Host / SSL SNI），无则 `IP:端口`（内网 DNS 是 `IP:53`） */
  asset: string;
  role: "site" | "dns" | string;
  /** ready = 已过观测期（可判偏离）；learning = 只学习 */
  state: "ready" | "learning" | string;
  /** 已攒了多少个观测区间 */
  windows: number;
  first_seen: string;
  /** 平均每个观测区间被访问多少次（**连接数**：同一连接内的多条日志只算一次） */
  visits_mean: number;
  /** internal = 内网被访问方（异常判定只看它）；external = 公网目标（含公共 DNS），只展示 */
  scope?: string;
  /** 平均每区间请求数（应用层日志：http/dns；纯 TCP 服务为 0） */
  requests_mean: number;
  /** 平均每区间不同真实客户端数 */
  clients_mean: number;
  /** 平均每区间不同目标数（HTTP=URI、DNS=域名） */
  targets_mean: number;
  window_seconds: number;
}

export interface AssetListPayload {
  total: number;
  returned: number;
  items: AssetRow[];
  /** 按归属的数量（口径 C）：界面用它渲染「内网 / 外部」分组 */
  by_scope?: { internal?: number; external?: number; unknown?: number };
  window_seconds: number;
  error?: string;
}

/** `GET /api/baseline/assets/stats?asset=`：单个资产的各特征明细 */
export interface AssetStatItem {
  feature: string;
  count: number;
  mean: number;
  std: number;
  first_seen: string;
  warmed: boolean;
}

export interface AssetDetailPayload {
  asset: string;
  role: string;
  observe_days: number;
  window_seconds: number;
  items: AssetStatItem[];
  error?: string;
}

/** `GET /api/zeek/relay-nodes`：中继节点清单（界面「监控网段」页维护，只读 PG） */
export interface RelayNodesPayload {
  text: string;
  count: number;
  /** 清单解析出的条目（单地址 = 纯 IP；真正的网段 = CIDR 写法） */
  nodes: string[];
  /** false = 系统认定「网络里没有中继」（不认代理头、不做去重） */
  configured: boolean;
  /** 检测器自动推算的角色、证据计数与两侧内容统计（界面只读，侧向/角色可覆盖） */
  roles: Record<
    string,
    {
      proxy?: number;
      dns?: number;
      roles?: string[];
      /** 本轮（本进程）证据数：看“最近活不活跃” */
      window_hits?: number;
      /** 跨重启累计证据数（按单个角色）：角色判定用它，所以重启不会掉成未判定 */
      hits_total?: { proxy?: number; dns?: number };
      /** 客户端侧（该地址作目的地）的明文请求内容条数 */
      front_content?: number;
      /** 源站侧（该地址作来源）的明文请求内容条数 */
      back_content?: number;
      front_total?: number;
      back_total?: number;
      /** 当前生效的侧向：front = 保留客户端侧，back = 保留源站侧 */
      side?: "front" | "back" | string;
      /** auto = 按实测内容自动判；manual = 运维手动指定；kept = 本轮内容不足、沿用上次判定 */
      side_source?: "auto" | "manual" | "kept" | string;
      /** 角色来源：manual = 手工指定，auto = 按证据 */
      role_source?: "auto" | "manual" | string;
      /** 该中继最近一次被观测到的业务时间 */
      last_seen?: string;
      /** 角色未判定的原因（人话）；手工指定过则为空 */
      role_reason?: string;
      /** 侧向走保守默认的原因（人话） */
      side_reason?: string;
    }
  >;
  /** 运维的侧向设置（auto / front / back），键是清单里的地址 */
  sides: Record<string, string>;
  /** 运维的角色手工指定（auto / proxy / dns / both），键是清单里的地址 */
  role_overrides: Record<string, string>;
  /** 上下级链路拓扑（检测器推算回写） */
  topology: RelayTopology;
  detected_at: string;
}

/** 中继上下级拓扑：边 / 层级 / 链 + 异常标记 */
export interface RelayTopology {
  edges?: Array<{
    from: string;
    to: string;
    direct?: number;
    header?: number;
    /** 两类证据任一达到门槛才算“已确认”（链路推导只认已确认的边） */
    confirmed?: boolean;
    stale?: boolean;
    last_seen?: string;
  }>;
  levels?: Record<string, number>;
  chains?: string[][];
  min_evidence?: number;
  pruned?: number;
  cycle_broken?: string[][];
  generated_at?: string;
}

/** 攻击链还原：一条链的逐段证据 */
export interface ChainSegment {
  from: string;
  to: string;
  kind?: string;
  direct?: number;
  header?: number;
  confirmed?: boolean;
}

/** 攻击链还原：一条链（真实请求IP →（中继…）→ 源站） */
export interface ChainItem {
  client: string;
  /** 展示用源站：`IP:端口`（界面默认显示它；`origin` 是域名/Host，只作补充） */
  origin_ip?: string;
  client_source?: string;
  /** known = 取到了请求方；not_recorded = 这批事件不带代理头，确实没记下（不是出错） */
  client_state?: string;
  client_reason?: string;
  origin_source?: string;
  origin: string;
  origin_kind?: string;
  relay_path: string[];
  segments: ChainSegment[];
  suspicious?: boolean;
  hop?: string;
  facts: {
    events?: number;
    log_types?: Record<string, number>;
    event_types?: Record<string, number>;
    status_codes?: Record<string, number>;
    signatures?: Record<string, number>;
    filenames?: Record<string, number>;
    dns_queries?: Record<string, number>;
    top_paths?: Record<string, number>;
    methods?: Record<string, number>;
    clients?: string[];
    first_seen?: string;
    last_seen?: string;
  };
}

/** 攻击链列表响应 */
export interface ChainListPayload {
  window: { from: string; to: string };
  relays: {
    configured?: boolean;
    sides?: Record<string, string>;
    role_overrides?: Record<string, string>;
    levels?: Record<string, number>;
  };
  chains: ChainItem[];
  scanned: number;
  truncated: boolean;
  suspicious_only: boolean;
}

/** 节点别名（IP → 显示名）；空表 = 都用 IP */
export interface TopologyAliasesPayload {
  aliases: Record<string, string>;
  count: number;
}

/** `GET /api/config/audit`：配置体检的一项（口令/令牌已脱敏） */
export interface ConfigAuditItem {
  key: string;
  name: string;
  /** 这一项**从哪来**：环境变量 / 数据库（界面可改）/ 编排部署侧 / 代码默认值 */
  source: string;
  value: string;
  secret: boolean;
  warn?: string;
  note?: string;
}

export interface ConfigAuditPayload {
  items: ConfigAuditItem[];
  warnings: string[];
  default_agent_host: string;
  checked_at: string;
  note: string;
  error?: string;
}

/** `GET /api/stats/traffic?minutes=10`：近 N 分钟流量（每分钟一个点，进行中的点标 partial） */
export interface TrafficMinutePoint {
  ts: string;
  docs: number;
  bytes_total: number;
  /** 该秒的发送/接收字节数（右上角「实时发送 / 实时接收」用它，参考图口径） */
  bytes_out: number;
  bytes_in: number;
  bytes_per_sec: number;
  /** 发送/接收各自的每秒速率（桶内总量 ÷ 桶秒数，与 bytes_per_sec 同口径） */
  bytes_out_per_sec?: number;
  bytes_in_per_sec?: number;
  /** Zeek 上报的丢包数（stats.log 每 5 分钟一条的**增量**；没上报的格子是 0） */
  pkts_dropped?: number;
  /** 同区间 Zeek 处理的包数（算掉包率用） */
  pkts_proc?: number;
  /** true = 这一分钟还没过完（速率已按实际经过秒数折算） */
  partial: boolean;
}

export interface TrafficMinutes {
  minutes: number;
  since: string;
  until: string;
  /** 曲线点：**每 20 秒一个**（近 30 分钟 = 90 个点） */
  points: TrafficMinutePoint[];
  /** 每 5 分钟一个分区标记（前端据此画分区线；**X 轴不显示刻度文字**） */
  segment_marks?: string[];
  /** 打点粒度（秒），前端据此算"多少点 = 一个分区" */
  interval_seconds?: number;
  /** 分区长度（分钟） */
  segment_minutes?: number;
  total_bytes: number;
  avg_bytes_per_sec: number;
  /** 右上角大字：当前（最近一格）/ 峰值 / 近端均值 */
  current_bytes_per_sec?: number;
  peak_bytes_per_sec?: number;
  avg_recent_bytes_per_sec?: number;
  /** Zeek 最近一次上报的丢包值 */
  pkts_dropped_latest?: number;
  /** 窗口丢包总数（pkts_dropped 是增量，可直接求和） */
  pkts_dropped_total?: number;
  /** 窗口处理包数 */
  pkts_proc_total?: number;
  /** 掉包率（%）：dropped / (dropped + proc) */
  drop_rate?: number;
  cached?: boolean;
  computed_at: string;
  note?: string;
  error?: string;
}

// ---------- 分析机制（/api/analysis，派工队列） ----------

/**
 * 一个可调参数（**analysis 与 suppressions 共用**，形状与 `/api/baseline/config` 相近但不完全一致）。
 *
 * 关键差异（2026-10 实测，别踩）：**这里没有 `value`** —— 当前生效值在响应的顶层
 * `effective[item.key]`。`/api/baseline/config` 的 item 才带 `value`，所以**不要复用
 * `BaselineConfigItem`**，也不要照抄 `behavior-panel.tsx` 里 `item.value` 的读法。
 */
export interface KnobItem {
  key: string;
  label: string;
  /** analysis 多一个 `text`（如 `analysis.candidate_kinds` 的逗号串）；两个模块都没有 `regex` */
  kind: "bool" | "int" | "float" | "text";
  default: string | number | boolean;
  low: number | null;
  high: number | null;
  unit: string;
  note: string;
  /** true = 后台改过（不等于当前值，当前值看 `effective`） */
  overridden: boolean;
}

/** 参数读写的公共回包形状（GET / PUT / POST reset 三处共用） */
export interface KnobConfigPayload {
  items: KnobItem[];
  effective: Record<string, string | number | boolean>;
  /** 保存 / 恢复默认时才回带的两个额外字段 */
  written?: number;
  removed?: number;
}

/** `GET /api/analysis/config`：参数清单 + 生效值 + 线索类型/结论词表（界面下拉的唯一来源） */
export interface AnalysisConfigPayload extends KnobConfigPayload {
  kinds: string[];
  verdicts: string[];
  hint: string;
}

/** 队列状态：后端 `queue.py` 只有这 6 个，没有第 7 种（超容量不是状态，是计数器） */
export type AnalysisTaskState =
  | "pending"
  | "claimed"
  | "deferred"
  | "done"
  | "stuck"
  | "expired";

/** 线索类型（`params.KINDS`） */
export type AnalysisTaskKind = "novelty" | "shift" | "structure" | "coverage" | "hit";

/** 任务结论（`analysis/verdicts.py` 的结论态；`pending`/`done` 是流程态不算判定） */
export type AnalysisVerdict =
  | "true_positive"
  | "false_positive"
  | "benign"
  | "suspicious"
  | "inconclusive";

/**
 * 一条客观线索（`queue.py::_task_dict`）。
 *
 * 注意：**没有 `note` / `claimed_by` / `updated_at`** —— 虽然库里 `AnalysisTask.note`
 * 有值（"为什么被挤掉/延后"），但列表与详情都不返回它，界面不要设计"结束原因"区块。
 * `lease_until` 在列表/详情里恒为 `""`（只有 MCP `claim_tasks` 那条路径会带）。
 */
export interface AnalysisTaskItem {
  id: string;
  kind: string;
  /** 客观强度 0~1（三位小数），队列排序与首列都靠它 */
  strength: number;
  priority: number;
  subject_kind: string;
  subject: string;
  /** 建议分析窗口，可能为空串 */
  window_start: string;
  window_end: string;
  /** 客观线索：**恒含 `suggested_tools: string[]`**，其余键由候选生成器决定，不含严重度与结论 */
  hint: Record<string, unknown>;
  coalesced: number;
  attempts: number;
  depth: number;
  parent_id: string;
  state: string;
  lease_until: string;
  created_at: string;
}

/** `GET /api/analysis/tasks`：失败时也返回 200，形状变成 `{error, items:[], total:0}` */
export interface AnalysisTaskList {
  total: number;
  returned: number;
  items: AnalysisTaskItem[];
  error?: string;
}

/** 任务结论（任务级，带成本口径：`tools_used` / `duration_ms`） */
export interface AnalysisResultItem {
  id: string;
  task_id: string;
  kind: string;
  subject_kind: string;
  subject: string;
  verdict: string;
  confidence: number;
  summary: string;
  findings: Record<string, unknown>;
  evidence_refs: string[];
  tools_used: number;
  duration_ms: number;
  claimed_by: string;
  created_at: string | null;
}

/** 详情抽屉里的历史结论（`task_detail.results`，最近 10 条，字段比 `/results` 少） */
export interface AnalysisResultBrief {
  verdict: string;
  confidence: number;
  summary: string;
  tools_used: number;
  duration_ms: number;
  claimed_by: string;
  created_at: string;
}

/** `GET /api/analysis/tasks/{id}`：不存在时是 **200 + `{error}`**，不是 404 */
export interface AnalysisTaskDetail extends AnalysisTaskItem {
  results?: AnalysisResultBrief[];
  error?: string;
}

/** `GET /api/analysis/results`：`task_id`/`subject`/`verdict` 都是**精确等值**（无模糊、无 kind 过滤） */
export interface AnalysisResultList {
  total: number;
  returned: number;
  items: AnalysisResultItem[];
  error?: string;
}

export interface AnalysisKindCount {
  kind: string;
  count: number;
}

export interface AnalysisVerdictCount {
  verdict: string;
  count: number;
}

/** `stats.budget`：当前预算（也用于容量压力条的分母 `queue_capacity`） */
export interface AnalysisBudget {
  rate_per_token_hour: number;
  rate_total_hour: number;
  max_inflight: number;
  reserved_slots: number;
  reserved_min_strength: number;
  lease_seconds: number;
  queue_capacity: number;
  pending_ttl_hours: number;
}

/**
 * `GET /api/analysis/stats`：总览。
 *
 * `counters` 来自 Redis（`shentong:analysis:stats`），Redis 不可用时是 `{}` 而不是报错。
 * 会出现的键：`enqueued / merged / superseded / dropped_overflow / claimed / done /
 * deferred / expired / reclaimed / stuck / candidate_error / followup_accepted /
 * suppression_rebound`（**没有 `doorbell_*`**，那是 `/api/detector/stats` 的口径）。
 */
export interface AnalysisStats {
  enabled: boolean;
  by_state: Record<string, number>;
  pending: number;
  deferred: number;
  claimed: number;
  stuck: number;
  /** 只统计 pending+deferred，按条数降序 */
  by_kind: AnalysisKindCount[];
  by_verdict: AnalysisVerdictCount[];
  results_total: number;
  avg_tools_used: number;
  avg_duration_ms: number;
  counters: Record<string, number>;
  budget: AnalysisBudget;
  generated_at: string;
  error?: string;
}

/** 盲区清单的一行。**`kind` 恒为 `"asset"`（后端硬编码），真实类别看 `subject_kind`** */
export interface AnalysisCoverageItem {
  kind: string;
  subject: string;
  subject_kind: string;
  first_seen_at: string;
  last_seen_at: string;
  seen_count: number;
  analyzed_count: number;
  last_analyzed_at: string;
  /** `从未分析` / `久未分析` */
  why: string;
}

/**
 * `GET /api/analysis/coverage`：覆盖率与盲区。
 *
 * 两个坑：① `items` 是 `never(≤limit) + stale(≤limit)` 再切片 `[:limit]`，所以「久未分析」
 * 常被切掉；② `returned` 是**切片前**长度（可能 200 而 `items.length` 只有 100）。
 * → 界面所有计数**一律用 `items.length`**，不要用 `returned`。
 * 失败时形状是 `{error, days, items:[]}`（没有下面这些统计键）。
 */
export interface AnalysisCoverage {
  days: number;
  subjects_total?: number;
  analyzed?: number;
  coverage_ratio?: number;
  never_analyzed?: number;
  stale?: number;
  returned?: number;
  items: AnalysisCoverageItem[];
  error?: string;
}

export interface AnalysisInventoryRow {
  value: string;
  first_seen_at: string;
  last_seen_at: string;
  seen_count: number;
  analyzed_count: number;
}

export interface AnalysisInventoryKind {
  /** 该类全量条数（`items` 只是本次取的样本） */
  count: number;
  items: AnalysisInventoryRow[];
}

/**
 * `GET /api/analysis/inventory`：对象清单（数据地图）。
 * **空类别整条不出现**（后端 `if not rows: continue`），不要假设六类齐全。
 */
export interface AnalysisInventory {
  generated_at: string;
  kinds: Record<string, AnalysisInventoryKind>;
  known_kinds: string[];
  error?: string;
}

/** 人工派工请求体（`subject` 空白 → 400 `{detail}`，**不是** field_errors） */
export interface ManualTaskIn {
  subject: string;
  subject_kind?: string;
  kind?: string;
  note?: string;
  /** 0~1，默认 0.6 */
  strength?: number;
}

/**
 * 人工派工回包：**HTTP 200 恒定**，成败看 `ok` / `result`。
 * - `new` 入队 / `merged` 并入同族（这两个 `ok=true`）
 * - `dropped` 队列满且不比队尾强 / `skipped` 队列关闭或该类型未开启 / `error` 异常
 */
export interface ManualTaskOut {
  ok: boolean;
  result: "new" | "merged" | "superseded" | "dropped" | "skipped" | "error";
  subject: string;
  error?: string;
}

// ---------- 精准抑制（/api/suppressions） ----------

/**
 * 抑制匹配条件树（与规则引擎同一套语法，引擎见 `rules/engine.py`）。
 * `rules` 里可以嵌 `{logic, rules}` 子组，也支持 `{not: …}`；界面只做扁平顶层。
 */
export type SuppressionMatch = RuleConditions;

/**
 * 抑制档位（后端 `suppression.MODE_*` 只有这两个值）。
 *
 * **不是请求参数**：`SuppressionIn` 里没有 `mode` —— 新建/改条件时由后端
 * `choose_mode(trial)` 按试算结果自己判（影响面过大或自动生效关闭 → `record_only`），
 * 前端只能读、不能写。这个联合类型只用于前端本地的短标签 map。
 */
export type SuppressionMode = "suppress" | "record_only";

/**
 * 抑制条目（**26 字段**，`detector/suppression.py::_item`）。
 *
 * 要点：界面建抑制（`origin="ui"`）**不受**证据条数/工具种类/置信度/新现象保护期门槛约束；
 * `hits` 是内存攒批、每 30 秒才落库 → 命中数最多滞后约 30 秒，别标"实时"。
 */
export interface SuppressionItem {
  id: string;
  name: string;
  match: SuppressionMatch;
  /** 条件树里出现的字段（去重保序） */
  fields: string[];
  /** = `fields.length`，界面显示「N 维」 */
  dims: number;
  /** `suppress` = 事件不再生成；`record_only` = 事件仍生成、只不派工不推送 */
  mode: string;
  /** 后端原值只有两句：`完全不生成事件` / `只不派工（事件保留）`（窄列请用本地短标签） */
  mode_label: string;
  /** 申请时的爆炸半径试算快照；试算失败时是 `{days, error, events:-1, srcs:-1, segments:-1}` */
  trial: Record<string, unknown>;
  reason_code: string;
  reason_label: string;
  note: string;
  evidence_refs: string[];
  evidence_tools: number;
  confidence: number;
  source_task_id: string;
  created_by: string;
  origin: string;
  enabled: boolean;
  hits: number;
  last_hit_at: string | null;
  expires_at: string | null;
  /** 动态判定（`expires_at <= now`），过期**不会**把 `enabled` 置 false（两者正交） */
  expired: boolean;
  revoked_at: string | null;
  /** 成因靠前缀解析：`被真实事件推翻（` / `熔断：` / `超出活跃上限 ` / 其余=人工 */
  revoke_reason: string;
  created_at: string | null;
  updated_at: string | null;
}

/** 列表响应的门槛（`limits.hit_cap` 是命中列 80% 预警的数据源） */
export interface SuppressionLimits {
  max_active: number;
  min_match_dims: number;
  min_refs: number;
  min_tools: number;
  min_confidence: number;
  default_ttl_days: number;
  hit_cap: number;
}

/**
 * `GET /api/suppressions`：清单（按命中数降序）。
 *
 * 计数口径：`total` **含过期项**，而 `include_expired=false` 是"分页之后再过滤" →
 * 会出现「共 30 条、本页 12 行」。界面固定显式传 `include_expired=true`，
 * 分页文案用 `total`、行数用 `items.length`。
 */
export interface SuppressionListPayload {
  total: number;
  returned: number;
  items: SuppressionItem[];
  limits?: SuppressionLimits;
  error?: string;
}

/**
 * `GET /api/suppressions/stats`：总览。
 * `by_mode` 是**裸计数且只统计 active 条目**（`enabled && !expired`）→ 两项之和 = `active`，
 * **不等于 `total`**；`expired` 与 `revoked` 可重叠，不能相加当总数。
 */
export interface SuppressionStats {
  enabled: boolean;
  auto_apply: boolean;
  active: number;
  expired: number;
  revoked: number;
  total: number;
  suppressed_total: number;
  by_mode: Record<string, number>;
  limits?: SuppressionLimits & {
    trial_days?: number;
    trial_max_srcs?: number;
    trial_max_hits?: number;
    trial_max_segments?: number;
    newcomer_hours?: number;
  };
  /** 理由码 → 中文（chip 的唯一来源） */
  reason_codes?: Record<string, string>;
  /** 允许的匹配字段 → 中文标签（条件树字段下拉的唯一来源） */
  allowed_fields?: Record<string, string>;
  error?: string;
}

/** `GET /api/suppressions/config`：参数 + 理由码 + 允许字段（界面表单全靠它渲染） */
export interface SuppressionConfigPayload extends KnobConfigPayload {
  reason_codes: Record<string, string>;
  allowed_fields: Record<string, string>;
  hint: string;
}

/** 试算结果（`estimate_trial`）：成功时带 `max_*`；**失败时只有 `days/error` 与三个 -1** */
export interface SuppressionTrial {
  days: number;
  phenomenon?: string;
  events: number;
  srcs: number;
  segments: number;
  max_events?: number;
  max_srcs?: number;
  max_segments?: number;
  error?: string;
}

/**
 * `POST /api/suppressions/preview` 的回包。
 *
 * `thresholds` 的键名是 **`max_hits` / `max_srcs` / `max_segments` / `trial_days`**，
 * 不是 `trial_max_*`（那是 knob 名）。degraded 时 `trial` 没有 `max_*`，要回退到这里。
 */
export interface SuppressionPreviewOut {
  trial: SuppressionTrial;
  mode: string;
  mode_label: string;
  thresholds: {
    trial_days: number;
    max_hits: number;
    max_srcs: number;
    max_segments: number;
    min_match_dims: number;
  };
}

/**
 * 新建 / 修改抑制的请求体。
 *
 * ⚠️ `PUT /api/suppressions/{id}` **只落 4 个字段**（`match` / `reason_code` /
 * `evidence_refs` / `expires_at`(ttl_days)），`name` / `note` / `confidence` 会被静默丢弃
 * → 编辑态这些字段只读（前端规避，2026-10 拍板）。
 */
export interface SuppressionIn {
  name?: string;
  match: SuppressionMatch;
  reason_code?: string;
  note?: string;
  evidence_refs?: string[];
  /** 0~1（不是 0~100） */
  confidence?: number;
  /** 1~30，缺省用 `default_ttl_days`（默认 14） */
  ttl_days?: number | null;
}
