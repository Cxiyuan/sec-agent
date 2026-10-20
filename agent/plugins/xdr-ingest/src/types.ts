/** XDR ingest 的数据契约：NDR 推送载荷、事件身份、分析记录。 */

/** NDR 检测器聚合摘要（ndr/backend/app/detector/aggregate.py 的 state 结构）。 */
export interface NdrDigest {
  rule?: string
  src_ip?: string
  dst_ips?: readonly unknown[]
  dst_ports?: readonly unknown[]
  event_types?: readonly unknown[]
  rule_severity?: string
  count?: number
  first_seen?: string
  last_seen?: string
  samples?: readonly unknown[]
  [key: string]: unknown
}

/** NDR 推送载荷的单条 item（app/detector/push.py build_items）。 */
export interface NdrDigestItem {
  event_id?: string
  fingerprint?: string
  digest?: NdrDigest
  [key: string]: unknown
}

/**
 * 事件身份：决定「是否同一类事件」的内容元组。
 * 与 NDR 摘要指纹（fingerprint.py digest_fingerprint）同一套指标，但**不含
 * 30 分钟时间桶**——NDR 指纹回答「本窗口是不是新事件」，事件分析 ID 回答
 * 「跨窗口是否同类事件」，分析结果因此可以跨窗口复用。
 */
export interface EventIdentity {
  readonly rule: string
  readonly srcIp: string
  readonly dstIps: readonly string[]
  readonly dstPorts: readonly string[]
  readonly eventTypes: readonly string[]
}

/** 分析判断结果（v0 为启发式；P1 由 LLM 分析器替换）。 */
export interface TriageResult {
  readonly category: string
  readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  readonly summary: string
  readonly recommendation: string
  readonly analyzer: 'heuristic-v0'
}

/** 缓存中的分析记录：结果 + 复用统计。 */
export interface AnalysisRecord {
  readonly analysisId: string
  identity: EventIdentity
  result: TriageResult
  /** 累计收到该类事件的次数（含首次分析那次）。 */
  occurrences: number
  firstSeenAt: string
  lastSeenAt: string
  analyzedAt: string
  /** 最近的投递溯源（NDR event_id / 指纹），最多保留 10 条。 */
  deliveries: DeliveryRef[]
}

export interface DeliveryRef {
  readonly eventId: string
  readonly fingerprint: string
  readonly at: string
}

/** 单条 item 的回执条目。 */
export interface ReceiptEntry {
  readonly eventId: string
  readonly analysisId: string
  reused: boolean
  reanalyzed: boolean
  occurrences: number
  error?: string
}

/** 整批回执：NDR 收到 2xx 即视为投递成功。 */
export interface IngestReceipt {
  accepted: number
  analyzed: number
  reused: number
  reanalyzed: number
  rejected: number
  results: ReceiptEntry[]
}
