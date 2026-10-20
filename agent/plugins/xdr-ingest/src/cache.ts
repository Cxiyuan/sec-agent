/**
 * 分析结果高速缓存：内存 Map + TTL + 复用计数 + 容量淘汰。
 *
 * 语义（对应用户需求）：
 * - 未命中 → 调 analyze 生成判断结果并入库（occurrences = 1）
 * - 命中且未过 TTL → **不进入分析**，直接复用结果、occurrences 计数 +1
 * - 命中但已过 TTL → 结果过时，重新分析；occurrences/firstSeen 累计保留
 * - 容量超限 → 淘汰 lastSeen 最老的记录（热事件不受影响）
 *
 * 为什么不做持久化：v0 先用进程内存换取「高速」；dsh 进程重启只丢统计与
 * 结果（NDR 重推后自动重建），P2 再接 ctx.storageDomain 持久化。
 */

import type { AnalysisRecord, DeliveryRef, EventIdentity, TriageResult } from './types.ts'

const MAX_DELIVERIES = 10

export interface AnalysisCacheOptions {
  /** 分析结果的有效期（毫秒），过期即重分析。 */
  readonly ttlMs: number
  /** 记录容量上限，超出淘汰最久未见的记录。 */
  readonly maxEntries: number
  /** 可注入时钟（测试用）；默认 Date.now。 */
  readonly now?: () => number
}

export interface AdmitOutcome {
  readonly record: AnalysisRecord
  /** true = 命中缓存直接复用，未进入分析。 */
  readonly reused: boolean
  /** true = 命中但结果已过 TTL，重新分析（统计累计保留）。 */
  readonly reanalyzed: boolean
}

export interface CacheCounters {
  analyzed: number
  reused: number
  reanalyzed: number
}

function iso(epochMs: number): string {
  return new Date(epochMs).toISOString()
}

export class AnalysisCache {
  private readonly map = new Map<string, AnalysisRecord>()
  private readonly ttlMs: number
  private readonly maxEntries: number
  private readonly now: () => number
  readonly counters: CacheCounters = { analyzed: 0, reused: 0, reanalyzed: 0 }

  constructor(options: AnalysisCacheOptions) {
    this.ttlMs = Math.max(1, Math.floor(options.ttlMs))
    this.maxEntries = Math.max(1, Math.floor(options.maxEntries))
    this.now = options.now ?? Date.now
  }

  get size(): number {
    return this.map.size
  }

  /**
   * 事件进入缓存的唯一入口：内部完成「命中复用 / 过期重分析 / 未命中新析」
   * 三种分支，调用方无需关心。analyze 只在真正需要分析时被调用。
   */
  admit(
    analysisId: string,
    identity: EventIdentity,
    delivery: Omit<DeliveryRef, 'at'>,
    analyze: (identity: EventIdentity) => TriageResult,
  ): AdmitOutcome {
    const nowMs = this.now()
    const existing = this.map.get(analysisId)
    const fresh = existing !== undefined && nowMs - Date.parse(existing.analyzedAt) < this.ttlMs

    if (existing !== undefined && fresh) {
      this.bump(existing, delivery, nowMs)
      this.counters.reused += 1
      return { record: existing, reused: true, reanalyzed: false }
    }

    const result = analyze(identity)
    const record: AnalysisRecord = existing ?? {
      analysisId,
      identity,
      result,
      occurrences: 0,
      firstSeenAt: iso(nowMs),
      lastSeenAt: iso(nowMs),
      analyzedAt: iso(nowMs),
      deliveries: [],
    }
    record.identity = identity
    record.result = result
    record.occurrences += 1
    record.lastSeenAt = iso(nowMs)
    record.analyzedAt = iso(nowMs)
    this.pushDelivery(record, delivery, nowMs)
    this.map.set(analysisId, record)

    if (existing === undefined) {
      this.counters.analyzed += 1
      this.evictOverflow()
    } else {
      this.counters.reanalyzed += 1
    }
    return { record, reused: false, reanalyzed: existing !== undefined }
  }

  /** 缓存规模与计数快照（/stats 端点用）。 */
  stats(): { size: number } & CacheCounters {
    return { size: this.map.size, ...this.counters }
  }

  private bump(record: AnalysisRecord, delivery: Omit<DeliveryRef, 'at'>, nowMs: number): void {
    record.occurrences += 1
    record.lastSeenAt = iso(nowMs)
    this.pushDelivery(record, delivery, nowMs)
  }

  private pushDelivery(record: AnalysisRecord, delivery: Omit<DeliveryRef, 'at'>, nowMs: number): void {
    const ref: DeliveryRef = { eventId: delivery.eventId, fingerprint: delivery.fingerprint, at: iso(nowMs) }
    record.deliveries.push(ref)
    if (record.deliveries.length > MAX_DELIVERIES) {
      record.deliveries.splice(0, record.deliveries.length - MAX_DELIVERIES)
    }
  }

  private evictOverflow(): void {
    if (this.map.size <= this.maxEntries) return
    let oldestKey: string | undefined
    let oldestSeen = Number.POSITIVE_INFINITY
    for (const [key, record] of this.map) {
      const seen = Date.parse(record.lastSeenAt)
      if (seen < oldestSeen) {
        oldestSeen = seen
        oldestKey = key
      }
    }
    if (oldestKey !== undefined) this.map.delete(oldestKey)
  }
}
