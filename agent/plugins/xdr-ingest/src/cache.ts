/**
 * 两级分析缓存：热层（内存 LRU）+ 冷层（ColdStore，v1 = PostgreSQL）。
 *
 * 语义（对应用户需求：热数据内存加载、冷数据落盘、判重复用）：
 * - 未命中 → 调 analyze 生成结果，**写穿冷库**；occurrences = 1 默认只进冷库
 *   （「不长分析的 IP」待在数据库里，不占内存）；
 * - 冷命中且未过期 → 不进入分析，occurrences +1；达到 hotThreshold 才
 *   **晋升**热层（「经常出现的 IP」由此进入内存）；
 * - 热命中且未过期 → 不进入分析，occurrences +1（计数先只动内存，淘汰时
 *   一次性回写冷库，避免每次命中都打 PG）；
 * - 命中但已过 TTL → 重新分析，occurrences/firstSeen/deliveries 累计保留；
 * - 热层满 → 淘汰最久未见的记录**降级回冷库**（回写后移除，不丢数据）；
 * - 启动 warmup：按 occurrences 降序把冷库热数据预加载进热层。
 *
 * PG 故障时（ColdStore 降级）本类自动退化为纯内存判重，不阻断摄入。
 */

import type { AnalysisRecord, DeliveryRef, EventIdentity, TriageResult } from './types.ts'
import type { ColdEntry, ColdStore } from './store.ts'

const MAX_DELIVERIES = 10

export interface TieredCacheOptions {
  /** 分析结果的有效期（毫秒），两层一致。 */
  readonly ttlMs: number
  /** 热层容量上限（条）。 */
  readonly hotMaxEntries: number
  /** 晋升热层的出现次数门槛：occurrences >= 此值才进内存。 */
  readonly hotThreshold: number
  /** 冷存储实现（PG 或内存）。 */
  readonly store: ColdStore
  /** 可注入时钟（测试用）；默认 Date.now。 */
  readonly now?: () => number
}

export interface AdmitOutcome {
  readonly record: AnalysisRecord
  /** true = 命中缓存直接复用，未进入分析。 */
  readonly reused: boolean
  /** true = 命中但结果已过 TTL，重新分析（统计累计保留）。 */
  readonly reanalyzed: boolean
  /** 结果来自哪一层（观测用）。 */
  readonly tier: 'hot' | 'cold'
}

export interface CacheCounters {
  analyzed: number
  reused: number
  reanalyzed: number
  /** 冷 → 热晋升次数。 */
  promoted: number
  /** 热 → 冷降级（淘汰回写）次数。 */
  demoted: number
  /** 启动预热装入热层的条数。 */
  warmed: number
  coldHits: number
  coldMisses: number
}

export interface CacheStats extends CacheCounters {
  hotSize: number
  coldSize: number
  /** 冷库实现标识。 */
  storeKind: string
}

interface HotEntry {
  readonly record: AnalysisRecord
  readonly expiresAt: string
}

function iso(epochMs: number): string {
  return new Date(epochMs).toISOString()
}

function fresh(analyzedAt: string, ttlMs: number, nowMs: number): boolean {
  return nowMs - Date.parse(analyzedAt) < ttlMs
}

export class TieredCache {
  private readonly hot = new Map<string, HotEntry>()
  private readonly ttlMs: number
  private readonly hotMaxEntries: number
  private readonly hotThreshold: number
  private readonly store: ColdStore
  private readonly now: () => number
  readonly counters: CacheCounters = {
    analyzed: 0, reused: 0, reanalyzed: 0,
    promoted: 0, demoted: 0, warmed: 0,
    coldHits: 0, coldMisses: 0,
  }

  constructor(options: TieredCacheOptions) {
    this.ttlMs = Math.max(1, Math.floor(options.ttlMs))
    this.hotMaxEntries = Math.max(1, Math.floor(options.hotMaxEntries))
    this.hotThreshold = Math.max(1, Math.floor(options.hotThreshold))
    this.store = options.store
    this.now = options.now ?? Date.now
  }

  /** 热层条数。 */
  get hotSize(): number {
    return this.hot.size
  }

  /**
   * 事件进入缓存的唯一入口：内部完成「热命中 / 冷命中晋升 / 过期重分析 /
   * 未命中新析」四种分支，调用方无需关心分层。analyze 只在真正需要分析时
   * 被调用。
   */
  async admit(
    analysisId: string,
    identity: EventIdentity,
    delivery: Omit<DeliveryRef, 'at'>,
    analyze: (identity: EventIdentity) => TriageResult,
  ): Promise<AdmitOutcome> {
    const nowMs = this.now()

    const hot = this.hot.get(analysisId)
    if (hot !== undefined) {
      if (fresh(hot.record.analyzedAt, this.ttlMs, nowMs)) {
        this.bump(hot.record, delivery, nowMs)
        this.counters.reused += 1
        return { record: hot.record, reused: true, reanalyzed: false, tier: 'hot' }
      }
      // 热层过期：交给冷层判定（冷层可能还有效或同样过期）
      this.hot.delete(analysisId)
    }

    const cold = await this.store.load(analysisId)
    if (cold !== null && fresh(cold.analyzedAt, this.ttlMs, nowMs)) {
      this.counters.coldHits += 1
      const hitAt = await this.store.recordHit(analysisId, nowMs)
      const occurrences = hitAt ?? cold.occurrences + 1
      const record = this.materialize(cold, occurrences, delivery, nowMs)
      if (occurrences >= this.hotThreshold) this.promote(record)
      this.counters.reused += 1
      return { record, reused: true, reanalyzed: false, tier: 'cold' }
    }
    this.counters.coldMisses += 1

    // 未命中或已过期：重新分析。过期时从冷库继承累计统计（含首次时间）。
    const carry = cold ?? null
    const result = analyze(identity)
    const record: AnalysisRecord = carry === null
      ? {
        analysisId,
        identity,
        result,
        occurrences: 1,
        firstSeenAt: iso(nowMs),
        lastSeenAt: iso(nowMs),
        analyzedAt: iso(nowMs),
        deliveries: [],
      }
      : {
        analysisId,
        identity,
        result,
        occurrences: carry.occurrences + 1,
        firstSeenAt: carry.firstSeenAt,
        lastSeenAt: iso(nowMs),
        analyzedAt: iso(nowMs),
        deliveries: [...carry.deliveries],
      }
    this.pushDelivery(record, delivery, nowMs)
    await this.store.upsert({ ...record, expiresAt: iso(nowMs + this.ttlMs) })
    if (record.occurrences >= this.hotThreshold) this.promote(record)
    if (carry === null) this.counters.analyzed += 1
    else this.counters.reanalyzed += 1
    return { record, reused: false, reanalyzed: carry !== null, tier: 'cold' }
  }

  /**
   * 启动预热：把冷库里最热的记录装进热层（进程重启后热数据不冷启动）。
   * 重复调用安全（幂等覆盖）。
   */
  async warmup(limit: number): Promise<number> {
    const entries = await this.store.warmup(limit)
    const nowMs = this.now()
    let loaded = 0
    for (const entry of entries) {
      if (!fresh(entry.analyzedAt, this.ttlMs, nowMs)) continue
      const record = this.materialize(entry, entry.occurrences, { eventId: '(warmup)', fingerprint: '' }, this.now())
      this.insertHot(record)
      loaded += 1
    }
    this.counters.warmed += loaded
    return loaded
  }

  /** 定期清理：两层一起删过期记录。 */
  async pruneExpired(): Promise<{ hot: number; cold: number }> {
    const nowMs = this.now()
    let hot = 0
    for (const [key, entry] of this.hot) {
      if (Date.parse(entry.expiresAt) <= nowMs) {
        this.hot.delete(key)
        hot += 1
      }
    }
    const cold = await this.store.pruneExpired(nowMs)
    return { hot, cold }
  }

  /** 缓存规模与计数快照（/stats 端点用）。 */
  async stats(): Promise<CacheStats> {
    const coldSize = await this.store.count()
    return {
      hotSize: this.hot.size,
      coldSize,
      storeKind: this.store.kind,
      ...this.counters,
    }
  }

  private promote(record: AnalysisRecord): void {
    this.insertHot(record)
    this.counters.promoted += 1
  }

  private insertHot(record: AnalysisRecord): void {
    if (!this.hot.has(record.analysisId) && this.hot.size >= this.hotMaxEntries) {
      this.evictLeastRecentlySeen()
    }
    this.hot.set(record.analysisId, { record, expiresAt: iso(Date.parse(record.analyzedAt) + this.ttlMs) })
  }

  /** 热层淘汰 = 降级：记录已在冷库（写穿保证），只需移除；计数差由下次写穿补齐。 */
  private evictLeastRecentlySeen(): void {
    let oldestKey: string | undefined
    let oldestSeen = Number.POSITIVE_INFINITY
    for (const [key, entry] of this.hot) {
      const seen = Date.parse(entry.record.lastSeenAt)
      if (seen < oldestSeen) {
        oldestSeen = seen
        oldestKey = key
      }
    }
    if (oldestKey !== undefined) {
      this.hot.delete(oldestKey)
      this.counters.demoted += 1
    }
  }

  /** 冷库记录 → 缓存记录：套用本次投递并推进 lastSeen。 */
  private materialize(cold: ColdEntry, occurrences: number, delivery: Omit<DeliveryRef, 'at'>, nowMs: number): AnalysisRecord {
    const record: AnalysisRecord = {
      analysisId: cold.analysisId,
      identity: cold.identity,
      result: cold.result,
      occurrences,
      firstSeenAt: cold.firstSeenAt,
      lastSeenAt: iso(nowMs),
      analyzedAt: cold.analyzedAt,
      deliveries: [...cold.deliveries],
    }
    this.pushDelivery(record, delivery, nowMs)
    return record
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
}
