/**
 * 冷存储层：分析结果的持久化载体（v1 = PostgreSQL）。
 *
 * 分层语义（对应用户需求）：
 * - 热层（TieredCache 内的内存 LRU）：经常出现的 IP/事件模式，出现次数达到
 *   阈值才晋升，供高速复用；
 * - 冷层（本接口的实现）：一切分析结果写穿落盘——「不长分析的 IP」直接待在
 *   数据库里，热层淘汰 = 降级回冷层，不丢数据；
 * - 两层 TTL 一致：过期都走「重分析、累计统计保留」。
 *
 * 实现方契约：
 * - 所有方法不得因瞬时故障抛出（PG 抖动不该让整批摄入 500）；故障返回
 *   null/0/[] 并自行日志，由上层降级；
 * - 参数全部走绑定，禁止字符串拼接 SQL。
 */

import type { AnalysisRecord } from './types.ts'
import type { RuntimeSettings, SettingsStore } from './settings.ts'

/** 冷库中的一条分析记录 = 缓存记录 + 过期时刻。 */
export interface ColdEntry extends AnalysisRecord {
  /** ISO 时刻；早于它的记录视为过时，命中也要重分析。 */
  readonly expiresAt: string
}

/** 运营工作台的列表查询（xdr-ui 插件经 xdrIngest 服务用它翻页）。 */
export interface AnalysesQuery {
  /** 单页条数（调用方已钳制）。 */
  readonly limit: number
  /** 跳过条数。 */
  readonly offset: number
  /** 空串 = 不过滤；非空时对分析 ID / 身份 / 结论做不区分大小写的包含匹配。 */
  readonly search: string
}

/** 列表页：过滤后的总数（供分页）+ 一页记录。 */
export interface AnalysesPage {
  readonly total: number
  /** last_seen 降序，同一条记录仍带完整结论与累计次数。 */
  readonly entries: readonly ColdEntry[]
}

export interface ColdStore {
  /** 实现标识（/stats 观测用）。 */
  readonly kind: 'memory' | 'postgres'

  /** 按分析 ID 取冷记录；没有返回 null。过期判断由上层做（要保留累计统计）。 */
  load(analysisId: string): Promise<ColdEntry | null>

  /** 整行 upsert：分析完成后写穿冷库（热层也保留同一份）。 */
  upsert(entry: ColdEntry): Promise<void>

  /**
   * 冷命中计数 +1，返回递增后的 occurrences。
   * 行已被并发清理等情况下返回 null，上层按「本地 +1」继续。
   */
  recordHit(analysisId: string, at: number): Promise<number | null>

  /** 冷库总条数（/stats 用）。 */
  count(): Promise<number>

  /** 清理过期行，返回删除条数。 */
  pruneExpired(now: number): Promise<number>

  /** 按 occurrences 降序取前 limit 条未过期记录（启动预热用）。 */
  warmup(limit: number): Promise<ColdEntry[]>

  /**
   * 分析记录按 last_seen 降序分页（工作台用）。
   * 与预热返回未过期记录不同：这里**含过期记录**——过期只是"待重分析"，
   * 结论与累计统计对排查仍然有效。
   */
  listRecent(query: AnalysesQuery): Promise<AnalysesPage>

  /** 释放资源（连接池等）。 */
  close(): Promise<void>
}

/**
 * 内存冷库：无 PG 的开发/测试环境兜底，语义与 PG 实现一致。
 * 注意它同样怕丢（进程退出即没），生产必须配 pgUrl。
 */
export class MemoryColdStore implements ColdStore, SettingsStore {
  readonly kind = 'memory' as const
  private readonly map = new Map<string, ColdEntry>()
  /** 运行参数（内存实现只在进程内有效；生产用 PG 实现才持久）。 */
  private settings: unknown = null

  async load(analysisId: string): Promise<ColdEntry | null> {
    return this.map.get(analysisId) ?? null
  }

  async upsert(entry: ColdEntry): Promise<void> {
    this.map.set(entry.analysisId, entry)
  }

  async recordHit(analysisId: string, at: number): Promise<number | null> {
    const existing = this.map.get(analysisId)
    if (existing === undefined) return null
    const updated: ColdEntry = {
      ...existing,
      occurrences: existing.occurrences + 1,
      lastSeenAt: new Date(at).toISOString(),
    }
    this.map.set(analysisId, updated)
    return updated.occurrences
  }

  async count(): Promise<number> {
    return this.map.size
  }

  async pruneExpired(now: number): Promise<number> {
    let removed = 0
    for (const [key, entry] of this.map) {
      if (Date.parse(entry.expiresAt) <= now) {
        this.map.delete(key)
        removed += 1
      }
    }
    return removed
  }

  async warmup(limit: number): Promise<ColdEntry[]> {
    const fresh = [...this.map.values()].filter(entry => Date.parse(entry.expiresAt) > Date.now())
    fresh.sort((a, b) => b.occurrences - a.occurrences)
    return fresh.slice(0, Math.max(0, limit))
  }

  async close(): Promise<void> {
    this.map.clear()
  }

  async listRecent(query: AnalysesQuery): Promise<AnalysesPage> {
    const needle = query.search.trim().toLowerCase()
    const matched = [...this.map.values()].filter(entry => needle === '' || listableText(entry).includes(needle))
    matched.sort((a, b) => (a.lastSeenAt < b.lastSeenAt ? 1 : -1))
    return {
      total: matched.length,
      entries: matched.slice(Math.max(0, query.offset), Math.max(0, query.offset) + query.limit),
    }
  }

  async loadSettings(): Promise<unknown> {
    return this.settings
  }

  async saveSettings(settings: RuntimeSettings): Promise<boolean> {
    this.settings = { ...settings }
    return true
  }
}

/** 列表搜索的比对文本：分析 ID + 身份 + 结论，小写。 */
function listableText(entry: ColdEntry): string {
  return JSON.stringify({ analysisId: entry.analysisId, identity: entry.identity, result: entry.result }).toLowerCase()
}
