/**
 * PostgreSQL 冷库实现：分析结果的持久化层（项目统一 PG 存储）。
 *
 * 设计要点：
 * - 单表 + 内联 DDL（CREATE TABLE IF NOT EXISTS）：插件级 schema 自管理，
 *   不引入迁移工具；表结构变更时改 SCHEMA_SQL 并保持幂等；
 * - 连接串复用 NDR 侧约定（postgresql://user:pass@host:5432/db，注意 Node 的
 *   pg 不吃 SQLAlchemy 的 +psycopg 驱动后缀，部署时去掉）；
 * - 故障降级：schema 初始化或任一条查询失败 → 记日志、标记不可用，后续调用
 *   直接走降级分支（load→null / upsert→no-op / recordHit→null）。PG 抖动不
 *   该让 NDR 整批 500 重推——热层仍在内存里兜底判重；
 * - statement_timeout 5s：慢查询不占着连接池拖垮摄入线程。
 */

import { Pool } from 'pg'
import type { AnalysesPage, AnalysesQuery, ColdEntry, ColdStore } from './store.ts'
import type { RuntimeSettings, SettingsStore } from './settings.ts'
import type { AnalysisRecord } from './types.ts'

/** 单表 DDL。索引覆盖冷命中清理（last_seen）与预热排序（occurrences）。 */
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS xdr_ingest_analysis (
  analysis_id  TEXT PRIMARY KEY,
  identity     JSONB NOT NULL,
  result       JSONB NOT NULL,
  occurrences  INTEGER NOT NULL DEFAULT 1,
  first_seen   TIMESTAMPTZ NOT NULL,
  last_seen    TIMESTAMPTZ NOT NULL,
  analyzed_at  TIMESTAMPTZ NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  deliveries   JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS xdr_ingest_analysis_last_seen_idx
  ON xdr_ingest_analysis (last_seen);
CREATE INDEX IF NOT EXISTS xdr_ingest_analysis_occurrences_idx
  ON xdr_ingest_analysis (occurrences DESC);
CREATE TABLE IF NOT EXISTS xdr_ingest_settings (
  singleton   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  value       JSONB NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

const LOG_PREFIX = '[xdr-ingest:pg]'

export interface PostgresColdStoreOptions {
  /** libpq 连接串，如 postgresql://shentong:shentong@localhost:5432/shentong。 */
  readonly connectionString: string
  /** 连接池上限；摄入是低频写、命中读，默认 10 足够。 */
  readonly poolSize?: number
}

interface AnalysisRow {
  analysis_id: string
  identity: unknown
  result: unknown
  occurrences: number
  first_seen: Date | string
  last_seen: Date | string
  analyzed_at: Date | string
  expires_at: Date | string
  deliveries: unknown
}

function isoTime(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString()
}

function toEntry(row: AnalysisRow): ColdEntry {
  return {
    analysisId: row.analysis_id,
    identity: row.identity as ColdEntry['identity'],
    result: row.result as ColdEntry['result'],
    occurrences: Number(row.occurrences),
    firstSeenAt: isoTime(row.first_seen),
    lastSeenAt: isoTime(row.last_seen),
    analyzedAt: isoTime(row.analyzed_at),
    expiresAt: isoTime(row.expires_at),
    deliveries: Array.isArray(row.deliveries) ? (row.deliveries as ColdEntry['deliveries']) : [],
  }
}

export class PostgresColdStore implements ColdStore, SettingsStore {
  readonly kind = 'postgres' as const
  private readonly pool: Pool
  /** schema 初始化结果；false = PG 不可用，全实例降级。 */
  private readonly ready: Promise<boolean>

  constructor(options: PostgresColdStoreOptions) {
    this.pool = new Pool({
      connectionString: options.connectionString,
      max: options.poolSize ?? 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      application_name: 'xdr-ingest',
      options: '-c statement_timeout=5000',
    })
    this.pool.on('error', error => {
      console.error(`${LOG_PREFIX} idle client error:`, error.message)
    })
    this.ready = this.init()
  }

  private async init(): Promise<boolean> {
    try {
      await this.pool.query(SCHEMA_SQL)
      return true
    } catch (error) {
      console.error(
        `${LOG_PREFIX} schema init failed, degrading to memory-only dedup:`,
        error instanceof Error ? error.message : String(error),
      )
      return false
    }
  }

  /** 统一降级闸门：初始化失败或运行期故障后返回 false，调用方走空实现。 */
  private async usable(): Promise<boolean> {
    return this.ready
  }

  async load(analysisId: string): Promise<ColdEntry | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<AnalysisRow>(
        'SELECT analysis_id, identity, result, occurrences, first_seen, last_seen, analyzed_at, expires_at, deliveries'
        + ' FROM xdr_ingest_analysis WHERE analysis_id = $1',
        [analysisId],
      )
      const row = rows[0]
      return row === undefined ? null : toEntry(row)
    } catch (error) {
      console.error(`${LOG_PREFIX} load failed for ${analysisId}:`, error instanceof Error ? error.message : String(error))
      return null
    }
  }

  async upsert(entry: ColdEntry): Promise<void> {
    if (!await this.usable()) return
    try {
      await this.pool.query(
        `INSERT INTO xdr_ingest_analysis
           (analysis_id, identity, result, occurrences, first_seen, last_seen, analyzed_at, expires_at, deliveries)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (analysis_id) DO UPDATE SET
           identity = EXCLUDED.identity,
           result = EXCLUDED.result,
           occurrences = EXCLUDED.occurrences,
           last_seen = EXCLUDED.last_seen,
           analyzed_at = EXCLUDED.analyzed_at,
           expires_at = EXCLUDED.expires_at,
           deliveries = EXCLUDED.deliveries`,
        [
          entry.analysisId,
          JSON.stringify(entry.identity),
          JSON.stringify(entry.result),
          entry.occurrences,
          entry.firstSeenAt,
          entry.lastSeenAt,
          entry.analyzedAt,
          entry.expiresAt,
          JSON.stringify(entry.deliveries),
        ],
      )
    } catch (error) {
      // 写穿失败不阻断摄入：结果仍在热层，PG 恢复后由下次写穿补上
      console.error(`${LOG_PREFIX} upsert failed for ${entry.analysisId}:`, error instanceof Error ? error.message : String(error))
    }
  }

  async recordHit(analysisId: string, at: number): Promise<number | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<{ occurrences: number }>(
        'UPDATE xdr_ingest_analysis SET occurrences = occurrences + 1, last_seen = $2'
        + ' WHERE analysis_id = $1 RETURNING occurrences',
        [analysisId, new Date(at).toISOString()],
      )
      return rows[0]?.occurrences ?? null
    } catch (error) {
      console.error(`${LOG_PREFIX} recordHit failed for ${analysisId}:`, error instanceof Error ? error.message : String(error))
      return null
    }
  }

  async count(): Promise<number> {
    if (!await this.usable()) return 0
    try {
      const { rows } = await this.pool.query<{ count: string }>('SELECT count(*) AS count FROM xdr_ingest_analysis')
      return Number(rows[0]?.count ?? 0)
    } catch (error) {
      console.error(`${LOG_PREFIX} count failed:`, error instanceof Error ? error.message : String(error))
      return 0
    }
  }

  async pruneExpired(now: number): Promise<number> {
    if (!await this.usable()) return 0
    try {
      const { rowCount } = await this.pool.query('DELETE FROM xdr_ingest_analysis WHERE expires_at <= $1', [new Date(now)])
      return rowCount ?? 0
    } catch (error) {
      console.error(`${LOG_PREFIX} prune failed:`, error instanceof Error ? error.message : String(error))
      return 0
    }
  }

  async warmup(limit: number): Promise<ColdEntry[]> {
    if (!await this.usable()) return []
    try {
      const { rows } = await this.pool.query<AnalysisRow & { total: string }>(
        'SELECT analysis_id, identity, result, occurrences, first_seen, last_seen, analyzed_at, expires_at, deliveries,'
        + ' count(*) OVER () AS total'
        + ' FROM xdr_ingest_analysis WHERE expires_at > $1 ORDER BY occurrences DESC LIMIT $2',
        [new Date(), Math.max(0, limit)],
      )
      return rows.map(toEntry)
    } catch (error) {
      console.error(`${LOG_PREFIX} warmup failed for limit ${limit}:`, error instanceof Error ? error.message : String(error))
      return []
    }
  }

  /**
   * last_seen 降序分页。搜索走 ILIKE 不区分英文大小写；比对 analysis_id 与
   * identity/result 的 JSON 文本（含规则名、源 IP、结论摘要），过滤后的总数
   * 用窗口函数一次算出——翻页与总数读同一快照。深翻页越过末尾（窗口函数
   * 没有行可看）时补一趟 count，只为总数仍准确。
   */
  async listRecent(query: AnalysesQuery): Promise<AnalysesPage> {
    if (!await this.usable()) return { total: 0, entries: [] }
    const search = query.search.trim()
    const offset = Math.max(0, Math.floor(query.offset))
    const limit = Math.max(0, Math.floor(query.limit))
    try {
      const { rows } = await this.pool.query<AnalysisRow & { total: string }>(
        'SELECT analysis_id, identity, result, occurrences, first_seen, last_seen, analyzed_at, expires_at, deliveries,'
        + ' count(*) OVER () AS total'
        + ' FROM xdr_ingest_analysis'
        + ' WHERE ($1 = \'\' OR analysis_id ILIKE \'%\' || $1 || \'%\''
        + '   OR identity::text   ILIKE \'%\' || $1 || \'%\''
        + '   OR result::text     ILIKE \'%\' || $1 || \'%\')'
        + ' ORDER BY last_seen DESC'
        + ' LIMIT $2 OFFSET $3',
        [search, limit, offset],
      )
      const total = rows.length === 0 && offset === 0 ? 0 : Number(rows[0]?.total ?? 0)
      // 深翻页越过末尾时窗口函数没有行可看；此时过滤后的总数只能再问一趟。
      if (rows.length === 0 && offset > 0) {
        const counted = await this.pool.query<{ count: string }>(
          'SELECT count(*) AS count FROM xdr_ingest_analysis'
          + ' WHERE ($1 = \'\' OR analysis_id ILIKE \'%\' || $1 || \'%\''
          + '   OR identity::text   ILIKE \'%\' || $1 || \'%\''
          + '   OR result::text     ILIKE \'%\' || $1 || \'%\')',
          [search],
        )
        return { total: Number(counted.rows[0]?.count ?? 0), entries: [] }
      }
      return { total, entries: rows.map(toEntry) }
    } catch (error) {
      console.error(`${LOG_PREFIX} listRecent failed:`, error instanceof Error ? error.message : String(error))
      return { total: 0, entries: [] }
    }
  }

  async close(): Promise<void> {
    try {
      await this.pool.end()
    } catch (error) {
      console.error(`${LOG_PREFIX} pool close failed:`, error instanceof Error ? error.message : String(error))
    }
  }

  /** 读上次保存的运行参数；没存过或库不可用时返回 null（用 cordis 配置默认值）。 */
  async loadSettings(): Promise<unknown> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<{ value: unknown }>(
        'SELECT value FROM xdr_ingest_settings WHERE singleton',
      )
      return rows[0]?.value ?? null
    } catch (error) {
      console.error(`${LOG_PREFIX} loadSettings failed:`, error instanceof Error ? error.message : String(error))
      return null
    }
  }

  /** 整份 upsert；写失败返回 false（调用方保留内存值并告警，不阻断运行）。 */
  async saveSettings(settings: RuntimeSettings): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      await this.pool.query(
        `INSERT INTO xdr_ingest_settings (singleton, value, updated_at)
         VALUES (TRUE, $1, now())
         ON CONFLICT (singleton) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
        [JSON.stringify(settings)],
      )
      return true
    } catch (error) {
      console.error(`${LOG_PREFIX} saveSettings failed:`, error instanceof Error ? error.message : String(error))
      return false
    }
  }
}

/** 便于测试与复用：冷记录 → 缓存记录（去掉 expiresAt）。 */
export function recordOf(entry: ColdEntry): AnalysisRecord {
  const { expiresAt: _expiresAt, ...record } = entry
  return record
}
