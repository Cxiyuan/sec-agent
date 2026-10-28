/**
 * PostgreSQL 版智能体记忆（结论复用 + 脚本库）。
 *
 * 与 `state-store.ts`（内存实现）同一套接口；单独成文件是为了让本地测试
 * 不必安装 `pg`（无依赖也能跑纯内存路径）。
 *
 * 表结构自管理（CREATE TABLE IF NOT EXISTS），不引入迁移工具；改结构时保持
 * DDL 幂等。所有参数走绑定，禁止拼接用户输入。
 */

import { randomUUID } from 'node:crypto'
import { Pool } from 'pg'
import type { AnalysisScript, ScriptInput, ScriptQuery, ScriptStore, TaskSeenStore } from './state-store.ts'
import { seenKey } from './state-store.ts'
import type { SuppressedTask, TaskIdentity, TaskResultRecord, TaskResultStore, TaskSeenRecord } from './task-results.ts'

const LOG_PREFIX = '[xdr-ingest:state]'

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS xdr_ingest_task_result (
  reuse_key    TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  subject      TEXT NOT NULL,
  feature      TEXT NOT NULL,
  task_id      TEXT NOT NULL,
  verdict      TEXT NOT NULL,
  terminal_reason TEXT NOT NULL DEFAULT '',
  confidence   DOUBLE PRECISION NOT NULL DEFAULT 0,
  summary      TEXT NOT NULL DEFAULT '',
  strength     DOUBLE PRECISION NOT NULL DEFAULT 0,
  occurrences  INTEGER NOT NULL DEFAULT 1,
  analyzed_at  TIMESTAMPTZ NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL
);
ALTER TABLE xdr_ingest_task_result
  ADD COLUMN IF NOT EXISTS terminal_reason TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS xdr_ingest_task_result_expires_idx
  ON xdr_ingest_task_result (expires_at);
CREATE TABLE IF NOT EXISTS xdr_ingest_script (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  scenario       TEXT NOT NULL,
  language       TEXT NOT NULL DEFAULT 'bash',
  code           TEXT NOT NULL,
  variables      JSONB NOT NULL DEFAULT '{}'::jsonb,
  tags           JSONB NOT NULL DEFAULT '[]'::jsonb,
  notes          TEXT NOT NULL DEFAULT '',
  source_task_id TEXT NOT NULL DEFAULT '',
  usage_count    INTEGER NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ NOT NULL,
  updated_at     TIMESTAMPTZ NOT NULL,
  last_used_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS xdr_ingest_script_usage_idx
  ON xdr_ingest_script (usage_count DESC, updated_at DESC);
CREATE TABLE IF NOT EXISTS xdr_ingest_task_seen (
  identity_key   TEXT PRIMARY KEY,
  task_id        TEXT NOT NULL DEFAULT '',
  kind           TEXT NOT NULL DEFAULT '',
  subject_kind   TEXT NOT NULL DEFAULT '',
  subject        TEXT NOT NULL DEFAULT '',
  feature        TEXT NOT NULL DEFAULT '',
  verdict        TEXT NOT NULL DEFAULT '',
  suppressed_by  TEXT NOT NULL DEFAULT '',
  created_at     TIMESTAMPTZ NOT NULL,
  updated_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS xdr_ingest_task_seen_task_idx
  ON xdr_ingest_task_seen (task_id);
`

/** PG 时间列统一成 ISO 字符串。 */
function isoTime(value: unknown): string {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? '' : value.toISOString()
  return typeof value === 'string' ? value : ''
}

function asTags(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is string => typeof item === 'string')
}

/* ------------------------------------------------------------------ */
/* PostgreSQL 实现                                                     */
/* ------------------------------------------------------------------ */

interface TaskRow {
  reuse_key: string
  kind: string
  subject_kind: string
  subject: string
  feature: string
  task_id: string
  verdict: string
  terminal_reason: string
  confidence: number
  summary: string
  strength: number
  occurrences: number
  analyzed_at: Date | string
  expires_at: Date | string
}

interface ScriptRow {
  id: string
  name: string
  scenario: string
  language: string
  code: string
  variables: unknown
  tags: unknown
  notes: string
  source_task_id: string
  usage_count: number
  created_at: Date | string
  updated_at: Date | string
  last_used_at: Date | string | null
}

function toRecord(row: TaskRow): TaskResultRecord {
  return {
    key: row.reuse_key,
    kind: row.kind,
    subjectKind: row.subject_kind,
    subject: row.subject,
    feature: row.feature,
    taskId: row.task_id,
    verdict: row.verdict,
    terminalReason: row.terminal_reason,
    confidence: Number(row.confidence),
    summary: row.summary,
    strength: Number(row.strength),
    occurrences: Number(row.occurrences),
    analyzedAt: isoTime(row.analyzed_at),
    expiresAt: isoTime(row.expires_at),
  }
}

function toScript(row: ScriptRow): AnalysisScript {
  return {
    id: row.id,
    name: row.name,
    scenario: row.scenario,
    language: row.language,
    code: row.code,
    variables: row.variables,
    tags: asTags(row.tags),
    notes: row.notes,
    sourceTaskId: row.source_task_id,
    usageCount: Number(row.usage_count),
    createdAt: isoTime(row.created_at),
    updatedAt: isoTime(row.updated_at),
    lastUsedAt: isoTime(row.last_used_at),
  }
}

export interface PostgresStateStoreOptions {
  readonly connectionString: string
  /** 连接池上限（脚本/结论都是低频写入，不需要大池）。 */
  readonly poolSize?: number
}

export class PostgresStateStore implements TaskResultStore, ScriptStore, TaskSeenStore {
  readonly kind = 'postgres' as const
  private readonly pool: Pool
  private readonly ready: Promise<boolean>

  constructor(options: PostgresStateStoreOptions) {
    this.pool = new Pool({
      connectionString: options.connectionString,
      max: options.poolSize ?? 4,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      application_name: 'xdr-ingest-state',
      options: '-c statement_timeout=5000',
    })
    this.pool.on('error', error => {
      console.error(`${LOG_PREFIX} idle client error:`, error.message)
    })
    this.ready = this.init()
  }

  private async init(): Promise<boolean> {
    const attempts = 5
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        await this.pool.query(SCHEMA_SQL)
        return true
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        if (attempt === attempts) {
          console.error(`${LOG_PREFIX} schema init failed, task reuse/script library degraded:`, message)
          return false
        }
        console.warn(`${LOG_PREFIX} schema init failed (${attempt}/${attempts}), retrying in 2s:`, message)
        await new Promise(resolve => setTimeout(resolve, 2000))
      }
    }
    return false
  }

  private async usable(): Promise<boolean> {
    return this.ready
  }

  async load(key: string): Promise<TaskResultRecord | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<TaskRow>(
        'SELECT * FROM xdr_ingest_task_result WHERE reuse_key = $1',
        [key],
      )
      const row = rows[0]
      return row === undefined ? null : toRecord(row)
    } catch (error) {
      console.error(`${LOG_PREFIX} task result load failed for ${key}:`, this.message(error))
      return null
    }
  }

  async save(record: TaskResultRecord): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      await this.pool.query(
        `INSERT INTO xdr_ingest_task_result
           (reuse_key, kind, subject_kind, subject, feature, task_id, verdict, terminal_reason, confidence,
            summary, strength, occurrences, analyzed_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         ON CONFLICT (reuse_key) DO UPDATE SET
           task_id = EXCLUDED.task_id,
           verdict = EXCLUDED.verdict,
           terminal_reason = EXCLUDED.terminal_reason,
           confidence = EXCLUDED.confidence,
           summary = EXCLUDED.summary,
           strength = EXCLUDED.strength,
           occurrences = EXCLUDED.occurrences,
           analyzed_at = EXCLUDED.analyzed_at,
           expires_at = EXCLUDED.expires_at`,
        [
          record.key, record.kind, record.subjectKind, record.subject, record.feature,
          record.taskId, record.verdict, record.terminalReason, record.confidence, record.summary, record.strength,
          record.occurrences, record.analyzedAt, record.expiresAt,
        ],
      )
      return true
    } catch (error) {
      console.error(`${LOG_PREFIX} task result save failed for ${record.key}:`, this.message(error))
      return false
    }
  }

  async bump(key: string, _nowIso: string, _taskId: string): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      const { rowCount } = await this.pool.query(
        'UPDATE xdr_ingest_task_result SET occurrences = occurrences + 1 WHERE reuse_key = $1',
        [key],
      )
      return (rowCount ?? 0) > 0
    } catch (error) {
      console.error(`${LOG_PREFIX} task result bump failed for ${key}:`, this.message(error))
      return false
    }
  }

  async prune(nowIso: string): Promise<number> {
    if (!await this.usable()) return 0
    try {
      const { rowCount } = await this.pool.query(
        'DELETE FROM xdr_ingest_task_result WHERE expires_at <= $1',
        [nowIso],
      )
      return rowCount ?? 0
    } catch (error) {
      console.error(`${LOG_PREFIX} task result prune failed:`, this.message(error))
      return 0
    }
  }

  async count(): Promise<number> {
    if (!await this.usable()) return 0
    try {
      const { rows } = await this.pool.query<{ n: string }>(
        'SELECT count(*)::text AS n FROM xdr_ingest_task_result',
      )
      return Number(rows[0]?.n ?? 0)
    } catch (error) {
      console.error(`${LOG_PREFIX} task result count failed:`, this.message(error))
      return 0
    }
  }

  async countScripts(): Promise<number> {
    if (!await this.usable()) return 0
    try {
      const { rows } = await this.pool.query<{ n: string }>(
        'SELECT count(*)::text AS n FROM xdr_ingest_script',
      )
      return Number(rows[0]?.n ?? 0)
    } catch (error) {
      console.error(`${LOG_PREFIX} script count failed:`, this.message(error))
      return 0
    }
  }

  async upsert(input: ScriptInput, nowIso: string): Promise<AnalysisScript> {
    if (!await this.usable()) {
      throw new Error('脚本库不可用：PostgreSQL 未连接，保存失败（不要当作已保存）')
    }
    try {
      const { rows } = await this.pool.query<ScriptRow>(
        `INSERT INTO xdr_ingest_script
           (id, name, scenario, language, code, variables, tags, notes, source_task_id,
            usage_count, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, 0, $10, $10)
         ON CONFLICT (name) DO UPDATE SET
           scenario = EXCLUDED.scenario,
           language = EXCLUDED.language,
           code = EXCLUDED.code,
           variables = EXCLUDED.variables,
           tags = EXCLUDED.tags,
           notes = EXCLUDED.notes,
           source_task_id = EXCLUDED.source_task_id,
           updated_at = EXCLUDED.updated_at
         RETURNING *`,
        [
          randomUUID(), input.name.trim(), input.scenario.trim(), (input.language ?? 'bash').trim() || 'bash',
          input.code, JSON.stringify(input.variables ?? {}), JSON.stringify(input.tags ?? []),
          (input.notes ?? '').trim(), (input.sourceTaskId ?? '').trim(), nowIso,
        ],
      )
      const row = rows[0]
      if (row === undefined) throw new Error('脚本保存失败：数据库没有返回记录')
      return toScript(row)
    } catch (error) {
      throw new Error(`脚本保存失败：${this.message(error)}`)
    }
  }

  async get(nameOrId: string): Promise<AnalysisScript | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<ScriptRow>(
        'SELECT * FROM xdr_ingest_script WHERE name = $1 OR id::text = $1 LIMIT 1',
        [nameOrId.trim()],
      )
      const row = rows[0]
      return row === undefined ? null : toScript(row)
    } catch (error) {
      console.error(`${LOG_PREFIX} script get failed:`, this.message(error))
      return null
    }
  }

  async find(query: ScriptQuery): Promise<AnalysisScript[]> {
    if (!await this.usable()) return []
    try {
      const where: string[] = []
      const params: unknown[] = []
      const needle = query.query.trim()
      if (needle !== '') {
        params.push(`%${needle}%`)
        where.push(
          `(name ILIKE $${params.length} OR scenario ILIKE $${params.length}`
          + ` OR notes ILIKE $${params.length} OR tags::text ILIKE $${params.length})`,
        )
      }
      const tag = query.tag.trim()
      if (tag !== '') {
        params.push(tag)
        where.push(`tags ? $${params.length}`)
      }
      params.push(Math.max(1, query.limit))
      const { rows } = await this.pool.query<ScriptRow>(
        `SELECT * FROM xdr_ingest_script
         ${where.length === 0 ? '' : `WHERE ${where.join(' AND ')}`}
         ORDER BY usage_count DESC, updated_at DESC
         LIMIT $${params.length}`,
        params,
      )
      return rows.map(toScript)
    } catch (error) {
      console.error(`${LOG_PREFIX} script find failed:`, this.message(error))
      return []
    }
  }

  async bumpUsage(id: string, nowIso: string): Promise<void> {
    if (!await this.usable()) return
    try {
      await this.pool.query(
        'UPDATE xdr_ingest_script SET usage_count = usage_count + 1, last_used_at = $2 WHERE id = $1',
        [id, nowIso],
      )
    } catch (error) {
      console.error(`${LOG_PREFIX} script bumpUsage failed:`, this.message(error))
    }
  }

  async close(): Promise<void> {
    await this.pool.end().catch(() => undefined)
  }

  /* ---------- 抑制记忆 ---------- */

  async recordTaskSeen(record: TaskSeenRecord): Promise<void> {
    if (!await this.usable()) return
    try {
      await this.pool.query(
        `INSERT INTO xdr_ingest_task_seen
           (identity_key, task_id, kind, subject_kind, subject, feature, verdict, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
         ON CONFLICT (identity_key) DO UPDATE SET
           task_id = EXCLUDED.task_id,
           verdict = EXCLUDED.verdict,
           updated_at = now()`,
        [
          seenKey(record), record.taskId, record.kind, record.subjectKind,
          record.subject, record.feature, record.verdict,
        ],
      )
    } catch (error) {
      console.error(`${LOG_PREFIX} task seen record failed:`, this.message(error))
    }
  }

  async markSuppressed(taskId: string, name: string): Promise<boolean> {
    if (!await this.usable()) return false
    const key = taskId.trim()
    if (key === '') return false
    try {
      const { rowCount } = await this.pool.query(
        `UPDATE xdr_ingest_task_seen SET suppressed_by = $1, updated_at = now() WHERE task_id = $2`,
        [name, key],
      )
      return (rowCount ?? 0) > 0
    } catch (error) {
      console.error(`${LOG_PREFIX} suppression mark failed for task ${key}:`, this.message(error))
      return false
    }
  }

  async markSuppressedByIdentity(identity: TaskIdentity, name: string): Promise<number> {
    if (!await this.usable()) return 0
    try {
      const { rowCount } = await this.pool.query(
        `UPDATE xdr_ingest_task_seen SET suppressed_by = $1, updated_at = now() WHERE identity_key = $2`,
        [name, seenKey(identity)],
      )
      return rowCount ?? 0
    } catch (error) {
      console.error(`${LOG_PREFIX} suppression mark failed by identity:`, this.message(error))
      return 0
    }
  }

  async findSuppressed(identity: TaskIdentity): Promise<SuppressedTask | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<{
        task_id: string
        kind: string
        subject_kind: string
        subject: string
        feature: string
        verdict: string
        suppressed_by: string
      }>(
        `SELECT task_id, kind, subject_kind, subject, feature, verdict, suppressed_by
         FROM xdr_ingest_task_seen WHERE identity_key = $1`,
        [seenKey(identity)],
      )
      const row = rows[0]
      if (row === undefined || row.suppressed_by === '') return null
      return {
        taskId: row.task_id,
        kind: row.kind,
        subjectKind: row.subject_kind,
        subject: row.subject,
        feature: row.feature,
        verdict: row.verdict,
        suppressedBy: row.suppressed_by,
      }
    } catch (error) {
      console.error(`${LOG_PREFIX} suppression lookup failed:`, this.message(error))
      return null
    }
  }

  private message(error: unknown): string {
    return error instanceof Error ? error.message : String(error)
  }
}
