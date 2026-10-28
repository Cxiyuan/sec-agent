/**
 * PostgreSQL 版结论只读面（控制台「分析记录」的数据源）。
 *
 * 与 `conclusions.ts`（类型 + 内存实现）同一套接口；单独成文件是为了让本地测试
 * 不必安装 `pg`（无依赖也能跑纯内存路径），与 `pg-store.ts` / `pg-state-store.ts` 同理。
 *
 * 结论的**写**在 NDR 侧（`complete_task` 写 `analysis_results`），这里只读。
 * 项目统一用一份 PG，所以 agent 与 ndr 看到的是同一张表，不会出现两份真相。
 *
 * 表不存在（NDR 版本旧/未初始化）时一律降级成"没有结论"，不报错——
 * 控制台必须能打开，只是数据区显示不可用。
 */

import { Pool } from 'pg'
import type { ConclusionPage, ConclusionQuery, ConclusionReader, ConclusionRecord } from './conclusions.ts'

const LOG_PREFIX = '[xdr-ingest:conclusions]'

interface ConclusionRow {
  id: string
  task_id: string
  kind: string
  subject_kind: string
  subject: string
  verdict: string
  confidence: number | string
  summary: string
  findings: unknown
  evidence_refs: unknown
  tools_used: number | string
  duration_ms: number | string
  terminal_reason: string
  created_at: Date | string
}

function isoTime(value: unknown): string {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? '' : value.toISOString()
  return typeof value === 'string' ? value : ''
}

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is string => typeof item === 'string')
}

function toRecord(row: ConclusionRow): ConclusionRecord {
  const findings = row.findings
  const reusedFrom = typeof findings === 'object' && findings !== null && !Array.isArray(findings)
    ? String((findings as Record<string, unknown>)['reused_from'] ?? '').trim()
    : ''
  return {
    id: String(row.id),
    taskId: String(row.task_id ?? ''),
    kind: String(row.kind ?? ''),
    subjectKind: String(row.subject_kind ?? ''),
    subject: String(row.subject ?? ''),
    verdict: String(row.verdict ?? ''),
    confidence: Number(row.confidence ?? 0),
    summary: String(row.summary ?? ''),
    findings: row.findings ?? {},
    evidenceRefs: asStringList(row.evidence_refs),
    toolsUsed: Number(row.tools_used ?? 0),
    durationMs: Number(row.duration_ms ?? 0),
    // 复用交回的行标出来：成本不算它（没起会话），界面也不该显示成"又分析了一遍"
    reused: reusedFrom !== '',
    reusedFrom,
    terminalReason: String(row.terminal_reason ?? ''),
    createdAt: isoTime(row.created_at),
  }
}

const SELECT_COLUMNS = 'id, task_id, kind, subject_kind, subject, verdict, confidence, summary,'
  + ' findings, evidence_refs, tools_used, duration_ms, terminal_reason, created_at'

export interface PostgresConclusionReaderOptions {
  readonly connectionString: string
  readonly poolSize?: number
}

/** PG 的「表不存在」错误码：表没建 = 数据不可用，不是故障。 */
const UNDEFINED_TABLE = '42P01'

export class PostgresConclusionReader implements ConclusionReader {
  private readonly pool: Pool
  private readonly readyPromise: Promise<boolean>
  private usable = false

  constructor(options: PostgresConclusionReaderOptions) {
    this.pool = new Pool({
      connectionString: options.connectionString,
      max: options.poolSize ?? 2,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      application_name: 'xdr-ingest-conclusions',
      options: '-c statement_timeout=5000',
    })
    this.pool.on('error', error => {
      console.error(`${LOG_PREFIX} idle client error:`, error.message)
    })
    this.readyPromise = this.init()
  }

  /** 探一次表在不在：不在就整页降级成"没有结论"。 */
  private async init(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1 FROM analysis_results LIMIT 1')
      this.usable = true
    } catch (error) {
      const code = (error as { code?: string }).code ?? ''
      if (code === UNDEFINED_TABLE) {
        console.warn(`${LOG_PREFIX} NDR 表 analysis_results 不存在：控制台的「分析记录」显示为空。`)
      } else {
        console.error(`${LOG_PREFIX} 结论表不可读：`, this.message(error))
      }
      this.usable = false
    }
    return this.usable
  }

  available(): boolean {
    return this.usable
  }

  /** 等探表结束（构造后立刻问一次会拿到 false —— 探表是异步的）。 */
  async ready(): Promise<boolean> {
    return this.readyPromise
  }

  async listRecent(query: ConclusionQuery): Promise<ConclusionPage> {
    if (!await this.readyPromise) return { total: 0, entries: [] }
    const limit = Math.max(1, Math.min(200, Math.trunc(query.limit) || 50))
    const offset = Math.max(0, Math.trunc(query.offset) || 0)
    const needle = query.search.trim()
    try {
      const where = needle === ''
        ? ''
        : 'WHERE subject ILIKE $1 OR summary ILIKE $1 OR verdict ILIKE $1'
          + ' OR kind ILIKE $1 OR subject_kind ILIKE $1 OR task_id ILIKE $1'
      const params: unknown[] = needle === '' ? [] : [`%${needle}%`]
      const [{ rows: listRows }, { rows: countRows }] = await Promise.all([
        this.pool.query<ConclusionRow>(
          `SELECT ${SELECT_COLUMNS} FROM analysis_results ${where}`
          + ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, limit, offset],
        ),
        this.pool.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM analysis_results ${where}`,
          params,
        ),
      ])
      return {
        total: Number(countRows[0]?.n ?? 0),
        entries: listRows.map(toRecord),
      }
    } catch (error) {
      console.error(`${LOG_PREFIX} 结论列表查询失败：`, this.message(error))
      return { total: 0, entries: [] }
    }
  }

  async get(id: string): Promise<ConclusionRecord | null> {
    if (!await this.readyPromise) return null
    const key = id.trim()
    if (key === '') return null
    try {
      const { rows } = await this.pool.query<ConclusionRow>(
        `SELECT ${SELECT_COLUMNS} FROM analysis_results WHERE id::text = $1 LIMIT 1`,
        [key],
      )
      const row = rows[0]
      return row === undefined ? null : toRecord(row)
    } catch (error) {
      console.error(`${LOG_PREFIX} 结论详情查询失败：`, this.message(error))
      return null
    }
  }

  async count(): Promise<number> {
    if (!await this.readyPromise) return 0
    try {
      const { rows } = await this.pool.query<{ n: string }>(
        'SELECT count(*)::text AS n FROM analysis_results',
      )
      return Number(rows[0]?.n ?? 0)
    } catch (error) {
      console.error(`${LOG_PREFIX} 结论计数失败：`, this.message(error))
      return 0
    }
  }

  async close(): Promise<void> {
    await this.pool.end().catch(() => undefined)
  }

  private message(error: unknown): string {
    return error instanceof Error ? error.message : String(error)
  }
}
