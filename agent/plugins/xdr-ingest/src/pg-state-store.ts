/**
 * PostgreSQL 版智能体记忆（**按项目组织隔离**）。
 *
 * 与 `state-store.ts`（内存实现）同一套接口；单独成文件是为了让本地测试
 * 不必安装 `pg`（无依赖也能跑纯内存路径）。
 *
 * 表结构自管理（CREATE TABLE IF NOT EXISTS + ALTER ... IF NOT EXISTS），不引入迁移
 * 工具；改结构时保持 DDL 幂等。所有参数走绑定，禁止拼接用户输入。
 *
 * 每张表都带 `project_id`（NDR 授权ID），**唯一键都在项目内唯一**：
 * 一台 agent 接多台 NDR 时，各项目的脚本/结论/抑制记忆互不可见。
 */

import { randomUUID } from 'node:crypto'
import { Pool } from 'pg'
import type {
  AnalysisScript,
  ConclusionStore,
  ProcessFinish,
  ProcessRecord,
  ProcessStart,
  ProcessStore,
  ProjectInput,
  ProjectRecord,
  ProjectStatus,
  RuntimeSettings,
  ScriptInput,
  ScriptQuery,
  ScriptStore,
  SettingsStore,
  TaskSeenStore,
  WorkflowInput,
  WorkflowRecord,
  WorkflowStage,
  WorkflowStore,
} from './state-store.ts'
import { seenKey } from './state-store.ts'
import type { ConclusionPage, ConclusionQuery, ConclusionRecord } from './conclusions.ts'
import type {
  SuppressedTask,
  TaskIdentity,
  TaskResultRecord,
  TaskResultStore,
  TaskSeenRecord,
} from './task-results.ts'

const LOG_PREFIX = '[xdr-ingest:state]'

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS xdr_ingest_project (
  project_id      TEXT PRIMARY KEY,
  name            TEXT NOT NULL DEFAULT '',
  mcp_url         TEXT NOT NULL DEFAULT '',
  mcp_token       TEXT NOT NULL DEFAULT '',
  push_token      TEXT NOT NULL DEFAULT '',
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  status          TEXT NOT NULL DEFAULT 'unchecked',
  status_detail   TEXT NOT NULL DEFAULT '',
  last_checked_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS xdr_ingest_task_result (
  project_id   TEXT NOT NULL,
  reuse_key    TEXT NOT NULL,
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
  expires_at   TIMESTAMPTZ NOT NULL,
  recommendation TEXT NOT NULL DEFAULT '',
  payload      JSONB NOT NULL DEFAULT '{}'::jsonb,
  version      INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (project_id, reuse_key)
);
ALTER TABLE xdr_ingest_task_result
  ADD COLUMN IF NOT EXISTS terminal_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE xdr_ingest_task_result
  ADD COLUMN IF NOT EXISTS recommendation TEXT NOT NULL DEFAULT '';
ALTER TABLE xdr_ingest_task_result
  ADD COLUMN IF NOT EXISTS payload JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE xdr_ingest_task_result
  ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS xdr_ingest_task_result_expires_idx
  ON xdr_ingest_task_result (project_id, expires_at);
CREATE TABLE IF NOT EXISTS xdr_ingest_script (
  project_id     TEXT NOT NULL,
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  scenario       TEXT NOT NULL,
  language       TEXT NOT NULL DEFAULT 'bash',
  code           TEXT NOT NULL,
  variables      JSONB NOT NULL DEFAULT '{}'::jsonb,
  tags           JSONB NOT NULL DEFAULT '[]'::jsonb,
  notes          TEXT NOT NULL DEFAULT '',
  source_task_id TEXT NOT NULL DEFAULT '',
  usage_count    INTEGER NOT NULL DEFAULT 0,
  enabled        BOOLEAN NOT NULL DEFAULT TRUE,
  origin         TEXT NOT NULL DEFAULT 'agent',
  updated_by     TEXT NOT NULL DEFAULT '',
  created_at     TIMESTAMPTZ NOT NULL,
  updated_at     TIMESTAMPTZ NOT NULL,
  last_used_at   TIMESTAMPTZ,
  UNIQUE (project_id, name)
);
ALTER TABLE xdr_ingest_script ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE xdr_ingest_script ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE xdr_ingest_script ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS xdr_ingest_script_usage_idx
  ON xdr_ingest_script (project_id, usage_count DESC, updated_at DESC);
CREATE TABLE IF NOT EXISTS xdr_ingest_task_seen (
  project_id     TEXT NOT NULL,
  identity_key   TEXT NOT NULL,
  task_id        TEXT NOT NULL DEFAULT '',
  kind           TEXT NOT NULL DEFAULT '',
  subject_kind   TEXT NOT NULL DEFAULT '',
  subject        TEXT NOT NULL DEFAULT '',
  feature        TEXT NOT NULL DEFAULT '',
  verdict        TEXT NOT NULL DEFAULT '',
  suppressed_by  TEXT NOT NULL DEFAULT '',
  created_at     TIMESTAMPTZ NOT NULL,
  updated_at     TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (project_id, identity_key)
);
CREATE INDEX IF NOT EXISTS xdr_ingest_task_seen_task_idx
  ON xdr_ingest_task_seen (project_id, task_id);
CREATE TABLE IF NOT EXISTS xdr_ingest_conclusion (
  id             TEXT PRIMARY KEY,
  project_id     TEXT NOT NULL,
  task_id        TEXT NOT NULL DEFAULT '',
  kind           TEXT NOT NULL DEFAULT '',
  subject_kind   TEXT NOT NULL DEFAULT '',
  subject        TEXT NOT NULL DEFAULT '',
  verdict        TEXT NOT NULL DEFAULT '',
  confidence     DOUBLE PRECISION NOT NULL DEFAULT 0,
  summary        TEXT NOT NULL DEFAULT '',
  findings       JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs  JSONB NOT NULL DEFAULT '[]'::jsonb,
  tools_used     INTEGER NOT NULL DEFAULT 0,
  duration_ms    BIGINT NOT NULL DEFAULT 0,
  terminal_reason TEXT NOT NULL DEFAULT '',
  reused         BOOLEAN NOT NULL DEFAULT FALSE,
  reused_from    TEXT NOT NULL DEFAULT '',
  created_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS xdr_ingest_conclusion_project_idx
  ON xdr_ingest_conclusion (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS xdr_ingest_conclusion_task_idx
  ON xdr_ingest_conclusion (project_id, task_id);
CREATE TABLE IF NOT EXISTS xdr_ingest_workflow (
  workflow_id  TEXT PRIMARY KEY,
  name         TEXT NOT NULL DEFAULT '',
  description  TEXT NOT NULL DEFAULT '',
  stages       JSONB NOT NULL DEFAULT '[]'::jsonb,
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  is_default   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS xdr_ingest_process (
  project_id   TEXT NOT NULL,
  task_id      TEXT NOT NULL,
  session_id   TEXT NOT NULL DEFAULT '',
  kind         TEXT NOT NULL DEFAULT '',
  subject      TEXT NOT NULL DEFAULT '',
  model        TEXT NOT NULL DEFAULT '',
  started_at   TIMESTAMPTZ NOT NULL,
  ended_at     TIMESTAMPTZ,
  outcome      TEXT NOT NULL DEFAULT 'running',
  tools_used   INTEGER NOT NULL DEFAULT 0,
  duration_ms  BIGINT NOT NULL DEFAULT 0,
  verdict      TEXT NOT NULL DEFAULT '',
  note         TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (project_id, task_id)
);
CREATE INDEX IF NOT EXISTS xdr_ingest_process_started_idx
  ON xdr_ingest_process (project_id, started_at DESC);
ALTER TABLE xdr_ingest_project ADD COLUMN IF NOT EXISTS workflow_id TEXT NOT NULL DEFAULT '';
ALTER TABLE xdr_ingest_project ADD COLUMN IF NOT EXISTS model TEXT NOT NULL DEFAULT '';
ALTER TABLE xdr_ingest_project ADD COLUMN IF NOT EXISTS fallback_model TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS xdr_ingest_schema (
  version    INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO xdr_ingest_schema (version) VALUES (2) ON CONFLICT (version) DO NOTHING;
ALTER TABLE xdr_ingest_process ADD COLUMN IF NOT EXISTS workflow_id TEXT NOT NULL DEFAULT '';
ALTER TABLE xdr_ingest_process ADD COLUMN IF NOT EXISTS workflow_name TEXT NOT NULL DEFAULT '';
ALTER TABLE xdr_ingest_process ADD COLUMN IF NOT EXISTS workflow_stages JSONB NOT NULL DEFAULT '[]'::jsonb;
-- 老部署的 settings 是单租户表（singleton），与现在的 project_id 结构不兼容：
-- CREATE IF NOT EXISTS 不会改已有表，直接改名留档，再建新表（运行参数丢了会用默认值）。
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'xdr_ingest_settings' AND column_name = 'singleton'
  ) THEN
    ALTER TABLE xdr_ingest_settings RENAME TO xdr_ingest_settings_legacy;
  END IF;
END $$;
CREATE TABLE IF NOT EXISTS xdr_ingest_settings (
  project_id TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
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

function asStringList(value: unknown): string[] {
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
  recommendation: string
  payload: unknown
  version: number
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
  enabled: boolean
  origin: string
  updated_by: string
  created_at: Date | string
  updated_at: Date | string
  last_used_at: Date | string | null
}

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
  reused: boolean
  reused_from: string
  created_at: Date | string
}

interface ProcessRow {
  task_id: string
  session_id: string
  kind: string
  subject: string
  model: string
  started_at: Date | string
  ended_at: Date | string | null
  outcome: string
  tools_used: number | string
  duration_ms: number | string
  verdict: string
  note: string
  workflow_id: string
  workflow_name: string
  workflow_stages: unknown
}

interface WorkflowRow {
  workflow_id: string
  name: string
  description: string
  stages: unknown
  enabled: boolean
  is_default: boolean
  created_at: Date | string
  updated_at: Date | string
  updated_by: string
}

interface ProjectRow {
  project_id: string
  name: string
  mcp_url: string
  mcp_token: string
  push_token: string
  enabled: boolean
  workflow_id: string
  model: string
  fallback_model: string
  status: string
  status_detail: string
  last_checked_at: Date | string | null
  created_at: Date | string
  updated_at: Date | string
}

const PROJECT_STATUSES: ReadonlySet<string> = new Set([
  'ok', 'auth_mismatch', 'unreachable', 'unchecked', 'disabled',
])

function toProject(row: ProjectRow): ProjectRecord {
  const status = String(row.status ?? 'unchecked')
  return {
    projectId: String(row.project_id),
    name: String(row.name ?? ''),
    mcpUrl: String(row.mcp_url ?? ''),
    mcpToken: String(row.mcp_token ?? ''),
    pushToken: String(row.push_token ?? ''),
    enabled: row.enabled === true,
    workflowId: String(row.workflow_id ?? ''),
    model: String(row.model ?? ''),
    fallbackModel: String(row.fallback_model ?? ''),
    status: (PROJECT_STATUSES.has(status) ? status : 'unchecked') as ProjectStatus,
    statusDetail: String(row.status_detail ?? ''),
    lastCheckedAt: isoTime(row.last_checked_at),
    createdAt: isoTime(row.created_at),
    updatedAt: isoTime(row.updated_at),
  }
}

function toRecord(row: TaskRow): TaskResultRecord {
  // B2：复用回放的附加字段（老记录 payload 为空 → 不回放，行为同改造前）
  const payload =
    typeof row.payload === 'object' && row.payload !== null && !Array.isArray(row.payload)
      ? (row.payload as Record<string, unknown>)
      : {}
  const findings =
    typeof payload['findings'] === 'object' && payload['findings'] !== null
      ? (payload['findings'] as Record<string, unknown>)
      : undefined
  const anchors = Array.isArray(payload['anchors'])
    ? (payload['anchors'] as { kind?: unknown; value?: unknown }[])
        .map(a => ({ kind: String(a.kind ?? ''), value: String(a.value ?? '') }))
        .filter(a => a.kind !== '' && a.value !== '')
    : []
  const recommendation = String(row.recommendation ?? '')
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
    version: Number(row.version ?? 1),
    ...(findings !== undefined && Object.keys(findings).length > 0 ? { findings } : {}),
    ...(anchors.length > 0 ? { anchors } : {}),
    ...(recommendation !== '' ? { recommendation } : {}),
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
    enabled: row.enabled !== false,
    origin: String(row.origin ?? 'agent'),
    updatedBy: String(row.updated_by ?? ''),
  }
}

function toConclusion(row: ConclusionRow): ConclusionRecord {
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
    reused: row.reused === true,
    reusedFrom: String(row.reused_from ?? ''),
    terminalReason: String(row.terminal_reason ?? ''),
    createdAt: isoTime(row.created_at),
  }
}

function toProcess(row: ProcessRow): ProcessRecord {
  const outcome = String(row.outcome ?? 'running')
  return {
    taskId: String(row.task_id),
    sessionId: String(row.session_id ?? ''),
    kind: String(row.kind ?? ''),
    subject: String(row.subject ?? ''),
    model: String(row.model ?? ''),
    startedAt: isoTime(row.started_at),
    endedAt: isoTime(row.ended_at),
    outcome: outcome as ProcessRecord['outcome'],
    toolsUsed: Number(row.tools_used ?? 0),
    durationMs: Number(row.duration_ms ?? 0),
    verdict: String(row.verdict ?? ''),
    note: String(row.note ?? ''),
    workflowId: String(row.workflow_id ?? ''),
    workflowName: String(row.workflow_name ?? ''),
    workflowStages: Array.isArray(row.workflow_stages)
      ? (row.workflow_stages as WorkflowStage[])
      : [],
  }
}

function toWorkflow(row: WorkflowRow): WorkflowRecord {
  const stages = Array.isArray(row.stages) ? (row.stages as WorkflowStage[]) : []
  return {
    workflowId: String(row.workflow_id),
    name: String(row.name ?? ''),
    description: String(row.description ?? ''),
    stages,
    enabled: row.enabled === true,
    isDefault: row.is_default === true,
    createdAt: isoTime(row.created_at),
    updatedAt: isoTime(row.updated_at),
    updatedBy: String(row.updated_by ?? ''),
  }
}

const SELECT_CONCLUSION = 'id, task_id, kind, subject_kind, subject, verdict, confidence,'
  + ' summary, findings, evidence_refs, tools_used, duration_ms, terminal_reason,'
  + ' reused, reused_from, created_at'

export interface PostgresStateStoreOptions {
  readonly connectionString: string
  /** 项目组织（= NDR 授权ID）：本实例的所有读写都限定在这个项目内。 */
  readonly projectId: string
  /** 连接池上限（脚本/结论都是低频写入，不需要大池）。 */
  readonly poolSize?: number
}

export class PostgresStateStore
implements TaskResultStore, ScriptStore, TaskSeenStore, ConclusionStore, SettingsStore, ProcessStore, WorkflowStore {
  readonly kind = 'postgres' as const
  readonly projectId: string
  private readonly pool: Pool
  private readonly ready: Promise<boolean>

  constructor(options: PostgresStateStoreOptions) {
    this.projectId = String(options.projectId ?? '').trim()
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

  /* ---------- 结论复用 ---------- */

  async load(key: string): Promise<TaskResultRecord | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<TaskRow>(
        'SELECT * FROM xdr_ingest_task_result WHERE project_id = $1 AND reuse_key = $2',
        [this.projectId, key],
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
           (project_id, reuse_key, kind, subject_kind, subject, feature, task_id, verdict,
            terminal_reason, confidence, summary, strength, occurrences, analyzed_at, expires_at,
            recommendation, payload, version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
         ON CONFLICT (project_id, reuse_key) DO UPDATE SET
           task_id = EXCLUDED.task_id,
           verdict = EXCLUDED.verdict,
           terminal_reason = EXCLUDED.terminal_reason,
           confidence = EXCLUDED.confidence,
           summary = EXCLUDED.summary,
           strength = EXCLUDED.strength,
           occurrences = EXCLUDED.occurrences,
           analyzed_at = EXCLUDED.analyzed_at,
           expires_at = EXCLUDED.expires_at,
           recommendation = EXCLUDED.recommendation,
           payload = EXCLUDED.payload,
           version = EXCLUDED.version`,
        [
          this.projectId, record.key, record.kind, record.subjectKind, record.subject,
          record.feature, record.taskId, record.verdict, record.terminalReason, record.confidence,
          record.summary, record.strength, record.occurrences, record.analyzedAt, record.expiresAt,
          record.recommendation ?? '',
          JSON.stringify({
            findings: record.findings ?? {},
            anchors: record.anchors ?? [],
          }),
          record.version ?? 1,
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
        'UPDATE xdr_ingest_task_result SET occurrences = occurrences + 1'
        + ' WHERE project_id = $1 AND reuse_key = $2',
        [this.projectId, key],
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
        'DELETE FROM xdr_ingest_task_result WHERE project_id = $1 AND expires_at <= $2',
        [this.projectId, nowIso],
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
        'SELECT count(*)::text AS n FROM xdr_ingest_task_result WHERE project_id = $1',
        [this.projectId],
      )
      return Number(rows[0]?.n ?? 0)
    } catch (error) {
      console.error(`${LOG_PREFIX} task result count failed:`, this.message(error))
      return 0
    }
  }

  /* ---------- 脚本库 ---------- */

  async countScripts(): Promise<number> {
    if (!await this.usable()) return 0
    try {
      const { rows } = await this.pool.query<{ n: string }>(
        'SELECT count(*)::text AS n FROM xdr_ingest_script WHERE project_id = $1',
        [this.projectId],
      )
      return Number(rows[0]?.n ?? 0)
    } catch (error) {
      console.error(`${LOG_PREFIX} script count failed:`, this.message(error))
      return 0
    }
  }

  async upsert(input: ScriptInput, nowIso?: string): Promise<AnalysisScript> {
    if (!await this.usable()) {
      throw new Error('脚本库不可用：PostgreSQL 未连接，保存失败（不要当作已保存）')
    }
    // created_at/updated_at 是 NOT NULL：调用方没给时间就用当前时间（测试/手工脚本会省）
    const stamp = (nowIso ?? '').trim() || new Date().toISOString()
    const name = input.name.trim()
    try {
      const { rows } = await this.pool.query<ScriptRow>(
        `INSERT INTO xdr_ingest_script
           (project_id, id, name, scenario, language, code, variables, tags, notes, source_task_id,
            usage_count, enabled, origin, updated_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, 0, $11, $12, $13, $14, $14)
         ON CONFLICT (project_id, name) DO UPDATE SET
           scenario = EXCLUDED.scenario,
           language = EXCLUDED.language,
           code = EXCLUDED.code,
           variables = EXCLUDED.variables,
           tags = EXCLUDED.tags,
           notes = EXCLUDED.notes,
           source_task_id = EXCLUDED.source_task_id,
           enabled = EXCLUDED.enabled,
           origin = EXCLUDED.origin,
           updated_by = EXCLUDED.updated_by,
           updated_at = EXCLUDED.updated_at
         RETURNING *`,
        [
          this.projectId, randomUUID(), name, input.scenario.trim(),
          (input.language ?? 'bash').trim() || 'bash', input.code,
          JSON.stringify(input.variables ?? {}), JSON.stringify(input.tags ?? []),
          (input.notes ?? '').trim(), (input.sourceTaskId ?? '').trim(),
          input.enabled ?? true, (input.origin ?? 'agent').trim() || 'agent',
          (input.updatedBy ?? '').trim(), stamp,
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
    const script = await this.getAny(nameOrId)
    return script !== null && script.enabled ? script : null
  }

  async getAny(nameOrId: string): Promise<AnalysisScript | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<ScriptRow>(
        'SELECT * FROM xdr_ingest_script WHERE project_id = $1'
        + ' AND (name = $2 OR id::text = $2) LIMIT 1',
        [this.projectId, nameOrId.trim()],
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
      const where: string[] = ['project_id = $1']
      const params: unknown[] = [this.projectId]
      if (query.enabledOnly ?? true) where.push('enabled')
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
         WHERE ${where.join(' AND ')}
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

  async list(query: { search: string; limit: number; offset: number }): Promise<{ total: number; items: AnalysisScript[] }> {
    if (!await this.usable()) return { total: 0, items: [] }
    const needle = query.search.trim()
    try {
      const params: unknown[] = [this.projectId]
      let where = 'project_id = $1'
      if (needle !== '') {
        params.push(`%${needle}%`)
        where += ` AND (name ILIKE $2 OR scenario ILIKE $2 OR notes ILIKE $2)`
      }
      const [{ rows }, { rows: countRows }] = await Promise.all([
        this.pool.query<ScriptRow>(
          `SELECT * FROM xdr_ingest_script WHERE ${where} ORDER BY updated_at DESC`
          + ` LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, Math.max(1, query.limit), Math.max(0, query.offset)],
        ),
        this.pool.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM xdr_ingest_script WHERE ${where}`,
          params,
        ),
      ])
      return { total: Number(countRows[0]?.n ?? 0), items: rows.map(toScript) }
    } catch (error) {
      console.error(`${LOG_PREFIX} script list failed:`, this.message(error))
      return { total: 0, items: [] }
    }
  }

  async setEnabled(nameOrId: string, enabled: boolean): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      const { rowCount } = await this.pool.query(
        'UPDATE xdr_ingest_script SET enabled = $1, updated_at = now()'
        + ' WHERE project_id = $2 AND (name = $3 OR id::text = $3)',
        [enabled, this.projectId, nameOrId.trim()],
      )
      return (rowCount ?? 0) > 0
    } catch (error) {
      console.error(`${LOG_PREFIX} script setEnabled failed:`, this.message(error))
      return false
    }
  }

  async remove(nameOrId: string): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      const { rowCount } = await this.pool.query(
        'DELETE FROM xdr_ingest_script WHERE project_id = $1 AND (name = $2 OR id::text = $2)',
        [this.projectId, nameOrId.trim()],
      )
      return (rowCount ?? 0) > 0
    } catch (error) {
      console.error(`${LOG_PREFIX} script remove failed:`, this.message(error))
      return false
    }
  }

  async bumpUsage(id: string, nowIso: string): Promise<void> {
    if (!await this.usable()) return
    try {
      await this.pool.query(
        'UPDATE xdr_ingest_script SET usage_count = usage_count + 1, last_used_at = $1'
        + ' WHERE project_id = $2 AND id = $3',
        [nowIso, this.projectId, id],
      )
    } catch (error) {
      console.error(`${LOG_PREFIX} script bumpUsage failed:`, this.message(error))
    }
  }

  /* ---------- 抑制记忆 ---------- */

  async recordTaskSeen(record: TaskSeenRecord): Promise<void> {
    if (!await this.usable()) return
    try {
      await this.pool.query(
        `INSERT INTO xdr_ingest_task_seen
           (project_id, identity_key, task_id, kind, subject_kind, subject, feature, verdict,
            created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
         ON CONFLICT (project_id, identity_key) DO UPDATE SET
           task_id = EXCLUDED.task_id,
           verdict = EXCLUDED.verdict,
           updated_at = now()`,
        [
          this.projectId, seenKey(record), record.taskId, record.kind, record.subjectKind,
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
        'UPDATE xdr_ingest_task_seen SET suppressed_by = $1, updated_at = now()'
        + ' WHERE project_id = $2 AND task_id = $3',
        [name, this.projectId, key],
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
        'UPDATE xdr_ingest_task_seen SET suppressed_by = $1, updated_at = now()'
        + ' WHERE project_id = $2 AND identity_key = $3',
        [name, this.projectId, seenKey(identity)],
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
         FROM xdr_ingest_task_seen WHERE project_id = $1 AND identity_key = $2`,
        [this.projectId, seenKey(identity)],
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

  /* ---------- 结论留档 ---------- */

  async saveConclusion(record: ConclusionRecord): Promise<void> {
    if (!await this.usable()) return
    try {
      await this.pool.query(
        `INSERT INTO xdr_ingest_conclusion
           (id, project_id, task_id, kind, subject_kind, subject, verdict, confidence, summary,
            findings, evidence_refs, tools_used, duration_ms, terminal_reason, reused, reused_from,
            created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12, $13, $14, $15, $16, $17)
         ON CONFLICT (id) DO UPDATE SET
           verdict = EXCLUDED.verdict,
           confidence = EXCLUDED.confidence,
           summary = EXCLUDED.summary,
           findings = EXCLUDED.findings,
           evidence_refs = EXCLUDED.evidence_refs,
           tools_used = EXCLUDED.tools_used,
           duration_ms = EXCLUDED.duration_ms,
           terminal_reason = EXCLUDED.terminal_reason,
           reused = EXCLUDED.reused,
           reused_from = EXCLUDED.reused_from`,
        [
          record.id, this.projectId, record.taskId, record.kind, record.subjectKind,
          record.subject, record.verdict, record.confidence, record.summary,
          JSON.stringify(record.findings ?? {}), JSON.stringify(record.evidenceRefs ?? []),
          record.toolsUsed, record.durationMs, record.terminalReason, record.reused,
          record.reusedFrom, record.createdAt || new Date().toISOString(),
        ],
      )
    } catch (error) {
      console.error(`${LOG_PREFIX} conclusion save failed:`, this.message(error))
    }
  }

  async listConclusions(query: ConclusionQuery): Promise<ConclusionPage> {
    if (!await this.usable()) return { total: 0, entries: [] }
    const needle = query.search.trim()
    try {
      const params: unknown[] = [this.projectId]
      let where = 'project_id = $1'
      if (needle !== '') {
        params.push(`%${needle}%`)
        where += ' AND (subject ILIKE $2 OR summary ILIKE $2 OR verdict ILIKE $2'
          + ' OR kind ILIKE $2 OR subject_kind ILIKE $2 OR task_id ILIKE $2)'
      }
      const [{ rows }, { rows: countRows }] = await Promise.all([
        this.pool.query<ConclusionRow>(
          `SELECT ${SELECT_CONCLUSION} FROM xdr_ingest_conclusion WHERE ${where}`
          + ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, Math.max(1, query.limit), Math.max(0, query.offset)],
        ),
        this.pool.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM xdr_ingest_conclusion WHERE ${where}`,
          params,
        ),
      ])
      return { total: Number(countRows[0]?.n ?? 0), entries: rows.map(toConclusion) }
    } catch (error) {
      console.error(`${LOG_PREFIX} conclusion list failed:`, this.message(error))
      return { total: 0, entries: [] }
    }
  }

  async getConclusion(id: string): Promise<ConclusionRecord | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<ConclusionRow>(
        `SELECT ${SELECT_CONCLUSION} FROM xdr_ingest_conclusion WHERE project_id = $1 AND id = $2`,
        [this.projectId, id.trim()],
      )
      const row = rows[0]
      return row === undefined ? null : toConclusion(row)
    } catch (error) {
      console.error(`${LOG_PREFIX} conclusion get failed:`, this.message(error))
      return null
    }
  }

  async countConclusions(): Promise<number> {
    if (!await this.usable()) return 0
    try {
      const { rows } = await this.pool.query<{ n: string }>(
        'SELECT count(*)::text AS n FROM xdr_ingest_conclusion WHERE project_id = $1',
        [this.projectId],
      )
      return Number(rows[0]?.n ?? 0)
    } catch (error) {
      console.error(`${LOG_PREFIX} conclusion count failed:`, this.message(error))
      return 0
    }
  }

  /* ---------- 运行参数 ---------- */

  async loadSettings(): Promise<RuntimeSettings | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<{ value: unknown }>(
        'SELECT value FROM xdr_ingest_settings WHERE project_id = $1',
        [this.projectId],
      )
      const value = rows[0]?.value
      return typeof value === 'object' && value !== null ? (value as RuntimeSettings) : null
    } catch (error) {
      console.error(`${LOG_PREFIX} settings load failed:`, this.message(error))
      return null
    }
  }

  async saveSettings(settings: RuntimeSettings): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      await this.pool.query(
        `INSERT INTO xdr_ingest_settings (project_id, value, updated_at)
         VALUES ($1, $2::jsonb, now())
         ON CONFLICT (project_id) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
        [this.projectId, JSON.stringify(settings)],
      )
      return true
    } catch (error) {
      console.error(`${LOG_PREFIX} settings save failed:`, this.message(error))
      return false
    }
  }

  /* ---------- 过程索引 ---------- */

  async startProcess(start: ProcessStart): Promise<void> {
    if (!await this.usable()) return
    try {
      await this.pool.query(
        `INSERT INTO xdr_ingest_process
           (project_id, task_id, session_id, kind, subject, model, started_at, outcome,
            workflow_id, workflow_name, workflow_stages)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'running', $8, $9, $10::jsonb)
         ON CONFLICT (project_id, task_id) DO UPDATE SET
           session_id = EXCLUDED.session_id,
           kind = EXCLUDED.kind,
           subject = EXCLUDED.subject,
           model = EXCLUDED.model,
           started_at = EXCLUDED.started_at,
           ended_at = NULL,
           outcome = 'running',
           workflow_id = EXCLUDED.workflow_id,
           workflow_name = EXCLUDED.workflow_name,
           workflow_stages = EXCLUDED.workflow_stages`,
        [
          this.projectId, start.taskId, start.sessionId, start.kind, start.subject, start.model,
          start.startedAt, start.workflowId ?? '', start.workflowName ?? '',
          JSON.stringify(start.workflowStages ?? []),
        ],
      )
    } catch (error) {
      console.error(`${LOG_PREFIX} process start failed:`, this.message(error))
    }
  }

  async finishProcess(finish: ProcessFinish): Promise<void> {
    if (!await this.usable()) return
    try {
      await this.pool.query(
        `INSERT INTO xdr_ingest_process
           (project_id, task_id, model, started_at, ended_at, outcome, tools_used, duration_ms, verdict, note)
         VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (project_id, task_id) DO UPDATE SET
           model = CASE WHEN EXCLUDED.model = '' THEN xdr_ingest_process.model
                        ELSE EXCLUDED.model END,
           ended_at = EXCLUDED.ended_at,
           outcome = EXCLUDED.outcome,
           tools_used = EXCLUDED.tools_used,
           duration_ms = EXCLUDED.duration_ms,
           verdict = EXCLUDED.verdict,
           note = EXCLUDED.note`,
        [
          this.projectId, finish.taskId, finish.model ?? '', finish.endedAt, finish.outcome,
          finish.toolsUsed ?? 0, finish.durationMs ?? 0, finish.verdict ?? '', finish.note ?? '',
        ],
      )
    } catch (error) {
      console.error(`${LOG_PREFIX} process finish failed:`, this.message(error))
    }
  }

  async listProcesses(query: { limit: number; offset: number; search: string; outcome: string }): Promise<{
    total: number
    items: ProcessRecord[]
  }> {
    if (!await this.usable()) return { total: 0, items: [] }
    const needle = query.search.trim()
    const outcome = query.outcome.trim()
    try {
      const params: unknown[] = [this.projectId]
      const where: string[] = ['project_id = $1']
      if (outcome !== '') {
        params.push(outcome)
        where.push(`outcome = $${params.length}`)
      }
      if (needle !== '') {
        params.push(`%${needle}%`)
        where.push(`(task_id ILIKE $${params.length} OR subject ILIKE $${params.length} OR kind ILIKE $${params.length})`)
      }
      const clause = where.join(' AND ')
      const [{ rows }, { rows: countRows }] = await Promise.all([
        this.pool.query<ProcessRow>(
          `SELECT * FROM xdr_ingest_process WHERE ${clause} ORDER BY started_at DESC`
          + ` LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, Math.max(1, query.limit), Math.max(0, query.offset)],
        ),
        this.pool.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM xdr_ingest_process WHERE ${clause}`,
          params,
        ),
      ])
      return { total: Number(countRows[0]?.n ?? 0), items: rows.map(toProcess) }
    } catch (error) {
      console.error(`${LOG_PREFIX} process list failed:`, this.message(error))
      return { total: 0, items: [] }
    }
  }

  async getProcess(taskId: string): Promise<ProcessRecord | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<ProcessRow>(
        'SELECT * FROM xdr_ingest_process WHERE project_id = $1 AND task_id = $2',
        [this.projectId, taskId.trim()],
      )
      const row = rows[0]
      return row === undefined ? null : toProcess(row)
    } catch (error) {
      console.error(`${LOG_PREFIX} process get failed:`, this.message(error))
      return null
    }
  }

  /**
   * 保留期清理（跨项目；由维护定时器调用）。
   * 只 DELETE 有明确保留期的表，不碰脚本/设置/项目/工作流。
   */
  async maintenance(policy: {
    conclusionsDays: number, processesDays: number, observationsDays: number,
    egressDays: number, taskSeenDays: number,
  }): Promise<Record<string, number>> {
    if (!await this.usable()) return {}
    const job = async (sql: string, days: number): Promise<number> => {
      try {
        const { rowCount } = await this.pool.query(sql, [Math.max(1, Math.floor(days))])
        return rowCount ?? 0
      } catch (error) {
        console.error(`${LOG_PREFIX} maintenance failed:`, this.message(error))
        return 0
      }
    }
    return {
      conclusions: await job(
        "DELETE FROM xdr_ingest_conclusion WHERE created_at < now() - ($1 || ' days')::interval",
        policy.conclusionsDays,
      ),
      processes: await job(
        "DELETE FROM xdr_ingest_process WHERE started_at < now() - ($1 || ' days')::interval",
        policy.processesDays,
      ),
      observations: await job(
        "DELETE FROM xdr_ingest_observation WHERE last_seen < now() - ($1 || ' days')::interval",
        policy.observationsDays,
      ),
      egress: await job(
        "DELETE FROM xdr_ingest_egress_baseline WHERE last_seen < now() - ($1 || ' days')::interval",
        policy.egressDays,
      ),
      task_seen: await job(
        "DELETE FROM xdr_ingest_task_seen WHERE updated_at < now() - ($1 || ' days')::interval",
        policy.taskSeenDays,
      ),
    }
  }

  /* ---------- 工作流模版（全局，不按项目过滤） ---------- */

  async listWorkflows(): Promise<WorkflowRecord[]> {
    if (!await this.usable()) return []
    try {
      const { rows } = await this.pool.query<WorkflowRow>(
        'SELECT * FROM xdr_ingest_workflow ORDER BY is_default DESC, updated_at DESC',
      )
      return rows.map(toWorkflow)
    } catch (error) {
      console.error(`${LOG_PREFIX} workflow list failed:`, this.message(error))
      return []
    }
  }

  async getWorkflow(workflowId: string): Promise<WorkflowRecord | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<WorkflowRow>(
        'SELECT * FROM xdr_ingest_workflow WHERE workflow_id = $1',
        [workflowId.trim()],
      )
      const row = rows[0]
      return row === undefined ? null : toWorkflow(row)
    } catch (error) {
      console.error(`${LOG_PREFIX} workflow get failed:`, this.message(error))
      return null
    }
  }

  async upsertWorkflow(input: WorkflowInput, nowIso: string): Promise<WorkflowRecord> {
    if (!await this.usable()) throw new Error('state store unavailable')
    const fallbackId = `wf-${randomUUID().slice(0, 8)}`
    const workflowId = input.isDefault === true ? 'default' : (input as { workflowId?: string }).workflowId?.trim() || fallbackId
    const { rows } = await this.pool.query<WorkflowRow>(
      `INSERT INTO xdr_ingest_workflow
         (workflow_id, name, description, stages, enabled, is_default, updated_at, updated_by)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, 'console')
       ON CONFLICT (workflow_id) DO UPDATE SET
         name = EXCLUDED.name,
         description = EXCLUDED.description,
         stages = EXCLUDED.stages,
         enabled = EXCLUDED.enabled,
         is_default = EXCLUDED.is_default,
         updated_at = EXCLUDED.updated_at
       RETURNING *`,
      [
        workflowId, input.name.trim(), (input.description ?? '').trim(),
        JSON.stringify(input.stages ?? []), input.enabled ?? true, input.isDefault === true, nowIso,
      ],
    )
    return toWorkflow(rows[0] as WorkflowRow)
  }

  async setWorkflowEnabled(workflowId: string, enabled: boolean): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      const { rowCount } = await this.pool.query(
        'UPDATE xdr_ingest_workflow SET enabled = $1, updated_at = now() WHERE workflow_id = $2',
        [enabled, workflowId.trim()],
      )
      return (rowCount ?? 0) > 0
    } catch (error) {
      console.error(`${LOG_PREFIX} workflow toggle failed:`, this.message(error))
      return false
    }
  }

  async removeWorkflow(workflowId: string): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      const { rowCount } = await this.pool.query(
        'DELETE FROM xdr_ingest_workflow WHERE workflow_id = $1',
        [workflowId.trim()],
      )
      return (rowCount ?? 0) > 0
    } catch (error) {
      console.error(`${LOG_PREFIX} workflow remove failed:`, this.message(error))
      return false
    }
  }

  /* ---------- 项目组织（不按实例项目过滤：跨项目读写） ---------- */

  async listProjects(): Promise<ProjectRecord[]> {
    if (!await this.usable()) return []
    try {
      const { rows } = await this.pool.query<ProjectRow>(
        'SELECT * FROM xdr_ingest_project ORDER BY created_at ASC',
      )
      return rows.map(toProject)
    } catch (error) {
      console.error(`${LOG_PREFIX} project list failed:`, this.message(error))
      return []
    }
  }

  async getProject(projectId: string): Promise<ProjectRecord | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<ProjectRow>(
        'SELECT * FROM xdr_ingest_project WHERE project_id = $1',
        [projectId.trim()],
      )
      const row = rows[0]
      return row === undefined ? null : toProject(row)
    } catch (error) {
      console.error(`${LOG_PREFIX} project get failed:`, this.message(error))
      return null
    }
  }

  async upsertProject(input: ProjectInput): Promise<ProjectRecord | null> {
    if (!await this.usable()) return null
    try {
      const { rows } = await this.pool.query<ProjectRow>(
        `INSERT INTO xdr_ingest_project
           (project_id, name, mcp_url, mcp_token, push_token, enabled, workflow_id, model,
          fallback_model, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
         ON CONFLICT (project_id) DO UPDATE SET
           name = EXCLUDED.name,
           mcp_url = EXCLUDED.mcp_url,
           mcp_token = EXCLUDED.mcp_token,
           push_token = EXCLUDED.push_token,
           enabled = EXCLUDED.enabled,
           workflow_id = CASE WHEN EXCLUDED.workflow_id = '' THEN xdr_ingest_project.workflow_id
                              ELSE EXCLUDED.workflow_id END,
           -- 不传模型（空串）时保留已有配置：迁移脚本/老控制台不会把模型清空
           model = CASE WHEN EXCLUDED.model = '' THEN xdr_ingest_project.model
                        ELSE EXCLUDED.model END,
           fallback_model = CASE WHEN EXCLUDED.fallback_model = '' THEN xdr_ingest_project.fallback_model
                                 ELSE EXCLUDED.fallback_model END,
           updated_at = now()
         RETURNING *`,
        [
          input.projectId.trim(), input.name.trim(), input.mcpUrl.trim(), input.mcpToken,
          input.pushToken, input.enabled ?? true, String(input.workflowId ?? '').trim(),
          String(input.model ?? '').trim(), String(input.fallbackModel ?? '').trim(),
        ],
      )
      const row = rows[0]
      return row === undefined ? null : toProject(row)
    } catch (error) {
      console.error(`${LOG_PREFIX} project upsert failed:`, this.message(error))
      return null
    }
  }

  async setProjectStatus(projectId: string, status: ProjectStatus, detail: string): Promise<void> {
    if (!await this.usable()) return
    try {
      await this.pool.query(
        `UPDATE xdr_ingest_project
         SET status = $1, status_detail = $2, last_checked_at = now(), updated_at = now()
         WHERE project_id = $3`,
        [status, detail.slice(0, 500), projectId.trim()],
      )
    } catch (error) {
      console.error(`${LOG_PREFIX} project status failed:`, this.message(error))
    }
  }

  async setProjectWorkflow(projectId: string, workflowId: string): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      const { rowCount } = await this.pool.query(
        'UPDATE xdr_ingest_project SET workflow_id = $1, updated_at = now() WHERE project_id = $2',
        [workflowId.trim(), projectId.trim()],
      )
      return (rowCount ?? 0) > 0
    } catch (error) {
      console.error(`${LOG_PREFIX} project workflow failed:`, this.message(error))
      return false
    }
  }

  async removeProject(projectId: string): Promise<boolean> {
    if (!await this.usable()) return false
    try {
      const { rowCount } = await this.pool.query(
        'DELETE FROM xdr_ingest_project WHERE project_id = $1',
        [projectId.trim()],
      )
      return (rowCount ?? 0) > 0
    } catch (error) {
      console.error(`${LOG_PREFIX} project remove failed:`, this.message(error))
      return false
    }
  }

  async ping(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1')
      return true
    } catch {
      return false
    }
  }

  async close(): Promise<void> {
    await this.pool.end().catch(() => undefined)
  }

  private message(error: unknown): string {
    return error instanceof Error ? error.message : String(error)
  }
}

