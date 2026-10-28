#!/usr/bin/env node
/**
 * 一次性迁移：把「智能体数据从 NDR 的 PG 搬到智能体自己的 PG」并打上项目ID。
 *
 * 背景（P1）：agent 以前把结论复用/脚本/设置直接写在 NDR 的库里（统一 PG）。
 * 多项目后每个 NDR 一套库，控制台跨库读不可持续 —— 改成 agent 自建一套 PG，
 * 所有表带 `project_id`（= NDR 授权ID），现有数据归到指定项目（默认"南充职业技术学院"）。
 *
 * 用法（在 agent 容器里跑，库地址用容器内可解析的主机名）：
 *   SOURCE_PG_URL=postgresql://shentong:shentong@host.docker.internal:5432/shentong \
 *   TARGET_PG_URL=postgresql://shentong:shentong@postgres:5432/shentong \
 *   PROJECT_ID=<NDR 授权ID> PROJECT_NAME='南充职业技术学院' \
 *   node /tmp/migrate-project.mjs
 *
 * 幂等：重复跑不会插重（复用键/结论 ID/脚本名都有唯一约束，走 ON CONFLICT）。
 * 只搬数据，不改源库（源库保留，作为 NDR 自己的 analysis_results 数据源）。
 */

import { createRequire } from 'node:module'

const SOURCE = process.env.SOURCE_PG_URL ?? ''
const TARGET = process.env.TARGET_PG_URL ?? ''
const PROJECT_ID = (process.env.PROJECT_ID ?? '').trim().toUpperCase()
const PROJECT_NAME = (process.env.PROJECT_NAME ?? '').trim() || '默认项目'

if (SOURCE === '' || TARGET === '' || PROJECT_ID === '') {
  console.error('需要 SOURCE_PG_URL / TARGET_PG_URL / PROJECT_ID 三个环境变量')
  process.exit(2)
}

// 用插件自己的 store 建表（schema 与线上完全一致，不另抄一份 DDL）
const lib = await import('/opt/agent/plugins/xdr-ingest/lib/pg-state-store.js')
// `pg` 按插件目录解析（脚本本身在 /tmp，裸导入会找不到）
const requireFromPlugin = createRequire('/opt/agent/plugins/xdr-ingest/lib/pg-state-store.js')
const pg = requireFromPlugin('pg')
const source = new pg.Pool({ connectionString: SOURCE, max: 2 })
const target = new lib.PostgresStateStore({ connectionString: TARGET, projectId: PROJECT_ID })

const stats = { taskResults: 0, scripts: 0, settings: 0, conclusions: 0, projects: 0 }

function say(stage, n) {
  console.log(`[migrate] ${stage}: ${n}`)
}

try {
  // 1) 项目行（名字沿用配置）
  const existing = await target.getProject(PROJECT_ID)
  await target.upsertProject({
    projectId: PROJECT_ID,
    name: (existing?.name ?? '').trim() || PROJECT_NAME,
    mcpUrl: existing?.mcpUrl ?? '',
    mcpToken: existing?.mcpToken ?? '',
    pushToken: existing?.pushToken ?? '',
    enabled: true,
  })
  stats.projects += 1

  // 2) 结论复用（旧库 xdr_ingest_task_result）
  const { rows: reuseRows } = await source.query(
    'SELECT * FROM xdr_ingest_task_result',
  ).catch(() => ({ rows: [] }))
  for (const row of reuseRows) {
    const saved = await target.save({
      key: String(row.reuse_key),
      kind: String(row.kind ?? ''),
      subjectKind: String(row.subject_kind ?? ''),
      subject: String(row.subject ?? ''),
      feature: String(row.feature ?? ''),
      taskId: String(row.task_id ?? ''),
      verdict: String(row.verdict ?? ''),
      terminalReason: String(row.terminal_reason ?? ''),
      confidence: Number(row.confidence ?? 0),
      summary: String(row.summary ?? ''),
      strength: Number(row.strength ?? 0),
      occurrences: Number(row.occurrences ?? 1),
      analyzedAt: new Date(row.analyzed_at).toISOString(),
      expiresAt: new Date(row.expires_at).toISOString(),
    })
    if (saved) stats.taskResults += 1
  }
  say('复用结论', stats.taskResults)

  // 3) 脚本库（旧库 xdr_ingest_script；表可能不存在）
  const { rows: scriptRows } = await source.query(
    'SELECT * FROM xdr_ingest_script',
  ).catch(() => ({ rows: [] }))
  for (const row of scriptRows) {
    await target.upsert({
      name: String(row.name ?? ''),
      scenario: String(row.scenario ?? ''),
      code: String(row.code ?? ''),
      language: String(row.language ?? 'bash'),
      variables: row.variables ?? {},
      tags: Array.isArray(row.tags) ? row.tags.map(String) : [],
      notes: String(row.notes ?? ''),
      sourceTaskId: String(row.source_task_id ?? ''),
      origin: String(row.origin ?? 'agent'),
      updatedBy: String(row.updated_by ?? ''),
    }, new Date(row.updated_at ?? Date.now()).toISOString())
    stats.scripts += 1
  }
  say('脚本', stats.scripts)

  // 4) 运行参数（旧库 xdr_ingest_settings 是单行 JSONB：{"value": {...}}）
  try {
    const { rows } = await source.query('SELECT value FROM xdr_ingest_settings WHERE singleton')
    const raw = rows[0]?.value
    const value = raw && typeof raw === 'object' && 'value' in raw ? raw.value : raw
    if (value && typeof value === 'object') {
      const settings = {
        pollSeconds: Number(value.pollSeconds ?? value.poll_seconds ?? 300),
        maxConcurrent: Number(value.maxConcurrent ?? value.max_concurrent ?? 2),
        claimLimit: Number(value.claimLimit ?? value.claim_limit ?? 2),
      }
      if (await target.saveSettings(settings)) stats.settings += 1
    }
  } catch {
    // 旧表不存在/格式不同都不影响主迁移
  }
  say('运行参数', stats.settings)

  // 5) 结论留档：NDR 的 analysis_results → 智能体自己的 xdr_ingest_conclusion
  const { rows: resultRows } = await source.query(
    `SELECT id, task_id, kind, subject_kind, subject, verdict, confidence, summary, findings,
            evidence_refs, tools_used, duration_ms, terminal_reason, created_at
     FROM analysis_results ORDER BY created_at ASC`,
  ).catch(() => ({ rows: [] }))
  for (const row of resultRows) {
    const findings = row.findings && typeof row.findings === 'object' ? row.findings : {}
    const reusedFrom = String(findings?.reused_from ?? '')
    await target.saveConclusion({
      id: String(row.id),
      taskId: String(row.task_id ?? ''),
      kind: String(row.kind ?? ''),
      subjectKind: String(row.subject_kind ?? ''),
      subject: String(row.subject ?? ''),
      verdict: String(row.verdict ?? ''),
      confidence: Number(row.confidence ?? 0),
      summary: String(row.summary ?? ''),
      findings,
      evidenceRefs: Array.isArray(row.evidence_refs) ? row.evidence_refs.map(String) : [],
      toolsUsed: Number(row.tools_used ?? 0),
      durationMs: Number(row.duration_ms ?? 0),
      reused: reusedFrom !== '',
      reusedFrom,
      terminalReason: String(row.terminal_reason ?? ''),
      createdAt: new Date(row.created_at).toISOString(),
    })
    stats.conclusions += 1
  }
  say('结论留档', stats.conclusions)

  console.log('[migrate] 完成：', JSON.stringify(stats))
} finally {
  await source.end().catch(() => undefined)
  await target.close()
}
