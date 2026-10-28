/**
 * 结论只读面（控制台「分析记录」的数据源）。
 *
 * 内存实现永远是"没有结论"（没有 PG 时的兜底）；PostgreSQL 实现要真 PG
 * （`XDR_TEST_PG_URL`），CI 的 agent-plugins job 提供 service 容器；
 * 本地未设置时整体跳过。
 *
 * `pg` 依赖用动态 import：无 PG 的本地环境连模块都不会加载。
 */

import { strict as assert } from 'node:assert'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

const PG_URL = process.env.XDR_TEST_PG_URL ?? ''
const withPg = PG_URL !== ''

test('内存结论面：永远空、永远不可用（页面照常打开，只是数据区空）', async () => {
  const { MemoryConclusionReader } = await import('../src/conclusions.ts')
  const reader = new MemoryConclusionReader()
  assert.equal(reader.available(), false)
  assert.equal(await reader.ready(), false)
  const page = await reader.listRecent({ limit: 10, offset: 0, search: '' })
  assert.equal(page.total, 0)
  assert.deepEqual(page.entries, [])
  assert.equal(await reader.get('anything'), null)
  assert.equal(await reader.count(), 0)
  await reader.close()
})

test('postgres 结论面：列表 / 详情 / 搜索 / 计数', { skip: !withPg }, async () => {
  const { Pool } = await import('pg')
  const { PostgresConclusionReader } = await import('../src/pg-conclusions.ts')
  const pool = new Pool({ connectionString: PG_URL })
  // 表是 NDR 侧的（结论由 complete_task 写）；测试库里按同样的列建一份。
  await pool.query(`CREATE TABLE IF NOT EXISTS analysis_results (
    id UUID PRIMARY KEY,
    task_id TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT '',
    subject_kind TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL DEFAULT '',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    findings JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    tools_used INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    terminal_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`)
  const id = randomUUID()
  const subject = `198.51.100.${Math.floor(Math.random() * 200) + 1}`
  await pool.query(
    `INSERT INTO analysis_results
       (id, task_id, kind, subject_kind, subject, verdict, confidence, summary, findings,
        evidence_refs, tools_used, duration_ms, terminal_reason, created_at)
     VALUES ($1, $2, 'hit', 'ip', $3, 'false_positive', 0.86, $4, $5::jsonb, $6::jsonb, 12, 4200, 'concluded', now())`,
    [id, 'task-it', subject, '集成测试：误报', JSON.stringify({ residual: '无' }), JSON.stringify(['es:/ev:1'])],
  )
  const reader = new PostgresConclusionReader({ connectionString: PG_URL })
  try {
    // 探表是异步的：先等它落定，再看可用性
    assert.equal(await reader.ready(), true)
    assert.equal(reader.available(), true)
    const all = await reader.listRecent({ limit: 50, offset: 0, search: '' })
    assert.ok(all.total >= 1, '表里刚插的结论应该能被列出来')
    const hit = all.entries.find(entry => entry.id === id)
    assert.ok(hit !== undefined, '刚插入的结论要在列表里')
    assert.equal(hit?.verdict, 'false_positive')
    assert.equal(hit?.subject, subject)
    assert.equal(hit?.toolsUsed, 12)
    assert.equal(hit?.durationMs, 4200)
    assert.equal(hit?.terminalReason, 'concluded')
    assert.equal(hit?.confidence, 0.86)
    assert.deepEqual(hit?.evidenceRefs, ['es:/ev:1'])
    assert.equal((hit?.findings as { residual?: string }).residual, '无')

    // 搜索：按对象 / 判定 / 摘要都能命中
    const bySubject = await reader.listRecent({ limit: 10, offset: 0, search: subject })
    assert.ok(bySubject.entries.some(entry => entry.id === id))
    const byVerdict = await reader.listRecent({ limit: 10, offset: 0, search: 'false_positive' })
    assert.ok(byVerdict.entries.some(entry => entry.id === id))
    const byNothing = await reader.listRecent({ limit: 10, offset: 0, search: '查无此结论-xyz' })
    assert.equal(byNothing.total, 0)

    // 详情与计数
    const one = await reader.get(id)
    assert.equal(one?.taskId, 'task-it')
    assert.equal(one?.kind, 'hit')
    assert.equal(await reader.get(randomUUID()), null)
    assert.ok(await reader.count() >= 1)
  } finally {
    await pool.query('DELETE FROM analysis_results WHERE id = $1', [id])
    await reader.close()
    await pool.end()
  }
})
