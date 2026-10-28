/**
 * PostgreSQL 版智能体记忆集成测试：需要真实 PG（`XDR_TEST_PG_URL`），
 * CI 的 agent-plugins job 提供 service 容器；本地未设置时整体跳过。
 *
 * `pg` 依赖用动态 import：无 PG 的本地环境连模块都不会加载。
 */

import { strict as assert } from 'node:assert'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

const PG_URL = process.env.XDR_TEST_PG_URL ?? ''
const withPg = PG_URL !== ''

test('postgres state: task results round-trip and prune', { skip: !withPg }, async () => {
  const { PostgresStateStore } = await import('../src/pg-state-store.ts')
  const store = new PostgresStateStore({ connectionString: PG_URL, projectId: 'TESTPROJ' })
  try {
    const key = `TR-it-${randomUUID()}`
    const now = new Date()
    assert.equal(await store.load(key), null)
    assert.equal(await store.save({
      key,
      kind: 'hit',
      subjectKind: 'ip',
      subject: '203.0.113.9',
      feature: 'sid:1',
      taskId: 'task-it',
      verdict: 'false_positive',
      terminalReason: 'concluded',
      confidence: 0.9,
      summary: '集成测试',
      strength: 0.6,
      occurrences: 1,
      analyzedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    }), true)

    const loaded = await store.load(key)
    assert.equal(loaded?.verdict, 'false_positive')
    assert.equal(loaded?.confidence, 0.9)
    assert.equal(await store.bump(key, now.toISOString(), 'task-it-2'), true)
    assert.equal((await store.load(key))?.occurrences, 2)
    assert.ok(await store.count() >= 1)
    assert.equal(await store.prune(new Date(now.getTime() + 7_200_000).toISOString()), 1)
    assert.equal(await store.load(key), null)
  } finally {
    await store.close()
  }
})

test('postgres state: scripts upsert/find/bump usage', { skip: !withPg }, async () => {
  const { PostgresStateStore } = await import('../src/pg-state-store.ts')
  const store = new PostgresStateStore({ connectionString: PG_URL, projectId: 'TESTPROJ' })
  const name = `it_script_${randomUUID().slice(0, 8)}`
  try {
    const first = await store.upsert({
      name,
      scenario: '集成测试：按源 IP 聚合连接状态',
      code: 'echo one',
      language: 'bash',
      variables: { SRC: '源 IP' },
      tags: ['it-conn'],
      notes: '测试数据',
    }, new Date().toISOString())
    assert.equal(first.name, name)

    const byName = await store.get(name)
    assert.equal(byName?.code, 'echo one')
    assert.deepEqual(byName?.variables, { SRC: '源 IP' })

    const found = await store.find({ query: '连接状态', tag: 'it-conn', limit: 5 })
    assert.ok(found.some(item => item.name === name))

    await store.bumpUsage(first.id, new Date().toISOString())
    const second = await store.upsert({
      name,
      scenario: '集成测试：按源 IP 聚合连接状态（v2）',
      code: 'echo two',
      tags: ['it-conn'],
    }, new Date().toISOString())
    assert.equal(second.id, first.id, '同名覆盖保留 id')
    assert.equal(second.usageCount, 1, '覆盖不清空使用次数')
    assert.equal(second.code, 'echo two')
    assert.ok(await store.countScripts() >= 1)
  } finally {
    await store.close()
  }
})

test('postgres state: unreachable dsn degrades on reads', { skip: !withPg }, async () => {
  const { PostgresStateStore } = await import('../src/pg-state-store.ts')
  const store = new PostgresStateStore({
    connectionString: 'postgresql://shentong:shentong@127.0.0.1:1/nope',
    projectId: 'TESTPROJ',
  })
  try {
    assert.equal(await store.load('TR-any'), null)
    assert.deepEqual(await store.find({ query: '', tag: '', limit: 5 }), [])
    assert.equal(await store.count(), 0)
    assert.equal(await store.countScripts(), 0)
  } finally {
    await store.close()
  }
})


/**
 * 项目隔离：同一张表里两个项目的数据互不可见。
 *
 * 这是多项目的前提 —— 一台 agent 接多台 NDR 时，脚本/结论/复用/抑制记忆
 * 绝不能因为忘记带 project_id 而串到别人项目里。
 */
test('postgres state: projects are isolated', { skip: !withPg }, async () => {
  const { PostgresStateStore } = await import('../src/pg-state-store.ts')
  const a = new PostgresStateStore({ connectionString: PG_URL, projectId: 'PROJA' })
  const b = new PostgresStateStore({ connectionString: PG_URL, projectId: 'PROJB' })
  try {
    const key = `TR-iso-${randomUUID()}`
    const now = new Date()
    await a.save({
      key, kind: 'hit', subjectKind: 'ip', subject: '203.0.113.10', feature: 'sid:9',
      taskId: 'task-a', verdict: 'benign', terminalReason: 'concluded', confidence: 0.5,
      summary: 'A 项目', strength: 0.3, occurrences: 1,
      analyzedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    })
    assert.notEqual(await a.load(key), null)
    assert.equal(await b.load(key), null, 'B 项目不能看到 A 项目的复用结论')

    // 同名脚本在两个项目里是两条独立记录
    const name = `iso_${randomUUID().slice(0, 8)}`
    await a.upsert({ name, scenario: 'A 的场景', code: 'echo a' })
    await b.upsert({ name, scenario: 'B 的场景', code: 'echo b' })
    assert.equal((await a.find({ query: name, tag: '', limit: 5 }))[0]?.code, 'echo a')
    assert.equal((await b.find({ query: name, tag: '', limit: 5 }))[0]?.code, 'echo b')
  } finally {
    await a.close()
    await b.close()
  }
})

test('postgres state: conclusions + process index round-trip', { skip: !withPg }, async () => {
  const { PostgresStateStore } = await import('../src/pg-state-store.ts')
  const store = new PostgresStateStore({ connectionString: PG_URL, projectId: 'PROJC' })
  const taskId = `task-${randomUUID()}`
  try {
    await store.saveConclusion({
      id: `${taskId}-r`, taskId, kind: 'hit', subjectKind: 'ip', subject: '203.0.113.11',
      verdict: 'suspicious', confidence: 0.7, summary: '可疑', findings: { k: 'v' },
      evidenceRefs: ['es:idx/1'], toolsUsed: 12, durationMs: 4200, reused: false,
      reusedFrom: '', terminalReason: 'concluded', createdAt: new Date().toISOString(),
    })
    const one = await store.getConclusion(`${taskId}-r`)
    assert.equal(one?.verdict, 'suspicious')
    assert.deepEqual(one?.evidenceRefs, ['es:idx/1'])
    assert.ok(await store.countConclusions() >= 1)

    await store.startProcess({
      taskId, sessionId: 'xdr-analysis-x', kind: 'hit', subject: '203.0.113.11',
      model: 'p/m', startedAt: new Date().toISOString(),
    })
    assert.equal((await store.getProcess(taskId))?.outcome, 'running')
    await store.finishProcess({ taskId, endedAt: new Date().toISOString(), outcome: 'done', toolsUsed: 12, durationMs: 4200, verdict: 'suspicious' })
    const proc = await store.getProcess(taskId)
    assert.equal(proc?.outcome, 'done')
    assert.equal(proc?.sessionId, 'xdr-analysis-x')
    const page = await store.listProcesses({ limit: 10, offset: 0, search: subjectOf(taskId), outcome: '' })
    assert.ok(page.items.some(item => item.taskId === taskId))
  } finally {
    await store.close()
  }
})

function subjectOf(taskId: string): string {
  return taskId
}
