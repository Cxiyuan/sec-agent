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
  const store = new PostgresStateStore({ connectionString: PG_URL })
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
  const store = new PostgresStateStore({ connectionString: PG_URL })
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
