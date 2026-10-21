/**
 * PostgreSQL 冷库集成测试：需要真实 PG。
 * 设置 XDR_TEST_PG_URL（如 postgresql://shentong:shentong@127.0.0.1:5432/shentong）
 * 后运行；未设置时整体跳过（CI 的 agent-plugins job 通过 service 容器提供）。
 *
 * pg 依赖用动态 import：无 PG 的本地环境连模块都不会加载。
 */

import { strict as assert } from 'node:assert'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'
import type { ColdEntry } from '../src/store.ts'
import type { EventIdentity } from '../src/types.ts'

const PG_URL = process.env.XDR_TEST_PG_URL ?? ''
const withPg = PG_URL !== ''

const identity: EventIdentity = {
  rule: 'integration-rule',
  srcIp: '203.0.113.9',
  dstIps: ['10.0.0.9'],
  dstPorts: ['443'],
  eventTypes: ['alert'],
}

function entry(analysisId: string, occurrences: number, expiresAt: string): ColdEntry {
  return {
    analysisId,
    identity,
    result: {
      category: 'generic-alert',
      severity: 'medium',
      summary: `pg summary ${analysisId}`,
      recommendation: 'review',
      analyzer: 'heuristic-v0',
    },
    occurrences,
    firstSeenAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    analyzedAt: new Date().toISOString(),
    expiresAt,
    deliveries: [],
  }
}

test('postgres cold store: schema self-init, upsert/load/hit/warmup/prune round-trip', { skip: !withPg }, async () => {
  const { PostgresColdStore } = await import('../src/pg-store.ts')
  const store = new PostgresColdStore({ connectionString: PG_URL })
  try {
    const id = `EA-it-${randomUUID()}`
    const future = new Date(Date.now() + 3_600_000).toISOString()

    assert.equal(await store.load(id), null, 'unknown id loads as null')
    await store.upsert(entry(id, 1, future))

    const loaded = await store.load(id)
    assert.equal(loaded?.occurrences, 1)
    assert.equal(loaded?.result.summary, `pg summary ${id}`)
    assert.equal(loaded?.identity.srcIp, '203.0.113.9')

    assert.equal(await store.recordHit(id, Date.now()), 2)
    assert.equal((await store.load(id))?.occurrences, 2)

    const warmed = await store.warmup(10)
    assert.ok(warmed.some(item => item.analysisId === id), 'fresh row appears in warmup')

    assert.ok((await store.count()) >= 1)
    assert.equal(await store.pruneExpired(Date.now()), 0, 'fresh row survives prune')
  } finally {
    await store.close()
  }
})

test('postgres cold store: expired row is prunable', { skip: !withPg }, async () => {
  const { PostgresColdStore } = await import('../src/pg-store.ts')
  const store = new PostgresColdStore({ connectionString: PG_URL })
  try {
    const id = `EA-it-expired-${randomUUID()}`
    await store.upsert(entry(id, 1, new Date(Date.now() - 60_000).toISOString()))
    assert.equal(await store.pruneExpired(Date.now()), 1)
    assert.equal(await store.load(id), null)
  } finally {
    await store.close()
  }
})

test('postgres cold store: unreachable dsn degrades instead of throwing', { skip: !withPg }, async () => {
  const { PostgresColdStore } = await import('../src/pg-store.ts')
  const store = new PostgresColdStore({
    connectionString: 'postgresql://shentong:shentong@127.0.0.1:1/nope',
  })
  try {
    assert.equal(await store.load('EA-any'), null, 'load degrades to null')
    await store.upsert(entry('EA-any', 1, new Date(Date.now() + 3_600_000).toISOString()))
    assert.equal(await store.recordHit('EA-any', Date.now()), null)
    assert.equal(await store.count(), 0)
    assert.equal(await store.pruneExpired(Date.now()), 0)
    assert.deepEqual(await store.warmup(10), [])
  } finally {
    await store.close()
  }
})
