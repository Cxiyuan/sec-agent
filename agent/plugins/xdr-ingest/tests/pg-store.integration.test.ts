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

test('postgres cold store: listRecent orders, filters and paginates', { skip: !withPg }, async () => {
  const { PostgresColdStore } = await import('../src/pg-store.ts')
  const store = new PostgresColdStore({ connectionString: PG_URL })
  try {
    const base = randomUUID()
    const a = `EA-it-${base}-a`
    const b = `EA-it-${base}-b`
    const expired = `EA-it-${base}-expired`
    await store.upsert({ ...entry(a, 1, new Date(Date.now() + 3_600_000).toISOString()), lastSeenAt: '2026-10-20T00:00:00.000Z' })
    await store.upsert({ ...entry(b, 1, new Date(Date.now() + 3_600_000).toISOString()), lastSeenAt: '2026-10-22T00:00:00.000Z' })
    // 过期行也要出现在列表（过期 = 待重分析，不是删除）
    await store.upsert({ ...entry(expired, 1, '2000-01-01T00:00:00.000Z'), lastSeenAt: '2026-10-21T00:00:00.000Z' })

    // 降序：b (10-22) > expired (10-21) > a (10-20)
    const page = await store.listRecent({ limit: 10, offset: 0, search: base })
    assert.deepEqual(page.entries.map(item => item.analysisId), [b, expired, a])
    assert.equal(page.total, 3)

    // 分页与总数（total 不随页缩）
    const second = await store.listRecent({ limit: 1, offset: 1, search: base })
    assert.equal(second.total, 3)
    assert.equal(second.entries[0]?.analysisId, expired)

    // 搜索大写不敏感（ILIKE）
    const byUpper = await store.listRecent({ limit: 10, offset: 0, search: `EA-IT-${base.toUpperCase()}-A` })
    assert.equal(byUpper.total, 1)
    assert.equal(byUpper.entries[0]?.analysisId, a)

    // 深翻页越过末尾：entries 为空但 total 仍准确（补 count 的分支）
    const beyond = await store.listRecent({ limit: 10, offset: 100, search: base })
    assert.equal(beyond.total, 3)
    assert.deepEqual(beyond.entries, [])
  } finally {
    await store.close()
  }
})
