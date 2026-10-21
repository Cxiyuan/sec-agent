/** 冷存储（内存实现）语义测试：upsert / 命中计数 / 清理 / 预热排序。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { MemoryColdStore } from '../src/store.ts'
import type { ColdEntry } from '../src/store.ts'
import type { EventIdentity } from '../src/types.ts'

const identity: EventIdentity = {
  rule: 'rule-a',
  srcIp: '10.0.0.1',
  dstIps: ['10.0.0.2'],
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
      summary: `summary ${analysisId}`,
      recommendation: 'review',
      analyzer: 'heuristic-v0',
    },
    occurrences,
    firstSeenAt: '2026-10-21T00:00:00.000Z',
    lastSeenAt: '2026-10-21T00:10:00.000Z',
    analyzedAt: '2026-10-21T00:10:00.000Z',
    expiresAt,
    deliveries: [],
  }
}

test('upsert then load round-trips the record', async () => {
  const store = new MemoryColdStore()
  await store.upsert(entry('EA-a', 1, '2026-10-22T00:00:00.000Z'))
  const loaded = await store.load('EA-a')
  assert.equal(loaded?.occurrences, 1)
  assert.equal(loaded?.result.summary, 'summary EA-a')
  assert.equal(await store.count(), 1)
})

test('recordHit increments occurrences and moves lastSeen', async () => {
  const store = new MemoryColdStore()
  await store.upsert(entry('EA-a', 1, '2026-10-22T00:00:00.000Z'))
  const after = await store.recordHit('EA-a', Date.parse('2026-10-21T01:00:00.000Z'))
  assert.equal(after, 2)
  const loaded = await store.load('EA-a')
  assert.equal(loaded?.lastSeenAt, '2026-10-21T01:00:00.000Z')
})

test('recordHit on a missing row returns null', async () => {
  const store = new MemoryColdStore()
  assert.equal(await store.recordHit('EA-missing', Date.now()), null)
})

test('pruneExpired removes only expired rows', async () => {
  const store = new MemoryColdStore()
  const now = Date.parse('2026-10-21T12:00:00.000Z')
  await store.upsert(entry('EA-fresh', 1, '2026-10-22T00:00:00.000Z'))
  await store.upsert(entry('EA-stale', 1, '2026-10-21T06:00:00.000Z'))
  assert.equal(await store.pruneExpired(now), 1)
  assert.equal(await store.count(), 1)
  assert.equal((await store.load('EA-fresh'))?.analysisId, 'EA-fresh')
})

test('warmup returns hottest fresh entries first and skips expired', async () => {
  const store = new MemoryColdStore()
  const now = Date.now()
  const future = new Date(now + 3_600_000).toISOString()
  const past = new Date(now - 3_600_000).toISOString()
  await store.upsert(entry('EA-low', 1, future))
  await store.upsert(entry('EA-high', 9, future))
  await store.upsert(entry('EA-mid', 5, future))
  await store.upsert(entry('EA-expired', 99, past))
  const warmed = await store.warmup(2)
  assert.deepEqual(warmed.map(item => item.analysisId), ['EA-high', 'EA-mid'])
})
