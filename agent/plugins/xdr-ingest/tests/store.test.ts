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

test('listRecent 按 last_seen 降序分页，且包含已过期记录', async () => {
  const store = new MemoryColdStore()
  // 三条不同 lastSeen：EA-c 最新、EA-a 最旧；EA-expired 已过期但列表仍可见
  await store.upsert({ ...entry('EA-a', 1, '2099-01-01T00:00:00.000Z'), lastSeenAt: '2026-10-20T00:00:00.000Z' })
  await store.upsert({ ...entry('EA-b', 1, '2099-01-01T00:00:00.000Z'), lastSeenAt: '2026-10-22T00:00:00.000Z' })
  await store.upsert({ ...entry('EA-expired', 1, '2000-01-01T00:00:00.000Z'), lastSeenAt: '2026-10-21T00:00:00.000Z' })
  const page = await store.listRecent({ limit: 10, offset: 0, search: '' })
  assert.equal(page.total, 3)
  assert.deepEqual(page.entries.map(item => item.analysisId), ['EA-b', 'EA-expired', 'EA-a'])
  // 翻页：第二页从降序列表切出
  const second = await store.listRecent({ limit: 1, offset: 1, search: '' })
  assert.equal(second.total, 3)
  assert.equal(second.entries[0]?.analysisId, 'EA-expired')
})

test('listRecent 搜索大小写不敏感地匹配分析 ID、结论摘要', async () => {
  const store = new MemoryColdStore()
  await store.upsert(entry('EA-a', 1, '2099-01-01T00:00:00.000Z'))
  await store.upsert({ ...entry('EA-b', 1, '2099-01-01T00:00:00.000Z'), lastSeenAt: '2026-10-25T00:00:00.000Z',
    result: { category: 'generic-alert', severity: 'medium', summary: '端口扫描特征', recommendation: '封禁', analyzer: 'heuristic-v0' } })
  const byId = await store.listRecent({ limit: 10, offset: 0, search: 'ea-b' })
  assert.equal(byId.total, 1)
  assert.equal(byId.entries[0]?.analysisId, 'EA-b')
  const bySummary = await store.listRecent({ limit: 10, offset: 0, search: '端口扫描' })
  assert.deepEqual(bySummary.entries.map(item => item.analysisId), ['EA-b'])
  const miss = await store.listRecent({ limit: 10, offset: 0, search: '不存在的关键词' })
  assert.equal(miss.total, 0)
})
