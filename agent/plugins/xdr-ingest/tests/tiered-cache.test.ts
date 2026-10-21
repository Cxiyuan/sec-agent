/** 两级缓存语义测试：热层晋升/降级、冷层复用、预热、清理、重启不丢。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { TieredCache } from '../src/cache.ts'
import { analysisIdOf } from '../src/identity.ts'
import { MemoryColdStore } from '../src/store.ts'
import type { EventIdentity, TriageResult } from '../src/types.ts'

function identity(rule: string): EventIdentity {
  return {
    rule,
    srcIp: '203.0.113.7',
    dstIps: ['10.0.0.5'],
    dstPorts: ['22', '80'],
    eventTypes: ['alert'],
  }
}

const delivery = { eventId: 'evt-1', fingerprint: 'fp-1' }

function result(tag: string): TriageResult {
  return {
    category: 'generic-alert',
    severity: 'medium',
    summary: `summary ${tag}`,
    recommendation: 'review',
    analyzer: 'heuristic-v0',
  }
}

function makeCache(overrides: Partial<{ ttlMs: number; hotMaxEntries: number; hotThreshold: number; clock: { value: number } }> = {}) {
  const clock = overrides.clock ?? { value: 1_000_000 }
  const store = new MemoryColdStore()
  const cache = new TieredCache({
    ttlMs: overrides.ttlMs ?? 3_600_000,
    hotMaxEntries: overrides.hotMaxEntries ?? 100,
    hotThreshold: overrides.hotThreshold ?? 2,
    store,
    now: () => clock.value,
  })
  return { cache, store, clock }
}

test('first occurrence lands in the cold store only (rare IPs stay on disk)', async () => {
  const { cache, store } = makeCache()
  let analysisRuns = 0
  const id = analysisIdOf(identity('rule-a'))

  const first = await cache.admit(id, identity('rule-a'), delivery, () => {
    analysisRuns += 1
    return result('a')
  })
  assert.equal(first.reused, false)
  assert.equal(first.tier, 'cold')
  assert.equal(first.record.occurrences, 1)
  assert.equal(cache.hotSize, 0, 'below hotThreshold: must not occupy memory')
  assert.equal(await store.count(), 1, 'analysis is written through to the cold store')
  assert.equal(analysisRuns, 1)
})

test('second occurrence is a cold hit, promotes to hot, and does not re-analyze', async () => {
  const { cache } = makeCache()
  const id = analysisIdOf(identity('rule-a'))
  let analysisRuns = 0
  const analyze = () => {
    analysisRuns += 1
    return result('a')
  }

  await cache.admit(id, identity('rule-a'), delivery, analyze)
  const second = await cache.admit(id, identity('rule-a'), { eventId: 'evt-2', fingerprint: 'fp-2' }, analyze)

  assert.equal(second.reused, true)
  assert.equal(second.tier, 'cold')
  assert.equal(second.record.occurrences, 2)
  assert.equal(second.record.result.summary, 'summary a', 'reused result must not be recomputed')
  assert.equal(analysisRuns, 1, 'identical event must not enter analysis')
  assert.equal(cache.hotSize, 1, 'occurrences reached hotThreshold: promoted')
  assert.deepEqual(cache.counters.promoted, 1)

  const third = await cache.admit(id, identity('rule-a'), { eventId: 'evt-3', fingerprint: 'fp-3' }, analyze)
  assert.equal(third.tier, 'hot', 'promoted entry is served from memory afterwards')
  assert.equal(third.record.occurrences, 3)
  assert.equal(analysisRuns, 1)
})

test('result older than TTL is re-analyzed but keeps cumulative occurrences and firstSeen', async () => {
  const { cache, clock, store } = makeCache({ ttlMs: 1_000 })
  const id = analysisIdOf(identity('rule-a'))

  const first = await cache.admit(id, identity('rule-a'), delivery, () => result('v1'))
  clock.value += 2_000
  const second = await cache.admit(id, identity('rule-a'), { eventId: 'evt-2', fingerprint: 'fp-2' }, () => result('v2'))

  assert.equal(second.reused, false)
  assert.equal(second.reanalyzed, true)
  assert.equal(second.record.occurrences, 2, 'cumulative count survives re-analysis')
  assert.equal(second.record.firstSeenAt, first.record.firstSeenAt)
  assert.equal(second.record.result.summary, 'summary v2', 'result must be refreshed')
  const persisted = await store.load(id)
  assert.equal(persisted?.occurrences, 2, 're-analysis is persisted too')
})

test('hot overflow demotes the least-recently-seen record back to the cold store (never dropped)', async () => {
  const { cache, store } = makeCache({ hotMaxEntries: 2, hotThreshold: 1 })
  const hot = identity('hot')
  const cold = identity('cold')
  const warm = identity('warm')

  await cache.admit(analysisIdOf(hot), hot, delivery, () => result('hot'))
  await cache.admit(analysisIdOf(cold), cold, delivery, () => result('cold'))
  await cache.admit(analysisIdOf(warm), warm, delivery, () => result('warm'))

  assert.equal(cache.hotSize, 2, 'hot tier stays within capacity')
  assert.equal(await store.count(), 3, 'demotion keeps every record in the cold store')
  assert.equal(cache.counters.demoted, 1, 'the least-recently-seen record (hot) was demoted')

  // 被降级的记录仍在冷库可复用，再次出现时经冷命中重新晋升
  const hotAgain = await cache.admit(analysisIdOf(hot), hot, delivery, () => result('hot-again'))
  assert.equal(hotAgain.reused, true, 'demoted record is still reusable from the cold tier')
  assert.equal(hotAgain.tier, 'cold')
  assert.equal(hotAgain.record.occurrences, 2)
  assert.equal(cache.hotSize, 2, 're-promotion evicts another LRU record instead of overflowing')
  assert.equal(cache.counters.demoted, 2)
  assert.equal(await store.count(), 3, 'still nothing lost')
})

test('a fresh cache over the same cold store reuses results without re-analysis (restart survival)', async () => {
  const store = new MemoryColdStore()
  const id = analysisIdOf(identity('rule-a'))
  const before = new TieredCache({ ttlMs: 3_600_000, hotMaxEntries: 10, hotThreshold: 2, store })
  let analysisRuns = 0
  const analyze = () => {
    analysisRuns += 1
    return result('a')
  }
  await before.admit(id, identity('rule-a'), delivery, analyze)
  await before.admit(id, identity('rule-a'), { eventId: 'evt-2', fingerprint: 'fp-2' }, analyze)
  assert.equal(analysisRuns, 1)

  // 模拟进程重启：全新缓存实例（热层空），冷库不变
  const after = new TieredCache({ ttlMs: 3_600_000, hotMaxEntries: 10, hotThreshold: 2, store })
  const reused = await after.admit(id, identity('rule-a'), { eventId: 'evt-3', fingerprint: 'fp-3' }, analyze)
  assert.equal(reused.reused, true, 'cold store survives restart: no re-analysis')
  assert.equal(reused.record.occurrences, 3)
  assert.equal(analysisRuns, 1)
})

test('warmup loads the hottest cold records into the hot tier', async () => {
  const store = new MemoryColdStore()
  const now = Date.now()
  const expiresAt = new Date(now + 3_600_000).toISOString()
  for (const [rule, occurrences] of [['cold-rule', 1], ['hot-rule', 7]] as const) {
    const id = analysisIdOf(identity(rule))
    await store.upsert({
      analysisId: id,
      identity: identity(rule),
      result: result(rule),
      occurrences,
      firstSeenAt: new Date(now - 60_000).toISOString(),
      lastSeenAt: new Date(now - 60_000).toISOString(),
      analyzedAt: new Date(now - 60_000).toISOString(),
      expiresAt,
      deliveries: [],
    })
  }

  const cache = new TieredCache({ ttlMs: 3_600_000, hotMaxEntries: 10, hotThreshold: 2, store, now: () => now })
  assert.equal(await cache.warmup(10), 2, 'both fresh records are preloaded')
  assert.equal(cache.hotSize, 2)

  let analysisRuns = 0
  const hit = await cache.admit(analysisIdOf(identity('hot-rule')), identity('hot-rule'), delivery, () => {
    analysisRuns += 1
    return result('never')
  })
  assert.equal(hit.tier, 'hot')
  assert.equal(analysisRuns, 0, 'warmed entry serves from memory without analysis')
})

test('pruneExpired clears both tiers', async () => {
  const { cache, store, clock } = makeCache({ ttlMs: 1_000, hotThreshold: 1 })
  const id = analysisIdOf(identity('rule-a'))
  await cache.admit(id, identity('rule-a'), delivery, () => result('a'))
  assert.equal(cache.hotSize, 1)

  clock.value += 2_000
  const pruned = await cache.pruneExpired()
  assert.equal(pruned.hot, 1)
  assert.equal(pruned.cold, 1)
  assert.equal(cache.hotSize, 0)
  assert.equal(await store.count(), 0)
})

test('stats reports tier sizes, store kind and counters', async () => {
  const { cache } = makeCache()
  const id = analysisIdOf(identity('rule-a'))
  await cache.admit(id, identity('rule-a'), delivery, () => result('a'))
  await cache.admit(id, identity('rule-a'), { eventId: 'evt-2', fingerprint: 'fp-2' }, () => result('a'))
  const stats = await cache.stats()
  assert.equal(stats.hotSize, 1)
  assert.equal(stats.coldSize, 1)
  assert.equal(stats.storeKind, 'memory')
  assert.equal(stats.analyzed, 1)
  assert.equal(stats.reused, 1)
  assert.equal(stats.promoted, 1)
})
