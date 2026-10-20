/** 分析缓存语义测试：复用计数、TTL 重分析、容量淘汰、投递溯源上限。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { AnalysisCache } from '../src/cache.ts'
import { analysisIdOf, normalizeDigest } from '../src/identity.ts'
import type { EventIdentity, TriageResult } from '../src/types.ts'

const identity: EventIdentity = {
  rule: 'rule-a',
  srcIp: '10.0.0.1',
  dstIps: ['10.0.0.2'],
  dstPorts: ['443'],
  eventTypes: ['alert'],
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

function makeCache(overrides: Partial<{ ttlMs: number; maxEntries: number; clock: { value: number } }> = {}) {
  const clock = overrides.clock ?? { value: 1_000_000 }
  const cache = new AnalysisCache({
    ttlMs: overrides.ttlMs ?? 3_600_000,
    maxEntries: overrides.maxEntries ?? 100,
    now: () => clock.value,
  })
  return { cache, clock }
}

test('first event is analyzed with occurrences = 1; identical event is reused without analysis', () => {
  const { cache } = makeCache()
  const id = analysisIdOf(identity)
  let analysisRuns = 0

  const first = cache.admit(id, identity, delivery, () => {
    analysisRuns += 1
    return result('a')
  })
  assert.equal(first.reused, false)
  assert.equal(first.reanalyzed, false)
  assert.equal(first.record.occurrences, 1)

  const second = cache.admit(id, identity, { eventId: 'evt-2', fingerprint: 'fp-2' }, () => {
    analysisRuns += 1
    return result('b')
  })
  assert.equal(second.reused, true)
  assert.equal(second.record.occurrences, 2)
  assert.equal(second.record.result.summary, 'summary a', 'reused result must not be recomputed')
  assert.equal(analysisRuns, 1, 'identical event must not enter analysis')
  assert.deepEqual(cache.counters, { analyzed: 1, reused: 1, reanalyzed: 0 })
})

test('result older than TTL is re-analyzed but keeps cumulative occurrences and firstSeen', () => {
  const { cache, clock } = makeCache({ ttlMs: 1_000 })
  const id = analysisIdOf(identity)

  const first = cache.admit(id, identity, delivery, () => result('v1'))
  assert.equal(first.reused, false)

  clock.value += 2_000
  const second = cache.admit(id, identity, { eventId: 'evt-2', fingerprint: 'fp-2' }, () => result('v2'))
  assert.equal(second.reused, false)
  assert.equal(second.reanalyzed, true)
  assert.equal(second.record.occurrences, 2, 'cumulative count survives re-analysis')
  assert.equal(second.record.firstSeenAt, first.record.firstSeenAt)
  assert.equal(second.record.result.summary, 'summary v2', 'result must be refreshed')
})

test('capacity overflow evicts the least-recently-seen record; hot records survive', () => {
  const { cache } = makeCache({ maxEntries: 2 })
  const cold = { ...identity, rule: 'cold' }
  const hot = { ...identity, rule: 'hot' }
  const warm = { ...identity, rule: 'warm' }

  cache.admit(analysisIdOf(cold), cold, delivery, () => result('cold'))
  cache.admit(analysisIdOf(hot), hot, delivery, () => result('hot'))

  cache.admit(analysisIdOf(warm), warm, delivery, () => result('warm'))
  assert.equal(cache.size, 2, 'cold was evicted when warm arrived')

  const hotAgain = cache.admit(analysisIdOf(hot), hot, delivery, () => result('again'))
  assert.equal(hotAgain.reused, true, 'hot record must survive eviction')

  const coldAgain = cache.admit(analysisIdOf(cold), cold, delivery, () => result('cold-again'))
  assert.equal(coldAgain.reused, false, 'cold record was evicted and must be re-analyzed')
})

test('deliveries keep only the 10 most recent refs', () => {
  const { cache, clock } = makeCache()
  const id = analysisIdOf(identity)
  for (let i = 0; i < 15; i += 1) {
    cache.admit(id, identity, { eventId: `evt-${i}`, fingerprint: `fp-${i}` }, () => result('x'))
    clock.value += 1
  }
  const record = cache.admit(id, identity, { eventId: 'evt-final', fingerprint: 'fp-final' }, () => result('y'))
    .record
  assert.equal(record.deliveries.length, 10)
  assert.equal(record.deliveries[0]?.eventId, 'evt-6')
  assert.equal(record.deliveries[record.deliveries.length - 1]?.eventId, 'evt-final')
})

test('stats reports size and counters', () => {
  const { cache } = makeCache()
  cache.admit(analysisIdOf(identity), identity, delivery, () => result('a'))
  cache.admit(analysisIdOf(identity), identity, delivery, () => result('a'))
  const stats = cache.stats()
  assert.equal(stats.size, 1)
  assert.equal(stats.analyzed, 1)
  assert.equal(stats.reused, 1)
})
