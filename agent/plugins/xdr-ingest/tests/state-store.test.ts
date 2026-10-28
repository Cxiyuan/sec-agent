/**
 * 内存版智能体记忆（PG 不可用时的兜底）：结论库 + 脚本库。
 * PG 实现的行为与这里一致，集成测试在 `pg-store.integration.test.ts` 里跑。
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { MemoryStateStore } from '../src/state-store.ts'
import type { TaskResultRecord } from '../src/task-results.ts'

const now = '2026-10-27T00:00:00.000Z'

function record(over: Partial<TaskResultRecord> = {}): TaskResultRecord {
  return {
    key: 'TR-1',
    kind: 'hit',
    subjectKind: 'ip',
    subject: '10.0.0.9',
    feature: 'sid:1',
    taskId: 'task-1',
    verdict: 'false_positive',
    terminalReason: 'concluded',
    confidence: 0.9,
    summary: '误报',
    strength: 0.6,
    occurrences: 1,
    analyzedAt: now,
    expiresAt: '2026-10-28T00:00:00.000Z',
    ...over,
  }
}

test('task results: save, bump without extending TTL, prune', async () => {
  const store = new MemoryStateStore()
  assert.equal(await store.load('TR-1'), null)
  assert.equal(await store.save(record()), true)
  assert.equal((await store.load('TR-1'))?.occurrences, 1)
  assert.equal(await store.bump('TR-1', now, 'task-2'), true)
  assert.equal(await store.bump('missing', now, 'task-2'), false)
  const after = await store.load('TR-1')
  assert.equal(after?.occurrences, 2)
  assert.equal(after?.expiresAt, '2026-10-28T00:00:00.000Z', '复用时不能续期')
  assert.equal(await store.count(), 1)
  assert.equal(await store.prune('2026-10-28T00:00:01.000Z'), 1)
  assert.equal(await store.count(), 0)
})

test('scripts: upsert by name keeps id/usage, find by scenario and tag', async () => {
  const store = new MemoryStateStore()
  const first = await store.upsert({
    name: 'aggregate_conn_states',
    scenario: '按源 IP 聚合连接状态，判断有没有成功会话',
    code: 'echo hi',
    language: 'bash',
    tags: ['conn', 'basics'],
    variables: { SRC: '源 IP' },
  }, now)
  assert.equal(await store.countScripts(), 1)
  assert.equal((await store.get('aggregate_conn_states'))?.code, 'echo hi')

  await store.bumpUsage(first.id, now)
  const second = await store.upsert({
    name: 'aggregate_conn_states',
    scenario: '按源 IP 聚合连接状态（新版）',
    code: 'echo hi 2',
    tags: ['conn'],
  }, '2026-10-27T01:00:00.000Z')
  assert.equal(second.id, first.id, '同名覆盖保留 id')
  assert.equal(second.usageCount, 1, '覆盖不清空使用次数')
  assert.equal(second.code, 'echo hi 2')
  assert.equal(second.createdAt, now)
  assert.equal(await store.countScripts(), 1)

  const byScenario = await store.find({ query: '连接状态', tag: '', limit: 5 })
  assert.deepEqual(byScenario.map(item => item.name), ['aggregate_conn_states'])
  const byTag = await store.find({ query: '', tag: 'conn', limit: 5 })
  assert.equal(byTag.length, 1)
  const noMatch = await store.find({ query: 'dns tunnel', tag: '', limit: 5 })
  assert.equal(noMatch.length, 0)
})

/**
 * 抑制记忆（现象身份 + 抑制标记）。
 *
 * 为什么要单独记一层：抑制是**现象级**的事 —— NDR 拦的是规则命中那条路径，
 * 同一个现象还会从别的线索类型冒出来；本地记住就能在起会话前挡住。
 */
test('抑制记忆：记身份 → 标记被抑制 → 按身份查到', async () => {
  const store = new MemoryStateStore()
  const identity = { kind: 'hit', subjectKind: 'ip', subject: '10.0.0.5', feature: 'sid:1' }
  assert.equal(await store.findSuppressed(identity), null)

  await store.recordTaskSeen({ ...identity, taskId: 'task-1', verdict: 'false_positive' })
  assert.equal(await store.findSuppressed(identity), null, '还没标抑制前不该命中')

  assert.equal(await store.markSuppressed('task-1', '厂商心跳'), true)
  const hit = await store.findSuppressed(identity)
  assert.equal(hit?.suppressedBy, '厂商心跳')
  assert.equal(hit?.taskId, 'task-1')
  assert.equal(hit?.verdict, 'false_positive')
})

test('抑制记忆：没见过的任务 id 标不上；按身份可以补标', async () => {
  const store = new MemoryStateStore()
  const identity = { kind: 'hit', subjectKind: 'ip', subject: '10.0.0.9', feature: 'sid:2' }
  assert.equal(await store.markSuppressed('不存在的任务', 'x'), false)
  await store.recordTaskSeen({ ...identity, taskId: 'task-2', verdict: 'benign' })
  assert.equal(await store.markSuppressedByIdentity(identity, '人建的抑制'), 1)
  assert.equal((await store.findSuppressed(identity))?.suppressedBy, '人建的抑制')
})
