/**
 * 同类现象结论复用的身份与策略（纯函数，不碰存储）。
 *
 * 关键护栏：
 * - 身份必须带 feature，否则同一台机器上的不同规则会共用一条结论；
 * - 只有 TP/FP/benign/inconclusive 可复用，suspicious 必须重查；
 * - 现象变强（strength 上升超过阈值）或过期就必须重查；
 * - 复用时 TTL 不续期（否则一条结论可以被无限复用下去）。
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import type { ClaimedTask } from '../src/claim-loop.ts'
import { reuseDecision, taskResultKey, TASK_RESULT_PREFIX } from '../src/task-results.ts'
import type { TaskResultRecord } from '../src/task-results.ts'

const task: ClaimedTask = {
  id: 'task-1',
  kind: 'hit',
  strength: 0.6,
  subject_kind: 'ip',
  subject: '10.0.0.9',
  feature: 'sid:1000001',
  hint: { reuse_identity: 'content-a' },
}

const NOW = Date.parse('2026-10-27T00:00:00Z')

function record(over: Partial<TaskResultRecord> = {}): TaskResultRecord {
  return {
    key: 'TR-x',
    kind: 'hit',
    subjectKind: 'ip',
    subject: '10.0.0.9',
    feature: 'sid:1000001',
    taskId: 'task-old',
    verdict: 'false_positive',
    terminalReason: 'concluded',
    confidence: 0.9,
    summary: '历史误报',
    strength: 0.6,
    occurrences: 2,
    analyzedAt: '2026-10-26T12:00:00.000Z',
    expiresAt: '2026-10-27T12:00:00.000Z',
    ...over,
  }
}

test('identity is stable and includes the feature', () => {
  const key = taskResultKey(task)
  assert.ok(key !== null)
  assert.ok(key.startsWith(TASK_RESULT_PREFIX))
  assert.equal(taskResultKey({ ...task }), key)
  assert.notEqual(taskResultKey({ ...task, feature: 'sid:1000002' }), key)
  assert.notEqual(taskResultKey({ ...task, subject: '10.0.0.10' }), key)
  assert.notEqual(taskResultKey({ ...task, hint: { reuse_identity: 'content-b' } }), key)
})

test('identity refuses to guess when feature is missing', () => {
  // 老版本 NDR 不下发 feature：宁可多分析一次，也不能把不同规则混成一条结论
  assert.equal(taskResultKey({ ...task, feature: '' }), null)
  assert.equal(taskResultKey({ ...task, feature: undefined }), null)
  assert.equal(taskResultKey({ ...task, hint: {} }), null, 'hit 缺稳定事件身份时不复用')
})

test('fresh reusable verdicts are reused', () => {
  for (const verdict of ['true_positive', 'false_positive', 'benign', 'inconclusive']) {
    assert.deepEqual(
      reuseDecision(record({ verdict }), task, NOW, 86_400_000, 0.15),
      { reuse: true },
      verdict,
    )
  }
})

test('suspicious is never reused', () => {
  assert.equal(reuseDecision(record({ verdict: 'suspicious' }), task, NOW, 86_400_000, 0.15).reuse, false)
  assert.equal(reuseDecision(record({ verdict: 'unknown' }), task, NOW, 86_400_000, 0.15).reuse, false)
  assert.equal(
    reuseDecision(record({ verdict: 'inconclusive', terminalReason: 'budget_exhausted' }), task, NOW, 86_400_000, 0.15).reuse,
    false,
    '预算耗尽的 inconclusive 不是完成分析，不能复用',
  )
})

test('expired or disabled cache means re-analysis', () => {
  assert.equal(reuseDecision(record({ expiresAt: '2026-10-26T23:59:59.000Z' }), task, NOW, 86_400_000, 0.15).reuse, false)
  assert.equal(reuseDecision(record(), task, NOW, 6 * 3_600_000, 0.15).reuse, false, '运行时缩短 TTL 立即生效')
  assert.equal(reuseDecision(record(), task, NOW, 0, 0.15).reuse, false)
  assert.equal(reuseDecision(null, task, NOW, 86_400_000, 0.15).reuse, false)
})

test('a stronger signal forces re-analysis, a small drift does not', () => {
  assert.equal(reuseDecision(record({ strength: 0.5 }), task, NOW, 86_400_000, 0.15).reuse, true)
  assert.equal(reuseDecision(record({ strength: 0.3 }), task, NOW, 86_400_000, 0.15).reuse, false)
  assert.equal(reuseDecision(record(), { ...task, strength: Number.NaN }, NOW, 86_400_000, 0.15).reuse, false)
})
