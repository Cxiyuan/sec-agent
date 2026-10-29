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

test('identity prefers the NDR-issued reuse_identity', () => {
  const key = taskResultKey(task)
  assert.ok(key !== null)
  assert.ok(key.startsWith(TASK_RESULT_PREFIX))
  assert.equal(taskResultKey({ ...task }), key)
  assert.notEqual(taskResultKey({ ...task, subject: '10.0.0.10' }), key)
  assert.notEqual(taskResultKey({ ...task, hint: { reuse_identity: 'content-b' } }), key)
  // B1：有了 NDR 下发的稳定身份，本地 feature 不再参与（同一事实跨窗口复用）
  assert.equal(taskResultKey({ ...task, feature: 'sid:1000002' }), key)
})

test('identity refuses to guess when feature and identity are missing', () => {
  // 老版本 NDR（或不带身份的 kind）：宁可多分析一次，也不能把不同规则混成一条结论
  assert.equal(taskResultKey({ ...task, feature: '', hint: {} }), null)
  assert.equal(taskResultKey({ ...task, feature: undefined, hint: {} }), null)
  assert.equal(taskResultKey({ ...task, hint: {} }), null, 'hit 缺稳定事件身份时不复用')
  assert.equal(
    taskResultKey({ ...task, kind: 'hit_cluster', feature: 'cluster:x', hint: {} }),
    null,
    'hit_cluster 缺身份同样不复用',
  )
})

test('requireIdentity=false temporarily restores the old keying', () => {
  const noIdentity = { ...task, hint: {} }
  assert.equal(taskResultKey(noIdentity, { requireIdentity: true }), null)
  const legacy = taskResultKey(noIdentity, { requireIdentity: false })
  assert.ok(legacy !== null, '回滚开关打开时按旧四元组拼键')
  assert.notEqual(
    taskResultKey({ ...noIdentity, feature: 'sid:1000002' }, { requireIdentity: false }),
    legacy,
  )
})

test('B1: same asset to different egress targets are different facts', () => {
  // 实测 bug：observation 任务只按 kind|subject|feature 拼键，
  // 同一资产外连 A/B 共用一条结论。身份来自事实自身的稳定去重键。
  const base: ClaimedTask = {
    id: 'task-obs',
    kind: 'observation',
    strength: 0.5,
    subject_kind: 'asset',
    subject: '10.0.0.5',
    feature: 'egress_new',
    hint: { reuse_identity: 'egress_new:asset:10.0.0.5:domain:a.example' },
  }
  const targetB: ClaimedTask = {
    ...base,
    hint: { reuse_identity: 'egress_new:asset:10.0.0.5:domain:b.example' },
  }
  const keyA = taskResultKey(base)
  assert.ok(keyA !== null)
  assert.notEqual(taskResultKey(targetB), keyA, '不同外连目标不能复用同一条结论')
  assert.equal(taskResultKey({ ...base }), keyA)
})

test('non-hit kinds fall back to feature only when identity is not required', () => {
  // 滚动升级：NDR 先上（所有 kind 都发 reuse_identity）；旧 NDR 环境下
  // 临时置 requireIdentity=false 才允许按旧四元组复用
  const novelty: ClaimedTask = {
    id: 'task-n',
    kind: 'novelty',
    strength: 0.4,
    subject_kind: 'asset',
    subject: '10.0.0.7',
    feature: 'first:asset',
    hint: {},
  }
  assert.equal(taskResultKey(novelty), null, 'B1：默认任何 kind 都必须有下发身份')
  const key = taskResultKey(novelty, { requireIdentity: false })
  assert.ok(key !== null)
  assert.notEqual(taskResultKey({ ...novelty, feature: 'first:account' }, { requireIdentity: false }), key)
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

/**
 * 抑制条件树 → 现象身份。
 *
 * 抑制条目若没带 source_task_id（人建的、或提交时没传），就只能从条件树反推
 * 它针对哪类现象：命中线索的身份是 `hit | 源 IP | 规则名`，条件树里的
 * src_ip + rule 正好拼得出来。推不出来就不推 —— 宁可不同步，也别乱标。
 */
test('identityOfMatch：从条件树反推命中线索的身份', async () => {
  const { identityOfMatch } = await import('../src/task-results.ts')
  const match = {
    logic: 'and',
    rules: [
      { field: 'src_ip', op: 'eq', value: '10.1.2.3' },
      { field: 'rule', op: 'eq', value: 'TLS握手失败风暴' },
    ],
  }
  assert.deepEqual(identityOfMatch(match), {
    kind: 'hit',
    subjectKind: 'ip',
    subject: '10.1.2.3',
    feature: 'TLS握手失败风暴',
  })
})

test('identityOfMatch：推不出完整身份就返回 null', async () => {
  const { identityOfMatch } = await import('../src/task-results.ts')
  // 只有端口与 UA：既不知道源 IP，也不知道规则名 → 不同步
  assert.equal(identityOfMatch({
    logic: 'and',
    rules: [
      { field: 'dst_port', op: 'eq', value: 22346 },
      { field: 'user_agent', op: 'eq', value: '00_linux_client' },
    ],
  }), null)
  assert.equal(identityOfMatch(null), null)
})
