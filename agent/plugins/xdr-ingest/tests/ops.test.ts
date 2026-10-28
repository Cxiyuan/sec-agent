/** 运维保护：失败熔断 / 全局并发 / 保留期清理 / 模型串解析。 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { ConcurrencyGate, FailureBreaker, isTransientFailure } from '../src/breaker.ts'
import { pruneSessions } from '../src/maintenance.ts'
import { splitModel } from '../src/projects.ts'

test('熔断：连续失败到阈值才打开，冷却逐次翻倍，成功即恢复', () => {
  const breaker = new FailureBreaker({ threshold: 3, baseCooldownMs: 60_000, maxCooldownMs: 300_000 })
  assert.equal(breaker.recordFailure('429', 1_000), false)
  assert.equal(breaker.recordFailure('429', 2_000), false)
  assert.equal(breaker.recordFailure('429', 3_000), true, '第 3 次才打开')
  assert.equal(breaker.isOpen(4_000), true)
  assert.equal(breaker.remainingSeconds(4_000), 59)
  // 冷却后的第一次失败：立刻重新打开，且冷却翻倍
  assert.equal(breaker.recordFailure('429', 70_000), true)
  assert.equal(breaker.remainingSeconds(70_000), 120)
  // 成功一次清零（半开成功）
  breaker.recordSuccess()
  assert.equal(breaker.isOpen(0), false)
  assert.equal(breaker.state()['failures'], 0)
})

test('熔断：只有模型/网络类的暂时性失败算数（业务失败不该停下整个项目）', () => {
  assert.equal(isTransientFailure('429 quota exceeded'), true)
  assert.equal(isTransientFailure('context window exceeds limit'), true)
  assert.equal(isTransientFailure('socket hang up'), true)
  assert.equal(isTransientFailure('没有交回结论'), false)
  assert.equal(isTransientFailure(''), false)
})

test('全局闸门：跨项目共享，占满即拒绝', () => {
  let max = 2
  const gate = new ConcurrencyGate(() => max)
  assert.equal(gate.tryAcquire(), true)
  assert.equal(gate.tryAcquire(), true)
  assert.equal(gate.tryAcquire(), false)
  gate.release()
  assert.equal(gate.free(), 1)
  max = 1
  assert.equal(gate.tryAcquire(), false, '缩容后按新上限算')
  assert.deepEqual(gate.state(), { in_use: 1, max: 1, free: 0 })
})

test('保留期：过期会话目录删掉，未过期不动', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'xdr-sess-'))
  const oldDir = path.join(root, '_no-cwd', 'old-session')
  const newDir = path.join(root, '_no-cwd', 'new-session')
  await fs.mkdir(oldDir, { recursive: true })
  await fs.mkdir(newDir, { recursive: true })
  await fs.writeFile(path.join(oldDir, 'session.v4.jsonl.zstd'), 'x'.repeat(100))
  await fs.writeFile(path.join(newDir, 'session.v4.jsonl.zstd'), 'y'.repeat(50))
  const old = (Date.now() - 30 * 86_400_000) / 1000
  await fs.utimes(path.join(oldDir, 'session.v4.jsonl.zstd'), old, old)
  const result = await pruneSessions(root, 14)
  assert.equal(result.removed, 1)
  assert.equal(result.bytes, 100)
  await assert.rejects(fs.access(path.join(oldDir, 'session.v4.jsonl.zstd')))
  await fs.access(path.join(newDir, 'session.v4.jsonl.zstd'))
  await fs.rm(root, { recursive: true, force: true })
})

test('模型串：provider/model 拆两段，没有斜杠当 model', () => {
  assert.deepEqual(splitModel('minimax/MiniMax-M2.5'), ['minimax', 'MiniMax-M2.5'])
  assert.deepEqual(splitModel('MiniMax-M2.5'), ['', 'MiniMax-M2.5'])
  assert.deepEqual(splitModel('  '), ['', ''])
})
