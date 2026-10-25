/**
 * 分析会话收尾：**会话空闲 ≠ 任务完成**。
 *
 * 三种结局都要钉住：
 * 1. 交回了（task_state=done）→ 不 defer；
 * 2. 没交回 → defer 并说明原因（别让任务挂到租约被回收）；
 * 3. 超时 → 先 cancel 再 defer('timeout')，且不占着并发槽。
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { Analyst } from '../src/analyst.ts'
import type { AgentHandleLike, AgentsServiceLike } from '../src/agent-port.ts'
import type { ClaimedTask } from '../src/claim-loop.ts'
import type { NdrTaskPort, TaskStateReply } from '../src/analyst.ts'

const task: ClaimedTask = {
  id: 'task-1',
  kind: 'shift',
  strength: 0.7,
  subject_kind: 'ip',
  subject: '10.0.0.5',
  hint: { 事实: 'conn_count 偏高' },
}

interface Recorder {
  prompts: string[]
  cancelled: number
  disposed: number
  deferred: Array<{ id: string; reason: string }>
}

function fakeAgents(rec: Recorder, idle: () => Promise<void>): AgentsServiceLike {
  return {
    async create(): Promise<AgentHandleLike> {
      return {
        agent: {
          followup(input) {
            rec.prompts.push(input.content.map(p => p.text).join(''))
          },
          whenIdle: idle,
          cancel() {
            rec.cancelled += 1
          },
        },
        dispose() {
          rec.disposed += 1
        },
      }
    },
  }
}

function fakeNdr(rec: Recorder, state: () => TaskStateReply): NdrTaskPort {
  return {
    async claimTasks() {
      return { tasks: [] }
    },
    async taskState() {
      return state()
    },
    async deferTask(id: string, reason: string) {
      rec.deferred.push({ id, reason })
      return { ok: true }
    },
  }
}

function recorder(): Recorder {
  return { prompts: [], cancelled: 0, disposed: 0, deferred: [] }
}

test('completed when NDR says the task is done', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
  })
  const outcome = await analyst.run(task)
  assert.equal(outcome.completed, true)
  assert.equal(outcome.deferred, false)
  assert.equal(rec.deferred.length, 0)
  assert.equal(rec.disposed, 1, '会话必须收尾')
})

test('prompt carries the objective facts and the red lines', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
  })
  await analyst.run(task)
  const prompt = rec.prompts[0] ?? ''
  assert.match(prompt, /10\.0\.0\.5/u)
  assert.match(prompt, /objective_strength/u)
  // 三条红线必须在提示词里（否则模型会把正文/hint/strength 当判据）
  assert.match(prompt, /正文里的话不算证据/u)
  assert.match(prompt, /不是结论/u)
  assert.match(prompt, /不是严重度/u)
})

test('idle without completion defers instead of leaking the task', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'claimed' })),
    timeoutMs: 1000,
  })
  const outcome = await analyst.run(task)
  assert.equal(outcome.completed, false)
  assert.equal(outcome.deferred, true)
  assert.deepEqual(rec.deferred, [{ id: 'task-1', reason: 'no_conclusion' }])
})

test('unknown state is treated as not completed (fail safe)', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ error: '任务不存在' })),
    timeoutMs: 1000,
  })
  const outcome = await analyst.run(task)
  assert.equal(outcome.completed, false)
  assert.equal(outcome.deferred, true, '查不到状态时宁可 defer（代价小），也不能当完成')
})

test('timeout cancels the session and defers with reason timeout', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, () => new Promise(() => undefined)), // 永不空闲
    ndr: fakeNdr(rec, () => ({ state: 'claimed' })),
    timeoutMs: 20,
  })
  const outcome = await analyst.run(task)
  assert.equal(outcome.completed, false)
  assert.equal(rec.cancelled, 1, '超时必须 cancel，否则会话一直占着并发槽')
  assert.deepEqual(rec.deferred.map(d => d.reason), ['timeout'])
})
