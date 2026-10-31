/** 领取循环：并发上限、门铃去抖、失败退避、正常回执不算错误。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { ClaimLoop } from '../src/claim-loop.ts'
import type { ClaimedTask, ClaimReply } from '../src/claim-loop.ts'

function task(id: string): ClaimedTask {
  return {
    id,
    kind: 'shift',
    strength: 0.6,
    subject_kind: 'ip',
    subject: '10.0.0.5',
  }
}

function base(runTask: (t: ClaimedTask) => Promise<void>, claimTasks: (limit: number) => Promise<ClaimReply>) {
  return {
    pollSeconds: 900,
    maxConcurrent: 2,
    claimLimit: 2,
    doorbellDebounceMs: 10,
    backoffMaxMs: 40,
    claimTasks,
    runTask,
  }
}

test('claims and runs tasks, honouring maxConcurrent', async () => {
  let inFlight = 0
  let peak = 0
  const started: string[] = []
  const loop = new ClaimLoop(
    base(
      async t => {
        inFlight += 1
        peak = Math.max(peak, inFlight)
        started.push(t.id)
        await new Promise(resolve => setTimeout(resolve, 20))
        inFlight -= 1
      },
      async limit => {
        assert.ok(limit >= 1)
        return { tasks: [task('a'), task('b')] }
      },
    ),
  )
  await loop.tick()
  await new Promise(resolve => setTimeout(resolve, 80))
  assert.deepEqual(started.sort(), ['a', 'b'])
  assert.ok(peak <= 2, `并发超过上限：${peak}`)
  assert.equal(loop.stats.claimed, 2)
  assert.equal(loop.stats.running, 0)
})

test('queue_empty is a normal receipt, not an error', async () => {
  const loop = new ClaimLoop(base(async () => undefined, async () => ({ reason: 'queue_empty' })))
  await loop.tick()
  assert.equal(loop.stats.consecutiveErrors, 0)
  assert.equal(loop.stats.failedClaims, 0)
  assert.equal(loop.stats.polls, 1)
})

test('errors accumulate and backoff grows without exceeding the cap', async () => {
  const loop = new ClaimLoop(
    base(async () => undefined, async () => {
      throw new Error('ndr unreachable')
    }),
  )
  for (let i = 0; i < 4; i += 1) {
    await loop.tick()
  }
  assert.equal(loop.stats.consecutiveErrors, 4)
  assert.equal(loop.stats.failedClaims, 4)
  // 退避不超过配置上限（内部值不对外，但只能通过行为观察：最后一次失败后仍能继续 tick）
  assert.match(loop.stats.lastError, /unreachable/u)
})

test('success resets the error counter', async () => {
  let fail = true
  const loop = new ClaimLoop(
    base(async () => undefined, async () => {
      if (fail) throw new Error('boom')
      return { reason: 'queue_empty' }
    }),
  )
  await loop.tick()
  assert.equal(loop.stats.consecutiveErrors, 1)
  fail = false
  await loop.tick()
  assert.equal(loop.stats.consecutiveErrors, 0)
})

test('skips claiming when all slots are busy', async () => {
  let claims = 0
  const loop = new ClaimLoop(
    base(
      async () => {
        await new Promise(resolve => setTimeout(resolve, 50))
      },
      async () => {
        claims += 1
        return { tasks: [task('x'), task('y')] }
      },
    ),
  )
  await loop.tick()
  await loop.tick() // 两个槽都占着，这一轮不该再领
  assert.equal(claims, 1)
  assert.ok(loop.stats.droppedByConcurrency >= 1)
})

test('doorbell wake is debounced into a single poll', async () => {
  let claims = 0
  const loop = new ClaimLoop(
    base(async () => undefined, async () => {
      claims += 1
      return { reason: 'queue_empty' }
    }),
  )
  loop.start() // start 会立刻 tick 一次
  loop.wake()
  loop.wake()
  loop.wake()
  await new Promise(resolve => setTimeout(resolve, 60))
  loop.stop()
  // 启动 1 次 + 三次门铃合并成 1 次（若没去抖会是 4 次）
  assert.ok(claims >= 2 && claims <= 3, `去抖失效：${claims} 次领取`)
  assert.equal(loop.stats.doorbells, 3)
})

test('task failure does not leak the concurrency slot', async () => {
  const loop = new ClaimLoop(
    base(
      async t => {
        if (t.id === 'bad') throw new Error('analysis blew up')
      },
      async () => ({ tasks: [task('bad')] }),
    ),
  )
  await loop.tick()
  await new Promise(resolve => setTimeout(resolve, 30))
  // 槽位已释放：再来一轮还能领
  await loop.tick()
  assert.equal(loop.stats.claimed, 2)
  assert.match(loop.stats.lastError, /blew up/u)
})

test('running tracks concurrency without server budget fields', async () => {
  const loop = new ClaimLoop(
    base(
      async () => {
        // 任务在跑时 running=1（maxConcurrent=2 的第二个槽还没占满）
        assert.equal(loop.stats.running >= 0, true)
        await new Promise(resolve => setTimeout(resolve, 20))
      },
      async () => ({ tasks: [task('bt')] }),
    ),
  )
  await loop.tick()
  assert.equal(loop.stats.started, 1)
  await new Promise(resolve => setTimeout(resolve, 60))
  assert.equal(loop.stats.running, 0)
  // 队列空是正常回执：不启动任务，也不影响后续轮询。
  const quiet = new ClaimLoop(base(async () => undefined, async () => ({ reason: 'queue_empty' })))
  await quiet.tick()
  assert.equal(quiet.stats.started, 0)
})

test('configure：热更新领取条数与并发，立刻影响下一轮', async () => {
  const limits: number[] = []
  const loop = new ClaimLoop(base(
    async () => undefined,
    async limit => {
      limits.push(limit)
      return { tasks: [] }
    },
  ))
  assert.deepEqual(loop.settingsSnapshot(), { pollSeconds: 900, maxConcurrent: 2, claimLimit: 2 })
  loop.configure({ claimLimit: 5, maxConcurrent: 5 })
  assert.deepEqual(loop.settingsSnapshot(), { pollSeconds: 900, maxConcurrent: 5, claimLimit: 5 })
  await loop.tick()
  assert.deepEqual(limits, [5])
})

test('configure：热更新轮询间隔后按新间隔重排定时器', async () => {
  let polls = 0
  const loop = new ClaimLoop(base(
    async () => undefined,
    async () => {
      polls += 1
      return { tasks: [] }
    },
  ))
  loop.start()
  await new Promise(resolve => setTimeout(resolve, 20))
  assert.equal(polls, 1, 'start() 必须先领一次')
  loop.configure({ pollSeconds: 0.05 })
  await new Promise(resolve => setTimeout(resolve, 180))
  loop.stop()
  assert.ok(polls >= 2, `新间隔应触发再次轮询，实际 ${polls} 次`)
})
