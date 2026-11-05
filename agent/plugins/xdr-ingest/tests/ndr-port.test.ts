import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { NdrTaskPortAdapter } from '../src/ndr-port.ts'

test('task_state audits 被保留（跨进程恢复指针）', async () => {
  const calls: Array<{ name: string, args: Record<string, unknown> | undefined }> = []
  const adapter = new NdrTaskPortAdapter({
    async callTool(name, args) {
      calls.push({ name, args })
      return {
        state: 'deferred',
        audits: [{
          session_id: 'session-1',
          attempt: 3,
          outcome: 'deferred',
          decision: { task_fingerprint: 'fp', prompt_attempts: 1 },
          turn_end_reason: 'error:SERVER',
          tools_used: 4,
        }],
      }
    },
  })
  const reply = await adapter.taskState('task-1')
  assert.equal(reply.audits?.[0]?.session_id, 'session-1')
  assert.equal(reply.audits?.[0]?.attempt, 3)
  assert.equal(reply.audits?.[0]?.decision?.['task_fingerprint'], 'fp')
  assert.equal(reply.audits?.[0]?.turn_end_reason, 'error:SERVER')
})

test('defer_task 透传 retry_after_seconds，renewLease 错误由心跳兜住', async () => {
  const seen: Array<{ name: string, args: Record<string, unknown> | undefined }> = []
  const adapter = new NdrTaskPortAdapter({
    async callTool(name, args) {
      seen.push({ name, args })
      if (name === 'renew_task_lease') throw new Error('unknown tool')
      return { ok: true }
    },
  })
  await adapter.deferTask('task-1', 'model_unavailable', { retryAfterSeconds: 180 })
  assert.deepEqual(seen[0], {
    name: 'defer_task',
    args: { task_id: 'task-1', reason: 'model_unavailable', retry_after_seconds: 180 },
  })
  await assert.rejects(() => Promise.resolve(adapter.renewLease?.('task-1')), /unknown tool/u)
})
