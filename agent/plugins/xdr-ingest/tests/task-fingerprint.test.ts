import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import type { ClaimedTask } from '../src/claim-loop.ts'
import { taskFingerprint } from '../src/task-fingerprint.ts'

const task: ClaimedTask = {
  id: 'task-1',
  kind: 'hit',
  strength: 0.7,
  subject_kind: 'ip',
  subject: '10.0.0.5',
  window_start: '2026-11-05T00:00:00Z',
  window_end: '2026-11-05T01:00:00Z',
  hint: { b: 2, a: 1, reuse_identity: 'hit|ip:10.0.0.5|rule' },
}

test('fingerprint ignores object key order but tracks task facts', () => {
  const a = taskFingerprint(task, null)
  const b = taskFingerprint({ ...task, hint: { reuse_identity: 'hit|ip:10.0.0.5|rule', a: 1, b: 2 } }, null)
  assert.equal(a, b)
  assert.notEqual(a, taskFingerprint({ ...task, coalesced: 1 }, null))
  assert.notEqual(a, taskFingerprint({ ...task, strength: 0.8 }, null))
  assert.notEqual(a, taskFingerprint({ ...task, subject: '10.0.0.6' }, null))
})

test('fingerprint changes when the workflow changes', () => {
  const a = taskFingerprint(task, null)
  const workflow = {
    workflowId: 'wf-1',
    name: '默认',
    description: '',
    stages: [{ title: '取证', goal: '', guidance: '', tools: [] }],
    enabled: true,
    isDefault: true,
    createdAt: '',
    updatedAt: '',
    updatedBy: '',
  }
  assert.notEqual(a, taskFingerprint(task, workflow))
})
