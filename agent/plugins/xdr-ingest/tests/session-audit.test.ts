import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { parseSessionAudit, redactText } from '../src/session-audit.ts'

function line(value: Record<string, unknown>): string {
  return JSON.stringify(value)
}

const events = [
  line({ type: 'turn/start', seq: 1, time: 1_000, data: { turn: 1 } }),
  line({ type: 'step/start', seq: 2, time: 1_001, data: { turn: 1, step: 1 } }),
  line({
    type: 'request/header',
    seq: 3,
    time: 1_002,
    data: { header: { config: { provider: 'p', model: 'm' } }, reason: 'initial' },
  }),
  line({
    type: 'tool/call',
    seq: 4,
    time: 1_100,
    data: {
      turn: 1,
      step: 1,
      callId: 'c1',
      name: 'task_facts',
      arguments: '{"authorization":"Bearer super-secret-token"}',
    },
  }),
  line({
    type: 'tool/call',
    seq: 5,
    time: 1_150,
    data: { turn: 1, step: 1, callId: 'c2', name: 'search_events', arguments: '{"q":"x"}' },
  }),
  line({
    type: 'tool/result',
    seq: 6,
    time: 1_300,
    data: {
      turn: 1,
      step: 1,
      message: { role: 'tool', toolCallId: 'c2', content: [{ type: 'text', text: 'ok' }] },
    },
  }),
  line({
    type: 'tool/result',
    seq: 7,
    time: 1_250,
    data: {
      turn: 1,
      step: 1,
      message: { role: 'tool', toolCallId: 'c1', isError: true, content: [{ type: 'text', text: 'password=hunter2 failed' }] },
      error: { reason: 'timeout' },
    },
  }),
  line({
    type: 'assistant/message',
    seq: 8,
    time: 1_400,
    data: {
      turn: 1,
      step: 1,
      message: { role: 'assistant', content: [] },
      usage: { inputTokens: 10, outputTokens: 4, cacheReadTokens: 2 },
    },
  }),
  line({ type: 'turn/end', seq: 9, time: 1_500, data: { turn: 1, reason: { kind: 'max-tokens' } } }),
].join('\n')

test('session audit: pairs tool calls by callId and keeps turn reason', () => {
  const audit = parseSessionAudit(events, 's1')
  assert.equal(audit.ok, true)
  assert.equal(audit.turns, 1)
  assert.equal(audit.steps, 1)
  assert.equal(audit.model, 'p/m')
  assert.equal(audit.toolCount, 2)
  assert.equal(audit.toolErrors, 1)
  assert.equal(audit.toolCalls[0]?.callId, 'c1')
  assert.equal(audit.toolCalls[0]?.durationMs, 150)
  assert.equal(audit.toolCalls[0]?.isError, true)
  assert.equal(audit.toolCalls[1]?.durationMs, 150)
  assert.equal(audit.tokens.total, 16)
  assert.deepEqual(audit.turnEnds.map(item => item.reason), ['max-tokens'])
  assert.equal(audit.redacted, true)
})

test('session audit: secrets never survive redaction', () => {
  assert.equal(redactText('Cookie: abc123'), 'Cookie: [REDACTED]')
  assert.equal(redactText('Authorization: Bearer abcdefghijklmnop'), 'Authorization: [REDACTED]')
  assert.ok(!redactText('token=abc123').includes('abc123'))
  const audit = parseSessionAudit(events, 's1')
  assert.ok(!JSON.stringify(audit).includes('hunter2'))
  assert.ok(!JSON.stringify(audit).includes('super-secret-token'))
})

test('session audit: no-session decisions are still representable', () => {
  const audit = parseSessionAudit('', '')
  assert.equal(audit.ok, true)
  assert.equal(audit.toolCount, 0)
  assert.equal(audit.tokens.reported, false)
})
