/** 门铃载荷解析：区分"不是门铃"与"门铃坏了"——前者走旧摘要路径，后者必须 400。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { DoorbellFormatError, parseDoorbell } from '../src/doorbell.ts'

const valid = {
  doorbell: {
    queue_len: 137,
    top_kind: 'shift',
    max_strength: 0.92,
    watermark: '2026-10-21T12:15:00Z',
    ts: '2026-10-21T12:15:03Z',
  },
}

test('parses a valid doorbell', () => {
  const bell = parseDoorbell(valid)
  assert.notEqual(bell, null)
  assert.equal(bell?.queue_len, 137)
  assert.equal(bell?.top_kind, 'shift')
  assert.equal(bell?.max_strength, 0.92)
  assert.equal(bell?.watermark, '2026-10-21T12:15:00Z')
})

test('legacy digest payload is not a doorbell (returns null, not an error)', () => {
  assert.equal(parseDoorbell({ items: [] }), null)
  assert.equal(parseDoorbell(null), null)
  assert.equal(parseDoorbell('nope'), null)
  assert.equal(parseDoorbell([1, 2]), null)
})

test('malformed doorbell throws (must 400, not silently acknowledge)', () => {
  // 坏门铃被当成成功回执会导致「线索静默丢失」，所以必须报错让 NDR 看见
  assert.throws(() => parseDoorbell({ doorbell: 'x' }), DoorbellFormatError)
  assert.throws(() => parseDoorbell({ doorbell: {} }), DoorbellFormatError)
  assert.throws(
    () => parseDoorbell({ doorbell: { ...valid.doorbell, queue_len: 'many' } }),
    DoorbellFormatError,
  )
  assert.throws(
    () => parseDoorbell({ doorbell: { ...valid.doorbell, queue_len: -1 } }),
    DoorbellFormatError,
  )
  assert.throws(
    () => parseDoorbell({ doorbell: { ...valid.doorbell, watermark: 1 } }),
    DoorbellFormatError,
  )
})

test('unknown/extra fields are tolerated but bounded', () => {
  // 未来 NDR 加字段不该让老插件 500；但长度必须截断（防止有人用它塞大载荷）
  const bell = parseDoorbell({
    doorbell: { ...valid.doorbell, top_kind: 'x'.repeat(500), extra: 'ignored' },
  })
  assert.equal(bell?.top_kind.length, 32)
})
