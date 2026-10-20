/** 事件分析 ID 生成的测试：确定性、跨窗口稳定、指标敏感性。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { analysisIdOf, identityKey, normalizeDigest } from '../src/identity.ts'
import type { NdrDigest } from '../src/types.ts'

function digest(overrides: Partial<NdrDigest> = {}): NdrDigest {
  return {
    rule: 'ET SCAN Suricata Portscan',
    src_ip: '203.0.113.7',
    dst_ips: ['10.0.0.5', '10.0.0.6'],
    dst_ports: [22, 80, 443],
    event_types: ['alert', 'flow'],
    count: 17,
    first_seen: '2026-10-21T00:00:00+08:00',
    last_seen: '2026-10-21T00:12:00+08:00',
    samples: [],
    ...overrides,
  }
}

test('analysis id has the EA- prefix and 32 hex chars', () => {
  const identity = normalizeDigest(digest())
  assert.ok(identity !== null)
  const id = analysisIdOf(identity)
  assert.match(id, /^EA-[0-9a-f]{32}$/)
})

test('same content different windows (first_seen/last_seen/count) yields the same id', () => {
  const a = normalizeDigest(digest())
  const b = normalizeDigest(digest({
    count: 99,
    first_seen: '2026-10-21T08:00:00+08:00',
    last_seen: '2026-10-21T08:30:00+08:00',
  }))
  assert.ok(a !== null && b !== null)
  assert.equal(analysisIdOf(a), analysisIdOf(b))
})

test('volatile fields (samples, real_client_ips, proxied, conn_states) do not affect the id', () => {
  const a = normalizeDigest(digest())
  const b = normalizeDigest(digest({
    samples: [{ x: 1 }],
    real_client_ips: ['198.51.100.9'],
    proxied: true,
    conn_states: ['S1'],
  }))
  assert.ok(a !== null && b !== null)
  assert.equal(analysisIdOf(a), analysisIdOf(b))
})

test('a new target changes the id (new behavior must be analyzed)', () => {
  const a = normalizeDigest(digest())
  const b = normalizeDigest(digest({ dst_ips: ['10.0.0.5', '10.0.0.6', '10.0.0.7'] }))
  assert.ok(a !== null && b !== null)
  assert.notEqual(analysisIdOf(a), analysisIdOf(b))
})

test('a new port changes the id', () => {
  const a = normalizeDigest(digest())
  const b = normalizeDigest(digest({ dst_ports: [22, 80, 443, 8080] }))
  assert.ok(a !== null && b !== null)
  assert.notEqual(analysisIdOf(a), analysisIdOf(b))
})

test('a different rule changes the id even with the same tuple', () => {
  const a = normalizeDigest(digest())
  const b = normalizeDigest(digest({ rule: 'ET SCAN Nmap SIP' }))
  assert.ok(a !== null && b !== null)
  assert.notEqual(analysisIdOf(a), analysisIdOf(b))
})

test('a different source changes the id', () => {
  const a = normalizeDigest(digest())
  const b = normalizeDigest(digest({ src_ip: '203.0.113.8' }))
  assert.ok(a !== null && b !== null)
  assert.notEqual(analysisIdOf(a), analysisIdOf(b))
})

test('normalization is order-insensitive for target/port/type sets', () => {
  const a = normalizeDigest(digest({ dst_ips: ['10.0.0.6', '10.0.0.5'], dst_ports: [443, 22, 80] }))
  const b = normalizeDigest(digest({ dst_ips: ['10.0.0.5', '10.0.0.6'], dst_ports: [80, 443, 22] }))
  assert.ok(a !== null && b !== null)
  assert.equal(analysisIdOf(a), analysisIdOf(b))
})

test('ip addresses are lowercased (IPv6 case normalization)', () => {
  const a = normalizeDigest(digest({ src_ip: '2001:DB8::1' }))
  const b = normalizeDigest(digest({ src_ip: '2001:db8::1' }))
  assert.ok(a !== null && b !== null)
  assert.equal(analysisIdOf(a), analysisIdOf(b))
})

test('identity caps at 20 dsts / 20 ports / 10 event types like the NDR fingerprint', () => {
  const manyDsts = Array.from({ length: 25 }, (_, i) => `10.0.1.${i}`)
  const a = normalizeDigest(digest({ dst_ips: manyDsts }))
  const b = normalizeDigest(digest({ dst_ips: manyDsts.slice(0, 20) }))
  assert.ok(a !== null && b !== null)
  assert.equal(a.dstIps.length, 20)
  assert.equal(analysisIdOf(a), analysisIdOf(b))
})

test('digest without rule/src/targets/types is rejected (null identity)', () => {
  assert.equal(normalizeDigest({ rule: '', src_ip: '' }), null)
  assert.equal(normalizeDigest({}), null)
})

test('identityKey mirrors the NDR fingerprint tuple minus the time bucket', () => {
  const identity = normalizeDigest(digest())
  assert.ok(identity !== null)
  assert.equal(identityKey(identity), 'ET SCAN Suricata Portscan|203.0.113.7|10.0.0.5,10.0.0.6|22,443,80|alert,flow')
})
