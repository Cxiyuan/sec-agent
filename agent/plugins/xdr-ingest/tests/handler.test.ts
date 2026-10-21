/** HTTP 层集成测试：真实 socket 上对齐 NDR 推送契约的行为。 */

import { strict as assert } from 'node:assert'
import { createServer, type Server } from 'node:http'
import { test } from 'node:test'
import { TieredCache } from '../src/cache.ts'
import { createIngestHandler } from '../src/handler.ts'
import { MemoryColdStore } from '../src/store.ts'

const BASE = '/xdr/ingest'
const TOKEN = 'test-token-123'

function makeApp(overrides: Partial<{ token: string; maxBodyBytes: number; store: MemoryColdStore }> = {}) {
  const store = overrides.store ?? new MemoryColdStore()
  const cache = new TieredCache({ ttlMs: 3_600_000, hotMaxEntries: 100, hotThreshold: 2, store })
  const handler = createIngestHandler(BASE, {
    token: overrides.token ?? TOKEN,
    maxBodyBytes: overrides.maxBodyBytes ?? 64 * 1024,
    cache,
  })
  return { server: createServer(handler), cache, store }
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  assert.ok(address !== null && typeof address === 'object')
  return `http://127.0.0.1:${address.port}`
}

function itemsPayload(count = 1): string {
  const items = Array.from({ length: count }, (_, i) => ({
    event_id: `evt-${i}`,
    fingerprint: `ndr-fp-${i}`,
    digest: {
      rule: 'ET SCAN Portscan',
      src_ip: '203.0.113.7',
      dst_ips: ['10.0.0.5'],
      dst_ports: [22, 80],
      event_types: ['alert'],
      count: 5,
      first_seen: '2026-10-21T00:00:00+08:00',
      last_seen: '2026-10-21T00:05:00+08:00',
    },
  }))
  return JSON.stringify({ items })
}

async function withServer<T>(fn: (base: string) => Promise<T>): Promise<T> {
  const { server } = makeApp()
  const base = await listen(server)
  try {
    return await fn(base)
  } finally {
    server.close()
  }
}

test('GET ping with bearer token answers 200 ok', async () => {
  await withServer(async base => {
    const response = await fetch(`${base}${BASE}/ping`, { headers: { authorization: `Bearer ${TOKEN}` } })
    assert.equal(response.status, 200)
    assert.equal(await response.text(), 'ok')
  })
})

test('GET ping without token is 401 (NDR marks config error instead of retrying)', async () => {
  await withServer(async base => {
    const response = await fetch(`${base}${BASE}/ping`)
    assert.equal(response.status, 401)
  })
})

test('POST digests with wrong token is 401', async () => {
  await withServer(async base => {
    const response = await fetch(`${base}${BASE}/digests`, {
      method: 'POST',
      headers: { authorization: 'Bearer wrong', 'content-type': 'application/json' },
      body: itemsPayload(),
    })
    assert.equal(response.status, 401)
  })
})

test('empty configured token refuses everything with 401', async () => {
  const { server } = makeApp({ token: '' })
  const base = await listen(server)
  try {
    const response = await fetch(`${base}${BASE}/digests`, {
      method: 'POST',
      headers: { authorization: 'Bearer anything', 'content-type': 'application/json' },
      body: itemsPayload(),
    })
    assert.equal(response.status, 401)
    assert.match(await response.text(), /not configured/)
  } finally {
    server.close()
  }
})

test('POST malformed JSON is 400; wrong shape is 400; oversized body is 413', async () => {
  await withServer(async base => {
    const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' }
    const bad = await fetch(`${base}${BASE}/digests`, { method: 'POST', headers, body: '{nope' })
    assert.equal(bad.status, 400)
    const shape = await fetch(`${base}${BASE}/digests`, { method: 'POST', headers, body: '{"no":[]}' })
    assert.equal(shape.status, 400)
    const big = await fetch(`${base}${BASE}/digests`, {
      method: 'POST', headers, body: 'x'.repeat(65 * 1024),
    })
    assert.equal(big.status, 413)
  })
})

test('first batch analyzes; identical second batch is reused with occurrence count', async () => {
  await withServer(async base => {
    const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' }
    const first = await fetch(`${base}${BASE}/digests`, { method: 'POST', headers, body: itemsPayload() })
    assert.equal(first.status, 200)
    const firstReceipt = await first.json() as { accepted: number; analyzed: number; reused: number; results: Array<{ analysisId: string; reused: boolean; occurrences: number }> }
    assert.equal(firstReceipt.accepted, 1)
    assert.equal(firstReceipt.analyzed, 1)
    assert.equal(firstReceipt.reused, 0)
    assert.match(firstReceipt.results[0]?.analysisId ?? '', /^EA-[0-9a-f]{32}$/)

    const second = await fetch(`${base}${BASE}/digests`, { method: 'POST', headers, body: itemsPayload() })
    const secondReceipt = await second.json() as typeof firstReceipt
    assert.equal(second.status, 200)
    assert.equal(secondReceipt.reused, 1)
    assert.equal(secondReceipt.analyzed, 0)
    assert.equal(secondReceipt.results[0]?.occurrences, 2)
    assert.equal(secondReceipt.results[0]?.analysisId, firstReceipt.results[0]?.analysisId)
  })
})

test('a digest without any identity fields is rejected inside a 200 receipt', async () => {
  await withServer(async base => {
    const response = await fetch(`${base}${BASE}/digests`, {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
      body: JSON.stringify({ items: [{ event_id: 'evt-bad', digest: {} }] }),
    })
    assert.equal(response.status, 200)
    const receipt = await response.json() as { accepted: number; rejected: number; results: Array<{ error?: string }> }
    assert.equal(receipt.accepted, 0)
    assert.equal(receipt.rejected, 1)
    assert.match(receipt.results[0]?.error ?? '', /identity/)
  })
})

test('GET stats reports tier sizes and counters; unknown path is 404; GET digests is 405', async () => {
  await withServer(async base => {
    const headers = { authorization: `Bearer ${TOKEN}` }
    const stats = await fetch(`${base}${BASE}/stats`, { headers })
    assert.equal(stats.status, 200)
    const body = await stats.json() as { hotSize: number; coldSize: number; storeKind: string; analyzed: number; reused: number; reanalyzed: number }
    assert.equal(body.hotSize, 0)
    assert.equal(body.coldSize, 0)
    assert.equal(body.storeKind, 'memory')

    const missing = await fetch(`${base}/nope`, { headers })
    assert.equal(missing.status, 404)

    const wrongMethod = await fetch(`${base}${BASE}/digests`, { headers })
    assert.equal(wrongMethod.status, 405)
  })
})

test('cold store survives a "restart": a fresh app over the same store reuses without re-analysis', async () => {
  const store = new MemoryColdStore()
  const headers = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' }

  const first = makeApp({ store })
  const firstBase = await listen(first.server)
  try {
    const response = await fetch(`${firstBase}${BASE}/digests`, { method: 'POST', headers, body: itemsPayload() })
    assert.equal(response.status, 200)
  } finally {
    first.server.close()
  }

  // 模拟重启：全新 app（热层空），冷库（PG）不变
  const second = makeApp({ store })
  const secondBase = await listen(second.server)
  try {
    const response = await fetch(`${secondBase}${BASE}/digests`, { method: 'POST', headers, body: itemsPayload() })
    const receipt = await response.json() as { analyzed: number; reused: number; results: Array<{ occurrences: number }> }
    assert.equal(receipt.analyzed, 0, 'restart must not re-analyze persisted events')
    assert.equal(receipt.reused, 1)
    assert.equal(receipt.results[0]?.occurrences, 2)
  } finally {
    second.server.close()
  }
})
