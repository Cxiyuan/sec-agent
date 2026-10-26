/**
 * MCP 客户端线上报文形态（2026-07-28 版规范）。
 *
 * 这几条是「本地单测全绿、上机第一次调用就挂」的典型，必须钉住：
 * 1. **没有 `initialize` 握手** —— 这一版把版本/能力改成每个请求的 `params._meta`，
 *    先发 initialize 会得到 `Method not found (data: "initialize")`（实测）。
 * 2. `params._meta` 必须同时带 protocolVersion 与 clientCapabilities 两个固定键，
 *    否则服务端 400（实测原话：params._meta must be an object carrying the required ...）。
 * 3. 每个请求要带路由头 `mcp-method`，`tools/call` 还要带 `mcp-name`，
 *    服务端会拿它与 JSON-RPC body 比对，不一致同样 400。
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { McpHttpClient } from '../src/mcp-http.ts'

interface Captured {
  readonly url: string
  readonly headers: Record<string, string>
  readonly body: Record<string, unknown>
}

function stubFetch(captured: Captured[], reply: unknown) {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>
    captured.push({
      url: String(url),
      headers,
      body: JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>,
    })
    return new Response(JSON.stringify(reply), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }) as unknown as typeof fetch
}

test('tools/call goes out with routing headers and _meta, without an initialize step', async () => {
  const captured: Captured[] = []
  const client = new McpHttpClient({
    url: 'http://ndr-mcp:8090/mcp',
    token: 'stmcp_x',
    fetchImpl: stubFetch(captured, {
      jsonrpc: '2.0',
      id: 1,
      result: { content: [{ type: 'text', text: '{"ok":true}' }] },
    }),
  })
  const out = await client.callTool('claim_tasks', { limit: 2 })
  assert.deepEqual(out, { ok: true })

  assert.equal(captured.length, 1, '不该有 initialize 之类的额外往返')
  const call = captured[0]
  assert.equal(call.body['method'], 'tools/call')
  assert.equal(call.headers['mcp-method'], 'tools/call')
  assert.equal(call.headers['mcp-name'], 'claim_tasks')
  assert.equal(call.headers['mcp-protocol-version'], '2026-07-28')
  assert.equal(call.headers['authorization'], 'Bearer stmcp_x')

  const params = call.body['params'] as Record<string, unknown>
  assert.deepEqual(params['arguments'], { limit: 2 })
  const meta = params['_meta'] as Record<string, unknown>
  assert.equal(meta['io.modelcontextprotocol/protocolVersion'], '2026-07-28')
  assert.ok('io.modelcontextprotocol/clientCapabilities' in meta, '_meta 必须带能力键')
})

test('plain-text tool results are preserved instead of pretending to parse', async () => {
  const captured: Captured[] = []
  const client = new McpHttpClient({
    url: 'http://x/mcp',
    token: 't',
    fetchImpl: stubFetch(captured, {
      jsonrpc: '2.0',
      id: 1,
      result: { content: [{ type: 'text', text: 'not json' }] },
    }),
  })
  assert.deepEqual(await client.callTool('task_state', { task_id: 'x' }), { text: 'not json' })
})

test('JSON-RPC errors surface as McpError with the server message', async () => {
  const captured: Captured[] = []
  const client = new McpHttpClient({
    url: 'http://x/mcp',
    token: 't',
    fetchImpl: stubFetch(captured, {
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32602, message: 'params._meta is required' },
    }),
  })
  await assert.rejects(
    () => client.callTool('claim_tasks', {}),
    (error: Error) => error.message.includes('_meta'),
  )
})

test('ndr double-wrapped receipts are unwrapped (the reason must reach the caller)', async () => {
  // 实测踩过：NDR 工具返回 {result: "<json string>"}，只剥一层的话
  // inflight_full 留在里层，调用方看到的是「没 reason 的空回执」→ 静默。
  const captured: Captured[] = []
  const client = new McpHttpClient({
    url: 'http://x/mcp',
    token: 't',
    fetchImpl: stubFetch(captured, {
      jsonrpc: '2.0',
      id: 1,
      result: {
        content: [{
          type: 'text',
          text: JSON.stringify({
            result: JSON.stringify({ tasks: [], reason: 'inflight_full', budget: { inflight: 2 } }),
          }),
        }],
      },
    }),
  })
  const reply = await client.callTool('claim_tasks', { limit: 1 })
  assert.equal(reply['reason'], 'inflight_full', '里层的 reason 必须浮到顶层')
  assert.deepEqual(reply['budget'], { inflight: 2 })
})

test('already-flat receipts pass through without a second unwrap', async () => {
  const captured: Captured[] = []
  const client = new McpHttpClient({
    url: 'http://x/mcp',
    token: 't',
    fetchImpl: stubFetch(captured, {
      jsonrpc: '2.0',
      id: 1,
      result: { content: [{ type: 'text', text: '{"tasks":[],"reason":"queue_empty"}' }] },
    }),
  })
  assert.equal((await client.callTool('claim_tasks', {}))['reason'], 'queue_empty')
})

test('structuredContent path unwraps the ndr envelope too (it returns early!)', async () => {
  // 上一轮修复只处理了 content[].text 分支；服务端 structuredContent 也给
  // {result:"<json>"}，而那个分支提前返回 —— reason 仍留在里层。必须同剥。
  const captured: Captured[] = []
  const client = new McpHttpClient({
    url: 'http://x/mcp',
    token: 't',
    fetchImpl: stubFetch(captured, {
      jsonrpc: '2.0',
      id: 1,
      result: {
        content: [{ type: 'text', text: 'ignored' }],
        structuredContent: {
          result: JSON.stringify({ tasks: [], reason: 'budget_exhausted' }),
        },
      },
    }),
  })
  const reply = await client.callTool('claim_tasks', {})
  assert.equal(reply['reason'], 'budget_exhausted')
})
