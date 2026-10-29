import { strict as assert } from 'node:assert'
import { afterEach, test } from 'node:test'
import { Bridge, createServer } from '../src/server.js'

const RAW_MODELS = [
  {
    providerID: 'opencode',
    id: 'deepseek-v4.1-flash-free',
    name: 'DeepSeek V4.1 Flash Free',
    enabled: true,
    capabilities: { output: ['text'], tools: true },
    cost: [{ input: 0, output: 0 }],
    limit: { context: 200000 },
  },
]

class FakeRuntime {
  constructor({ script = [], raw = RAW_MODELS } = {}) {
    this.version = '2.0.18'
    this.script = [...script]
    this.raw = raw
    this.prompts = []
    this.current = []
    this.deleted = 0
    this.interrupted = 0
  }

  async rawModels() {
    return this.raw
  }

  async createSession() {
    this.current = []
    return `s-${this.deleted + 1}`
  }

  async setModel(_id, model) {
    this.model = model
  }

  async prompt(_id, text) {
    this.prompts.push(text)
    const item = this.script.shift()
    if (item === undefined) return
    if (item.error !== undefined) {
      this.current.push({ type: 'assistant', content: [], error: { message: item.error, status: item.status } })
      return
    }
    this.current.push({
      type: 'assistant',
      content: [{ type: 'text', text: item.text }],
      tokens: item.tokens ?? { input: 10, output: 5 },
    })
  }

  async wait() {}

  async messages() {
    return [...this.current]
  }

  async pendingPermissions() {
    return []
  }

  async rejectPermission() {}

  async interrupt() {
    this.interrupted += 1
  }

  async deleteSession() {
    this.deleted += 1
  }
}

const servers = []

afterEach(async () => {
  while (servers.length > 0) {
    const server = servers.pop()
    await new Promise(resolve => server.close(resolve))
  }
})

function config(over = {}) {
  return {
    apiKey: 'test-key',
    maxConcurrency: 2,
    maxRequestsPerDay: 200,
    includeChatOnly: false,
    refreshMs: 600_000,
    ...over,
  }
}

async function start({ script, raw, config: over } = {}) {
  const runtime = new FakeRuntime({ script, raw })
  const bridge = new Bridge({
    config: config(over),
    runtime,
    log: () => {},
    now: () => Date.parse('2026-10-30T00:00:00Z'),
  })
  await bridge.refreshCatalog()
  const server = createServer(bridge)
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  servers.push(server)
  const base = `http://127.0.0.1:${server.address().port}`
  return { bridge, runtime, base }
}

function chatBody(over = {}) {
  return {
    model: 'deepseek-v4.1-flash-free',
    messages: [{ role: 'user', content: '看看 10.1.1.10' }],
    tools: [
      {
        type: 'function',
        function: {
          name: 'complete_task',
          parameters: { type: 'object', properties: { verdict: { type: 'string' } } },
        },
      },
    ],
    ...over,
  }
}

function envelope() {
  return JSON.stringify({
    content: '',
    calls: [{ name: 'complete_task', arguments: { verdict: 'benign' } }],
  })
}

test('/health 不需要鉴权，/v1/models 需要', async () => {
  const { base } = await start({ script: [] })
  const health = await fetch(`${base}/health`)
  assert.equal(health.status, 200)
  const unauth = await fetch(`${base}/v1/models`)
  assert.equal(unauth.status, 401)
  const models = await fetch(`${base}/v1/models`, {
    headers: { authorization: 'Bearer test-key' },
  })
  assert.equal(models.status, 200)
  const body = await models.json()
  assert.deepEqual(body.data.map(row => row.id), ['deepseek-v4.1-flash-free'])
})

test('浏览器 Origin 一律拒绝', async () => {
  const { base } = await start({ script: [] })
  const response = await fetch(`${base}/v1/models`, {
    headers: { authorization: 'Bearer test-key', origin: 'https://evil.example' },
  })
  assert.equal(response.status, 403)
})

test('非流式：模型信封转成 tool_calls', async () => {
  const { base, runtime } = await start({ script: [{ text: envelope() }] })
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: 'Bearer test-key', 'content-type': 'application/json' },
    body: JSON.stringify(chatBody()),
  })
  assert.equal(response.status, 200)
  const body = await response.json()
  assert.equal(body.choices[0].finish_reason, 'tool_calls')
  assert.equal(body.choices[0].message.tool_calls[0].function.name, 'complete_task')
  assert.equal(body.usage.total_tokens, 15)
  assert.equal(runtime.deleted, 1, '请求结束必须删 session')
})

test('格式不合格会纠正一次，成功后计数 escalations', async () => {
  const { base, bridge, runtime } = await start({
    script: [{ text: '不是 JSON' }, { text: envelope() }],
  })
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: 'Bearer test-key', 'content-type': 'application/json' },
    body: JSON.stringify(chatBody()),
  })
  assert.equal(response.status, 200)
  assert.equal(runtime.prompts.length, 2)
  assert.match(runtime.prompts[1], /没有通过格式校验/u)
  assert.equal(bridge.counters.invalid, 1)
  assert.equal(bridge.counters.escalated, 1)
})

test('两次都不合格 → 502 invalid_model_output', async () => {
  const { base } = await start({ script: [{ text: 'nope' }, { text: 'still nope' }] })
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: 'Bearer test-key', 'content-type': 'application/json' },
    body: JSON.stringify(chatBody()),
  })
  assert.equal(response.status, 502)
  const body = await response.json()
  assert.equal(body.error.code, 'invalid_model_output')
})

test('上游 429 原样映射（免费额度用尽）', async () => {
  const { base } = await start({ script: [{ error: 'Free usage limit reached', status: 429 }] })
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: 'Bearer test-key', 'content-type': 'application/json' },
    body: JSON.stringify(chatBody()),
  })
  assert.equal(response.status, 429)
  const body = await response.json()
  assert.equal(body.error.code, 'free_quota')
})

test('每日预算用完 → 429 daily_budget，不再发上游请求', async () => {
  const { base, runtime } = await start({
    script: [{ text: envelope() }],
    config: { maxRequestsPerDay: 1 },
  })
  const first = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: 'Bearer test-key', 'content-type': 'application/json' },
    body: JSON.stringify(chatBody()),
  })
  assert.equal(first.status, 200)
  const second = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: 'Bearer test-key', 'content-type': 'application/json' },
    body: JSON.stringify(chatBody()),
  })
  assert.equal(second.status, 429)
  assert.equal((await second.json()).error.code, 'daily_budget')
  assert.equal(runtime.prompts.length, 1, '预算耗尽后不能继续打上游')
})

test('未知模型 → 400 model_not_found', async () => {
  const { base } = await start({ script: [] })
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: 'Bearer test-key', 'content-type': 'application/json' },
    body: JSON.stringify(chatBody({ model: 'opencode/nope' })),
  })
  assert.equal(response.status, 400)
  assert.equal((await response.json()).error.code, 'model_not_found')
})

test('流式：先 role 块，最后 [DONE]', async () => {
  const { base } = await start({ script: [{ text: envelope() }] })
  const response = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: 'Bearer test-key', 'content-type': 'application/json' },
    body: JSON.stringify(chatBody({ stream: true, stream_options: { include_usage: true } })),
  })
  assert.equal(response.status, 200)
  assert.match(response.headers.get('content-type'), /text\/event-stream/u)
  const text = await response.text()
  assert.match(text, /"role":"assistant"/u)
  assert.match(text, /tool_calls/u)
  assert.match(text, /"usage"/u)
  assert.match(text, /\[DONE\]/u)
})

test('auth 关闭模式（仅测试）可用', async () => {
  const { base } = await start({ script: [{ text: envelope() }], config: { apiKey: '' } })
  const response = await fetch(`${base}/v1/models`)
  assert.equal(response.status, 200)
})
