import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import {
  BridgeError,
  buildPrompt,
  completion,
  correctionPrompt,
  parseEnvelope,
  readAssistant,
  validateRequest,
} from '../src/translate.js'

const tools = [
  {
    type: 'function',
    function: {
      name: 'complete_task',
      description: '交回结论',
      parameters: { type: 'object', properties: { verdict: { type: 'string' } }, required: ['verdict'] },
    },
  },
]

function body(over = {}) {
  return {
    model: 'deepseek-v4.1-flash-free',
    messages: [
      { role: 'system', content: '你是分析员' },
      { role: 'user', content: '看看这个资产' },
    ],
    tools,
    ...over,
  }
}

test('validateRequest：接受标准请求并归一化字段', () => {
  const request = validateRequest(body())
  assert.equal(request.model, 'deepseek-v4.1-flash-free')
  assert.equal(request.tools.length, 1)
  assert.equal(request.parallel, true)
  assert.equal(request.stream, false)
})

test('validateRequest：拒绝非法请求', () => {
  assert.throws(() => validateRequest({ messages: [] }), BridgeError)
  assert.throws(() => validateRequest(body({ messages: [{ role: 'robot', content: 'x' }] })), BridgeError)
  assert.throws(() => validateRequest(body({ tools: [{ type: 'function', function: {} }] })), BridgeError)
  assert.throws(() => validateRequest(body({ tool_choice: 'bad' })), BridgeError)
  assert.throws(
    () => validateRequest(body({ tool_choice: { type: 'function', function: { name: 'nope' } } })),
    BridgeError,
  )
})

test('buildPrompt：带工具清单、强制规则和完整对话', () => {
  const request = validateRequest(body())
  const prompt = buildPrompt(request)
  assert.match(prompt, /只输出一个 JSON 对象/u)
  assert.match(prompt, /complete_task/u)
  assert.match(prompt, /<external_conversation>/u)
  assert.match(prompt, /看看这个资产/u)
})

test('parseEnvelope：接受 fences 与前缀噪声', () => {
  const request = validateRequest(body())
  const parsed = parseEnvelope('```json\n{"content":"ok","calls":[]}\n```', request)
  assert.equal(parsed.content, 'ok')
  assert.deepEqual(parsed.calls, [])
  const noisy = parseEnvelope('思考：先看看。\n{"content":"","calls":[{"name":"complete_task","arguments":{"verdict":"benign"}}]}', request)
  assert.equal(noisy.calls[0].name, 'complete_task')
  assert.deepEqual(noisy.calls[0].arguments, { verdict: 'benign' })
})

test('parseEnvelope：拒绝未提供的工具/非法参数/强行并行', () => {
  const request = validateRequest(body())
  assert.throws(
    () => parseEnvelope('{"content":"","calls":[{"name":"shell","arguments":{}}]}', request),
    /未提供的工具/u,
  )
  assert.throws(
    () => parseEnvelope('{"content":"","calls":[{"name":"complete_task","arguments":"oops"}]}', request),
    /参数不是合法 JSON/u,
  )
  assert.throws(() => parseEnvelope('not json', request), BridgeError)
  const strict = validateRequest(body({ parallel_tool_calls: false }))
  assert.throws(
    () => parseEnvelope(
      '{"content":"","calls":[{"name":"complete_task","arguments":{}},{"name":"complete_task","arguments":{}}]}',
      strict,
    ),
    /不允许并行/u,
  )
})

test('parseEnvelope：tool_choice=none 不许调用工具', () => {
  const request = validateRequest(body({ tool_choice: 'none' }))
  assert.throws(
    () => parseEnvelope('{"content":"","calls":[{"name":"complete_task","arguments":{}}]}', request),
    /tool_choice=none/u,
  )
})

test('completion：工具调用转成 OpenAI tool_calls，纯文本不带 tool_calls', () => {
  const withCall = completion('m', { content: '', calls: [{ name: 'complete_task', arguments: { verdict: 'benign' } }] }, { input: 3, output: 4 })
  assert.equal(withCall.choices[0].finish_reason, 'tool_calls')
  assert.equal(withCall.choices[0].message.tool_calls[0].function.name, 'complete_task')
  assert.equal(withCall.usage.total_tokens, 7)
  const text = completion('m', { content: '结论', calls: [] }, null)
  assert.equal(text.choices[0].message.content, '结论')
  assert.equal(text.choices[0].message.tool_calls, undefined)
  assert.equal(text.usage, undefined)
})

test('readAssistant：区分正常文本、错误与原生工具', () => {
  const ok = readAssistant({ type: 'assistant', content: [{ type: 'text', text: 'hi' }], tokens: { input: 1, output: 2 } })
  assert.equal(ok.text, 'hi')
  const failed = readAssistant({ type: 'assistant', content: [], error: { message: 'free limit', status: 429 } })
  assert.equal(failed.error.status, 429)
  const native = readAssistant({ type: 'assistant', content: [{ type: 'tool', name: 'shell' }] })
  assert.equal(native.toolParts.length, 1)
})

test('correctionPrompt：包含失败原因与工具白名单', () => {
  const request = validateRequest(body())
  const prompt = correctionPrompt(new Error('bad envelope'), request)
  assert.match(prompt, /bad envelope/u)
  assert.match(prompt, /complete_task/u)
})
