/**
 * llm-agg 线协议转换的离线单测：请求投影、SSE 解帧、流式翻译、用量与失败分类。
 *
 * 这些测试刻意只 import `src/wire.ts`（纯模块），不加载 dsh 运行时，也不需要
 * 网络。真实网关的端到端验证由部署机完成。
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import {
  ChatStreamTranslator,
  SseDecoder,
  finishReasonOf,
  providerFailure,
  toChatRequest,
  toChatTools,
  toTokenUsage,
  translateCompletion,
  WireError,
} from '../src/wire.ts'

/** 造一条 user 消息（字段形状与 dsh 的 Message 对齐）。 */
function user(content: any[]) {
  return { id: 'm-user', role: 'user', source: { kind: 'user' }, content }
}

/** 造一条 assistant 消息。 */
function assistant(content: any[]) {
  return { id: 'm-assistant', role: 'assistant', source: { kind: 'model', provider: 'llm-agg', model: 'auto' }, content }
}

test('toChatRequest 合并开头 system 与 options.system，保留历史中间的 system', () => {
  const request = toChatRequest({
    provider: 'llm-agg',
    model: 'auto',
    system: '部署级系统提示',
    messages: [
      { id: 'm-sys', role: 'system', source: { kind: 'system-prompt' }, content: [{ type: 'text', text: '会话系统提示' }] },
      user([{ type: 'text', text: '开始' }]),
      { id: 'm-sys2', role: 'system', source: { kind: 'system-prompt' }, content: [{ type: 'text', text: '中途更新' }] },
      user([{ type: 'text', text: '继续' }]),
    ],
  })
  assert.deepEqual(request.messages, [
    { role: 'system', content: '部署级系统提示\n\n会话系统提示' },
    { role: 'user', content: '开始' },
    { role: 'system', content: '中途更新' },
    { role: 'user', content: '继续' },
  ])
})

test('toChatRequest 把 assistant 的文本与工具调用投影成 tool_calls，工具结果按 id 对应', () => {
  const request = toChatRequest({
    provider: 'llm-agg',
    model: 'auto',
    messages: [
      user([{ type: 'text', text: '查一下 1.1.1.1' }]),
      assistant([
        { type: 'reasoning', text: '内部推理不回灌' },
        { type: 'text', text: '我来查' },
        { type: 'tool-call', id: 'call_9', name: 'lookup_ip', arguments: '{"ip":"1.1.1.1"}' },
      ]),
      {
        id: 'm-tool',
        role: 'tool',
        source: { kind: 'tool', callId: 'call_9' },
        toolCallId: 'call_9',
        content: [{ type: 'text', text: '{"hits":3}' }],
        isError: false,
      },
    ],
  })
  assert.deepEqual(request.messages, [
    { role: 'user', content: '查一下 1.1.1.1' },
    {
      role: 'assistant',
      content: '我来查',
      tool_calls: [{ id: 'call_9', type: 'function', function: { name: 'lookup_ip', arguments: '{"ip":"1.1.1.1"}' } }],
    },
    { role: 'tool', tool_call_id: 'call_9', content: '{"hits":3}' },
  ])
})

test('toChatRequest 拒绝未 offload 的图片输入', () => {
  assert.throws(
    () => toChatRequest({
      provider: 'llm-agg',
      model: 'auto',
      messages: [user([{ type: 'image', attachment: { attachmentId: 'a1' } }])],
    }),
    (error: unknown) => error instanceof WireError && error.code === 'UNSUPPORTED_CONTENT',
  )
})

test('已 offload 的图片保留占位文本，不静默丢内容', () => {
  const request = toChatRequest({
    provider: 'llm-agg',
    model: 'auto',
    messages: [user([{ type: 'image', attachment: { attachmentId: 'a1' }, offloaded: true }])],
  })
  assert.deepEqual(request.messages, [{ role: 'user', content: '\n[图片已按上下文预算省略]\n' }])
})

test('空文本消息不产生空行；developer 文本按 system 下发', () => {
  const request = toChatRequest({
    provider: 'llm-agg',
    model: 'auto',
    messages: [
      user([]),
      { id: 'm-dev', role: 'developer', source: { kind: 'user' }, content: [{ type: 'text', text: '工具策略更新' }] },
    ],
  })
  assert.deepEqual(request.messages, [{ role: 'system', content: '工具策略更新' }])
})

test('toChatTools 映射 JSON Schema 并忽略空清单', () => {
  assert.equal(toChatTools(undefined), undefined)
  assert.equal(toChatTools([]), undefined)
  assert.deepEqual(
    toChatTools([{ name: 'lookup_ip', description: '查 IP', parameters: { type: 'object' } }]),
    [{ type: 'function', function: { name: 'lookup_ip', description: '查 IP', parameters: { type: 'object' } } }],
  )
})

test('SseDecoder 跨切片、CRLF、注释与多行 data 都能正确解帧', () => {
  const decoder = new SseDecoder()
  assert.deepEqual(decoder.push(': keepalive\r\n\r\n'), [])
  assert.deepEqual(decoder.push('data: {"a":'), [])
  assert.deepEqual(decoder.push('1}\r\n\r\ndata: line1\n'), ['{"a":1}'])
  assert.deepEqual(decoder.push('data: line2\n\n'), ['line1\nline2'])
  assert.deepEqual(decoder.push('data: [DONE]'), [])
  assert.deepEqual(decoder.end(), ['[DONE]'])
})

test('流式翻译：文本分片、结束块与 finish', () => {
  const translator = new ChatStreamTranslator()
  assert.deepEqual(translator.pushChunk({ choices: [{ delta: { content: 'Hel' } }] }), [
    { type: 'block-start', index: 0, blockType: 'text' },
    { type: 'text-delta', index: 0, text: 'Hel' },
  ])
  assert.deepEqual(translator.pushChunk({ choices: [{ delta: { content: 'lo' } }] }), [
    { type: 'text-delta', index: 0, text: 'lo' },
  ])
  assert.deepEqual(translator.pushChunk({ choices: [{ delta: {}, finish_reason: 'stop' }] }), [])
  assert.deepEqual(translator.end(), [
    { type: 'block-end', index: 0, block: { type: 'text', text: 'Hello' } },
    { type: 'finish', reason: { kind: 'stop' } },
  ])
})

test('流式翻译：推理块先于文本块，index 按首次出现顺序', () => {
  const translator = new ChatStreamTranslator()
  translator.pushChunk({ choices: [{ delta: { reasoning_content: '想' } }] })
  const chunks = translator.pushChunk({ choices: [{ delta: { content: '答' } }] })
  assert.deepEqual(chunks, [
    { type: 'block-start', index: 1, blockType: 'text' },
    { type: 'text-delta', index: 1, text: '答' },
  ])
  assert.deepEqual(translator.end(), [
    { type: 'block-end', index: 0, block: { type: 'reasoning', text: '想' } },
    { type: 'block-end', index: 1, block: { type: 'text', text: '答' } },
    { type: 'finish', reason: { kind: 'stop' } },
  ])
})

test('流式翻译：工具调用分片按 tool_calls[].index 归并并保留 id/name', () => {
  const translator = new ChatStreamTranslator()
  const first = translator.pushChunk({
    choices: [{ delta: { tool_calls: [{ index: 0, id: 'call_a', function: { name: 'lookup_ip', arguments: '{"ip"' } }] } }],
  })
  assert.deepEqual(first, [
    { type: 'block-start', index: 0, blockType: 'tool-call' },
    { type: 'tool-call-delta', index: 0, id: 'call_a', name: 'lookup_ip', argumentsDelta: '{"ip"' },
  ])
  assert.deepEqual(
    translator.pushChunk({ choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: ':"1.1.1.1"}' } }] }, finish_reason: 'tool_calls' }] }),
    [{ type: 'tool-call-delta', index: 0, id: 'call_a', argumentsDelta: ':"1.1.1.1"}' }],
  )
  assert.deepEqual(translator.end(), [
    {
      type: 'block-end',
      index: 0,
      block: { type: 'tool-call', id: 'call_a', name: 'lookup_ip', arguments: '{"ip":"1.1.1.1"}' },
    },
    { type: 'finish', reason: { kind: 'tool-calls' } },
  ])
})

test('usage 只发一次，缓存命中从 inputTokens 里扣除', () => {
  const translator = new ChatStreamTranslator()
  const usage = {
    prompt_tokens: 100,
    completion_tokens: 20,
    total_tokens: 120,
    prompt_tokens_details: { cached_tokens: 40 },
    completion_tokens_details: { reasoning_tokens: 5 },
  }
  const first = translator.pushChunk({ choices: [], usage })
  assert.deepEqual(first, [{
    type: 'usage',
    usage: { inputTokens: 60, outputTokens: 20, totalTokens: 120, cacheReadTokens: 40, reasoningTokens: 5 },
  }])
  assert.deepEqual(translator.pushChunk({ choices: [], usage }), [])
})

test('空响应没有内容块', () => {
  const translator = new ChatStreamTranslator()
  translator.pushChunk({ choices: [{ delta: {}, finish_reason: 'stop' }] })
  assert.equal(translator.hasContent(), false)
})

test('流内错误负载转成可路由的 WireError', () => {
  const translator = new ChatStreamTranslator()
  assert.throws(
    () => translator.pushChunk({ error: { message: 'insufficient quota', type: 'quota_exceeded' } }),
    (error: unknown) => error instanceof WireError && error.code === 'QUOTA',
  )
})

test('非流式完整响应也能翻译成同构 chunk', () => {
  const chunks = translateCompletion({
    choices: [{ message: { content: '完整回答' }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 3, completion_tokens: 2 },
  })
  assert.deepEqual(chunks, [
    { type: 'block-start', index: 0, blockType: 'text' },
    { type: 'text-delta', index: 0, text: '完整回答' },
    { type: 'usage', usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 } },
    { type: 'block-end', index: 0, block: { type: 'text', text: '完整回答' } },
    { type: 'finish', reason: { kind: 'stop' } },
  ])
})

test('finish_reason 与 usage 归一化', () => {
  assert.deepEqual(finishReasonOf('tool_calls'), { kind: 'tool-calls' })
  assert.deepEqual(finishReasonOf('length'), { kind: 'max-tokens' })
  assert.deepEqual(finishReasonOf(null), { kind: 'stop' })
  assert.deepEqual(toTokenUsage({ prompt_tokens: 0, completion_tokens: 0 }), {
    inputTokens: 0,
    outputTokens: 0,
  })
})

test('providerFailure 按状态与错误文本分类', () => {
  assert.equal(providerFailure(429, '{"error":{"message":"slow down"}}', '2').code, 'RATE_LIMIT')
  assert.equal(providerFailure(429, '', '2').retryAfterMs, 2_000)
  assert.equal(providerFailure(401, '{"error":{"message":"bad key"}}').code, 'INVALID_CREDENTIAL')
  assert.equal(providerFailure(404, '{"error":{"message":"no model"}}').code, 'UNKNOWN_MODEL')
  assert.equal(providerFailure(502, 'bad gateway').code, 'SERVER')
  assert.equal(
    providerFailure(400, '{"error":{"message":"This model maximum context length is 8192 tokens"}}').code,
    'CONTEXT_WINDOW_EXCEEDED',
  )
  assert.equal(
    providerFailure(403, '{"error":{"message":"insufficient balance"}}').code,
    'QUOTA',
  )
  assert.match(providerFailure(400, '{"error":{"message":"invalid tools"}}').message, /invalid tools/u)
})
