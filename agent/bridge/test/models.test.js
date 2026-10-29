import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { freeModels, resolveModel } from '../src/models.js'

const raw = [
  {
    providerID: 'opencode',
    id: 'deepseek-v4.1-flash-free',
    name: 'DeepSeek V4.1 Flash Free',
    enabled: true,
    status: 'active',
    capabilities: { output: ['text'], tools: true },
    cost: [{ input: 0, output: 0, cache: { read: 0, write: 0 } }],
    limit: { context: 200000, output: 8192 },
  },
  {
    providerID: 'opencode',
    id: 'chat-only-free',
    name: 'Chat Only',
    enabled: true,
    capabilities: { output: ['text'], tools: false },
    cost: [{ input: 0, output: 0 }],
  },
  {
    providerID: 'opencode',
    id: 'paid-model',
    name: 'Paid',
    enabled: true,
    capabilities: { output: ['text'], tools: true },
    cost: [{ input: 1, output: 2 }],
  },
  {
    providerID: 'other',
    id: 'free-elsewhere',
    name: 'Other',
    enabled: true,
    capabilities: { output: ['text'], tools: true },
    cost: [{ input: 0, output: 0 }],
  },
  {
    providerID: 'opencode',
    id: 'disabled-free',
    name: 'Disabled',
    enabled: false,
    capabilities: { output: ['text'], tools: true },
    cost: [{ input: 0, output: 0 }],
  },
]

test('只保留 opencode 提供方、启用、零成本、文本输出的模型', () => {
  const models = freeModels(raw)
  assert.deepEqual(models.map(model => model.id), ['deepseek-v4.1-flash-free'])
  assert.equal(models[0].tools, true)
  assert.equal(models[0].context, 200000)
})

test('默认排除不支持工具的模型（分析闭环必须有工具）', () => {
  const withChat = freeModels(raw, { includeChatOnly: true })
  assert.deepEqual(withChat.map(model => model.id).sort(), ['chat-only-free', 'deepseek-v4.1-flash-free'])
})

test('解析模型名兼容 opencode/ 前缀与显示名', () => {
  const models = freeModels(raw, { includeChatOnly: true })
  assert.equal(resolveModel(models, 'deepseek-v4.1-flash-free')?.id, 'deepseek-v4.1-flash-free')
  assert.equal(resolveModel(models, 'opencode/deepseek-v4.1-flash-free')?.id, 'deepseek-v4.1-flash-free')
  assert.equal(resolveModel(models, 'DeepSeek V4.1 Flash Free')?.id, 'deepseek-v4.1-flash-free')
  assert.equal(resolveModel(models, 'nope'), null)
})
