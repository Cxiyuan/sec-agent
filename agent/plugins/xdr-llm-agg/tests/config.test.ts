/**
 * 配置解析单测：默认值、尾部斜杠归一化、空模型清单回落、非法端点 fail loud。
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { Config, DEFAULT_BASE_URL, DEFAULT_MODELS, resolveConfig } from '../src/config.ts'

test('空配置解析出可直接用的默认端点与池别名', () => {
  const resolved = resolveConfig(Config({}))
  assert.equal(resolved.baseURL, DEFAULT_BASE_URL)
  assert.equal(resolved.apiKeyEnv, 'LLM_AGG_API_KEY')
  assert.equal(resolved.sessionHeader, 'x-session-id')
  assert.equal(resolved.displayName, 'LLM-AGG（智能路由）')
  assert.deepEqual(resolved.models.map(model => model.id), ['auto', 'free', 'cheap'])
})

test('尾部斜杠去掉；空模型清单回落默认别名', () => {
  const resolved = resolveConfig(Config({ baseURL: 'http://127.0.0.1:8788/v1///', models: [] }))
  assert.equal(resolved.baseURL, 'http://127.0.0.1:8788/v1')
  assert.deepEqual(resolved.models, DEFAULT_MODELS)
})

test('显式模型保留上下文窗口与去重', () => {
  const resolved = resolveConfig(Config({
    models: [
      { id: 'deepseek-chat', name: 'DeepSeek Chat', contextWindow: 65536 },
      { id: 'deepseek-chat' },
      { id: 'kimi-k2', maxTokens: 4096 },
    ],
  }))
  assert.deepEqual(resolved.models, [
    { id: 'deepseek-chat', name: 'DeepSeek Chat', contextWindow: 65536 },
    { id: 'kimi-k2', maxTokens: 4096 },
  ])
})

test('非法端点/头名在解析期就失败', () => {
  assert.throws(() => resolveConfig(Config({ baseURL: 'not-a-url' })), /baseURL/u)
  assert.throws(() => resolveConfig(Config({ sessionHeader: 'bad header' })), /sessionHeader/u)
  assert.throws(() => resolveConfig(Config({ apiKeyEnv: '9bad' })), /apiKeyEnv/u)
})
