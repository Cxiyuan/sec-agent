import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { loadConfig } from '../src/config.js'

const base = {
  BRIDGE_API_KEY: 'k'.repeat(32),
}

test('默认值：回环、41980、并发 2、每日 200', () => {
  const config = loadConfig({ ...base })
  assert.equal(config.host, '127.0.0.1')
  assert.equal(config.port, 41980)
  assert.equal(config.maxConcurrency, 2)
  assert.equal(config.maxRequestsPerDay, 200)
  assert.equal(config.includeChatOnly, false)
  assert.equal(config.opencodeBin, '/opt/opencode/opencode')
})

test('缺少密钥必须拒绝启动（除非显式测试开关）', () => {
  assert.throws(() => loadConfig({}), /BRIDGE_API_KEY/u)
  const testMode = loadConfig({ BRIDGE_ALLOW_NO_AUTH: '1' })
  assert.equal(testMode.allowNoAuth, true)
})

test('环境变量覆盖与范围校验', () => {
  const config = loadConfig({
    ...base,
    BRIDGE_PORT: '42001',
    BRIDGE_MAX_CONCURRENCY: '1',
    BRIDGE_MAX_REQUESTS_PER_DAY: '0',
    BRIDGE_INCLUDE_CHAT_ONLY: '1',
  })
  assert.equal(config.port, 42001)
  assert.equal(config.maxConcurrency, 1)
  assert.equal(config.maxRequestsPerDay, 0)
  assert.equal(config.includeChatOnly, true)
  assert.throws(() => loadConfig({ ...base, BRIDGE_PORT: '80' }), /BRIDGE_PORT/u)
  assert.throws(() => loadConfig({ ...base, BRIDGE_MAX_CONCURRENCY: '99' }), /BRIDGE_MAX_CONCURRENCY/u)
})
