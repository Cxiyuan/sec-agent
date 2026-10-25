/**
 * cordis 上下文取 `agents` 服务：**不能直接读属性**。
 *
 * 2026-10 冒烟实测：`ctx.agents` 是 Proxy，未在 `inject` 声明就读取会抛
 * `cannot get property "agents" without inject`，插件 `apply()` 整个失败 →
 * 路由不注册 → 门铃全 404。而 `inject: ['agents']` 又会把"必需服务"语义绑死
 * （宿主没装 dsh-agent 时插件根本不激活，连门铃都收不了）。
 * 所以只认 `ctx.reflect.get('agents', false)`，并且任何异常都必须降级成 null。
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { agentsOf } from '../src/agent-port.ts'

function fakeService(): unknown {
  return { create: async () => ({}) }
}

test('reads the service through reflect (non-strict)', () => {
  const service = fakeService()
  const ctx = { reflect: { get: (name: string) => (name === 'agents' ? service : undefined) } }
  assert.equal(agentsOf(ctx), service)
})

test('a proxy that throws on direct property access must not break us', () => {
  const service = fakeService()
  const ctx = new Proxy(
    { reflect: { get: () => service } },
    {
      get(target, prop) {
        // 模拟 cordis：未 inject 的服务属性一读就抛
        if (prop === 'agents') throw new Error('cannot get property "agents" without inject')
        return Reflect.get(target, prop)
      },
    },
  )
  // 关键：只要我们不去读 `ctx.agents`，就不会触发那个异常
  assert.equal(agentsOf(ctx), service)
})

test('missing service degrades to null, not a crash', () => {
  assert.equal(agentsOf({ reflect: { get: () => undefined } }), null)
  assert.equal(agentsOf({}), null)
  assert.equal(agentsOf(null), null)
  assert.equal(agentsOf('nope'), null)
})

test('a throwing reflect layer degrades to null', () => {
  const ctx = {
    reflect: {
      get: () => {
        throw new Error('not ready')
      },
    },
  }
  assert.equal(agentsOf(ctx), null)
})
