/** 系统设置面：从宿主机服务读快照、写模型/密钥（全部用桩服务，不启 dsh）。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { saveEndpoint, saveKey, saveModel, saveProvider, systemSnapshot } from '../src/system.ts'

type Calls = Array<{ kind: string, args: unknown[] }>

function fakeContext(options: {
  settings?: unknown
  credentials?: unknown
  loader?: unknown
}): { reflect: { get: (name: string) => unknown } } {
  const services: Record<string, unknown> = {
    settings: options.settings,
    credentials: options.credentials,
    loader: options.loader,
  }
  return { reflect: { get: (name: string) => services[name] } }
}

function fakeSettings(calls: Calls, value: Record<string, unknown> = {
  provider: 'deepseek-official', model: 'deepseek-chat',
}, providers: Record<string, unknown> = {}): unknown {
  return {
    describe: (opts?: { redactSecrets?: boolean }) => {
      assert.equal(opts?.redactSecrets, true)
      return [
        { ns: 'ui-settings-general', revision: 0, value: { welcomeNoticeVersion: 'x' } },
        { ns: 'default-model', revision: 7, value },
        { ns: 'llm-deepseek-api-key', revision: 2, value: { apiKeyEnv: 'DEEPSEEK_API_KEY', baseURL: 'https://api.deepseek.com/anthropic' } },
        { ns: 'llm-pi-ai', revision: 4, value: { providers } },
      ]
    },
    update: async (ns: string, patch: Record<string, unknown>, revision?: number) => {
      calls.push({ kind: 'update', args: [ns, patch, revision] })
    },
    mutate: async (ns: string, ops: unknown, revision?: number) => {
      calls.push({ kind: 'mutate', args: [ns, ops, revision] })
    },
  }
}

function fakeCredentials(calls: Calls): unknown {
  return {
    describe: async (ref: string) => {
      calls.push({ kind: 'describe', args: [ref] })
      return { configured: true, writable: true, source: 'file' }
    },
    set: async (ref: string, value: string) => { calls.push({ kind: 'set', args: [ref, value] }) },
    unset: async (ref: string) => { calls.push({ kind: 'unset', args: [ref] }) },
  }
}

test('快照：模型/密钥/插件清单映射，取消红act 只报状态不报值', async () => {
  const calls: Calls = []
  const ctx = fakeContext({
    settings: fakeSettings(calls),
    credentials: fakeCredentials(calls),
    loader: {
      entries: () => [
        { options: { id: 'xdr-ingest', name: '@sec-agent/xdr-ingest' }, fiber: { state: 2 } },
        { options: { id: 'xdr-ui', name: '@sec-agent/xdr-ui', disabled: true }, fiber: { state: 3 } },
      ],
    },
  })
  const snap = await systemSnapshot(ctx)
  assert.equal(snap.available, true)
  assert.equal(snap.model?.ns, 'default-model')
  assert.equal(snap.model?.provider, 'deepseek-official')
  assert.equal(snap.model?.revision, 7)
  assert.equal(snap.key?.ref, 'DEEPSEEK_API_KEY')
  assert.equal(snap.key?.configured, true)
  assert.equal(snap.key?.baseURL, 'https://api.deepseek.com/anthropic')
  assert.deepEqual(snap.plugins, [
    { id: 'xdr-ingest', name: '@sec-agent/xdr-ingest', phase: 'active', disabled: false },
    { id: 'xdr-ui', name: '@sec-agent/xdr-ui', phase: 'failed', disabled: true },
  ])
  assert.deepEqual(snap.notes, [])
})

test('服务全部缺席：快照仍返回结构，notes 说明缺什么', async () => {
  const snap = await systemSnapshot(fakeContext({}))
  assert.equal(snap.available, false)
  assert.equal(snap.model, null)
  assert.equal(snap.key, null)
  assert.deepEqual(snap.plugins, [])
  assert.ok(snap.notes.length >= 2)
})

test('保存模型：校验 provider/model/effort，成功后用最新 revision 提交', async () => {
  const calls: Calls = []
  const ctx = fakeContext({ settings: fakeSettings(calls), credentials: fakeCredentials(calls) })
  assert.equal((await saveModel(ctx, { provider: '', model: 'm' })).ok, false)
  assert.equal((await saveModel(ctx, { provider: 'p', model: '' })).ok, false)
  assert.equal((await saveModel(ctx, { provider: 'p', model: 'm', reasoningEffort: 'huge' })).ok, false)
  assert.equal((await saveModel(ctx, 'nope')).ok, false)

  const ok = await saveModel(ctx, { provider: 'deepseek-official', model: 'deepseek-chat', reasoningEffort: 'high' })
  assert.equal(ok.ok, true)
  const update = calls.find(call => call.kind === 'update')
  assert.deepEqual(update?.args, [
    'default-model',
    { provider: 'deepseek-official', model: 'deepseek-chat', reasoningEffort: 'high' },
    7,
  ])
  assert.equal(ok.snapshot?.model?.model, 'deepseek-chat')
})

test('保存密钥：set / 清除走 credentials，空值拒绝', async () => {
  const calls: Calls = []
  const ctx = fakeContext({ settings: fakeSettings(calls), credentials: fakeCredentials(calls) })
  assert.equal((await saveKey(ctx, { value: '  ' })).ok, false)
  const ok = await saveKey(ctx, { value: ' sk-test ' })
  assert.equal(ok.ok, true)
  assert.deepEqual(calls.find(call => call.kind === 'set')?.args, ['DEEPSEEK_API_KEY', 'sk-test'])
  const cleared = await saveKey(ctx, { clear: true })
  assert.equal(cleared.ok, true)
  assert.deepEqual(calls.find(call => call.kind === 'unset')?.args, ['DEEPSEEK_API_KEY'])
})

test('保存接口地址：非 http(s) 拒绝；空值走 unset 回落默认', async () => {
  const calls: Calls = []
  const ctx = fakeContext({ settings: fakeSettings(calls), credentials: fakeCredentials(calls) })
  assert.equal((await saveEndpoint(ctx, { baseURL: 'ftp://x' })).ok, false)
  assert.equal((await saveEndpoint(ctx, { baseURL: 'https://proxy.example/v1' })).ok, true)
  assert.deepEqual(calls.find(call => call.kind === 'update')?.args, [
    'llm-deepseek-api-key', { baseURL: 'https://proxy.example/v1' }, 2,
  ])
  assert.equal((await saveEndpoint(ctx, { baseURL: '' })).ok, true)
  const unset = calls.find(call => call.kind === 'mutate')
  assert.deepEqual(unset?.args, ['llm-deepseek-api-key', [{ op: 'unset', path: ['baseURL'] }], 2])
})

test('快照：列出 pi-ai 自定义服务商与 DeepSeek 官方通道', async () => {
  const calls: Calls = []
  const ctx = fakeContext({
    settings: fakeSettings(calls, { provider: 'kimi', model: 'kimi-k2' }, {
      kimi: {
        displayName: 'Kimi',
        api: 'openai-completions',
        baseURL: 'https://api.moonshot.cn/v1',
        apiKeyEnv: 'KIMI_API_KEY',
        models: [{ id: 'kimi-k2' }],
      },
    }),
    credentials: fakeCredentials(calls),
  })
  const snap = await systemSnapshot(ctx)
  const routes = snap.providers.map(p => p.route).sort()
  assert.deepEqual(routes, ['deepseek-official', 'kimi'])
  const kimi = snap.providers.find(p => p.route === 'kimi')
  assert.equal(kimi?.displayName, 'Kimi')
  assert.equal(kimi?.baseURL, 'https://api.moonshot.cn/v1')
  assert.deepEqual(kimi?.models, ['kimi-k2'])
  assert.equal(kimi?.configured, true)
})

test('保存服务商：写 pi-ai providers、存 Key、设为默认模型', async () => {
  const calls: Calls = []
  const ctx = fakeContext({ settings: fakeSettings(calls), credentials: fakeCredentials(calls) })
  const result = await saveProvider(ctx, {
    route: 'kimi',
    displayName: 'Kimi',
    api: 'openai-completions',
    baseURL: 'https://api.moonshot.cn/v1',
    modelId: 'kimi-k2',
    contextWindow: 131072,
    apiKey: 'sk-kimi',
    makeDefault: true,
  })
  assert.equal(result.ok, true)
  const piUpdate = calls.find(call => call.kind === 'update' && call.args[0] === 'llm-pi-ai')
  assert.deepEqual(piUpdate?.args[1], {
    providers: {
      kimi: {
        displayName: 'Kimi',
        api: 'openai-completions',
        baseURL: 'https://api.moonshot.cn/v1',
        apiKeyEnv: 'KIMI_API_KEY',
        models: [{ id: 'kimi-k2', contextWindow: 131072 }],
      },
    },
  })
  assert.equal(piUpdate?.args[2], 4)
  assert.deepEqual(calls.find(call => call.kind === 'set')?.args, ['KIMI_API_KEY', 'sk-kimi'])
  const modelUpdate = calls.find(call => call.kind === 'update' && call.args[0] === 'default-model')
  assert.deepEqual(modelUpdate?.args[1], { provider: 'kimi', model: 'kimi-k2' })
  assert.equal(modelUpdate?.args[2], 7)
})

test('保存服务商：非法 route / URL / 协议直接拒绝', async () => {
  const calls: Calls = []
  const ctx = fakeContext({ settings: fakeSettings(calls), credentials: fakeCredentials(calls) })
  const base = { route: 'kimi', baseURL: 'https://api.moonshot.cn/v1', modelId: 'm', apiKey: '' }
  assert.equal((await saveProvider(ctx, { ...base, route: 'Kimi!' })).ok, false)
  assert.equal((await saveProvider(ctx, { ...base, baseURL: 'ftp://x' })).ok, false)
  assert.equal((await saveProvider(ctx, { ...base, api: 'grpc' })).ok, false)
  assert.equal((await saveProvider(ctx, { ...base, modelId: '' })).ok, false)
})
