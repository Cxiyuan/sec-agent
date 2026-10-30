/** 系统设置面：从宿主机服务读快照、写模型/密钥（全部用桩服务，不启 dsh）。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { listModels, saveEndpoint, saveKey, saveModel, saveProvider, systemSnapshot } from '../src/system.ts'

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
        // 干扰项：搜索插件也有 apiKeyEnv，但不能被当成模型通道
        { ns: 'web-search-deepseek', revision: 1, value: { apiKeyEnv: 'DEEPSEEK_API_KEY' } },
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
  assert.equal(snap.key?.ns, 'llm-deepseek-api-key')
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

test('保存服务商：OpenCode Go 自动带 x-opencode-session（缺了会 400 MissingSessionID）', async () => {
  const calls: Calls = []
  const ctx = fakeContext({ settings: fakeSettings(calls), credentials: fakeCredentials(calls) })
  const result = await saveProvider(ctx, {
    route: 'opencode-go',
    api: 'openai-completions',
    baseURL: 'https://opencode.ai/inference/go/openai/v1',
    modelId: 'qwen3.8-flash',
    apiKey: 'sk-opencode-test',
  })
  assert.equal(result.ok, true)
  const piUpdate = calls.find(call => call.kind === 'update' && call.args[0] === 'llm-pi-ai')
  const profile = (piUpdate?.args[1] as { providers: Record<string, { headers?: Record<string, string> }> })
    .providers['opencode-go']
  assert.equal(profile?.headers?.['x-opencode-session'], 'xdr-opencode-go')

  // 非 Go 地址不自作主张加头
  const calls2: Calls = []
  const ctx2 = fakeContext({ settings: fakeSettings(calls2), credentials: fakeCredentials(calls2) })
  await saveProvider(ctx2, {
    route: 'kimi', api: 'openai-completions', baseURL: 'https://api.moonshot.cn/v1',
    modelId: 'kimi-k2', apiKey: '',
  })
  const pi2 = calls2.find(call => call.kind === 'update' && call.args[0] === 'llm-pi-ai')
  const profile2 = (pi2?.args[1] as { providers: Record<string, { headers?: unknown }> }).providers['kimi']
  assert.equal(profile2?.headers, undefined)
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

/** 带 xdr-llm-agg 数据块的设置桩：专用适配器不写 pi-ai 的 providers 字典。 */
function fakeSettingsWithAgg(calls: Calls): unknown {
  return {
    describe: () => [
      { ns: 'default-model', revision: 3, value: { provider: 'llm-agg', model: 'auto' } },
      { ns: 'llm-pi-ai', revision: 4, value: { providers: {} } },
      {
        ns: 'xdr-llm-agg',
        revision: 5,
        value: {
          displayName: 'LLM-AGG（智能路由）',
          baseURL: 'http://host.docker.internal:8788/v1',
          apiKeyEnv: 'LLM_AGG_API_KEY',
          models: [{ id: 'auto' }, { id: 'free' }],
        },
      },
    ],
    update: async (ns: string, patch: Record<string, unknown>, revision?: number) => {
      calls.push({ kind: 'update', args: [ns, patch, revision] })
    },
    mutate: async () => {},
  }
}

test('llm-agg：快照列出专用路由，保存写 xdr-llm-agg 并设为默认', async () => {
  const calls: Calls = []
  const ctx = fakeContext({ settings: fakeSettingsWithAgg(calls), credentials: fakeCredentials(calls) })
  const snap = await systemSnapshot(ctx)
  const agg = snap.providers.find(provider => provider.route === 'llm-agg')
  assert.equal(agg?.displayName, 'LLM-AGG（智能路由）')
  assert.equal(agg?.baseURL, 'http://host.docker.internal:8788/v1')
  assert.deepEqual(agg?.models, ['auto', 'free'])
  assert.equal(agg?.configured, true)

  // 专用适配器只走 OpenAI Chat 协议
  assert.equal((await saveProvider(ctx, {
    route: 'llm-agg',
    api: 'anthropic-messages',
    baseURL: 'http://127.0.0.1:8788/v1',
    modelId: 'auto',
  })).ok, false)

  const saved = await saveProvider(ctx, {
    route: 'llm-agg',
    displayName: 'LLM-AGG',
    api: 'openai-completions',
    baseURL: 'http://127.0.0.1:8788/v1',
    modelId: 'auto',
    contextWindow: 131072,
    apiKey: ' sk-pool ',
    makeDefault: true,
  })
  assert.equal(saved.ok, true)
  const aggUpdate = calls.find(call => call.kind === 'update' && call.args[0] === 'xdr-llm-agg')
  assert.deepEqual(aggUpdate?.args, [
    'xdr-llm-agg',
    {
      displayName: 'LLM-AGG',
      baseURL: 'http://127.0.0.1:8788/v1',
      apiKeyEnv: 'LLM_AGG_API_KEY',
      // 本次选择的模型放首位；原有别名保留（否则保存后就不能切回 free）
      models: [{ id: 'auto', contextWindow: 131072 }, { id: 'free' }],
    },
    5,
  ])
  assert.equal(
    calls.some(call => call.kind === 'update' && call.args[0] === 'llm-pi-ai'),
    false,
    'llm-agg 不能写进 pi-ai（会与专用适配器撞车）',
  )
  assert.deepEqual(calls.find(call => call.kind === 'set')?.args, ['LLM_AGG_API_KEY', 'sk-pool'])
  const modelUpdate = calls.find(call => call.kind === 'update' && call.args[0] === 'default-model')
  assert.deepEqual(modelUpdate?.args, ['default-model', { provider: 'llm-agg', model: 'auto' }, 3])
})

type FetchStub = (url: string, init?: { headers?: Record<string, string> }) => Promise<{
  ok: boolean
  status: number
  text: () => Promise<string>
}>

function fetchOf(responses: Record<string, { status?: number, body: unknown | string }>): FetchStub {
  return async (url: string) => {
    const hit = responses[url]
    if (hit === undefined) throw new Error(`unexpected fetch ${url}`)
    const body = typeof hit.body === 'string' ? hit.body : JSON.stringify(hit.body)
    return { ok: (hit.status ?? 200) < 300, status: hit.status ?? 200, text: async () => body }
  }
}

test('拉取模型清单：OpenAI 兼容走 /models，anthropic 走 /v1/models，Key 优先用请求值', async () => {
  const calls: Calls = []
  const ctx = fakeContext({ settings: fakeSettings(calls), credentials: fakeCredentials(calls) })
  const openai = await listModels(ctx, {
    baseURL: 'https://api.moonshot.cn/v1',
    api: 'openai-completions',
    apiKey: 'sk-test',
  }, fetchOf({
    'https://api.moonshot.cn/v1/models': { body: { data: [{ id: 'kimi-k2' }, { id: 'moonshot-v1-8k' }] } },
  }))
  assert.equal(openai.ok, true)
  assert.deepEqual(openai.models, ['kimi-k2', 'moonshot-v1-8k'])

  const anthropic = await listModels(ctx, {
    baseURL: 'https://api.anthropic.com',
    api: 'anthropic-messages',
    apiKey: 'sk-a',
  }, fetchOf({
    'https://api.anthropic.com/v1/models': { body: { data: [{ id: 'claude-sonnet-4-5' }] } },
  }))
  assert.equal(anthropic.ok, true)
  assert.deepEqual(anthropic.models, ['claude-sonnet-4-5'])
})

test('拉取模型清单：没传 Key 且已保存过，自动用凭证库里的值', async () => {
  const calls: Calls = []
  const ctx2 = fakeContext({
    settings: fakeSettings(calls, { provider: 'deepseek-official', model: 'm' }, {
      kimi: { api: 'openai-completions', baseURL: 'https://api.moonshot.cn/v1', apiKeyEnv: 'KIMI_API_KEY', models: [{ id: 'kimi-k2' }] },
    }),
    credentials: { describe: async () => ({ configured: true }), resolve: async () => ({ value: 'sk-saved', source: 'file' }) },
  })
  const result = await listModels(ctx2, { route: 'kimi' }, fetchOf({
    'https://api.moonshot.cn/v1/models': { body: { data: [{ id: 'kimi-k2' }] } },
  }))
  assert.equal(result.ok, true)
  assert.deepEqual(result.models, ['kimi-k2'])
})

test('拉取模型清单：没有 Key/坏地址/非 JSON 都给可读错误', async () => {
  const calls: Calls = []
  const ctx = fakeContext({ settings: fakeSettings(calls) })
  assert.equal((await listModels(ctx, { route: 'kimi' }) as { ok?: boolean }).ok, false)
  assert.equal((await listModels(ctx, { baseURL: 'ftp://x', api: 'openai-completions', apiKey: 'k' }) as { ok?: boolean }).ok, false)
  const ctx2 = fakeContext({
    settings: fakeSettings(calls, { provider: 'p', model: 'm' }),
    credentials: fakeCredentials(calls),
  })
  const bad = await listModels(ctx2, {
    baseURL: 'https://api.example.com/v1', api: 'openai-completions', apiKey: 'k',
  }, fetchOf({ 'https://api.example.com/v1/models': { status: 401, body: 'auth failed' } }))
  assert.equal(bad.ok, false)
})
