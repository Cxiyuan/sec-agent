/**
 * 系统设置面：控制台里读/写 dsh 的模型选择、模型 API Key 与插件清单。
 *
 * 为什么在这里做而不是去改原生界面：原生 dsh 的「设置」是它自己的 React 客户端，
 * 我们不碰上游；这些能力在同一进程里都是**宿主机服务**（`settings` /
 * `credentials` / `loader`），xdr-ui 作为 host 插件可以直接读写：
 *   - 模型选择（provider / model / reasoningEffort）→ `ctx.settings`
 *   - 模型 API Key（按 credential-ref 存）→ `ctx.credentials`
 *   - 插件清单 → `ctx.loader`（只读；安装/启停走镜像与 profile，不在页面里改）
 *
 * 服务全部可选：任何一个不在场时对应区块报"不可用"，控制台其余部分照常。
 * 写操作一律先取最新 revision 再提交（settings 是乐观并发，旧 revision 会被拒）。
 */

/** 可选服务的最小结构化接口（不跨包 import type，理由同 http.ts）。 */
interface SettingsLike {
  describe(options?: { redactSecrets?: boolean }): Array<{
    ns: string
    revision: number
    value: unknown
  }>
  update(ns: string, patch: Record<string, unknown>, expectedRevision?: number): Promise<void>
  mutate(ns: string, ops: ReadonlyArray<{ op: 'unset', path: string[] }>, expectedRevision?: number): Promise<void>
}

interface CredentialsLike {
  describe(ref: string): Promise<{ configured: boolean, writable?: boolean, source?: string }>
  /** 解析一个引用到当前值（读取处用于拉模型清单时不让用户重复填 Key）。 */
  resolve(ref: string): Promise<{ value: string, source: string } | undefined>
  set(ref: string, value: string): Promise<void>
  unset(ref: string): Promise<void>
}

interface LoaderLike {
  entries(): Iterable<{
    options: { id?: string, name?: string, disabled?: boolean | null }
    fiber?: { state?: number }
  }>
}

/** 结果：成功带快照，失败带可直接展示的原因。 */
export interface SystemResult {
  ok: boolean
  error?: string
  snapshot?: SystemSnapshot
}

export interface SystemSnapshot {
  /** 模型设置服务是否在场。 */
  available: boolean
  plugins: Array<{ id: string, name: string, phase: string, disabled: boolean }>
  model: {
    ns: string
    revision: number
    provider: string
    model: string
    reasoningEffort: string
  } | null
  key: {
    ns: string
    revision: number
    ref: string
    baseURL: string
    configured: boolean
    writable: boolean
    source: string
  } | null
  /** 已注册的服务商路由（pi-ai 自定义 + DeepSeek 官方通道）。 */
  providers: Array<{
    route: string
    displayName: string
    api: string
    baseURL: string
    models: string[]
    apiKeyRef: string
    configured: boolean
    writable: boolean
  }>
  /** 给界面看的说明（服务缺失、配置来自环境变量等）。 */
  notes: string[]
}

const FIBER_PHASE: Record<number, string> = {
  0: 'pending',
  1: 'loading',
  2: 'active',
  3: 'failed',
  4: 'disposed',
  5: 'unloading',
}

const MAX_TEXT = 256
const EFFORTS = new Set(['', 'off', 'low', 'high', 'max'])

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function serviceOf<T>(context: unknown, name: string): T | null {
  try {
    const reflect = (context as { reflect?: { get?: (name: string, strict?: boolean) => unknown } }).reflect
    if (typeof reflect?.get !== 'function') return null
    const service = reflect.get(name, false)
    return typeof service === 'object' && service !== null ? service as T : null
  } catch {
    return null
  }
}

/** 支持的线协议（pi-ai 适配器）。 */
const PROTOCOLS = new Set(['openai-completions', 'anthropic-messages'])
const ROUTE_PATTERN = /^[a-z][a-z0-9-]{1,32}$/u
const REF_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/u

/** 只接受短文本：这些值会写进 profile patch，不做长度上限就是给自己留坑。 */
function textOf(value: unknown): string | null {
  if (value === undefined || value === null) return ''
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length > MAX_TEXT ? null : trimmed
}

/** 模型选择对应的 settings 命名空间：优先 default-model，其次任一含 provider/model 的条目。 */
function pickModel(
  settings: SettingsLike,
): { descriptor: Extract<ReturnType<SettingsLike['describe']>[number], { value: unknown }> } | null {
  try {
    const rows = settings.describe({ redactSecrets: true })
    const shaped = rows.filter(row => {
      const value: unknown = row.value
      return isPlainObject(value) && typeof value['provider'] === 'string' && typeof value['model'] === 'string'
    })
    const preferred = shaped.find(row => row.ns === 'default-model') ?? shaped[0]
    return preferred === undefined ? null : { descriptor: preferred }
  } catch {
    return null
  }
}

/**
 * 模型适配器条目判定：只有 `llm-*` 的条目才是"模型服务商"。
 * 别把 web-search-deepseek 之类的条目算进来——它同样有 apiKeyEnv 字段，
 * 误判会导致 BaseURL/Key 写到搜索插件而不是模型通道。
 */
function isModelAdapter(ns: string): boolean {
  return ns === 'llm-deepseek' || ns.startsWith('llm-')
}

/** API Key 配置对应的命名空间：模型适配器里带 credential-ref（apiKeyEnv）的那个条目。 */
function pickKey(
  settings: SettingsLike,
): { ns: string, revision: number, ref: string, baseURL: string } | null {
  try {
    const rows = settings.describe({ redactSecrets: true })
    for (const row of rows) {
      if (!isModelAdapter(row.ns)) continue
      const value: unknown = row.value
      if (!isPlainObject(value)) continue
      if (isPlainObject(value['providers'])) continue
      const ref = value['apiKeyEnv']
      if (typeof ref !== 'string' || ref.trim() === '') continue
      const baseURL = typeof value['baseURL'] === 'string' ? value['baseURL'] : ''
      return { ns: row.ns, revision: row.revision, ref: ref.trim(), baseURL }
    }
    return null
  } catch {
    return null
  }
}

/** 读一份完整快照（界面每次保存后都重新拉它）。 */
export async function systemSnapshot(context: unknown): Promise<SystemSnapshot> {
  const notes: string[] = []
  const settings = serviceOf<SettingsLike>(context, 'settings')
  const credentials = serviceOf<CredentialsLike>(context, 'credentials')
  const loader = serviceOf<LoaderLike>(context, 'loader')

  const plugins: SystemSnapshot['plugins'] = []
  if (loader === null) {
    notes.push('插件清单不可用：loader 服务不在场')
  } else {
    try {
      for (const entry of loader.entries()) {
        const id = entry.options.id ?? ''
        const name = entry.options.name ?? ''
        if (id === '' || name === '') continue
        plugins.push({
          id,
          name,
          phase: FIBER_PHASE[entry.fiber?.state ?? -1] ?? 'unknown',
          disabled: entry.options.disabled === true,
        })
      }
      plugins.sort((a, b) => a.id.localeCompare(b.id))
    } catch {
      notes.push('插件清单读取失败')
    }
  }

  if (settings === null) {
    notes.push('模型配置不可用：settings 服务不在场')
    return { available: false, plugins, model: null, key: null, providers: [], notes }
  }

  let model: SystemSnapshot['model'] = null
  const pickedModel = pickModel(settings)
  if (pickedModel === null) {
    notes.push('没有找到模型选择条目（default-model）：部署的 profile 未启用模型插件')
  } else {
    const value = pickedModel.descriptor.value as Record<string, unknown>
    model = {
      ns: pickedModel.descriptor.ns,
      revision: pickedModel.descriptor.revision,
      provider: String(value['provider'] ?? ''),
      model: String(value['model'] ?? ''),
      reasoningEffort: typeof value['reasoningEffort'] === 'string' ? value['reasoningEffort'] : '',
    }
  }

  let key: SystemSnapshot['key'] = null
  const pickedKey = pickKey(settings)
  if (pickedKey === null) {
    notes.push('没有找到 API Key 配置条目：当前 profile 可能用账号授权而不是 API Key')
  } else {
    let configured = false
    let writable = false
    let source = ''
    if (credentials === null) {
      notes.push('API Key 状态不可读：credentials 服务不在场')
    } else {
      try {
        const info = await credentials.describe(pickedKey.ref)
        configured = info.configured === true
        writable = info.writable === true
        source = info.source ?? ''
      } catch (error) {
        notes.push(`API Key 状态读取失败：${error instanceof Error ? error.message : String(error)}`)
      }
    }
    key = { ...pickedKey, configured, writable, source }
  }

  const providers = await providerRows(settings, credentials, notes)
  return { available: true, plugins, model, key, providers, notes }
}

/** 列出可用的服务商路由：pi-ai 的 providers 字典 + DeepSeek 官方通道。 */
async function providerRows(
  settings: SettingsLike,
  credentials: CredentialsLike | null,
  notes: string[],
): Promise<SystemSnapshot['providers']> {
  const rows: SystemSnapshot['providers'] = []
  let described: ReturnType<SettingsLike['describe']>
  try {
    described = settings.describe({ redactSecrets: true })
  } catch {
    return rows
  }
  for (const row of described) {
    const value: unknown = row.value
    if (!isPlainObject(value)) continue
    const dict = value['providers']
    if (!isPlainObject(dict)) continue
    for (const [route, profile] of Object.entries(dict)) {
      if (!isPlainObject(profile)) continue
      const apiKeyRef = typeof profile['apiKeyEnv'] === 'string' ? profile['apiKeyEnv'] : ''
      const models = Array.isArray(profile['models'])
        ? profile['models'].flatMap(model => (isPlainObject(model) && typeof model['id'] === 'string' ? [model['id']] : []))
        : []
      const info = apiKeyRef === '' || credentials === null ? null : await safeDescribe(credentials, apiKeyRef)
      rows.push({
        route,
        displayName: typeof profile['displayName'] === 'string' ? profile['displayName'] : route,
        api: typeof profile['api'] === 'string' ? profile['api'] : '',
        baseURL: typeof profile['baseURL'] === 'string' ? profile['baseURL'] : '',
        models,
        apiKeyRef,
        configured: info?.configured === true,
        writable: info?.writable === true,
      })
    }
  }
  // DeepSeek 官方通道（独立适配器，不在 pi-ai 字典里）
  for (const row of described) {
    if (!isModelAdapter(row.ns)) continue
    const value: unknown = row.value
    if (!isPlainObject(value)) continue
    if (isPlainObject(value['providers'])) continue
    const ref = value['apiKeyEnv']
    if (typeof ref !== 'string' || ref.trim() === '') continue
    const info = credentials === null ? null : await safeDescribe(credentials, ref.trim())
    rows.push({
      route: 'deepseek-official',
      displayName: 'DeepSeek（官方通道）',
      api: 'anthropic-messages',
      baseURL: typeof value['baseURL'] === 'string' ? value['baseURL'] : '',
      models: Array.isArray(value['models'])
        ? value['models'].flatMap(model => (isPlainObject(model) && typeof model['id'] === 'string' ? [model['id']] : []))
        : [],
      apiKeyRef: ref.trim(),
      configured: info?.configured === true,
      writable: info?.writable === true,
    })
    break
  }
  if (rows.length === 0) notes.push('还没有可用的模型服务商，请在下方添加（或用 DeepSeek 官方通道填 Key）')
  return rows
}

async function safeDescribe(
  credentials: CredentialsLike,
  ref: string,
): Promise<{ configured: boolean, writable?: boolean } | null> {
  try {
    return await credentials.describe(ref)
  } catch {
    return null
  }
}

/** 保存模型选择（provider / model / 可选 reasoningEffort）。 */
export async function saveModel(context: unknown, patch: unknown): Promise<SystemResult> {
  const settings = serviceOf<SettingsLike>(context, 'settings')
  if (settings === null) return { ok: false, error: 'settings 服务不在场' }
  if (!isPlainObject(patch)) return { ok: false, error: '参数必须是 JSON 对象' }
  const provider = textOf(patch['provider'])
  const model = textOf(patch['model'])
  const effort = textOf(patch['reasoningEffort'] ?? '')
  if (provider === null || provider === '') return { ok: false, error: 'provider 不能为空（如 deepseek-official）' }
  if (model === null || model === '') return { ok: false, error: 'model 不能为空（如 deepseek-chat）' }
  if (effort === null || !EFFORTS.has(effort)) return { ok: false, error: 'reasoningEffort 只能是 off/low/high/max 或留空' }
  const picked = pickModel(settings)
  if (picked === null) return { ok: false, error: '没有找到模型选择条目（default-model）' }
  try {
    const fields: Record<string, unknown> = { provider, model }
    if (effort !== '') fields['reasoningEffort'] = effort
    await settings.update(picked.descriptor.ns, fields, picked.descriptor.revision)
    return { ok: true, snapshot: await systemSnapshot(context) }
  } catch (error) {
    return { ok: false, error: describeWriteError(error) }
  }
}

/** 保存 / 清除模型 API Key（写的是 credentials 服务，不落 profile patch）。 */
export async function saveKey(context: unknown, patch: unknown): Promise<SystemResult> {
  const settings = serviceOf<SettingsLike>(context, 'settings')
  const credentials = serviceOf<CredentialsLike>(context, 'credentials')
  if (settings === null) return { ok: false, error: 'settings 服务不在场' }
  if (credentials === null) return { ok: false, error: 'credentials 服务不在场，无法保存密钥' }
  if (!isPlainObject(patch)) return { ok: false, error: '参数必须是 JSON 对象' }
  const picked = pickKey(settings)
  if (picked === null) return { ok: false, error: '没有找到 API Key 配置条目' }
  const clear = patch['clear'] === true
  const value = typeof patch['value'] === 'string' ? patch['value'].trim() : ''
  if (!clear && value === '') return { ok: false, error: '密钥不能为空（要移除请点「清除密钥」）' }
  if (value.length > 4_096) return { ok: false, error: '密钥过长' }
  try {
    if (clear) await credentials.unset(picked.ref)
    else await credentials.set(picked.ref, value)
    return { ok: true, snapshot: await systemSnapshot(context) }
  } catch (error) {
    return { ok: false, error: describeWriteError(error) }
  }
}

/** 保存模型 API 地址（可选；清空表示回落 provider 默认/环境变量）。 */
export async function saveEndpoint(context: unknown, patch: unknown): Promise<SystemResult> {
  const settings = serviceOf<SettingsLike>(context, 'settings')
  if (settings === null) return { ok: false, error: 'settings 服务不在场' }
  if (!isPlainObject(patch)) return { ok: false, error: '参数必须是 JSON 对象' }
  const baseURL = textOf(patch['baseURL'])
  if (baseURL === null) return { ok: false, error: 'baseURL 不合法' }
  if (baseURL !== '' && !/^https?:\/\/\S+$/u.test(baseURL)) return { ok: false, error: 'baseURL 必须是 http(s) 地址' }
  const picked = pickKey(settings)
  if (picked === null) return { ok: false, error: '没有找到模型接口配置条目' }
  try {
    if (baseURL === '') {
      await settings.mutate(picked.ns, [{ op: 'unset', path: ['baseURL'] }], picked.revision)
    } else {
      await settings.update(picked.ns, { baseURL }, picked.revision)
    }
    return { ok: true, snapshot: await systemSnapshot(context) }
  } catch (error) {
    return { ok: false, error: describeWriteError(error) }
  }
}

/**
 * 新增或更新一个自定义服务商：写 pi-ai 的 providers 字典、存 Key、可选设为默认模型。
 * 覆盖同一 route 即更新；不动其他 route（settings.update 对普通对象是深合并）。
 */
export async function saveProvider(context: unknown, patch: unknown): Promise<SystemResult> {
  const settings = serviceOf<SettingsLike>(context, 'settings')
  const credentials = serviceOf<CredentialsLike>(context, 'credentials')
  if (settings === null) return { ok: false, error: 'settings 服务不在场' }
  if (!isPlainObject(patch)) return { ok: false, error: '参数必须是 JSON 对象' }

  const route = textOf(patch['route'])
  const displayName = textOf(patch['displayName'] ?? '')
  const api = textOf(patch['api'] ?? 'openai-completions')
  const baseURL = textOf(patch['baseURL'])
  const modelId = textOf(patch['modelId'])
  const apiKeyEnv = textOf(patch['apiKeyEnv'] ?? '')
  const apiKey = typeof patch['apiKey'] === 'string' ? patch['apiKey'].trim() : ''
  const makeDefault = patch['makeDefault'] !== false
  const contextWindowRaw = patch['contextWindow']
  const contextWindow = contextWindowRaw === undefined || contextWindowRaw === '' || contextWindowRaw === null
    ? undefined
    : Number(contextWindowRaw)

  if (route === null || !ROUTE_PATTERN.test(route)) {
    return { ok: false, error: '服务商标识（route）只能是小写字母开头、含小写字母/数字/短横线，长度 2~33' }
  }
  if (baseURL === null || !/^https?:\/\/\S+$/u.test(baseURL)) return { ok: false, error: 'Base URL 必须是 http(s) 地址' }
  if (modelId === null || modelId === '') return { ok: false, error: '模型 ID 不能为空' }
  if (api === null || !PROTOCOLS.has(api)) return { ok: false, error: '协议只支持 openai-completions / anthropic-messages' }
  if (contextWindow !== undefined && (!Number.isSafeInteger(contextWindow) || contextWindow < 1024 || contextWindow > 10_000_000)) {
    return { ok: false, error: '上下文窗口必须是 1024~10000000 的整数（可留空）' }
  }
  if (apiKeyEnv !== null && apiKeyEnv !== '' && !REF_PATTERN.test(apiKeyEnv)) {
    return { ok: false, error: '凭据变量名只能是字母/数字/下划线，且不能以数字开头' }
  }
  if (apiKey.length > 4_096) return { ok: false, error: '密钥过长' }

  let described: ReturnType<SettingsLike['describe']>
  try {
    described = settings.describe({ redactSecrets: true })
  } catch (error) {
    return { ok: false, error: describeWriteError(error) }
  }
  const piRow = described.find(row => row.ns === 'llm-pi-ai')
  if (piRow === undefined) return { ok: false, error: '这台 dsh 没有启用通用模型适配器（llm-pi-ai）' }
  const ref = apiKeyEnv !== null && apiKeyEnv !== ''
    ? apiKeyEnv
    : `${route.replace(/[^a-z0-9]+/gu, '_').toUpperCase()}_API_KEY`

  const profile: Record<string, unknown> = {
    displayName: displayName === null || displayName === '' ? route : displayName,
    api,
    baseURL,
    apiKeyEnv: ref,
    models: [{
      id: modelId,
      ...(contextWindow === undefined ? {} : { contextWindow }),
    }],
  }
  try {
    await settings.update('llm-pi-ai', { providers: { [route]: profile } }, piRow.revision)
    if (apiKey !== '') {
      if (credentials === null) return { ok: false, error: '服务商已保存，但 credentials 服务不在场，密钥未写入' }
      await credentials.set(ref, apiKey)
    }
    if (makeDefault) {
      const modelRow = described.find(row => {
        const value: unknown = row.value
        return isPlainObject(value) && typeof value['provider'] === 'string' && typeof value['model'] === 'string'
      })
      if (modelRow !== undefined) {
        await settings.update(modelRow.ns, { provider: route, model: modelId }, modelRow.revision)
      }
    }
    return { ok: true, snapshot: await systemSnapshot(context) }
  } catch (error) {
    return { ok: false, error: describeWriteError(error) }
  }
}

/**
 * 从服务商在线拉取可用的模型清单。
 *
 * OpenAI 兼容网关：`GET {baseURL}/models`；Anthropic 兼容网关：`GET {baseURL}/v1/models`。
 * Key 的取值顺序：请求里带的明文 → 该 route 已保存的凭证（经 credentials 服务）。
 * 明文不落库、不写日志；失败把服务商返回的片段截短回显，方便排错。
 */
export async function listModels(
  context: unknown,
  patch: unknown,
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<{ ok: boolean, error?: string, models?: string[] }> {
  const settings = serviceOf<SettingsLike>(context, 'settings')
  const credentials = serviceOf<CredentialsLike>(context, 'credentials')
  if (settings === null) return { ok: false, error: 'settings 服务不在场' }
  if (!isPlainObject(patch)) return { ok: false, error: '参数必须是 JSON 对象' }

  const route = textOf(patch['route'] ?? '') ?? ''
  const api = textOf(patch['api'] ?? 'openai-completions') ?? ''
  let baseURL = textOf(patch['baseURL'] ?? '') ?? ''
  const apiKeyRaw = typeof patch['apiKey'] === 'string' ? patch['apiKey'].trim() : ''

  // route 对准已保存的配置：Base URL / 协议 / 凭证 ref 都以保存值为准
  let savedRef = ''
  if (route !== '') {
    let described: ReturnType<SettingsLike['describe']>
    try {
      described = settings.describe({ redactSecrets: true })
    } catch (error) {
      return { ok: false, error: describeWriteError(error) }
    }
    const piRow = described.find(row => row.ns === 'llm-pi-ai')
    const dict = piRow !== undefined && isPlainObject(piRow.value) && isPlainObject(piRow.value['providers'])
      ? piRow.value['providers'] as Record<string, unknown>
      : {}
    const profile = isPlainObject(dict[route]) ? dict[route] as Record<string, unknown> : undefined
    if (profile !== undefined) {
      if (baseURL === '') baseURL = typeof profile['baseURL'] === 'string' ? profile['baseURL'] : ''
      if (typeof profile['apiKeyEnv'] === 'string') savedRef = profile['apiKeyEnv']
      if (patch['api'] === undefined && typeof profile['api'] === 'string') {
        if (!PROTOCOLS.has(profile['api'])) return { ok: false, error: '已保存的路由协议不认识，请重新保存该服务商' }
      }
    }
  }
  if (baseURL === '' || !/^https?:\/\/\S+$/u.test(baseURL)) return { ok: false, error: 'Base URL 必须是 http(s) 地址' }
  if (api === null || !PROTOCOLS.has(api)) return { ok: false, error: '协议只支持 openai-completions / anthropic-messages' }

  let key = apiKeyRaw
  if (key === '' && savedRef !== '' && credentials !== null) {
    try {
      const resolved = await credentials.resolve(savedRef)
      key = resolved?.value ?? ''
    } catch {
      key = ''
    }
  }
  if (key === '') return { ok: false, error: '该服务商还没有 API Key：先保存 Key，或在下拉按钮旁的输入框填一次' }

  const url = api === 'anthropic-messages' && !/\/v1\/?$/u.test(baseURL)
    ? `${baseURL.replace(/\/+$/u, '')}/v1/models`
    : `${baseURL.replace(/\/+$/u, '')}/models`
  const headers: Record<string, string> = {
    'authorization': `Bearer ${key}`,
    'x-api-key': key,
    'anthropic-version': '2023-06-01',
  }
  let response: Response
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(10_000),
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { ok: false, error: `拉取失败：${message.slice(0, 160)}` }
  }
  const raw = (await response.text().catch(() => '')).slice(0, 4096)
  if (!response.ok) {
    return {
      ok: false,
      error: `服务商返回 ${response.status}：${raw.replace(/\s+/gu, ' ').slice(0, 160) || '无响应体'}`,
    }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { ok: false, error: '返回的不是 JSON（检查 Base URL 是否已包含 /v1 等版本段）' }
  }
  const shape = isPlainObject(parsed) && Array.isArray(parsed['data']) ? parsed['data']
    : isPlainObject(parsed) && Array.isArray(parsed['models']) ? parsed['models']
    : Array.isArray(parsed) ? parsed : []
  const ids = shape
    .flatMap(item => (isPlainObject(item) && typeof item['id'] === 'string' ? [item['id']] : []))
    .filter(id => id.length <= 128 && !/[\u0000-\u001f]/u.test(id))
  if (ids.length === 0) {
    return { ok: false, error: '服务商返回里没有模型清单；检查 Base URL 与协议是否匹配（OpenAI 兼容 → /models）' }
  }
  return { ok: true, models: [...new Set(ids)].sort((a, b) => a.localeCompare(b)).slice(0, 300) }
}

/** 写失败原因：并发冲突/字段不可改/配置校验，都要能直接读懂。 */
function describeWriteError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error)
  return message.slice(0, 240)
}
