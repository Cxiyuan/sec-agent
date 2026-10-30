/**
 * xdr-llm-agg — 聚合网关（Free-LLM-API / LLM-API-AGG）的专用 dsh 模型连接器。
 *
 * 与其它服务商的边界：本插件**只**声明 `llm-agg` 这一条路由；agent 在系统页
 * 选择其它服务商（DeepSeek 官方、pi-ai 自定义网关…）时完全不受影响。
 *
 * 为什么必须专用适配器：聚合网关的智能负载路由依赖请求级的会话标识。dsh 在
 * `GenerateOptions.sessionId` 上已经把会话身份交到适配器边界，通用 pi-ai
 * 适配器却只能发静态请求头；只有自研 `LlmAdapter` 能在每次请求上把
 * `sessionId` 写成 `x-session-id`。同一会话因此稳定落在同一后端模型上，
 * 不同并发会话被网关分摊到不同模型，后端不可用时网关自行重绑。
 *
 * 配置全部 volatile：控制台（xdr-ui 系统页）改完端点/Key/模型清单后下一轮
 * 请求立即生效。凭据只经 dsh credentials 服务或同名环境变量解析。
 */

import type { Context } from '@deepseek-ai/cordis'
import { assertUsableApiKey, LlmError } from '@deepseek-ai/dsh-llm'
import { LlmAggAdapter } from './adapter.ts'
import { Config, DEFAULT_MODELS, PROVIDER, resolveConfig, SETTINGS_NS } from './config.ts'
import type { ResolvedLlmAggConfig } from './config.ts'

export { Config, DEFAULT_BASE_URL, DEFAULT_MODELS, PROVIDER, resolveConfig, SETTINGS_NS } from './config.ts'
export type { LlmAggModel, ResolvedLlmAggConfig } from './config.ts'
export { LlmAggAdapter } from './adapter.ts'
export type { LlmAggAdapterOptions } from './adapter.ts'
export {
  ChatStreamTranslator,
  SseDecoder,
  finishReasonOf,
  providerFailure,
  toChatRequest,
  toChatTools,
  toTokenUsage,
  translateCompletion,
  WireError,
} from './wire.ts'
export type {
  ChatMessage,
  ChatRequest,
  ChatTool,
  ChatToolCall,
  ProviderFailure,
  WireChunk,
  WireUsage,
} from './wire.ts'

/** Cordis function-plugin name（bundle patch 行的 id 与之对应）。 */
export const name = 'xdr-llm-agg'

/** 只依赖 LLM 注册表；凭证/设置服务按需读取，不在场时降级到环境变量。 */
export const inject = ['llm']

/** 凭证服务的最小结构化接口（不跨包 import type，避免必装 dsh-credentials）。 */
interface CredentialsLike {
  resolve(ref: string): Promise<{ value: string, source: string } | undefined>
}

/** 从 Context 读凭证服务；缺失时返回 undefined（纯环境变量部署）。 */
function credentialsOf(ctx: Context): CredentialsLike | undefined {
  const service: unknown = ctx.get('credentials')
  return typeof service === 'object' && service !== null
    && typeof (service as CredentialsLike).resolve === 'function'
    ? service as CredentialsLike
    : undefined
}

/**
 * 加载期读取配置：非法值只告警、不拒绝加载。
 *
 * 如果这里抛错，插件会变成 inactive，控制台的 `xdr-llm-agg` 设置条目也跟着
 * 消失——用户就再也没法在界面里把写坏的地址改回来（只能手改 profile）。
 * 所以路由照常注册：元数据查询走容错读取，真正的请求在 `stream()` 里带
 * `INVALID_CONFIG` 失败，控制台保存合法值后下一轮立即恢复。
 */
function initialConfig(config: Config): ResolvedLlmAggConfig {
  try {
    return resolveConfig(config)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.warn(`[xdr-llm-agg] 配置暂不可用，路由仍注册以便控制台修复：${message}`)
    const models = config.models.get()
    return {
      displayName: config.displayName.get().trim() || 'LLM-AGG',
      baseURL: config.baseURL.get().trim(),
      apiKeyEnv: config.apiKeyEnv.get().trim(),
      models: models.length === 0 ? [...DEFAULT_MODELS] : models,
      defaultContextWindow: config.defaultContextWindow.get(),
      maxTokens: config.maxTokens.get(),
      sessionHeader: config.sessionHeader.get().trim(),
      streamIdleTimeoutMs: config.streamIdleTimeoutMs.get(),
      requestTimeoutMs: config.requestTimeoutMs.get(),
    }
  }
}

/** 注册 llm-agg 适配器与可配置服务商目录项。 */
export function apply(ctx: Context, config: Config): void {
  // 加载期只求「能加载」：非法值由请求路径带 INVALID_CONFIG 失败（见 initialConfig）。
  const initial = initialConfig(config)

  const resolveApiKey = async (ref: string): Promise<string | undefined> => {
    if (ref === '') return undefined
    // 凭证服务每次请求现取：服务可能晚于本插件激活（apply 期读取会永久
    // 记住 undefined），而且控制台换 Key 后下一轮就要生效。
    const credentials = credentialsOf(ctx)
    const hit = credentials === undefined ? undefined : await credentials.resolve(ref)
    const value = hit !== undefined && hit.value.length > 0 ? hit.value : process.env[ref]
    if (value !== undefined && value.trim() !== '') return assertUsableApiKey(value, 'llm-agg', ref)
    throw new LlmError(
      `llm-agg: 没有可用的池 Key。请在控制台「系统 → 服务商」里保存 ${ref}，`
      + `或为容器设置同名环境变量；聚合网关的 /v1 不鉴权就没法路由`,
      'MISSING_CREDENTIAL',
    )
  }

  const adapter = new LlmAggAdapter({ config: () => resolveConfig(config), resolveApiKey })
  ctx.llm.registerAdapter([PROVIDER], adapter)
  ctx.llm.registerConfigurableProviders([{
    provider: PROVIDER,
    displayName: initial.displayName,
    settingsNs: SETTINGS_NS,
    settingsPath: [],
    // 本适配器只知道配置声明过的网关，不随 dsh 目录自带。
    declared: true,
    defaultBaseURL: initial.baseURL,
  }])

  console.log(
    `[xdr-llm-agg] apply(): route "${PROVIDER}" → ${initial.baseURL}`
    + `（会话头 ${initial.sessionHeader}，模型 ${initial.models.map(model => model.id).join('/')}）`,
  )
  if (credentialsOf(ctx) === undefined) {
    console.warn('[xdr-llm-agg] credentials 服务当前不在场：池 Key 先走环境变量，服务到位后自动改读凭证库。')
  }
}
