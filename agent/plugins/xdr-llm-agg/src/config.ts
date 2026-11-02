/**
 * llm-agg 连接器配置：端点、凭据引用、可选模型清单与超时。
 *
 * 字段全部 `volatile`：控制台（xdr-ui 的系统页）通过 dsh settings 服务
 * 直接改写这些值，下一次请求读到新值，**不需要重启**。只认「配置 +
 * 凭证库」，不缓存令牌。
 *
 * 路由固定为 `llm-agg`：它既是 dsh 的 provider 名，也是 `default-model`
 * 里写的值；本插件是唯一声明该路由的适配器（不能与 llm-pi-ai 的同名
 * route 共存，否则注册时抛 DUPLICATE_ADAPTER）。
 */

import type { Volatile } from '@deepseek-ai/cordis'
import { resolveRetryPolicy, RetryPolicySchema } from '@deepseek-ai/dsh-llm'
import type { NormalRetryPolicyConfig, RetryPolicyConfig, ResolvedRetryPolicy } from '@deepseek-ai/dsh-llm'
import z from '@deepseek-ai/schemastery'

/** 本插件拥有的唯一 provider 路由。 */
export const PROVIDER = 'llm-agg'

/** 插件在 profile 里的条目 id；xdr-ui 按它找设置命名空间。 */
export const SETTINGS_NS = 'xdr-llm-agg'

/** 默认网关地址：容器与 Free-LLM-API 同机时经 host-gateway 访问。 */
export const DEFAULT_BASE_URL = 'http://host.docker.internal:8788/v1'

/** 网关侧的三个池别名；显式模型 ID 也可以直接写。 */
export const DEFAULT_MODELS: readonly LlmAggModel[] = [
  { id: 'auto', name: 'Auto（智能路由）' },
  { id: 'free', name: 'Free（只用免费额度）' },
  { id: 'cheap', name: 'Cheap（最低倍率）' },
]

/** 一条可选模型（选择器展示用；请求不校验成员资格）。 */
export interface LlmAggModel {
  /** 传给网关的 model 字段。 */
  id: string
  /** 选择器里的显示名；缺省用 id。 */
  name?: string
  /** 已知上下文窗口；缺省用 defaultContextWindow。 */
  contextWindow?: number
  /** 单请求输出上限；缺省用 maxTokens。 */
  maxTokens?: number
}

/** 插件配置（profile 设置页 / cordis.patch.yml 均可提供）。 */
export interface Config {
  /** 选择器与诊断里显示的服务商名。 */
  displayName: Volatile<string>
  /** 网关的 /v1 根路径（例如 http://host.docker.internal:8788/v1）。 */
  baseURL: Volatile<string>
  /** 池 Key 的 credential-ref；空串 = 不发送 Authorization。 */
  apiKeyEnv: Volatile<string>
  /** 选择器可选的模型清单；空清单回落默认 auto/free/cheap。 */
  models: Volatile<LlmAggModel[]>
  /** 模型没有声明上下文窗口时的保守值。 */
  defaultContextWindow: Volatile<number>
  /** 请求没带 maxTokens 时的默认输出上限。 */
  maxTokens: Volatile<number>
  /** 会话标识请求头名（网关读 x-session-id）。 */
  sessionHeader: Volatile<string>
  /** 流式读取的空闲超时（毫秒，两帧之间）。 */
  streamIdleTimeoutMs: Volatile<number>
  /** 单次请求总时长上限（毫秒）。 */
  requestTimeoutMs: Volatile<number>
  /** 工具结果送入模型前的字符预算；超出时按结构化/首尾裁剪。 */
  toolResultMaxChars: Volatile<number>
  /** 文本裁剪时保留的头部字符数。 */
  toolResultHeadChars: Volatile<number>
  /** 文本裁剪时保留的尾部字符数。 */
  toolResultTailChars: Volatile<number>
  /**
   * 模型请求重试策略。默认比 dsh 通用策略更保守：每次重试都会重发整段
   * 上下文，5 次重试在多步会话里代价很高。
   */
  retryPolicy: Volatile<RetryPolicyConfig | undefined>
}

const modelSchema: z<LlmAggModel> = z.object({
  id: z.string().required(),
  name: z.string(),
  contextWindow: z.number().step(1).min(1),
  maxTokens: z.number().step(1).min(1),
})

/**
 * 连接器配置 schema。
 *
 * 刻意不写 `: z<Config>` 注解：volatile 字段的 schema 输入是普通值、输出是
 * `Volatile<T>`，注解会把「输入类型」也钉成带引用的 Config，在
 * strictFunctionTypes 下反而不成立。dsh 自己的适配器（llm-deepseek-api-key
 * 等）同样只导出 schema 让类型自然推导。
 */
export const Config = z.object({
  displayName: z.string().default('LLM-AGG（智能路由）').volatile(),
  baseURL: z.string().default(DEFAULT_BASE_URL).volatile(),
  apiKeyEnv: z.string().role('credential-ref').default('LLM_AGG_API_KEY').volatile(),
  models: z.array(modelSchema).default([...DEFAULT_MODELS]).volatile(),
  defaultContextWindow: z.number().step(1).min(1024).default(128_000).volatile(),
  maxTokens: z.number().step(1).min(1).default(8_192).volatile(),
  sessionHeader: z.string().default('x-session-id').volatile(),
  streamIdleTimeoutMs: z.number().step(1).min(1_000).default(300_000).volatile(),
  requestTimeoutMs: z.number().step(1).min(1_000).default(900_000).volatile(),
  // 工具结果会随历史进入后续每一步请求；50k 字符的原始结果在 6 步会话里
  // 会被重复发送几十万字符。默认 12k 预算，保留首尾，中间给出明确裁剪标记。
  toolResultMaxChars: z.number().step(1).min(1_000).default(12_000).volatile(),
  toolResultHeadChars: z.number().step(1).min(0).default(9_000).volatile(),
  toolResultTailChars: z.number().step(1).min(0).default(2_000).volatile(),
  retryPolicy: RetryPolicySchema.volatile(),
})

/** 一次请求读到的一份配置快照（已去掉 volatile 引用）。 */
export interface ResolvedLlmAggConfig {
  readonly displayName: string
  readonly baseURL: string
  readonly apiKeyEnv: string
  readonly models: readonly LlmAggModel[]
  readonly defaultContextWindow: number
  readonly maxTokens: number
  readonly sessionHeader: string
  readonly streamIdleTimeoutMs: number
  readonly requestTimeoutMs: number
  readonly toolResultMaxChars: number
  readonly toolResultHeadChars: number
  readonly toolResultTailChars: number
  readonly retryPolicy: ResolvedRetryPolicy
}

function resolveToolResultLimits(
  config: Config,
): Pick<ResolvedLlmAggConfig, 'toolResultMaxChars' | 'toolResultHeadChars' | 'toolResultTailChars'> {
  const maxChars = Math.max(1_000, Math.floor(Number(config.toolResultMaxChars.get())))
  const headChars = Math.min(
    Math.max(0, Math.floor(Number(config.toolResultHeadChars.get()))),
    Math.max(0, maxChars - 300),
  )
  const tailChars = Math.min(
    Math.max(0, Math.floor(Number(config.toolResultTailChars.get()))),
    Math.max(0, maxChars - headChars - 200),
  )
  return { toolResultMaxChars: maxChars, toolResultHeadChars: headChars, toolResultTailChars: tailChars }
}

/** 默认重试比 dsh 通用 5 次更保守：每次重试都会重发整段上下文。 */
const DEFAULT_RETRY_POLICY: NormalRetryPolicyConfig = {
  mode: 'normal',
  maxRetries: 2,
  retryableCodes: ['EMPTY_RESPONSE', 'RATE_LIMIT', 'SERVER', 'TIMEOUT', 'TRANSPORT'],
  backoff: { initialDelayMs: 1_000, maxDelayMs: 8_000, jitterRatio: 0.2 },
}

/**
 * Volatile 暴露的是只读快照，而 retry 解析器接收可变配置。
 * 复制成普通对象，避免 readonly 数组/字段的类型不兼容。
 */
export function resolveRetryPolicyConfig(config: Config): ResolvedRetryPolicy {
  const raw = config.retryPolicy.get()
  const policy: RetryPolicyConfig = raw === undefined
    ? {
        ...DEFAULT_RETRY_POLICY,
        backoff: { ...(DEFAULT_RETRY_POLICY.backoff ?? {}) },
      } as RetryPolicyConfig
    : JSON.parse(JSON.stringify(raw)) as RetryPolicyConfig
  if (policy.mode === 'normal') {
    const backoff = policy.backoff
    // 配置层可能把 schema 的通用默认值（5 次、500ms/10s/0.1）materialize
    // 出来。只有完全命中这组默认值时才改成 2 次/1–8 秒；显式配置保留，
    // 便于运维按需调高。
    if ((policy.maxRetries ?? 5) === 5
      && backoff !== undefined
      && backoff.initialDelayMs === 500
      && backoff.maxDelayMs === 10_000
      && backoff.jitterRatio === 0.1) {
      policy.maxRetries = 2
      policy.backoff = { initialDelayMs: 1_000, maxDelayMs: 8_000, jitterRatio: 0.2 }
    }
  }
  return resolveRetryPolicy(policy, 'xdr-llm-agg: retryPolicy')
}

const REF_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/u
const HEADER_PATTERN = /^[A-Za-z0-9-]+$/u

/**
 * 读取并校验当前配置。
 *
 * 每次请求调用一次：volatile 引用在 settings 写入后即时更新。非法值直接
 * 抛错（fail loud）——把请求发到一个空地址只会得到难以定位的超时。
 * @param config - 插件持有的 live 配置。
 * @returns 一份不可变配置快照。
 */
export function resolveConfig(config: Config): ResolvedLlmAggConfig {
  const baseURL = config.baseURL.get().trim().replace(/\/+$/u, '')
  if (!/^https?:\/\/\S+$/u.test(baseURL)) {
    throw new Error(`llm-agg: baseURL 必须是 http(s) 地址，当前是 "${baseURL}"`)
  }
  const apiKeyEnv = config.apiKeyEnv.get().trim()
  if (apiKeyEnv !== '' && !REF_PATTERN.test(apiKeyEnv)) {
    throw new Error(`llm-agg: apiKeyEnv 必须是环境变量/凭据名（字母数字下划线），当前是 "${apiKeyEnv}"`)
  }
  const sessionHeader = config.sessionHeader.get().trim()
  if (!HEADER_PATTERN.test(sessionHeader)) {
    throw new Error(`llm-agg: sessionHeader 不是合法的 HTTP 头名，当前是 "${sessionHeader}"`)
  }
  const seen = new Set<string>()
  const models: LlmAggModel[] = []
  for (const entry of config.models.get()) {
    const id = entry.id.trim()
    if (id === '' || seen.has(id)) continue
    seen.add(id)
    const name = entry.name?.trim()
    models.push({
      id,
      ...name === undefined || name === '' ? {} : { name },
      ...entry.contextWindow === undefined ? {} : { contextWindow: entry.contextWindow },
      ...entry.maxTokens === undefined ? {} : { maxTokens: entry.maxTokens },
    })
  }
  return Object.freeze({
    displayName: config.displayName.get().trim() || 'LLM-AGG',
    baseURL,
    apiKeyEnv,
    models: Object.freeze(models.length === 0 ? [...DEFAULT_MODELS] : models),
    defaultContextWindow: config.defaultContextWindow.get(),
    maxTokens: config.maxTokens.get(),
    sessionHeader,
    streamIdleTimeoutMs: config.streamIdleTimeoutMs.get(),
    requestTimeoutMs: config.requestTimeoutMs.get(),
    ...resolveToolResultLimits(config),
    retryPolicy: resolveRetryPolicyConfig(config),
  })
}
