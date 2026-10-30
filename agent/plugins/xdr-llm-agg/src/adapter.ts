/**
 * llm-agg 专用 LlmAdapter：OpenAI Chat Completions 传输 + 会话 ID 请求头。
 *
 * 这是本插件存在的理由。dsh 的通用 pi-ai 适配器只能给一个服务商配**静态**
 * 请求头，而聚合网关需要每次请求携带 `GenerateOptions.sessionId`
 * （`x-session-id`）：网关据此把不同会话分摊到不同后端模型，并让同一会话
 * 粘在同一模型上。专用适配器在 `stream()` 里直接写这个头。
 *
 * 配置与令牌**每次请求现读**：控制台改端点/Key 后下一轮立即生效，不需要
 * 重启（与 dsh 其它适配器的 volatile 语义一致）。令牌只从 dsh 凭证库
 * （或同名环境变量）解析，不落日志。
 */

import {
  EMPTY_RESPONSE_CODE,
  attributionHeaders,
  LlmAdapter,
  LlmError,
} from '@deepseek-ai/dsh-llm'
import type {
  GenerateOptions,
  LlmModelInfo,
  LlmResolvedModelInfo,
  StreamChunk,
} from '@deepseek-ai/dsh-llm'
import type { ResolvedLlmAggConfig } from './config.ts'
import {
  ChatStreamTranslator,
  providerFailure,
  SseDecoder,
  toChatRequest,
  WireError,
  type WireChunk,
} from './wire.ts'

/** 适配器依赖：宿主插件提供的两个读取钩子。 */
export interface LlmAggAdapterOptions {
  /** 当前配置快照；每次操作调用一次，配置变更即时生效。 */
  config: () => ResolvedLlmAggConfig
  /**
   * 解析池 Key；引用为空串时返回 undefined（不发 Authorization）。
   * 引用已配置但解析不到时必须抛 `MISSING_CREDENTIAL`（fail loud）。
   */
  resolveApiKey: (ref: string) => Promise<string | undefined>
}

/** 单次请求的长度上限：错误体重读进内存前先截断。 */
const MAX_ERROR_BODY = 64 * 1024

/** 可重置的看门狗：超时即中止上游请求。 */
class Watchdog {
  private readonly controller = new AbortController()
  private timer: ReturnType<typeof setTimeout> | undefined

  constructor(private readonly timeoutMs: number) {
    this.pulse()
  }

  get signal(): AbortSignal {
    return this.controller.signal
  }

  /** 有数据到达：重置计时。 */
  pulse(): void {
    if (this.timer !== undefined) clearTimeout(this.timer)
    this.timer = setTimeout(() => { this.controller.abort() }, this.timeoutMs)
    // 别让一个挂起中的请求拖住进程退出（CLI/测试场景）。
    this.timer.unref?.()
  }

  /** 停止计时（不中止已完成的请求）。 */
  stop(): void {
    if (this.timer !== undefined) clearTimeout(this.timer)
    this.timer = undefined
  }

  abort(): void {
    this.controller.abort()
  }
}

/** 解析 JSON，非法负载返回 undefined（SSE 里偶有 keepalive/非 JSON 行）。 */
function parseJson(text: string): WireChunk | undefined {
  try {
    const parsed: unknown = JSON.parse(text)
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? parsed as WireChunk
      : undefined
  } catch {
    return undefined
  }
}

/** 面向 OpenAI Chat 的 llm-agg 适配器。 */
export class LlmAggAdapter extends LlmAdapter {
  constructor(private readonly options: LlmAggAdapterOptions) {
    super()
  }

  /**
   * 元数据查询用的容错配置读取：控制台正在编辑（端点暂时非法）时不能把
   * 整个 provider 目录拖垮——只有真正的请求路径（`stream`）才 fail loud。
   */
  private peek(): ResolvedLlmAggConfig | undefined {
    try {
      return this.options.config()
    } catch {
      return undefined
    }
  }

  override providerInfo(provider: string) {
    return { id: provider, name: this.peek()?.displayName ?? 'LLM-AGG' }
  }

  override listModels(provider: string): Promise<readonly LlmModelInfo[]> {
    return Promise.resolve(this.peek()?.models.map(model => ({
      provider,
      id: model.id,
      name: model.name ?? model.id,
      inputModalities: ['text'] as const,
    })) ?? [])
  }

  override resolveModel(provider: string, model: string): Promise<LlmResolvedModelInfo> {
    return Promise.resolve().then(() => {
      const config = this.peek()
      const declared = config?.models.find(entry => entry.id === model)
      const contextWindow = declared?.contextWindow ?? config?.defaultContextWindow
      const maxTokens = declared?.maxTokens ?? config?.maxTokens
      return {
        provider,
        id: model,
        name: declared?.name ?? model,
        inputModalities: ['text'] as const,
        ...contextWindow === undefined ? {} : { context: { contextWindow } },
        ...maxTokens === undefined ? {} : { defaultMaxTokens: maxTokens },
      }
    })
  }

  async *stream(options: GenerateOptions): AsyncGenerator<StreamChunk> {
    const config = this.options.config()
    const apiKey = await this.options.resolveApiKey(config.apiKeyEnv)
    const { messages, tools } = toChatRequest(options)
    const body = {
      model: options.model,
      messages,
      stream: true,
      stream_options: { include_usage: true },
      ...options.temperature === undefined ? {} : { temperature: options.temperature },
      max_tokens: options.maxTokens ?? config.maxTokens,
      ...tools === undefined ? {} : { tools, tool_choice: 'auto' },
      ...options.stop === undefined || options.stop.length === 0 ? {} : { stop: options.stop },
    }
    const headers: Record<string, string> = {
      // Harness 自有身份头；同名部署头不能覆盖。
      ...attributionHeaders(),
      'content-type': 'application/json',
      'accept': 'text/event-stream',
    }
    if (apiKey !== undefined) headers['authorization'] = `Bearer ${apiKey}`
    const session = options.sessionId === undefined ? '' : String(options.sessionId).trim()
    if (session !== '') headers[config.sessionHeader] = session

    const idle = new Watchdog(config.streamIdleTimeoutMs)
    const overall = new Watchdog(config.requestTimeoutMs)
    const signal = AbortSignal.any([
      idle.signal,
      overall.signal,
      ...(options.signal === undefined ? [] : [options.signal]),
    ])
    let response: Response
    try {
      response = await fetch(`${config.baseURL}/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal,
        redirect: 'error',
      })
    } catch (error) {
      idle.stop()
      overall.stop()
      throw this.transportError(error, options, idle, overall, config)
    }

    try {
      if (!response.ok) throw await this.responseError(response)
      const contentType = response.headers.get('content-type') ?? ''
      if (!contentType.toLowerCase().includes('text/event-stream')) {
        // 网关忽略 stream=true 时按完整响应处理，语义与流式一致。
        const text = (await response.text()).slice(0, MAX_ERROR_BODY)
        const parsed = parseJson(text)
        if (parsed === undefined) throw new LlmError('llm-agg: 上游返回了无法解析的响应', 'SERVER')
        const translator = new ChatStreamTranslator()
        const chunks = translator.pushChunk(parsed)
        if (!translator.hasContent()) throw emptiness()
        for (const chunk of chunks) yield chunk
        for (const chunk of translator.end()) yield chunk
        return
      }
      if (response.body === null) throw emptiness()
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      const sse = new SseDecoder()
      const translator = new ChatStreamTranslator()
      let done = false
      try {
        while (!done) {
          const next = await reader.read()
          if (next.done) break
          idle.pulse()
          for (const data of sse.push(decoder.decode(next.value, { stream: true }))) {
            if (data.trim() === '[DONE]') { done = true; break }
            const parsed = parseJson(data)
            if (parsed === undefined) continue
            for (const chunk of translator.pushChunk(parsed)) yield chunk
          }
        }
        if (!done) {
          // 先冲出 TextDecoder 里可能残留的多字节字符，再排空解帧器。
          for (const data of sse.push(decoder.decode())) {
            if (data.trim() === '[DONE]') { done = true; break }
            const parsed = parseJson(data)
            if (parsed === undefined) continue
            for (const chunk of translator.pushChunk(parsed)) yield chunk
          }
        }
        if (!done) {
          for (const data of sse.end()) {
            if (data.trim() === '[DONE]') break
            const parsed = parseJson(data)
            if (parsed === undefined) continue
            for (const chunk of translator.pushChunk(parsed)) yield chunk
          }
        }
      } finally {
        // 消费方提前停止时取消 socket；正常结束时这是无操作。
        void reader.cancel().catch(() => {})
      }
      if (!translator.hasContent()) throw emptiness()
      for (const chunk of translator.end()) yield chunk
    } catch (error) {
      throw this.transportError(error, options, idle, overall, config)
    } finally {
      idle.stop()
      overall.stop()
      overall.abort()
    }
  }

  /** 把非 2xx 响应转成结构化失败。 */
  private async responseError(response: Response): Promise<LlmError> {
    const text = (await response.text().catch(() => '')).slice(0, MAX_ERROR_BODY)
    const failure = providerFailure(response.status, text, response.headers.get('retry-after'))
    return new LlmError(failure.message, failure.code, {
      cause: new Error(text.slice(0, 2_000)),
      status: response.status,
      ...failure.retryAfterMs === undefined ? {} : { providerRetryAfterMs: failure.retryAfterMs },
    })
  }

  /** 统一映射中止/超时/网络错误，保留可路由的失败码。 */
  private transportError(
    error: unknown,
    options: GenerateOptions,
    idle: Watchdog,
    overall: Watchdog,
    config: ResolvedLlmAggConfig,
  ): Error {
    if (error instanceof LlmError) return error
    if (error instanceof WireError) return new LlmError(error.message, error.code, { cause: error })
    if (options.signal?.aborted === true) {
      return new LlmError('llm-agg: 请求已被调用方取消', 'ABORTED', { cause: error })
    }
    if (overall.signal.aborted) {
      return new LlmError(`llm-agg: 请求超过总时长上限 ${config.requestTimeoutMs}ms`, 'TIMEOUT', { cause: error })
    }
    if (idle.signal.aborted) {
      return new LlmError(`llm-agg: 流式读取空闲超过 ${config.streamIdleTimeoutMs}ms`, 'TIMEOUT', { cause: error })
    }
    const message = error instanceof Error ? error.message : String(error)
    return new LlmError(`llm-agg: 网关请求失败：${message}`, 'TRANSPORT', { cause: error })
  }
}

/** 空响应失败（上游正常结束但没有任何内容块）。 */
function emptiness(): LlmError {
  return new LlmError('llm-agg: 上游正常结束但没有返回任何内容', EMPTY_RESPONSE_CODE)
}
