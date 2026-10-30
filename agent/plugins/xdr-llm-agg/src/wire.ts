/**
 * OpenAI Chat Completions 线协议转换（纯函数 + 纯状态机，可离线单测）。
 *
 * 为什么单独一层：dsh 的 `StreamChunk` 是各家适配器的公共词汇，而 llm-agg
 * 网关说的是 OpenAI Chat 方言。这里只做「词汇翻译」，不碰网络与凭证；
 * 因此本文件只有 `import type`，CI 用 `node --experimental-strip-types`
 * 跑测试时不需要先构建或加载宿主的 dsh 运行时。
 *
 * 与 llm-pi-ai 的差异（刻意）：本适配器**不支持图片输入**（XDR 分析智能体
 * 只发文本，网关侧路由到的后端也不保证视觉能力），遇到未 offload 的图片
 * 直接以 `UNSUPPORTED_CONTENT` 失败，而不是悄悄丢内容。
 */

import type {
  ContentBlock,
  FinishReason,
  GenerateOptions,
  RequestMessage,
  StreamChunk,
  TokenUsage,
  ToolCallId,
  ToolSchema,
} from '@deepseek-ai/dsh-llm'

/** 转换层自己的失败类型；适配器把它包成 `LlmError`。 */
export class WireError extends Error {
  /** 稳定的机器可路由失败码（与 dsh-llm 的约定一致）。 */
  readonly code: string

  constructor(message: string, code: string) {
    super(message)
    this.name = 'WireError'
    this.code = code
  }
}

// ---------------------------------------------------------------------------
// 请求方向：dsh 消息 → OpenAI Chat
// ---------------------------------------------------------------------------

/** OpenAI 文本内容分片（本适配器只会产出文本分片）。 */
export interface ChatTextPart {
  type: 'text'
  text: string
}

/** OpenAI 工具调用。 */
export interface ChatToolCall {
  id: string
  type: 'function'
  function: { name: string, arguments: string }
}

/** OpenAI Chat 消息。 */
export type ChatMessage =
  | { role: 'system', content: string }
  | { role: 'user', content: string | ChatTextPart[] }
  | { role: 'assistant', content: string | null, tool_calls?: ChatToolCall[] }
  | { role: 'tool', tool_call_id: string, content: string }

/** OpenAI 工具声明。 */
export interface ChatTool {
  type: 'function'
  function: { name: string, description: string, parameters: Record<string, unknown> }
}

/** 一次请求转换后的消息与工具。 */
export interface ChatRequest {
  messages: ChatMessage[]
  tools?: ChatTool[]
}

/** 消息里所有 text 块按原顺序拼接。 */
function textOf(blocks: readonly ContentBlock[]): string {
  let text = ''
  for (const block of blocks) {
    if (block.type === 'text') text += block.text
  }
  return text
}

/** 一条消息的文本内容；图片未 offload 时失败，其余扩展块忽略。 */
function textOfStrict(blocks: readonly ContentBlock[], role: string): string {
  for (const block of blocks) {
    if (block.type === 'image' && block.offloaded !== true) {
      throw new WireError(
        `llm-agg: 不支持 ${role} 消息里的图片输入；请改用文本描述或换用支持视觉的服务商`,
        'UNSUPPORTED_CONTENT',
      )
    }
  }
  return textOf(blocks)
}

/** 把 assistant 历史里的文本与工具调用投影成一条 OpenAI assistant 消息。 */
function assistantOf(message: RequestMessage): ChatMessage | undefined {
  let text = ''
  const toolCalls: ChatToolCall[] = []
  for (const block of message.content) {
    if (block.type === 'text') text += block.text
    else if (block.type === 'tool-call') {
      toolCalls.push({
        id: block.id,
        type: 'function',
        function: { name: block.name, arguments: block.arguments },
      })
    }
    // reasoning 是模型内部内容，不回灌给下一轮（不同后端对 thinking 回放的
    // 方言不一致，回灌反而会被部分网关拒绝）。
  }
  if (text === '' && toolCalls.length === 0) return undefined
  return {
    role: 'assistant',
    content: text === '' ? null : text,
    ...toolCalls.length === 0 ? {} : { tool_calls: toolCalls },
  }
}

/** 把一条 dsh 消息转换成零条或多条 OpenAI 消息。 */
function convertMessage(message: RequestMessage): ChatMessage[] {
  switch (message.role) {
    case 'system': {
      const text = textOfStrict(message.content, 'system')
      return text === '' ? [] : [{ role: 'system', content: text }]
    }
    case 'developer': {
      // 工具增删由 `options.tools` 的完整清单表达（本适配器每轮都发全量声明），
      // 事件里的文本仍按 system 指令下发，语义与 pi-ai 的投影一致。
      const text = textOf(message.content)
      return text === '' ? [] : [{ role: 'system', content: text }]
    }
    case 'user': {
      const text = textOfStrict(message.content, 'user')
      return text === '' ? [] : [{ role: 'user', content: text }]
    }
    case 'assistant': {
      const assistant = assistantOf(message)
      return assistant === undefined ? [] : [assistant]
    }
    case 'tool': {
      const text = textOf(message.content)
      return [{ role: 'tool', tool_call_id: message.toolCallId, content: text === '' ? '(no output)' : text }]
    }
    default:
      return []
  }
}

/**
 * 组装一次请求的消息列表。
 *
 * 开头的连续 system 消息（以及 `options.system`）合并成一条系统消息，
 * 与 OpenAI 客户端的常见做法一致；历史中间的 system 消息保留原位。
 * @param options - 已组装的请求。
 * @returns OpenAI 消息与工具声明。
 */
export function toChatRequest(options: GenerateOptions): ChatRequest {
  const leading: string[] = []
  if (options.system !== undefined && options.system !== '') leading.push(options.system)
  let start = 0
  while (start < options.messages.length && options.messages[start]?.role === 'system') {
    const text = textOfStrict(options.messages[start]!.content, 'system')
    if (text !== '') leading.push(text)
    start += 1
  }
  const messages: ChatMessage[] = []
  if (leading.length > 0) messages.push({ role: 'system', content: leading.join('\n\n') })
  for (const message of options.messages.slice(start)) messages.push(...convertMessage(message))
  const tools = toChatTools(options.tools)
  return { messages, ...tools === undefined ? {} : { tools } }
}

/**
 * 工具声明转换。`deferLoading` 的工具也照常发送：本适配器不实现
 * tool-addition 的增量语义，发全量清单是 OpenAI 兼容端点最安全的行为。
 * @param tools - 声明清单，可缺省。
 * @returns OpenAI 工具数组，或没有工具时的 undefined。
 */
export function toChatTools(tools: readonly ToolSchema[] | undefined): ChatTool[] | undefined {
  if (tools === undefined || tools.length === 0) return undefined
  return tools.map(tool => ({
    type: 'function',
    function: { name: tool.name, description: tool.description, parameters: tool.parameters },
  }))
}

// ---------------------------------------------------------------------------
// SSE 解帧
// ---------------------------------------------------------------------------

/**
 * 增量 SSE 解帧器：只认 `data:` 字段与空行分派（`event:`/`id:`/注释忽略）。
 * 一个 `data:` 事件可能被拆在多次 `push()` 里，也可能跨多行（用 `\n` 连接）。
 */
export class SseDecoder {
  private buffer = ''
  private data: string[] = []

  /**
   * 喂入一段解码后的文本。
   * @param text - 任意切分的文本片段。
   * @returns 本次凑齐的事件 data 负载（按到达顺序）。
   */
  push(text: string): string[] {
    this.buffer += text
    const events: string[] = []
    let newline = this.buffer.indexOf('\n')
    while (newline >= 0) {
      const line = this.buffer.slice(0, newline).replace(/\r$/u, '')
      this.buffer = this.buffer.slice(newline + 1)
      this.consume(line, events)
      newline = this.buffer.indexOf('\n')
    }
    return events
  }

  /**
   * 流结束：把残留的半行与未分派的事件交出来。
   * @returns 剩余事件 data 负载。
   */
  end(): string[] {
    const events: string[] = []
    if (this.buffer !== '') {
      this.consume(this.buffer.replace(/\r$/u, ''), events)
      this.buffer = ''
    }
    this.dispatch(events)
    return events
  }

  private consume(line: string, events: string[]): void {
    if (line === '') {
      this.dispatch(events)
      return
    }
    if (line.startsWith(':')) return
    if (!line.startsWith('data:')) return
    const value = line.slice(5)
    this.data.push(value.startsWith(' ') ? value.slice(1) : value)
  }

  private dispatch(events: string[]): void {
    if (this.data.length === 0) return
    events.push(this.data.join('\n'))
    this.data = []
  }
}

// ---------------------------------------------------------------------------
// 响应方向：OpenAI 流 → dsh StreamChunk
// ---------------------------------------------------------------------------

/** OpenAI 用量字段（兼容网关常见变体）。 */
export interface WireUsage {
  prompt_tokens?: number
  completion_tokens?: number
  total_tokens?: number
  prompt_tokens_details?: { cached_tokens?: number }
  completion_tokens_details?: { reasoning_tokens?: number }
}

/** OpenAI 工具调用增量。 */
export interface WireToolCallDelta {
  index?: number
  id?: string
  type?: string
  function?: { name?: string, arguments?: string }
}

/** OpenAI delta。 */
export interface WireDelta {
  content?: string | null
  reasoning_content?: string | null
  reasoning?: string | null
  tool_calls?: WireToolCallDelta[]
}

/** OpenAI 流式分片 / 非流式完整响应共用的形状。 */
export interface WireChoice {
  index?: number
  delta?: WireDelta
  message?: WireDelta
  finish_reason?: string | null
}

/** OpenAI 错误负载。 */
export interface WireFailureBody {
  message?: string
  type?: string
  code?: string | number | null
}

/** OpenAI 流式分片 / 非流式响应的顶层形状。 */
export interface WireChunk {
  id?: string
  model?: string
  choices?: WireChoice[]
  usage?: WireUsage | null
  error?: WireFailureBody | string
}

/** 把计数字段规整为非负整数。 */
function countOf(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0
}

/**
 * OpenAI usage → dsh 的 TokenUsage。
 *
 * dsh 的 `inputTokens` 是**未缓存**输入：网关若把缓存命中算进
 * `prompt_tokens`，这里减掉并单列 `cacheReadTokens`（与 pi-ai 的约定一致）。
 * @param usage - 网关返回的 usage。
 * @returns 规范化用量。
 */
export function toTokenUsage(usage: WireUsage): TokenUsage {
  const prompt = countOf(usage.prompt_tokens)
  const cached = Math.min(countOf(usage.prompt_tokens_details?.cached_tokens), prompt)
  const output = countOf(usage.completion_tokens)
  const total = countOf(usage.total_tokens) || prompt + output
  const reasoning = countOf(usage.completion_tokens_details?.reasoning_tokens)
  return {
    inputTokens: prompt - cached,
    outputTokens: output,
    ...total === 0 ? {} : { totalTokens: total },
    ...cached === 0 ? {} : { cacheReadTokens: cached },
    ...reasoning === 0 ? {} : { reasoningTokens: reasoning },
  }
}

/** OpenAI finish_reason → dsh FinishReason。 */
export function finishReasonOf(reason: string | null | undefined): FinishReason {
  switch (reason) {
    case 'tool_calls':
    case 'function_call':
      return { kind: 'tool-calls' }
    case 'length':
      return { kind: 'max-tokens' }
    case 'error':
      return { kind: 'error', failure: { message: 'upstream reported finish_reason=error', code: 'SERVER' } }
    default:
      return { kind: 'stop' }
  }
}

// ---------------------------------------------------------------------------
// HTTP 失败分类
// ---------------------------------------------------------------------------

/** 一次上游失败的分类结果。 */
export interface ProviderFailure {
  code: string
  message: string
  /** 服务端建议的重试等待（秒转毫秒），仅当头合法时存在。 */
  retryAfterMs?: number
}

const CONTEXT_OVERFLOW = /(?:context[\s_-]?(?:length|window)|maximum context|too (?:long|large) for (?:this|the) (?:model|context)|request (?:is )?too large)/iu
const QUOTA_EXHAUSTED = /(?:insufficient[\s_-]+(?:quota|balance|credits?)|quota[\s_-]?(?:exceeded|exhausted)|out of (?:credits?|budget)|usage[\s_-]limit)/iu

/** 从 OpenAI 风格错误体里取可读文本；非 JSON 时截断原文。 */
function failureText(body: string): { message: string, detail: string } {
  const trimmed = body.trim()
  if (trimmed === '') return { message: '', detail: '' }
  try {
    const parsed: unknown = JSON.parse(trimmed)
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      const record = parsed as Record<string, unknown>
      const error = record['error']
      if (typeof error === 'string') return { message: error, detail: error }
      if (typeof error === 'object' && error !== null && !Array.isArray(error)) {
        const inner = error as Record<string, unknown>
        const message = typeof inner['message'] === 'string' ? inner['message'] : ''
        const type = typeof inner['type'] === 'string' ? inner['type'] : ''
        const code = typeof inner['code'] === 'string' || typeof inner['code'] === 'number' ? String(inner['code']) : ''
        return { message, detail: [message, type, code].filter(part => part !== '').join(' ') }
      }
      const detail = typeof record['detail'] === 'string' ? record['detail'] : ''
      if (detail !== '') return { message: detail, detail }
    }
  } catch {
    // 非 JSON：按纯文本处理。
  }
  return { message: trimmed, detail: trimmed }
}

/**
 * 把 HTTP 状态与响应体映射成稳定的失败码。
 *
 * 码集合与 dsh 的默认重试策略对齐：`RATE_LIMIT`/`SERVER`/`TIMEOUT`/`TRANSPORT`
 * 可重试，`INVALID_CREDENTIAL`/`INVALID_REQUEST`/`UNKNOWN_MODEL`/`QUOTA`/
 * `CONTEXT_WINDOW_EXCEEDED` 不重试。
 * @param status - HTTP 状态码。
 * @param body - 响应体原文（调用方负责限制长度）。
 * @param retryAfter - `Retry-After` 头原值，可缺省。
 * @returns 分类结果。
 */
export function providerFailure(
  status: number,
  body: string,
  retryAfter?: string | null,
): ProviderFailure {
  const { message, detail } = failureText(body)
  const code = status === 401
    ? 'INVALID_CREDENTIAL'
    : status === 403
      // 403 既可能是鉴权失败，也可能是网关用 403 表达「额度耗尽」；文本更像
      // 后者时按 QUOTA 处理（不可重试），否则才是凭据问题。
      ? QUOTA_EXHAUSTED.test(detail) ? 'QUOTA' : 'INVALID_CREDENTIAL'
      : status === 402
        ? 'QUOTA'
        : status === 404
          ? 'UNKNOWN_MODEL'
          : status === 408
            ? 'TIMEOUT'
            : status === 429
              ? 'RATE_LIMIT'
              : status >= 500
                ? 'SERVER'
                : CONTEXT_OVERFLOW.test(detail)
                  ? 'CONTEXT_WINDOW_EXCEEDED'
                  : QUOTA_EXHAUSTED.test(detail)
                    ? 'QUOTA'
                    : 'INVALID_REQUEST'
  const seconds = retryAfter === undefined || retryAfter === null ? Number.NaN : Number(retryAfter)
  return {
    code,
    message: message === '' ? `llm-agg: upstream returned HTTP ${status}` : `llm-agg: ${message}`,
    ...Number.isFinite(seconds) && seconds > 0 ? { retryAfterMs: Math.min(seconds, 3_600) * 1_000 } : {},
  }
}

/** 从流内错误负载构造异常。 */
export function streamFailure(error: WireFailureBody | string): WireError {
  if (typeof error === 'string') return new WireError(`llm-agg: upstream stream error: ${error}`, 'SERVER')
  const detail = [error.message, error.type, error.code === null || error.code === undefined ? '' : String(error.code)]
    .filter((part): part is string => typeof part === 'string' && part !== '')
    .join(' ')
  const code = QUOTA_EXHAUSTED.test(detail)
    ? 'QUOTA'
    : CONTEXT_OVERFLOW.test(detail) ? 'CONTEXT_WINDOW_EXCEEDED' : 'SERVER'
  return new WireError(`llm-agg: upstream stream error${detail === '' ? '' : `: ${detail}`}`, code)
}

// ---------------------------------------------------------------------------
// 流式翻译
// ---------------------------------------------------------------------------

interface TextState {
  kind: 'text'
  index: number
  text: string
}

interface ReasoningState {
  kind: 'reasoning'
  index: number
  text: string
}

interface ToolState {
  kind: 'tool-call'
  index: number
  id: string
  name: string
  arguments: string
}

type BlockState = TextState | ReasoningState | ToolState

/**
 * 把一个 OpenAI Chat 流翻译成 dsh 的 `StreamChunk` 序列。
 *
 * 块 index 按**首次出现顺序**分配（文本 0、推理 1、工具 2…），工具调用
 * 用网关给的 `tool_calls[].index` 归并；网关没给 index 时按出现顺序兜底。
 * `finish` 不在此处立即发出：带 usage 的收尾分片可能晚于 finish_reason，
 * 由调用方在流结束后统一 `end()`。
 */
export class ChatStreamTranslator {
  private readonly blocks: BlockState[] = []
  private readonly tools = new Map<number, ToolState>()
  private nextIndex = 0
  private nextImplicitTool = 0
  private text: TextState | undefined
  private reasoning: ReasoningState | undefined
  private finish: FinishReason | undefined
  private usageEmitted = false

  /** 是否已经产生任何内容块（用于识别空响应）。 */
  hasContent(): boolean {
    return this.blocks.length > 0
  }

  /**
   * 处理一个 SSE/JSON 分片。
   * @param chunk - 解析后的 OpenAI 分片。
   * @returns 本次应发出的 chunk（不含 finish）。
   * @throws {WireError} 分片携带上游错误时。
   */
  pushChunk(chunk: WireChunk): StreamChunk[] {
    if (chunk.error !== undefined && chunk.error !== null) throw streamFailure(chunk.error)
    const events: StreamChunk[] = []
    const choice = chunk.choices?.[0]
    if (choice !== undefined) {
      const delta = choice.delta ?? choice.message
      if (delta !== undefined) events.push(...this.applyDelta(delta))
      if (choice.finish_reason !== undefined && choice.finish_reason !== null) {
        this.finish = finishReasonOf(choice.finish_reason)
      }
    }
    // 部分网关在每个分片都带 usage；只认第一份，避免下游反复覆盖。
    if (!this.usageEmitted && chunk.usage !== undefined && chunk.usage !== null) {
      this.usageEmitted = true
      events.push({ type: 'usage', usage: toTokenUsage(chunk.usage) })
    }
    return events
  }

  /**
   * 结束流：补齐 block-end 并发出终端 finish。
   * @returns 收尾 chunk 序列。
   */
  end(): StreamChunk[] {
    const events: StreamChunk[] = this.blocks.map(block => ({
      type: 'block-end' as const,
      index: block.index,
      block: block.kind === 'text'
        ? { type: 'text', text: block.text }
        : block.kind === 'reasoning'
          ? { type: 'reasoning', text: block.text }
          : { type: 'tool-call', id: block.id as unknown as ToolCallId, name: block.name, arguments: block.arguments },
    }))
    events.push({ type: 'finish', reason: this.finish ?? { kind: 'stop' } })
    return events
  }

  private applyDelta(delta: WireDelta): StreamChunk[] {
    const events: StreamChunk[] = []
    const reasoning = delta.reasoning_content ?? delta.reasoning
    if (typeof reasoning === 'string' && reasoning !== '') events.push(...this.reasoningDelta(reasoning))
    if (typeof delta.content === 'string' && delta.content !== '') events.push(...this.textDelta(delta.content))
    if (Array.isArray(delta.tool_calls)) {
      for (const call of delta.tool_calls) events.push(...this.toolDelta(call))
    }
    return events
  }

  private reasoningDelta(text: string): StreamChunk[] {
    if (this.reasoning === undefined) {
      this.reasoning = { kind: 'reasoning', index: this.nextIndex++, text: '' }
      this.blocks.push(this.reasoning)
      const start: StreamChunk = { type: 'block-start', index: this.reasoning.index, blockType: 'reasoning' }
      this.reasoning.text += text
      return [start, { type: 'reasoning-delta', index: this.reasoning.index, text }]
    }
    this.reasoning.text += text
    return [{ type: 'reasoning-delta', index: this.reasoning.index, text }]
  }

  private textDelta(text: string): StreamChunk[] {
    if (this.text === undefined) {
      this.text = { kind: 'text', index: this.nextIndex++, text: '' }
      this.blocks.push(this.text)
      const start: StreamChunk = { type: 'block-start', index: this.text.index, blockType: 'text' }
      this.text.text += text
      return [start, { type: 'text-delta', index: this.text.index, text }]
    }
    this.text.text += text
    return [{ type: 'text-delta', index: this.text.index, text }]
  }

  private toolDelta(call: WireToolCallDelta): StreamChunk[] {
    const key = typeof call.index === 'number' && Number.isSafeInteger(call.index) && call.index >= 0
      ? call.index
      : this.nextImplicitTool
    this.nextImplicitTool = Math.max(this.nextImplicitTool, key + 1)
    const name = call.function?.name
    const argumentsDelta = call.function?.arguments ?? ''
    let state = this.tools.get(key)
    const events: StreamChunk[] = []
    if (state === undefined) {
      state = {
        kind: 'tool-call',
        index: this.nextIndex++,
        id: typeof call.id === 'string' && call.id !== '' ? call.id : `call-${key}`,
        name: typeof name === 'string' ? name : '',
        arguments: '',
      }
      this.tools.set(key, state)
      this.blocks.push(state)
      events.push({ type: 'block-start', index: state.index, blockType: 'tool-call' })
    } else {
      if (typeof call.id === 'string' && call.id !== '') state.id = call.id
      if (typeof name === 'string' && name !== '') state.name = name
    }
    state.arguments += argumentsDelta
    events.push({
      type: 'tool-call-delta',
      index: state.index,
      id: state.id as unknown as ToolCallId,
      ...typeof name === 'string' && name !== '' ? { name } : {},
      argumentsDelta,
    })
    return events
  }
}

/**
 * 非流式完整响应 → chunk 序列（网关忽略 stream=true 时的兜底）。
 * @param body - 完整响应 JSON。
 * @returns 与流式路径同构的 chunk，含 block-end 与 finish。
 */
export function translateCompletion(body: WireChunk): StreamChunk[] {
  const translator = new ChatStreamTranslator()
  return [...translator.pushChunk(body), ...translator.end()]
}
