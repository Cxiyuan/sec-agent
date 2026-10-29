/**
 * 分析过程时间线：读 DSH 会话日志（`session.v4.jsonl.zstd`），给控制台一个"看得见在干什么"的视图。
 *
 * 为什么直接读日志而不是走 `sessionQuery`：控制台要的是**原始事件顺序 + 当前工具调用**，
 * 查询服务返回的是折叠后的会话面（没有原始事件体）。日志是唯一的完整事实来源，
 * 而且是 append-only：轮询时带 `after` 只取新增事件，就能实时看到运行中的会话。
 *
 * 输出做**压缩投影**：只保留能解释"分析是怎么走的"的字段（谁说了什么、调了什么工具、
 * 拿回什么、烧了多少 token、哪里报错），正文各自截断，避免把整段日志塞给浏览器。
 */

import { promises as fs } from 'node:fs'
import path from 'node:path'
import * as zlib from 'node:zlib'

/** 一条时间线事件（控制台直接渲染）。 */
export interface TimelineEvent {
  readonly seq: number
  readonly time: number
  readonly kind: 'task' | 'thinking' | 'assistant' | 'tool' | 'tool_result' | 'usage' | 'error' | 'turn'
  readonly label: string
  readonly detail: string
  readonly turn: number
  readonly step: number
  readonly tokens: number
  readonly isError: boolean
}

export interface SessionTimeline {
  readonly ok: boolean
  readonly error?: string
  readonly sessionId: string
  readonly running: boolean
  readonly startedAt: string
  readonly updatedAt: string
  readonly events: readonly TimelineEvent[]
  readonly tools: readonly { readonly name: string; readonly count: number; readonly errors: number; readonly totalMs: number }[]
  readonly tokens: {
    readonly input: number
    readonly output: number
    readonly cacheRead: number
    readonly cacheWrite: number
    readonly total: number
    readonly reported: boolean
  }
  readonly nextSeq: number
  readonly truncated: boolean
}

interface RawEvent {
  readonly type?: string
  readonly seq?: number
  readonly time?: number
  readonly data?: Record<string, unknown>
}

const MAX_EVENTS = 400
const DETAIL_LIMIT = 600

function clip(value: unknown, max = DETAIL_LIMIT): string {
  const text = typeof value === 'string' ? value : value === undefined || value === null ? '' : String(value)
  const trimmed = text.replace(/\s+/gu, ' ').trim()
  return trimmed.length <= max ? trimmed : `${trimmed.slice(0, max)}…`
}

/** 找到某个会话的日志文件（目录按 `<sessionId>/session.v4.jsonl.zstd` 组织）。 */
async function locate(root: string, sessionId: string): Promise<string | null> {
  const direct = path.join(root, sessionId, 'session.v4.jsonl.zstd')
  try {
    await fs.access(direct)
    return direct
  } catch {
    // 会话落在 `_no-cwd` 之类的一层子目录下：扫一层就够（不递归整个卷）
    let entries: Array<{ name: string, isDirectory(): boolean }>
    try {
      entries = await fs.readdir(root, { withFileTypes: true })
    } catch {
      return null
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const candidate = path.join(root, entry.name, sessionId, 'session.v4.jsonl.zstd')
      try {
        await fs.access(candidate)
        return candidate
      } catch {
        continue
      }
    }
    return null
  }
}

function textOfContent(content: unknown): string {
  if (!Array.isArray(content)) return ''
  const parts: string[] = []
  for (const part of content) {
    if (typeof part !== 'object' || part === null) continue
    const row = part as { type?: string, text?: string }
    if (row.type === 'text' && typeof row.text === 'string') parts.push(row.text)
  }
  return parts.join('\n')
}

/** 一条 usage 对象 → 三个数（兼容 camelCase 与 Anthropic 的 snake_case）。 */
function usageCounts(raw: unknown): {
  input: number
  output: number
  cacheRead: number
  cacheWrite: number
  total: number
} | null {
  if (typeof raw !== 'object' || raw === null) return null
  const row = raw as Record<string, unknown>
  const pick = (...keys: string[]): number => {
    for (const key of keys) {
      const value = row[key]
      if (typeof value === 'number' && Number.isFinite(value)) return value
    }
    return 0
  }
  const input = pick('inputTokens', 'input_tokens', 'input')
  const output = pick('outputTokens', 'output_tokens', 'output')
  const cacheRead = pick('cacheReadTokens', 'cache_read_input_tokens', 'cache_read_tokens', 'cached_tokens')
  const cacheWrite = pick('cacheWriteTokens', 'cache_creation_input_tokens', 'cache_write_tokens')
  const total = pick('totalTokens', 'total_tokens', 'total') || input + output + cacheRead
  if (input === 0 && output === 0 && cacheRead === 0 && total === 0) return null
  return { input, output, cacheRead, cacheWrite, total }
}

function reasoningOfContent(content: unknown): string {
  if (!Array.isArray(content)) return ''
  const parts: string[] = []
  for (const part of content) {
    if (typeof part !== 'object' || part === null) continue
    const row = part as { type?: string, text?: string }
    if (row.type === 'reasoning' && typeof row.text === 'string') parts.push(row.text)
  }
  return parts.join('\n')
}

/**
 * 读一个会话的时间线。
 *
 * @param root - 会话根目录（容器里是 `/data/dsh/sessions`）。
 * @param sessionId - 会话 ID。
 * @param options.after - 只要 seq 大于它的事件（实时轮询用）。
 * @param options.running - 过程是否还在跑（决定 `running` 标记与轮询提示）。
 */
export async function readSessionTimeline(
  root: string,
  sessionId: string,
  options: { readonly after?: number, readonly running?: boolean } = {},
): Promise<SessionTimeline> {
  const empty = (error: string): SessionTimeline => ({
    ok: false,
    error,
    sessionId,
    running: false,
    startedAt: '',
    updatedAt: '',
    events: [],
    tools: [],
    tokens: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0, reported: false },
    nextSeq: options.after ?? 0,
    truncated: false,
  })
  const file = await locate(root, sessionId)
  if (file === null) return empty(`找不到会话日志（${sessionId}）`)
  // Node ≥ 22.15 才有 zstd；旧版本显式报错，不静默返回空时间线
  const decompress = (zlib as unknown as { zstdDecompressSync?: (input: Buffer) => Buffer }).zstdDecompressSync
  if (decompress === undefined) return empty('当前 Node 不支持 zstd（需要 Node ≥ 22.15）')
  let raw: Buffer
  try {
    const compressed = await fs.readFile(file)
    raw = decompress(compressed)
  } catch (error) {
    return empty(`读会话日志失败：${error instanceof Error ? error.message : String(error)}`)
  }
  return parseSessionLog(raw.toString('utf8'), sessionId, options)
}

/** 纯解析（单测入口）：JSONL 文本 → 压缩投影。 */
export function parseSessionLog(
  text: string,
  sessionId: string,
  options: { readonly after?: number, readonly running?: boolean } = {},
): SessionTimeline {
  const after = Math.max(0, Number(options.after ?? 0))
  const events: TimelineEvent[] = []
  const tools = new Map<string, { name: string, count: number, errors: number, totalMs: number, openAt: number }>()
  const tokens = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0, reported: false }
  let firstTime = 0
  let lastTime = 0
  let nextSeq = after
  let truncated = false
  let sawTask = false

  const push = (row: TimelineEvent): void => {
    if (row.time > 0) {
      if (firstTime === 0 || row.time < firstTime) firstTime = row.time
      if (row.time > lastTime) lastTime = row.time
    }
    if (row.seq > nextSeq) nextSeq = row.seq
    if (row.seq <= after) return
    events.push(row)
  }

  for (const line of text.split('\n')) {
    if (line.trim() === '') continue
    let event: RawEvent
    try {
      event = JSON.parse(line) as RawEvent
    } catch {
      continue
    }
    const type = String(event.type ?? '')
    const seq = Number(event.seq ?? 0)
    const time = Number(event.time ?? 0)
    const data = (event.data ?? {}) as Record<string, unknown>
    const turn = Number(data['turn'] ?? 0)
    const step = Number(data['step'] ?? 0)
    const base = { seq, time, turn, step, tokens: 0, isError: false }
    if (type === 'user/message') {
      const text = textOfContent(data['content'])
      // 运行时上下文/时间快照是系统注入的噪声，不占时间线
      if (text === '' || text.startsWith('Current runtime context') || text.startsWith('Time sampled while')) continue
      if (sawTask) continue
      sawTask = true
      push({ ...base, kind: 'task', label: '下发任务', detail: clip(text, 900) })
      continue
    }
    if (type === 'assistant/message') {
      const message = (data['message'] ?? {}) as Record<string, unknown>
      // 有些版本把 usage 直接挂在 message 上（不单独发 attempt 事件）
      const fromMessage = usageCounts(data['usage']) ?? usageCounts(message['usage'])
      if (fromMessage !== null) {
        tokens.input += fromMessage.input
        tokens.output += fromMessage.output
        tokens.cacheRead += fromMessage.cacheRead
        tokens.cacheWrite += fromMessage.cacheWrite
        tokens.total += fromMessage.total
        tokens.reported = true
        push({ ...base, kind: 'usage', label: 'token 用量', detail: `缓存读 ${fromMessage.cacheRead} / 新输入 ${fromMessage.input} / 输出 ${fromMessage.output}`, tokens: fromMessage.total })
      }
      const thinking = reasoningOfContent(message['content'])
      if (thinking !== '') push({ ...base, kind: 'thinking', label: '思考', detail: clip(thinking) })
      const text = textOfContent(message['content'])
      if (text !== '') push({ ...base, kind: 'assistant', label: '模型输出', detail: clip(text) })
      continue
    }
    if (type === 'tool/call') {
      const name = String(data['name'] ?? '')
      push({ ...base, kind: 'tool', label: `调用 ${name}`, detail: clip(data['arguments']) })
      const acc = tools.get(name) ?? { name, count: 0, errors: 0, totalMs: 0, openAt: 0 }
      acc.count += 1
      acc.openAt = time
      tools.set(name, acc)
      continue
    }
    if (type === 'tool/result') {
      const message = (data['message'] ?? {}) as Record<string, unknown>
      const callId = String(message['toolCallId'] ?? '')
      const isError = message['isError'] === true
      const detail = clip(textOfContent(message['content']))
      push({ ...base, kind: 'tool_result', label: isError ? '工具报错' : '工具返回', detail, isError })
      // 工具耗时归到最近一次调用（按名称不好对，取"最近打开且还没关"的那个）
      let target: { name: string, count: number, errors: number, totalMs: number, openAt: number } | null = null
      for (const acc of tools.values()) {
        if (acc.openAt > 0 && (target === null || acc.openAt > target.openAt)) target = acc
      }
      if (target !== null) {
        if (target.openAt > 0 && time >= target.openAt) target.totalMs += time - target.openAt
        target.openAt = 0
        if (isError) target.errors += 1
      }
      void callId
      continue
    }
    if (type === 'assistant/attempt') {
      const stream = Array.isArray(data['stream']) ? data['stream'] : []
      for (const item of stream) {
        if (typeof item !== 'object' || item === null) continue
        const chunk = (item as { chunk?: Record<string, unknown> }).chunk
        if (chunk === undefined) continue
        if (chunk['type'] === 'usage') {
          const counts = usageCounts(chunk['usage'])
          if (counts !== null) {
            tokens.input += counts.input
            tokens.output += counts.output
            tokens.cacheRead += counts.cacheRead
            tokens.cacheWrite += counts.cacheWrite
            tokens.total += counts.total
            tokens.reported = true
            push({ ...base, kind: 'usage', label: 'token 用量', detail: `缓存读 ${counts.cacheRead} / 新输入 ${counts.input} / 输出 ${counts.output}`, tokens: counts.total })
          }
        }
        if (chunk['type'] === 'finish') {
          const reason = (chunk['reason'] ?? {}) as Record<string, unknown>
          if (reason['kind'] === 'error') {
            const failure = (reason['failure'] ?? {}) as Record<string, unknown>
            push({ ...base, kind: 'error', label: '模型报错', detail: clip(failure['message'] ?? failure['code']), isError: true })
          }
        }
      }
      continue
    }
    if (type === 'turn/end') {
      push({ ...base, kind: 'turn', label: `第 ${turn} 轮结束`, detail: '' })
    }
  }

  if (events.length > MAX_EVENTS) {
    truncated = true
    events.splice(0, events.length - MAX_EVENTS)
  }
  return {
    ok: true,
    sessionId,
    running: options.running === true,
    startedAt: firstTime === 0 ? '' : new Date(firstTime).toISOString(),
    updatedAt: lastTime === 0 ? '' : new Date(lastTime).toISOString(),
    events,
    tools: [...tools.values()]
      .filter(acc => acc.count > 0)
      .map(acc => ({ name: acc.name, count: acc.count, errors: acc.errors, totalMs: acc.totalMs })),
    tokens,
    nextSeq,
    truncated,
  }
}
