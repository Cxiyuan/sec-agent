/**
 * DSH 会话审计投影（运行事实，不是模型叙事）。
 *
 * 数据源是 DSH 自己写的 `session.v4.jsonl.zstd`：turn/start|end、step、tool/call、
 * tool/result、assistant/message、usage、错误都已在里面。这里只做**有界投影**，
 * 不把原始报文搬进 PG：
 * - 工具调用按 `callId` 配对（并行工具不会串时长）；
 * - 保留 turn/end 的终态原因（completed / max-tokens / error / aborted …）；
 * - token、工具报错、模型与首末时间单独成字段，供预算与质量看板聚合；
 * - 所有自由文本先脱敏再截断，避免把 Cookie/Token/密码带进审计库。
 *
 * 为什么不用 `ctx.sessionQuery`：分析插件拿到的是 host 的 Context，而审计发生在
 * 会话 dispose 之后、同一进程里；直接读 append-only 日志是唯一不依赖会话是否仍
 * live 的路径。`sessionQuery` 的产品化查询仍然留给模型侧工具（history 组）。
 */

import { promises as fs } from 'node:fs'
import path from 'node:path'
import * as zlib from 'node:zlib'

export interface AuditTokenUsage {
  readonly input: number
  readonly output: number
  readonly cacheRead: number
  readonly cacheWrite: number
  readonly total: number
  readonly reported: boolean
}

export interface AuditToolCall {
  readonly callId: string
  readonly name: string
  readonly startedAt: string
  readonly endedAt: string
  readonly durationMs: number
  readonly isError: boolean
  readonly error: string
  readonly arguments: string
  readonly result: string
}

export interface AuditTurnEnd {
  readonly turn: number
  readonly reason: string
  readonly at: string
}

export interface SessionAudit {
  readonly ok: boolean
  readonly error?: string
  readonly sessionId: string
  readonly startedAt: string
  readonly endedAt: string
  readonly turns: number
  readonly steps: number
  readonly toolCalls: readonly AuditToolCall[]
  readonly toolCount: number
  readonly toolErrors: number
  readonly tokens: AuditTokenUsage
  readonly errors: readonly string[]
  readonly model: string
  readonly turnEnds: readonly AuditTurnEnd[]
  readonly redacted: boolean
  readonly truncated: boolean
}

interface RawEvent {
  readonly type?: string
  readonly seq?: number
  readonly time?: number
  readonly data?: Record<string, unknown>
}

const MAX_TOOL_CALLS = 200
const MAX_ERRORS = 100
const MAX_PREVIEW = 500
const MAX_EVENT_BYTES = 64 * 1024 * 1024

const EMPTY_TOKENS: AuditTokenUsage = {
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0,
  total: 0,
  reported: false,
}

const SECRET_PATTERNS: readonly RegExp[] = [
  /((?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=]\s*)(?:(?:bearer|basic)\s+)?([^\s,;]+)/giu,
  /((?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret)\s*[:=]\s*)([^\s,;]+)/giu,
  /\b(bearer\s+)([A-Za-z0-9._~+/=-]{8,})/giu,
]

export function redactText(value: unknown, max = MAX_PREVIEW): string {
  const text = typeof value === 'string' ? value : value === undefined || value === null ? '' : String(value)
  let out = text
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (_whole, prefix: string) => `${prefix}[REDACTED]`)
  }
  const compact = out.replace(/\s+/gu, ' ').trim()
  return compact.length <= max ? compact : `${compact.slice(0, max)}…`
}

function iso(ms: number): string {
  return ms > 0 ? new Date(ms).toISOString() : ''
}

function textOfContent(content: unknown): string {
  if (!Array.isArray(content)) return ''
  const parts: string[] = []
  for (const part of content) {
    if (typeof part !== 'object' || part === null) continue
    const row = part as { type?: string; text?: string }
    if (row.type === 'text' && typeof row.text === 'string') parts.push(row.text)
  }
  return parts.join('\n')
}

function usageCounts(raw: unknown): AuditTokenUsage | null {
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
  return { input, output, cacheRead, cacheWrite, total, reported: true }
}

function addUsage(target: AuditTokenUsage, next: AuditTokenUsage): AuditTokenUsage {
  return {
    input: target.input + next.input,
    output: target.output + next.output,
    cacheRead: target.cacheRead + next.cacheRead,
    cacheWrite: target.cacheWrite + next.cacheWrite,
    total: target.total + next.total,
    reported: target.reported || next.reported,
  }
}

function reasonOf(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value !== 'object' || value === null) return ''
  const row = value as Record<string, unknown>
  const kind = String(row['kind'] ?? '').trim()
  if (kind !== '') return kind
  const error = row['error']
  if (typeof error === 'object' && error !== null) {
    const failure = error as Record<string, unknown>
    return String(failure['code'] ?? failure['message'] ?? 'error').slice(0, 200)
  }
  return ''
}

async function locate(root: string, sessionId: string): Promise<string | null> {
  const direct = path.join(root, sessionId, 'session.v4.jsonl.zstd')
  try {
    await fs.access(direct)
    return direct
  } catch {
    let entries: Array<{ name: string; isDirectory(): boolean }>
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

function emptyAudit(sessionId: string, error: string): SessionAudit {
  return {
    ok: false,
    error,
    sessionId,
    startedAt: '',
    endedAt: '',
    turns: 0,
    steps: 0,
    toolCalls: [],
    toolCount: 0,
    toolErrors: 0,
    tokens: EMPTY_TOKENS,
    errors: [],
    model: '',
    turnEnds: [],
    redacted: false,
    truncated: false,
  }
}

/** 解析 DSH JSONL 文本（单测入口）。 */
export function parseSessionAudit(text: string, sessionId: string): SessionAudit {
  const events: RawEvent[] = []
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue
    try {
      events.push(JSON.parse(line) as RawEvent)
    } catch {
      continue
    }
  }
  let startedAt = 0
  let endedAt = 0
  let turns = 0
  let steps = 0
  let model = ''
  let tokens: AuditTokenUsage = EMPTY_TOKENS
  let redacted = false
  let truncated = false
  const errors: string[] = []
  const turnEnds: AuditTurnEnd[] = []
  const calls = new Map<string, {
    callId: string
    name: string
    startedAt: number
    endedAt: number
    isError: boolean
    error: string
    arguments: string
    result: string
  }>()
  let anonymousCall = 0

  const noteError = (textValue: string): void => {
    if (textValue === '' || errors.length >= MAX_ERRORS) return
    errors.push(redactText(textValue, 300))
  }

  for (const event of events) {
    const time = Number(event.time ?? 0)
    if (time > 0) {
      if (startedAt === 0 || time < startedAt) startedAt = time
      if (time > endedAt) endedAt = time
    }
    const data = (event.data ?? {}) as Record<string, unknown>
    const type = String(event.type ?? '')
    if (type === 'turn/start') {
      turns = Math.max(turns, Number(data['turn'] ?? 0))
      continue
    }
    if (type === 'step/start') {
      steps = Math.max(steps, Number(data['step'] ?? 0))
      continue
    }
    if (type === 'turn/end') {
      const turn = Number(data['turn'] ?? 0)
      const reason = reasonOf(data['reason']) || 'unknown'
      turnEnds.push({ turn, reason, at: iso(time) })
      continue
    }
    if (type === 'request/header') {
      const header = (data['header'] ?? {}) as Record<string, unknown>
      const config = (header['config'] ?? {}) as Record<string, unknown>
      const provider = String(config['provider'] ?? '').trim()
      const name = String(config['model'] ?? '').trim()
      model = [provider, name].filter(value => value !== '').join('/')
      continue
    }
    if (type === 'assistant/message') {
      const message = (data['message'] ?? {}) as Record<string, unknown>
      const fromMessage = usageCounts(data['usage']) ?? usageCounts(message['usage'])
      if (fromMessage !== null) tokens = addUsage(tokens, fromMessage)
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
          if (counts !== null) tokens = addUsage(tokens, counts)
        }
        if (chunk['type'] === 'finish') {
          const reason = (chunk['reason'] ?? {}) as Record<string, unknown>
          if (reason['kind'] === 'error') {
            const failure = (reason['failure'] ?? {}) as Record<string, unknown>
            noteError(String(failure['message'] ?? failure['code'] ?? 'model error'))
          }
        }
      }
      continue
    }
    if (type === 'tool/call') {
      const callId = String(data['callId'] ?? '') || `anonymous-${anonymousCall++}`
      const name = String(data['name'] ?? '')
      const args = redactText(data['arguments'])
      if (args.includes('[REDACTED]')) redacted = true
      calls.set(callId, {
        callId,
        name,
        startedAt: time,
        endedAt: 0,
        isError: false,
        error: '',
        arguments: args,
        result: '',
      })
      continue
    }
    if (type === 'tool/result') {
      const message = (data['message'] ?? {}) as Record<string, unknown>
      const callId = String(message['toolCallId'] ?? '')
      const target = calls.get(callId)
      if (target !== undefined) {
        target.endedAt = time
        target.isError = message['isError'] === true
        const error = data['error']
        if (typeof error === 'object' && error !== null) {
          const row = error as Record<string, unknown>
          target.error = redactText(row['reason'] ?? row['code'] ?? row['name'], 300)
        }
        const preview = textOfContent(message['content'])
        target.result = redactText(preview)
        if (target.result.includes('[REDACTED]') || target.error.includes('[REDACTED]')) redacted = true
        if (target.isError) noteError(target.error || target.result || 'tool error')
      } else {
        noteError(redactText(textOfContent(message['content']), 300))
      }
      continue
    }
    if (type === 'session/error' || type === 'error') {
      noteError(redactText(data['message'] ?? data['error'], 300))
    }
  }

  const allCalls = [...calls.values()]
  if (allCalls.length > MAX_TOOL_CALLS) truncated = true
  const toolCalls: AuditToolCall[] = allCalls.slice(0, MAX_TOOL_CALLS).map(call => ({
    callId: call.callId.slice(0, 96),
    name: call.name.slice(0, 80),
    startedAt: iso(call.startedAt),
    endedAt: iso(call.endedAt),
    durationMs: call.endedAt > 0 && call.startedAt > 0 ? Math.max(0, call.endedAt - call.startedAt) : 0,
    isError: call.isError,
    error: call.error,
    arguments: call.arguments,
    result: call.result,
  }))

  return {
    ok: true,
    sessionId,
    startedAt: iso(startedAt),
    endedAt: iso(endedAt),
    turns,
    steps,
    toolCalls,
    toolCount: allCalls.length,
    toolErrors: allCalls.filter(call => call.isError).length,
    tokens,
    errors,
    model,
    turnEnds: turnEnds.slice(-40),
    redacted,
    truncated,
  }
}

/** 读一个 DSH 会话的审计投影；日志不存在/解压失败返回 `ok:false`，不抛。 */
export async function readSessionAudit(root: string, sessionId: string): Promise<SessionAudit> {
  if (sessionId.trim() === '') return emptyAudit(sessionId, '没有会话 ID')
  const file = await locate(root, sessionId)
  if (file === null) return emptyAudit(sessionId, '找不到会话日志')
  const decompress = (zlib as unknown as {
    zstdDecompressSync?: (input: Buffer) => Buffer
  }).zstdDecompressSync
  if (decompress === undefined) return emptyAudit(sessionId, '当前 Node 不支持 zstd（需要 Node ≥ 22.15）')
  try {
    const stat = await fs.stat(file)
    if (stat.size > MAX_EVENT_BYTES) return emptyAudit(sessionId, '会话日志超过审计上限')
    const raw = decompress(await fs.readFile(file))
    return parseSessionAudit(raw.toString('utf8'), sessionId)
  } catch (error) {
    return emptyAudit(sessionId, `读会话日志失败：${error instanceof Error ? error.message : String(error)}`)
  }
}
