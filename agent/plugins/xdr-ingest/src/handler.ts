/**
 * Webhook HTTP 层：对齐 NDR 推送契约（app/detector/push.py）。
 *
 * 契约要点：
 * - POST {basePath}/digests，Bearer token 认证，**2xx 即回执**；
 * - GET {basePath}/ping 是 NDR 的连通性自检（由推送地址把 /digests 换成 /ping 推出）；
 * - NDR 把 4xx（除 408/429）判为「这批永久失败」、5xx/超时判为「整体不可达」
 *   落重试队列——所以本层的语义必须是：
 *     鉴权失败/载荷坏 → 4xx（配错了就该让 NDR 立刻看见，别空转重试）
 *     我们内部分析出错 → 500（NDR 稍后重推整批；判重缓存天然幂等，不会重复分析）
 *     无法识别的 item → 不算错误，200 回执里逐条标注 rejected。
 */

import { createHash, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { AnalysisCache } from './cache.ts'
import { analysisIdOf, normalizeDigest } from './identity.ts'
import { triageDigest } from './analyzer.ts'
import type { IngestReceipt, NdrDigestItem, ReceiptEntry } from './types.ts'

const DEFAULT_DIGESTS_SUFFIX = '/digests'
const PING_SUFFIX = '/ping'
const STATS_SUFFIX = '/stats'
const MAX_DELIVERY_ID_LENGTH = 128

export class WebhookHttpError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export interface IngestHandlerConfig {
  /** Bearer token；为空时所有请求一律 401（拒绝在无鉴权状态下收事件）。 */
  readonly token: string
  /** 请求体字节上限；超出按 413（NDR 判永久失败，属于批太大，不是我们的错）。 */
  readonly maxBodyBytes: number
  /** 判重缓存（与插件其余部分共享同一实例）。 */
  readonly cache: AnalysisCache
  /** 可注入时钟（测试用）。 */
  readonly now?: () => number
}

function respondText(response: ServerResponse, status: number, message: string): void {
  response.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' })
  response.end(message)
}

function respondJson(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
  response.end(JSON.stringify(value))
}

/** 定长比较：两侧都先哈希成定长摘要再 timingSafeEqual，避免长度泄露。 */
function tokenMatches(presented: string, expected: string): boolean {
  if (expected === '') return false
  const a = createHash('sha256').update(presented, 'utf8').digest()
  const b = createHash('sha256').update(expected, 'utf8').digest()
  return timingSafeEqual(a, b)
}

function bearerToken(request: IncomingMessage): string {
  const raw = request.headers.authorization
  if (raw === undefined) return ''
  const match = /^Bearer\s+(.+)$/iu.exec(raw.trim())
  return match?.[1]?.trim() ?? ''
}

function requireAuth(request: IncomingMessage, token: string): void {
  if (!tokenMatches(bearerToken(request), token)) {
    if (token === '') throw new WebhookHttpError(401, 'ingest token is not configured on the agent side')
    throw new WebhookHttpError(401, 'invalid or missing bearer token')
  }
}

async function readBody(request: IncomingMessage, maxBytes: number): Promise<string> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of request) {
    const piece = chunk as Buffer
    total += piece.length
    if (total > maxBytes) throw new WebhookHttpError(413, `body exceeds ${maxBytes} bytes`)
    chunks.push(piece)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function boundedId(value: unknown): string {
  const raw = String(value ?? '').trim()
  return raw === '' ? '(missing)' : raw.slice(0, MAX_DELIVERY_ID_LENGTH)
}

/** 处理一批 item：生成分析 ID → 查缓存 → 命中复用计数，未命中分析入库。 */
export function processItems(
  items: readonly unknown[],
  cache: AnalysisCache,
  now: () => number,
): { receipt: IngestReceipt; internalFailure: boolean } {
  const receipt: IngestReceipt = {
    accepted: 0, analyzed: 0, reused: 0, reanalyzed: 0, rejected: 0, results: [],
  }
  let internalFailure = false
  for (const item of items) {
    const raw = item as NdrDigestItem
    const entry: ReceiptEntry = {
      eventId: boundedId(raw.event_id),
      analysisId: '',
      reused: false,
      reanalyzed: false,
      occurrences: 0,
    }
    try {
      const identity = normalizeDigest(raw.digest ?? {})
      if (identity === null) {
        entry.error = 'digest lacks any usable identity fields (rule/src/targets all empty)'
        receipt.rejected += 1
      } else {
        entry.analysisId = analysisIdOf(identity)
        const digest = raw.digest ?? {}
        const outcome = cache.admit(entry.analysisId, identity, {
          eventId: entry.eventId,
          fingerprint: String(raw.fingerprint ?? '').slice(0, MAX_DELIVERY_ID_LENGTH),
        }, candidate => triageDigest(candidate, digest))
        entry.reused = outcome.reused
        entry.reanalyzed = outcome.reanalyzed
        entry.occurrences = outcome.record.occurrences
        receipt.accepted += 1
        if (outcome.reused) receipt.reused += 1
        else if (outcome.reanalyzed) receipt.reanalyzed += 1
        else receipt.analyzed += 1
      }
    } catch (error) {
      // 单条内部异常 → 整批按失败处理（500 让 NDR 重推；缓存幂等，重推无副作用）
      internalFailure = true
      entry.error = error instanceof Error ? error.message : String(error)
    }
    receipt.results.push(entry)
  }
  if (internalFailure) receipt.accepted = 0
  return { receipt, internalFailure }
}

export function createIngestHandler(
  basePath: string,
  config: IngestHandlerConfig,
): (request: IncomingMessage, response: ServerResponse) => Promise<void> {
  const digestsPath = basePath + DEFAULT_DIGESTS_SUFFIX
  const pingPath = basePath + PING_SUFFIX
  const statsPath = basePath + STATS_SUFFIX
  const now = config.now ?? Date.now

  return async (request, response) => {
    const pathname = (request.url ?? '/').split('?')[0] ?? '/'
    try {
      if (pathname === pingPath && request.method === 'GET') {
        requireAuth(request, config.token)
        respondText(response, 200, 'ok')
        return
      }
      if (pathname === statsPath && request.method === 'GET') {
        requireAuth(request, config.token)
        respondJson(response, 200, config.cache.stats())
        return
      }
      if (pathname === digestsPath) {
        if (request.method !== 'POST') {
          throw new WebhookHttpError(405, 'digests accepts POST only')
        }
        requireAuth(request, config.token)
        const body = await readBody(request, config.maxBodyBytes)
        let parsed: unknown
        try {
          parsed = JSON.parse(body)
        } catch {
          throw new WebhookHttpError(400, 'body is not valid JSON')
        }
        const items = (parsed as { items?: unknown } | null)?.items
        if (!Array.isArray(items)) {
          throw new WebhookHttpError(400, 'body must be {"items": [...]}')
        }
        const { receipt, internalFailure } = processItems(items, config.cache, now)
        if (internalFailure) {
          respondJson(response, 500, receipt)
          return
        }
        respondJson(response, 200, receipt)
        return
      }
      respondText(response, 404, `no ingest endpoint at ${pathname}`)
    } catch (error) {
      if (error instanceof WebhookHttpError) {
        respondText(response, error.status, error.message)
        return
      }
      respondText(response, 500, 'internal ingest error')
    }
  }
}
