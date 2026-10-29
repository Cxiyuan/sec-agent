/**
 * OpenAI 兼容 HTTP 层。
 *
 * 只做四件事：鉴权、限流/预算、模型目录、把一次 chat 请求翻译成 OpenCode 的一次
 * 受限推理。没有浏览器界面、没有文件接口、没有任何本地执行能力。
 */

import http from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { freeModels, resolveModel } from './models.js'
import {
  BridgeError,
  buildPrompt,
  completion,
  correctionPrompt,
  parseEnvelope,
  readAssistant,
  validateRequest,
  writeSse,
  MAX_REQUEST_BYTES,
} from './translate.js'

function authorized(req, key) {
  if (key === '') return true
  const actual = Buffer.from(String(req.headers.authorization ?? ''))
  const expected = Buffer.from(`Bearer ${key}`)
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let bytes = 0
    req.on('data', chunk => {
      bytes += chunk.length
      if (bytes > MAX_REQUEST_BYTES) {
        reject(new BridgeError('请求体超过 8MB', 413, 'payload_too_large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('error', reject)
    req.on('end', () => {
      try {
        resolve(chunks.length === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        reject(new BridgeError('请求体不是合法 JSON', 400, 'invalid_json'))
      }
    })
  })
}

function json(res, status, value) {
  const body = JSON.stringify(value)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  })
  res.end(body)
}

function errorBody(error) {
  const status = Number(error?.status ?? 500)
  return {
    status: status >= 400 && status <= 599 ? status : 502,
    body: {
      error: {
        message: String(error?.message ?? '内部错误').slice(0, 600),
        type: String(error?.code ?? 'bridge_error'),
        code: String(error?.code ?? 'bridge_error'),
      },
    },
  }
}

export class Bridge {
  constructor({ config, runtime, log = () => {}, now = () => Date.now() }) {
    this.config = config
    this.runtime = runtime
    this.log = log
    this.now = now
    this.catalog = []
    this.catalogAt = 0
    this.active = 0
    this.budget = { date: this.dateKey(), used: 0 }
    this.counters = { requests: 0, ok: 0, errors: 0, escalated: 0, invalid: 0, rateLimited: 0 }
    this.lastError = ''
    this.refreshTask = null
  }

  dateKey() {
    return new Date(this.now()).toISOString().slice(0, 10)
  }

  async refreshCatalog() {
    if (this.refreshTask !== null) return this.refreshTask
    this.refreshTask = (async () => {
      // 启动瞬间 /api/model 可能还是空的（目录异步加载/首次拉 models.dev）；空结果重试，
      // 最多等 60 秒，否则桥接会带着空模型列表起来，dsh 一直 model_not_found。
      let raw = await this.runtime.rawModels()
      let rows = freeModels(raw, { includeChatOnly: this.config.includeChatOnly })
      for (let attempt = 0; attempt < 60 && rows.length === 0; attempt += 1) {
        await delay(1000)
        raw = await this.runtime.rawModels()
        rows = freeModels(raw, { includeChatOnly: this.config.includeChatOnly })
      }
      this.catalog = rows
      this.catalogAt = this.now()
      this.log('info', 'model catalog refreshed', {
        count: this.catalog.length,
        raw: Array.isArray(raw) ? raw.length : 0,
      })
      return this.catalog
    })()
    try {
      return await this.refreshTask
    } finally {
      this.refreshTask = null
    }
  }

  async ensureCatalog() {
    if (this.catalog.length > 0 && this.now() - this.catalogAt < this.config.refreshMs) return this.catalog
    try {
      return await this.refreshCatalog()
    } catch (error) {
      if (this.catalog.length > 0) return this.catalog
      throw error
    }
  }

  /** 每日上游请求预算（0 = 不限）：免费额度有限，宁可 429 也不要把额度打空。 */
  consumeBudget() {
    const date = this.dateKey()
    if (this.budget.date !== date) this.budget = { date, used: 0 }
    if (this.config.maxRequestsPerDay > 0 && this.budget.used >= this.config.maxRequestsPerDay) {
      throw new BridgeError(
        `今日免费模型请求预算已用完（${this.config.maxRequestsPerDay}）`,
        429,
        'daily_budget',
      )
    }
    this.budget.used += 1
  }

  health() {
    return {
      ok: true,
      version: '0.1.0',
      opencode: this.runtime.version,
      models: this.catalog.map(model => model.id),
      counters: { ...this.counters },
      budget: { ...this.budget, limit: this.config.maxRequestsPerDay },
      active: this.active,
      maxConcurrency: this.config.maxConcurrency,
      lastError: this.lastError,
      catalogAt: this.catalogAt === 0 ? null : new Date(this.catalogAt).toISOString(),
    }
  }

  async runAttempt(sessionId, prompt, request) {
    this.consumeBudget()
    await this.runtime.prompt(sessionId, prompt)
    await this.runtime.wait(sessionId)
    const messages = await this.runtime.messages(sessionId)
    const assistant = messages.filter(message => message?.type === 'assistant').at(-1)
    const result = readAssistant(assistant)
    if (result.error !== null) {
      const status = result.error.status || 502
      const code = status === 429 ? 'free_quota' : status === 403 ? 'free_tier_blocked' : 'model_error'
      throw new BridgeError(result.error.message, status, code)
    }
    if (result.text.trim() === '') {
      throw new BridgeError(
        result.toolParts?.length > 0
          ? '模型尝试使用原生工具（已拒绝），且没有返回信封'
          : '模型没有返回任何文本',
        502,
        'invalid_model_output',
      )
    }
    return { text: result.text, tokens: result.tokens }
  }

  /** 一次完整推理：建 session → 提示 → 解析；格式不合格再纠正一次。 */
  async complete(request, model, signal) {
    const sessionId = await this.runtime.createSession()
    const watcher = setInterval(() => {
      void this.runtime.pendingPermissions(sessionId).then(rows => {
        for (const row of rows) {
          void this.runtime.rejectPermission(sessionId, row.id, '本机工具不允许执行，请把动作作为 calls 返回。')
        }
      })
    }, 500)
    watcher.unref?.()
    const onAbort = () => {
      void this.runtime.interrupt(sessionId)
    }
    signal?.addEventListener('abort', onAbort, { once: true })
    try {
      await this.runtime.setModel(sessionId, model.id)
      const first = await this.runAttempt(sessionId, buildPrompt(request), request)
      try {
        const parsed = parseEnvelope(first.text, request)
        return { parsed, tokens: first.tokens }
      } catch (error) {
        if (!(error instanceof BridgeError) || !['invalid_model_output', 'invalid_tool_call'].includes(error.code)) {
          throw error
        }
        this.counters.invalid += 1
        const second = await this.runAttempt(sessionId, correctionPrompt(error, request), request)
        const parsed = parseEnvelope(second.text, request)
        this.counters.escalated += 1
        return { parsed, tokens: second.tokens }
      }
    } finally {
      clearInterval(watcher)
      signal?.removeEventListener('abort', onAbort)
      if (signal?.aborted) await this.runtime.interrupt(sessionId)
      await this.runtime.deleteSession(sessionId)
    }
  }

  async handleChat(req, res, body, signal) {
    const request = validateRequest(body)
    const catalog = await this.ensureCatalog()
    const model = resolveModel(catalog, request.model)
    if (model === null) {
      throw new BridgeError(
        `未知或当前不可用的免费模型：${request.model.slice(0, 80)}（见 /v1/models）`,
        400,
        'model_not_found',
      )
    }
    if (request.tools.length > 0 && !model.tools) {
      throw new BridgeError(`模型 ${model.id} 未声明支持工具调用，不能用于分析任务`, 400, 'tools_not_supported')
    }
    if (this.active >= this.config.maxConcurrency) {
      this.counters.rateLimited += 1
      throw new BridgeError('桥接并发已满，请稍后重试', 429, 'busy')
    }
    this.active += 1
    this.counters.requests += 1
    const started = this.now()
    const completionId = `chatcmpl-${globalThis.crypto.randomUUID().replaceAll('-', '')}`
    const completionCreated = Math.floor(started / 1000)
    let heartbeat = null
    let roleSent = false
    try {
      if (request.stream) {
        res.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-store',
          connection: 'keep-alive',
        })
        // 先发 role 块，客户端可以立刻进入流状态；内容在格式校验后才发。
        res.write(`data: ${JSON.stringify({
          id: completionId,
          object: 'chat.completion.chunk',
          created: completionCreated,
          model: model.id,
          choices: [{ index: 0, delta: { role: 'assistant' }, finish_reason: null }],
        })}\n\n`)
        roleSent = true
        heartbeat = setInterval(() => {
          if (!res.writableEnded) res.write(': waiting\n\n')
        }, 10_000)
        heartbeat.unref?.()
      }
      const { parsed, tokens } = await this.complete(request, model, signal)
      const result = completion(model.id, parsed, tokens, { id: completionId, created: completionCreated })
      if (request.stream) {
        clearInterval(heartbeat)
        writeSse(res, result, request.includeUsage, roleSent)
      } else {
        json(res, 200, result)
      }
      this.counters.ok += 1
      this.log('info', 'completion ok', {
        model: model.id,
        ms: this.now() - started,
        tools: request.tools.length,
        calls: parsed.calls.length,
        budget: this.budget.used,
      })
    } catch (error) {
      this.counters.errors += 1
      this.lastError = String(error?.message ?? error).slice(0, 300)
      const { status, body: payload } = errorBody(error)
      this.log('warn', 'completion failed', {
        model: model.id,
        ms: this.now() - started,
        status,
        code: error?.code ?? 'unknown',
        message: this.lastError,
      })
      if (res.headersSent) {
        res.write(`data: ${JSON.stringify(payload)}\n\ndata: [DONE]\n\n`)
        res.end()
      } else {
        json(res, status, payload)
      }
    } finally {
      if (heartbeat !== null) clearInterval(heartbeat)
      this.active -= 1
    }
  }

  async handle(req, res) {
    const route = new URL(req.url ?? '/', 'http://127.0.0.1').pathname
    if (req.method === 'GET' && route === '/health') {
      json(res, 200, this.health())
      return
    }
    if (!authorized(req, this.config.apiKey)) {
      json(res, 401, { error: { message: '需要 Bearer 本地密钥', type: 'authentication_error' } })
      return
    }
    if (String(req.headers.origin ?? '') !== '') {
      json(res, 403, { error: { message: '禁止浏览器来源', type: 'forbidden' } })
      return
    }
    if (req.method === 'GET' && route === '/v1/models') {
      const catalog = await this.ensureCatalog()
      json(res, 200, {
        object: 'list',
        data: catalog.map(model => ({
          id: model.id,
          object: 'model',
          owned_by: 'opencode',
          name: model.name,
          context_length: model.context,
          supports_tools: model.tools,
        })),
      })
      return
    }
    if (req.method === 'POST' && route === '/admin/refresh') {
      const catalog = await this.refreshCatalog()
      json(res, 200, { count: catalog.length, models: catalog.map(model => model.id) })
      return
    }
    if (req.method === 'POST' && route === '/v1/chat/completions') {
      const body = await readBody(req)
      const controller = new AbortController()
      res.on('close', () => {
        if (!res.writableEnded) controller.abort()
      })
      await this.handleChat(req, res, body, controller.signal)
      return
    }
    json(res, 404, { error: { message: '不存在该接口', type: 'not_found' } })
  }
}

export function createServer(bridge) {
  const server = http.createServer((req, res) => {
    void bridge.handle(req, res).catch(error => {
      if (res.headersSent) {
        res.end()
        return
      }
      const { status, body } = errorBody(error)
      json(res, status, body)
    })
  })
  // 免费模型可能很慢；超时由 runtime 的显式 deadline 管，不靠 socket 超时。
  server.requestTimeout = 0
  server.headersTimeout = 30_000
  return server
}

export { delay }
