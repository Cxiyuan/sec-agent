/**
 * 工作台的 HTTP 分发层：一个 prefix 路由 handler 内部按方法 + 路径分发。
 *
 * 认证语义（与 dsh 的 /login 互补，凭据同源不同 Cookie，浏览器里两个登录互不冒充）：
 * - 页面：未登录访问工作台 → 303 到 {basePath}/login；已登录访问登录页 → 303 回工作台；
 * - API：未登录一律 401 JSON（页面 JS 收到 401 自己跳登录页）；
 * - 登录成功 303 回工作台；登录失败 303 回 {basePath}/login?error=1；
 * - redirect 一律用绝对路径：相对的 "./" 会按 URL 目录解析，
 *   在无尾部斜杠的 /xdr/ui 上跳错一级。
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import { parseLoginBody, UiAuth } from './ui-auth.ts'
import { loginPage, workbenchPage } from './html.ts'

/** 工作台数据面（xdr-ingest provide 的服务）；不在场时数据区报不可用。 */
export interface IngestServiceView {
  status(): Record<string, unknown>
  cacheStats(): Promise<unknown>
  wake(): boolean
  listAnalyses(query: { limit: number, offset: number, search: string }): Promise<{
    total: number
    entries: readonly unknown[]
  }>
  getAnalysis(analysisId: string): Promise<unknown>
  /** 运行参数快照（可选：老版本 xdr-ingest 没有，控制台显示"不可改"）。 */
  settings?(): Promise<Record<string, unknown>>
  /** 保存运行参数（可选；校验在数据面做，控制台只透传）。 */
  updateSettings?(patch: unknown): Promise<{
    ok: boolean
    error?: string
    persisted?: boolean
    settings?: Record<string, number>
  }>
}

export interface UiHandlerOptions {
  /** 已初始化的会话鉴权（凭据 + 密钥 + 时长已在构造期内定稿）。 */
  readonly auth: UiAuth
  /** 数据面读取函数：每请求现取（xdr-ingest 晚于 xdr-ui 激活也能接上）。 */
  readonly ingest: () => IngestServiceView | null
  /** 登录页模板（含错误横幅位），由 index.ts 注入。 */
  readonly renderLogin: (authError: boolean) => string
  /** 控制台页模板，由 index.ts 注入。 */
  readonly renderWorkbench: () => string
  /** 配置页展示的部署侧事实（账号、令牌是否配置、NDR 入口等；不含密钥值）。 */
  readonly meta: () => Record<string, unknown>
}

const DEFAULT_LIMIT = 50
const MAX_LIMIT = 200
const MAX_OFFSET = 10_000_000
/** 深链/暴力枚举一个防护栏：真实 ID 形如 EA-<32hex>，上限取宽不取严。 */
const MAX_ANALYSIS_ID = 128
/** 登录体上限：账号密码合理长度之外的都是攻击。 */
const MAX_LOGIN_BODY = 4 * 1024
/** 运行参数体上限：三个整数，8KB 已经很宽松。 */
const MAX_SETTINGS_BODY = 8 * 1024
const MAX_COOKIE_HEADER = 4096

/**
 * 组装工作台的路由 handler（webserver 前缀匹配后被调用，req.url 是**全路径**）。
 * @param basePath - 路由前缀，同时是页面相对链接的绝对化基准。
 */
export function createUiHandler(
  basePath: string,
  options: UiHandlerOptions,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const loginUrl = `${basePath}/login`
  const workbenchUrl = `${basePath}/`

  const authed = (req: IncomingMessage): boolean =>
    options.auth.verifyCookie(req.headers.cookie === undefined ? undefined : req.headers.cookie.slice(0, MAX_COOKIE_HEADER))

  const respondJson = (res: ServerResponse, status: number, value: unknown): void => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
    res.end(JSON.stringify(value))
  }

  const redirect = (res: ServerResponse, location: string): void => {
    res.writeHead(303, { 'cache-control': 'no-store', 'location': location, 'referrer-policy': 'no-referrer' })
    res.end()
  }

  const sendHtml = (res: ServerResponse, html: string, extraHeaders: Record<string, string> = {}): void => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...extraHeaders })
    res.end(html)
  }

  const queryOf = (req: IncomingMessage): URLSearchParams => {
    if (req.url === undefined || req.url === '') return new URLSearchParams()
    const at = req.url.indexOf('?')
    return at === -1 ? new URLSearchParams() : new URLSearchParams(req.url.slice(at + 1))
  }

  /** 读全请求体并按上限拒绝（async-iter 语义与 dsh BrowserAuth 的登录读法相同）。 */
  const readBody = async (req: IncomingMessage, maxBytes: number): Promise<{ text: string, contentType: string } | undefined> => {
    const chunks: Buffer[] = []
    let total = 0
    for await (const chunk of req as unknown as AsyncIterable<Buffer>) {
      total += chunk.length
      if (total > maxBytes) return undefined
      chunks.push(chunk)
    }
    const text = Buffer.concat(chunks).toString('utf8')
    const rawContentType = (req.headers as { readonly ['content-type']?: unknown })['content-type']
    const contentType = typeof rawContentType === 'string' ? rawContentType : ''
    return { text, contentType }
  }

  const dispatch = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    /* v8 ignore next -- node:http always sets method on server requests. */
    const method = req.method ?? 'GET'
    const pathname = normalizePath(req.url)
    // webserver 前缀匹配后才调到这里：路径必然是 basePath 或 basePath/<tail>；
    // 其余情况按 404 JSON 兜底，不落进 dsh 的 SPA fallback。
    let tail: string
    if (pathname === basePath) tail = '/'
    else if (pathname.startsWith(`${basePath}/`)) tail = pathname.slice(basePath.length)
    else {
      respondJson(res, 404, { error: 'not found' })
      return
    }

    try {
      // ---------- 页面 ----------
      if (tail === '/' || tail === '/index.html') {
        if (method !== 'GET' && method !== 'HEAD') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!authed(req)) {
          redirect(res, loginUrl)
          return
        }
        sendHtml(res, method === 'HEAD' ? '' : options.renderWorkbench())
        return
      }
      if (tail === '/login') {
        if (method === 'GET' || method === 'HEAD') {
          if (authed(req)) {
            redirect(res, workbenchUrl)
            return
          }
          const error = queryOf(req).get('error') === '1'
          sendHtml(res, method === 'HEAD' ? '' : options.renderLogin(error))
          return
        }
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'login accepts GET and POST only' })
          return
        }
        const body = await readBody(req, MAX_LOGIN_BODY)
        const credentials = body === undefined
          ? { user: '', password: '' }
          : parseLoginBody(body.text, body.contentType)
        if (!options.auth.verify(credentials.user, credentials.password)) {
          redirect(res, `${loginUrl}?error=1`)
          return
        }
        const cookie = options.auth.issueCookie()
        res.writeHead(303, {
          'cache-control': 'no-store',
          'location': workbenchUrl,
          'referrer-policy': 'no-referrer',
          'set-cookie': cookie.value,
        })
        res.end()
        return
      }
      if (tail === '/logout') {
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'logout accepts POST only' })
          return
        }
        res.writeHead(303, {
          'cache-control': 'no-store',
          'location': loginUrl,
          'referrer-policy': 'no-referrer',
          'set-cookie': options.auth.clearCookie(),
        })
        res.end()
        return
      }
      // ---------- API（未登录一律 401；页面 JS 统一按 401 跳登录） ----------
      const apiGuard = (): boolean => {
        if (!authed(req)) {
          respondJson(res, 401, { error: 'unauthorized' })
          return false
        }
        return true
      }
      if (tail === '/api/settings') {
        if (method !== 'GET' && method !== 'POST') {
          respondJson(res, 405, { error: 'settings accepts GET and POST only' })
          return
        }
        if (!apiGuard()) return
        const ingest = options.ingest()
        const meta = options.meta()
        if (method === 'GET') {
          if (ingest === null || typeof ingest.settings !== 'function') {
            respondJson(res, 200, { available: false, meta })
            return
          }
          const settings = await ingest.settings()
          respondJson(res, 200, { available: true, settings, meta })
          return
        }
        if (ingest === null || typeof ingest.updateSettings !== 'function') {
          respondJson(res, 503, { ok: false, error: '数据面不可用，运行参数暂不可改' })
          return
        }
        const body = await readBody(req, MAX_SETTINGS_BODY)
        if (body === undefined) {
          respondJson(res, 413, { ok: false, error: '请求体过大' })
          return
        }
        let patch: unknown
        try {
          patch = JSON.parse(body.text)
        } catch {
          respondJson(res, 400, { ok: false, error: '请求体必须是 JSON' })
          return
        }
        const result = await ingest.updateSettings(patch)
        respondJson(res, result.ok === false ? 400 : 200, result)
        return
      }
      if (tail === '/api/overview') {
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        const ingest = options.ingest()
        if (ingest === null) {
          respondJson(res, 200, { available: false })
          return
        }
        const status = ingest.status()
        let cache: unknown = null
        try {
          cache = await ingest.cacheStats()
        } catch {
          cache = null
        }
        respondJson(res, 200, { available: true, status, cache })
        return
      }
      if (tail === '/api/analyses') {
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        const ingest = options.ingest()
        if (ingest === null) {
          respondJson(res, 200, { available: false, total: 0, entries: [] })
          return
        }
        const query = queryOf(req)
        const limit = clampInt(query.get('limit'), DEFAULT_LIMIT, 1, MAX_LIMIT)
        const offset = clampInt(query.get('offset'), 0, 0, MAX_OFFSET)
        const search = (query.get('q') ?? '').slice(0, 128)
        const page = await ingest.listAnalyses({ limit, offset, search })
        respondJson(res, 200, { available: true, total: page.total, entries: page.entries })
        return
      }
      if (tail.startsWith('/api/analyses/')) {
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        const analysisId = decodeURIComponent(tail.slice('/api/analyses/'.length)).trim()
        if (analysisId === '' || analysisId.length > MAX_ANALYSIS_ID || /[\u0000-\u001f]/u.test(analysisId)) {
          respondJson(res, 400, { error: 'invalid analysis id' })
          return
        }
        const ingest = options.ingest()
        if (ingest === null) {
          respondJson(res, 404, { error: 'data plane unavailable' })
          return
        }
        const entry = await ingest.getAnalysis(analysisId)
        if (entry === null) {
          respondJson(res, 404, { error: 'not found' })
          return
        }
        respondJson(res, 200, { entry })
        return
      }
      if (tail === '/api/wake') {
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        const ingest = options.ingest()
        respondJson(res, 200, { accepted: ingest === null ? false : ingest.wake() })
        return
      }
      respondJson(res, 404, { error: 'not found' })
    } catch (error) {
      // 单请求失败不影响进程；内部异常对客户端统一 500（页面与 API 同语义）。
      console.error('[xdr-ui] handler error:', error instanceof Error ? error.message : String(error))
      respondJson(res, 500, { error: 'internal error' })
    }
  }

  return dispatch
}

/**
 * 站点根路径 → 控制台的跳转（dsh 原生界面不再作为默认入口）。
 * 原生界面仍在 /index.html 可达（frontend-static 会渲染它）；这里只接管 `/`。
 * @param basePath - 控制台前缀，跳转目标为 `{basePath}/`（未登录会再转登录页）。
 */
export function createRootRedirect(basePath: string): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const target = `${basePath}/`
  return async (req, res) => {
    const method = req.method ?? 'GET'
    if (method !== 'GET' && method !== 'HEAD') {
      res.writeHead(405, { 'content-type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ error: 'method not allowed' }))
      return
    }
    res.writeHead(303, {
      'cache-control': 'no-store',
      'location': target,
      'referrer-policy': 'no-referrer',
    })
    res.end()
  }
}

/** URL 的 pathname 形式；末尾斜杠去掉（basePath 本身不带），畸形回根。 */
function normalizePath(raw: string | undefined): string {
  if (raw === undefined || raw === '') return '/'
  try {
    const pathname = new URL(raw, 'http://ui.invalid').pathname
    return pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname
  } catch {
    return '/'
  }
}

function clampInt(raw: string | null, fallback: number, min: number, max: number): number {
  if (raw === null || raw === '') return fallback
  const value = Number(raw)
  if (!Number.isSafeInteger(value)) return fallback
  return Math.max(min, Math.min(max, value))
}
