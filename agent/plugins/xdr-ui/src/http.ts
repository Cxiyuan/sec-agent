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
  wake(projectId?: string): boolean
  listAnalyses(query: { limit: number, offset: number, search: string }): Promise<{
    total: number
    entries: readonly unknown[]
  }>
  getAnalysis(analysisId: string): Promise<unknown>
  /**
   * 智能体交回的结论（NDR 的 `analysis_results`）——控制台「分析记录」页真正的数据源。
   * 可选：老版本 xdr-ingest 没有这一面，界面回落到旧的摘要缓存（那份表在新架构下是空的）。
   */
  listConclusions?(query: { limit: number, offset: number, search: string, project?: string }): Promise<{
    total: number
    entries: readonly unknown[]
  }>
  getConclusion?(id: string, projectId?: string): Promise<unknown>
  conclusionStats?(projectId?: string): Promise<{ available: boolean, total: number }>
  /** 分析脚本库（P4 控制台管理）：列表/详情/新建编辑/启停/删除。 */
  listScripts?(query: { search: string, limit: number, offset: number, project?: string }): Promise<{
    total: number
    items: readonly unknown[]
  }>
  getScript?(nameOrId: string, projectId?: string): Promise<unknown>
  saveScript?(body: unknown, projectId?: string): Promise<unknown>
  setScriptEnabled?(nameOrId: string, enabled: boolean, projectId?: string): Promise<boolean>
  removeScript?(nameOrId: string, projectId?: string): Promise<boolean>
  /** 项目组织（P2）：列表 / 新增编辑 / 删除 / 复核。 */
  projects?(): Promise<readonly unknown[]>
  saveProject?(body: unknown): Promise<{ ok: boolean, error?: string, project?: unknown }>
  removeProject?(projectId: string): Promise<boolean>
  verifyProject?(projectId: string): Promise<unknown>
  /** 行为基线事实（外连新目标/异地登录/爆破/404/连接数偏离）。 */
  listObservations?(query: { kind: string, subject: string, minutes: number, limit: number, offset: number }): Promise<{
    total: number
    items: readonly unknown[]
  }>
  observationStats?(): Promise<unknown>
  /** 外连白名单：列表 / 新增编辑 / 删除（留墓碑）/ 撤销墓碑。 */
  listEgressAllow?(query: { kind: string, includeTombstone: boolean }): Promise<readonly unknown[]>
  saveEgressAllow?(body: unknown): Promise<unknown>
  removeEgressAllow?(entryId: string): Promise<boolean>
  restoreEgressAllow?(entryId: string): Promise<boolean>
  /** 运维：健康检查 / Prometheus 指标 / 手动清理。 */
  health?(): Promise<Record<string, unknown>>
  metrics?(): Promise<string>
  maintenance?(): Promise<Record<string, number>>
  /** 工作流模版（分析编排）：列表 / 保存 / 启停 / 删除 / 项目引用。 */
  workflows?(): Promise<readonly unknown[]>
  saveWorkflow?(body: unknown): Promise<unknown>
  setWorkflowEnabled?(workflowId: string, enabled: boolean): Promise<boolean>
  removeWorkflow?(workflowId: string): Promise<boolean>
  bindWorkflow?(projectId: string, workflowId: string): Promise<{ ok: boolean, error?: string }>
  /** 分析过程（P3）：列表 / 详情 / 会话时间线（after 增量）。 */
  listProcesses?(query: { limit: number, offset: number, search: string, outcome: string, project?: string }): Promise<{
    total: number
    items: readonly unknown[]
  }>
  getProcess?(taskId: string, projectId?: string): Promise<unknown>
  processEvents?(taskId: string, projectId?: string, after?: number): Promise<unknown>
  /** 运行参数快照（可选：老版本 xdr-ingest 没有，控制台显示"不可改"）。 */
  settings?(projectId?: string): Promise<Record<string, unknown>>
  /** 保存运行参数（可选；校验在数据面做，控制台只透传）。 */
  updateSettings?(patch: unknown, projectId?: string): Promise<{
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
  /** 系统设置面（模型选择 / API Key / 插件清单）；所有方法都可返回 {ok:false,error}。 */
  readonly system: {
    snapshot: () => Promise<unknown>
    saveModel: (patch: unknown) => Promise<unknown>
    saveKey: (patch: unknown) => Promise<unknown>
    saveEndpoint: (patch: unknown) => Promise<unknown>
    saveProvider: (patch: unknown) => Promise<unknown>
    listProviderModels: (patch: unknown) => Promise<unknown>
  }
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
/** 脚本正文上限：与 xdr-ingest 的 scriptMaxCodeBytes（默认 64KB）对齐，留点 JSON 余量 */
const MAX_SCRIPT_BODY = 256 * 1024
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

  /**
   * 项目参数：`?project=XXXXXXXX`（NDR 授权ID）。
   * 不传 = 数据面用默认项目（单项目部署等价于原来）。
   */
  const projectParam = (query: URLSearchParams): { project?: string } => {
    const project = (query.get('project') ?? '').trim().toUpperCase()
    return /^[A-Z0-9]{8}$/u.test(project) ? { project } : {}
  }
  const projectFrom = (req: IncomingMessage): string | undefined => projectParam(queryOf(req)).project

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
      if (tail === '/api/system') {
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'system accepts GET only; use /api/system/model|key|endpoint' })
          return
        }
        if (!apiGuard()) return
        respondJson(res, 200, await options.system.snapshot())
        return
      }
      if (tail === '/api/system/models') {
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
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
        respondJson(res, 200, await options.system.listProviderModels(patch))
        return
      }
      if (tail === '/api/system/model' || tail === '/api/system/key' || tail === '/api/system/endpoint' || tail === '/api/system/provider') {
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
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
        const save = tail === '/api/system/model'
          ? options.system.saveModel
          : tail === '/api/system/key'
            ? options.system.saveKey
            : tail === '/api/system/provider' ? options.system.saveProvider : options.system.saveEndpoint
        const result = await save(patch) as { ok?: boolean }
        respondJson(res, result.ok === false ? 400 : 200, result)
        return
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
        const result = await ingest.updateSettings(patch, projectParam(queryOf(req)).project)
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
        let conclusions: { available: boolean, total: number } = { available: false, total: 0 }
        if (typeof ingest.conclusionStats === 'function') {
          try {
            conclusions = await ingest.conclusionStats(projectFrom(req))
          } catch {
            conclusions = { available: false, total: 0 }
          }
        }
        respondJson(res, 200, { available: true, status, cache, conclusions })
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
      // ---------- 结论（智能体交回的判定；NDR 写、同库只读） ----------
      if (tail === '/api/conclusions') {
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        const ingest = options.ingest()
        if (ingest === null || typeof ingest.listConclusions !== 'function') {
          respondJson(res, 200, { available: false, total: 0, entries: [] })
          return
        }
        const query = queryOf(req)
        const limit = clampInt(query.get('limit'), DEFAULT_LIMIT, 1, MAX_LIMIT)
        const offset = clampInt(query.get('offset'), 0, 0, MAX_OFFSET)
        const search = (query.get('q') ?? '').slice(0, 128)
        const page = await ingest.listConclusions({ limit, offset, search, ...projectParam(query) })
        respondJson(res, 200, { available: true, total: page.total, entries: page.entries })
        return
      }
      if (tail.startsWith('/api/conclusions/')) {
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        const id = decodeURIComponent(tail.slice('/api/conclusions/'.length)).trim()
        if (id === '' || id.length > MAX_ANALYSIS_ID || /[\u0000-\u001f]/u.test(id)) {
          respondJson(res, 400, { error: 'invalid conclusion id' })
          return
        }
        const ingest = options.ingest()
        if (ingest === null || typeof ingest.getConclusion !== 'function') {
          respondJson(res, 404, { error: 'data plane unavailable' })
          return
        }
        const entry = await ingest.getConclusion(id, projectFrom(req))
        if (entry === null || entry === undefined) {
          respondJson(res, 404, { error: 'not found' })
          return
        }
        respondJson(res, 200, { entry })
        return
      }
      // ---------- 项目组织（P2：一个 agent 接多台 NDR，数据按项目隔离） ----------
      if (tail === '/api/projects') {
        if (method === 'GET') {
          if (!apiGuard()) return
          const ingest = options.ingest()
          if (ingest === null || typeof ingest.projects !== 'function') {
            respondJson(res, 200, { available: false, projects: [] })
            return
          }
          const projects = await ingest.projects()
          respondJson(res, 200, { available: true, projects })
          return
        }
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        if (options.ingest() === null || typeof options.ingest()?.saveProject !== 'function') {
          respondJson(res, 503, { ok: false, error: '数据面不可用，项目暂不可改' })
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
        const result = await options.ingest()?.saveProject?.(patch)
        respondJson(res, result?.ok === false ? 400 : 200, result ?? { ok: false })
        return
      }
      if (tail.startsWith('/api/projects/')) {
        if (!apiGuard()) return
        const rest = decodeURIComponent(tail.slice('/api/projects/'.length)).trim().toUpperCase()
        // 复核：POST /api/projects/{id}/verify
        if (rest.endsWith('/VERIFY')) {
          if (method !== 'POST') {
            respondJson(res, 405, { error: 'method not allowed' })
            return
          }
          const id = rest.slice(0, -'/VERIFY'.length)
          const ingest = options.ingest()
          if (ingest === null || typeof ingest.verifyProject !== 'function') {
            respondJson(res, 503, { ok: false, error: '数据面不可用' })
            return
          }
          const project = await ingest.verifyProject(id)
          respondJson(res, project === null || project === undefined ? 404 : 200, { ok: project !== null, project })
          return
        }
        if (!/^[A-Z0-9]{8}$/u.test(rest)) {
          respondJson(res, 400, { error: 'invalid project id' })
          return
        }
        if (method !== 'DELETE') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        const ingest = options.ingest()
        if (ingest === null || typeof ingest.removeProject !== 'function') {
          respondJson(res, 503, { ok: false, error: '数据面不可用' })
          return
        }
        const done = await ingest.removeProject(rest)
        respondJson(res, done ? 200 : 404, { ok: done })
        return
      }
      // ---------- 运维：健康检查 / 指标（不需要登录，给探针用） ----------
      if (tail === '/healthz') {
        const ingest = options.ingest()
        if (ingest === null || typeof ingest.health !== 'function') {
          respondJson(res, 503, { ok: false, error: 'data plane unavailable' })
          return
        }
        const health = await ingest.health()
        respondJson(res, health?.['ok'] === true ? 200 : 503, health)
        return
      }
      if (tail === '/metrics') {
        const ingest = options.ingest()
        if (ingest === null || typeof ingest.metrics !== 'function') {
          res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' })
          res.end('# data plane unavailable\n')
          return
        }
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
        res.end(await ingest.metrics())
        return
      }
      // ---------- 行为基线与外连白名单 ----------
      if (tail === '/api/observations') {
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        const ingest = options.ingest()
        if (ingest === null || typeof ingest.listObservations !== 'function') {
          respondJson(res, 200, { available: false, total: 0, items: [] })
          return
        }
        const query = queryOf(req)
        const page = await ingest.listObservations({
          kind: (query.get('kind') ?? '').slice(0, 32),
          subject: (query.get('subject') ?? '').slice(0, 128),
          minutes: clampInt(query.get('minutes'), 1440, 1, 60 * 24 * 30),
          limit: clampInt(query.get('limit'), DEFAULT_LIMIT, 1, MAX_LIMIT),
          offset: clampInt(query.get('offset'), 0, 0, MAX_OFFSET),
        })
        let stats: unknown = null
        if (typeof ingest.observationStats === 'function') {
          stats = await ingest.observationStats().catch(() => null)
        }
        respondJson(res, 200, { available: true, total: page.total, items: page.items, stats })
        return
      }
      if (tail === '/api/egress-allow') {
        if (method === 'GET') {
          if (!apiGuard()) return
          const ingest = options.ingest()
          if (ingest === null || typeof ingest.listEgressAllow !== 'function') {
            respondJson(res, 200, { available: false, items: [] })
            return
          }
          const query = queryOf(req)
          const items = await ingest.listEgressAllow({
            kind: (query.get('kind') ?? '').slice(0, 16),
            includeTombstone: query.get('tombstone') === '1',
          })
          respondJson(res, 200, { available: true, items })
          return
        }
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        if (typeof options.ingest()?.saveEgressAllow !== 'function') {
          respondJson(res, 503, { ok: false, error: '数据面不可用' })
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
        const result = (await options.ingest()?.saveEgressAllow?.(patch)) as
          | { ok?: boolean }
          | undefined
        respondJson(res, result?.ok === false ? 400 : 200, result ?? { ok: false })
        return
      }
      if (tail.startsWith('/api/egress-allow/')) {
        if (!apiGuard()) return
        const rest = decodeURIComponent(tail.slice('/api/egress-allow/'.length)).trim()
        if (rest === '' || rest.length > 80) {
          respondJson(res, 400, { error: 'invalid entry id' })
          return
        }
        if (rest.endsWith('/restore')) {
          if (method !== 'POST') {
            respondJson(res, 405, { error: 'method not allowed' })
            return
          }
          const id = rest.slice(0, -'/restore'.length)
          const done = await options.ingest()?.restoreEgressAllow?.(id)
          respondJson(res, done === true ? 200 : 404, { ok: done === true })
          return
        }
        if (method !== 'DELETE') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        const done = await options.ingest()?.removeEgressAllow?.(rest)
        respondJson(res, done === true ? 200 : 404, { ok: done === true })
        return
      }
      if (tail === '/api/maintenance') {
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        const result = await options.ingest()?.maintenance?.()
        respondJson(res, 200, { ok: true, deleted: result ?? {} })
        return
      }
      // ---------- 工作流模版（分析编排） ----------
      if (tail === '/api/workflows') {
        if (method === 'GET') {
          if (!apiGuard()) return
          const ingest = options.ingest()
          if (ingest === null || typeof ingest.workflows !== 'function') {
            respondJson(res, 200, { available: false, items: [] })
            return
          }
          respondJson(res, 200, { available: true, items: await ingest.workflows() })
          return
        }
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        if (typeof options.ingest()?.saveWorkflow !== 'function') {
          respondJson(res, 503, { ok: false, error: '数据面不可用' })
          return
        }
        const body = await readBody(req, MAX_SETTINGS_BODY * 4)
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
        try {
          const saved = await options.ingest()?.saveWorkflow?.(patch)
          respondJson(res, 200, { ok: true, workflow: saved })
        } catch (error) {
          respondJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) })
        }
        return
      }
      if (tail === '/api/workflows/bind') {
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        if (typeof options.ingest()?.bindWorkflow !== 'function') {
          respondJson(res, 503, { ok: false, error: '数据面不可用' })
          return
        }
        const body = await readBody(req, MAX_SETTINGS_BODY)
        if (body === undefined) {
          respondJson(res, 413, { ok: false, error: '请求体过大' })
          return
        }
        let patch: { projectId?: unknown, workflowId?: unknown } = {}
        try {
          patch = JSON.parse(body.text) as typeof patch
        } catch {
          respondJson(res, 400, { ok: false, error: '请求体必须是 JSON' })
          return
        }
        const projectId = String(patch.projectId ?? '').trim().toUpperCase()
        if (!/^[A-Z0-9]{8}$/u.test(projectId)) {
          respondJson(res, 400, { ok: false, error: 'projectId 必须是 8 位授权ID' })
          return
        }
        const result = await options.ingest()?.bindWorkflow?.(projectId, String(patch.workflowId ?? '').trim())
        respondJson(res, result?.ok === false ? 400 : 200, result ?? { ok: false })
        return
      }
      if (tail.startsWith('/api/workflows/')) {
        if (!apiGuard()) return
        const rest = decodeURIComponent(tail.slice('/api/workflows/'.length)).trim()
        if (rest === '' || rest.length > 80 || /[\u0000-\u001f]/u.test(rest)) {
          respondJson(res, 400, { error: 'invalid workflow id' })
          return
        }
        if (rest.endsWith('/enabled')) {
          if (method !== 'POST') {
            respondJson(res, 405, { error: 'method not allowed' })
            return
          }
          const body = await readBody(req, MAX_SETTINGS_BODY)
          if (body === undefined) {
            respondJson(res, 413, { ok: false, error: '请求体过大' })
            return
          }
          let patch: { enabled?: unknown } = {}
          try {
            patch = JSON.parse(body.text) as { enabled?: unknown }
          } catch {
            respondJson(res, 400, { ok: false, error: '请求体必须是 JSON' })
            return
          }
          if (typeof patch.enabled !== 'boolean' || typeof options.ingest()?.setWorkflowEnabled !== 'function') {
            respondJson(res, 400, { ok: false, error: 'enabled 必须是布尔值' })
            return
          }
          const key = rest.slice(0, -'/enabled'.length)
          const done = await options.ingest()?.setWorkflowEnabled?.(key, patch.enabled)
          respondJson(res, done === true ? 200 : 404, { ok: done === true })
          return
        }
        if (method !== 'DELETE') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (typeof options.ingest()?.removeWorkflow !== 'function') {
          respondJson(res, 503, { ok: false, error: '数据面不可用' })
          return
        }
        const done = await options.ingest()?.removeWorkflow?.(rest)
        respondJson(res, done === true ? 200 : 404, { ok: done === true })
        return
      }
      // ---------- 分析过程（P3：任务 → 会话 → 时间线，运行中可增量轮询） ----------
      if (tail === '/api/processes') {
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        const ingest = options.ingest()
        if (ingest === null || typeof ingest.listProcesses !== 'function') {
          respondJson(res, 200, { available: false, total: 0, items: [] })
          return
        }
        const query = queryOf(req)
        const limit = clampInt(query.get('limit'), DEFAULT_LIMIT, 1, MAX_LIMIT)
        const offset = clampInt(query.get('offset'), 0, 0, MAX_OFFSET)
        const search = (query.get('q') ?? '').slice(0, 128)
        const outcome = (query.get('outcome') ?? '').slice(0, 16)
        const page = await ingest.listProcesses({ limit, offset, search, outcome, ...projectParam(query) })
        respondJson(res, 200, { available: true, total: page.total, items: page.items })
        return
      }
      if (tail.startsWith('/api/processes/')) {
        if (!apiGuard()) return
        const rest = decodeURIComponent(tail.slice('/api/processes/'.length)).trim()
        if (rest === '' || rest.length > MAX_ANALYSIS_ID || /[\u0000-\u001f]/u.test(rest)) {
          respondJson(res, 400, { error: 'invalid task id' })
          return
        }
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        const ingest = options.ingest()
        // 时间线：GET /api/processes/{taskId}/events?after=12
        if (rest.endsWith('/events')) {
          if (ingest === null || typeof ingest.processEvents !== 'function') {
            respondJson(res, 503, { ok: false, error: '数据面不可用' })
            return
          }
          const taskId = rest.slice(0, -'/events'.length)
          const after = clampInt(queryOf(req).get('after'), 0, 0, Number.MAX_SAFE_INTEGER)
          const timeline = await ingest.processEvents(taskId, projectFrom(req), after)
          respondJson(res, 200, timeline)
          return
        }
        if (ingest === null || typeof ingest.getProcess !== 'function') {
          respondJson(res, 404, { error: 'data plane unavailable' })
          return
        }
        const entry = await ingest.getProcess(rest, projectFrom(req))
        if (entry === null || entry === undefined) {
          respondJson(res, 404, { error: 'not found' })
          return
        }
        // 详情顺带把会话时间线首段带回来，前端少一次往返
        let timeline: unknown = null
        if (typeof ingest.processEvents === 'function') {
          try {
            timeline = await ingest.processEvents(rest, projectFrom(req), 0)
          } catch {
            timeline = null
          }
        }
        respondJson(res, 200, { entry, timeline })
        return
      }
      // ---------- 分析脚本（P4：控制台管理；模型侧仍走 find/get/save 工具） ----------
      if (tail === '/api/scripts') {
        if (method === 'GET') {
          if (!apiGuard()) return
          const ingest = options.ingest()
          if (ingest === null || typeof ingest.listScripts !== 'function') {
            respondJson(res, 200, { available: false, total: 0, items: [] })
            return
          }
          const query = queryOf(req)
          const limit = clampInt(query.get('limit'), DEFAULT_LIMIT, 1, MAX_LIMIT)
          const offset = clampInt(query.get('offset'), 0, 0, MAX_OFFSET)
          const search = (query.get('q') ?? '').slice(0, 128)
          const page = await ingest.listScripts({ search, limit, offset, ...projectParam(query) })
          respondJson(res, 200, { available: true, total: page.total, items: page.items })
          return
        }
        if (method !== 'POST') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (!apiGuard()) return
        if (options.ingest() === null || typeof options.ingest()?.saveScript !== 'function') {
          respondJson(res, 503, { ok: false, error: '数据面不可用，脚本暂不可改' })
          return
        }
        const body = await readBody(req, MAX_SCRIPT_BODY)
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
        try {
          const saved = await options.ingest()?.saveScript?.(patch, projectFrom(req))
          respondJson(res, 200, { ok: true, script: saved })
        } catch (error) {
          respondJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) })
        }
        return
      }
      if (tail.startsWith('/api/scripts/')) {
        if (!apiGuard()) return
        const rest = decodeURIComponent(tail.slice('/api/scripts/'.length)).trim()
        if (rest === '' || rest.length > MAX_ANALYSIS_ID || /[\u0000-\u001f]/u.test(rest)) {
          respondJson(res, 400, { error: 'invalid script id' })
          return
        }
        const ingest = options.ingest()
        // 启停：POST /api/scripts/{nameOrId}/enabled {enabled:bool}
        if (rest.endsWith('/enabled')) {
          if (method !== 'POST') {
            respondJson(res, 405, { error: 'method not allowed' })
            return
          }
          if (ingest === null || typeof ingest.setScriptEnabled !== 'function') {
            respondJson(res, 503, { ok: false, error: '数据面不可用' })
            return
          }
          const body = await readBody(req, MAX_SETTINGS_BODY)
          if (body === undefined) {
            respondJson(res, 413, { ok: false, error: '请求体过大' })
            return
          }
          let patch: { enabled?: unknown } = {}
          try {
            patch = JSON.parse(body.text) as { enabled?: unknown }
          } catch {
            respondJson(res, 400, { ok: false, error: '请求体必须是 JSON' })
            return
          }
          if (typeof patch.enabled !== 'boolean') {
            respondJson(res, 400, { ok: false, error: 'enabled 必须是布尔值' })
            return
          }
          const key = rest.slice(0, -'/enabled'.length)
          const done = await ingest.setScriptEnabled(key, patch.enabled, projectFrom(req))
          respondJson(res, done ? 200 : 404, { ok: done })
          return
        }
        if (method === 'DELETE') {
          if (ingest === null || typeof ingest.removeScript !== 'function') {
            respondJson(res, 503, { ok: false, error: '数据面不可用' })
            return
          }
          const done = await ingest.removeScript(rest, projectFrom(req))
          respondJson(res, done ? 200 : 404, { ok: done })
          return
        }
        if (method !== 'GET') {
          respondJson(res, 405, { error: 'method not allowed' })
          return
        }
        if (ingest === null || typeof ingest.getScript !== 'function') {
          respondJson(res, 404, { error: 'data plane unavailable' })
          return
        }
        const entry = await ingest.getScript(rest, projectFrom(req))
        if (entry === null || entry === undefined) {
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
