/**
 * 极简 MCP 客户端（Streamable HTTP），只做控制面要的三件事：
 * `initialize` → `notifications/initialized` → `tools/call`。
 *
 * 为什么自己写而不是复用 dsh 的 mcp-client：dsh 那个是**给模型用**的（把工具暴露成
 * `mcp__ndr__*` 让 LLM 调）。而"领任务 / 查状态 / 延后"属于**插件的控制面**，
 * 不能依赖模型这轮有没有去调 —— 模型不发呆是运气，不是设计。
 *
 * 零依赖（只用 Node 自带 fetch）：本地没有 node_modules 也能跑测试。
 */

export interface McpClientOptions {
  /** 例如 http://ndr-mcp:8090/mcp */
  readonly url: string
  /** Bearer 令牌（NDR 侧 stmcp_ 前缀那种） */
  readonly token: string
  readonly clientName?: string
  readonly clientVersion?: string
  readonly timeoutMs?: number
  /** 可注入 fetch（测试用） */
  readonly fetchImpl?: typeof fetch
}

export class McpError extends Error {
  readonly status: number

  constructor(message: string, status = 0) {
    super(message)
    this.status = status
  }
}

const PROTOCOL_VERSION = '2026-07-28'
const SESSION_HEADER = 'mcp-session-id'
const VERSION_HEADER = 'mcp-protocol-version'
//: 2026-07-28 起每个请求还要带路由头：方法与（tools/call 时）工具名，
//: 服务端会拿它和 JSON-RPC body 比对，不一致直接 400。
const METHOD_HEADER = 'mcp-method'
const NAME_HEADER = 'mcp-name'
//: `params._meta` 里的两个协商键（键名由 MCP 规范固定，不能改）
const PROTOCOL_VERSION_META_KEY = 'io.modelcontextprotocol/protocolVersion'
const CLIENT_CAPABILITIES_META_KEY = 'io.modelcontextprotocol/clientCapabilities'

interface JsonRpcResponse {
  readonly id?: number | string | null
  readonly result?: unknown
  readonly error?: { readonly code?: number; readonly message?: string }
}

/** 把 SSE 响应体里所有 `data:` 帧拼出来（服务端可能用事件流回一个单响应）。 */
function parseSse(text: string): string[] {
  const out: string[] = []
  for (const line of text.split(/\r?\n/u)) {
    if (line.startsWith('data:')) {
      out.push(line.slice(5).trim())
    }
  }
  return out.filter(item => item !== '')
}

/** `tools/call` 的路由头要带工具名；其它方法不需要。 */
function toolNameOf(params: Record<string, unknown>): string {
  const name = params['name']
  return typeof name === 'string' ? name : ''
}


export class McpHttpClient {
  private readonly options: McpClientOptions
  private readonly fetchImpl: typeof fetch
  private sessionId = ''
  private nextId = 1
  private ready = false

  constructor(options: McpClientOptions) {
    this.options = options
    this.fetchImpl = options.fetchImpl ?? fetch
  }

  /** 调一个 MCP 工具，返回解析后的对象（NDR 的工具都返回 JSON 字符串）。 */
  async callTool(
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    await this.ensureReady()
    const payload = await this.request('tools/call', { name, arguments: args })
    return this.unwrapToolResult(payload)
  }

  /**
   * 2026-07-28 这一版**没有 `initialize` 握手**：协议版本与客户端能力改为
   * 每个请求用 `params._meta` 随行声明，服务端按 `mcp-method` 路由头分派。
   * 所以这里没有"先握手"这一步 —— 早先按旧规范先发 initialize 会得到
   * `Method not found (data: "initialize")`（实测）。
   */
  private async ensureReady(): Promise<void> {
    return
  }

  private unwrapToolResult(result: unknown): Record<string, unknown> {
    const record = (result ?? {}) as {
      content?: Array<{ type?: string; text?: string }>
      isError?: boolean
      structuredContent?: Record<string, unknown>
    }
    if (record.structuredContent !== undefined) {
      return record.structuredContent
    }
    const text = (record.content ?? [])
      .filter(part => part?.type === 'text' && typeof part.text === 'string')
      .map(part => part.text as string)
      .join('')
    if (text === '') {
      return record.isError === true ? { error: '工具返回为空' } : {}
    }
    try {
      const parsed: unknown = JSON.parse(text)
      if (typeof parsed === 'object' && parsed !== null) {
        return parsed as Record<string, unknown>
      }
      return { result: parsed }
    } catch {
      // 少数工具返回纯文本；保留原文，别假装解析成功
      return { text }
    }
  }

  /** 每个请求都要带的协商元数据（键名由 MCP 规范固定）。 */
  private metaOf(): Record<string, unknown> {
    return {
      [PROTOCOL_VERSION_META_KEY]: PROTOCOL_VERSION,
      [CLIENT_CAPABILITIES_META_KEY]: {},
    }
  }

  private async notify(method: string): Promise<void> {
    await this.post({ jsonrpc: '2.0', method }, method)
  }

  private async request(method: string, params: Record<string, unknown>): Promise<unknown> {
    const id = this.nextId++
    const enriched = { ...params, _meta: this.metaOf() }
    const body = await this.post(
      { jsonrpc: '2.0', id, method, params: enriched },
      method,
      toolNameOf(params),
    )
    const response = this.pickResponse(body, id)
    if (response?.error !== undefined && response.error !== null) {
      throw new McpError(
        `MCP ${method} 失败：${response.error.message ?? '未知错误'}`,
        Number(response.error.code ?? 0),
      )
    }
    return response?.result ?? null
  }

  private pickResponse(raw: string, id: number): JsonRpcResponse | null {
    if (raw.trim() === '') return null
    const candidates: string[] = []
    try {
      JSON.parse(raw)
      candidates.push(raw)
    } catch {
      candidates.push(...parseSse(raw))
    }
    for (const candidate of candidates) {
      try {
        const parsed = JSON.parse(candidate) as JsonRpcResponse | JsonRpcResponse[]
        const list = Array.isArray(parsed) ? parsed : [parsed]
        for (const item of list) {
          if (item?.id === id) return item
        }
      } catch {
        continue
      }
    }
    return null
  }

  private async post(
    payload: Record<string, unknown>,
    method: string,
    name = '',
  ): Promise<string> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${this.options.token}`,
      [VERSION_HEADER]: PROTOCOL_VERSION,
      [METHOD_HEADER]: method,
    }
    if (name !== '') {
      headers[NAME_HEADER] = name
    }
    if (this.sessionId !== '') {
      headers[SESSION_HEADER] = this.sessionId
    }
    const controller = new AbortController()
    const timeoutMs = this.options.timeoutMs ?? 60_000
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const response = await this.fetchImpl(this.options.url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      })
      const session = response.headers.get(SESSION_HEADER)
      if (session !== null && session !== '') {
        this.sessionId = session
      }
      const text = await response.text()
      if (!response.ok) {
        // 会话过期（404）时清掉会话，下次调用重新握手
        if (response.status === 404) {
          this.sessionId = ''
          this.ready = false
        }
        throw new McpError(
          `MCP HTTP ${response.status}：${text.slice(0, 200)}`,
          response.status,
        )
      }
      return text
    } finally {
      clearTimeout(timer)
    }
  }
}
