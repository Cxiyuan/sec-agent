/**
 * OpenCode v2 运行时的最小封装。
 *
 * 为什么是 v2：10.44.77.249 上验证过的版本是 2.0.18；v2 的 HTTP API 在 `/api/**`，
 * 与 v1 完全不同。我们把版本 pin 在镜像里，不依赖宿主机装了什么。
 *
 * 安全边界：
 * - 隔离 XDG 目录 + 独立 server 密码；
 * - 权限全部 deny（模型不能 shell/写文件/联网抓取）；
 * - 每次请求一个 session，结束即删。
 */

import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

export class OpenCodeError extends Error {
  constructor(message, status = 502, code = 'opencode_error') {
    super(message)
    Object.assign(this, { status, code })
  }
}

/** v2 隔离配置：模型只能"说"，不能"做"。 */
export const ISOLATED_CONFIG = {
  update: 'disable',
  share: 'disabled',
  snapshots: false,
  permissions: [{ action: '*', resource: '*', effect: 'deny' }],
  agents: {
    'xdr-bridge': {
      mode: 'primary',
      system:
        '你是外部安全分析智能体的推理内核。'
        + '你不能执行任何本机工具；所有外部动作只能作为 JSON 数据返回给客户端。',
      permissions: [{ action: '*', resource: '*', effect: 'deny' }],
    },
  },
  default_agent: 'xdr-bridge',
}

export class OpenCodeRuntime {
  constructor(config, { log = () => {}, fetchImpl = globalThis.fetch } = {}) {
    this.config = config
    this.log = log
    this.fetchImpl = fetchImpl
    this.child = null
    this.baseUrl = ''
    this.password = config.opencodePassword || randomUUID().replaceAll('-', '')
    this.version = ''
  }

  /** 启动进程（或连接测试注入的地址）并等到 /api/info 就绪。 */
  async start() {
    if (this.config.opencodeUrl !== '') {
      this.baseUrl = this.config.opencodeUrl.replace(/\/+$/u, '')
      const info = await this.info()
      this.version = String(info.version ?? '')
      return this
    }
    const data = path.join(this.config.dataDir, 'opencode')
    for (const dir of ['config', 'data', 'cache', 'state', 'work']) {
      await fs.mkdir(path.join(data, dir), { recursive: true, mode: 0o700 })
    }
    const env = {}
    for (const key of ['PATH', 'HOME', 'USER', 'LANG', 'TMPDIR', 'SSL_CERT_FILE', 'NODE_EXTRA_CA_CERTS']) {
      if (process.env[key]) env[key] = process.env[key]
    }
    for (const name of ['config', 'data', 'cache', 'state']) {
      env[`XDG_${name.toUpperCase()}_HOME`] = path.join(data, name)
    }
    Object.assign(env, {
      OPENCODE_SERVER_USERNAME: this.config.opencodeUsername,
      OPENCODE_SERVER_PASSWORD: this.password,
      OPENCODE_DISABLE_AUTOUPDATE: 'true',
      OPENCODE_DISABLE_PROJECT_CONFIG: 'true',
      OPENCODE_DISABLE_CLAUDE_CODE: 'true',
      OPENCODE_DISABLE_EXTERNAL_SKILLS: 'true',
      OPENCODE_CONFIG_CONTENT: JSON.stringify(ISOLATED_CONFIG),
    })
    const port = 1024 + Math.floor(Math.random() * 50000)
    this.baseUrl = `http://127.0.0.1:${port}`
    this.child = spawn(
      this.config.opencodeBin,
      ['serve', '--hostname', '127.0.0.1', '--port', String(port)],
      { cwd: path.join(data, 'work'), env, stdio: ['ignore', 'pipe', 'pipe'] },
    )
    this.child.stdout.on('data', chunk => this.log(`opencode: ${String(chunk).trim()}`))
    this.child.stderr.on('data', chunk => this.log(`opencode[err]: ${String(chunk).trim()}`))
    this.child.on('exit', code => this.log(`opencode 进程退出：${code}`))
    for (let attempt = 0; attempt < 120; attempt += 1) {
      if (this.child.exitCode !== null) {
        throw new OpenCodeError(`OpenCode 启动失败（exit ${this.child.exitCode}）`, 502, 'opencode_exit')
      }
      try {
        const info = await this.info(1500)
        if (info !== null) {
          this.version = String(info.version ?? '')
          if (this.config.expectedVersion !== '' && this.version !== this.config.expectedVersion) {
            throw new OpenCodeError(
              `OpenCode 版本不符：期望 ${this.config.expectedVersion}，实际 ${this.version}`,
              502,
              'opencode_version',
            )
          }
          return this
        }
      } catch (error) {
        if (error instanceof OpenCodeError) throw error
      }
      await delay(500)
    }
    throw new OpenCodeError('OpenCode 启动超时', 502, 'opencode_timeout')
  }

  async stop() {
    if (this.child !== null && this.child.exitCode === null) {
      this.child.kill('SIGTERM')
      await Promise.race([
        new Promise(resolve => this.child.once('exit', resolve)),
        delay(4000),
      ])
      if (this.child.exitCode === null) this.child.kill('SIGKILL')
    }
    this.child = null
  }

  headers() {
    return {
      'content-type': 'application/json',
      authorization:
        'Basic '
        + Buffer.from(`${this.config.opencodeUsername}:${this.password}`).toString('base64'),
    }
  }

  async request(route, method = 'GET', body, timeout = this.config.timeoutMs) {
    const signal = timeout > 0 ? AbortSignal.timeout(timeout) : undefined
    let response
    try {
      response = await this.fetchImpl(`${this.baseUrl}${route}`, {
        method,
        headers: this.headers(),
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
      })
    } catch (error) {
      if (error?.name === 'TimeoutError' || /abort/iu.test(String(error?.message ?? ''))) {
        throw new OpenCodeError('OpenCode 请求超时', 504, 'timeout')
      }
      throw new OpenCodeError(`OpenCode 连接失败：${String(error?.message ?? error).slice(0, 200)}`)
    }
    const text = await response.text()
    if (response.status < 200 || response.status >= 300) {
      throw new OpenCodeError(
        `OpenCode HTTP ${response.status}：${text.slice(0, 400)}`,
        response.status === 429 ? 429 : 502,
        response.status === 429 ? 'free_quota' : 'upstream_error',
      )
    }
    if (text.trim() === '') return null
    try {
      return JSON.parse(text)
    } catch {
      throw new OpenCodeError('OpenCode 返回了非 JSON 响应', 502, 'upstream_error')
    }
  }

  async info(timeout = 3000) {
    try {
      return await this.request('/api/info', 'GET', undefined, timeout)
    } catch {
      return null
    }
  }

  /** 当前免费模型目录（v2：/api/model -> {data:[...]}）。 */
  async rawModels() {
    const result = await this.request('/api/model', 'GET', undefined, 20_000)
    return Array.isArray(result?.data) ? result.data : []
  }

  async createSession() {
    const result = await this.request(
      '/api/session',
      'POST',
      { title: 'xdr-bridge', agent: 'xdr-bridge' },
      20_000,
    )
    const id = result?.data?.id ?? result?.id
    if (typeof id !== 'string' || id === '') {
      throw new OpenCodeError('OpenCode 没有返回 session id', 502, 'upstream_error')
    }
    return id
  }

  async setModel(sessionId, modelId) {
    await this.request(
      `/api/session/${encodeURIComponent(sessionId)}/model`,
      'POST',
      { model: { providerID: 'opencode', id: modelId } },
      20_000,
    )
  }

  async prompt(sessionId, text) {
    await this.request(
      `/api/session/${encodeURIComponent(sessionId)}/prompt`,
      'POST',
      { text },
      this.config.timeoutMs,
    )
  }

  async wait(sessionId) {
    await this.request(
      `/api/experimental/session/${encodeURIComponent(sessionId)}/wait`,
      'POST',
      {},
      this.config.timeoutMs,
    )
  }

  async messages(sessionId) {
    const result = await this.request(
      `/api/session/${encodeURIComponent(sessionId)}/message?limit=50&order=desc`,
      'GET',
      undefined,
      30_000,
    )
    const rows = Array.isArray(result?.data) ? result.data : []
    return rows.slice().reverse()
  }

  async pendingPermissions(sessionId) {
    try {
      const result = await this.request('/api/permission/request', 'GET', undefined, 5000)
      const rows = Array.isArray(result?.data) ? result.data : []
      return rows.filter(row => row?.sessionID === sessionId)
    } catch {
      return []
    }
  }

  async rejectPermission(sessionId, permissionId, message) {
    await this.request(
      `/api/session/${encodeURIComponent(sessionId)}/permission/${encodeURIComponent(permissionId)}/reply`,
      'POST',
      { decision: 'reject', message },
      5000,
    ).catch(() => null)
  }

  async interrupt(sessionId) {
    await this.request(
      `/api/session/${encodeURIComponent(sessionId)}/interrupt`,
      'POST',
      undefined,
      5000,
    ).catch(() => null)
  }

  async deleteSession(sessionId) {
    await this.request(
      `/api/session/${encodeURIComponent(sessionId)}`,
      'DELETE',
      undefined,
      5000,
    ).catch(() => null)
  }
}
