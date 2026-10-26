/**
 * 工作台鉴权：账号密码登录 + HMAC 签名会话 Cookie。
 *
 * 设计要点：
 * - **与 dsh 的 /login 同一组凭据**：都读 DSH_WEB_AUTH_USER / DSH_WEB_AUTH_PASSWORD，
 *   部署只改一处；两者都没配时用默认 admin/admin123（现场部署默认值）。
 * - **不 forge dsh 的会话**：dsh 的 Cookie 密钥在它的 credentials 存储里，本插件
 *   拿不到也不去拿——工作台自签自验，Cookie 名与 dsh 的不冲突。
 * - **密钥寻源**：DSH_WEB_UI_SECRET → DSH_WEB_LAUNCH_TOKEN（部署缝已固定，重启
 *   不变）→ 进程内随机。随机兜底一次重启全下线，属可用性损失而非安全损失，
 *   由调用方在启动时显式告警。
 * - 恒时比较（先哈希定长）；HMAC 校验 timingSafeEqual。
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

export const COOKIE_NAME = 'xdr-ui-auth'
export const COOKIE_VERSION = 'v1'
const SECRET_BYTES = 32
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/
/** Cookie 主体上限：版本+时间戳的合法载荷远小于此，超小的本来就是垃圾。 */
const COOKIE_VALUE_MAX = 256

/** 登录凭据（部署现场默认 admin/admin123；可经环境缝覆盖）。 */
export interface UiCredentials {
  readonly user: string
  readonly password: string
}

/** 与 dsh /login 同一读法：DSH_WEB_AUTH_USER / DSH_WEB_AUTH_PASSWORD，缺省回落。 */
export function credentialsOf(env: NodeJS.ProcessEnv): UiCredentials {
  return {
    user: env['DSH_WEB_AUTH_USER']?.trim() || 'admin',
    password: env['DSH_WEB_AUTH_PASSWORD'] || 'admin123',
  }
}

function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '')
}

function decodeBase64Url(value: string): Buffer | undefined {
  if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) return undefined
  const decoded = Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4), 'base64')
  return encodeBase64Url(decoded) === value ? decoded : undefined
}

/** 恒时比较（先哈希成定长，避免长度泄露）。 */
export function loginMatches(presented: string, expected: string): boolean {
  const a = createHash('sha256').update(presented, 'utf8').digest()
  const b = createHash('sha256').update(expected, 'utf8').digest()
  return timingSafeEqual(a, b)
}

/**
 * 会话签名密钥的文字形态（最终使用其 SHA-256 摘要作 HMAC key，任意长度都安全）。
 * @returns 第一个够长的缝（≥16 字符），都没有时为每个进程生成一次随机值。
 */
export function resolveSessionSecret(env: NodeJS.ProcessEnv): { secret: string, volatile: boolean } {
  const seams = [env['DSH_WEB_UI_SECRET']?.trim(), env['DSH_WEB_LAUNCH_TOKEN']?.trim()]
  for (const seam of seams) {
    if (seam !== undefined && seam.length >= 16) return { secret: seam, volatile: false }
  }
  // SAFETY：只有调用方（apply）紧跟着警告这件事，这里不吞掉上下文。
  return { secret: encodeBase64Url(randomBytes(SECRET_BYTES)), volatile: true }
}

interface SessionPayload {
  readonly iat: number
  readonly exp: number
}

/** 会话句柄：签发 / 校验 / 失效，全部围绕一个 HMAC 密钥。 */
export class UiAuth {
  private readonly key: Buffer
  private readonly expectedUserHash: Buffer
  private readonly expectedPasswordHash: Buffer
  private readonly maxAgeMs: number
  private readonly now: () => number

  constructor(
    credentials: UiCredentials,
    secret: string,
    /** 会话时长（毫秒）。 */
    maxAgeMs: number,
    now: () => number = Date.now,
  ) {
    // 参数属性（constructor(private readonly x)）在 Node strip-only 模式下不可解析，
    // 测试用 node --test 直跑源文件，这里显式赋值保持"零转换"可测。
    this.key = createHash('sha256').update(secret, 'utf8').digest()
    this.expectedUserHash = createHash('sha256').update(credentials.user, 'utf8').digest()
    this.expectedPasswordHash = createHash('sha256').update(credentials.password, 'utf8').digest()
    this.maxAgeMs = maxAgeMs
    this.now = now
  }

  /** 登录校验（账号与密码都恒时比较）。 */
  verify(user: string, password: string): boolean {
    const userOk = timingSafeEqual(createHash('sha256').update(user, 'utf8').digest(), this.expectedUserHash)
    const passwordOk = timingSafeEqual(createHash('sha256').update(password, 'utf8').digest(), this.expectedPasswordHash)
    return userOk && passwordOk
  }

  /** 签发一个会话 Cookie 的完整 Set-Cookie 值（HttpOnly + SameSite=Strict）。 */
  issueCookie(): { readonly value: string, readonly maxAgeSeconds: number } {
    const issuedAt = this.now()
    const expiresAt = issuedAt + this.maxAgeMs
    const payload = encodeBase64Url(Buffer.from(JSON.stringify({ iat: issuedAt, exp: expiresAt }), 'utf8'))
    const value = `${COOKIE_VERSION}.${payload}.${encodeBase64Url(this.sign(payload))}`
    return {
      value: `${COOKIE_NAME}=${value}; Max-Age=${String(Math.floor(this.maxAgeMs / 1000))}; Path=/; HttpOnly; SameSite=Strict`,
      maxAgeSeconds: Math.floor(this.maxAgeMs / 1000),
    }
  }

  /** 失效 Cookie（登出）：同名 + Max-Age=0。 */
  clearCookie(): string {
    return `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`
  }

  /**
   * 校验请求携带的会话 Cookie。
   * @returns true 仅当签名有效且未过期。
   */
  verifyCookie(rawCookieHeader: string | undefined): boolean {
    if (rawCookieHeader === undefined || rawCookieHeader.length > 4096) return false
    const value = cookieValueOf(rawCookieHeader)
    if (value === undefined || value.length > COOKIE_VALUE_MAX) return false
    const parts = value.split('.')
    const [version, payload, signatureText] = parts
    if (parts.length !== 3 || version !== COOKIE_VERSION || payload === undefined || signatureText === undefined) return false
    const signature = decodeBase64Url(signatureText)
    if (signature === undefined) return false
    const expected = this.sign(payload)
    if (signature.byteLength !== expected.byteLength || !timingSafeEqual(signature, expected)) return false
    const payloadBytes = decodeBase64Url(payload)
    if (payloadBytes === undefined) return false
    let decoded: unknown
    try {
      decoded = JSON.parse(payloadBytes.toString('utf8')) as unknown
    } catch {
      return false
    }
    if (typeof decoded !== 'object' || decoded === null) return false
    const { iat, exp } = decoded as { iat?: unknown, exp?: unknown }
    if (typeof iat !== 'number' || typeof exp !== 'number'
      || !Number.isSafeInteger(iat) || !Number.isSafeInteger(exp)) return false
    const now = this.now()
    return iat <= now && exp > now && exp - iat <= this.maxAgeMs
  }

  /** HMAC-SHA256 定长签名，密钥为构造时定稿的密钥摘要。 */
  private sign(payload: string): Buffer {
    return createHmac('sha256', this.key).update(payload, 'utf8').digest()
  }
}

/** 从 Cookie 头取本插件的会话值（只解析最简形式，dsh 的同名解析语义保持独立）。 */
function cookieValueOf(header: string): string | undefined {
  for (const segment of header.split(';')) {
    const at = segment.indexOf('=')
    if (at === -1 || segment.slice(0, at).trim() !== COOKIE_NAME) continue
    return segment.slice(at + 1).trim()
  }
  return undefined
}

/** 表单/JSON 双读法的登录请求体 */
export interface LoginBody {
  readonly user: string
  readonly password: string
}

export function parseLoginBody(raw: string, contentType: string): LoginBody {
  if (contentType.toLowerCase().includes('application/json')) {
    try {
      const parsed: unknown = JSON.parse(raw)
      if (typeof parsed === 'object' && parsed !== null) {
        const record = parsed as Record<string, unknown>
        return {
          user: typeof record['user'] === 'string' ? record['user'] : '',
          password: typeof record['password'] === 'string' ? record['password'] : '',
        }
      }
    } catch {
      // 解析失败按空凭据处理：登录必然失败并回登录页
    }
    return { user: '', password: '' }
  }
  const fields = new URLSearchParams(raw)
  return { user: fields.get('user') ?? '', password: fields.get('password') ?? '' }
}
