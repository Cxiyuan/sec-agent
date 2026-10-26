/** 鉴权层单测：凭据寻源、登录校验、会话签发/校验、登录体解析。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { COOKIE_NAME, credentialsOf, loginMatches, parseLoginBody, resolveSessionSecret, UiAuth } from '../src/ui-auth.ts'

const HOUR = 3_600_000

function makeAuth(overrides: Partial<{ user: string, password: string, secret: string, maxAgeMs: number, now: () => number }> = {}): UiAuth {
  return new UiAuth(
    { user: overrides.user ?? 'admin', password: overrides.password ?? 'admin123' },
    overrides.secret ?? 'unit-test-secret-0123456789',
    overrides.maxAgeMs ?? 12 * HOUR,
    overrides.now,
  )
}

test('credentialsOf 默认 admin/admin123（现场部署默认值）', () => {
  assert.deepEqual(credentialsOf({}), { user: 'admin', password: 'admin123' })
  assert.deepEqual(credentialsOf({ DSH_WEB_AUTH_USER: ' ops ', DSH_WEB_AUTH_PASSWORD: 'secret' }),
    { user: 'ops', password: 'secret' })
  // 空串不改默认（空值回落）
  assert.deepEqual(credentialsOf({ DSH_WEB_AUTH_USER: '  ' }), { user: 'admin', password: 'admin123' })
})

test('resolveSessionSecret 按 DSH_WEB_UI_SECRET → DSH_WEB_LAUNCH_TOKEN 寻源，都不够长才随机', () => {
  assert.deepEqual(resolveSessionSecret({ DSH_WEB_UI_SECRET: 'ui-secret-0123456789' }),
    { secret: 'ui-secret-0123456789', volatile: false })
  assert.deepEqual(resolveSessionSecret({ DSH_WEB_LAUNCH_TOKEN: 'launch-token-0123456789' }).volatile, false)
  const random = resolveSessionSecret({})
  assert.equal(random.volatile, true)
  assert.ok(random.secret.length >= 16)
  // 两者都短时仍回落随机（弱缝不算缝）
  const short = resolveSessionSecret({ DSH_WEB_UI_SECRET: 's', DSH_WEB_LAUNCH_TOKEN: 'short' })
  assert.equal(short.volatile, true)
})

test('登录校验恒时比较：正确通过、错误拒绝、空凭据拒绝', () => {
  const auth = makeAuth()
  assert.equal(auth.verify('admin', 'admin123'), true)
  assert.equal(auth.verify('admin', 'wrong'), false)
  assert.equal(auth.verify('root', 'admin123'), false)
  assert.equal(auth.verify('', ''), false)
  // loginMatches 是同语义的独立函数
  assert.equal(loginMatches('a', 'a'), true)
  assert.equal(loginMatches('a', 'b'), false)
})

test('签发的 Cookie 校验通过；改一字节、换密钥、过期都拒绝', async () => {
  const auth = makeAuth()
  const { value } = auth.issueCookie()
  const raw = value.split('=')[1] ?? ''
  assert.ok(raw.startsWith('v1.'))
  assert.equal(auth.verifyCookie(`${COOKIE_NAME}=${raw}`), true)
  assert.equal(auth.verifyCookie(`${COOKIE_NAME}=tampered`), false)

  // 篡改签名（payload 相同、签名错）
  const [version, payload, signature] = raw.split('.')
  assert.ok(version !== undefined && payload !== undefined && signature !== undefined)
  const flipped = signature.startsWith('A') ? `B${signature.slice(1)}` : `A${signature.slice(1)}`
  assert.equal(auth.verifyCookie(`${COOKIE_NAME}=v1.${payload}.${flipped}`), false)

  // 过期：时钟放到 maxAge 之后
  const later = makeAuth({ now: () => Date.now() + 13 * HOUR })
  assert.equal(later.verifyCookie(`${COOKIE_NAME}=${raw}`), false)

  // 换了密钥（重启换环境缝）失效
  const other = makeAuth({ secret: 'another-secret-0123456789' })
  assert.equal(other.verifyCookie(`${COOKIE_NAME}=${raw}`), false)

  // 没带 Cookie / 缺字段
  assert.equal(auth.verifyCookie(undefined), false)
  assert.equal(auth.verifyCookie(' anderer = thing'), false)
})

test('parseLoginBody 同时吃表单与 JSON；坏 JSON 按空凭据处理', () => {
  assert.deepEqual(parseLoginBody('user=admin&password=admin123', 'application/x-www-form-urlencoded'),
    { user: 'admin', password: 'admin123' })
  assert.deepEqual(parseLoginBody('{"user":"a","password":"b"}', 'application/json'), { user: 'a', password: 'b' })
  assert.deepEqual(parseLoginBody('not json', 'application/json'), { user: '', password: '' })
  assert.deepEqual(parseLoginBody('', 'text/plain'), { user: '', password: '' })
})
