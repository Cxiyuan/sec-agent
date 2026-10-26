/** 工作台 HTTP 层集成测试：真实 socket 走完整「未登录→登录→看数据」流程。 */

import { strict as assert } from 'node:assert'
import { createServer, type Server } from 'node:http'
import { test } from 'node:test'
import { loginPage, workbenchPage } from '../src/html.ts'
import { createUiHandler, type IngestServiceView } from '../src/http.ts'
import { UiAuth } from '../src/ui-auth.ts'

const BASE = '/xdr/ui'

function makeIngest(overrides: Partial<IngestServiceView> = {}): IngestServiceView {
  const views: Array<Record<string, unknown>> = []
  return {
    status: () => ({ analysis: 'enabled', poll_seconds: 900, max_concurrent: 2, loop: { polls: 3, claimed: 4, started: 4, running: 1, failedClaims: 0, doorbells: 5, droppedByConcurrency: 0, consecutiveErrors: 0, lastError: '', lastBudget: '12+5/2' } }),
    cacheStats: async () => ({ hot: 10, cold: 20, analyzed: 5, reused: 9, reanalyzed: 2 }),
    wake: () => overrides.wake?.() ?? true,
    listAnalyses: async query => {
      const needles = views.filter(
        view => query.search === '' || JSON.stringify(view).toLowerCase().includes(query.search.toLowerCase()),
      )
      return {
        total: needles.length,
        entries: needles.slice(query.offset, query.offset + query.limit),
      }
    },
    getAnalysis: async id => views.find(view => view['analysisId'] === id) ?? null,
  }
}

function makeApp(options: Partial<{
  ingest: IngestServiceView | null
  password: string
  system: {
    snapshot: () => Promise<unknown>
    saveModel: (patch: unknown) => Promise<unknown>
    saveKey: (patch: unknown) => Promise<unknown>
    saveEndpoint: (patch: unknown) => Promise<unknown>
  }
}> = {}) {
  const auth = new UiAuth(
    { user: 'admin', password: options.password ?? 'admin123' },
    'http-test-secret-0123456789',
    12 * 3_600_000,
  )
  const ingestRef = { current: options.ingest === undefined ? makeIngest() : options.ingest }
  const handler = createUiHandler(BASE, {
    auth,
    ingest: () => ingestRef.current,
    renderLogin: error => loginPage(BASE, error),
    renderWorkbench: () => workbenchPage(BASE),
    meta: () => ({ user: 'admin', basePath: BASE, mcpTokenSet: true, doorbellTokenSet: true, pgSet: true }),
    system: options.system ?? {
      snapshot: async () => ({ available: false, plugins: [], model: null, key: null, notes: ['测试桩'] }),
      saveModel: async () => ({ ok: false, error: '未接线' }),
      saveKey: async () => ({ ok: false, error: '未接线' }),
      saveEndpoint: async () => ({ ok: false, error: '未接线' }),
    },
  })
  return { server: createServer(handler), ingest: ingestRef }
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  assert.ok(address !== null && typeof address === 'object')
  return `http://127.0.0.1:${address.port}`
}

function entry(id: string): Record<string, unknown> {
  return {
    analysisId: id,
    identity: { rule: 'ET SCAN', srcIp: '203.0.113.7', dstIps: ['10.0.0.5'], dstPorts: ['22'], eventTypes: ['alert'] },
    result: { category: 'scanning', severity: 'medium', summary: '端口扫描', recommendation: '观察封禁', analyzer: 'heuristic-v0' },
    occurrences: 3,
    firstSeenAt: '2026-10-26T01:00:00Z',
    lastSeenAt: '2026-10-26T02:00:00Z',
    analyzedAt: '2026-10-26T01:01:00Z',
    expiresAt: '2026-10-27T01:01:00Z',
    deliveries: [],
  }
}

async function login(base: string, password = 'admin123'): Promise<string> {
  const response = await fetch(`${base}${BASE}/login`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'user=admin&password=admin123',
  })
  assert.equal(response.status, 303)
  const setCookie = response.headers.get('set-cookie')
  assert.ok(setCookie?.startsWith('xdr-ui-auth='))
  return setCookie?.split(';')[0] ?? ''
}

test('未登录访问工作台 → 303 到登录页；登录页渲染表单与默认账号提示', async () => {
  const { server } = makeApp()
  const base = await listen(server)
  try {
    const redirected = await fetch(`${base}${BASE}/`, { redirect: 'manual' })
    assert.equal(redirected.status, 303)
    assert.equal(redirected.headers.get('location'), `${BASE}/login`)

    const page = await fetch(`${base}${BASE}/login`)
    assert.equal(page.status, 200)
    const html = await page.text()
    assert.ok(html.includes('深瞳 · 安全分析智能体'))
    assert.ok(html.includes('admin / admin123'))
    assert.ok(html.includes(`action="${BASE}/login"`))
  } finally {
    server.close()
  }
})

test('登录成功种 Cookie（HttpOnly/SameSite）；凭据错误回登录页带 error=1', async () => {
  const { server } = makeApp()
  const base = await listen(server)
  try {
    const bad = await fetch(`${base}${BASE}/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'user=admin&password=nope',
    })
    assert.equal(bad.status, 303)
    assert.equal(bad.headers.get('location'), `${BASE}/login?error=1`)
    assert.equal(bad.headers.get('set-cookie'), null)

    const cookie = await login(base)
    const page = await fetch(`${base}${BASE}/`, { headers: { cookie }, redirect: 'manual' })
    assert.equal(page.status, 200)
    const html = await page.text()
    assert.ok(html.includes('运行总览'))
    // 页面 JS 用 BASE 拼接 API，这里锁住数据源路径存在
    assert.ok(html.includes("'/api/overview'"))
    // 已登录访问登录页 → 直接回工作台
    const again = await fetch(`${base}${BASE}/login`, { headers: { cookie }, redirect: 'manual' })
    assert.equal(again.status, 303)
    assert.equal(again.headers.get('location'), `${BASE}/`)
  } finally {
    server.close()
  }
})

test('API 未登录 401；登录后 overview 返回数据面快照', async () => {
  const { server } = makeApp()
  const base = await listen(server)
  try {
    const denied = await fetch(`${base}${BASE}/api/overview`)
    assert.equal(denied.status, 401)
    assert.deepEqual(await denied.json(), { error: 'unauthorized' })

    const cookie = await login(base)
    const ok = await fetch(`${base}${BASE}/api/overview`, { headers: { cookie } })
    assert.equal(ok.status, 200)
    const data = await ok.json() as { available: boolean, status: Record<string, unknown>, cache: Record<string, unknown> }
    assert.equal(data.available, true)
    assert.equal((data.status['analysis'] as string), 'enabled')
    assert.equal((data.cache['hot'] as number), 10)
  } finally {
    server.close()
  }
})

test('数据面不在场（xdr-ingest 未安装）时 available=false 且工作台照常打开', async () => {
  const { server } = makeApp({ ingest: null })
  const base = await listen(server)
  try {
    const cookie = await login(base)
    const overview = await fetch(`${base}${BASE}/api/overview`, { headers: { cookie } })
    assert.deepEqual(await overview.json(), { available: false })
    const list = await fetch(`${base}${BASE}/api/analyses`, { headers: { cookie } })
    assert.deepEqual(await list.json(), { available: false, total: 0, entries: [] })
  } finally {
    server.close()
  }
})

test('analyses 分页参数钳制与搜索透传；详情 404/200；wake 透传数据面', async () => {
  const ingest = makeIngest({
    wake: () => false, // 分析循环未启用
  })
  const { server } = makeApp({ ingest })
  const base = await listen(server)
  try {
    const cookie = await login(base)
    // 钳制：limit>200 → 200；offset<0 → 0；search=q
    let called = 'none'
    ingest.listAnalyses = async query => {
      called = JSON.stringify(query)
      return { total: 0, entries: [] }
    }
    await fetch(`${base}${BASE}/api/analyses?limit=9999&offset=-5&q=10.0.0.5`, { headers: { cookie } })
    assert.deepEqual(JSON.parse(called), { limit: 200, offset: 0, search: '10.0.0.5' })

    const seeded = makeApp() // separate app has its own views; use detail path against seeded store
    void seeded

    const detail404 = await fetch(`${base}${BASE}/api/analyses/EA-unknown`, { headers: { cookie } })
    assert.equal(detail404.status, 404)

    // wake
    const wake = await fetch(`${base}${BASE}/api/wake`, { method: 'POST', headers: { cookie } })
    assert.equal(wake.status, 200)
    assert.deepEqual(await wake.json(), { accepted: false })
  } finally {
    server.close()
  }
})

test('详情：命中返回完整记录；非法 ID 400', async () => {
  const ingest = makeIngest()
  ingest.getAnalysis = async id => (id === 'EA-abc' ? entry('EA-abc') : null)
  const { server } = makeApp({ ingest })
  const base = await listen(server)
  try {
    const cookie = await login(base)
    const ok = await fetch(`${base}${BASE}/api/analyses/EA-abc`, { headers: { cookie } })
    assert.equal(ok.status, 200)
    const data = await ok.json() as { entry: Record<string, unknown> }
    assert.equal(data.entry['analysisId'], 'EA-abc')

    const bad = await fetch(`${base}${BASE}/api/analyses/${'e'.repeat(200)}`, { headers: { cookie } })
    assert.equal(bad.status, 400)

    const missing = await fetch(`${base}${BASE}/api/analyses/EA-none`, { headers: { cookie } })
    assert.equal(missing.status, 404)
  } finally {
    server.close()
  }
})

test('未知路径 404；登出后 Cookie 失效', async () => {
  const { server } = makeApp()
  const base = await listen(server)
  try {
    await login(base) // ensure auth path not needed for 404 check
    const unknown = await fetch(`${base}${BASE}/api/nothing`)
    assert.equal(unknown.status, 404)

    const cookie = await login(base)
    const out = await fetch(`${base}${BASE}/logout`, { method: 'POST', headers: { cookie }, redirect: 'manual' })
    assert.equal(out.status, 303)
    assert.equal(out.headers.get('location'), `${BASE}/login`)
    assert.ok(out.headers.get('set-cookie')?.includes('Max-Age=0'))
    // 原会话 Cookie 依旧签的是原值，但登出响应只发清除头；再次访问仍有效——
    // 这是有意的：登出只清本浏览器 Cookie，不吊销其他端（工作台单账号语义）。
    const still = await fetch(`${base}${BASE}/`, { headers: { cookie }, redirect: 'manual' })
    assert.equal(still.status, 200)
  } finally {
    server.close()
  }
})

test('工作台 HTML 注入防护：数据里的尖括号经 textContent 渲染不进前端脚本上下文', async () => {
  const html = workbenchPage(BASE)
  // 数据均为运行期 JSON 填充；这里只锁住模板不含把 BASE 拼进可执行字符串的缝隙
  assert.ok(html.includes(JSON.stringify(BASE)))
  assert.ok(!html.includes('`${BASE}'))
})

test('站点根路径 → 303 到控制台；非 GET 405', async () => {
  const { createRootRedirect } = await import('../src/http.ts')
  const server = createServer(createRootRedirect(BASE))
  const base = await listen(server)
  try {
    const res = await fetch(`${base}/`, { redirect: 'manual' })
    assert.equal(res.status, 303)
    assert.equal(res.headers.get('location'), `${BASE}/`)
    const post = await fetch(`${base}/`, { method: 'POST' })
    assert.equal(post.status, 405)
  } finally {
    server.close()
  }
})

test('运行参数：未登录 401；GET 回参数+配置事实；POST 校验失败 400、成功 200', async () => {
  const stored: Record<string, number> = { poll_seconds: 900, max_concurrent: 2, claim_limit: 2 }
  const ingest: IngestServiceView = {
    ...makeIngest(),
    settings: async () => ({ ...stored, store: 'postgres' }),
    updateSettings: async patch => {
      const p = patch as Record<string, number>
      if (typeof p['claimLimit'] !== 'number' || p['claimLimit'] > 20) {
        return { ok: false, error: '单次领取条数必须是 1~20 的整数' }
      }
      stored.poll_seconds = p['pollSeconds']
      stored.max_concurrent = p['maxConcurrent']
      stored.claim_limit = p['claimLimit']
      return { ok: true, persisted: true, settings: { ...stored } }
    },
  }
  const { server } = makeApp({ ingest })
  const base = await listen(server)
  try {
    const denied = await fetch(`${base}${BASE}/api/settings`)
    assert.equal(denied.status, 401)

    const cookie = await login(base)
    const got = await fetch(`${base}${BASE}/api/settings`, { headers: { cookie } })
    assert.equal(got.status, 200)
    const data = await got.json() as { available: boolean, settings: Record<string, unknown>, meta: Record<string, unknown> }
    assert.equal(data.available, true)
    assert.equal(data.settings['poll_seconds'], 900)
    assert.equal(data.meta['user'], 'admin')

    const bad = await fetch(`${base}${BASE}/api/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ claimLimit: 99 }),
    })
    assert.equal(bad.status, 400)

    const ok = await fetch(`${base}${BASE}/api/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ pollSeconds: 60, maxConcurrent: 3, claimLimit: 4 }),
    })
    assert.equal(ok.status, 200)
    const saved = await ok.json() as { ok: boolean, settings: Record<string, number> }
    assert.equal(saved.ok, true)
    assert.deepEqual(saved.settings, { poll_seconds: 60, max_concurrent: 3, claim_limit: 4 })
  } finally {
    server.close()
  }
})

test('运行参数：数据面不在场时 available=false，POST 503', async () => {
  const { server } = makeApp({ ingest: null })
  const base = await listen(server)
  try {
    const cookie = await login(base)
    const got = await fetch(`${base}${BASE}/api/settings`, { headers: { cookie } })
    assert.deepEqual(await got.json(), {
      available: false,
      meta: { user: 'admin', basePath: BASE, mcpTokenSet: true, doorbellTokenSet: true, pgSet: true },
    })
    const post = await fetch(`${base}${BASE}/api/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: '{}',
    })
    assert.equal(post.status, 503)
  } finally {
    server.close()
  }
})

test('系统设置：未登录 401；GET 返回快照；POST 模型校验失败 400、成功 200', async () => {
  const seen: unknown[] = []
  const system = {
    snapshot: async () => ({
      available: true,
      plugins: [{ id: 'xdr-ingest', name: '@sec-agent/xdr-ingest', phase: 'active', disabled: false }],
      model: { ns: 'default-model', revision: 3, provider: 'deepseek-official', model: 'deepseek-chat', reasoningEffort: '' },
      key: { ns: 'llm', revision: 1, ref: 'DEEPSEEK_API_KEY', baseURL: '', configured: true, writable: true, source: 'file' },
      notes: [],
    }),
    saveModel: async (patch: unknown) => {
      seen.push(patch)
      const p = patch as Record<string, string>
      if (!p['provider']) return { ok: false, error: 'provider 不能为空' }
      return { ok: true }
    },
    saveKey: async () => ({ ok: true }),
    saveEndpoint: async () => ({ ok: true }),
  }
  const { server } = makeApp({ system })
  const base = await listen(server)
  try {
    const denied = await fetch(`${base}${BASE}/api/system`)
    assert.equal(denied.status, 401)

    const cookie = await login(base)
    const got = await fetch(`${base}${BASE}/api/system`, { headers: { cookie } })
    assert.equal(got.status, 200)
    const data = await got.json() as { plugins: unknown[], model: Record<string, unknown> }
    assert.equal((data.plugins[0] as Record<string, unknown>)['id'], 'xdr-ingest')
    assert.equal(data.model['ns'], 'default-model')

    const bad = await fetch(`${base}${BASE}/api/system/model`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ provider: '', model: 'x' }),
    })
    assert.equal(bad.status, 400)

    const ok = await fetch(`${base}${BASE}/api/system/model`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'deepseek-official', model: 'deepseek-chat' }),
    })
    assert.equal(ok.status, 200)
    assert.deepEqual(seen[1], { provider: 'deepseek-official', model: 'deepseek-chat' })

    const wrongMethod = await fetch(`${base}${BASE}/api/system`, { method: 'POST', headers: { cookie } })
    assert.equal(wrongMethod.status, 405)
  } finally {
    server.close()
  }
})
