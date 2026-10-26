/**
 * 工作台与登录页（自包含 HTML，无前端构建链）。
 *
 * 为什么是内联 HTML 而不是 React SPA：dsh 客户端有自己的构建链与研发门禁
 * （项目约定本地不装依赖不构建，一切构建在 CI），工作台是运营侧只读面板，
 * vanilla JS + fetch 轮询完全够用，且插件包只经 `tsc` 一种构建。
 * 页面文案是中文（这是项目自己的插件，不走 dsh 的 locale 门禁）。
 */

/** HTML 文本逃逸（包含 JS 侧动态插入到 innerHTML 的场景）。 */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll('\'', '&#39;')
}

/** 登录页。base 用于绝对化表单 action；authError 表示上一次提交凭据错误。 */
export function loginPage(base: string, authError: boolean): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>深瞳 · 分析工作台登录</title>
<style>
  body { font-family: system-ui, sans-serif; display: grid; place-items: center;
         min-height: 100vh; margin: 0; background: #f5f7fb; }
  form { background: #fff; padding: 2.5rem 3rem; border-radius: 12px;
         box-shadow: 0 2px 12px rgba(0,0,0,.08); width: 270px; }
  h1 { font-size: 1.1rem; margin: 0 0 1.2rem; color: #1e293b; text-align: center; }
  label { display: block; font-size: .8rem; color: #64748b; margin: .8rem 0 .25rem; }
  input { width: 100%; box-sizing: border-box; padding: .55rem .7rem;
          border: 1px solid #cbd5e1; border-radius: 6px; font-size: .9rem; }
  button { margin-top: 1.4rem; width: 100%; padding: .6rem; border: none;
           border-radius: 6px; background: #2563eb; color: #fff;
           font-size: .95rem; cursor: pointer; }
  button:hover { background: #1d4ed8; }
  .error { color: #dc2626; font-size: .8rem; margin-top: .8rem; text-align: center; }
  .back { margin-top: 1rem; font-size: .75rem; color: #94a3b8; text-align: center; }
</style>
</head>
<body>
<form method="POST" action="${escapeHtml(base)}/login">
  <h1>深瞳 · 分析工作台</h1>
  <label for="user">账号</label>
  <input id="user" name="user" autocomplete="username" autofocus>
  <label for="password">密码</label>
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">登录</button>
  ${authError ? '<div class="error">账号或密码不正确</div>' : ''}
  <div class="back">默认账号 admin / admin123（部署时可用环境变量修改）</div>
</form>
</body>
</html>`
}

/** 工作台页：运行总览 + 分析记录 + 手动领取。数据全部来自 ${basePath}/api/*。 */
export function workbenchPage(basePath: string): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>深瞳 · 分析工作台</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; background: #f5f7fb; color: #1e293b; }
  header { position: sticky; top: 0; z-index: 2; display: flex; align-items: center;
           gap: .8rem; padding: .7rem 1.2rem; background: #0f172a; color: #f8fafc; }
  header h1 { font-size: 1rem; margin: 0 0; font-weight: 600; }
  header .spacer { flex: 1; }
  header button { padding: .35rem .8rem; border: 1px solid #334155; border-radius: 6px;
                  background: #1e293b; color: #e2e8f0; font-size: .8rem; cursor: pointer; }
  header button:hover { background: #334155; }
  main { max-width: 1180px; margin: 0 auto; padding: 1rem 1.2rem 3rem; }
  h2 { font-size: .95rem; margin: 1.4rem 0 .6rem; color: #475569; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: .6rem; }
  .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: .7rem .9rem; }
  .card .k { font-size: .72rem; color: #94a3b8; }
  .card .v { font-size: 1.05rem; font-weight: 600; margin-top: .15rem; word-break: break-all; }
  .card .v.ok { color: #16a34a; } .card .v.bad { color: #dc2626; } .card .v.off { color: #d97706; }
  .unavailable { background: #fffbeb; border: 1px solid #fde68a; color: #92400e;
                 padding: .7rem 1rem; border-radius: 10px; font-size: .85rem; }
  .toolbar { display: flex; gap: .6rem; align-items: center; margin: .4rem 0 .6rem; }
  .toolbar input { flex: 0 0 300px; padding: .45rem .6rem; border: 1px solid #cbd5e1;
                   border-radius: 6px; font-size: .85rem; }
  .toolbar button { padding: .45rem .9rem; border: 1px solid #cbd5e1; border-radius: 6px;
                    background: #fff; font-size: .85rem; cursor: pointer; }
  .toolbar button:hover { background: #f1f5f9; }
  .toolbar .count { font-size: .8rem; color: #94a3b8; }
  table { width: 100%; border-collapse: collapse; background: #fff;
          border: 1px solid #e2e8f0; border-radius: 10px; font-size: .85rem; }
  th, td { text-align: left; padding: .5rem .7rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  th { font-size: .75rem; color: #64748b; background: #f8fafc; white-space: nowrap; }
  td .mono { font-family: ui-monospace, monospace; font-size: .75rem; color: #475569; }
  tbody tr:hover { background: #f8fafc; cursor: pointer; }
  .sev { font-weight: 600; white-space: nowrap; }
  .sev.high, .sev.critical { color: #dc2626; } .sev.medium { color: #d97706; }
  .pager { display: flex; gap: .5rem; align-items: center; font-size: .8rem; color: #64748b; margin-top: .6rem; }
  .pager button { padding: .35rem .8rem; border: 1px solid #cbd5e1; border-radius: 6px;
                  background: #fff; cursor: pointer; }
  dialog { border: none; border-radius: 12px; max-width: 720px; width: 88%;
           padding: 1.2rem 1.4rem; box-shadow: 0 8px 30px rgba(0,0,0,.18); }
  dialog::backdrop { background: rgba(15,23,42,.45); }
  dialog h3 { margin: 0 0 .6rem; font-size: 1rem; }
  dialog .kv { font-size: .85rem; margin: .3rem 0; }
  dialog .kv .k { color: #94a3b8; margin-right: .5rem; }
  dialog pre { background: #0f172a; color: #e2e8f0; padding: .8rem; border-radius: 8px;
               font-size: .72rem; overflow: auto; max-height: 40vh; white-space: pre-wrap; }
  #toast { position: fixed; bottom: 1.2rem; left: 50%; transform: translateX(-50%);
           background: #0f172a; color: #f8fafc; padding: .5rem 1rem; border-radius: 8px;
           font-size: .85rem; opacity: 0; transition: opacity .2s; pointer-events: none; }
  #toast.show { opacity: .95; }
</style>
</head>
<body>
<header>
  <h1>深瞳 · 分析工作台</h1>
  <span id="state" style="font-size:.75rem;color:#94a3b8;"></span>
  <span class="spacer"></span>
  <button id="wake" title="等同一记门铃：立即触发一次领取，仍受并发与预算约束">立即领取</button>
  <button id="logout">退出</button>
</header>
<main>
  <h2>运行总览</h2>
  <div id="overview"></div>

  <h2>分析记录</h2>
  <div class="toolbar">
    <input id="q" type="search" placeholder="搜索：规则 / 源 IP / 结论…" maxlength="128">
    <button id="reload">搜索 / 刷新</button>
    <span class="count" id="count"></span>
  </div>
  <table>
    <thead>
      <tr><th>规则</th><th>源 IP</th><th>严重度</th><th>结论摘要</th><th>出现</th><th>最近出现</th></tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>
  <div class="pager">
    <button id="prev">‹ 上一页</button>
    <button id="next">下一页 ›</button>
    <span id="page"></span>
  </div>
</main>

<dialog id="detail"><div id="detail-body"></div>
  <button id="close" style="margin-top:1rem;padding:.4rem .9rem;border:1px solid #cbd5e1;border-radius:6px;background:#fff;cursor:pointer;">关闭</button>
</dialog>
<div id="toast"></div>

<script>
(() => {
  const BASE = ${JSON.stringify(basePath)}
  const PAGE = 20
  let offset = 0, total = 0

  const esc = v => { const d = document.createElement('div'); d.textContent = v == null ? '' : String(v); return d.innerHTML }
  const fmt = iso => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d) ? '—' : d.toLocaleString('zh-CN', { hour12: false }) }
  const toast = text => { const t = document.getElementById('toast'); t.textContent = text; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 1800) }

  const json = (url, init) => fetch(url, init).then(r => { if (r.status === 401) { location.href = BASE + '/login'; throw new Error('unauthorized') } return r.json() })

  async function loadOverview() {
    const box = document.getElementById('overview')
    const data = await json(BASE + '/api/overview')
    if (!data.available) {
      box.innerHTML = '<div class="unavailable">xdr-ingest 插件未在场（分析循环未部署）——工作台自身正常，数据面不可用。</div>'
      return
    }
    const s = data.status || {}, c = data.cache || {}
    const loop = s.loop || {}
    const analysisOn = s.analysis === 'enabled'
    const cards = [
      ['分析循环', analysisOn ? '启用' : '停用', analysisOn ? 'ok' : 'off'],
      ['在跑 / 上限', esc(loop.running + ' / ' + s.max_concurrent), ''],
      ['门铃次数', esc(loop.doorbells), ''],
      ['轮询次数', esc(loop.polls), ''],
      ['已领取', esc(loop.claimed), ''],
      ['已启动分析', esc(loop.started), ''],
      ['并发放弃', esc(loop.droppedByConcurrency), ''],
      ['领取失败', esc(loop.failedClaims), ''],
      ['连续错误', esc(loop.consecutiveErrors), Number(loop.consecutiveErrors) > 0 ? 'bad' : 'ok'],
      ['剩余预算', esc(loop.lastBudget == null ? '—' : loop.lastBudget), ''],
      ['热层条数', esc(c.hot), ''],
      ['冷库条数', esc(c.cold), ''],
      ['判定分析', esc(c.analyzed), ''],
      ['命中复用', esc(c.reused), ''],
      ['过期重析', esc(c.reanalyzed), ''],
    ]
    let html = '<div class="cards">' + cards.map(([k, v, cls]) =>
      '<div class="card"><div class="k">' + k + '</div><div class="v ' + cls + '">' + v + '</div></div>').join('') + '</div>'
    if (loop.lastError) html += '<div class="unavailable" style="margin-top:.6rem;">最近领取错误：' + esc(loop.lastError) + '</div>'
    box.innerHTML = html
    document.getElementById('state').textContent = analysisOn ? '分析循环运行中' : '分析循环停用'
  }

  async function loadList() {
    const data = await json(BASE + '/api/analyses?limit=' + PAGE + '&offset=' + offset + '&q=' + encodeURIComponent(document.getElementById('q').value.trim()))
    total = data.total || 0
    const rows = document.getElementById('rows')
    rows.innerHTML = (data.entries || []).map(e => {
      const sev = e.result && e.result.severity ? e.result.severity : ''
      return '<tr data-id="' + esc(e.analysisId) + '">' +
        '<td>' + esc(e.identity && e.identity.rule) + '</td>' +
        '<td class="mono">' + esc(e.identity && e.identity.srcIp) + '</td>' +
        '<td class="sev ' + esc(sev) + '">' + esc(sev) + '</td>' +
        '<td>' + esc(e.result && e.result.summary) + '</td>' +
        '<td>' + esc(e.occurrences) + '</td>' +
        '<td>' + esc(fmt(e.lastSeenAt)) + '</td></tr>'
    }).join('') || '<tr><td colspan="6" style="color:#94a3b8;">暂无分析记录</td></tr>'
    const last = Math.max(0, Math.ceil(total / PAGE) - 1) * PAGE
    offset = Math.min(offset, last)
    document.getElementById('count').textContent = '共 ' + total + ' 条'
    document.getElementById('page').textContent = total === 0 ? '' : ('第 ' + (offset / PAGE + 1) + ' / ' + Math.ceil(total / PAGE) + ' 页')
    document.getElementById('prev').disabled = offset === 0
    document.getElementById('next').disabled = offset + PAGE >= total
  }

  async function openDetail(id) {
    const r = await fetch(BASE + '/api/analyses/' + encodeURIComponent(id))
    if (r.status === 401) { location.href = BASE + '/login'; return }
    if (r.status === 404) { toast('记录不存在'); return }
    const data = await r.json()
    const e = data.entry || {}
    const idn = e.identity || {}, res = e.result || {}
    document.getElementById('detail-body').innerHTML =
      '<h3 style="font-family:ui-monospace,monospace;font-size:.8rem;">' + esc(e.analysisId) + '</h3>' +
      '<div class="kv"><span class="k">规则</span>' + esc(idn.rule) + '</div>' +
      '<div class="kv"><span class="k">源 IP</span>' + esc(idn.srcIp) + '</div>' +
      '<div class="kv"><span class="k">目标</span>' + esc((idn.dstIps || []).join('、')) + '</div>' +
      '<div class="kv"><span class="k">端口</span>' + esc((idn.dstPorts || []).join('、')) + '</div>' +
      '<div class="kv"><span class="k">事件类型</span>' + esc((idn.eventTypes || []).join('、')) + '</div>' +
      '<div class="kv"><span class="k">出现次数</span>' + esc(e.occurrences) + '（首次 ' + esc(fmt(e.firstSeenAt)) + '）</div>' +
      '<div class="kv"><span class="k">分析时间</span>' + esc(fmt(e.analyzedAt)) + '　<span class="k">分析器</span>' + esc(res.analyzer) + '</div>' +
      '<div class="kv"><span class="k">定级</span><span class="sev ' + esc(res.severity) + '">' + esc(res.severity) + '</span>　<span class="k">归组</span>' + esc(res.category) + '</div>' +
      '<div class="kv"><span class="k">结论</span>' + esc(res.summary) + '</div>' +
      '<div class="kv"><span class="k">处置建议</span>' + esc(res.recommendation) + '</div>' +
      '<pre>' + esc(JSON.stringify(e, null, 2)) + '</pre>'
    document.getElementById('detail').showModal()
  }

  document.getElementById('rows').addEventListener('click', ev => {
    const tr = ev.target.closest('tr[data-id]')
    if (tr) void openDetail(tr.dataset.id)
  })
  document.getElementById('reload').addEventListener('click', () => { offset = 0; void loadList() })
  document.getElementById('q').addEventListener('keydown', ev => { if (ev.key === 'Enter') { offset = 0; void loadList() } })
  document.getElementById('prev').addEventListener('click', () => { offset = Math.max(0, offset - PAGE); void loadList() })
  document.getElementById('next').addEventListener('click', () => { offset += PAGE; void loadList() })
  document.getElementById('close').addEventListener('click', () => document.getElementById('detail').close())
  document.getElementById('logout').addEventListener('click', () => { void fetch(BASE + '/logout', { method: 'POST' }).then(() => { location.href = BASE + '/login' }) })
  document.getElementById('wake').addEventListener('click', () => {
    void json(BASE + '/api/wake', { method: 'POST' }).then(d => toast(d.accepted ? '已叫醒领取循环（受并发与预算约束）' : '分析循环未启用，无循环可叫醒'), () => toast('请求失败'))
  })

  function onError(err) { console.warn(err); toast('数据加载失败') }

  async function tick() {
    await loadOverview().catch(onError)
    await loadList().catch(onError)
  }
  void tick()
  setInterval(tick, 30000)
})()
</script>
</body>
</html>`
}
