/**
 * 登录页与控制台（自包含 HTML，无前端构建链）。
 *
 * 为什么是内联 HTML 而不是 React SPA：dsh 客户端有自己的构建链与研发门禁
 * （项目约定本地不装依赖不构建，一切构建在 CI），控制台是运营侧面板，
 * vanilla JS + fetch 轮询完全够用，且插件包只经 `tsc` 一种构建。
 *
 * 产品形态：这不是"对话窗口"，是后台分析智能体的运营控制台——
 * 左侧功能菜单（运行总览 / 分析记录 / 配置），右侧工作区，无聊天输入框。
 * 页面文案中文（本项目自己的插件，不走 dsh 的 locale 门禁）。
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

/** 两个页面共用的设计变量（深瞳深色主题）。 */
const THEME = `
  :root {
    --bg: #070d1a; --panel: #0d1526; --panel-2: #111c33; --line: #1e2a44;
    --text: #e6edf7; --muted: #8b9bb4; --accent: #38bdf8; --accent-2: #0ea5e9;
    --ok: #34d399; --warn: #fbbf24; --bad: #f87171; --radius: 10px;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font: 14px/1.55 system-ui, -apple-system, "Segoe UI", "PingFang SC", sans-serif; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  button { font: inherit; cursor: pointer; }
  input, select { font: inherit; }
`

/** 登录页。base 用于绝对化表单 action；authError 表示上一次提交凭据错误。 */
export function loginPage(base: string, authError: boolean): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>深瞳 · 安全分析智能体</title>
<style>
${THEME}
  body { display: grid; place-items: center; min-height: 100vh;
         background: radial-gradient(1200px 600px at 50% -10%, #123 0%, var(--bg) 60%); }
  form { width: 330px; background: var(--panel); border: 1px solid var(--line);
         border-radius: 14px; padding: 2rem 2rem 1.6rem; box-shadow: 0 18px 60px rgba(0,0,0,.45); }
  .brand { display: flex; align-items: center; gap: .65rem; margin-bottom: .3rem; }
  .logo { width: 34px; height: 34px; display: grid; place-items: center; border-radius: 9px;
          background: linear-gradient(135deg, var(--accent), #2563eb); color: #04101f;
          font-weight: 800; font-size: 1.05rem; }
  h1 { font-size: 1.05rem; margin: 0; }
  .sub { color: var(--muted); font-size: .78rem; margin: 0 0 1.4rem; }
  label { display: block; font-size: .78rem; color: var(--muted); margin: .9rem 0 .3rem; }
  input { width: 100%; padding: .6rem .75rem; border-radius: 8px; background: #0a1322;
          border: 1px solid var(--line); color: var(--text); }
  input:focus { outline: none; border-color: var(--accent); }
  button { margin-top: 1.5rem; width: 100%; padding: .65rem; border: none; border-radius: 8px;
           background: linear-gradient(135deg, var(--accent), var(--accent-2));
           color: #04101f; font-weight: 700; }
  button:hover { filter: brightness(1.08); }
  .error { color: var(--bad); font-size: .8rem; margin-top: .9rem; text-align: center; }
  .hint { margin-top: 1.1rem; font-size: .72rem; color: var(--muted); text-align: center; }
</style>
</head>
<body>
<form method="POST" action="${escapeHtml(base)}/login">
  <div class="brand"><span class="logo">瞳</span><h1>深瞳 · 安全分析智能体</h1></div>
  <p class="sub">后台自助分析控制台</p>
  <label for="user">账号</label>
  <input id="user" name="user" autocomplete="username" autofocus>
  <label for="password">密码</label>
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">进入控制台</button>
  ${authError ? '<div class="error">账号或密码不正确</div>' : ''}
  <div class="hint">默认账号 admin / admin123（部署时用环境变量改）</div>
</form>
</body>
</html>`
}

/** 控制台页：运行总览 + 分析记录 + 配置。数据全部来自 ${basePath}/api/*。 */
export function workbenchPage(basePath: string): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>深瞳 · 安全分析智能体</title>
<style>
${THEME}
  .app { display: grid; grid-template-columns: 216px 1fr; min-height: 100vh; }
  .rail { position: sticky; top: 0; height: 100vh; display: flex; flex-direction: column;
          gap: 1.2rem; padding: 1.1rem .9rem; background: var(--panel);
          border-right: 1px solid var(--line); }
  .brand { display: flex; align-items: center; gap: .6rem; padding: 0 .3rem; }
  .brand .logo { width: 32px; height: 32px; border-radius: 9px; display: grid; place-items: center;
                 background: linear-gradient(135deg, var(--accent), #2563eb); color: #04101f;
                 font-weight: 800; }
  .brand b { font-size: .98rem; display: block; line-height: 1.2; }
  .brand small { color: var(--muted); font-size: .7rem; }
  nav { display: flex; flex-direction: column; gap: .25rem; }
  nav a { display: flex; align-items: center; gap: .5rem; padding: .5rem .6rem; border-radius: 8px;
          color: #cdd8e8; font-size: .9rem; }
  nav a:hover { background: var(--panel-2); text-decoration: none; }
  nav a.active { background: rgba(56,189,248,.12); color: var(--accent); }
  nav a .dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; opacity: .7; }
  .rail-foot { margin-top: auto; display: flex; flex-direction: column; gap: .45rem;
               font-size: .78rem; color: var(--muted); padding: 0 .3rem; }
  .rail-foot a { color: var(--muted); }
  .rail-foot a:hover { color: var(--accent); }
  main { min-width: 0; padding: 1.2rem 1.6rem 3rem; }
  .top { display: flex; align-items: flex-end; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.1rem; }
  .top h1 { margin: 0; font-size: 1.25rem; }
  .top p { margin: .15rem 0 0; color: var(--muted); font-size: .8rem; }
  .actions { margin-left: auto; display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
  .chip { font-size: .75rem; padding: .3rem .6rem; border-radius: 999px;
          border: 1px solid var(--line); color: var(--muted); }
  .chip.ok { color: var(--ok); border-color: rgba(52,211,153,.35); background: rgba(52,211,153,.08); }
  .chip.off { color: var(--warn); border-color: rgba(251,191,36,.35); background: rgba(251,191,36,.08); }
  .actions button { padding: .42rem .8rem; border-radius: 8px; border: 1px solid var(--line);
                    background: var(--panel-2); color: var(--text); font-size: .82rem; }
  .actions button:hover { border-color: var(--accent); }
  .actions button.primary { background: linear-gradient(135deg, var(--accent), var(--accent-2));
                            color: #04101f; border: none; font-weight: 700; }
  .actions button.ghost { background: transparent; color: var(--muted); }
  section[hidden] { display: none; }
  h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .08em;
       color: var(--muted); margin: 1.5rem 0 .6rem; font-weight: 600; }
  h2:first-child { margin-top: 0; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: .6rem; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: .7rem .85rem; }
  .card .k { font-size: .72rem; color: var(--muted); }
  .card .v { font-size: 1.02rem; font-weight: 600; margin-top: .2rem; word-break: break-all; }
  .v.ok { color: var(--ok); } .v.bad { color: var(--bad); } .v.off { color: var(--warn); }
  .notice { border-radius: var(--radius); padding: .7rem 1rem; font-size: .82rem; margin-top: .7rem;
            background: rgba(251,191,36,.08); border: 1px solid rgba(251,191,36,.3); color: #fcd34d; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 1rem 1.1rem; }
  .toolbar { display: flex; gap: .6rem; align-items: center; margin-bottom: .7rem; flex-wrap: wrap; }
  .toolbar input[type=search] { flex: 0 0 300px; max-width: 100%; padding: .45rem .65rem;
                                border-radius: 8px; border: 1px solid var(--line);
                                background: #0a1322; color: var(--text); }
  .toolbar button, .btn { padding: .45rem .85rem; border-radius: 8px; border: 1px solid var(--line);
                          background: var(--panel-2); color: var(--text); font-size: .82rem; }
  .toolbar button:hover, .btn:hover { border-color: var(--accent); }
  .count { font-size: .78rem; color: var(--muted); }
  table { width: 100%; border-collapse: collapse; background: var(--panel);
          border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden; font-size: .84rem; }
  th, td { text-align: left; padding: .55rem .7rem; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { font-size: .72rem; color: var(--muted); background: var(--panel-2); white-space: nowrap; font-weight: 600; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: var(--panel-2); cursor: pointer; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .76rem; color: #a9b8cd; }
  .sev { font-weight: 600; white-space: nowrap; }
  .sev.high, .sev.critical { color: var(--bad); } .sev.medium { color: var(--warn); }
  .empty { color: var(--muted); text-align: center; padding: 1.2rem; }
  .pager { display: flex; gap: .5rem; align-items: center; font-size: .78rem; color: var(--muted); margin-top: .6rem; }
  .pager button { padding: .35rem .75rem; border-radius: 8px; border: 1px solid var(--line);
                  background: var(--panel-2); color: var(--text); }
  .pager button:disabled { opacity: .45; cursor: default; }
  dialog { border: 1px solid var(--line); border-radius: 14px; max-width: 760px; width: 90%;
           padding: 1.2rem 1.4rem; background: var(--panel); color: var(--text);
           box-shadow: 0 20px 70px rgba(0,0,0,.55); }
  dialog::backdrop { background: rgba(3,8,18,.72); }
  dialog h3 { margin: 0 0 .8rem; font-size: .9rem; color: var(--muted); }
  dialog .kv { font-size: .84rem; margin: .3rem 0; }
  dialog .kv .k { color: var(--muted); margin-right: .5rem; }
  dialog pre { background: #050b16; border: 1px solid var(--line); color: #cfe0f5; padding: .8rem;
               border-radius: 8px; font-size: .7rem; overflow: auto; max-height: 40vh; white-space: pre-wrap; }
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: .8rem 1.2rem; }
  .field label { display: block; font-size: .76rem; color: var(--muted); margin-bottom: .3rem; }
  .field input { width: 100%; padding: .5rem .65rem; border-radius: 8px; border: 1px solid var(--line);
                 background: #0a1322; color: var(--text); }
  .field input:focus { outline: none; border-color: var(--accent); }
  .field small { display: block; color: var(--muted); font-size: .7rem; margin-top: .25rem; }
  .form-actions { display: flex; gap: .6rem; align-items: center; margin-top: 1rem; }
  .form-actions .msg { font-size: .78rem; color: var(--muted); }
  .form-actions .msg.bad { color: var(--bad); } .form-actions .msg.ok { color: var(--ok); }
  .kv-list { display: grid; grid-template-columns: minmax(130px, 190px) 1fr; gap: .45rem .9rem; font-size: .82rem; }
  .kv-list dt { color: var(--muted); }
  .kv-list dd { margin: 0; word-break: break-all; }
  .tag { font-size: .7rem; padding: .1rem .45rem; border-radius: 999px; border: 1px solid var(--line); color: var(--muted); }
  .tag.ok { color: var(--ok); border-color: rgba(52,211,153,.4); }
  .tag.bad { color: var(--bad); border-color: rgba(248,113,113,.4); }
  #toast { position: fixed; bottom: 1.2rem; left: 50%; transform: translateX(-50%);
           background: var(--panel-2); border: 1px solid var(--line); color: var(--text);
           padding: .55rem 1rem; border-radius: 9px; font-size: .83rem; opacity: 0;
           transition: opacity .2s; pointer-events: none; z-index: 9; }
  #toast.show { opacity: 1; }
  @media (max-width: 820px) {
    .app { grid-template-columns: 1fr; }
    .rail { position: static; height: auto; flex-direction: row; align-items: center;
            flex-wrap: wrap; gap: .6rem; border-right: none; border-bottom: 1px solid var(--line); }
    nav { flex-direction: row; }
    .rail-foot { margin: 0 0 0 auto; flex-direction: row; }
    main { padding: 1rem; }
  }
</style>
</head>
<body>
<div class="app">
  <aside class="rail">
    <div class="brand"><span class="logo">瞳</span><div><b>深瞳</b><small>安全分析智能体</small></div></div>
    <nav>
      <a href="#/overview" data-view="overview"><span class="dot"></span>运行总览</a>
      <a href="#/records" data-view="records"><span class="dot"></span>分析记录</a>
      <a href="#/settings" data-view="settings"><span class="dot"></span>配置</a>
      <a href="#/system" data-view="system"><span class="dot"></span>系统</a>
    </nav>
    <div class="rail-foot">
      <a id="ndr-link" href="#" target="_blank" rel="noreferrer" hidden>NDR 控制台 ↗</a>
      <a id="native-link" href="/index.html" target="_blank" rel="noreferrer">原始会话界面 ↗</a>
      <span>v0.2 · 后台自助分析</span>
    </div>
  </aside>
  <main>
    <div class="top">
      <div>
        <h1 id="view-title">运行总览</h1>
        <p id="view-sub">门铃 → 领工单 → 取证 → 交结论</p>
      </div>
      <div class="actions">
        <span id="state" class="chip">连接中…</span>
        <button id="wake" class="primary" title="等同一记门铃：立即触发一次领取，仍受并发与预算约束">立即领取</button>
        <button id="refresh">刷新</button>
        <button id="logout" class="ghost">退出<span id="who"></span></button>
      </div>
    </div>

    <section id="view-overview">
      <div id="overview"></div>
      <h2>最近结论</h2>
      <table>
        <thead><tr><th>对象</th><th>判定</th><th>结论摘要</th><th>时间</th></tr></thead>
        <tbody id="recent"></tbody>
      </table>
    </section>

    <section id="view-records" hidden>
      <div class="toolbar">
        <input id="q" type="search" placeholder="搜索：对象 / 判定 / 结论摘要…" maxlength="128">
        <button id="search">搜索 / 刷新</button>
        <span class="count" id="count"></span>
      </div>
      <table>
        <thead>
          <tr><th>对象</th><th>类型</th><th>判定</th><th>置信度</th><th>结论摘要</th><th>工具/耗时</th><th>时间</th></tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
      <div class="pager">
        <button id="prev">‹ 上一页</button>
        <button id="next">下一页 ›</button>
        <span id="page"></span>
      </div>
    </section>

    <section id="view-settings" hidden>
      <h2>运行参数</h2>
      <div class="panel">
        <div class="form-grid">
          <div class="field">
            <label for="pollSeconds">定时轮询间隔（秒）</label>
            <input id="pollSeconds" type="number" min="30" max="86400" step="1">
            <small>门铃会丢，这是"自己去看一眼"的兜底节奏：30 ~ 86400</small>
          </div>
          <div class="field">
            <label for="maxConcurrent">本机并发上限</label>
            <input id="maxConcurrent" type="number" min="1" max="16" step="1">
            <small>同时跑几个分析会话：1 ~ 16（NDR 侧每令牌并发另行限制）</small>
          </div>
          <div class="field">
            <label for="claimLimit">单次领取条数</label>
            <input id="claimLimit" type="number" min="1" max="20" step="1">
            <small>一次 claim_tasks 最多领几条：1 ~ 20</small>
          </div>
        </div>
        <div class="form-actions">
          <button id="save-settings" class="btn" style="border-color:var(--accent);color:var(--accent)">保存并生效</button>
          <button id="reload-settings" class="btn">重新读取</button>
          <span id="settings-msg" class="msg"></span>
        </div>
      </div>

      <h2>连接与凭据</h2>
      <div class="panel">
        <dl class="kv-list" id="meta"></dl>
      </div>
      <div class="notice">
        登录密码与 NDR MCP 令牌由部署环境变量提供（DSH_WEB_AUTH_PASSWORD / XDR_NDR_MCP_TOKEN），
        修改后需重启容器；本页只展示"是否已配置"，不回显密钥。
      </div>
    </section>

    <section id="view-system" hidden>
      <div id="system-notes"></div>
      <h2>模型与密钥</h2>
      <div class="panel">
        <div class="form-grid">
          <div class="field">
            <label for="sys-provider">Provider</label>
            <input id="sys-provider" placeholder="deepseek-official">
            <small>当前部署注册的模型路由</small>
          </div>
          <div class="field">
            <label for="sys-model">模型</label>
            <input id="sys-model" placeholder="deepseek-chat">
            <small>分析会话使用的默认模型</small>
          </div>
          <div class="field">
            <label for="sys-effort">推理强度</label>
            <select id="sys-effort" style="width:100%;padding:.5rem .65rem;border-radius:8px;border:1px solid var(--line);background:#0a1322;color:var(--text)">
              <option value="">跟随默认</option><option value="off">off</option>
              <option value="low">low</option><option value="high">high</option><option value="max">max</option>
            </select>
          </div>
        </div>
        <div class="form-actions">
          <button id="save-model" class="btn" style="border-color:var(--accent);color:var(--accent)">保存模型</button>
          <span id="model-msg" class="msg"></span>
        </div>
        <div class="form-grid" style="margin-top:1rem">
          <div class="field">
            <label for="sys-baseurl">接口地址（可选）</label>
            <input id="sys-baseurl" placeholder="https://api.deepseek.com/anthropic">
            <small>留空 = 用 provider 默认/环境变量；保存空值会清掉覆盖</small>
          </div>
          <div class="field">
            <label for="sys-key">API Key</label>
            <input id="sys-key" type="password" autocomplete="new-password" placeholder="输入新的 Key（不回显已存的）">
            <small>存放在 dsh 凭证库，不写进配置文件；分析会话下次请求即生效</small>
          </div>
        </div>
        <div class="form-actions">
          <button id="save-endpoint" class="btn">保存接口地址</button>
          <button id="save-key" class="btn">保存密钥</button>
          <button id="clear-key" class="btn">清除密钥</button>
          <span id="key-msg" class="msg"></span>
        </div>
        <div class="kv-list" style="margin-top:1rem"><dt>密钥状态</dt><dd id="key-state">—</dd></div>
      </div>

      <h2>模型接入（自定义服务商）</h2>
      <div class="panel">
        <table>
          <thead><tr><th>标识</th><th>显示名</th><th>协议</th><th>Base URL</th><th>模型</th><th>密钥</th></tr></thead>
          <tbody id="provider-rows"></tbody>
        </table>
        <div class="form-grid" style="margin-top:1rem">
          <div class="field">
            <label for="p-preset">服务商预设</label>
            <select id="p-preset" style="width:100%;padding:.5rem .65rem;border-radius:8px;border:1px solid var(--line);background:#0a1322;color:var(--text)">
              <option value="">— 选择服务商 —</option>
            </select>
            <small>预设负责填好协议与地址；网关地址变了可手动改</small>
          </div>
          <div class="field">
            <label for="p-route">服务商标识（route）</label>
            <input id="p-route" placeholder="kimi">
            <small>小写字母开头，可含数字与 -；同一标识再次保存即覆盖</small>
          </div>
          <div class="field">
            <label for="p-name">显示名</label>
            <input id="p-name" placeholder="Kimi">
          </div>
          <div class="field">
            <label for="p-api">协议</label>
            <select id="p-api" style="width:100%;padding:.5rem .65rem;border-radius:8px;border:1px solid var(--line);background:#0a1322;color:var(--text)">
              <option value="openai-completions">openai-completions（OpenAI 兼容）</option>
              <option value="anthropic-messages">anthropic-messages（Anthropic 兼容）</option>
            </select>
          </div>
          <div class="field">
            <label for="p-baseurl">Base URL</label>
            <input id="p-baseurl" placeholder="https://api.moonshot.cn/v1">
            <small>填到版本段（/v1 或 /api/paas/v4 等），不要带 /chat/completions</small>
          </div>
          <div class="field">
            <label for="p-model">模型</label>
            <div style="display:flex;gap:.4rem">
              <select id="p-model" style="flex:1;width:auto;padding:.5rem .55rem;border-radius:8px;border:1px solid var(--line);background:#0a1322;color:var(--text)"></select>
              <button id="refresh-models" class="btn" title="从服务商在线拉取最新模型列表">刷新</button>
            </div>
            <small>预设带一份机型清单作初值，点「刷新」取最新的</small>
          </div>
          <div class="field">
            <label for="p-ctx">上下文窗口（可选）</label>
            <input id="p-ctx" type="number" min="1024" step="1" placeholder="131072">
            <small>留空用默认 262144</small>
          </div>
          <div class="field">
            <label for="p-key">API Key</label>
            <input id="p-key" type="password" autocomplete="new-password" placeholder="填了才会写入凭证库">
            <small>留空 = 保留已有密钥，只改地址/模型</small>
          </div>
        </div>
        <div class="form-actions">
          <label class="chip" style="display:inline-flex;gap:.35rem;align-items:center">
            <input id="p-default" type="checkbox" checked> 设为默认模型
          </label>
          <button id="save-provider" class="btn" style="border-color:var(--accent);color:var(--accent)">保存服务商</button>
          <span id="provider-msg" class="msg"></span>
        </div>
        <div class="notice" style="margin-top:.8rem">
          支持任意 OpenAI / Anthropic 兼容网关（预设之外的选「自定义网关」手填）；模型清单可点「刷新」从服务商在线拉取。
        </div>
      </div>

      <h2>插件</h2>
      <div class="panel">
        <table>
          <thead><tr><th>条目 ID</th><th>包名</th><th>状态</th><th>启用</th></tr></thead>
          <tbody id="plugins"></tbody>
        </table>
        <div class="notice" style="margin-top:.8rem">
          插件在镜像构建时烤进 profile，容器启动自动刷新（镜像指纹变了就覆盖卷里的旧副本），
          不需要手工启用。安装/升级/启停走部署层，本页只读。
        </div>
      </div>

      <h2>更多原生设置</h2>
      <div class="panel">
        Agent 循环、Shell、Web Search、会话日志等其余设置仍在 dsh 原始界面：
        <a href="/index.html" target="_blank" rel="noreferrer">打开原生设置 ↗</a>
      </div>
    </section>
  </main>
</div>

<dialog id="detail"><div id="detail-body"></div>
  <div style="margin-top:1rem;display:flex;gap:.6rem;">
    <button id="close" class="btn">关闭</button>
  </div>
</dialog>
<div id="toast"></div>

<script>
(() => {
  const BASE = ${JSON.stringify(basePath)}
  const PAGE = 20
  const VIEWS = {
    overview: { title: '运行总览', sub: '门铃 → 领工单 → 取证 → 交结论' },
    records: { title: '分析记录', sub: '智能体交回的判定，可搜索与翻页' },
    settings: { title: '配置', sub: '运行参数、连接状态与入口' },
    system: { title: '系统', sub: '模型与密钥、插件清单、原生设置入口' },
  }
  let offset = 0, total = 0, settingsLoaded = false

  const esc = v => { const d = document.createElement('div'); d.textContent = v == null ? '' : String(v); return d.innerHTML }
  const fmt = iso => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d) ? '—' : d.toLocaleString('zh-CN', { hour12: false }) }
  const toast = text => { const t = document.getElementById('toast'); t.textContent = text; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2000) }
  const json = (url, init) => fetch(url, init).then(r => { if (r.status === 401) { location.href = BASE + '/login'; throw new Error('unauthorized') } return r.json() })

  function viewOf(hash) {
    const key = String(hash || '').replace(/^#\\/?/, '')
    return VIEWS[key] ? key : 'overview'
  }

  function route() {
    const view = viewOf(location.hash)
    for (const name of Object.keys(VIEWS)) {
      document.getElementById('view-' + name).hidden = name !== view
      const link = document.querySelector('nav a[data-view="' + name + '"]')
      if (link) link.classList.toggle('active', name === view)
    }
    document.getElementById('view-title').textContent = VIEWS[view].title
    document.getElementById('view-sub').textContent = VIEWS[view].sub
    if (view === 'records') void loadList().catch(onError)
    if (view === 'settings' && !settingsLoaded) void loadSettings().catch(onError)
    if (view === 'system') void loadSystem().catch(onError)
  }

  async function loadOverview() {
    const box = document.getElementById('overview')
    const data = await json(BASE + '/api/overview')
    if (!data.available) {
      box.innerHTML = '<div class="notice">xdr-ingest 插件未在场（分析循环未部署）——控制台自身正常，数据面不可用。</div>'
      document.getElementById('state').textContent = '数据面不可用'
      document.getElementById('state').className = 'chip off'
      return
    }
    const s = data.status || {}, c = data.cache || {}, loop = s.loop || {}, cc = data.conclusions || {}
    const analysisOn = s.analysis === 'enabled'
    const groups = [
      ['运行状态', [
        ['分析循环', analysisOn ? '启用' : '停用', analysisOn ? 'ok' : 'off'],
        ['在跑 / 并发上限', esc(String(loop.running ?? 0) + ' / ' + (s.max_concurrent ?? '—')), ''],
        ['门铃次数', esc(loop.doorbells ?? 0), ''],
        ['轮询次数', esc(loop.polls ?? 0), ''],
        ['已领取', esc(loop.claimed ?? 0), ''],
        ['已启动分析', esc(loop.started ?? 0), ''],
        ['并发放弃', esc(loop.droppedByConcurrency ?? 0), ''],
        ['领取失败', esc(loop.failedClaims ?? 0), ''],
        ['连续错误', esc(loop.consecutiveErrors ?? 0), Number(loop.consecutiveErrors) > 0 ? 'bad' : 'ok'],
      ]],
      ['结论', [
        ['结论总数', esc(cc.total ?? '—'), ''],
        ['结论数据源', esc(s.conclusion_source || '—'), cc.available === false ? 'bad' : 'ok'],
        ['同类结论复用', esc((s.task_reuse || {}).reused ?? 0), ''],
        ['已存结论（复用库）', esc((s.task_reuse || {}).stored ?? 0), ''],
      ]],
    ]
    let html = ''
    for (const [title, cards] of groups) {
      html += '<h2>' + esc(title) + '</h2><div class="cards">' + cards.map(([k, v, cls]) =>
        '<div class="card"><div class="k">' + esc(k) + '</div><div class="v ' + cls + '">' + v + '</div></div>').join('') + '</div>'
    }
    if (loop.lastError) html += '<div class="notice">最近领取错误：' + esc(loop.lastError) + '</div>'
    box.innerHTML = html
    const chip = document.getElementById('state')
    chip.textContent = analysisOn ? '分析循环运行中' : '分析循环停用'
    chip.className = 'chip ' + (analysisOn ? 'ok' : 'off')
  }

  /** 结论行：对象 / 类型 / 判定 / 置信度 / 摘要 / 工具·耗时 / 时间。 */
  function rowHtml(e, full) {
    const verdict = e.verdict || ''
    return '<tr data-id="' + esc(e.id) + '">' +
      '<td class="mono">' + esc(e.subject) + '</td>' +
      '<td>' + esc(e.subjectKind || e.kind) + '</td>' +
      '<td class="sev ' + esc(verdict) + '">' + esc(verdict) + '</td>' +
      (full ? '<td>' + esc(Math.round(Number(e.confidence || 0) * 100) + '%') + '</td>' : '') +
      '<td>' + esc(e.summary) + '</td>' +
      (full
        ? '<td>' + (e.reused
          ? '<span class="tag" title="同类现象复用：没有起分析会话（0 token）">复用</span>'
          : esc(String(e.toolsUsed ?? 0) + ' 次 / ' + Math.round(Number(e.durationMs || 0) / 1000) + 's')) + '</td>'
        : '') +
      '<td>' + esc(fmt(e.createdAt)) + '</td></tr>'
  }

  async function loadRecent() {
    const data = await json(BASE + '/api/conclusions?limit=5&offset=0&q=')
    const rows = document.getElementById('recent')
    rows.innerHTML = (data.entries || []).map(e => rowHtml(e, false)).join('') ||
      '<tr><td colspan="4" class="empty">暂无结论</td></tr>'
  }

  async function loadList() {
    const q = document.getElementById('q').value.trim()
    const data = await json(BASE + '/api/conclusions?limit=' + PAGE + '&offset=' + offset + '&q=' + encodeURIComponent(q))
    total = data.total || 0
    document.getElementById('rows').innerHTML = (data.entries || []).map(e => rowHtml(e, true)).join('') ||
      '<tr><td colspan="7" class="empty">暂无结论</td></tr>'
    const last = Math.max(0, Math.ceil(total / PAGE) - 1) * PAGE
    offset = Math.min(offset, last)
    document.getElementById('count').textContent = '共 ' + total + ' 条'
    document.getElementById('page').textContent = total === 0 ? '' : ('第 ' + (offset / PAGE + 1) + ' / ' + Math.ceil(total / PAGE) + ' 页')
    document.getElementById('prev').disabled = offset === 0
    document.getElementById('next').disabled = offset + PAGE >= total
  }

  async function openDetail(id) {
    const r = await fetch(BASE + '/api/conclusions/' + encodeURIComponent(id))
    if (r.status === 401) { location.href = BASE + '/login'; return }
    if (r.status === 404) { toast('记录不存在'); return }
    const data = await r.json()
    const e = data.entry || {}
    const verdict = e.verdict || ''
    document.getElementById('detail-body').innerHTML =
      '<h3 class="mono">' + esc(e.subject) + '</h3>' +
      '<div class="kv"><span class="k">判定</span><span class="sev ' + esc(verdict) + '">' + esc(verdict) + '</span>'
      + '　<span class="k">置信度</span>' + esc(Math.round(Number(e.confidence || 0) * 100) + '%') + '</div>' +
      '<div class="kv"><span class="k">类型</span>' + esc(e.kind) + ' / ' + esc(e.subjectKind) + '</div>' +
      '<div class="kv"><span class="k">任务</span>' + esc(e.taskId) + '</div>' +
      '<div class="kv"><span class="k">终态原因</span>' + esc(e.terminalReason || '—') + '</div>' +
      '<div class="kv"><span class="k">成本</span>' + (e.reused
        ? '<span class="tag">复用（未起会话，0 token）</span> '
          + '原任务 <span class="mono">' + esc(e.reusedFrom || '—') + '</span>'
        : esc(String(e.toolsUsed ?? 0) + ' 次工具 / ' + Math.round(Number(e.durationMs || 0) / 1000) + ' 秒')) + '</div>' +
      '<div class="kv"><span class="k">时间</span>' + esc(fmt(e.createdAt)) + '</div>' +
      '<div class="kv"><span class="k">结论</span>' + esc(e.summary) + '</div>' +
      '<pre>' + esc(JSON.stringify(e.findings ?? {}, null, 2)) + '</pre>'
    document.getElementById('detail').showModal()
  }

  function tag(ok) { return '<span class="tag ' + (ok ? 'ok' : 'bad') + '">' + (ok ? '已配置' : '未配置') + '</span>' }

  async function loadSettings() {
    const data = await json(BASE + '/api/settings')
    const s = data.settings || {}, m = data.meta || {}
    if (data.available && s.poll_seconds != null) {
      document.getElementById('pollSeconds').value = s.poll_seconds
      document.getElementById('maxConcurrent').value = s.max_concurrent
      document.getElementById('claimLimit').value = s.claim_limit
    }
    document.getElementById('save-settings').disabled = !data.available
    document.getElementById('settings-msg').textContent = data.available ? '' : '数据面不可用，运行参数暂不可改'
    document.getElementById('settings-msg').className = 'msg' + (data.available ? '' : ' bad')
    const ndr = document.getElementById('ndr-link')
    if (m.ndrConsoleUrl) { ndr.href = m.ndrConsoleUrl; ndr.hidden = false }
    if (m.user) document.getElementById('who').textContent = ' · ' + m.user
    const rows = [
      ['服务', esc(m.service || '深瞳 · 安全分析智能体')],
      ['NDR MCP', '<span class="mono">' + esc(m.mcpUrl || '—') + '</span> ' + tag(m.mcpTokenSet)],
      ['门铃令牌', tag(m.doorbellTokenSet) + ' <span class="mono">' + esc(m.doorbellPath || '') + '</span>'],
      ['冷库', esc(s.store || m.store || '—') + ' ' + tag(m.pgSet)],
      ['登录账号', esc(m.user || '—') + ' <span class="tag">' + esc(m.passwordSource || '') + '</span>'],
      ['会话时长', esc(m.sessionHours != null ? m.sessionHours + ' 小时' : '—')],
      ['控制台路径', '<span class="mono">' + esc(m.basePath || BASE) + '</span>'],
      ['原始会话界面', '<a href="/index.html" target="_blank" rel="noreferrer">/index.html</a>'],
    ]
    document.getElementById('meta').innerHTML = rows.map(([k, v]) => '<dt>' + k + '</dt><dd>' + v + '</dd>').join('')
    settingsLoaded = true
  }

  async function saveSettings() {
    const msg = document.getElementById('settings-msg')
    const body = {
      pollSeconds: Number(document.getElementById('pollSeconds').value),
      maxConcurrent: Number(document.getElementById('maxConcurrent').value),
      claimLimit: Number(document.getElementById('claimLimit').value),
    }
    msg.textContent = '保存中…'; msg.className = 'msg'
    const r = await fetch(BASE + '/api/settings', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    })
    if (r.status === 401) { location.href = BASE + '/login'; return }
    const data = await r.json().catch(() => ({}))
    if (!r.ok || data.ok === false) {
      msg.textContent = data.error || '保存失败'; msg.className = 'msg bad'; return
    }
    msg.textContent = data.persisted === false ? '已生效（持久化失败，重启会回退）' : '已保存并生效'
    msg.className = 'msg ' + (data.persisted === false ? 'bad' : 'ok')
    if (data.settings) {
      document.getElementById('pollSeconds').value = data.settings.poll_seconds
      document.getElementById('maxConcurrent').value = data.settings.max_concurrent
      document.getElementById('claimLimit').value = data.settings.claim_limit
    }
    toast('运行参数已更新')
    void loadOverview().catch(onError)
  }

  // ---- 内置服务商预设：负责一次点选填好 route/名称/协议/地址与模型初值 ----
  // 清单是初值性质：点「刷新」会从服务商在线拉取最新模型列表。
  const PRESETS = {
    'kimi':            { name: 'Kimi（月之暗面）',      api: 'openai-completions',   baseURL: 'https://api.moonshot.cn/v1',            models: ['kimi-k2', 'moonshot-v1-32k', 'moonshot-v1-128k'] },
    'glm':             { name: 'GLM（智谱）',           api: 'openai-completions',   baseURL: 'https://open.bigmodel.cn/api/paas/v4',  models: ['glm-4.5', 'glm-4.5-air', 'glm-4-flash'] },
    'minimax':         { name: 'MiniMax',              api: 'openai-completions',   baseURL: 'https://api.minimax.chat/v1',           models: ['MiniMax-M1', 'abab6.5s-chat'] },
    'deepseek-openai': { name: 'DeepSeek（OpenAI 兼容）', api: 'openai-completions', baseURL: 'https://api.deepseek.com/v1',           models: ['deepseek-chat', 'deepseek-reasoner'] },
    'anthropic':       { name: 'Anthropic',            api: 'anthropic-messages',   baseURL: 'https://api.anthropic.com',             models: ['claude-sonnet-4-5'] },
    'custom':          { name: '自定义网关',            api: 'openai-completions',   baseURL: '',                                      models: [] },
  }
  const presetEl = document.getElementById('p-preset')
  for (const [route, preset] of Object.entries(PRESETS)) {
    const opt = document.createElement('option')
    opt.value = route
    if (route !== 'custom') opt.textContent = preset.name + '（' + route + '）'
    else opt.textContent = '自定义网关'
    presetEl.appendChild(opt)
  }
  const modelOptions = (models, selected) => {
    const el = document.getElementById('p-model')
    const ids = Array.from(new Set(models || []))
    el.innerHTML = ids.length ? '' : '<option value="">— 暂无清单，点「刷新」拉取 —</option>'
    for (const id of ids) {
      const opt = document.createElement('option')
      opt.value = id; opt.textContent = id
      el.appendChild(opt)
    }
    if (selected && ids.includes(selected)) el.value = selected
    else if (ids.length) { el.value = ids.includes(document.getElementById('p-model').value) ? document.getElementById('p-model').value : ids[0] }
  }

  presetEl.addEventListener('change', () => {
    const preset = PRESETS[presetEl.value]
    if (!preset) return
    if (presetEl.value !== 'custom') {
      document.getElementById('p-route').value = presetEl.value
      document.getElementById('p-name').value = preset.name
      document.getElementById('p-baseurl').value = preset.baseURL
    }
    document.getElementById('p-api').value = preset.api
    modelOptions(preset.models)
  })

  document.getElementById('refresh-models').addEventListener('click', async () => {
    const btn = document.getElementById('refresh-models')
    msg('provider-msg', '拉取模型清单中…')
    btn.disabled = true
    try {
      const body = {
        route: document.getElementById('p-route').value.trim(),
        api: document.getElementById('p-api').value,
        baseURL: document.getElementById('p-baseurl').value.trim(),
        key: document.getElementById('p-key').value,
      }
      const r = await fetch(BASE + '/api/system/models', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
      })
      if (r.status === 401) { location.href = BASE + '/login'; return }
      const data = await r.json().catch(() => ({}))
      if (!r.ok || data.ok === false) { msg('provider-msg', data.error || '拉取失败', 'bad'); return }
      modelOptions(data.models)
      msg('provider-msg', '已拉取 ' + data.models.length + ' 个模型，下拉框已更新', 'ok')
    } catch (err) { msg('provider-msg', '拉取失败：网络错误', 'bad') }
    finally { btn.disabled = false }
  })

  // 服务商清单行点击 → 载入到下方表单（模型下拉优先用已保存清单）
  document.getElementById('provider-rows').addEventListener('click', event => {
    const tr = event.target.closest('tr[data-provider]')
    if (!tr) return
    let p
    try { p = JSON.parse(tr.dataset.provider) } catch { return }
    document.getElementById('p-route').value = p.route
    document.getElementById('p-name').value = p.displayName
    if (p.api) document.getElementById('p-api').value = p.api
    document.getElementById('p-baseurl').value = p.baseURL
    const staticModels = PRESETS[p.route] ? PRESETS[p.route].models : []
    modelOptions((p.models && p.models.length) ? p.models : staticModels, (p.models || [])[0])
  })
  modelOptions([])

  document.querySelectorAll('nav a[data-view]').forEach(link => {
    link.addEventListener('click', () => { location.hash = '#/' + link.dataset.view })
  })
  window.addEventListener('hashchange', route)

  document.getElementById('rows').addEventListener('click', ev => {
    const tr = ev.target.closest('tr[data-id]')
    if (tr) void openDetail(tr.dataset.id)
  })
  document.getElementById('recent').addEventListener('click', ev => {
    const tr = ev.target.closest('tr[data-id]')
    if (tr) void openDetail(tr.dataset.id)
  })
  document.getElementById('search').addEventListener('click', () => { offset = 0; void loadList().catch(onError) })
  document.getElementById('q').addEventListener('keydown', ev => { if (ev.key === 'Enter') { offset = 0; void loadList().catch(onError) } })
  document.getElementById('prev').addEventListener('click', () => { offset = Math.max(0, offset - PAGE); void loadList().catch(onError) })
  document.getElementById('next').addEventListener('click', () => { offset += PAGE; void loadList().catch(onError) })
  document.getElementById('close').addEventListener('click', () => document.getElementById('detail').close())
  document.getElementById('logout').addEventListener('click', () => {
    void fetch(BASE + '/logout', { method: 'POST' }).then(() => { location.href = BASE + '/login' })
  })
  document.getElementById('wake').addEventListener('click', () => {
    void json(BASE + '/api/wake', { method: 'POST' }).then(
      d => toast(d.accepted ? '已叫醒领取循环（受并发与预算约束）' : '分析循环未启用，无循环可叫醒'),
      () => toast('请求失败'),
    )
  })
  document.getElementById('refresh').addEventListener('click', () => { void tick() })
  document.getElementById('save-settings').addEventListener('click', () => { void saveSettings().catch(onError) })
  document.getElementById('reload-settings').addEventListener('click', () => { settingsLoaded = false; void loadSettings().catch(onError) })

  function msg(el, text, cls) {
    const node = document.getElementById(el)
    node.textContent = text
    node.className = 'msg' + (cls ? ' ' + cls : '')
  }

  async function loadSystem() {
    const data = await json(BASE + '/api/system')
    const notes = data.notes || []
    document.getElementById('system-notes').innerHTML = notes.length
      ? '<div class="notice">' + notes.map(esc).join('<br>') + '</div>' : ''
    const m = data.model
    document.getElementById('sys-provider').value = m ? m.provider : ''
    document.getElementById('sys-model').value = m ? m.model : ''
    document.getElementById('sys-effort').value = m ? (m.reasoningEffort || '') : ''
    document.getElementById('sys-baseurl').value = data.key ? data.key.baseURL : ''
    document.getElementById('save-model').disabled = !m
    document.getElementById('save-endpoint').disabled = !data.key
    document.getElementById('save-key').disabled = !data.key
    document.getElementById('clear-key').disabled = !data.key
    const k = data.key
    document.getElementById('key-state').innerHTML = k
      ? (k.configured ? '<span class="tag ok">已配置</span>' : '<span class="tag bad">未配置</span>')
        + ' <span class="mono">' + esc(k.ref) + '</span>'
        + (k.source ? ' <span class="tag">来源 ' + esc(k.source) + '</span>' : '')
        + (k.writable ? '' : ' <span class="tag bad">不可写</span>')
      : '未找到 API Key 配置条目'
    const providerRows = (data.providers || []).map(p =>
      '<tr data-provider="' + esc(JSON.stringify(p)).replace(/"/g, '&quot;') + '" title="点击载入到下方表单">'
      + '<td class="mono">' + esc(p.route) + '</td><td>' + esc(p.displayName) + '</td>'
      + '<td class="mono">' + esc(p.api || '—') + '</td><td class="mono">' + esc(p.baseURL || '—') + '</td>'
      + '<td class="mono">' + esc((p.models || []).join(', ') || '目录默认') + '</td>'
      + '<td>' + (p.configured ? '<span class="tag ok">已配置</span>' : '<span class="tag bad">未配置</span>')
      + ' <span class="mono">' + esc(p.apiKeyRef || '') + '</span></td></tr>')
    document.getElementById('provider-rows').innerHTML = providerRows.join('') ||
      '<tr><td colspan="6" class="empty">还没有自定义服务商</td></tr>'
    const rows = (data.plugins || []).map(p =>
      '<tr><td class="mono">' + esc(p.id) + '</td><td class="mono">' + esc(p.name) + '</td>'
      + '<td>' + esc(p.phase) + '</td><td>' + (p.disabled ? '否' : '是') + '</td></tr>')
    document.getElementById('plugins').innerHTML = rows.join('') ||
      '<tr><td colspan="4" class="empty">插件清单不可用</td></tr>'
  }

  async function postJson(path, body, msgId) {
    msg(msgId, '保存中…')
    const r = await fetch(BASE + path, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    })
    if (r.status === 401) { location.href = BASE + '/login'; return }
    const data = await r.json().catch(() => ({}))
    if (!r.ok || data.ok === false) { msg(msgId, data.error || '保存失败', 'bad'); return }
    msg(msgId, '已保存并生效', 'ok')
    toast('设置已更新')
    await loadSystem()
  }

  document.getElementById('save-provider').addEventListener('click', () => {
    const ctxRaw = document.getElementById('p-ctx').value.trim()
    void postJson('/api/system/provider', {
      route: document.getElementById('p-route').value.trim(),
      displayName: document.getElementById('p-name').value.trim(),
      api: document.getElementById('p-api').value,
      baseURL: document.getElementById('p-baseurl').value.trim(),
      modelId: document.getElementById('p-model').value.trim(),
      contextWindow: ctxRaw === '' ? undefined : Number(ctxRaw),
      apiKey: document.getElementById('p-key').value,
      makeDefault: document.getElementById('p-default').checked,
    }, 'provider-msg').then(() => { document.getElementById('p-key').value = '' }).catch(onError)
  })

  document.getElementById('save-model').addEventListener('click', () => {
    void postJson('/api/system/model', {
      provider: document.getElementById('sys-provider').value.trim(),
      model: document.getElementById('sys-model').value.trim(),
      reasoningEffort: document.getElementById('sys-effort').value,
    }, 'model-msg').catch(onError)
  })
  document.getElementById('save-endpoint').addEventListener('click', () => {
    void postJson('/api/system/endpoint', {
      baseURL: document.getElementById('sys-baseurl').value.trim(),
    }, 'key-msg').catch(onError)
  })
  document.getElementById('save-key').addEventListener('click', () => {
    void postJson('/api/system/key', {
      value: document.getElementById('sys-key').value,
    }, 'key-msg').then(() => { document.getElementById('sys-key').value = '' }).catch(onError)
  })
  document.getElementById('clear-key').addEventListener('click', () => {
    if (!confirm('确定清除已保存的 API Key？清除后分析会话将无法调用模型，直到重新配置。')) return
    void postJson('/api/system/key', { clear: true }, 'key-msg').catch(onError)
  })

  function onError(err) { console.warn(err); toast('数据加载失败') }

  async function tick() {
    await loadOverview().catch(onError)
    if (viewOf(location.hash) === 'overview') await loadRecent().catch(onError)
    if (viewOf(location.hash) === 'records') await loadList().catch(onError)
    if (viewOf(location.hash) === 'system') await loadSystem().catch(onError)
  }

  route()
  void tick()
  setInterval(tick, 30000)
})()
</script>
</body>
</html>`
}
