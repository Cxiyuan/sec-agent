/**
 * xdr-ui — 深瞳安全分析控制台插件（dsh out-of-tree bundle）。
 *
 * **产品定位**：agent 已不是"对话模式的任务窗口"，而是后台自助分析的工作智能体
 * （门铃 → 领工单 → 取证 → 交结论）。原生 dsh 聊天界面服务不了运营侧——本插件
 * 在 {basePath}（默认 /xdr/ui）提供一个**登录鉴权的控制台**，并把站点根路径
 * `/` 直接重定向到它：
 *   ① 运行总览：分析循环开关、在跑/并发、门铃与领取统计、剩余预算、缓存规模、
 *      最近分析；
 *   ② 分析记录：PG 冷库的历史结论（分页 + 搜索 + 详情）；
 *   ③ 配置：运行参数热更新（轮询/并发/领取条数，持久化）+ 连接与凭据状态；
 *   ④ 手动领取：立即叫醒领取循环（仍受并发与服务端预算约束）。
 *
 * 与原生的关系：dsh 的 /login（admin/admin123）登录的是**原始会话界面**；
 * 本插件的 ./login 登录的是**控制台**，凭据共用 DSH_WEB_AUTH_USER /
 * DSH_WEB_AUTH_PASSWORD（与 dsh 同一组环境缝），但 Cookie 各自独立。
 * 原始界面保留在 /index.html（不再是默认入口），badge: true 时向它注入一枚
 * 「返回控制台」角标（webserver.tapIndex，登记式注入，不改上游文件）。
 *
 * 数据面来自 xdr-ingest provide 的 `xdrIngest` 服务（同一进程，可选读取；
 * 契约见 xdr-ingest 的 src/workbench.ts——这里按**结构化本地接口**对齐，
 * 不跨包 import type：独立 plugin workspace 的 typecheck 先于它的 build 跑，
 * 跨包类型引用会造成必须先构建邻居的门禁顺序耦合）。
 * 未在场时工作台照常打开，数据区显示「数据面不可用」。
 */

import type { Context } from '@deepseek-ai/cordis'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { escapeHtml, loginPage, workbenchPage } from './html.ts'
import { createRootRedirect, createUiHandler, type IngestServiceView } from './http.ts'
import { saveEndpoint, saveKey, saveModel, saveProvider, systemSnapshot } from './system.ts'
import { credentialsOf, resolveSessionSecret, UiAuth } from './ui-auth.ts'

/** Cordis function-plugin name（bundle patch 行的 id 与之对应）。 */
export const name = 'xdr-ui'

/** 路由注册需要宿主 webServer。 */
export const inject = ['webServer']

export interface Config {
  /** 路由基路径：页面与 API 都挂在它下面。 */
  readonly basePath: string
  /** 登录账号；空串回落 admin（现场部署默认）。 */
  readonly user: string
  /** 登录密码；空串回落 admin123（现场部署默认）。 */
  readonly password: string
  /** 会话签名密钥。空串时按 DSH_WEB_UI_SECRET → DSH_WEB_LAUNCH_TOKEN → 进程内随机寻源。 */
  readonly secret: string
  /** 会话时长（小时）。 */
  readonly sessionHours: number
  /** 是否向原生界面 index.html 注入跳转工作台的角标。 */
  readonly badge: boolean
  /** NDR 控制台地址（左侧菜单的「NDR 控制台」入口）；留空则隐藏该入口。 */
  readonly ndrConsoleUrl: string
}

export const Config: z<Config> = z.object({
  basePath: z.string().default('/xdr/ui'),
  user: z.string().default(''),
  password: z.string().default(''),
  secret: z.string().default(''),
  sessionHours: z.number().min(0.5).max(24 * 7).default(12),
  badge: z.boolean().default(true),
  ndrConsoleUrl: z.string().default(''),
})

function assertConfig(config: Config): void {
  if (!/^\/[\w\-.]+(\/[\w\-.]+)*$/u.test(config.basePath)) {
    throw new Error('xdr-ui basePath must be an absolute, plain pathname without trailing slash (for example /xdr/ui)')
  }
}

/**
 * 从 cordis Context 读 xdr-ingest 提供的数据面服务。
 * **必须走 ctx.reflect.get，不能直接写 ctx.xdrIngest**——cordis 的 context Proxy
 * 读未在 inject 里声明的服务属性会直接抛错（见 xdr-ingest 的 agent-port.ts 注释）。
 * 服务不存在（xdr-ingest 未安装/未激活）返回 null，工作台降级只显示自身。
 */
function ingestOf(context: Context): IngestServiceView | null {
  try {
    const reflect = (context as { reflect?: { get?: (name: string, strict?: boolean) => unknown } }).reflect
    if (typeof reflect?.get !== 'function') return null
    const service: unknown = reflect.get('xdrIngest', false)
    if (typeof service !== 'object' || service === null) return null
    const shape = service as Partial<IngestServiceView>
    if (typeof shape.status !== 'function'
      || typeof shape.cacheStats !== 'function'
      || typeof shape.listAnalyses !== 'function'
      || typeof shape.getAnalysis !== 'function') return null
    if (shape.wake === undefined) {
      return { ...shape, wake: () => false } as IngestServiceView
    }
    return shape as IngestServiceView
  } catch {
    return null
  }
}

/** 工作台路由注册与生命周期。 */
export function apply(ctx: Context, config: Config): void {
  assertConfig(config)
  const base = config.basePath
  const env = process.env
  const credentials = {
    // 配置留空回落现场默认（与 credentialsOf 同源），显式配置优先
    user: config.user.trim() === '' ? credentialsOf(env).user : config.user.trim(),
    password: config.password === '' ? credentialsOf(env).password : config.password,
  }
  const secretResolution = config.secret.trim() === ''
    ? resolveSessionSecret(env)
    : { secret: config.secret.trim(), volatile: false }
  if (secretResolution.volatile) {
    console.warn(
      '[xdr-ui] no session secret seam (set DSH_WEB_UI_SECRET, or the DSH_WEB_LAUNCH_TOKEN the deployment already fixes): '
      + 'using a per-process random secret; every restart logs current workbench sessions out.',
    )
  }
  const auth = new UiAuth(
    credentials,
    secretResolution.secret,
    config.sessionHours * 3_600_000,
  )
  console.log(`[xdr-ui] apply(): workbench at ${base}/（登录账号 ${credentials.user}）`)
  if (!ingestOf(ctx)) {
    console.warn('[xdr-ui] xdrIngest service is absent: the workbench will open but show 数据面不可用 until xdr-ingest activates.')
  }

  /** 配置页展示的部署侧事实；令牌只报"是否配置"，不回显。 */
  const meta = (): Record<string, unknown> => ({
    service: '深瞳 · 安全分析智能体',
    basePath: base,
    user: credentials.user,
    passwordSource: config.password !== ''
      ? '配置文件'
      : ((env.DSH_WEB_AUTH_PASSWORD ?? '') !== '' ? '环境变量' : '部署默认'),
    sessionHours: config.sessionHours,
    ndrConsoleUrl: config.ndrConsoleUrl.trim(),
    mcpUrl: env.XDR_NDR_MCP_URL ?? '',
    mcpTokenSet: (env.XDR_NDR_MCP_TOKEN ?? '') !== '',
    doorbellTokenSet: (env.XDR_INGEST_TOKEN ?? '') !== '',
    doorbellPath: '/xdr/ingest/digests',
    pgSet: (env.XDR_INGEST_PG_URL ?? '') !== '',
  })

  const route: WebRoute = {
    kind: 'prefix',
    path: base,
    handler: createUiHandler(base, {
      auth,
      ingest: () => ingestOf(ctx),
      renderLogin: (error: boolean) => loginPage(base, error),
      renderWorkbench: () => workbenchPage(base),
      meta,
      system: {
        snapshot: () => systemSnapshot(ctx),
        saveModel: patch => saveModel(ctx, patch),
        saveKey: patch => saveKey(ctx, patch),
        saveEndpoint: patch => saveEndpoint(ctx, patch),
        saveProvider: patch => saveProvider(ctx, patch),
      },
    }),
  }
  // 站点根路径交给控制台：原生 dsh 界面不再作为默认入口（仍可从左侧菜单进 /index.html）。
  const rootRoute: WebRoute = { kind: 'exact', path: '/', handler: createRootRedirect(base) }

  ctx.effect(
    () => {
      const disposeRoute = ctx.webServer.register(route)
      const disposeRoot = ctx.webServer.register(rootRoute)
      const disposeBadge = config.badge ? injectBadge(ctx, base) : undefined
      return () => {
        disposeBadge?.()
        disposeRoot()
        disposeRoute()
      }
    },
    `xdr-ui: ${base}/* + /`,
  )
}

/**
 * 向原生 index.html 注入跳转工作台的角标（webserver.tapIndex 是它公开的
 * "markup 逃生口"；这里只做登记式注入，不改 dsh 任何文件）。
 * 角标是固定右下角的小链接，点开 /xdr/ui；未登录会被工作台引到登录页。
 */
function injectBadge(ctx: Context, base: string): () => void {
  const markup = `<a href="${escapeHtml(base)}/" id="xdr-ui-badge" style="position:fixed;right:1rem;bottom:1rem;z-index:2147483647;display:inline-flex;padding:.45rem .8rem;border-radius:999px;background:#0d1526;border:1px solid #1e2a44;color:#e6edf7;font:600 .78rem/1 system-ui,sans-serif;text-decoration:none;box-shadow:0 4px 16px rgba(0,0,0,.45);" aria-label="返回分析控制台">← 返回控制台</a>`
  const transform = (html: string): string => {
    if (!html.includes('</body>')) return html
    return html.replace('</body>', `${markup}</body>`)
  }
  const dispose = ctx.webServer.tapIndex(transform)
  return dispose
}
