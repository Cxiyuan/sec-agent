/**
 * xdr-ingest — NDR 摘要接收插件（dsh out-of-tree bundle）。
 *
 * 职责分两条腿：
 * 1. **旧路径（回滚用）**：收 NDR 的摘要推送，内容派生「事件分析 ID」+ 两级缓存判重，
 *    用启发式分诊（`analyzer.ts`）。新架构上线后 NDR 不再推摘要，这条路保留以便回滚。
 * 2. **新路径（派工闭环）**：收**门铃**（只带队列状况，不含事件）→ `claim_tasks` 领客观线索
 *    → 起分析会话（`ctx.agents`）→ 模型用 MCP 工具取证并 `complete_task` 交回 →
 *    本插件回查 `task_state` 确认真的交回了（没交回就 `defer_task`，别占着租约）。
 *
 * 挂载：插件经 plugin manager / profile 依赖安装后，由本包的 cordis.patch.yml
 * 声明默认配置；token 与 PG 连接串必须由部署层提供（token 默认从
 * XDR_INGEST_TOKEN、pgUrl 从 XDR_INGEST_PG_URL 读）。
 */

import type { Context } from '@deepseek-ai/cordis'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { agentsOf } from './agent-port.ts'
import { Analyst } from './analyst.ts'
import { ClaimLoop } from './claim-loop.ts'
import { McpHttpClient } from './mcp-http.ts'
import { NdrTaskPortAdapter } from './ndr-port.ts'
import { TieredCache } from './cache.ts'
import { createIngestHandler } from './handler.ts'
import { PostgresColdStore } from './pg-store.ts'
import { MemoryColdStore } from './store.ts'

export type * from './types.ts'
export { analysisIdOf, identityKey, normalizeDigest, ANALYSIS_ID_PREFIX } from './identity.ts'
export { TieredCache } from './cache.ts'
export { triageDigest } from './analyzer.ts'
export { parseDoorbell, DoorbellFormatError } from './doorbell.ts'
export type { Doorbell } from './doorbell.ts'
export { ClaimLoop } from './claim-loop.ts'
export type { ClaimedTask, ClaimLoopOptions, ClaimReply } from './claim-loop.ts'
export { Analyst } from './analyst.ts'
export { McpHttpClient, McpError } from './mcp-http.ts'
export { NdrTaskPortAdapter } from './ndr-port.ts'
export { buildAnalysisPrompt } from './prompt.ts'
export { processItems, createIngestHandler, WebhookHttpError } from './handler.ts'
export { MemoryColdStore } from './store.ts'
export { PostgresColdStore } from './pg-store.ts'
export type { ColdEntry, ColdStore, AnalysesPage, AnalysesQuery } from './store.ts'
export type { XdrIngestService } from './workbench.ts'

/** Cordis function-plugin name（bundle patch 行的 id 与之对应）。 */
export const name = 'xdr-ingest'

// 生命周期可见性：模块被 Loader import、apply() 真正激活，各留一条日志。
// 路由 404 排查时，docker logs 里这两行在不在直接区分「行没插进去」
// 「模块没 import」「apply 没跑」三种根因。
console.log('[xdr-ingest] module loaded')

/** 路由注册需要宿主 webServer。 */
export const inject = ['webServer']

/** 插件配置（web 设置页 / profile patch 均可提供）。 */
export interface Config {
  /** 路由基路径：/digests、/ping、/stats 三个端点挂在它下面。 */
  readonly basePath: string
  /** Bearer token，与 NDR 侧 agent_push.token 一致；留空插件拒绝加载。 */
  readonly token: string
  /** 请求体字节上限。 */
  readonly maxBodyBytes: number
  /** 分析结果有效期（小时），两层一致，过期重分析。 */
  readonly resultTtlHours: number
  /**
   * 冷库连接串（项目统一 PG）。留空 = 仅内存冷库（开发/测试兜底，
   * 进程退出即丢判重结果，生产必须配置）。
   */
  readonly pgUrl: string
  /** 热层容量上限（条）：超出淘汰最久未见记录，降级回冷库不丢数据。 */
  readonly hotMaxEntries: number
  /** 晋升热层的出现次数门槛：occurrences >= 此值才进内存。 */
  readonly hotThreshold: number
  /** 启动预热条数：按 occurrences 降序把冷库热数据装进热层。 */
  readonly warmupLimit: number
  /** 过期清理周期（分钟）。 */
  readonly pruneIntervalMinutes: number

  // ---------- 派工闭环（新架构） ----------
  /** NDR 的 MCP 地址（analyst 档）。留空 = 只收门铃不分析（回滚档）。 */
  readonly mcpUrl: string
  /** MCP 令牌（与门铃的 `token` 是**两个**东西，不要混用）。 */
  readonly mcpToken: string
  /** 定点自轮询兜底（秒）：门铃会丢，必须还有一条"自己去看"的路。 */
  readonly pollSeconds: number
  /** 本进程最多同时跑几个分析会话（服务端还有每令牌并发上限）。 */
  readonly maxConcurrent: number
  /** 单次领取条数上限。 */
  readonly claimLimit: number
  /** 单会话超时（秒）：超时先 cancel 再 defer，别让它一直占着并发槽。 */
  readonly analysisTimeoutSeconds: number
  /** 门铃去抖（毫秒）：一串门铃合并成一次领取。 */
  readonly doorbellDebounceMs: number
  /** 领取失败退避上限（毫秒）。 */
  readonly backoffMaxMs: number
  /** 分析用的模型（留空 = 用 dsh 部署默认）。 */
  readonly provider: string
  readonly model: string
}

export const Config: z<Config> = z.object({
  basePath: z.string().default('/xdr/ingest'),
  token: z.string().default(''),
  maxBodyBytes: z.number().step(1).min(1024).max(64 * 1024 * 1024).default(4 * 1024 * 1024),
  resultTtlHours: z.number().min(0.1).max(24 * 30).default(24),
  pgUrl: z.string().default(''),
  hotMaxEntries: z.number().step(1).min(1).max(1_000_000).default(5_000),
  hotThreshold: z.number().step(1).min(1).max(1_000).default(2),
  warmupLimit: z.number().step(1).min(0).max(100_000).default(1_000),
  pruneIntervalMinutes: z.number().step(1).min(1).max(1_440).default(60),

  mcpUrl: z.string().default('http://ndr-mcp:8090/mcp'),
  mcpToken: z.string().default(''),
  pollSeconds: z.number().step(1).min(30).max(86_400).default(900),
  maxConcurrent: z.number().step(1).min(1).max(16).default(2),
  claimLimit: z.number().step(1).min(1).max(20).default(2),
  analysisTimeoutSeconds: z.number().step(1).min(60).max(7_200).default(1_200),
  doorbellDebounceMs: z.number().step(1).min(0).max(60_000).default(3_000),
  backoffMaxMs: z.number().step(1).min(1_000).max(3_600_000).default(300_000),
  provider: z.string().default(''),
  model: z.string().default(''),
})

/** Schemastery 表达不了的约束在这里校验，加载期即失败。 */
function assertConfig(config: Config): void {
  if (!config.basePath.startsWith('/') || config.basePath === '/' || config.basePath.endsWith('/')) {
    throw new Error('xdr-ingest basePath must be an absolute pathname without trailing slash')
  }
  if (config.token.trim() === '') {
    throw new Error(
      'xdr-ingest token is empty: refusing to accept unauthenticated security events. '
      + 'Set it in the profile patch (token: ...) or via the XDR_INGEST_TOKEN environment seam, '
      + 'and keep it identical to the NDR side agent_push.token.',
    )
  }
  // MCP 令牌为空不算致命（可以只回执门铃、由运维手工驱动），但必须有人知道"分析不会发生"：
  // 静默不分析是最坏的形态 —— 队列会一直涨，而界面上看不到任何异常。
  if (config.mcpToken.trim() === '') {
    console.warn(
      '[xdr-ingest] mcpToken is empty: doorbells will be acknowledged but NO analysis session '
      + 'will start. Set XDR_NDR_MCP_TOKEN (a stmcp_ token from the NDR console) to enable the loop.',
    )
  }
  if (config.mcpToken.trim() !== '' && !/^https?:\/\//u.test(config.mcpUrl.trim())) {
    throw new Error(`xdr-ingest mcpUrl must be an http(s) URL, got ${config.mcpUrl}`)
  }
}

/** 注册 NDR 摘要接收路由，并管理两级缓存的生命周期。 */
export function apply(ctx: Context, config: Config): void {
  assertConfig(config)
  const store = config.pgUrl.trim() === ''
    ? new MemoryColdStore()
    : new PostgresColdStore({ connectionString: config.pgUrl.trim() })
  if (store.kind === 'memory') {
    console.warn(
      '[xdr-ingest] pgUrl is empty: falling back to the in-memory cold store. '
      + 'Dedup results are lost on restart; set pgUrl (or XDR_INGEST_PG_URL) in production.',
    )
  }
  console.log(`[xdr-ingest] apply(): routes at ${config.basePath}/*, cold store: ${store.kind}`)
  const cache = new TieredCache({
    ttlMs: config.resultTtlHours * 3_600_000,
    hotMaxEntries: config.hotMaxEntries,
    hotThreshold: config.hotThreshold,
    store,
  })
  // ---------- 派工闭环（新架构）----------
  // agents 服务由 dsh 的 `dsh-agent` 提供；没装时降级成"只收门铃"，并明确告警
  // （宁可显式不分析，也不要假装在分析）。
  const agents = agentsOf(ctx)
  let loop: ClaimLoop | null = null
  if (config.mcpToken.trim() !== '' && agents !== null) {
    const client = new McpHttpClient({
      url: config.mcpUrl.trim(),
      token: config.mcpToken.trim(),
      clientName: 'xdr-ingest',
      clientVersion: '0.2.0',
    })
    const ndr = new NdrTaskPortAdapter(client)
    const analyst = new Analyst({
      agents,
      ndr,
      timeoutMs: config.analysisTimeoutSeconds * 1000,
      source: 'xdr-ingest',
      ...(config.provider.trim() !== '' ? { provider: config.provider.trim() } : {}),
      ...(config.model.trim() !== '' ? { model: config.model.trim() } : {}),
    })
    loop = new ClaimLoop({
      pollSeconds: config.pollSeconds,
      maxConcurrent: config.maxConcurrent,
      claimLimit: config.claimLimit,
      doorbellDebounceMs: config.doorbellDebounceMs,
      backoffMaxMs: config.backoffMaxMs,
      claimTasks: limit => ndr.claimTasks(limit),
      runTask: async task => {
        const outcome = await analyst.run(task)
        if (!outcome.completed) {
          console.warn(
            `[xdr-ingest] 任务 ${task.id} 未交回（state=${outcome.state || 'unknown'}，`
            + `${outcome.deferred ? '已延后' : '延后失败'}）`,
          )
        }
      },
    })
  } else if (config.mcpToken.trim() !== '' && agents === null) {
    console.error(
      '[xdr-ingest] this dsh build has no `agents` service: analysis loop disabled. '
      + 'Load @deepseek-ai/dsh-agent (or your profile equivalent) to enable it.',
    )
  }

  /** 运行观测快照：`/xdr/ingest/status` 与 xdrIngest 服务共用同一份。 */
  function statusSnapshot(): Record<string, unknown> {
    return {
      analysis: loop === null ? 'disabled' : 'enabled',
      poll_seconds: config.pollSeconds,
      max_concurrent: config.maxConcurrent,
      ...(loop === null ? {} : { loop: loop.stats }),
    }
  }
  const route: WebRoute = {
    kind: 'prefix',
    path: config.basePath,
    handler: createIngestHandler(config.basePath, {
      token: config.token,
      maxBodyBytes: config.maxBodyBytes,
      cache,
      status: statusSnapshot,
      ...(loop === null ? {} : { onDoorbell: () => loop.wake() }),
    }),
  }
  /**
   * 工作台数据面：xdr-ui（同进程）经 ctx.reflect.get('xdrIngest', false) 读取。
   * 本插件未在场时工作台返回 undefined——它在 API 里报「数据不可用」而不是拒绝打开。
   * provide 自带 fiber 生命周期，插件停用时自动注销。
   */
  const service = {
    status: statusSnapshot,
    cacheStats: () => cache.stats(),
    wake: () => {
      if (loop === null) return false
      loop.wake()
      return true
    },
    listAnalyses: (query: { limit: number, offset: number, search: string }) => store.listRecent(query),
    getAnalysis: (analysisId: string) => store.load(analysisId),
  }
  void ctx.reflect.provide('xdrIngest', service)
  ctx.effect(
    () => {
      const disposeRoute = ctx.webServer.register(route)
      loop?.start()
      // 预热失败不影响路由（冷库不可用时退化为纯内存判重）
      void cache.warmup(config.warmupLimit).catch(error => {
        console.warn('[xdr-ingest] warmup failed:', error instanceof Error ? error.message : String(error))
      })
      const timer = setInterval(() => {
        void cache.pruneExpired().catch(error => {
          console.warn('[xdr-ingest] prune failed:', error instanceof Error ? error.message : String(error))
        })
      }, config.pruneIntervalMinutes * 60_000)
      timer.unref()
      return () => {
        loop?.stop()
        clearInterval(timer)
        disposeRoute()
        void store.close().catch(() => undefined)
      }
    },
    `xdr-ingest: ${config.basePath}/*`,
  )
}
