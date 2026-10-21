/**
 * xdr-ingest — NDR 摘要接收插件（dsh out-of-tree bundle）。
 *
 * 职责：在 dsh webServer 上注册 webhook 路由接收 NDR 推送；为每条摘要生成
 * 内容派生的「事件分析 ID」；两级缓存判重复用——热层（内存，经常出现的
 * IP/事件模式）+ 冷层（PostgreSQL 落盘，一切分析结果写穿），重复事件不
 * 重复分析。v0 分析器为启发式，P1 接 LLM。
 *
 * 挂载：插件经 plugin manager / profile 依赖安装后，由本包的 cordis.patch.yml
 * 声明默认配置；token 与 PG 连接串必须由部署层提供（token 默认从
 * XDR_INGEST_TOKEN、pgUrl 从 XDR_INGEST_PG_URL 读）。
 */

import type { Context } from '@deepseek-ai/cordis'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { TieredCache } from './cache.ts'
import { createIngestHandler } from './handler.ts'
import { PostgresColdStore } from './pg-store.ts'
import { MemoryColdStore } from './store.ts'

export type * from './types.ts'
export { analysisIdOf, identityKey, normalizeDigest, ANALYSIS_ID_PREFIX } from './identity.ts'
export { TieredCache } from './cache.ts'
export { triageDigest } from './analyzer.ts'
export { processItems, createIngestHandler, WebhookHttpError } from './handler.ts'
export { MemoryColdStore } from './store.ts'
export { PostgresColdStore } from './pg-store.ts'
export type { ColdEntry, ColdStore } from './store.ts'

/** Cordis function-plugin name（bundle patch 行的 id 与之对应）。 */
export const name = 'xdr-ingest'

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
  const cache = new TieredCache({
    ttlMs: config.resultTtlHours * 3_600_000,
    hotMaxEntries: config.hotMaxEntries,
    hotThreshold: config.hotThreshold,
    store,
  })
  const route: WebRoute = {
    kind: 'prefix',
    path: config.basePath,
    handler: createIngestHandler(config.basePath, {
      token: config.token,
      maxBodyBytes: config.maxBodyBytes,
      cache,
    }),
  }
  ctx.effect(
    () => {
      const disposeRoute = ctx.webServer.register(route)
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
        clearInterval(timer)
        disposeRoute()
        void store.close().catch(() => undefined)
      }
    },
    `xdr-ingest: ${config.basePath}/*`,
  )
}
