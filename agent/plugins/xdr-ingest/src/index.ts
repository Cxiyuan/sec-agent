/**
 * xdr-ingest — NDR 摘要接收插件（dsh out-of-tree bundle）。
 *
 * 职责：在 dsh webServer 上注册 webhook 路由接收 NDR 推送；为每条摘要生成
 * 内容派生的「事件分析 ID」；命中分析缓存则复用结果并计数，未命中才进入
 * 分析（v0 启发式，P1 接 LLM）。重复事件不重复分析。
 *
 * 挂载：插件经 plugin manager / profile 依赖安装后，由本包的 cordis.patch.yml
 * 声明默认配置；token 必须由部署层提供（patch 行默认从 XDR_INGEST_TOKEN 读）。
 */

import type { Context } from '@deepseek-ai/cordis'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { AnalysisCache } from './cache.ts'
import { createIngestHandler } from './handler.ts'

export type * from './types.ts'
export { analysisIdOf, identityKey, normalizeDigest, ANALYSIS_ID_PREFIX } from './identity.ts'
export { AnalysisCache } from './cache.ts'
export { triageDigest } from './analyzer.ts'
export { processItems, createIngestHandler, WebhookHttpError } from './handler.ts'

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
  /** 分析结果有效期（小时），过期重分析。 */
  readonly resultTtlHours: number
  /** 缓存容量上限（条），超出淘汰最久未见的记录。 */
  readonly maxEntries: number
}

export const Config: z<Config> = z.object({
  basePath: z.string().default('/xdr/ingest'),
  token: z.string().default(''),
  maxBodyBytes: z.number().step(1).min(1024).max(64 * 1024 * 1024).default(4 * 1024 * 1024),
  resultTtlHours: z.number().min(0.1).max(24 * 30).default(24),
  maxEntries: z.number().step(1).min(100).max(1_000_000).default(20_000),
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

/** 注册 NDR 摘要接收路由。 */
export function apply(ctx: Context, config: Config): void {
  assertConfig(config)
  const cache = new AnalysisCache({
    ttlMs: config.resultTtlHours * 3_600_000,
    maxEntries: config.maxEntries,
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
    () => ctx.webServer.register(route),
    `xdr-ingest: ${config.basePath}/*`,
  )
}
