/**
 * xdr-ingest — NDR 门铃派工与智能体记忆插件（dsh out-of-tree bundle）。
 *
 * 主路径：NDR 只发门铃与客观任务元数据；智能体自行选择数据、问题和分析范围，
 * 模型用 MCP 工具取证并 `complete_task` 交回；本插件回查 `task_state`，没交回则延后。
 * 智能体侧结论库负责同类现象复用，脚本库保存可按场景重用的分析工具。
 * 旧摘要推送与 EA 判重只为回滚保留。
 *
 * 挂载：插件经 plugin manager / profile 依赖安装后，由本包的 cordis.patch.yml
 * 声明默认配置；token 与 PG 连接串必须由部署层提供（token 默认从
 * XDR_INGEST_TOKEN、pgUrl 从 XDR_INGEST_PG_URL 读）。
 */

import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-agent-default-model'
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
import type { ColdStore } from './store.ts'
import { mergeSettings, settingsView } from './settings.ts'
import type { RuntimeSettings, SettingsStore } from './settings.ts'
import { ANALYSIS_SCRIPT_TOOL_NAMES, registerScriptTools } from './script-tools.ts'
import { MemoryConclusionReader } from './conclusions.ts'
import { PostgresConclusionReader } from './pg-conclusions.ts'
import type { ConclusionReader } from './conclusions.ts'
import { MemoryStateStore } from './state-store.ts'
import { PostgresStateStore } from './pg-state-store.ts'
import type { ScriptStore, TaskSeenStore } from './state-store.ts'
import type { TaskResultStore } from './task-results.ts'

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
export { mergeSettings, settingsView, SETTING_LIMITS } from './settings.ts'
export type { RuntimeSettings, SettingsStore } from './settings.ts'
export { ANALYSIS_SCRIPT_TOOL_NAMES, registerScriptTools } from './script-tools.ts'
export { MemoryStateStore } from './state-store.ts'
export { PostgresStateStore } from './pg-state-store.ts'
export type { AnalysisScript, ScriptInput, ScriptQuery, ScriptStore } from './state-store.ts'
export { taskResultKey, reuseDecision, REUSABLE_VERDICTS } from './task-results.ts'
export type { TaskResultRecord, TaskResultStore } from './task-results.ts'
export { MemoryConclusionReader } from './conclusions.ts'
export { PostgresConclusionReader } from './pg-conclusions.ts'
export type {
  ConclusionPage,
  ConclusionQuery,
  ConclusionReader,
  ConclusionRecord,
} from './conclusions.ts'
export type { XdrIngestService } from './workbench.ts'

/** 抑制记忆同步的节拍（毫秒）：抑制是低频事件，1.5 分钟一次足够。 */
const SUPPRESSION_SYNC_MS = 90_000

/** Cordis function-plugin name（bundle patch 行的 id 与之对应）。 */
export const name = 'xdr-ingest'

/**
 * 从抑制条件树里取一个对象（`src_ip` / `dst_ip`）。
 *
 * 用途：抑制条目若没有 `source_task_id`（人建的那些），就按对象粗匹配一次，
 * 让"这类对象的现象"也能被本地抑制记忆挡住。
 */
function subjectOfMatch(match: unknown): string {
  const found: string[] = []
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item)
      return
    }
    if (typeof node !== 'object' || node === null) return
    const row = node as Record<string, unknown>
    if (Array.isArray(row['rules'])) {
      for (const item of row['rules']) walk(item)
      return
    }
    const field = String(row['field'] ?? '')
    const value = String(row['value'] ?? '').trim()
    if (value !== '' && (field === 'src_ip' || field === 'dst_ip')) found.push(value)
  }
  walk(match)
  return found[0] ?? ''
}

// 生命周期可见性：模块被 Loader import、apply() 真正激活，各留一条日志。
// 路由 404 排查时，docker logs 里这两行在不在直接区分「行没插进去」
// 「模块没 import」「apply 没跑」三种根因。
console.log('[xdr-ingest] module loaded')

/** 路由注册需要宿主 webServer；脚本库工具需要 tools 注册表。 */
export const inject = ['webServer', 'tools']

/** 插件配置（web 设置页 / profile patch 均可提供）。 */
export interface Config {
  /** 路由基路径：门铃/旧摘要、连通性、状态与旧缓存统计端点的共同前缀。 */
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

  // ---------- 智能体侧记忆（结论复用 + 脚本库） ----------
  /** 同类现象结论复用有效期（小时，从上次真实分析起算）；0 = 关闭复用。 */
  readonly taskReuseTtlHours: number
  /** 新线索强度比上次高多少就重查（现象变强，旧结论可能不够用）。 */
  readonly taskReuseStrengthDelta: number
  /** 单条脚本正文上限（字节）。 */
  readonly scriptMaxCodeBytes: number
  /** 脚本检索默认返回条数。 */
  readonly scriptMaxResults: number
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

  taskReuseTtlHours: z.number().min(0).max(24 * 90).default(24),
  taskReuseStrengthDelta: z.number().min(0).max(1).default(0.15),
  scriptMaxCodeBytes: z.number().step(1).min(1024).max(262_144).default(65_536),
  scriptMaxResults: z.number().step(1).min(1).max(20).default(5),
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

/** 注册 NDR 路由、智能体脚本工具与持久化存储的生命周期。 */
export function apply(ctx: Context, config: Config): void {
  assertConfig(config)
  const store: ColdStore & SettingsStore = config.pgUrl.trim() === ''
    ? new MemoryColdStore()
    : new PostgresColdStore({ connectionString: config.pgUrl.trim() })
  if (store.kind === 'memory') {
    console.warn(
      '[xdr-ingest] pgUrl is empty: falling back to the in-memory cold store. '
      + 'Dedup results are lost on restart; set pgUrl (or XDR_INGEST_PG_URL) in production.',
    )
  }
  console.log(`[xdr-ingest] apply(): routes at ${config.basePath}/*, cold store: ${store.kind}`)
  // 智能体侧记忆：结论复用（task-results）与脚本库（scripts）共用同一份 PG。
  // 内存兜底只保证进程内可用；重启丢失会在启动日志和 /status 里显示。
  const stateStore: TaskResultStore & ScriptStore & TaskSeenStore = config.pgUrl.trim() === ''
    ? new MemoryStateStore()
    : new PostgresStateStore({ connectionString: config.pgUrl.trim() })
  if (stateStore.kind === 'memory') {
    console.warn(
      '[xdr-ingest] 结论复用与脚本库使用内存存储（pgUrl 为空）：重启后丢失。'
      + '生产请配置 pgUrl / XDR_INGEST_PG_URL。',
    )
  }
  // 结论只读面：控制台「分析记录」读 NDR 写进同一份 PG 的 `analysis_results`。
  // 没有 PG 就退化成"没有结论"（页面照常打开，只是数据区空）。
  const conclusions: ConclusionReader = config.pgUrl.trim() === ''
    ? new MemoryConclusionReader()
    : new PostgresConclusionReader({ connectionString: config.pgUrl.trim() })
  // 探表是异步的：先等它落定，status 里的「结论数据源」才不会一启动就报不可用。
  void conclusions.ready().catch(() => undefined)
  // 旧摘要契约（/digests）是**回滚专用**：新架构下 NDR 只安门铃（analysis.enabled=true
  // 时不推摘要）。端点保留以便一键回滚到推送契约，日常流量不会走到它。
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
  let analyst: Analyst | null = null
  /** 抑制记忆的同步器（要 MCP 通道；没有 MCP 就只能靠 agent 自己提交的抑制） */
  let syncSuppressions: (() => Promise<void>) | null = null
  if (config.mcpToken.trim() !== '' && agents !== null) {
    const client = new McpHttpClient({
      url: config.mcpUrl.trim(),
      token: config.mcpToken.trim(),
      clientName: 'xdr-ingest',
      clientVersion: '0.2.0',
    })
    const ndr = new NdrTaskPortAdapter(client)
    analyst = new Analyst({
      agents,
      ndr,
      timeoutMs: config.analysisTimeoutSeconds * 1000,
      source: 'xdr-ingest',
      // Read the current DSH selection for every task. The model prompt's
      // {{model}} variable is assembled from agentOptions.model.
      modelSelection: () => {
        const selected = ctx.get('agentDefaultModel')?.currentSelection()
        return selected === undefined
          ? undefined
          : { provider: selected.provider, model: selected.model }
      },
      ...(config.provider.trim() !== '' ? { provider: config.provider.trim() } : {}),
      ...(config.model.trim() !== '' ? { model: config.model.trim() } : {}),
      taskResults: stateStore,
      taskReuseTtlMs: config.taskReuseTtlHours * 3_600_000,
      taskReuseStrengthDelta: config.taskReuseStrengthDelta,
      // 抑制记忆：被精准抑制的现象不起会话（省模型，也省取数）
      taskSeen: stateStore,
    })
    syncSuppressions = async (): Promise<void> => {
      const items = await ndr.listSuppressions()
      let marked = 0
      for (const item of items) {
        if (!item.enabled) continue
        if (item.sourceTaskId !== '') {
          if (await stateStore.markSuppressed(item.sourceTaskId, item.name)) marked += 1
        }
        // 没有任务 id 的抑制（人建的）：按条件树里的对象粗匹配一次
        const subject = subjectOfMatch(item.match)
        if (subject === '') continue
        const count = await stateStore.markSuppressedByIdentity(
          { kind: 'hit', subjectKind: 'ip', subject, feature: '' },
          item.name,
        )
        marked += count
      }
      if (marked > 0) {
        console.log(`[xdr-ingest] 抑制记忆已同步：${marked} 条现象被标记为「不再分析」`)
      }
    }
    const activeAnalyst = analyst
    loop = new ClaimLoop({
      pollSeconds: config.pollSeconds,
      maxConcurrent: config.maxConcurrent,
      claimLimit: config.claimLimit,
      doorbellDebounceMs: config.doorbellDebounceMs,
      backoffMaxMs: config.backoffMaxMs,
      claimTasks: limit => ndr.claimTasks(limit),
      runTask: async task => {
        const outcome = await activeAnalyst.run(task)
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

  /** 当前生效的运行参数：有领取循环读循环（可能被工作台改过），没有就取配置默认。 */
  function currentSettings(): RuntimeSettings {
    return loop?.settingsSnapshot() ?? {
      pollSeconds: config.pollSeconds,
      maxConcurrent: config.maxConcurrent,
      claimLimit: config.claimLimit,
    }
  }

  /** 运行观测快照：`/xdr/ingest/status` 与 xdrIngest 服务共用同一份。 */
  function statusSnapshot(): Record<string, unknown> {
    return {
      analysis: loop === null ? 'disabled' : 'enabled',
      ...settingsView(currentSettings()),
      store_kind: store.kind,
      state_store_kind: stateStore.kind,
      // 控制台「分析记录」的数据源（NDR 写的结论表）；不可用时界面显示"数据面不可用"
      conclusion_source: conclusions.available() ? 'ndr:analysis_results' : 'unavailable',
      script_tool_names: ANALYSIS_SCRIPT_TOOL_NAMES.filter(name =>
        ctx.tools.schemas().some(schema => schema.name === name),
      ),
      ...(analyst === null ? {} : { task_reuse: analyst.reuseStats }),
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
    taskReuseStats: () => analyst?.reuseStats ?? { reused: 0, stored: 0 },
    scriptStats: async () => ({ store: stateStore.kind, count: await stateStore.countScripts() }),
    conclusionStats: async () => ({ available: await conclusions.ready(), total: await conclusions.count() }),
    wake: () => {
      if (loop === null) return false
      loop.wake()
      return true
    },
    listAnalyses: (query: { limit: number, offset: number, search: string }) => store.listRecent(query),
    getAnalysis: (analysisId: string) => store.load(analysisId),
    listConclusions: (query: { limit: number, offset: number, search: string }) =>
      conclusions.listRecent(query),
    getConclusion: (id: string) => conclusions.get(id),
    settings: async () => ({ ...settingsView(currentSettings()), store: store.kind }),
    updateSettings: async (patch: unknown) => {
      const merged = mergeSettings(currentSettings(), patch)
      if ('error' in merged) return { ok: false, error: merged.error }
      loop?.configure(merged.settings)
      const persisted = await store.saveSettings(merged.settings)
      if (!persisted) {
        console.warn(
          '[xdr-ingest] 运行参数只在内存生效：冷库写入失败，重启后会回到上次成功保存的值。',
        )
      }
      return { ok: true, persisted, settings: settingsView(merged.settings) }
    },
  }
  void ctx.reflect.provide('xdrIngest', service)
  ctx.effect(
    () => {
      const disposeRoute = ctx.webServer.register(route)
      let disposeScriptTools = (): void => undefined
      try {
        disposeScriptTools = registerScriptTools(ctx, stateStore, {
          maxCodeBytes: config.scriptMaxCodeBytes,
          maxResults: config.scriptMaxResults,
        })
      } catch (error) {
        disposeRoute()
        throw error
      }
      // 工作台保存过的运行参数优先于 cordis 配置默认值；读失败就用默认值继续跑。
      void store.loadSettings().then(saved => {
        if (saved === null) return
        const merged = mergeSettings(currentSettings(), saved)
        if ('error' in merged) {
          console.warn('[xdr-ingest] 已保存的运行参数不合法，忽略：', merged.error)
          return
        }
        loop?.configure(merged.settings)
      }).catch((error: unknown) => {
        console.warn('[xdr-ingest] 运行参数读取失败，使用配置默认值：', error instanceof Error ? error.message : String(error))
      })
      loop?.start()
      // 预热失败不影响路由（冷库不可用时退化为纯内存判重）
      void cache.warmup(config.warmupLimit).catch(error => {
        console.warn('[xdr-ingest] warmup failed:', error instanceof Error ? error.message : String(error))
      })
      // 抑制记忆同步：把 NDR 侧生效中的精准抑制搬进本地记忆，
      // 之后同类现象**不起会话**（NDR 拦派工，这里拦分析）。
      const syncTimer = setInterval(() => {
        if (syncSuppressions === null) return
        void syncSuppressions().catch(error => {
          console.warn(
            '[xdr-ingest] suppression sync failed:',
            error instanceof Error ? error.message : String(error),
          )
        })
      }, SUPPRESSION_SYNC_MS)
      syncTimer.unref()
      if (syncSuppressions !== null) {
        void syncSuppressions().catch(() => undefined)
      }
      const timer = setInterval(() => {
        void cache.pruneExpired().catch(error => {
          console.warn('[xdr-ingest] prune failed:', error instanceof Error ? error.message : String(error))
        })
        void stateStore.prune(new Date().toISOString()).catch(error => {
          console.warn('[xdr-ingest] task result prune failed:', error instanceof Error ? error.message : String(error))
        })
      }, config.pruneIntervalMinutes * 60_000)
      timer.unref()
      return () => {
        loop?.stop()
        clearInterval(timer)
        clearInterval(syncTimer)
        disposeScriptTools()
        disposeRoute()
        void store.close().catch(() => undefined)
        void stateStore.close().catch(() => undefined)
        void conclusions.close().catch(() => undefined)
      }
    },
    `xdr-ingest: ${config.basePath}/*`,
  )
}
