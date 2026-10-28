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
import type { RuntimeSettings } from './settings.ts'
import { ANALYSIS_SCRIPT_TOOL_NAMES, registerScriptTools } from './script-tools.ts'
import { identityOfMatch } from './task-results.ts'
import { MemoryStateStore } from './state-store.ts'
import type {
  ConclusionStore,
  ProcessStore,
  ProjectRecord,
  ProjectStatus,
  ScriptStore,
  SettingsStore,
  TaskSeenStore,
} from './state-store.ts'
import { PostgresStateStore } from './pg-state-store.ts'
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
export type { ConclusionPage, ConclusionQuery, ConclusionRecord } from './conclusions.ts'
export type { XdrIngestService } from './workbench.ts'

/** 抑制记忆同步的节拍（毫秒）：抑制是低频事件，1.5 分钟一次足够。 */
const SUPPRESSION_SYNC_MS = 90_000

/** Cordis function-plugin name（bundle patch 行的 id 与之对应）。 */
export const name = 'xdr-ingest'

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

  // ---------- 项目组织（= 一台 NDR；多项目见 projects 表） ----------
  /**
   * 绑定的项目组织 ID（= NDR 授权ID，8 位）。留空 = 启动时调 NDR 的 `server_info`
   * 自动取；取不到就**不启动分析**（宁可显式失败，也不写到归属不明的库里）。
   */
  readonly projectId: string
  /** 项目显示名（控制台展示；留空 = 沿用库里已有名字，再不行用"默认项目"）。 */
  readonly projectName: string

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

  projectId: z.string().default(''),
  projectName: z.string().default(''),

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

/**
 * 项目注册表：每个项目（NDR 授权ID）一个项目绑定的 store 实例。
 *
 * 为什么按项目建实例而不是所有方法都传 projectId：调用方（分析循环、脚本工具、
 * 控制台）漏传一次就会串项目；把项目钉在实例上，漏不掉。
 * 池很小（项目数不会多，连接按需建立），一个实例一个池。
 */
class StateStoreRegistry {
  private readonly cache = new Map<string, PostgresStateStore>()
  private readonly connectionString: string
  private readonly poolSize: number

  constructor(connectionString: string, poolSize: number) {
    this.connectionString = connectionString
    this.poolSize = poolSize
  }

  get(projectId: string): PostgresStateStore {
    const key = projectId.trim()
    let store = this.cache.get(key)
    if (store === undefined) {
      store = new PostgresStateStore({
        connectionString: this.connectionString,
        projectId: key,
        poolSize: this.poolSize,
      })
      this.cache.set(key, store)
    }
    return store
  }

  async closeAll(): Promise<void> {
    const stores = [...this.cache.values()]
    this.cache.clear()
    await Promise.all(stores.map(store => store.close().catch(() => undefined)))
  }
}

/** 当前项目的数据面（随项目解析结果切换；未解析前是内存兜底，方法返回空）。 */
type DataStore = TaskResultStore & ScriptStore & TaskSeenStore & ConclusionStore & SettingsStore & ProcessStore

/** 把"随时可能换实例"的 getter 包成稳定对象：脚本工具/服务拿到的引用不变。 */
function liveStore<T extends object>(get: () => T): T {
  return new Proxy({} as T, {
    get: (_target, prop) => {
      const target = get()
      const value = Reflect.get(target, prop)
      return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value
    },
    has: (_target, prop) => prop in get(),
  })
}

/** 注册 NDR 路由、智能体脚本工具与持久化存储的生命周期。 */
export function apply(ctx: Context, config: Config): void {
  assertConfig(config)
  // 旧摘要契约（/digests）是**回滚专用**：新架构下 NDR 只安门铃，冷库只用于回滚与
  // 旧缓存统计；主数据（结论复用/脚本/结论留档/过程/项目/参数）都在 state store 里。
  const coldStore: ColdStore = config.pgUrl.trim() === ''
    ? new MemoryColdStore()
    : new PostgresColdStore({ connectionString: config.pgUrl.trim() })
  if (coldStore.kind === 'memory') {
    console.warn(
      '[xdr-ingest] pgUrl is empty: falling back to the in-memory cold store. '
      + 'Dedup results are lost on restart; set pgUrl (or XDR_INGEST_PG_URL) in production.',
    )
  }
  const memoryStore = new MemoryStateStore()
  const registry = config.pgUrl.trim() === ''
    ? null
    : new StateStoreRegistry(config.pgUrl.trim(), 3)
  /** 项目数据面：解析前用内存兜底（方法返回空，不会串项目）。 */
  let projectStore: DataStore = memoryStore
  const data = liveStore<DataStore>(() => projectStore)

  let project: ProjectRecord | null = null
  let resolving = true
  let resolveError = ''
  let loop: ClaimLoop | null = null
  let analyst: Analyst | null = null
  let syncSuppressions: (() => Promise<void>) | null = null
  let mcpClient: McpHttpClient | null = null
  let ndrPort: NdrTaskPortAdapter | null = null
  const agents = agentsOf(ctx)

  console.log(
    `[xdr-ingest] apply(): routes at ${config.basePath}/*, `
    + `cold store: ${coldStore.kind}, state store: ${registry === null ? 'memory' : 'postgres'}`,
  )

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
      analysis: resolving ? 'resolving' : loop === null ? 'disabled' : 'enabled',
      ...settingsView(currentSettings()),
      store_kind: coldStore.kind,
      state_store_kind: registry === null ? 'memory' : 'postgres',
      project: {
        id: project?.projectId ?? config.projectId.trim(),
        name: project?.name ?? config.projectName.trim(),
        status: project?.status ?? (resolving ? 'unchecked' : 'unreachable'),
        detail: project?.statusDetail ?? resolveError,
      },
      // 控制台「分析记录」的数据源（智能体自己的结论留档，按项目隔离）
      conclusion_source: 'agent:xdr_ingest_conclusion',
      script_tool_names: ANALYSIS_SCRIPT_TOOL_NAMES.filter(name =>
        ctx.tools.schemas().some(schema => schema.name === name),
      ),
      ...(analyst === null ? {} : { task_reuse: analyst.reuseStats }),
      ...(loop === null ? {} : { loop: loop.stats }),
    }
  }

  /**
   * 解析并校验项目绑定：
   * 1. 授权ID 从配置取，或调 NDR 的 `server_info` 自动取；
   * 2. 用 `server_info`（以及响应头 `x-ndr-auth-id`）核对，不一致 → 停分析并报警；
   * 3. 绑不上就不启动领取循环（宁可显式失败，也不写到归属不明的库里）。
   */
  async function resolveProject(): Promise<void> {
    if (config.mcpToken.trim() === '' || agents === null) {
      resolving = false
      return
    }
    const client = new McpHttpClient({
      url: config.mcpUrl.trim(),
      token: config.mcpToken.trim(),
      clientName: 'xdr-ingest',
      clientVersion: '0.2.0',
    })
    mcpClient = client
    const ndr = new NdrTaskPortAdapter(client)
    ndrPort = ndr
    let info: { authId: string, source: string, stable: boolean }
    try {
      info = await ndr.serverInfo()
    } catch (error) {
      resolveError = `绑定校验失败：${error instanceof Error ? error.message : String(error)}`
      resolving = false
      console.error(`[xdr-ingest] ${resolveError}（不启动分析循环）`)
      return
    }
    const declared = config.projectId.trim()
    const bound = (declared !== '' ? declared : info.authId).toUpperCase()
    if (bound === '') {
      resolveError = 'NDR 未返回授权ID（server_info 为空）'
      resolving = false
      console.error(`[xdr-ingest] ${resolveError}（不启动分析循环）`)
      return
    }
    const admin = registry?.get('')
    if (declared !== '' && info.authId !== '' && declared.toUpperCase() !== info.authId.toUpperCase()) {
      resolveError = `授权ID 不一致：配置 ${declared} / NDR ${info.authId}`
      project = (await admin?.upsertProject({
        projectId: bound,
        name: config.projectName.trim() || config.projectName.trim() || '默认项目',
        mcpUrl: config.mcpUrl.trim(),
        mcpToken: config.mcpToken.trim(),
        pushToken: config.token.trim(),
        enabled: true,
      }).catch(() => null)) ?? null
      await admin?.setProjectStatus(bound, 'auth_mismatch', resolveError)
      resolving = false
      console.error(`[xdr-ingest] ${resolveError}：已停用该项目（到控制台改绑定ID后可恢复）`)
      return
    }
    // 绑定成立：落项目行（名字沿用已有，其次配置，最后"默认项目"）
    const existing = await admin?.getProject(bound).catch(() => null)
    const name = (existing?.name ?? '').trim() || config.projectName.trim() || '默认项目'
    project = (await admin?.upsertProject({
      projectId: bound,
      name,
      mcpUrl: config.mcpUrl.trim(),
      mcpToken: config.mcpToken.trim(),
      pushToken: config.token.trim(),
      enabled: true,
    }).catch(() => null)) ?? null
    await admin?.setProjectStatus(bound, 'ok', '')
    projectStore = registry?.get(bound) ?? memoryStore
    resolving = false
    if (project === null) project = { ...(project ?? {}), ...({
      projectId: bound, name, mcpUrl: config.mcpUrl.trim(), mcpToken: config.mcpToken.trim(),
      pushToken: config.token.trim(), enabled: true, status: 'ok' as ProjectStatus,
      statusDetail: '', lastCheckedAt: '', createdAt: '', updatedAt: '',
    }) } as ProjectRecord
    console.log(
      `[xdr-ingest] 项目绑定：${name}（授权ID ${bound}，来源 ${info.source}${info.stable ? '' : '，不稳定'}）`,
    )

    analyst = new Analyst({
      agents,
      ndr,
      timeoutMs: config.analysisTimeoutSeconds * 1000,
      source: 'xdr-ingest',
      modelSelection: () => {
        const selected = ctx.get('agentDefaultModel')?.currentSelection()
        return selected === undefined
          ? undefined
          : { provider: selected.provider, model: selected.model }
      },
      ...(config.provider.trim() !== '' ? { provider: config.provider.trim() } : {}),
      ...(config.model.trim() !== '' ? { model: config.model.trim() } : {}),
      taskResults: projectStore,
      taskReuseTtlMs: config.taskReuseTtlHours * 3_600_000,
      taskReuseStrengthDelta: config.taskReuseStrengthDelta,
      taskSeen: projectStore,
      process: projectStore,
      conclusions: projectStore,
      projectId: bound,
    })
    syncSuppressions = async (): Promise<void> => {
      const items = await ndr.listSuppressions()
      let marked = 0
      for (const item of items) {
        if (!item.enabled) continue
        if (item.sourceTaskId !== '') {
          if (await projectStore.markSuppressed(item.sourceTaskId, item.name)) marked += 1
        }
        const identity = identityOfMatch(item.match)
        if (identity === null) continue
        marked += await projectStore.markSuppressedByIdentity(identity, item.name)
      }
      if (marked > 0) {
        console.log(`[xdr-ingest] 抑制记忆已同步：${marked} 条现象被标记为「不再分析」`)
      }
    }
    const activeAnalyst = analyst
    loop = new ClaimLoop({
      pollSeconds: currentSettings().pollSeconds,
      maxConcurrent: currentSettings().maxConcurrent,
      claimLimit: currentSettings().claimLimit,
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
    // 工作台保存过的运行参数优先于配置默认值
    const saved = await projectStore.loadSettings().catch(() => null)
    if (saved !== null) {
      const merged = mergeSettings(currentSettings(), saved)
      if ('error' in merged) {
        console.warn('[xdr-ingest] 已保存的运行参数不合法，忽略：', merged.error)
      } else {
        loop.configure(merged.settings)
      }
    }
    loop.start()
    void syncSuppressions().catch(() => undefined)
  }
  void resolveProject().catch((error: unknown) => {
    resolving = false
    resolveError = error instanceof Error ? error.message : String(error)
    console.error('[xdr-ingest] 项目解析失败：', resolveError)
  })

  // 旧摘要冷库的两级缓存（回滚专用；主数据在 state store）
  const cache = new TieredCache({
    ttlMs: config.resultTtlHours * 3_600_000,
    hotMaxEntries: config.hotMaxEntries,
    hotThreshold: config.hotThreshold,
    store: coldStore,
  })
  const route: WebRoute = {
    kind: 'prefix',
    path: config.basePath,
    handler: createIngestHandler(config.basePath, {
      token: config.token,
      maxBodyBytes: config.maxBodyBytes,
      cache,
      status: statusSnapshot,
      onDoorbell: () => {
        if (loop === null) return
        loop.wake()
      },
    }),
  }

  const service = {
    status: statusSnapshot,
    cacheStats: () => cache.stats(),
    taskReuseStats: () => analyst?.reuseStats ?? { reused: 0, stored: 0 },
    scriptStats: async () => ({ store: projectStore.kind, count: await projectStore.countScripts() }),
    conclusionStats: async () => ({ available: true, total: await projectStore.countConclusions() }),
    processStats: async () => ({ available: true }),
    wake: () => {
      if (loop === null) return false
      loop.wake()
      return true
    },
    listAnalyses: (query: { limit: number, offset: number, search: string }) => coldStore.listRecent(query),
    getAnalysis: (analysisId: string) => coldStore.load(analysisId),
    listConclusions: (query: { limit: number, offset: number, search: string }) =>
      projectStore.listConclusions(query),
    getConclusion: (id: string) => projectStore.getConclusion(id),
    listProcesses: (query: { limit: number, offset: number, search: string, outcome: string }) =>
      projectStore.listProcesses(query),
    getProcess: (taskId: string) => projectStore.getProcess(taskId),
    listScripts: (query: { search: string, limit: number, offset: number }) =>
      projectStore.list(query),
    getScript: (nameOrId: string) => projectStore.getAny(nameOrId),
    saveScript: (body: unknown) => projectStore.upsert(scriptInputOf(body), new Date().toISOString()),
    setScriptEnabled: (nameOrId: string, enabled: boolean) => projectStore.setEnabled(nameOrId, enabled),
    removeScript: (nameOrId: string) => projectStore.remove(nameOrId),
    settings: async () => ({ ...settingsView(currentSettings()), store: projectStore.kind }),
    updateSettings: async (patch: unknown) => {
      const merged = mergeSettings(currentSettings(), patch)
      if ('error' in merged) return { ok: false, error: merged.error }
      loop?.configure(merged.settings)
      const persisted = await projectStore.saveSettings(merged.settings)
      if (!persisted) {
        console.warn('[xdr-ingest] 运行参数只在内存生效：state store 写入失败，重启后会回到上次成功保存的值。')
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
        disposeScriptTools = registerScriptTools(ctx, projectStore, {
          maxCodeBytes: config.scriptMaxCodeBytes,
          maxResults: config.scriptMaxResults,
        })
      } catch (error) {
        disposeRoute()
        throw error
      }
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
      const timer = setInterval(() => {
        void cache.pruneExpired().catch(error => {
          console.warn('[xdr-ingest] prune failed:', error instanceof Error ? error.message : String(error))
        })
        void projectStore.prune(new Date().toISOString()).catch(() => undefined)
      }, config.pruneIntervalMinutes * 60_000)
      timer.unref()
      return () => {
        loop?.stop()
        clearInterval(timer)
        clearInterval(syncTimer)
        disposeScriptTools()
        disposeRoute()
        void coldStore.close().catch(() => undefined)
        void registry?.closeAll()
      }
    },
    `xdr-ingest: ${config.basePath}/*`,
  )
}

/** 控制台新建/编辑脚本的入参归一（字段少、校验在 store 里做）。 */
function scriptInputOf(body: unknown): {
  name: string
  scenario: string
  code: string
  language?: string
  variables?: unknown
  tags?: readonly string[]
  notes?: string
  enabled?: boolean
  origin: string
  updatedBy: string
} {
  const row = (typeof body === 'object' && body !== null ? body : {}) as Record<string, unknown>
  return {
    name: String(row['name'] ?? '').trim(),
    scenario: String(row['scenario'] ?? '').trim(),
    code: String(row['code'] ?? ''),
    ...(typeof row['language'] === 'string' ? { language: row['language'] } : {}),
    variables: row['variables'],
    ...(Array.isArray(row['tags']) ? { tags: row['tags'].map(String) } : {}),
    ...(typeof row['notes'] === 'string' ? { notes: row['notes'] } : {}),
    ...(typeof row['enabled'] === 'boolean' ? { enabled: row['enabled'] } : {}),
    origin: 'console',
    updatedBy: 'console',
  }
}
