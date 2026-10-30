/**
 * 项目组织运行时：一个 agent 同时接多台 NDR（多项目）。
 *
 * 每个项目 = 一台 NDR + 一套 MCP 凭据 + 一个领取循环。项目之间**完全隔离**：
 * - 数据：store 实例按项目绑定（`xdr_ingest_*` 表都带 project_id）；
 * - 运行时：各自的 MCP 客户端、租约、并发、运行参数；
 * - 身份：MCP 响应头 `x-ndr-auth-id` / `server_info` 必须与项目ID（= NDR 授权ID）一致，
 *   不一致或连不上 → 该项目停掉并标状态（`auth_mismatch` / `unreachable`），别的项目不受影响。
 *
 * 门铃按**推送令牌**找项目：每个项目在控制台录入自己的 push token，
 * 收到门铃只叫醒那一台 NDR 的循环（不会串到别的项目）。
 */

import type { AgentsServiceLike } from './agent-port.ts'
import { ConcurrencyGate, FailureBreaker, isTransientFailure } from './breaker.ts'
import { sendAlert } from './notify.ts'
import { Analyst } from './analyst.ts'
import { ClaimLoop } from './claim-loop.ts'
import { LightTriage } from './light-triage.ts'
import { identityOfMatch } from './task-results.ts'
import { McpHttpClient } from './mcp-http.ts'
import { NdrTaskPortAdapter } from './ndr-port.ts'
import { DEFAULT_LIGHT_TRIAGE, mergeSettings, settingsView } from './settings.ts'
import { readSessionTimeline } from './session-timeline.ts'
import type { SessionTimeline } from './session-timeline.ts'
import type { LightTriageConfig, RuntimeSettings } from './settings.ts'
import type {
  DataStore,
  ProjectInput,
  ProjectRecord,
  ProjectStatus,
  WorkflowInput,
  WorkflowRecord,
  WorkflowStage,
} from './state-store.ts'

/** 项目运行参数（从插件配置里抽出来的那几项）。 */
export interface ProjectRuntimeConfig {
  readonly pollSeconds: number
  readonly maxConcurrent: number
  readonly claimLimit: number
  readonly analysisTimeoutSeconds: number
  readonly doorbellDebounceMs: number
  readonly backoffMaxMs: number
  readonly provider: string
  readonly model: string
  readonly taskReuseTtlHours: number
  readonly taskReuseStrengthDelta: number
  /** DSH 会话日志根目录（分析过程时间线从这里读）。 */
  readonly sessionDir: string
  /** 熔断：连续失败阈值 / 初始冷却 / 冷却上限（毫秒） */
  readonly breakerThreshold: number
  readonly breakerBaseMs: number
  readonly breakerMaxMs: number
  /** 单任务工具调用上限（0 = 不限）与停滞判定（分钟） */
  readonly maxToolsPerTask: number
  readonly stallMinutes: number
  /** 告警 webhook（空 = 只写日志）。 */
  readonly alertWebhookUrl: string
  /** 仅测试注入：替换控制面 MCP 的 fetch。 */
  readonly mcpFetch?: typeof fetch
}

/** 项目表的读写面（生产实现是 PostgresStateStore；测试可注入内存实现）。 */
export interface ProjectAdminStore {
  listProjects(): Promise<ProjectRecord[]>
  getProject(projectId: string): Promise<ProjectRecord | null>
  upsertProject(input: ProjectInput): Promise<ProjectRecord | null>
  setProjectStatus(projectId: string, status: ProjectStatus, detail: string): Promise<void>
  removeProject(projectId: string): Promise<boolean>
  /** 工作流模版（全局表）：项目按 ID 引用。 */
  listWorkflows(): Promise<WorkflowRecord[]>
  getWorkflow(workflowId: string): Promise<WorkflowRecord | null>
  upsertWorkflow(input: WorkflowInput, nowIso: string): Promise<WorkflowRecord>
  setWorkflowEnabled(workflowId: string, enabled: boolean): Promise<boolean>
  removeWorkflow(workflowId: string): Promise<boolean>
  setProjectWorkflow(projectId: string, workflowId: string): Promise<boolean>
  maintenance(policy: {
    conclusionsDays: number, processesDays: number, observationsDays: number,
    egressDays: number, taskSeenDays: number,
  }): Promise<Record<string, number>>
  ping(): Promise<boolean>
}

/** 分析会话 → 项目：脚本工具靠它找到「这次分析属于哪个项目」。 */
export class SessionProjects {
  private readonly map = new Map<string, string>()

  set(sessionId: string, projectId: string): void {
    if (sessionId.trim() === '' || projectId.trim() === '') return
    this.map.set(sessionId, projectId)
  }

  get(sessionId: string | undefined): string | null {
    if (sessionId === undefined || sessionId === '') return null
    return this.map.get(sessionId) ?? null
  }

  delete(sessionId: string): void {
    this.map.delete(sessionId)
  }
}

/** `provider/model` → 两段；没有斜杠时整串当 model（provider 留空 = DSH 默认）。 */
export function splitModel(text: string): [string, string] {
  const value = String(text || '').trim()
  if (value === '') return ['', '']
  const at = value.indexOf('/')
  if (at <= 0) return ['', value]
  return [value.slice(0, at).trim(), value.slice(at + 1).trim()]
}

/** 项目引用的工作流；没绑定/被停用就回落到默认模版（再没有就 null = 不注入编排）。 */
export async function resolveWorkflow(
  admin: ProjectAdminStore,
  workflowId: string,
): Promise<WorkflowRecord | null> {
  const id = (workflowId ?? '').trim()
  if (id !== '') {
    const bound = await admin.getWorkflow(id).catch(() => null)
    if (bound !== null && bound.enabled) return bound
  }
  const all = await admin.listWorkflows().catch(() => [] as WorkflowRecord[])
  return all.find(row => row.isDefault && row.enabled)
    ?? all.find(row => row.enabled)
    ?? null
}

/** 默认工作流（首次启动播种）：与提示词里的取证顺序一致，不写死工具白名单。 */
export const DEFAULT_WORKFLOW_STAGES: readonly WorkflowStage[] = [
  {
    key: 'context',
    title: '定位与上下文',
    goal: '这条线索是什么、对象是谁、之前看过没有',
    guidance: '先查历史结论与资产台账；确认对象角色（服务器/终端/代理）再决定查哪类数据',
    tools: ['prior_findings', 'asset_context', 'entity_profile', 'describe_data', 'list_networks'],
  },
  {
    key: 'evidence',
    title: '现场取证',
    goal: '用原始事件确认发生了什么（时间窗、五元组、证据引用）',
    guidance: '证据必须本会话真取回（raw_evidence）；正文里的话不算证据',
    tools: ['search_events', 'aggregate_events', 'raw_evidence', 'net_flows', 'dns_queries', 'tls_fingerprints', 'web_requests'],
  },
  {
    key: 'baseline',
    title: '基线与偏离核对',
    goal: '这次和它自己的平时比，哪里不一样（外连目的地/账号/连接数/被访问量）',
    guidance: '新目标要看它原本连多少个目标；账号看上次登录地点与失败来源；被访问资产看它平时的客户端数（asset_baseline，warmed=false 说明还在学习期）',
    tools: ['baseline_lookup', 'asset_baseline', 'list_observations', 'egress_baseline'],
  },
  {
    key: 'correlate',
    title: '关联与影响面',
    goal: '是否影响其他资产、是否经过代理/中继、是否成簇',
    guidance: '反代/中继会让源 IP 失真；同簇事件是同一件事，别重复分析',
    tools: ['search_hits', 'get_event_detail', 'relay_nodes', 'asset_map', 'hit_clusters'],
  },
  {
    key: 'conclude',
    title: '结论与交回',
    goal: '定性 + 证据 + 影响面（anchors）+ 是否提交抑制',
    guidance: '交回是唯一硬性收尾要求；没查完也要交回并写 terminal_reason',
    tools: ['complete_task'],
  },
]

/** 首次启动播种默认模版（已有任何模版就不动）。 */
export async function ensureDefaultWorkflow(admin: ProjectAdminStore, nowIso: string): Promise<void> {
  const existing = await admin.listWorkflows().catch(() => [] as WorkflowRecord[])
  if (existing.length > 0) return
  await admin.upsertWorkflow({
    name: '标准分析',
    description: '默认编排：上下文 → 取证 → 基线核对 → 关联 → 结论。阶段是提纲，可按需调整。',
    stages: DEFAULT_WORKFLOW_STAGES,
    enabled: true,
    isDefault: true,
  }, nowIso).catch(() => null)
}

/** 一个项目的运行时（MCP 客户端 + 领取循环 + 分析器 + 抑制同步）。 */
export class ProjectRuntime {
  readonly projectId: string
  readonly store: DataStore
  private record: ProjectRecord
  private readonly config: ProjectRuntimeConfig
  private readonly agents: AgentsServiceLike
  private readonly admin: ProjectAdminStore
  private readonly sessions: SessionProjects
  private readonly gate: ConcurrencyGate
  private readonly breaker: FailureBreaker
  private client: McpHttpClient | null = null
  private ndr: NdrTaskPortAdapter | null = null
  private analyst: Analyst | null = null
  /** 轻量初筛（低阶模型闸门）：配置每任务现取，控制台改了下一个任务就生效。 */
  private lightTriage: LightTriage | null = null
  private light: LightTriageConfig = DEFAULT_LIGHT_TRIAGE
  private loop: ClaimLoop | null = null
  private syncSuppressions: (() => Promise<void>) | null = null
  private workflowRecord: WorkflowRecord | null = null
  private lastError = ''

  constructor(deps: {
    readonly project: ProjectRecord
    readonly store: DataStore
    readonly config: ProjectRuntimeConfig
    readonly agents: AgentsServiceLike
    readonly admin: ProjectAdminStore
    readonly sessions: SessionProjects
    readonly gate: ConcurrencyGate
  }) {
    this.record = deps.project
    this.projectId = deps.project.projectId
    this.store = deps.store
    this.config = deps.config
    this.agents = deps.agents
    this.admin = deps.admin
    this.sessions = deps.sessions
    this.gate = deps.gate
    this.breaker = new FailureBreaker({
      threshold: deps.config.breakerThreshold,
      baseCooldownMs: deps.config.breakerBaseMs,
      maxCooldownMs: deps.config.breakerMaxMs,
    })
  }

  get project(): ProjectRecord {
    return this.record
  }

  /** 当前生效的运行参数（领取循环可就地改）。 */
  settings(): RuntimeSettings {
    const base = this.loop?.settingsSnapshot() ?? {
      pollSeconds: this.config.pollSeconds,
      maxConcurrent: this.config.maxConcurrent,
      claimLimit: this.config.claimLimit,
    }
    return { ...base, light: this.light }
  }

  /** 轻量初筛配置快照（控制台回显/status 用）。 */
  lightSettings(): LightTriageConfig {
    return { ...this.light, kinds: [...this.light.kinds] }
  }

  /** 只有「校验通过 + 循环在跑」才算 enabled；控制台据此显示"分析中"。 */
  get running(): boolean {
    return this.loop !== null
  }

  /**
   * 校验绑定并启动本项目。
   *
   * 校验两路：`server_info` 的 authId + 响应头 `x-ndr-auth-id`（客户端已校验并抽成
   * `serverInfo()`）；任一不一致 → 停（不启动循环），状态落库给控制台看。
   */
  async start(): Promise<ProjectRecord> {
    this.stop()
    if (this.agents === null) {
      this.lastError = 'agent 服务不可用，无法启动分析'
      return this.mark('unreachable', this.lastError)
    }
    if (this.record.mcpToken.trim() === '') {
      this.lastError = '未配置 MCP 令牌，只收门铃不分析'
      return this.mark('unchecked', this.lastError)
    }
    this.client = new McpHttpClient({
      url: this.record.mcpUrl,
      token: this.record.mcpToken,
      clientName: 'xdr-ingest',
      clientVersion: '0.2.0',
      ...(this.config.mcpFetch === undefined ? {} : { fetchImpl: this.config.mcpFetch }),
    })
    this.ndr = new NdrTaskPortAdapter(this.client)
    let info: { authId: string, source: string, stable: boolean }
    try {
      info = await this.ndr.serverInfo()
    } catch (error) {
      // 校验失败也要清掉半成品 client/ndr：否则下一轮 verify() 看到 client 非空，
      // 只会把状态改回 ok，却不会重新起循环（网络恢复后项目一直显示"停用"）。
      this.stop()
      this.lastError = `绑定校验失败：${this.message(error)}`
      return this.mark('unreachable', this.lastError)
    }
    if (info.authId === '' || info.authId !== this.projectId) {
      this.stop()
      this.lastError = `授权ID 不一致：项目 ${this.projectId} / NDR ${info.authId || '(空)'}`
      return this.mark('auth_mismatch', this.lastError)
    }
    this.workflowRecord = await resolveWorkflow(this.admin, this.record.workflowId)
    // 每项目模型：`provider/model`；空则回落到全局配置（三处兜底：项目 → 配置 → DSH 默认）
    const [modelProvider, modelName] = splitModel(this.record.model)
    const [fallbackProvider, fallbackName] = splitModel(this.record.fallbackModel)
    // 初筛器只建一次：配置经 getter 现取（改配置不用重启、不用换实例），
    // 熔断状态也因此跨任务保留。
    this.lightTriage = new LightTriage({ config: () => this.light })
    const analyst = new Analyst({
      agents: this.agents,
      ndr: this.ndr,
      timeoutMs: this.config.analysisTimeoutSeconds * 1000,
      source: 'xdr-ingest',
      ...(modelProvider !== '' ? { provider: modelProvider } : {}),
      ...(modelName !== '' ? { model: modelName } : {}),
      ...(fallbackName !== '' ? { fallbackModel: { provider: fallbackProvider, model: fallbackName } } : {}),
      ...(fallbackName === '' && this.config.provider.trim() !== '' ? { provider: this.config.provider.trim() } : {}),
      ...(fallbackName === '' && this.config.model.trim() !== '' ? { model: this.config.model.trim() } : {}),
      taskResults: this.store,
      taskReuseTtlMs: this.config.taskReuseTtlHours * 3_600_000,
      taskReuseStrengthDelta: this.config.taskReuseStrengthDelta,
      taskSeen: this.store,
      process: this.store,
      conclusions: this.store,
      lightTriage: this.lightTriage,
      projectId: this.projectId,
      // 每次起会话都取当前绑定：控制台换模版后下一个任务立刻生效（不用重启）
      workflow: () => this.workflowRecord,
      // 单任务预算与停滞：读会话日志计数，超了取消并延后（比只看 1200s 超时准）
      probeSession: async sessionId => {
        const timeline = await readSessionTimeline(this.config.sessionDir, sessionId, {})
        if (!timeline.ok) return null
        const last = timeline.events.length > 0 ? timeline.events[timeline.events.length - 1] : null
        return {
          tools: timeline.tools.reduce((sum, item) => sum + item.count, 0),
          lastEventAt: last?.time ?? 0,
        }
      },
      maxTools: this.config.maxToolsPerTask,
      stallMinutes: this.config.stallMinutes,
      onSession: (sessionId, phase) => {
        if (phase === 'start') this.sessions.set(sessionId, this.projectId)
        else this.sessions.delete(sessionId)
      },
    })
    this.analyst = analyst
    const ndr = this.ndr
    this.syncSuppressions = async (): Promise<void> => {
      const items = await ndr.listSuppressions()
      let marked = 0
      for (const item of items) {
        if (!item.enabled) continue
        if (item.sourceTaskId !== '') {
          if (await this.store.markSuppressed(item.sourceTaskId, item.name)) marked += 1
        }
        const identity = identityOfMatch(item.match)
        if (identity === null) continue
        marked += await this.store.markSuppressedByIdentity(identity, item.name)
      }
      if (marked > 0) {
        console.log(`[xdr-ingest] ${this.projectId} 抑制记忆已同步：${marked} 条现象标记为不再分析`)
      }
    }
    const loop = new ClaimLoop({
      pollSeconds: this.settings().pollSeconds,
      maxConcurrent: this.settings().maxConcurrent,
      claimLimit: this.settings().claimLimit,
      doorbellDebounceMs: this.config.doorbellDebounceMs,
      backoffMaxMs: this.config.backoffMaxMs,
      // 熔断打开时不领活（服务还在，只是暂停）；全局闸门没空位也不领，避免领了跑不动
      claimTasks: async limit => {
        if (this.breaker.isOpen()) return { tasks: [] }
        const capacity = Math.min(limit, this.gate.free())
        if (capacity <= 0) return { tasks: [] }
        return ndr.claimTasks(capacity)
      },
      runTask: async task => {
        if (!this.gate.tryAcquire()) {
          await ndr.deferTask(task.id, 'agent_busy').catch(() => undefined)
          return
        }
        try {
          const outcome = await analyst.run(task)
          const failure = outcome.completed ? '' : (outcome.error ?? '')
          if (outcome.completed) {
            this.breaker.recordSuccess()
          } else if (isTransientFailure(failure) && this.breaker.recordFailure(failure)) {
            const state = this.breaker.state()
            console.error(
              `[xdr-ingest] ${this.projectId} 连续失败，暂停领取 ${state['retry_in_seconds']} 秒`
              + `（${state['last_error']}）`,
            )
            void sendAlert(this.config.alertWebhookUrl, {
              event: 'breaker_open',
              project: this.projectId,
              message: `连续失败 ${String(state['failures'])} 次，暂停领取 ${String(state['retry_in_seconds'])} 秒`,
              detail: state,
            })
          }
          if (!outcome.completed) {
            console.warn(
              `[xdr-ingest] ${this.projectId} 任务 ${task.id} 未交回（state=${outcome.state || 'unknown'}，`
              + `${outcome.deferred ? '已延后' : '延后失败'}）`,
            )
          }
        } finally {
          this.gate.release()
        }
      },
    })
    this.loop = loop
    // 控制台保存过的运行参数优先于配置默认值（按项目各自保存）
    const saved = await this.store.loadSettings().catch(() => null)
    if (saved !== null) {
      const merged = mergeSettings(this.settings(), saved)
      if ('error' in merged) {
        console.warn(`[xdr-ingest] ${this.projectId} 已保存的运行参数不合法，忽略：`, merged.error)
      } else {
        loop.configure(merged.settings)
        this.light = merged.settings.light ?? DEFAULT_LIGHT_TRIAGE
      }
    }
    loop.start()
    this.lastError = ''
    void this.syncSuppressions().catch(() => undefined)
    console.log(
      `[xdr-ingest] 项目已启动：${this.record.name}（授权ID ${this.projectId}，`
      + `来源 ${info.source}${info.stable ? '' : '，不稳定'}）`,
    )
    return this.mark('ok', '')
  }

  /** 停掉循环（保留项目行与数据；重启时再起）。 */
  stop(): void {
    this.loop?.stop()
    this.loop = null
    this.analyst = null
    this.lightTriage = null
    this.syncSuppressions = null
    this.ndr = null
    this.client = null
    if (this.record.enabled) this.record = { ...this.record, status: 'disabled' }
  }

  /** 运行期复核（定时器/控制台手动）：不一致或不可达就停掉本项目。 */
  async verify(): Promise<ProjectRecord> {
    // loop 为空也必须重新 start：网络中断时 start() 可能在 serverInfo 之前就建好了
    // client，旧逻辑只判断 client/ndr，恢复后会把状态标成 ok 但循环永远起不来。
    if (this.client === null || this.ndr === null || this.loop === null) {
      return this.start()
    }
    try {
      const info = await this.ndr.serverInfo()
      if (info.authId !== this.projectId) {
        const detail = `授权ID 不一致：项目 ${this.projectId} / NDR ${info.authId || '(空)'}`
        this.stop()
        return this.mark('auth_mismatch', detail)
      }
      return this.mark('ok', '')
    } catch (error) {
      const detail = `NDR 不可达：${this.message(error)}`
      this.stop()
      return this.mark('unreachable', detail)
    }
  }

  wake(): void {
    this.loop?.wake()
  }

  /** 运行参数：就地改循环 + 按项目落库（含轻量初筛配置，同样热生效）。 */
  async configure(patch: unknown): Promise<{
    ok: boolean
    error?: string
    persisted?: boolean
    settings?: Record<string, number>
    light?: LightTriageConfig
  }> {
    const merged = mergeSettings(this.settings(), patch)
    if ('error' in merged) return { ok: false, error: merged.error }
    this.loop?.configure(merged.settings)
    // LightTriage 的 getter 每任务现取 this.light：改配置不用重启、不用换实例
    this.light = merged.settings.light ?? DEFAULT_LIGHT_TRIAGE
    const persisted = await this.store.saveSettings(merged.settings)
    if (!persisted) {
      console.warn(`[xdr-ingest] ${this.projectId} 运行参数只在内存生效：写入失败，重启后会回到上次成功保存的值。`)
    }
    return { ok: true, persisted, settings: settingsView(merged.settings), light: this.light }
  }

  status(): Record<string, unknown> {
    return {
      id: this.projectId,
      name: this.record.name,
      status: this.record.status,
      detail: this.record.statusDetail || this.lastError,
      running: this.loop !== null,
      last_checked_at: this.record.lastCheckedAt,
      mcp_url: this.record.mcpUrl,
      workflow_id: this.workflowRecord?.workflowId ?? this.record.workflowId,
      workflow_name: this.workflowRecord?.name ?? '',
      model: this.record.model,
      breaker: this.breaker.state(),
      ...settingsView(this.settings()),
      light_triage: {
        enabled: this.light.enabled,
        model: this.light.model,
        endpoint: this.light.baseUrl,
        threshold: this.light.threshold,
        audit_rate: this.light.auditRate,
        kinds: [...this.light.kinds],
        ...(this.lightTriage === null ? {} : { stats: this.lightTriage.stats() }),
      },
      ...(this.analyst === null ? {} : { task_reuse: this.analyst.reuseStats }),
      ...(this.loop === null ? {} : { loop: this.loop.stats }),
    }
  }

  async syncNow(): Promise<void> {
    if (this.syncSuppressions === null) return
    await this.syncSuppressions()
  }

  /** 换绑工作流：更新内存绑定（下一个任务生效）并把模版 ID 落库。 */
  async applyWorkflow(workflowId: string): Promise<void> {
    this.workflowRecord = await resolveWorkflow(this.admin, workflowId)
    this.record = { ...this.record, workflowId: workflowId.trim() }
    await this.admin.setProjectWorkflow(this.projectId, workflowId).catch(() => false)
  }

  /** 行为基线事实：走 MCP 读 NDR（事实在 NDR 库里，agent 不存副本）。 */
  async listObservations(query: {
    kind?: string, subject?: string, minutes?: number, limit?: number, offset?: number,
  }): Promise<Record<string, unknown>> {
    if (this.ndr === null) return { available: false, total: 0, items: [] }
    return this.ndr.listObservations(query)
  }

  /** 会话时间线（分析过程页；`after` 用于实时轮询只取新增事件）。 */
  sessionTimeline(sessionId: string, options: { after?: number, running?: boolean } = {}): Promise<SessionTimeline> {
    return readSessionTimeline(this.config.sessionDir, sessionId, options)
  }

  /** 显式失败（门铃/绑定不一致时由管理器调用）：停掉循环并落状态。 */
  async fail(status: ProjectStatus, detail: string): Promise<ProjectRecord> {
    this.stop()
    return this.mark(status, detail)
  }

  private async mark(status: ProjectStatus, detail: string): Promise<ProjectRecord> {
    this.lastError = detail
    await this.admin.setProjectStatus(this.projectId, status, detail).catch(() => undefined)
    this.record = { ...this.record, status, statusDetail: detail }
    if (detail !== '') console.warn(`[xdr-ingest] ${this.projectId}：${detail}`)
    if (status === 'auth_mismatch' || status === 'unreachable') {
      void sendAlert(this.config.alertWebhookUrl, {
        event: status === 'auth_mismatch' ? 'project_auth_mismatch' : 'project_unreachable',
        project: this.projectId,
        message: detail,
      })
    }
    return this.record
  }

  private message(error: unknown): string {
    return error instanceof Error ? error.message : String(error)
  }
}

/**
 * 多项目管理器：项目的增删改查 + 运行时启停 + 门铃路由。
 *
 * 控制台的所有接口都带 `project`，这里统一校验「项目存在且启用」；
 * 一致性校验由各 runtime 负责，失败只停那一个项目。
 */
export class ProjectManager {
  private readonly runtimes = new Map<string, ProjectRuntime>()
  /** 推送令牌 → 项目ID（即使项目暂时没起循环，门铃也要能认出来，别让 NDR 一直重推）。 */
  private readonly tokenIndex = new Map<string, string>()
  private readonly config: ProjectRuntimeConfig
  private readonly agents: AgentsServiceLike | null
  private readonly admin: ProjectAdminStore | null
  private readonly sessions: SessionProjects
  private readonly storeOf: (projectId: string) => DataStore
  private readonly gate: ConcurrencyGate

  constructor(deps: {
    readonly config: ProjectRuntimeConfig
    readonly agents: AgentsServiceLike | null
    readonly admin: ProjectAdminStore | null
    readonly sessions: SessionProjects
    readonly storeOf: (projectId: string) => DataStore
    readonly maxConcurrentTotal?: () => number
  }) {
    this.config = deps.config
    this.agents = deps.agents
    this.admin = deps.admin
    this.sessions = deps.sessions
    this.storeOf = deps.storeOf
    this.gate = new ConcurrencyGate(deps.maxConcurrentTotal ?? (() => 16))
  }

  /** 启动时加载所有项目：启用的逐个校验并起循环。 */
  async init(fallback?: ProjectInput): Promise<void> {
    if (this.admin === null) return
    let projects = await this.admin.listProjects().catch(() => [] as ProjectRecord[])
    if (projects.length === 0 && fallback !== undefined) {
      // 没配授权ID 的旧部署：先问 NDR 的 server_info，拿到再登记（拿不到就不建空项目）
      if (/^[A-Z0-9]{8}$/u.test(fallback.projectId)) {
        const created = await this.admin.upsertProject(fallback).catch(() => null)
        if (created !== null) projects = [created]
      } else {
        console.warn('[xdr-ingest] 还没有登记任何项目，且未配置 projectId：请到控制台「项目组织」新增项目')
      }
    }
    for (const project of projects) {
      if (project.pushToken.trim() !== '') this.tokenIndex.set(project.pushToken, project.projectId)
      if (!project.enabled) {
        this.recordDisabled(project)
        continue
      }
      await this.startProject(project)
    }
  }

  list(): Promise<ProjectRecord[]> {
    return this.admin?.listProjects() ?? Promise.resolve([])
  }

  get(projectId: string): ProjectRuntime | null {
    return this.runtimes.get(projectId.trim()) ?? null
  }

  /** 默认项目：只有一个时就是它；多个时不猜（返回 null，调用方必须带 project）。 */
  defaultProjectId(): string {
    const keys = [...this.runtimes.keys()]
    if (keys.length === 1) return keys[0] ?? ''
    const list = [...this.runtimes.values()]
    return list.length === 0 ? '' : (list[0]?.projectId ?? '')
  }

  /**
   * 新增/更新项目（控制台「项目组织」页）。
   *
   * 校验规则：
   * - 授权ID 必须是 8 位大写字母+数字（与 NDR `system_license` 同规则）；
   * - 先落库再校验（校验失败也要能在界面上看到并改）；
   * - 校验通过才起循环。
   */
  async save(input: ProjectInput & { readonly previousId?: string }): Promise<{ ok: boolean, error?: string, project?: ProjectRecord }> {
    if (this.admin === null) return { ok: false, error: 'state store 不可用（pgUrl 未配置）' }
    const projectId = input.projectId.trim().toUpperCase()
    if (!/^[A-Z0-9]{8}$/u.test(projectId)) {
      return { ok: false, error: '授权ID 必须是 8 位大写字母或数字（在 NDR 控制台「系统授权」页查看）' }
    }
    if (input.mcpUrl.trim() === '' || !/^https?:\/\//u.test(input.mcpUrl.trim())) {
      return { ok: false, error: 'MCP 地址必须是 http(s) URL' }
    }
    const previous = (input.previousId ?? projectId).trim().toUpperCase()
    const existing = await this.admin.getProject(projectId).catch(() => null)
    const project = await this.admin.upsertProject({
      projectId,
      name: input.name.trim() || existing?.name || projectId,
      mcpUrl: input.mcpUrl.trim(),
      mcpToken: input.mcpToken.trim(),
      pushToken: input.pushToken.trim(),
      enabled: input.enabled ?? existing?.enabled ?? true,
      // 模型/备用模型：DB 列与 ProjectInput 早就有，但控制台保存一直没透传（缺口顺手补上）。
      // 注意 upsert 的语义是「空串保留原值」，所以清空只能到库里改。
      ...(input.model !== undefined ? { model: input.model } : {}),
      ...(input.fallbackModel !== undefined ? { fallbackModel: input.fallbackModel } : {}),
    })
    if (project === null) return { ok: false, error: '保存项目失败（数据库不可用）' }
    if (previous !== projectId) {
      // 改授权ID = 换项目：新行落库成功后再停旧的（数据留在旧项目下，不迁）
      const old = this.runtimes.get(previous)
      if (old !== undefined) {
        old.stop()
        this.runtimes.delete(previous)
      }
      await this.admin.removeProject(previous).catch(() => false)
    }
    // 旧令牌解绑（换令牌后旧令牌不能再路由）
    for (const [token, id] of this.tokenIndex) {
      if (id === projectId && token !== project.pushToken) this.tokenIndex.delete(token)
    }
    if (project.pushToken.trim() !== '') this.tokenIndex.set(project.pushToken, projectId)
    if (!project.enabled) {
      const runtime = this.runtimes.get(projectId)
      runtime?.stop()
      const disabled = { ...project, status: 'disabled' as ProjectStatus }
      await this.admin.setProjectStatus(projectId, 'disabled', '').catch(() => undefined)
      return { ok: true, project: disabled }
    }
    const started = await this.startProject(project)
    return { ok: true, project: started }
  }

  async remove(projectId: string): Promise<boolean> {
    const id = projectId.trim().toUpperCase()
    this.runtimes.get(id)?.stop()
    this.runtimes.delete(id)
    for (const [token, owner] of this.tokenIndex) {
      if (owner === id) this.tokenIndex.delete(token)
    }
    return this.admin?.removeProject(id) ?? Promise.resolve(false)
  }

  /** 项目引用某个工作流（空串 = 用默认模版）。 */
  async bindWorkflow(projectId: string, workflowId: string): Promise<{ ok: boolean, error?: string }> {
    if (this.admin === null) return { ok: false, error: 'state store 不可用' }
    const id = projectId.trim().toUpperCase()
    const project = await this.admin.getProject(id).catch(() => null)
    if (project === null) return { ok: false, error: '项目不存在' }
    const target = (workflowId ?? '').trim()
    if (target !== '') {
      const workflow = await this.admin.getWorkflow(target).catch(() => null)
      if (workflow === null) return { ok: false, error: '工作流不存在' }
    }
    const runtime = this.runtimes.get(id)
    if (runtime !== undefined) {
      await runtime.applyWorkflow(target)
    } else {
      const done = await this.admin.setProjectWorkflow(id, target).catch(() => false)
      if (!done) return { ok: false, error: '保存失败' }
    }
    return { ok: true }
  }

  async verify(projectId: string): Promise<ProjectRecord | null> {
    const id = projectId.trim().toUpperCase()
    const runtime = this.runtimes.get(id)
    if (runtime !== undefined) return runtime.verify()
    const project = await this.admin?.getProject(id).catch(() => null)
    if (project === null || project === undefined) return null
    return this.startProject(project)
  }

  async verifyAll(): Promise<void> {
    for (const runtime of [...this.runtimes.values()]) {
      await runtime.verify().catch(() => undefined)
    }
  }

  /** 门铃路由：按推送令牌找项目；空令牌/未匹配返回 null（handler 回 401）。 */
  resolvePushToken(token: string): string | null {
    if (token.trim() === '') return null
    for (const runtime of this.runtimes.values()) {
      if (runtime.project.pushToken !== '' && runtime.project.pushToken === token) {
        return runtime.projectId
      }
    }
    return this.tokenIndex.get(token) ?? null
  }

  /**
   * 收到门铃：只叫醒对应项目。
   *
   * 门铃载荷里的 `project` 是 NDR 自报的授权ID；与令牌解析出的项目不一致，
   * 说明配对错了（典型：把 A 的推送地址配到了 B 的项目里）——停掉并报警。
   */
  async onDoorbell(projectId: string, declared: string): Promise<void> {
    const runtime = this.runtimes.get(projectId)
    if (runtime === undefined) return
    const fromNdr = declared.trim().toUpperCase()
    if (fromNdr !== '' && fromNdr !== projectId) {
      const detail = `门铃项目不一致：令牌属于 ${projectId}，门铃声明 ${fromNdr}`
      console.error(`[xdr-ingest] ${detail}：已停用该项目`)
      await runtime.fail('auth_mismatch', detail).catch(() => undefined)
      return
    }
    runtime.wake()
  }

  all(): ProjectRuntime[] {
    return [...this.runtimes.values()]
  }

  projectIds(): string[] {
    return [...this.runtimes.keys()]
  }

  status(): Record<string, unknown> {
    const projects = [...this.runtimes.values()].map(runtime => runtime.status())
    return {
      project_count: projects.length,
      enabled: projects.filter(p => (p as { running?: boolean }).running === true).length,
      concurrency: this.gate.state(),
      projects,
    }
  }

  /** 保留期清理（管理台设置里改天数，这里只执行）。 */
  async maintenance(policy: {
    conclusionsDays: number, processesDays: number, observationsDays: number,
    egressDays: number, taskSeenDays: number,
  }): Promise<Record<string, number>> {
    return this.admin?.maintenance(policy) ?? {}
  }

  async stopAll(): Promise<void> {
    for (const runtime of this.runtimes.values()) runtime.stop()
    this.runtimes.clear()
  }

  private recordDisabled(project: ProjectRecord): void {
    void this.admin?.setProjectStatus(project.projectId, 'disabled', '').catch(() => undefined)
  }

  private async startProject(project: ProjectRecord): Promise<ProjectRecord> {
    if (project.enabled === false) {
      this.recordDisabled(project)
      return { ...project, status: 'disabled' }
    }
    if (this.agents === null) {
      await this.admin?.setProjectStatus(project.projectId, 'unreachable', 'agent 服务不可用').catch(() => undefined)
      return { ...project, status: 'unreachable', statusDetail: 'agent 服务不可用' }
    }
    const existing = this.runtimes.get(project.projectId)
    existing?.stop()
    const runtime = new ProjectRuntime({
      project,
      store: this.storeOf(project.projectId),
      config: this.config,
      agents: this.agents,
      admin: this.admin as ProjectAdminStore,
      sessions: this.sessions,
      gate: this.gate,
    })
    this.runtimes.set(project.projectId, runtime)
    return runtime.start()
  }
}

export type { DataStore }
