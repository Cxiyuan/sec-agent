/**
 * 一次分析会话的完整生命周期：起 agent → 喂提示词 → 等空闲 → **确认交回** → 收尾。
 *
 * 为什么"确认交回"是单独一步（`task_state`）：
 * 会话空闲 **不等于** 任务完成 —— 模型很可能查完就收工、忘了 `complete_task`。
 * 不查这一步，任务会一直挂着直到租约到期被回收，`attempts` 累加，
 * 最后进 `stuck`（表面上"智能体在跑"，实际什么都没交）。
 */

import { defineTool } from '@deepseek-ai/dsh-tools'
import type { AgentsServiceLike } from './agent-port.ts'
import type { WorkflowRecord } from './state-store.ts'
import type { ClaimedTask, NdrPort } from './claim-loop.ts'
import type { LightTriagePort, TriageResult } from './light-triage.ts'
import { buildAnalysisPrompt } from './prompt.ts'
import { ALWAYS_DENY_TOOLS, planToolGroups, TOOL_GROUP_NAMES } from './tool-groups.ts'
import { registerRdapTool } from './rdap.ts'
import type { SessionAudit } from './session-audit.ts'
import { reuseDecision, taskIdentity, taskResultKey } from './task-results.ts'
import type { SuppressedTask, TaskResultRecord, TaskResultStore } from './task-results.ts'
import type { ConclusionStore, ProcessStore, TaskSeenStore } from './state-store.ts'
import type { ConclusionRecord } from './conclusions.ts'

/** `task_state` 里的一条历史结论（最新在前）。 */
export interface TaskResultView {
  readonly verdict?: string
  readonly terminal_reason?: string
  readonly confidence?: number
  readonly summary?: string
  readonly findings?: unknown
  readonly verdict_basis?: Record<string, unknown>
  readonly facts_hash?: string
  /** NDR 侧运行关联（旧 NDR 不返回）。 */
  readonly session_id?: string
  readonly attempt?: number
  readonly evidence_refs?: readonly string[]
  /** B2：结论挂的资产锚点（复用回放用；旧 NDR 不返回）。 */
  readonly anchors?: readonly { readonly kind?: string; readonly value?: string }[]
  /** B6：一句话建议（NDR 已提升成一等字段；旧版本只存在于 findings）。 */
  readonly recommendation?: string
  readonly tools_used?: number
  readonly duration_ms?: number
  readonly created_at?: string
}

/** 会话结束后任务应处的状态（NDR `task_state` 的返回形状）。 */
export interface TaskStateReply {
  readonly state?: string
  readonly task_state?: string
  readonly result_id?: string
  readonly verdict?: string
  readonly error?: string
  readonly results?: readonly TaskResultView[]
}

/** 直接交回（复用命中）的回执。 */
export interface CompleteReply {
  readonly ok?: boolean
  readonly task_state?: string
  readonly state?: string
  readonly error?: string
}

/** 复用成功时交回的载荷（不引用上次会话的证据：引用只在产出它的会话里有效）。 */
export interface ReusePayload {
  readonly verdict: string
  readonly summary: string
  readonly confidence: number
  readonly findings: Record<string, unknown>
  /** 结构化判断依据（hypothesis/evidence_categories/contradictions）。 */
  readonly verdict_basis?: Record<string, unknown>
  /** B2 回放：上次结论挂的资产（锚点），让复用行同样影响这些资产。 */
  readonly anchors?: readonly { readonly kind: string; readonly value: string }[]
  /** B2 回放：上次结论的一句话建议（B6 字段）。 */
  readonly recommendation?: string
  readonly terminal_reason: string
  readonly tools_used: number
  readonly duration_ms: number
}

export interface NdrTaskPort extends NdrPort {
  taskState(taskId: string): Promise<TaskStateReply>
  /** 复用命中时直接交回；正常分析由模型自己调 `complete_task`。 */
  completeTask(taskId: string, payload: ReusePayload): Promise<CompleteReply>
  /**
   * 把本次 attempt 的 DSH 运行事实写回 NDR（与模型叙事分开）。
   * 失败只告警：审计不能反过来让已经交回的任务失败。
   */
  recordAudit?(taskId: string, payload: Record<string, unknown>): Promise<unknown>
  deferTask(taskId: string, reason: string): Promise<unknown>
  /** 生效中的精准抑制清单（抑制记忆的来源；不实现 = 不做抑制记忆）。 */
  /** null = 本次同步失败（不要据此清空本地抑制记忆）。 */
  listSuppressions?(): Promise<readonly SuppressionView[] | null>
  /** 本 NDR 的授权ID（`server_info`）：项目组织绑定校验用；不实现 = 跳过校验。 */
  serverInfo?(): Promise<{ readonly authId: string, readonly source: string, readonly stable: boolean }>
}

/** NDR 侧一条精准抑制（只要抑制记忆用得到的几个字段）。 */
export interface SuppressionView {
  readonly id: string
  readonly name: string
  /** suppress = 事件都不生成；record_only = 事件保留但不派工。 */
  readonly mode: string
  readonly enabled: boolean
  /** 提交这条抑制的那个任务（智能体自己提交时才有）。 */
  readonly sourceTaskId: string
  /** 任务级抑制的 canonical identity（事件级为空）。 */
  readonly reuseIdentity?: string
  /** 任务级抑制对应的 task kind（事件级为空）。 */
  readonly taskKind?: string
  /** 条件树（用来按对象粗匹配没有任务 id 的抑制）。 */
  readonly match: unknown
}

export interface AnalystOptions {
  readonly agents: AgentsServiceLike
  readonly ndr: NdrTaskPort
  /** 单会话超时（毫秒）——超时先 cancel 再 defer，别让它无限占着并发槽 */
  readonly timeoutMs: number
  readonly provider?: string
  readonly model?: string
  /** Current DSH default selection (read for each task so Settings changes take effect). */
  readonly modelSelection?: () => { readonly provider: string, readonly model: string } | undefined
  /** 事件来源标记（出现在会话记录里，便于回溯是哪段代码起的） */
  readonly source?: string
  /** 同类现象结论库；不传 = 不复用（测试/回滚）。 */
  readonly taskResults?: TaskResultStore
  /** 抑制记忆（"这类现象已被精准抑制"）；不传 = 不跳过。 */
  readonly taskSeen?: TaskSeenStore
  /** 分析过程索引（任务 → 会话）；不传 = 不记录。 */
  readonly process?: ProcessStore
  /** 结论留档（控制台「分析记录」的数据源）；不传 = 不留档。 */
  readonly conclusions?: ConclusionStore
  /** 轻量初筛（低阶模型闸门）；不传 = 不做初筛，一切任务走付费会话。 */
  readonly lightTriage?: LightTriagePort
  /** 当前项目（NDR 授权ID），写进结论留档；空串 = 未知项目。 */
  readonly projectId?: string
  /** 复用有效期（毫秒，从上次真实分析起算；0 = 关闭复用）。 */
  readonly taskReuseTtlMs?: number
  /** 新线索强度比上次高多少就必须重查（现象变强）。 */
  readonly taskReuseStrengthDelta?: number
  /**
   * 复用必须带 NDR 下发的稳定身份（`hint.reuse_identity`，默认 true）。
   * 回滚开关：旧版 NDR 不发身份时临时置 false，退回按 kind|subject|feature 拼键。
   */
  readonly taskReuseRequireIdentity?: boolean
  /**
   * 会话生命周期回调（多项目）：脚本工具靠 sessionId 找「这次分析属于哪个项目」。
   * 起会话前 `start`，会话收尾后 `end`。
   */
  readonly onSession?: (sessionId: string, phase: 'start' | 'end') => void
  /** 分析工作流（项目组织引用）：可以是固定模版，也可以是每次取最新绑定的 getter。 */
  readonly workflow?: WorkflowRecord | null | (() => WorkflowRecord | null)
  /** 主模型连续失败时切备用（下一轮生效）。 */
  readonly fallbackModel?: { readonly provider: string, readonly model: string }
  /** 单任务工具调用上限（0 = 不限）。 */
  readonly maxTools?: number
  /** 停滞判定（分钟，0 = 不判）：超过这么久没有新事件只告警，不取消（可能只是模型慢）。 */
  readonly stallMinutes?: number
  /** 会话探针间隔（毫秒）；默认 15 秒，测试里调小。 */
  readonly probeIntervalMs?: number
  /** 会话进度探针（读会话日志：工具调用数 + 最后事件时间）。 */
  readonly probeSession?: (sessionId: string) => Promise<{ tools: number, lastEventAt: number } | null>
  /** 会话结束后的 DSH 审计投影（工具调用/tokens/turn 终态/错误）。 */
  readonly sessionAudit?: (sessionId: string) => Promise<SessionAudit | null>
  /**
   * 首轮会话结束但任务未交回时，是否重发一次任务提示（默认 true）。
   * 关掉 = 保持旧行为（直接回查/延后），测试与严格部署可用。
   */
  readonly retryUnfinishedTurn?: boolean
}

export interface AnalystOutcome {
  readonly taskId: string
  readonly completed: boolean
  readonly state: string
  readonly deferred: boolean
  readonly durationMs: number
  readonly error?: string
  /** true = 没有起会话，直接复用了同类现象的既往结论。 */
  readonly reused?: boolean
  /** true = 没有起会话，由轻量初筛（低阶模型）单轮判定关单。 */
  readonly triaged?: boolean
  /** 没起会话时，为什么做了这个决定（复用来源/抑制名/初筛模型）。 */
  readonly decision?: Record<string, unknown>
  /** 本次 attempt（正常会话从 1 起；没起会话为 0）。 */
  readonly attempt?: number
}

/** 轻量初筛一次尝试的结果：要么关单成功，要么带回抽检预判（升级付费时留痕）。 */
interface LightTriageAttempt {
  readonly closed?: { verdict: string, confidence: number, summary: string, model: string, ms: number }
  readonly audit?: { verdict: string, confidence: number, model: string }
}

let sessionCounter = 0

export class Analyst {
  private readonly options: AnalystOptions
  private readonly reuse = { reused: 0, stored: 0, rejected: 0, identityMissing: 0 }
  /** 主模型刚失败过：下一轮用备用模型（成功即恢复）。 */
  private preferFallback = false
  /** 同一现象的并发任务排队：后来的任务等前一个写入结论后再查缓存。 */
  private readonly keyLocks = new Map<string, Promise<void>>()

  constructor(options: AnalystOptions) {
    this.options = options
  }

  /** 复用/入库计数（`/status` 观测用）。 */
  get reuseStats(): {
    readonly reused: number
    readonly stored: number
    /** 复用被拒次数（过期/更强/suspicious/终端原因…，Phase 3 指标看板用） */
    readonly rejected: number
    /** 任务缺 NDR 下发身份而跳过复用的次数（B1：拒绝跨现象复用） */
    readonly identityMissing: number
  } {
    return { ...this.reuse }
  }

  async run(task: ClaimedTask): Promise<AnalystOutcome> {
    const key = taskResultKey(task)
    if (key === null) {
      if (taskResultKey(task, { requireIdentity: false }) !== null) this.reuse.identityMissing += 1
      return this.runUnlocked(task)
    }

    const previous = this.keyLocks.get(key)
    let release!: () => void
    const lock = new Promise<void>(resolve => { release = resolve })
    this.keyLocks.set(key, lock)
    if (previous !== undefined) await previous
    try {
      return await this.runUnlocked(task)
    } finally {
      release()
      if (this.keyLocks.get(key) === lock) this.keyLocks.delete(key)
    }
  }

  private async runUnlocked(task: ClaimedTask): Promise<AnalystOutcome> {
    const startedAt = Date.now()
    const reused = await this.tryReuse(task, startedAt)
    if (reused !== null) {
      this.reuse.reused += 1
      console.log(
        `[xdr-ingest] 任务 ${task.id} 命中同类现象结论复用（${task.kind}/${task.subject}），`
        + '未起分析会话',
      )
      const decision = { action: 'reuse', ...(reused.decision ?? {}) }
      await this.finishProcess(task, 'reused', startedAt, {
        note: '同类现象结论复用（未起会话）',
        verdict: String(reused.decision?.['verdict'] ?? ''),
        sessionId: '',
        model: 'reuse',
        toolsUsed: 0,
        toolErrors: 0,
        tokens: tokenUsageOf(null),
        decision,
      })
      await this.sendAudit(task, {
        sessionId: '',
        attempt: 0,
        outcome: 'reused',
        verdict: String(reused.decision?.['verdict'] ?? ''),
        decision,
        startedAt,
        model: 'reuse',
      })
      return reused
    }

    // 抑制记忆：这类现象已经被精准抑制过 → 不起会话、不取数，直接交回。
    const suppressed = await this.trySuppressed(task, startedAt)
    if (suppressed !== null) {
      const decision = { action: 'suppressed', ...(suppressed.decision ?? {}) }
      await this.finishProcess(task, 'suppressed', startedAt, {
        note: '已被精准抑制（未起会话）',
        verdict: 'false_positive',
        sessionId: '',
        model: 'suppression-memory',
        toolsUsed: 0,
        toolErrors: 0,
        tokens: tokenUsageOf(null),
        decision,
      })
      await this.sendAudit(task, {
        sessionId: '',
        attempt: 0,
        outcome: 'suppressed',
        verdict: 'false_positive',
        decision,
        startedAt,
        model: 'suppression-memory',
      })
      return suppressed
    }

    // 轻量初筛（低阶模型闸门）：复用/抑制都没命中才轮到它。它只有「排除权」——
    // 只收得下通过全部硬约束的 benign/误报判定；拿不准/输出不合法/调用失败
    // 一律返回空对象，落到下面的付费会话（fail-open：初筛是省钱手段，不是正确性前提）。
    const triage = await this.tryLightTriage(task)
    if (triage.closed !== undefined) {
      const closed = triage.closed
      const decision = {
        action: 'light_triage',
        model: closed.model,
        verdict: closed.verdict,
        confidence: closed.confidence,
      }
      await this.finishProcess(task, 'triaged', startedAt, {
        verdict: closed.verdict,
        note: `轻量初筛关单：${closed.verdict}（${closed.model} 置信度 ${closed.confidence}）`,
        model: `light:${closed.model}`,
        sessionId: '',
        toolsUsed: 0,
        toolErrors: 0,
        tokens: tokenUsageOf(null),
        decision,
      })
      await this.sendAudit(task, {
        sessionId: '',
        attempt: 0,
        outcome: 'triaged',
        verdict: closed.verdict,
        decision,
        startedAt,
        model: `light:${closed.model}`,
      })
      return {
        taskId: task.id,
        completed: true,
        state: 'done',
        deferred: false,
        durationMs: Date.now() - startedAt,
        triaged: true,
      }
    }
    // 抽检样本：初筛本可关单，但被抽中送付费复核 —— 预判跟着会话走，事后可比对
    const audit = triage.audit
    const auditNote = audit === undefined
      ? ''
      : `抽检复核：初筛判 ${audit.verdict}（${audit.model} 置信度 ${audit.confidence}），已送付费复核`

    const sessionId = `xdr-analysis-${task.id}-${Date.now()}-${sessionCounter++}`
    const selected = this.options.modelSelection?.()
    const fallback = this.options.fallbackModel
    const useFallback = this.preferFallback && fallback !== undefined && fallback.model !== ''
    const provider = useFallback
      ? (fallback.provider || selected?.provider.trim())
      : (this.options.provider?.trim() || selected?.provider.trim())
    const model = useFallback
      ? fallback.model
      : (this.options.model?.trim() || selected?.model.trim())
    // 过程索引：控制台据此列出「任务 → 会话 → 耗时/工具数/状态」，并读会话时间线
    const workflow = typeof this.options.workflow === 'function'
      ? this.options.workflow()
      : this.options.workflow ?? null
    const attempt = await this.options.process?.startProcess({
      taskId: task.id,
      sessionId,
      kind: task.kind,
      subject: task.subject,
      model: [provider, model].filter(v => (v ?? '') !== '').join('/'),
      startedAt: new Date(startedAt).toISOString(),
      workflowId: workflow?.workflowId ?? '',
      workflowName: workflow?.name ?? '',
      workflowStages: workflow?.stages ?? [],
    }) ?? 0
    this.options.onSession?.(sessionId, 'start')
    // 项目级 cwd：DSH 的 session_search/session_trace 只允许同 cwd 会话互查。
    // 不传时 header.cwd 为空，所有历史工具都只能看到当前会话本身。
    const project = (this.options.projectId ?? '').trim().replace(/[^A-Za-z0-9._-]/gu, '') || 'default'
    const handle = await this.options.agents.create({
      sessionId,
      meta: { cwd: `/xdr/${project}` },
      agentOptions: {
        ...(provider ? { provider } : {}),
        ...(model ? { model } : {}),
      },
      // 每个分析会话只处理派给它的那条任务：把 claim_tasks 从工具面里拿掉。
      // 否则模型会自己去领别的任务、把别人的任务做完，而本任务一直是 claimed，
      // Analyst 回查时判定「未交回」并延后。
      setup: (agentCtx) => {
        // claim_tasks 必须无条件拿掉：即使 schemas() 暂不可用，也不能让模型
        // 去领别的任务，导致本任务一直停在 claimed。
        try {
          agentCtx.tools?.restrict?.({ deny: [...ALWAYS_DENY_TOOLS] })
        } catch (error) {
          console.warn(
            '[xdr-ingest] 无法禁用 claim_tasks 工具，仅靠提示词约束：',
            error instanceof Error ? error.message : String(error),
          )
        }
        // 工具面默认只保留核心取证工具；罕见能力通过 enable_analysis_tools
        // 按组激活。工具始终注册在 registry 里，不会因为 24 小时未调用而删除。
        const available = (agentCtx.tools?.schemas?.() ?? []).map(tool => tool.name)
        const planned = planToolGroups(available)
        const groupDisposers = new Map<string, () => void>()

        let loaderReady = false
        try {
          if (typeof agentCtx.tools?.register !== 'function') {
            throw new Error('agent tools.register 不可用')
          }
          agentCtx.tools.register(defineTool({
            name: 'enable_analysis_tools',
            description:
              '默认工具面只含常用取证工具。需要扩展能力时调用本工具：'
              + 'group=network（DNS/TLS/代理/观测/资产地图/基线）、'
              + 'identity（server_info/覆盖率）、evidence（文件内容）、'
              + 'task（任务状态/统计/延迟/规则/轨迹）、suppression（已有抑制清单）、'
              + 'schedule（定时任务）、deliverable（交付物）、'
              + 'other（未分组的新工具）、'
              + 'all（全部）。激活后下一轮工具列表生效；不确定时用 all。'
              + '不要因为当前列表看不到某个 NDR 工具就放弃取证。',
            parameters: {
              group: {
                type: 'string',
                enum: TOOL_GROUP_NAMES,
                required: true,
                description: '要激活的工具组；不确定时选 all。',
              },
            },
            output: {
              schema: { type: 'string' as const },
              render: (_args, value) => [{ type: 'text' as const, text: value }],
            },
            execute: async ({ group }) => {
              const requested = group === 'all'
                ? [...groupDisposers.keys()]
                : [group]
              const activated: string[] = []
              for (const name of requested) {
                const dispose = groupDisposers.get(name)
                if (dispose === undefined) continue
                dispose()
                groupDisposers.delete(name)
                activated.push(...(planned.groups[name] ?? []))
              }
              if (activated.length === 0) {
                return `没有可激活的工具组「${group}」。当前可用组：${[...groupDisposers.keys()].join(', ') || '无'}。`
              }
              return `已激活 ${group} 组：${activated.join(', ')}。下一轮请求会带上这些工具，继续取证即可。`
            },
          }))
          loaderReady = true
        } catch (error) {
          console.warn(
            '[xdr-ingest] 无法注册 enable_analysis_tools，工具面不会按需扩展：',
            error instanceof Error ? error.message : String(error),
          )
        }
        // 动态 RDAP 属于分析端取证：NDR 不承担外网查询；每个会话注册本地工具。
        try {
          registerRdapTool(agentCtx)
        } catch (error) {
          console.warn(
            '[xdr-ingest] 无法注册 rdap_lookup：',
            error instanceof Error ? error.message : String(error),
          )
        }
        // 只有加载工具确实注册成功才隐藏罕见工具组；否则宁可多带 schema，
        // 也不能让模型看得见“按需激活”的说明却没有任何恢复入口。
        if (loaderReady && planned.core.length > 0) {
          try {
            for (const [group, tools] of Object.entries(planned.groups)) {
              const dispose = agentCtx.tools?.restrict?.({ deny: [...tools] })
              if (dispose !== undefined) groupDisposers.set(group, dispose)
            }
          } catch (error) {
            console.warn(
              '[xdr-ingest] 无法按组隐藏工具，罕见能力保持可见：',
              error instanceof Error ? error.message : String(error),
            )
          }
        }
        // dsh 每轮都会在任务消息之后再注入一条 runtime-context（工作目录/Web GUI）。
        // 模型常把最后这条当成“用户请求”，回一句“没有任务”就不干活。把任务写进
        // 系统提示，并额外注册一条排在 runtime-context 之后的 required 用户上下文，
        // 让任务成为模型眼里的“最后一条请求”。
        try {
          const taskText = buildAnalysisPrompt(task, workflow)
          agentCtx.systemPrompt?.section?.({
            name: 'xdr-ingest/task',
            order: 10,
            text: '本次会话只执行下面 <task> 里的这一条任务；随后出现的 runtime context 只是环境快照，不是用户请求。'
              + '不要回复“没有任务/请告诉我做什么”，直接开始分析并在结束时调用 complete_task。',
            interpolate: false,
          })
          agentCtx.systemPrompt?.context?.({
            name: 'xdr-ingest/task',
            order: 300,
            text: taskText,
            interpolate: false,
            required: true,
          })
        } catch (error) {
          console.warn(
            '[xdr-ingest] 无法注入任务系统提示：',
            error instanceof Error ? error.message : String(error),
          )
        }
      },
    })
    // 每次运行独立的状态（Analyst 实例是共享的，不能用一个字段跨任务）
    // stalled 处置（A4 整改落地）：stallMinutes 配置此前是死配置——probe 每 15 秒
    // 拿到 lastEventAt 却没人用。现在：超过 1× 没新事件记 WARN（只记一次），
    // 超过 2× 仍无事件主动 cancel 会话，defer 原因写 `stalled`（可见、可统计）。
    const stallMs = (this.options.stallMinutes ?? 0) * 60_000
    const watch = {
      budgetExceeded: false,
      stalled: false,
      startedAt: startedAt,
      lastEventAt: startedAt,
      stallWarned: false,
      stallCancelled: false,
      tools: 0,
    }
    let probeTimer: ReturnType<typeof setInterval> | null = null
    if (this.options.probeSession !== undefined && ((this.options.maxTools ?? 0) > 0 || stallMs > 0)) {
      probeTimer = setInterval(() => {
        void this.options.probeSession?.(sessionId).then(info => {
          if (info === null) return
          watch.tools = info.tools
          const max = this.options.maxTools ?? 0
          if (max > 0 && info.tools > max && !watch.budgetExceeded) {
            watch.budgetExceeded = true
            console.warn(`[xdr-ingest] 任务 ${task.id} 工具调用 ${info.tools} 次超过预算 ${max}，取消会话`)
            void Promise.resolve(handle.agent.cancel({ reason: 'xdr-ingest tool budget' })).catch(
              () => undefined,
            )
          }
          if (info.lastEventAt > watch.lastEventAt) watch.lastEventAt = info.lastEventAt
          if (stallMs > 0 && !watch.stallCancelled && watch.lastEventAt > 0) {
            const idleMs = Date.now() - watch.lastEventAt
            if (idleMs > stallMs * 2) {
              watch.stallCancelled = true
              console.warn(
                `[xdr-ingest] 任务 ${task.id} 已 ${Math.round(idleMs / 60_000)} 分钟无新事件`
                + `（超过 stallMinutes=${this.options.stallMinutes} 的 2 倍），取消会话并延期`,
              )
              void Promise.resolve(handle.agent.cancel({ reason: 'xdr-ingest stalled' })).catch(
                () => undefined,
              )
            } else if (idleMs > stallMs && !watch.stallWarned) {
              watch.stallWarned = true
              watch.stalled = true
              console.warn(
                `[xdr-ingest] 任务 ${task.id} 已 ${Math.round(idleMs / 60_000)} 分钟无新事件`
                + `（stallMinutes=${this.options.stallMinutes}），再拖 1 倍仍未活动就取消`,
              )
            }
          }
        }).catch(() => undefined)
      }, this.options.probeIntervalMs ?? 15_000)
      probeTimer.unref?.()
    }
    let timedOut = false
    let nudged = false
    let error: string | undefined
    let sessionAudit: SessionAudit | null = null
    try {
      const followup = handle.agent.followup({
        content: [{ type: 'text', text: buildAnalysisPrompt(task, workflow) }],
        source: { kind: this.options.source ?? 'xdr-ingest' },
      })
      await Promise.resolve(followup)
      const idle = handle.agent.whenIdle()
      const raced = await this.raceTimeout(idle)
      if (raced === 'timeout') {
        timedOut = true
        await Promise.resolve(handle.agent.cancel({ reason: 'xdr-ingest timeout' })).catch(
          () => undefined,
        )
      } else if (
        this.options.retryUnfinishedTurn !== false
        && this.options.probeSession !== undefined
        && !watch.budgetExceeded
        && !watch.stallCancelled
      ) {
        // 第一轮结束了但任务没交回：常见原因是模型把 dsh 注入的 runtime-context
        // 当成了唯一请求（"没有任务，请告诉我做什么"），或者只做了些元数据查询就收尾。
        // 同一任务再发一次——这一次它排在运行时上下文之后，且明确要求交回。
        // 已交回（state=done）的不重发，避免把正常收尾变成重复派活。
        const firstState = stateOf(await this.readTask(task.id))
        if (firstState !== 'done') {
          nudged = true
          console.warn(
            `[xdr-ingest] 任务 ${task.id} 第一轮结束但未交回（state=${firstState || 'unknown'}，`
            + `工具 ${watch.tools} 次），重发任务提示`,
          )
          await Promise.resolve(handle.agent.followup({
            content: [{
              type: 'text',
              text: '上一轮结束时任务仍未交回。请立即继续执行下面的任务，'
                + '完成后调用 `complete_task` 交回；证据够就收尾，不要再做与任务无关的元数据查询：\n\n'
                + buildAnalysisPrompt(task, workflow),
            }],
            source: { kind: this.options.source ?? 'xdr-ingest' },
          }))
          const second = await this.raceTimeout(handle.agent.whenIdle())
          if (second === 'timeout') {
            timedOut = true
            await Promise.resolve(handle.agent.cancel({ reason: 'xdr-ingest timeout' })).catch(
              () => undefined,
            )
          }
        }
      }
    } catch (exc) {
      error = exc instanceof Error ? exc.message : String(exc)
    } finally {
      if (probeTimer !== null) clearInterval(probeTimer)
      await Promise.resolve(handle.dispose()).catch(() => undefined)
      this.options.onSession?.(sessionId, 'end')
    }
    if (this.options.sessionAudit !== undefined) {
      try {
        sessionAudit = await this.options.sessionAudit(sessionId)
      } catch (exc) {
        console.warn(
          `[xdr-ingest] 会话审计读取失败（${sessionId}）：`
          + `${exc instanceof Error ? exc.message : String(exc)}`.slice(0, 240),
        )
      }
    }
    // 两个来源都保留：审计解析成功但投影为空时，探针看到的工具数仍然是事实；
    // 取较大值避免把真实调用记成 0（这是旧版 tools_used=0 的直接原因）。
    const auditTools = Math.max(sessionAudit?.toolCount ?? 0, watch.tools)
    const auditErrors = Math.max(sessionAudit?.toolErrors ?? 0, 0)

    // 会话结束不等于任务完成：必须回查 NDR 侧状态
    let reply = await this.readTask(task.id)
    let state = stateOf(reply)
    let completed = state === 'done'
    // 预算/超时/停滞被强制取消时，模型往往来不及自己交回。会话已经结束，
    // 再延期只是把租约还回去（下次仍会重演）。这里由插件代交一条
    // inconclusive：结论质量降级，但闭环、可见、不再占着队列。
    let forced = false
    if (!completed && (watch.budgetExceeded || watch.stallCancelled || timedOut || nudged)) {
      const terminalReason = watch.budgetExceeded
        ? 'budget_exhausted'
        : timedOut
        ? 'timeout'
        : 'aborted'
      const summary = watch.budgetExceeded
        ? `分析在工具调用 ${auditTools} 次后达到预算上限，会话被取消；现有证据不足以给出确定判定。`
        : timedOut
        ? '分析超时，会话被取消；现有证据不足以给出确定判定。'
        : watch.stallCancelled
        ? '分析因长时间无新事件被判定停滞并取消；现有证据不足以给出确定判定。'
        : '模型在重发任务提示后仍未调用 `complete_task` 交回；由插件代交 inconclusive（aborted）。'
      const forcedPayload: ReusePayload = {
        verdict: 'inconclusive',
        summary,
        confidence: 0,
        findings: {
          forced_completion: true,
          reason: terminalReason,
          tools_used: auditTools,
          audit: sessionAudit === null ? undefined : auditPayload(sessionAudit),
        },
        terminal_reason: terminalReason,
        tools_used: auditTools,
        duration_ms: Date.now() - startedAt,
      }
      try {
        const receipt = await this.options.ndr.completeTask(task.id, forcedPayload)
        const receiptState = String(receipt.task_state ?? receipt.state ?? '')
        const accepted = (typeof receipt.error !== 'string' || receipt.error === '')
          && (receipt.ok === true || receiptState === 'done')
        if (accepted) {
          forced = true
          completed = true
          state = 'done'
          // `task_state` 可能还没读到刚写入的结论；先用回执载荷补齐，
          // 复用入库/抽检比对仍能拿到 verdict。
          reply = {
            ...reply,
            results: [{
              verdict: 'inconclusive',
              terminal_reason: terminalReason,
              confidence: 0,
              summary,
              findings: forcedPayload.findings,
              evidence_refs: [],
              tools_used: auditTools,
              duration_ms: forcedPayload.duration_ms,
            }],
          }
          await this.archiveConclusion(task, {
            verdict: 'inconclusive',
            confidence: 0,
            summary,
            findings: forcedPayload.findings,
            evidenceRefs: [],
            toolsUsed: auditTools,
            durationMs: forcedPayload.duration_ms,
            terminalReason,
            reused: false,
            reusedFrom: '',
          })
          console.warn(
            `[xdr-ingest] 任务 ${task.id} 已由插件代交 inconclusive（${terminalReason}，工具 ${auditTools} 次）`,
          )
        } else {
          console.warn(
            `[xdr-ingest] 任务 ${task.id} 代交 inconclusive 未被接受：`
            + `${String(receipt.error ?? receiptState ?? 'unknown').slice(0, 240)}`,
          )
        }
      } catch (exc) {
        console.warn(
          `[xdr-ingest] 任务 ${task.id} 代交 inconclusive 异常：`
          + `${exc instanceof Error ? exc.message : String(exc)}`.slice(0, 240),
        )
      }
    }
    if (completed) {
      // 结论入库供下次复用；失败只告警，不要让一条已交回的任务看起来失败
      await this.remember(task, reply)
      await this.archiveFromReply(task, reply, audit, auditTools)
      if (audit !== undefined) {
        // 抽检比对（校准初筛用）：两条判定摆在一起，控制台分析记录里也能看到 light_audit
        console.log(
          `[xdr-ingest] 任务 ${task.id} 抽检比对：初筛 ${audit.verdict}（${audit.model} 置信 ${audit.confidence}）`
          + ` vs 付费 ${String(reply.results?.[0]?.verdict ?? '') || '(未回执)'}`,
        )
      }
    }
    let deferred = false
    if (!completed) {
      // 没交回：显式延后（不算失败），把租约让出来，同时留下"为什么"
      const reason = watch.budgetExceeded
        ? 'budget_exhausted'
        : watch.stallCancelled
        ? 'stalled'
        : timedOut
        ? 'timeout'
        : error
        ? `agent_error: ${error.slice(0, 120)}`
        : 'no_conclusion'
      try {
        await this.options.ndr.deferTask(task.id, reason)
        deferred = true
      } catch (exc) {
        error = error ?? (exc instanceof Error ? exc.message : String(exc))
      }
    }
    const outcome = completed ? 'done' : error !== undefined ? 'failed' : 'deferred'
    const verdict = String(reply.results?.[0]?.verdict ?? '')
    const note = [
      auditNote,
      completed
        ? (forced ? '插件代交 inconclusive（预算/超时/停滞）' : '')
        : watch.budgetExceeded
          ? '工具调用超过预算，已取消并延后'
          : (error ?? (timedOut ? 'timeout' : 'no_conclusion')),
    ].filter(text => text !== '').join('；')
    const decision = forced
      ? {
          action: 'forced_completion',
          reason: watch.budgetExceeded ? 'budget_exhausted' : timedOut ? 'timeout' : 'stalled',
        }
      : {}
    await this.finishProcess(task, outcome, startedAt, {
      verdict,
      note,
      toolsUsed: auditTools,
      toolErrors: auditErrors,
      attempt,
      sessionId,
      tokens: tokenUsageOf(sessionAudit),
      error: error ?? (timedOut ? 'timeout' : watch.stallCancelled ? 'stalled' : ''),
      turnEndReason: sessionAudit?.turnEnds.at(-1)?.reason ?? '',
      decision,
      audit: sessionAudit === null ? {} : auditPayload(sessionAudit),
    })
    await this.sendAudit(task, {
      sessionId,
      attempt,
      resultId: String(reply.result_id ?? ''),
      outcome,
      verdict,
      note,
      error: error ?? '',
      decision,
      startedAt,
      sessionAudit,
      toolsUsed: auditTools,
      toolErrors: auditErrors,
      model: [provider, model].filter(value => (value ?? '') !== '').join('/'),
    })
    // 主模型连续失败 → 下一轮换备用；成功一次就切回主模型。
    // 插件代交（forced）不算"模型自己收尾成功"，预算/超时同样触发换备用。
    if (completed && !forced) {
      this.preferFallback = false
    } else if (
      this.options.fallbackModel !== undefined
      && (timedOut || watch.budgetExceeded || /429|rate limit|quota|timeout|overloaded|context window/i.test(error ?? ''))
    ) {
      this.preferFallback = true
    }
    return {
      taskId: task.id,
      completed,
      state,
      deferred,
      durationMs: Date.now() - startedAt,
      attempt,
      ...(error ? { error } : {}),
    }
  }

  /**
   * 复用尝试：命中就在**不起会话**的情况下直接交回。
   *
   * 失败（缓存读不到、NDR 拒收、状态不是 done）一律返回 null，退回正常分析：
   * 复用是省钱手段，不是正确性前提。唯一不能做的是"交回没成功却当成完成"。
   */
  private async tryReuse(task: ClaimedTask, startedAt: number): Promise<AnalystOutcome | null> {
    const store = this.options.taskResults
    const ttlMs = this.options.taskReuseTtlMs ?? 0
    if (store === undefined || ttlMs <= 0) return null
    const key = taskResultKey(task, {
      requireIdentity: this.options.taskReuseRequireIdentity ?? true,
    })
    if (key === null) return null
    let record: TaskResultRecord | null = null
    try {
      record = await store.load(key)
    } catch {
      return null
    }
    const decision = reuseDecision(
      record, task, startedAt, ttlMs, this.options.taskReuseStrengthDelta ?? 0,
    )
    if (!decision.reuse || record === null) {
      // 有记录但被拒（过期/更强/suspicious/终端原因）→ 计入拒绝，供指标看板看"复用没生效"
      if (record !== null) this.reuse.rejected += 1
      return null
    }
    try {
      // B2：复用不只回放 verdict —— findings / anchors / recommendation 一并带上，
      // 否则 NDR 里的新结论只剩一句 summary，之前查到的结构化事实和资产归属全丢了。
      const replayFindings: Record<string, unknown> = {
        ...(record.findings ?? {}),
        reused_from: record.taskId,
        reuse_key: key,
        reused_at: new Date(startedAt).toISOString(),
        reused_count: record.occurrences + 1,
      }
      delete replayFindings['triaged_by']  // 初筛结论的标记不能漂到复用行上
      if (record.recommendation !== undefined && record.recommendation !== '') {
        replayFindings['recommendation'] = record.recommendation
      }
      const reply = await this.options.ndr.completeTask(task.id, {
        verdict: record.verdict,
        summary: reuseSummary(record),
        confidence: record.confidence,
        findings: replayFindings,
        ...(typeof record.findings?.['verdict_basis'] === 'object'
          && record.findings['verdict_basis'] !== null
          ? { verdict_basis: record.findings['verdict_basis'] as Record<string, unknown> }
          : {}),
        ...(record.anchors !== undefined && record.anchors.length > 0
          ? { anchors: record.anchors.map(a => ({ kind: a.kind, value: a.value })) }
          : {}),
        ...(record.recommendation !== undefined && record.recommendation !== ''
          ? { recommendation: record.recommendation }
          : {}),
        terminal_reason: 'concluded',
        // 没有真的取证：成本如实记 0，证据引用留空（上次会话的引用在这里无效）
        tools_used: 0,
        duration_ms: 0,
      })
      if (typeof reply.error === 'string' && reply.error !== '') {
        console.warn(`[xdr-ingest] 复用交回失败（任务 ${task.id}）：${reply.error.slice(0, 240)}；改为正常分析`)
        return null
      }
      // 不把“工具调用没报错”当成“任务已交回”：服务端必须明确返回 ok 或 done。
      // NDR complete_task 的成功回执包含两者，旧/异常 MCP 包装层则退回正常分析。
      const state = String(reply.task_state ?? reply.state ?? '')
      if (reply.ok !== true && state !== 'done') return null
      if (state !== '' && state !== 'done') return null
      await store.bump(key, new Date().toISOString(), task.id).catch(() => false)
      // 复用路径没有模型会话，但抑制同步仍要能靠 source_task_id 找到这条身份。
      await this.rememberIdentity(task, record.verdict)
      await this.archiveConclusion(task, {
        verdict: record.verdict,
        confidence: record.confidence,
        summary: reuseSummary(record),
        findings: { ...replayFindings, reused: true },
        evidenceRefs: [],
        toolsUsed: 0,
        durationMs: 0,
        terminalReason: 'concluded',
        reused: true,
        reusedFrom: record.taskId,
      })
      return {
        taskId: task.id,
        completed: true,
        state: 'done',
        deferred: false,
        durationMs: Date.now() - startedAt,
        reused: true,
        decision: {
          verdict: record.verdict,
          source_task_id: record.taskId,
          reuse_key: key,
          reuse_at: record.analyzedAt,
          occurrences: record.occurrences + 1,
        },
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(`[xdr-ingest] 复用交回异常（任务 ${task.id}）：${message.slice(0, 240)}；改为正常分析`)
      return null
    }
  }

  /**
   * 抑制记忆命中：这类现象已被精准抑制，**不起会话**直接交回。
   *
   * 为什么 NDR 已经拦了还要在智能体这边再拦一层：NDR 拦的是"规则命中"这条
   * 路径，而同一个现象还会从别的线索类型（首见 / 基线偏离）再冒出来；
   * 这里再挡一次，省掉一整轮模型会话与取数，也省掉一次重复的结论。
   *
   * 交回的判定用 `false_positive`：这类现象此前已被判为误报并提交了抑制，
   * 这次的"确认"不产生新信息，但会喂给反馈学习（强度衰减），让派工更准。
   */
  private async trySuppressed(task: ClaimedTask, startedAt: number): Promise<AnalystOutcome | null> {
    const store = this.options.taskSeen
    if (store === undefined) return null
    let hit: SuppressedTask | null = null
    try {
      hit = await store.findSuppressed(taskIdentity(task))
    } catch {
      return null
    }
    if (hit === null) return null
    try {
      const reply = await this.options.ndr.completeTask(task.id, {
        verdict: 'false_positive',
        summary: `该现象已被精准抑制（${hit.suppressedBy}），按记忆不再分析`,
        confidence: 0.9,
        findings: {
          suppressed_by: hit.suppressedBy,
          suppressed_task: hit.taskId,
          reused_from: hit.taskId,
          skipped_reason: '已被精准抑制覆盖',
        },
        verdict_basis: {
          hypothesis: 'known_benign_infrastructure',
          evidence_categories: ['known_benign_infrastructure'],
          benign_explanation_checked: true,
          contradictions_checked: ['suppression_memory'],
        },
        terminal_reason: 'concluded',
        // 没有真的取证：成本如实记 0
        tools_used: 0,
        duration_ms: 0,
      })
      const state = String(reply.task_state ?? reply.state ?? '')
      if (reply.ok !== true && state !== 'done') return null
      if (state !== '' && state !== 'done') return null
      console.log(
        `[xdr-ingest] 任务 ${task.id} 命中抑制记忆（${hit.suppressedBy}），未起分析会话`,
      )
      await this.archiveConclusion(task, {
        verdict: 'false_positive',
        confidence: 0.9,
        summary: `该现象已被精准抑制（${hit.suppressedBy}），按记忆不再分析`,
        findings: { suppressed_by: hit.suppressedBy, suppressed_task: hit.taskId },
        evidenceRefs: [],
        toolsUsed: 0,
        durationMs: 0,
        terminalReason: 'concluded',
        reused: true,
        reusedFrom: hit.taskId,
      })
      return {
        taskId: task.id,
        completed: true,
        state: 'done',
        deferred: false,
        durationMs: Date.now() - startedAt,
        reused: true,
        decision: {
          suppressed_by: hit.suppressedBy,
          source_task_id: hit.taskId,
          verdict: 'false_positive',
        },
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(
        `[xdr-ingest] 抑制记忆交回异常（任务 ${task.id}）：${message.slice(0, 240)}；改为正常分析`,
      )
      return null
    }
  }

  /**
   * 轻量初筛：低阶模型单轮判定（无工具、无会话），只收通过全部硬约束的判定。
   *
   * 与复用/抑制同一套哲学：交回失败、输出不合法、置信不够、被抽中复核 ——
   * 一律返回空对象落回付费会话。唯一不能做的是"没交回成功却当完成"。
   * 初筛结论**不写复用库**：防止小模型的结论被后续同类任务悄悄放大。
   */
  private async tryLightTriage(task: ClaimedTask): Promise<LightTriageAttempt> {
    const port = this.options.lightTriage
    if (port === undefined) return {}
    let result: TriageResult
    try {
      result = await port.triage(task)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(`[xdr-ingest] 轻量初筛异常（任务 ${task.id}）：${message.slice(0, 240)}；改为付费分析`)
      return {}
    }
    if (result.kind === 'escalate') {
      if (result.reason === 'audit_sample' && result.preview !== undefined) {
        console.log(
          `[xdr-ingest] 任务 ${task.id} 命中初筛抽检：初筛判 ${result.preview.verdict}`
          + `（${result.preview.model} 置信 ${result.preview.confidence}），仍送付费复核`,
        )
        return { audit: result.preview }
      }
      return {}
    }
    const payload = {
      verdict: result.verdict,
      summary: `〔轻量初筛 ${result.model} · 置信度 ${result.confidence}〕${result.summary}`,
      confidence: result.confidence,
      findings: {
        triaged_by: 'light',
        light_model: result.model,
        light_confidence: result.confidence,
      },
      verdict_basis: {
        hypothesis: 'light_triage',
        evidence_categories: [result.verdict === 'benign' ? 'business_normal' : 'noise_only'],
        benign_explanation_checked: true,
        contradictions_checked: ['hint_only'],
      },
      terminal_reason: 'concluded',
      // 没有真的取证：成本如实记 0，证据引用留空
      tools_used: 0,
      duration_ms: result.ms,
    }
    try {
      const reply = await this.options.ndr.completeTask(task.id, payload)
      if (typeof reply.error === 'string' && reply.error !== '') {
        console.warn(`[xdr-ingest] 初筛交回失败（任务 ${task.id}）：${reply.error.slice(0, 240)}；改为付费分析`)
        return {}
      }
      const state = String(reply.task_state ?? reply.state ?? '')
      if (reply.ok !== true && state !== 'done') return {}
      if (state !== '' && state !== 'done') return {}
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(`[xdr-ingest] 初筛交回异常（任务 ${task.id}）：${message.slice(0, 240)}；改为付费分析`)
      return {}
    }
    console.log(
      `[xdr-ingest] 任务 ${task.id} 轻量初筛关单（${result.verdict} · ${result.model} 置信 ${result.confidence}），未起会话`,
    )
    await this.archiveConclusion(task, {
      verdict: result.verdict,
      confidence: result.confidence,
      summary: payload.summary,
      findings: payload.findings,
      evidenceRefs: [],
      toolsUsed: 0,
      durationMs: result.ms,
      terminalReason: 'concluded',
      reused: false,
      reusedFrom: '',
    })
    return {
      closed: {
        verdict: result.verdict,
        confidence: result.confidence,
        summary: result.summary,
        model: result.model,
        ms: result.ms,
      },
    }
  }

  /**
   * 把 DSH 审计写回 NDR。审计不是结论、不是抑制证据；写失败只告警。
   * 没起会话的复用/抑制/初筛也写一条（session_id 为空、decision 说明原因），
   * 否则控制台只能看到“跳过了”，看不见“为什么跳过”。
   */
  private async sendAudit(
    task: ClaimedTask,
    data: {
      readonly sessionId: string
      readonly attempt: number
      readonly resultId?: string
      readonly outcome: string
      readonly verdict: string
      readonly note?: string
      readonly error?: string
      readonly decision?: Record<string, unknown>
      readonly startedAt: number
      readonly sessionAudit?: SessionAudit | null
      readonly toolsUsed?: number
      readonly toolErrors?: number
      readonly model?: string
    },
  ): Promise<void> {
    if (this.options.ndr.recordAudit === undefined) return
    try {
      const audit = data.sessionAudit ?? null
      await this.options.ndr.recordAudit(task.id, {
        task_id: task.id,
        session_id: data.sessionId,
        attempt: Math.max(0, data.attempt),
        ...(data.resultId !== undefined && data.resultId !== '' ? { result_id: data.resultId } : {}),
        outcome: data.outcome,
        verdict: data.verdict,
        source: audit === null ? 'agent' : 'dsh',
        model: audit?.model || data.model || '',
        started_at: audit?.startedAt ?? new Date(data.startedAt).toISOString(),
        ended_at: audit?.endedAt ?? new Date().toISOString(),
        tools_used: data.toolsUsed ?? audit?.toolCount ?? 0,
        tool_errors: data.toolErrors ?? audit?.toolErrors ?? 0,
        turns: audit?.turns ?? 0,
        turn_end_reason: audit?.turnEnds.at(-1)?.reason ?? '',
        tokens: tokenUsageOf(audit),
        error: data.error ?? '',
        note: data.note ?? '',
        decision: data.decision ?? {},
        trace: audit === null ? {} : auditPayload(audit),
      })
    } catch (error) {
      console.warn(
        `[xdr-ingest] 审计写回失败（任务 ${task.id}）：`
        + `${error instanceof Error ? error.message : String(error)}`.slice(0, 240),
      )
    }
  }

  /** 过程索引收尾（控制台「分析过程」页的数据来源）。 */
  private async finishProcess(
    task: ClaimedTask,
    outcome: 'running' | 'done' | 'reused' | 'suppressed' | 'triaged' | 'deferred' | 'failed',
    startedAt: number,
    extra: {
      toolsUsed?: number
      toolErrors?: number
      verdict?: string
      note?: string
      model?: string
      attempt?: number
      sessionId?: string
      tokens?: ReturnType<typeof tokenUsageOf>
      error?: string
      turnEndReason?: string
      decision?: Record<string, unknown>
      audit?: Record<string, unknown>
    } = {},
  ): Promise<void> {
    const store = this.options.process
    if (store === undefined) return
    try {
      await store.finishProcess({
        taskId: task.id,
        endedAt: new Date().toISOString(),
        outcome,
        durationMs: Date.now() - startedAt,
        kind: task.kind,
        subject: task.subject,
        ...(extra.toolsUsed === undefined ? {} : { toolsUsed: extra.toolsUsed }),
        ...(extra.toolErrors === undefined ? {} : { toolErrors: extra.toolErrors }),
        ...(extra.verdict === undefined ? {} : { verdict: extra.verdict }),
        ...(extra.note === undefined ? {} : { note: extra.note }),
        ...(extra.model === undefined ? {} : { model: extra.model }),
        ...(extra.attempt === undefined ? {} : { attempt: extra.attempt }),
        ...(extra.sessionId === undefined ? {} : { sessionId: extra.sessionId }),
        ...(extra.tokens === undefined ? {} : { tokens: extra.tokens }),
        ...(extra.error === undefined ? {} : { error: extra.error }),
        ...(extra.turnEndReason === undefined ? {} : { turnEndReason: extra.turnEndReason }),
        ...(extra.decision === undefined ? {} : { decision: extra.decision }),
        ...(extra.audit === undefined ? {} : { audit: extra.audit }),
      })
    } catch (error) {
      console.warn(
        `[xdr-ingest] 过程索引收尾失败（任务 ${task.id}）：`,
        error instanceof Error ? error.message : String(error),
      )
    }
  }

  /**
   * 结论留档：控制台「分析记录」读的是**智能体自己这份**。
   *
   * 为什么不再直连 NDR 的 `analysis_results`：多项目下每个项目一套 NDR 库，
   * 控制台要跨库读既慢又依赖每条隧道。交回时顺手留一份，读自己库就够。
   */
  private async archiveConclusion(
    task: ClaimedTask,
    data: {
      id?: string
      verdict: string
      confidence: number
      summary: string
      findings: unknown
      evidenceRefs: readonly string[]
      toolsUsed: number
      durationMs: number
      terminalReason: string
      reused: boolean
      reusedFrom: string
      createdAt?: string
    },
  ): Promise<void> {
    const store = this.options.conclusions
    if (store === undefined) return
    const record: ConclusionRecord = {
      id: (data.id ?? '') !== ''
        ? String(data.id)
        : `${this.options.projectId ?? 'project'}:${task.id}`,
      taskId: task.id,
      kind: task.kind,
      subjectKind: task.subject_kind,
      subject: task.subject,
      verdict: data.verdict,
      confidence: data.confidence,
      summary: data.summary,
      findings: data.findings ?? {},
      evidenceRefs: data.evidenceRefs,
      toolsUsed: data.toolsUsed,
      durationMs: data.durationMs,
      reused: data.reused,
      reusedFrom: data.reusedFrom,
      terminalReason: data.terminalReason,
      createdAt: (data.createdAt ?? '') !== '' ? String(data.createdAt) : new Date().toISOString(),
    }
    try {
      await store.saveConclusion(record)
    } catch (error) {
      console.warn(
        `[xdr-ingest] 结论留档失败（任务 ${task.id}）：`,
        error instanceof Error ? error.message : String(error),
      )
    }
  }

  /** 从 `task_state` 的回执留档（正常分析路径）。 */
  private async archiveFromReply(
    task: ClaimedTask,
    reply: TaskStateReply,
    audit?: { readonly verdict: string, readonly confidence: number, readonly model: string },
    toolsUsedOverride?: number,
  ): Promise<void> {
    const latest = reply.results?.[0]
    if (latest === undefined) return
    // 抽检样本：把初筛预判并进 findings（light_audit），控制台分析记录里能直接比对两条判定
    const base = (typeof latest.findings === 'object' && latest.findings !== null && !Array.isArray(latest.findings))
      ? latest.findings as Record<string, unknown>
      : {}
    await this.archiveConclusion(task, {
      ...(typeof reply.result_id === 'string' && reply.result_id !== '' ? { id: reply.result_id } : {}),
      verdict: String(latest.verdict ?? ''),
      confidence: Number.isFinite(latest.confidence) ? Number(latest.confidence) : 0,
      summary: String(latest.summary ?? ''),
      findings: audit === undefined
        ? (latest.findings ?? {})
        : { ...base, light_audit: { verdict: audit.verdict, confidence: audit.confidence, model: audit.model } },
      evidenceRefs: Array.isArray(latest.evidence_refs) ? latest.evidence_refs : [],
      // 模型经常把 tools_used 填 0；运行层审计有真实工具数时以它为准。
      toolsUsed: Math.max(Number(latest.tools_used ?? 0), toolsUsedOverride ?? 0),
      durationMs: Number(latest.duration_ms ?? 0),
      terminalReason: String(latest.terminal_reason ?? ''),
      reused: false,
      reusedFrom: '',
      ...(typeof latest.created_at === 'string' && latest.created_at !== ''
        ? { createdAt: latest.created_at }
        : {}),
    })
  }

  /** 把刚交回的结论写进复用库（只存最新一条）。 */
  private async remember(task: ClaimedTask, reply: TaskStateReply): Promise<void> {
    const latest = reply.results?.[0]
    const verdict = String(latest?.verdict ?? '').trim().toLowerCase()
    // 现象身份先记下来（不管结论能不能复用）：抑制记忆要靠它把
    // 「这条任务 → 这类现象」对上号，抑制一生效就能跳过同现象的后续任务。
    await this.rememberIdentity(task, verdict)
    const store = this.options.taskResults
    const ttlMs = this.options.taskReuseTtlMs ?? 0
    if (store === undefined || ttlMs <= 0) return
    const key = taskResultKey(task, {
      requireIdentity: this.options.taskReuseRequireIdentity ?? true,
    })
    if (key === null) return
    if (latest === undefined) return
    if (verdict === '') return
    let previous: TaskResultRecord | null = null
    try {
      previous = await store.load(key)
    } catch {
      // 旧记录不可读时仍保存新结论；只是累计次数从 1 重新开始。
    }
    const now = Date.now()
    // B2：把 findings / anchors / recommendation 一起留档（下次复用原样回放）。
    // 只留「稳定事实」：reused_* / triaged_by 是一次性的过程标记，不能进记录。
    const recordFindings: Record<string, unknown> =
      typeof latest.findings === 'object' && latest.findings !== null && !Array.isArray(latest.findings)
        ? { ...(latest.findings as Record<string, unknown>) }
        : {}
    for (const drop of ['reused_from', 'reused_at', 'reused_count', 'reuse_key', 'triaged_by', 'reused']) {
      delete recordFindings[drop]
    }
    if (typeof latest.verdict_basis === 'object' && latest.verdict_basis !== null) {
      recordFindings['verdict_basis'] = latest.verdict_basis
    }
    if (typeof latest.facts_hash === 'string' && latest.facts_hash !== '') {
      recordFindings['facts_hash'] = latest.facts_hash
    }
    const recordAnchors = Array.isArray(latest.anchors)
      ? latest.anchors
          .map(a => ({ kind: String(a?.kind ?? '').trim(), value: String(a?.value ?? '').trim() }))
          .filter(a => a.kind !== '' && a.value !== '')
      : []
    const recommendation = String(latest.recommendation ?? recordFindings['recommendation'] ?? '').trim()
    const record: TaskResultRecord = {
      key,
      // v2：本版本起记录 findings/anchors/recommendation（复用回放用）
      version: 2,
      kind: task.kind,
      subjectKind: task.subject_kind,
      subject: task.subject,
      feature: (task.feature ?? '').trim(),
      taskId: task.id,
      verdict,
      terminalReason: String(latest.terminal_reason ?? ''),
      confidence: Number.isFinite(latest.confidence) ? Number(latest.confidence) : 0,
      summary: String(latest.summary ?? ''),
      strength: Number(task.strength),
      occurrences: (previous?.occurrences ?? 0) + 1,
      analyzedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlMs).toISOString(),
      ...(Object.keys(recordFindings).length > 0 ? { findings: recordFindings } : {}),
      ...(recordAnchors.length > 0 ? { anchors: recordAnchors } : {}),
      ...(Array.isArray(latest.evidence_refs)
        ? { evidenceRefs: latest.evidence_refs.map(String).filter(value => value !== '') }
        : {}),
      ...(recommendation !== '' ? { recommendation } : {}),
    }
    try {
      const saved = await store.save(record)
      if (saved) {
        this.reuse.stored += 1
      } else {
        console.warn(`[xdr-ingest] 结论未入库（任务 ${task.id}）：存储不可用，下次会重新分析`)
      }
    } catch (error) {
      console.warn(
        `[xdr-ingest] 结论入库异常（任务 ${task.id}）：`,
        error instanceof Error ? error.message : String(error),
      )
    }
  }

  /** 记下"这个任务的现象身份"（抑制记忆的底座）。 */
  private async rememberIdentity(task: ClaimedTask, verdict: string): Promise<void> {
    const store = this.options.taskSeen
    if (store === undefined) return
    try {
      await store.recordTaskSeen({ ...taskIdentity(task), taskId: task.id, verdict })
    } catch (error) {
      console.warn(
        `[xdr-ingest] 现象身份记录失败（任务 ${task.id}）：`,
        error instanceof Error ? error.message : String(error),
      )
    }
  }

  private async readTask(taskId: string): Promise<TaskStateReply> {
    try {
      return await this.options.ndr.taskState(taskId)
    } catch {
      // 查不到状态：宁可当成"没交回"（会 defer，代价小），也不要当成完成（会丢线索）
      return {}
    }
  }

  private async raceTimeout(work: Promise<void>): Promise<'ok' | 'timeout'> {
    if (!Number.isFinite(this.options.timeoutMs) || this.options.timeoutMs <= 0) {
      await work
      return 'ok'
    }
    let timer: ReturnType<typeof setTimeout> | null = null
    // 刻意**不 unref**：这个定时器是"这次等待的上界"，若 unref 掉，
    // 而 whenIdle 又是永不 resolve 的 promise，进程会因为没有任何活动句柄而提前退出
    // （表现是测试被 cancelled、生产里会话没收尾就断）。
    const timeout = new Promise<'timeout'>(resolve => {
      timer = setTimeout(() => resolve('timeout'), this.options.timeoutMs)
    })
    try {
      const done = work.then<'ok'>(() => 'ok')
      return await Promise.race([done, timeout])
    } finally {
      if (timer !== null) clearTimeout(timer)
    }
  }
}

/** `task_state` 的两种键名（历史兼容）统一成状态串；带 error 视为未知。 */
function stateOf(reply: TaskStateReply): string {
  if (typeof reply.error === 'string' && reply.error !== '') return ''
  return String(reply.task_state ?? reply.state ?? '')
}

function tokenUsageOf(audit: SessionAudit | null): {
  input: number
  output: number
  cacheRead: number
  cacheWrite: number
  total: number
  reported: boolean
} {
  return audit?.tokens ?? {
    input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0, reported: false,
  }
}

/** NDR 审计表只收有界投影：工具调用已经按 callId 配对并脱敏，这里再截断一次。 */
function auditPayload(audit: SessionAudit): Record<string, unknown> {
  return {
    ok: audit.ok,
    started_at: audit.startedAt,
    ended_at: audit.endedAt,
    turns: audit.turns,
    steps: audit.steps,
    tool_count: audit.toolCount,
    tool_errors: audit.toolErrors,
    tokens: audit.tokens,
    errors: audit.errors,
    turn_ends: audit.turnEnds,
    redacted: audit.redacted,
    truncated: audit.truncated,
    tool_calls: audit.toolCalls.slice(0, 200),
  }
}

/** 复用交回的摘要：开头注明来源，审计时一眼能看出这不是本次取证的结论。 */
function reuseSummary(record: TaskResultRecord): string {
  const day = record.analyzedAt.slice(0, 10)
  const short = record.taskId.slice(0, 8)
  return `〔复用 ${day} 的同类结论（来源任务 ${short}，第 ${record.occurrences + 1} 次出现）〕${record.summary}`
}
