/**
 * 一次分析会话的完整生命周期：起 agent → 喂提示词 → 等空闲 → **确认交回** → 收尾。
 *
 * 为什么"确认交回"是单独一步（`task_state`）：
 * 会话空闲 **不等于** 任务完成 —— 模型很可能查完就收工、忘了 `complete_task`。
 * 不查这一步，任务会一直挂着直到租约到期被回收，`attempts` 累加，
 * 最后进 `stuck`（表面上"智能体在跑"，实际什么都没交）。
 */

import type { AgentsServiceLike } from './agent-port.ts'
import type { WorkflowRecord } from './state-store.ts'
import type { ClaimedTask, NdrPort } from './claim-loop.ts'
import { buildAnalysisPrompt } from './prompt.ts'
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
  readonly evidence_refs?: readonly string[]
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
  readonly terminal_reason: string
  readonly tools_used: number
  readonly duration_ms: number
}

export interface NdrTaskPort extends NdrPort {
  taskState(taskId: string): Promise<TaskStateReply>
  /** 复用命中时直接交回；正常分析由模型自己调 `complete_task`。 */
  completeTask(taskId: string, payload: ReusePayload): Promise<CompleteReply>
  deferTask(taskId: string, reason: string): Promise<unknown>
  /** 生效中的精准抑制清单（抑制记忆的来源；不实现 = 不做抑制记忆）。 */
  listSuppressions?(): Promise<readonly SuppressionView[]>
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
  /** 当前项目（NDR 授权ID），写进结论留档；空串 = 未知项目。 */
  readonly projectId?: string
  /** 复用有效期（毫秒，从上次真实分析起算；0 = 关闭复用）。 */
  readonly taskReuseTtlMs?: number
  /** 新线索强度比上次高多少就必须重查（现象变强）。 */
  readonly taskReuseStrengthDelta?: number
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
  /** 会话进度探针（读会话日志：工具调用数 + 最后事件时间）。 */
  readonly probeSession?: (sessionId: string) => Promise<{ tools: number, lastEventAt: number } | null>
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
}

let sessionCounter = 0

export class Analyst {
  private readonly options: AnalystOptions
  private readonly reuse = { reused: 0, stored: 0 }
  /** 主模型刚失败过：下一轮用备用模型（成功即恢复）。 */
  private preferFallback = false
  /** 同一现象的并发任务排队：后来的任务等前一个写入结论后再查缓存。 */
  private readonly keyLocks = new Map<string, Promise<void>>()

  constructor(options: AnalystOptions) {
    this.options = options
  }

  /** 复用/入库计数（`/status` 观测用）。 */
  get reuseStats(): { readonly reused: number, readonly stored: number } {
    return { ...this.reuse }
  }

  async run(task: ClaimedTask): Promise<AnalystOutcome> {
    const key = taskResultKey(task)
    if (key === null) return this.runUnlocked(task)

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
      await this.finishProcess(task, 'reused', startedAt, { note: '同类现象结论复用（未起会话）' })
      return reused
    }

    // 抑制记忆：这类现象已经被精准抑制过 → 不起会话、不取数，直接交回。
    const suppressed = await this.trySuppressed(task, startedAt)
    if (suppressed !== null) {
      await this.finishProcess(task, 'suppressed', startedAt, { note: '已被精准抑制（未起会话）' })
      return suppressed
    }

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
    await this.options.process?.startProcess({
      taskId: task.id,
      sessionId,
      kind: task.kind,
      subject: task.subject,
      model: [provider, model].filter(v => (v ?? '') !== '').join('/'),
      startedAt: new Date(startedAt).toISOString(),
      workflowId: workflow?.workflowId ?? '',
      workflowName: workflow?.name ?? '',
      workflowStages: workflow?.stages ?? [],
    })
    this.options.onSession?.(sessionId, 'start')
    const handle = await this.options.agents.create({
      sessionId,
      agentOptions: {
        ...(provider ? { provider } : {}),
        ...(model ? { model } : {}),
      },
    })
    // 每次运行独立的状态（Analyst 实例是共享的，不能用一个字段跨任务）
    const watch = { budgetExceeded: false, stalled: false }
    let probeTimer: ReturnType<typeof setInterval> | null = null
    if (this.options.probeSession !== undefined && (this.options.maxTools ?? 0) > 0) {
      probeTimer = setInterval(() => {
        void this.options.probeSession?.(sessionId).then(info => {
          if (info === null) return
          const max = this.options.maxTools ?? 0
          if (max > 0 && info.tools > max && !watch.budgetExceeded) {
            watch.budgetExceeded = true
            console.warn(`[xdr-ingest] 任务 ${task.id} 工具调用 ${info.tools} 次超过预算 ${max}，取消会话`)
            void Promise.resolve(handle.agent.cancel({ reason: 'xdr-ingest tool budget' })).catch(
              () => undefined,
            )
          }
        }).catch(() => undefined)
      }, 15_000)
      probeTimer.unref?.()
    }
    let timedOut = false
    let error: string | undefined
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
      }
    } catch (exc) {
      error = exc instanceof Error ? exc.message : String(exc)
    } finally {
      if (probeTimer !== null) clearInterval(probeTimer)
      await Promise.resolve(handle.dispose()).catch(() => undefined)
      this.options.onSession?.(sessionId, 'end')
    }

    // 会话结束不等于任务完成：必须回查 NDR 侧状态
    const reply = await this.readTask(task.id)
    const state = stateOf(reply)
    const completed = state === 'done'
    if (completed) {
      // 结论入库供下次复用；失败只告警，不要让一条已交回的任务看起来失败
      await this.remember(task, reply)
      await this.archiveFromReply(task, reply)
    }
    let deferred = false
    if (!completed) {
      // 没交回：显式延后（不算失败），把租约让出来，同时留下"为什么"
      const reason = watch.budgetExceeded
        ? 'budget_exhausted'
        : timedOut ? 'timeout' : error ? `agent_error: ${error.slice(0, 120)}` : 'no_conclusion'
      try {
        await this.options.ndr.deferTask(task.id, reason)
        deferred = true
      } catch (exc) {
        error = error ?? (exc instanceof Error ? exc.message : String(exc))
      }
    }
    await this.finishProcess(
      task,
      completed ? 'done' : error !== undefined ? 'failed' : 'deferred',
      startedAt,
      {
        verdict: String(reply.results?.[0]?.verdict ?? ''),
        note: completed
          ? ''
          : watch.budgetExceeded
            ? '工具调用超过预算，已取消并延后'
            : (error ?? (timedOut ? 'timeout' : 'no_conclusion')),
      },
    )
    // 主模型连续失败 → 下一轮换备用；成功一次就切回主模型
    if (completed) {
      this.preferFallback = false
    } else if (
      this.options.fallbackModel !== undefined
      && (timedOut || /429|rate limit|quota|timeout|overloaded|context window/i.test(error ?? ''))
    ) {
      this.preferFallback = true
    }
    return {
      taskId: task.id,
      completed,
      state,
      deferred,
      durationMs: Date.now() - startedAt,
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
    const key = taskResultKey(task)
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
    if (!decision.reuse || record === null) return null
    try {
      const reply = await this.options.ndr.completeTask(task.id, {
        verdict: record.verdict,
        summary: reuseSummary(record),
        confidence: record.confidence,
        findings: {
          reused_from: record.taskId,
          reuse_key: key,
          reused_at: new Date(startedAt).toISOString(),
          reused_count: record.occurrences + 1,
        },
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
      await this.archiveConclusion(task, {
        verdict: record.verdict,
        confidence: record.confidence,
        summary: reuseSummary(record),
        findings: { reused_from: record.taskId, reuse_key: key, reused: true },
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
          skipped_reason: '已被精准抑制覆盖',
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
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(
        `[xdr-ingest] 抑制记忆交回异常（任务 ${task.id}）：${message.slice(0, 240)}；改为正常分析`,
      )
      return null
    }
  }

  /** 过程索引收尾（控制台「分析过程」页的数据来源）。 */
  private async finishProcess(
    task: ClaimedTask,
    outcome: 'running' | 'done' | 'reused' | 'suppressed' | 'deferred' | 'failed',
    startedAt: number,
    extra: { toolsUsed?: number; verdict?: string; note?: string } = {},
  ): Promise<void> {
    const store = this.options.process
    if (store === undefined) return
    try {
      await store.finishProcess({
        taskId: task.id,
        endedAt: new Date().toISOString(),
        outcome,
        durationMs: Date.now() - startedAt,
        ...(extra.toolsUsed === undefined ? {} : { toolsUsed: extra.toolsUsed }),
        ...(extra.verdict === undefined ? {} : { verdict: extra.verdict }),
        ...(extra.note === undefined ? {} : { note: extra.note }),
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
  private async archiveFromReply(task: ClaimedTask, reply: TaskStateReply): Promise<void> {
    const latest = reply.results?.[0]
    if (latest === undefined) return
    await this.archiveConclusion(task, {
      ...(typeof reply.result_id === 'string' && reply.result_id !== '' ? { id: reply.result_id } : {}),
      verdict: String(latest.verdict ?? ''),
      confidence: Number.isFinite(latest.confidence) ? Number(latest.confidence) : 0,
      summary: String(latest.summary ?? ''),
      findings: latest.findings ?? {},
      evidenceRefs: Array.isArray(latest.evidence_refs) ? latest.evidence_refs : [],
      toolsUsed: Number(latest.tools_used ?? 0),
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
    const key = taskResultKey(task)
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
    const record: TaskResultRecord = {
      key,
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

/** 复用交回的摘要：开头注明来源，审计时一眼能看出这不是本次取证的结论。 */
function reuseSummary(record: TaskResultRecord): string {
  const day = record.analyzedAt.slice(0, 10)
  const short = record.taskId.slice(0, 8)
  return `〔复用 ${day} 的同类结论（来源任务 ${short}，第 ${record.occurrences + 1} 次出现）〕${record.summary}`
}
