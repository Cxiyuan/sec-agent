/**
 * 一次分析会话的完整生命周期：起 agent → 喂提示词 → 等空闲 → **确认交回** → 收尾。
 *
 * 为什么"确认交回"是单独一步（`task_state`）：
 * 会话空闲 **不等于** 任务完成 —— 模型很可能查完就收工、忘了 `complete_task`。
 * 不查这一步，任务会一直挂着直到租约到期被回收，`attempts` 累加，
 * 最后进 `stuck`（表面上"智能体在跑"，实际什么都没交）。
 */

import type { AgentsServiceLike } from './agent-port.ts'
import type { ClaimedTask, NdrPort } from './claim-loop.ts'
import { buildAnalysisPrompt } from './prompt.ts'
import { reuseDecision, taskResultKey } from './task-results.ts'
import type { TaskResultRecord, TaskResultStore } from './task-results.ts'

/** `task_state` 里的一条历史结论（最新在前）。 */
export interface TaskResultView {
  readonly verdict?: string
  readonly terminal_reason?: string
  readonly confidence?: number
  readonly summary?: string
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
}

export interface AnalystOptions {
  readonly agents: AgentsServiceLike
  readonly ndr: NdrTaskPort
  /** 单会话超时（毫秒）——超时先 cancel 再 defer，别让它无限占着并发槽 */
  readonly timeoutMs: number
  readonly provider?: string
  readonly model?: string
  /** 事件来源标记（出现在会话记录里，便于回溯是哪段代码起的） */
  readonly source?: string
  /** 同类现象结论库；不传 = 不复用（测试/回滚）。 */
  readonly taskResults?: TaskResultStore
  /** 复用有效期（毫秒，从上次真实分析起算；0 = 关闭复用）。 */
  readonly taskReuseTtlMs?: number
  /** 新线索强度比上次高多少就必须重查（现象变强）。 */
  readonly taskReuseStrengthDelta?: number
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
      return reused
    }

    const sessionId = `xdr-analysis-${task.id}-${Date.now()}-${sessionCounter++}`
    const handle = await this.options.agents.create({
      sessionId,
      agentOptions: {
        ...(this.options.provider ? { provider: this.options.provider } : {}),
        ...(this.options.model ? { model: this.options.model } : {}),
      },
    })
    let timedOut = false
    let error: string | undefined
    try {
      const followup = handle.agent.followup({
        content: [{ type: 'text', text: buildAnalysisPrompt(task) }],
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
      await Promise.resolve(handle.dispose()).catch(() => undefined)
    }

    // 会话结束不等于任务完成：必须回查 NDR 侧状态
    const reply = await this.readTask(task.id)
    const state = stateOf(reply)
    const completed = state === 'done'
    if (completed) {
      // 结论入库供下次复用；失败只告警，不要让一条已交回的任务看起来失败
      await this.remember(task, reply)
    }
    let deferred = false
    if (!completed) {
      // 没交回：显式延后（不算失败），把租约让出来，同时留下"为什么"
      const reason = timedOut ? 'timeout' : error ? `agent_error: ${error.slice(0, 120)}` : 'no_conclusion'
      try {
        await this.options.ndr.deferTask(task.id, reason)
        deferred = true
      } catch (exc) {
        error = error ?? (exc instanceof Error ? exc.message : String(exc))
      }
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

  /** 把刚交回的结论写进复用库（只存最新一条）。 */
  private async remember(task: ClaimedTask, reply: TaskStateReply): Promise<void> {
    const store = this.options.taskResults
    const ttlMs = this.options.taskReuseTtlMs ?? 0
    if (store === undefined || ttlMs <= 0) return
    const key = taskResultKey(task)
    if (key === null) return
    const latest = reply.results?.[0]
    if (latest === undefined) return
    const verdict = String(latest.verdict ?? '').trim().toLowerCase()
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
