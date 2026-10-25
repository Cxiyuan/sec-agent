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

/** 会话结束后任务应处的状态（NDR `task_state` 的返回形状）。 */
export interface TaskStateReply {
  readonly state?: string
  readonly task_state?: string
  readonly result_id?: string
  readonly verdict?: string
  readonly error?: string
}

export interface NdrTaskPort extends NdrPort {
  taskState(taskId: string): Promise<TaskStateReply>
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
}

export interface AnalystOutcome {
  readonly taskId: string
  readonly completed: boolean
  readonly state: string
  readonly deferred: boolean
  readonly durationMs: number
  readonly error?: string
}

let sessionCounter = 0

export class Analyst {
  private readonly options: AnalystOptions

  constructor(options: AnalystOptions) {
    this.options = options
  }

  async run(task: ClaimedTask): Promise<AnalystOutcome> {
    const startedAt = Date.now()
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
    const state = await this.readState(task.id)
    const completed = state === 'done'
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

  private async readState(taskId: string): Promise<string> {
    try {
      const reply = await this.options.ndr.taskState(taskId)
      if (reply.error) return ''
      return String(reply.task_state ?? reply.state ?? '')
    } catch {
      // 查不到状态：宁可当成"没交回"（会 defer，代价小），也不要当成完成（会丢线索）
      return ''
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
