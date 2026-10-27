/**
 * 领取循环：门铃/定时唤醒 → `claim_tasks` 领活 → 起分析会话 → 结束判定。
 *
 * 设计取舍：
 * - **门铃会丢**（重启、网络），所以必须有定时自轮询兜底（默认 15 分钟）；
 * - **门铃会连着来**，所以唤醒要**去抖**（默认 3 秒合并），否则一串门铃会开出十几个会话；
 * - **失败要退避**：NDR 短暂不可用时不要每 15 分钟还按原速去撞，指数退避到封顶；
 * - **领取额度不设限**：NDR 不限制领取数量或并发，本进程只按 `maxConcurrent` 控制
 *   自己的会话并发（那是执行侧容量，不是分析额度）。
 */

export interface ClaimedTask {
  readonly id: string
  readonly kind: string
  readonly strength: number
  readonly priority?: number
  readonly subject_kind: string
  readonly subject: string
  /**
   * 现象特征（NDR 下发）：命中线索是规则名、偏移线索是指标名、首见是
   * `first:ip`…… 结论复用的身份必须带上它，否则同一台机器上的不同规则
   * 会被当成同一件事。老版本 NDR 不带这个字段时为 undefined（此时不复用）。
   */
  readonly feature?: string
  readonly window_start?: string | null
  readonly window_end?: string | null
  readonly hint?: unknown
  readonly coalesced?: number
  readonly attempts?: number
}

export interface ClaimReply {
  readonly tasks?: readonly ClaimedTask[]
  /** NDR 的正常回执：queue_empty —— 不是错误 */
  readonly reason?: string
  readonly error?: string
}

/** NDR 侧最小端口（测试里替换成假实现，不碰网络）。 */
export interface NdrPort {
  claimTasks(limit: number): Promise<ClaimReply>
}

export interface ClaimLoopOptions {
  /** 定时自轮询间隔（秒） */
  readonly pollSeconds: number
  /** 本进程最多同时跑几个分析会话 */
  readonly maxConcurrent: number
  /** 单次领取条数上限 */
  readonly claimLimit: number
  /** 门铃去抖窗口（毫秒） */
  readonly doorbellDebounceMs: number
  /** 退避上限（毫秒） */
  readonly backoffMaxMs: number
  /** 领活通道（生产由 MCP 客户端实现；测试里替换成假实现，不碰网络） */
  readonly claimTasks: (limit: number) => Promise<ClaimReply>
  /** 起一个分析会话（由 analyst 提供；测试里替换成计数桩） */
  readonly runTask: (task: ClaimedTask) => Promise<void>
  /** 可注入时钟/定时器（测试用） */
  readonly now?: () => number
}

export interface ClaimLoopStats {
  polls: number
  claimed: number
  started: number
  running: number
  failedClaims: number
  doorbells: number
  droppedByConcurrency: number
  consecutiveErrors: number
  lastError: string
}

export class ClaimLoop {
  private readonly options: ClaimLoopOptions
  /** 可在运行期热更新的三个旋钮；初值来自 cordis 配置，之后由工作台持久化的值覆盖。 */
  private readonly settings: { pollSeconds: number, maxConcurrent: number, claimLimit: number }
  private running = 0
  private timer: ReturnType<typeof setTimeout> | null = null
  private debounce: ReturnType<typeof setTimeout> | null = null
  private stopped = true
  private backoffMs = 0
  private lastErrorAt = 0
  private readonly now: () => number
  readonly stats: ClaimLoopStats = {
    polls: 0,
    claimed: 0,
    started: 0,
    running: 0,
    failedClaims: 0,
    doorbells: 0,
    droppedByConcurrency: 0,
    consecutiveErrors: 0,
    lastError: '',
  }

  constructor(options: ClaimLoopOptions) {
    this.options = options
    this.settings = {
      pollSeconds: options.pollSeconds,
      maxConcurrent: options.maxConcurrent,
      claimLimit: options.claimLimit,
    }
    this.now = options.now ?? Date.now
  }

  /** 当前生效的三个运行参数（status 与工作台表单读同一份）。 */
  settingsSnapshot(): { pollSeconds: number, maxConcurrent: number, claimLimit: number } {
    return { ...this.settings }
  }

  /**
   * 热更新运行参数：只改传入字段，其余保持。
   * 轮询间隔变化时立刻按新间隔重排定时器（否则要等旧周期走完才生效）。
   * @param patch - 已经过校验的新值（工作台/服务端保证范围）。
   */
  configure(patch: Partial<{ pollSeconds: number, maxConcurrent: number, claimLimit: number }>): void {
    const pollChanged = patch.pollSeconds !== undefined && patch.pollSeconds !== this.settings.pollSeconds
    if (patch.pollSeconds !== undefined) this.settings.pollSeconds = patch.pollSeconds
    if (patch.maxConcurrent !== undefined) this.settings.maxConcurrent = patch.maxConcurrent
    if (patch.claimLimit !== undefined) this.settings.claimLimit = patch.claimLimit
    if (pollChanged && !this.stopped) this.schedule(0)
  }

  /** 启动：先立刻领一次（部署后不必等第一个轮询周期），再按间隔自轮询。 */
  start(): void {
    if (!this.stopped) return
    this.stopped = false
    void this.tick()
    this.schedule(0)
  }

  stop(): void {
    this.stopped = true
    if (this.timer !== null) clearTimeout(this.timer)
    if (this.debounce !== null) clearTimeout(this.debounce)
    this.timer = null
    this.debounce = null
  }

  /** 门铃：去抖后立刻领一次（不是"每声都领"，否则一串门铃会瞬间打满并发）。 */
  wake(): void {
    this.stats.doorbells += 1
    if (this.stopped) return
    if (this.debounce !== null) clearTimeout(this.debounce)
    this.debounce = setTimeout(() => {
      this.debounce = null
      void this.tick()
    }, Math.max(0, this.options.doorbellDebounceMs))
    this.debounce.unref?.()
  }

  /** 一轮：按剩余并发领活；领到的任务立刻起会话（不串行等）。
   *
   * 刻意**不检查 `stopped`**：`tick()` 是可以被直接调用的一步（测试、运维手动戳），
   * `stopped` 只约束"定时器要不要继续排下一轮"，否则手动调用永远打不开。
   */
  async tick(): Promise<void> {
    this.stats.running = this.running
    const free = this.settings.maxConcurrent - this.running
    if (free <= 0) {
      this.stats.droppedByConcurrency += 1
      return
    }
    const want = Math.max(1, Math.min(free, this.settings.claimLimit))
    this.stats.polls += 1
    let reply: ClaimReply
    try {
      reply = await this.options.claimTasks(want)
    } catch (error) {
      this.recordFailure(error)
      return
    }
    if (reply.error) {
      this.recordFailure(new Error(reply.error))
      return
    }
    this.stats.consecutiveErrors = 0
    this.backoffMs = 0
    const tasks = reply.tasks ?? []
    if (tasks.length === 0) return
    this.stats.claimed += tasks.length
    for (const task of tasks) {
      this.running += 1
      this.stats.started += 1
      void this.runOne(task)
    }
  }

  private async runOne(task: ClaimedTask): Promise<void> {
    try {
      await this.options.runTask(task)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.stats.lastError = message.slice(0, 300)
    } finally {
      this.running = Math.max(0, this.running - 1)
      this.stats.running = this.running
    }
  }

  private recordFailure(error: unknown): void {
    this.stats.failedClaims += 1
    this.stats.consecutiveErrors += 1
    this.backoffMs = Math.min(
      this.options.backoffMaxMs,
      Math.max(1000, this.backoffMs === 0 ? 1000 : this.backoffMs * 2),
    )
    this.stats.lastError = (error instanceof Error ? error.message : String(error)).slice(0, 300)
    // 同类错误 5 分钟内只记一次（NDR 短时不可用时不要把日志刷满）
    const now = this.now()
    if (now - this.lastErrorAt > 300_000) {
      this.lastErrorAt = now
      console.warn(`[xdr-ingest] 领取失败（已连续 ${this.stats.consecutiveErrors} 次）：${this.stats.lastError}`)
    }
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return
    if (this.timer !== null) clearTimeout(this.timer)
    const baseMs = delayMs > 0 ? delayMs : this.options.pollSeconds * 1000
    const waitMs = Math.max(baseMs, this.backoffMs)
    this.timer = setTimeout(() => {
      this.timer = null
      void this.tick().finally(() => this.schedule(0))
    }, waitMs)
    this.timer.unref?.()
  }

}
