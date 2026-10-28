/**
 * 运行时保护：失败熔断 + 全局并发闸门。
 *
 * 为什么需要熔断：模型 429/超时的时候，领取循环会照常领活、每条都失败、再延后 ——
 * 队列被搅乱、租约被白白消耗，而运维只能靠翻日志发现（2026-10 实测）。
 * 连续失败到阈值就**暂停领取**（状态 degraded），冷却后半开重试，成功一次即恢复。
 *
 * 为什么需要全局闸门：并发原本只按"项目"算，项目数一多，总并发 = 项目数 × maxConcurrent，
 * 模型配额和内存都会被打爆。闸门是进程内共享的，跨项目生效。
 */

export interface BreakerOptions {
  /** 连续失败多少次打开熔断（默认 3）。 */
  readonly threshold: number
  /** 初始冷却（毫秒，默认 5 分钟），每次再失败翻倍。 */
  readonly baseCooldownMs: number
  /** 冷却上限（默认 60 分钟）。 */
  readonly maxCooldownMs: number
}

export class FailureBreaker {
  private readonly options: BreakerOptions
  private failures = 0
  private openUntil = 0
  private strikes = 0
  private lastError = ''

  constructor(options: BreakerOptions) {
    this.options = options
  }

  /** 记一次失败；返回是否**本次**打开了熔断（用于报警日志）。 */
  recordFailure(reason: string, now = Date.now()): boolean {
    this.failures += 1
    this.lastError = reason.slice(0, 200)
    if (this.failures < this.options.threshold || this.isOpen(now)) return false
    this.strikes += 1
    const cooldown = Math.min(
      this.options.maxCooldownMs,
      this.options.baseCooldownMs * 2 ** (this.strikes - 1),
    )
    this.openUntil = now + cooldown
    return true
  }

  recordSuccess(): void {
    this.failures = 0
    this.strikes = 0
    this.openUntil = 0
    this.lastError = ''
  }

  isOpen(now = Date.now()): boolean {
    return this.openUntil > now
  }

  /** 剩余冷却（秒），界面显示用。 */
  remainingSeconds(now = Date.now()): number {
    return this.openUntil > now ? Math.ceil((this.openUntil - now) / 1000) : 0
  }

  state(): Record<string, unknown> {
    return {
      open: this.isOpen(),
      failures: this.failures,
      strikes: this.strikes,
      retry_in_seconds: this.remainingSeconds(),
      last_error: this.lastError,
    }
  }
}

/** 进程内全局并发闸门（跨项目共享）。 */
export class ConcurrencyGate {
  private readonly max: () => number
  private inUse = 0

  constructor(max: () => number) {
    this.max = max
  }

  tryAcquire(): boolean {
    if (this.inUse >= Math.max(1, this.max())) return false
    this.inUse += 1
    return true
  }

  release(): void {
    this.inUse = Math.max(0, this.inUse - 1)
  }

  free(): number {
    return Math.max(0, Math.max(1, this.max()) - this.inUse)
  }

  state(): Record<string, number> {
    return { in_use: this.inUse, max: Math.max(1, this.max()), free: this.free() }
  }
}

/** 判断一次分析失败是不是"模型/服务商侧"的暂时性故障（用于熔断）。 */
export function isTransientFailure(message: string): boolean {
  const text = String(message || '').toLowerCase()
  if (text === '') return false
  return [
    '429', 'rate limit', 'quota', 'too many requests', 'overloaded',
    'timeout', 'timed out', 'econnreset', 'etimedout', 'socket hang up',
    '503', '502', '504', 'context window exceeds',
  ].some(token => text.includes(token))
}
