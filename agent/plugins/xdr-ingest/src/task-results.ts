/**
 * 同类现象的结论复用（**智能体侧**，NDR 不参与判断）。
 *
 * 为什么需要：
 * - NDR 的任务去重键带时间桶（同一现象跨窗口会再次派工）；
 * - 每起一次分析会话都要重新取数、跑模型，代价高；
 * - 同类现象在 TTL 内再来一次，直接沿用上次结论并累计出现次数即可。
 *
 * 身份怎么定：`kind | subject_kind | subject | feature`。`feature` 由 NDR 随任务
 * 下发（命中线索是规则名、偏移线索是指标名……），**必须参与**——否则同一台机器
 * 上的不同规则会共用一条结论。hit 还必须有 `hint.reuse_identity`（规则 + 源 +
 * 目标/端口/事件类型集合，不含时间桶），否则不同目标集也可能误共用。拿不到身份
 * 元数据时宁可不用缓存（返回 null）。
 *
 * 什么结论可以复用：只复用 `true_positive / false_positive / benign / inconclusive`。
 * `suspicious` 与未知值一律重查——可疑是"还没查完"，复用等于把线索吞掉。
 *
 * 复用不是永久：TTL 从**上次真实分析**起算（复用时只累加次数，不续期），
 * 且新线索强度比上次高出 `strengthDelta` 时必须重查（现象变强了）。
 */

import { createHash } from 'node:crypto'
import type { ClaimedTask } from './claim-loop.ts'

/** 复用键前缀，日志/库里一眼能认出这是"任务结论"而不是旧摘要的 EA-。 */
export const TASK_RESULT_PREFIX = 'TR-'

/** 允许直接复用的结论（可疑/未知必须重查）。 */
export const REUSABLE_VERDICTS: ReadonlySet<string> = new Set([
  'true_positive',
  'false_positive',
  'benign',
  'inconclusive',
])

/** 一条可复用的任务结论。 */
export interface TaskResultRecord {
  /** 现象身份（sha256，见 taskResultKey）。 */
  readonly key: string
  readonly kind: string
  readonly subjectKind: string
  readonly subject: string
  readonly feature: string
  /** 产出这条结论的任务（复用时要写进 findings.reused_from）。 */
  readonly taskId: string
  readonly verdict: string
  /** 只复用已查清/有结论的记录；预算耗尽、工具失败等未完成任务必须重查。 */
  readonly terminalReason: string
  readonly confidence: number
  readonly summary: string
  /** 上次分析时的客观强度（新线索更强就必须重查）。 */
  readonly strength: number
  /** 该现象被看到/复用的次数（含首次）。 */
  readonly occurrences: number
  readonly analyzedAt: string
  readonly expiresAt: string
}

/** 结论库的最小存储面（内存/PG 两套实现）。 */
export interface TaskResultStore {
  readonly kind: 'memory' | 'postgres'
  load(key: string): Promise<TaskResultRecord | null>
  save(record: TaskResultRecord): Promise<boolean>
  /** 复用命中：次数 +1（不续期——TTL 永远从上次真实分析起算）。 */
  bump(key: string, nowIso: string, taskId: string): Promise<boolean>
  prune(nowIso: string): Promise<number>
  count(): Promise<number>
  close(): Promise<void>
}

/**
 * 现象身份。`feature` 缺失时返回 null：宁可多分析一次，也不能把不同规则
 * 命中的同一台机器混成一条结论（老版本 NDR 不下发 feature 时就是这种情况）。
 */
export function taskResultKey(task: ClaimedTask): string | null {
  const feature = (task.feature ?? '').trim()
  const subject = (task.subject ?? '').trim()
  if (feature === '' || feature === '-' || subject === '' || task.kind.trim() === '' || task.subject_kind.trim() === '') return null
  let eventIdentity = ''
  if (task.kind === 'hit') {
    const hint = task.hint
    if (typeof hint !== 'object' || hint === null || Array.isArray(hint)) return null
    const value = (hint as Record<string, unknown>)['reuse_identity']
    if (typeof value !== 'string' || value.trim() === '') return null
    // hit 任务同源同规则仍可能是不同目标/端口；必须有 NDR 下发的稳定内容身份。
    eventIdentity = value.trim()
  }
  // JSON tuple 避免 subject/feature 本身含分隔符时出现身份碰撞。
  const base = JSON.stringify([task.kind, task.subject_kind, subject, feature, eventIdentity])
  return TASK_RESULT_PREFIX + createHash('sha256').update(base, 'utf8').digest('hex').slice(0, 32)
}

export type ReuseDecision =
  | { readonly reuse: true }
  | { readonly reuse: false, readonly reason: string }

/** 纯策略函数（便于测试）：给定缓存记录与当前任务，判断能不能直接复用。 */
export function reuseDecision(
  record: TaskResultRecord | null,
  task: ClaimedTask,
  nowMs: number,
  ttlMs: number,
  strengthDelta: number,
): ReuseDecision {
  if (record === null) return { reuse: false, reason: 'miss' }
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) return { reuse: false, reason: 'disabled' }
  const expiresAt = Date.parse(record.expiresAt)
  const analyzedAt = Date.parse(record.analyzedAt)
  if (!Number.isFinite(expiresAt) || !Number.isFinite(analyzedAt)) {
    return { reuse: false, reason: 'invalid_time' }
  }
  // 运行时把 TTL 调短也要立即生效；记录自己保存的 expiry 仍是另一道上限。
  if (expiresAt <= nowMs || analyzedAt + ttlMs <= nowMs) {
    return { reuse: false, reason: 'expired' }
  }
  if (!REUSABLE_VERDICTS.has(record.verdict)) return { reuse: false, reason: `verdict:${record.verdict}` }
  if (record.terminalReason !== 'concluded') {
    return { reuse: false, reason: `terminal:${record.terminalReason || 'unknown'}` }
  }
  // 现象变强（合并后 strength 抬升）意味着上次的结论可能不够用了。
  const currentStrength = Number(task.strength)
  if (!Number.isFinite(currentStrength) || !Number.isFinite(record.strength)) {
    return { reuse: false, reason: 'invalid_strength' }
  }
  if (currentStrength > record.strength + Math.max(0, strengthDelta)) {
    return { reuse: false, reason: 'stronger' }
  }
  return { reuse: true }
}
