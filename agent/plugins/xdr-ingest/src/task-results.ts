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
  /**
   * 记录格式版本：1 = 老记录（只有 verdict/summary）；2 = 带 findings/anchors/recommendation
   * 的回放字段（B2）。读旧记录照常可用，只是不回放结构化内容。
   */
  readonly version?: number
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
  /**
   * B2 回放：上次结论的结构化发现（剔除 volatile 键后原样保存）。
   * 缺省 = 老记录（复用只回放 verdict/summary）。
   */
  readonly findings?: Readonly<Record<string, unknown>>
  /** B2 回放：上次结论挂的资产锚点（NDR `task_detail.results[].anchors`）。 */
  readonly anchors?: readonly { readonly kind: string; readonly value: string }[]
  /** B2 回放：上次结论的一句话建议（B6 字段）。 */
  readonly recommendation?: string
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
 * 现象身份（任务级）：`kind | 对象类型 | 对象 | 特征`。
 *
 * 复用键是它的哈希（不给人看）；抑制记忆要用可读的元组 —— 抑制是
 * **现象级**的事（"这类现象不用再看"），不是某个任务 id 的事。
 */
export interface TaskIdentity {
  readonly kind: string
  readonly subjectKind: string
  readonly subject: string
  readonly feature: string
}

/** 见过的一个任务（身份 + 判定）。 */
export interface TaskSeenRecord extends TaskIdentity {
  readonly taskId: string
  readonly verdict: string
}

/** 命中抑制记忆的一行。 */
export interface SuppressedTask extends TaskIdentity {
  readonly taskId: string
  readonly verdict: string
  /** 抑制条目名（人能在界面上对上号）。 */
  readonly suppressedBy: string
}

/** 任务 → 现象身份（抑制记忆与复用共用同一套口径）。 */
export function taskIdentity(task: ClaimedTask): TaskIdentity {
  return {
    kind: String(task.kind ?? ''),
    subjectKind: String(task.subject_kind ?? ''),
    subject: String(task.subject ?? ''),
    feature: String(task.feature ?? '').trim(),
  }
}

/**
 * 抑制条件树 → 现象身份（能推出才推）。
 *
 * 为什么需要：抑制条目里若没带 `source_task_id`（人工建的、或者智能体没传），
 * 就没法按任务 id 对上号；这时只能从条件树反推它针对的是哪类现象：
 * 命中线索的身份是 `kind=hit | 对象=源 IP | 特征=规则名`，
 * 而条件树里的 `src_ip`/`dst_ip` + `rule` 正好能拼出这个四元组。
 *
 * 推不出来就返回 null —— **宁可不同步，也不乱标**（标错了会让不相干的线索被跳过）。
 */
export function identityOfMatch(match: unknown): TaskIdentity | null {
  const subjects: string[] = []
  const features: string[] = []
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
    if (value === '') return
    if (field === 'src_ip' || field === 'dst_ip') subjects.push(value)
    if (field === 'rule') features.push(value)
  }
  walk(match)
  const subject = subjects[0] ?? ''
  const feature = features[0] ?? ''
  if (subject === '' || feature === '') return null
  return { kind: 'hit', subjectKind: 'ip', subject, feature }
}

/**
 * 现象身份（B1，2026-10-29 整改）。
 *
 * **NDR 在 hint 里下发的 `reuse_identity` 优先**：它按 kind 给出完整客观身份 ——
 * observation 的身份含事实 key（同一资产外连 A/B 是两条不同事实，各有各的身份），
 * hit/hit_cluster 是跨时间窗稳定的内容身份。之前 agent 拿 kind|subject|feature 自己拼，
 * "同一资产的不同外连目标"共用一条结论（实测踩过）。
 *
 * 兜底：旧版 NDR 不发身份时，非 hit 类型回退到本地拼法（feature 缺失返回 null：
 * 宁可多分析一次，也不能把不同规则命中的同一台机器混成一条结论）。
 * `taskReuseRequireIdentity`（默认 true）关掉后彻底回退旧行为。
 */
export function taskResultKey(
  task: ClaimedTask,
  opts: { requireIdentity?: boolean } = {},
): string | null {
  const subject = (task.subject ?? '').trim()
  if (subject === '' || task.kind.trim() === '' || task.subject_kind.trim() === '') return null
  const hint = task.hint
  const hintIdentity =
    typeof hint === 'object' && hint !== null && !Array.isArray(hint)
      ? String((hint as Record<string, unknown>)['reuse_identity'] ?? '').trim()
      : ''
  // hit/hit_cluster 本地四元组不够稳（同源同规则仍可能是不同目标/端口/簇）：
  // 没有下发身份就不复用（taskReuseRequireIdentity=false 时临时回退旧行为）
  const requireIdentity = opts.requireIdentity ?? true
  if (hintIdentity === '' && requireIdentity) return null
  if (hintIdentity !== '') {
    const base = JSON.stringify([task.kind, task.subject_kind, subject, hintIdentity])
    return TASK_RESULT_PREFIX + createHash('sha256').update(base, 'utf8').digest('hex').slice(0, 32)
  }
  const feature = (task.feature ?? '').trim()
  if (feature === '' || feature === '-') return null
  // JSON tuple 避免 subject/feature 本身含分隔符时出现身份碰撞。
  const base = JSON.stringify([task.kind, task.subject_kind, subject, feature, ''])
  return TASK_RESULT_PREFIX + createHash('sha256').update(base, 'utf-8').digest('hex').slice(0, 32)
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
