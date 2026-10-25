/**
 * 门铃载荷：NDR 只告诉你「有新线索了」，**不含任何事件数据**。
 *
 * 契约（`docs/agent-contract.md` §1 / NDR 侧 `detector/push.send_doorbell`）：
 * `{"doorbell": {queue_len, top_kind, max_strength, watermark, ts}}` —— 恰好这 5 个字段。
 *
 * 为什么不带内容：带内容就退化成"规则结果解释器"，而且没有成本上限。
 * 看什么、查多深由智能体自己用 `claim_tasks` 领（服务端强制预算）。
 */

export interface Doorbell {
  /** 队列里当前有多少条线索（只用来决定要不要立刻领，不决定领多少） */
  readonly queue_len: number
  /** 队列里客观强度最高的那类线索（`novelty` / `shift` / `coverage` / `hit` / `retest`） */
  readonly top_kind: string
  /** 队列里最高的客观强度 0~1（**不是严重度**，不含威胁语义） */
  readonly max_strength: number
  /** NDR 侧的队列水位（只用于日志与去重，不要拿它做判断依据） */
  readonly watermark: string
  /** 门铃发出时间（ISO8601） */
  readonly ts: string
}

export class DoorbellFormatError extends Error {}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

/**
 * 从请求体里提取门铃。
 *
 * 返回 `null` 表示**不是门铃**（调用方继续按旧摘要载荷处理）；
 * 抛 `DoorbellFormatError` 表示"看起来是门铃但载荷坏了"——必须 400，
 * 让 NDR 立刻看见配置/版本不匹配，而不是被当成成功回执后静默丢线索。
 */
export function parseDoorbell(body: unknown): Doorbell | null {
  const root = asRecord(body)
  if (root === null) return null
  if (!('doorbell' in root)) return null
  const inner = asRecord(root['doorbell'])
  if (inner === null) throw new DoorbellFormatError('doorbell must be an object')

  const queueLen = inner['queue_len']
  if (typeof queueLen !== 'number' || !Number.isFinite(queueLen) || queueLen < 0) {
    throw new DoorbellFormatError('doorbell.queue_len must be a non-negative number')
  }
  const maxStrength = inner['max_strength']
  if (typeof maxStrength !== 'number' || !Number.isFinite(maxStrength)) {
    throw new DoorbellFormatError('doorbell.max_strength must be a number')
  }
  const watermark = inner['watermark']
  const ts = inner['ts']
  if (typeof watermark !== 'string') {
    throw new DoorbellFormatError('doorbell.watermark must be a string')
  }
  if (typeof ts !== 'string') {
    throw new DoorbellFormatError('doorbell.ts must be a string')
  }
  const topKind = inner['top_kind']
  return {
    queue_len: Math.trunc(queueLen),
    top_kind: typeof topKind === 'string' ? topKind.slice(0, 32) : '',
    max_strength: maxStrength,
    watermark: watermark.slice(0, 128),
    ts: ts.slice(0, 64),
  }
}
