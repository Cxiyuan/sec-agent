/**
 * 把 MCP 客户端适配成领取循环/会话收尾要用的语义接口：
 * 领取、状态查询、直接交回复用结果与延后任务。
 *
 * 单独一层的原因：`claim-loop` 与 `analyst` 只该依赖这三个语义动作，
 * 而不该知道 MCP 的方法名、参数形状与错误码 —— 测试里替换成桩也不用碰 HTTP。
 */

import type { ClaimedTask, ClaimReply } from './claim-loop.ts'
import type { CompleteReply, NdrTaskPort, TaskStateReply } from './analyst.ts'
import type { McpHttpClient } from './mcp-http.ts'

/** 只依赖 `callTool` 这一件事，便于测试注入。 */
export interface ToolCaller {
  callTool(name: string, args?: Record<string, unknown>): Promise<Record<string, unknown>>
}

function asTasks(value: unknown): ClaimedTask[] {
  if (!Array.isArray(value)) return []
  const out: ClaimedTask[] = []
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue
    const row = item as Record<string, unknown>
    const id = String(row['id'] ?? '').trim()
    if (id === '') continue
    out.push({
      id,
      kind: String(row['kind'] ?? ''),
      strength: Number(row['strength'] ?? 0),
      priority: Number(row['priority'] ?? 0),
      subject_kind: String(row['subject_kind'] ?? ''),
      subject: String(row['subject'] ?? ''),
      ...(typeof row['feature'] === 'string' && row['feature'] !== ''
        ? { feature: row['feature'] }
        : {}),
      window_start: row['window_start'] === undefined ? null : (row['window_start'] as string | null),
      window_end: row['window_end'] === undefined ? null : (row['window_end'] as string | null),
      hint: row['hint'] ?? null,
      coalesced: Number(row['coalesced'] ?? 0),
      attempts: Number(row['attempts'] ?? 0),
    })
  }
  return out
}

export class NdrTaskPortAdapter implements NdrTaskPort {
  private readonly caller: ToolCaller

  constructor(caller: McpHttpClient | ToolCaller) {
    this.caller = caller as ToolCaller
  }

  async claimTasks(limit: number): Promise<ClaimReply> {
    try {
      const reply = await this.caller.callTool('claim_tasks', { limit })
      if (typeof reply['error'] === 'string' && reply['error'] !== '') {
        console.warn(`[xdr-ingest] claim_tasks error: ${reply['error'].slice(0, 240)}`)
        return { error: reply['error'] }
      }
      const reason = typeof reply['reason'] === 'string' ? reply['reason'] : undefined
      const tasks = asTasks(reply['tasks'])
      if (tasks.length === 0) {
        // 「领到 0 条」本身是正常回执（queue_empty / budget_exhausted / inflight_full），
        // 但**不显示 reason 的空任务**不是 —— 那说明两侧的回执形状没对上（实测踩过）。
        // 这里把原始键打出来，下次一眼就能看出差在哪。
        if (!reason) {
          console.warn(
            `[xdr-ingest] claim_tasks returned 0 tasks with no reason; reply keys: `
            + `${Object.keys(reply).join(',')} | body: ${JSON.stringify(reply).slice(0, 240)}`,
          )
        } else if (reason !== 'queue_empty') {
          console.warn(`[xdr-ingest] claim_tasks: ${reason}`)
        }
      }
      // 预算快照原样透传（工作台展示；不参与本进程判断）
      const budget = typeof reply['budget'] === 'object' && reply['budget'] !== null
        ? reply['budget'] as ClaimReply['budget']
        : undefined
      return { tasks, ...(budget ? { budget } : {}), ...(reason ? { reason } : {}) }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(`[xdr-ingest] claim_tasks threw: ${message.slice(0, 240)}`)
      return { error: message }
    }
  }

  async taskState(taskId: string): Promise<TaskStateReply> {
    const reply = await this.caller.callTool('task_state', { task_id: taskId })
    // `exactOptionalPropertyTypes` 下可选属性不能显式赋 undefined，
    // 所以只把真正有值的键展开进去（否则类型检查拒绝）。
    const out: TaskStateReply = {}
    const pick = (key: string): string | null =>
      typeof reply[key] === 'string' && reply[key] !== '' ? (reply[key] as string) : null
    for (const key of ['state', 'task_state', 'result_id', 'verdict', 'error'] as const) {
      const value = pick(key)
      if (value !== null) {
        ;(out as Record<string, string>)[key] = value
      }
    }
    // `task_detail` 会带回该任务的历史结论（最新在前）：复用库要靠它拿
    // verdict/summary/confidence，否则只能存一个"看起来完成了"的空壳。
    if (Array.isArray(reply['results'])) {
      const results = reply['results']
        .filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null)
        .slice(0, 5)
        .map(item => ({
          ...(typeof item['verdict'] === 'string' ? { verdict: item['verdict'] } : {}),
          ...(typeof item['terminal_reason'] === 'string' ? { terminal_reason: item['terminal_reason'] } : {}),
          ...(typeof item['confidence'] === 'number' ? { confidence: item['confidence'] } : {}),
          ...(typeof item['summary'] === 'string' ? { summary: item['summary'] } : {}),
          ...(typeof item['created_at'] === 'string' ? { created_at: item['created_at'] } : {}),
        }))
      ;(out as { results?: unknown }).results = results
    }
    return out
  }

  /** 直接交回一条结论（复用命中时用，省掉一次完整分析会话）。 */
  async completeTask(
    taskId: string,
    payload: {
      readonly verdict: string
      readonly summary: string
      readonly confidence: number
      readonly findings: Record<string, unknown>
      readonly terminal_reason: string
      readonly tools_used: number
      readonly duration_ms: number
    },
  ): Promise<CompleteReply> {
    const reply = await this.caller.callTool('complete_task', { task_id: taskId, ...payload })
    const out: CompleteReply = {}
    const pick = (key: string): string | null =>
      typeof reply[key] === 'string' && reply[key] !== '' ? (reply[key] as string) : null
    for (const key of ['task_state', 'state', 'error'] as const) {
      const value = pick(key)
      if (value !== null) {
        ;(out as Record<string, string>)[key] = value
      }
    }
    if (reply['ok'] === true) {
      ;(out as { ok?: boolean }).ok = true
    }
    return out
  }

  async deferTask(taskId: string, reason: string): Promise<unknown> {
    return this.caller.callTool('defer_task', { task_id: taskId, reason })
  }
}
