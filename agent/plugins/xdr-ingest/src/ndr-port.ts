/**
 * 把 MCP 客户端适配成领取循环/会话收尾要用的三段接口：
 * `claimTasks` / `taskState` / `deferTask`。
 *
 * 单独一层的原因：`claim-loop` 与 `analyst` 只该依赖这三个语义动作，
 * 而不该知道 MCP 的方法名、参数形状与错误码 —— 测试里替换成桩也不用碰 HTTP。
 */

import type { ClaimedTask, ClaimReply } from './claim-loop.ts'
import type { NdrTaskPort, TaskStateReply } from './analyst.ts'
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
        return { error: reply['error'] }
      }
      const reason = typeof reply['reason'] === 'string' ? reply['reason'] : undefined
      return { tasks: asTasks(reply['tasks']), ...(reason ? { reason } : {}) }
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) }
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
    return out
  }

  async deferTask(taskId: string, reason: string): Promise<unknown> {
    return this.caller.callTool('defer_task', { task_id: taskId, reason })
  }
}
