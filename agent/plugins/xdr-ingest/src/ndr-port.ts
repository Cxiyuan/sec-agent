/**
 * 把 MCP 客户端适配成领取循环/会话收尾要用的语义接口：
 * 领取、状态查询、直接交回复用结果与延后任务。
 *
 * 单独一层的原因：`claim-loop` 与 `analyst` 只该依赖这三个语义动作，
 * 而不该知道 MCP 的方法名、参数形状与错误码 —— 测试里替换成桩也不用碰 HTTP。
 */

import type { ClaimedTask, ClaimReply } from './claim-loop.ts'
import type { CompleteReply, NdrTaskPort, SuppressionView, TaskStateReply } from './analyst.ts'
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

  /** 行为基线事实（MCP 工具 list_observations）；失败返回空表，控制台降级展示。 */
  async listObservations(query: {
    kind?: string, subject?: string, minutes?: number, limit?: number, offset?: number,
  }): Promise<Record<string, unknown>> {
    try {
      return await this.caller.callTool('list_observations', {
        kind: query.kind ?? '',
        subject: query.subject ?? '',
        minutes: query.minutes ?? 1440,
        limit: query.limit ?? 50,
        offset: query.offset ?? 0,
      })
    } catch (error) {
      return { available: false, total: 0, items: [], error: error instanceof Error ? error.message : String(error) }
    }
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
        // 「领到 0 条」本身是正常回执（queue_empty），但**不显示 reason 的空任务**
        // 不是 —— 那说明两侧的回执形状没对上（实测踩过）。这里把原始键打出来。
        if (!reason) {
          console.warn(
            `[xdr-ingest] claim_tasks returned 0 tasks with no reason; reply keys: `
            + `${Object.keys(reply).join(',')} | body: ${JSON.stringify(reply).slice(0, 240)}`,
          )
        } else if (reason !== 'queue_empty') {
          console.warn(`[xdr-ingest] claim_tasks: ${reason}`)
        }
      }
      return { tasks, ...(reason ? { reason } : {}) }
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
          // B2：复用要回放结构化的东西，这几个不能丢
          ...(typeof item['findings'] === 'object' && item['findings'] !== null
            && !Array.isArray(item['findings'])
            ? { findings: item['findings'] as Record<string, unknown> }
            : {}),
          ...(Array.isArray(item['anchors'])
            ? {
                anchors: (item['anchors'] as unknown[])
                  .filter((a): a is Record<string, unknown> => typeof a === 'object' && a !== null)
                  .map(a => ({ kind: String(a['kind'] ?? ''), value: String(a['value'] ?? '') }))
                  .filter(a => a.kind !== '' && a.value !== ''),
              }
            : {}),
          ...(typeof item['recommendation'] === 'string'
            ? { recommendation: item['recommendation'] }
            : {}),
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
      /** B2 回放：上次结论的资产锚点/建议（缺省 = 不复用这两项） */
      readonly anchors?: readonly { readonly kind: string; readonly value: string }[]
      readonly recommendation?: string
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

  /**
   * 本 NDR 的身份（授权ID）。同时看两处：
   * - 工具返回体（`server_info`）；
   * - 响应头 `x-ndr-auth-id`（每个响应都带）。
   * 两者都有且不一致 → 说明中间有代理/错配，宁可报错也不要把数据写到别的项目。
   */
  async serverInfo(): Promise<{ authId: string, source: string, stable: boolean }> {
    const reply = await this.caller.callTool('server_info', {})
    if (typeof reply['error'] === 'string' && reply['error'] !== '') {
      throw new Error(`server_info: ${reply['error']}`)
    }
    const authId = String(reply['auth_id'] ?? '').trim()
    const header = typeof (this.caller as { lastAuthId?: string }).lastAuthId === 'string'
      ? String((this.caller as { lastAuthId?: string }).lastAuthId ?? '').trim()
      : ''
    if (header !== '' && authId !== '' && header !== authId) {
      throw new Error(`授权ID 不一致：server_info=${authId} 响应头=${header}（中间可能有代理或指错了 NDR）`)
    }
    return {
      authId: authId || header,
      source: String(reply['source'] ?? ''),
      stable: reply['stable'] === true,
    }
  }

  /**
   * 生效中的精准抑制清单（抑制记忆的来源）。
   *
   * 为什么智能体要自己拉一遍：NDR 侧拦的是"规则命中"这条路径，同一个现象
   * 还会从别的线索类型冒出来；智能体自己记一份，才能在起会话之前就跳过。
   */
  async listSuppressions(): Promise<readonly SuppressionView[]> {
    try {
      const reply = await this.caller.callTool('list_suppressions', { enabled_only: true, limit: 200 })
      const items = reply['items']
      if (!Array.isArray(items)) return []
      const out: SuppressionView[] = []
      for (const item of items) {
        if (typeof item !== 'object' || item === null) continue
        const row = item as Record<string, unknown>
        const id = String(row['id'] ?? '').trim()
        if (id === '') continue
        out.push({
          id,
          name: String(row['name'] ?? ''),
          mode: String(row['mode'] ?? ''),
          enabled: row['enabled'] === true,
          sourceTaskId: String(row['source_task_id'] ?? ''),
          match: row['match'] ?? null,
        })
      }
      return out
    } catch (error) {
      console.warn(
        '[xdr-ingest] list_suppressions 失败：',
        error instanceof Error ? error.message : String(error),
      )
      return []
    }
  }
}
