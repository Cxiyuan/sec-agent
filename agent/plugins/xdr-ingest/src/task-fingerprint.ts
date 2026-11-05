/**
 * 分析事实指纹：决定“能不能续跑同一个 DSH 会话”。
 *
 * 只纳入会进入 `buildAnalysisPrompt` 的事实（以及工作流编排）。任务 ID/窗口/
 * 强度/合并次数/hint/资产角色任何一项变化，都意味着旧会话看到的是旧事实，
 * 不能拿它继续推理；反过来，NDR claim 的 attempts/state/lease 变化不是事实，
 * 必须排除，否则每次 defer 后都永远无法恢复。
 */

import { createHash } from 'node:crypto'
import type { ClaimedTask } from './claim-loop.ts'
import type { WorkflowRecord } from './state-store.ts'

/** 提示词语义版本；修改 prompt.ts 的任务事实格式时递增。 */
const PROMPT_VERSION = 1

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical)
  if (typeof value === 'object' && value !== null) {
    const source = value as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(source).sort()) {
      const next = canonical(source[key])
      if (next !== undefined) out[key] = next
    }
    return out
  }
  return value
}

function assetKey(asset: { readonly kind?: string; readonly value?: string }): string {
  return `${asset.kind ?? ''}\u0000${asset.value ?? ''}`
}

/**
 * 计算可恢复会话的指纹。
 *
 * `workflow` 是提示词的一部分（阶段/目标/工具建议），工作流换了就不该拿旧会话
 * 继续；`prompt_version` 让提示词语义升级时自动失效旧会话。
 */
export function taskFingerprint(task: ClaimedTask, workflow?: WorkflowRecord | null): string {
  const affected = [...(task.affected_assets ?? [])]
    .map(asset => ({ kind: asset.kind ?? '', value: asset.value ?? '' }))
    .sort((a, b) => assetKey(a).localeCompare(assetKey(b)))
  const peers = [...(task.peers ?? [])].sort()
  const facts = {
    version: PROMPT_VERSION,
    task_id: task.id,
    kind: task.kind,
    subject_kind: task.subject_kind,
    subject: task.subject,
    principal_asset: task.principal_asset ?? '',
    direction: task.direction ?? '',
    affected_assets: affected,
    peers,
    reuse_identity: task.reuse_identity ?? '',
    feature: task.feature ?? '',
    strength: Number.isFinite(task.strength) ? Math.round(task.strength * 1000) / 1000 : 0,
    priority: task.priority ?? 0,
    window_start: task.window_start ?? null,
    window_end: task.window_end ?? null,
    coalesced: task.coalesced ?? 0,
    hint: canonical(task.hint),
    workflow: workflow === undefined || workflow === null
      ? null
      : {
          workflowId: workflow.workflowId,
          name: workflow.name,
          stages: canonical(workflow.stages),
        },
  }
  const payload = JSON.stringify(canonical(facts))
  return createHash('sha256').update(payload, 'utf8').digest('hex').slice(0, 32)
}
