/**
 * 智能体侧持久化状态（**按项目组织隔离**）。
 *
 * 一个项目组织 = 一台 NDR（授权ID 8 位）。所有表都带 `project_id`，读写都在
 * 项目边界内 —— 一台 agent 接多个 NDR 时，各项目的数据（结论复用、脚本、抑制记忆、
 * 分析过程、结论留档、运行参数）互不可见。
 *
 * 为什么这些数据不再放 NDR 的 PG：多项目下每个 NDR 一套库，控制台要跨库读数据
 * 既慢又依赖每条隧道；agent 自建一套 PG，一份连接 + project_id 就够。
 *
 * 两份实现：
 * - `MemoryStateStore`：PG 不可用时的降级（重启即丢，明确告警）；
 * - `PostgresStateStore`（`pg-state-store.ts`）：生产实现，表结构自管理。
 *
 * 接口都不带 `projectId` 参数：**store 实例本身绑定一个项目**（构造时传入），
 * 这样调用方（分析循环、脚本工具、控制台）不会漏传项目而串数据。
 */

import { randomUUID } from 'node:crypto'
import type { TaskResultRecord, TaskResultStore, SuppressedTask, TaskIdentity, TaskSeenRecord } from './task-results.ts'
import type { ConclusionPage, ConclusionQuery, ConclusionRecord } from './conclusions.ts'
import type { RuntimeSettings } from './settings.ts'

export type { RuntimeSettings } from './settings.ts'

/* ------------------------------------------------------------------ */
/* 项目组织                                                            */
/* ------------------------------------------------------------------ */

/** 项目健康状态：`unchecked` 还没校验过；`auth_mismatch` 授权ID 对不上；`unreachable` 连不上。 */
export type ProjectStatus = 'ok' | 'auth_mismatch' | 'unreachable' | 'unchecked' | 'disabled'

/** 一个项目组织（= 一台 NDR）。`projectId` 就是 NDR 的授权ID。 */
export interface ProjectRecord {
  /** NDR 授权ID（8 位大写字母+数字），项目主键 */
  readonly projectId: string
  readonly name: string
  readonly mcpUrl: string
  readonly mcpToken: string
  readonly pushToken: string
  readonly enabled: boolean
  readonly status: ProjectStatus
  readonly statusDetail: string
  readonly lastCheckedAt: string
  readonly createdAt: string
  readonly updatedAt: string
}

/** 新建/更新项目时的输入（`projectId` 为空 = 新建时由调用方提供）。 */
export interface ProjectInput {
  readonly projectId: string
  readonly name: string
  readonly mcpUrl: string
  readonly mcpToken: string
  readonly pushToken: string
  readonly enabled?: boolean
}

/* ------------------------------------------------------------------ */
/* 分析过程索引（任务 → 会话）                                          */
/* ------------------------------------------------------------------ */

/** 项目数据面：一个项目绑定一套（分析循环、脚本工具、控制台共用同一实例）。 */
export type DataStore = TaskResultStore & ScriptStore & TaskSeenStore & ConclusionStore
  & SettingsStore & ProcessStore

/** 一次分析的结局。`running` 表示还没结束（控制台可实时看当前工具调用）。 */
export type ProcessOutcome = 'running' | 'done' | 'reused' | 'suppressed' | 'deferred' | 'failed'

/** 过程索引的一行。 */
export interface ProcessRecord {
  readonly taskId: string
  readonly sessionId: string
  readonly kind: string
  readonly subject: string
  readonly model: string
  readonly startedAt: string
  readonly endedAt: string
  readonly outcome: ProcessOutcome
  readonly toolsUsed: number
  readonly durationMs: number
  readonly verdict: string
  readonly note: string
}

/** 开始一次分析（起会话前调用）。 */
export interface ProcessStart {
  readonly taskId: string
  readonly sessionId: string
  readonly kind: string
  readonly subject: string
  readonly model: string
  readonly startedAt: string
}

/** 收尾（不起会话的复用/抑制跳过也走这里，`sessionId` 为空）。 */
export interface ProcessFinish {
  readonly taskId: string
  readonly endedAt: string
  readonly outcome: ProcessOutcome
  readonly toolsUsed?: number
  readonly durationMs?: number
  readonly verdict?: string
  readonly note?: string
}

/* ------------------------------------------------------------------ */
/* 脚本库                                                              */
/* ------------------------------------------------------------------ */

/** 脚本库里的一条脚本。 */
export interface AnalysisScript {
  readonly id: string
  /** 唯一名字（**项目内**唯一；工具按名字覆盖/复用）。 */
  readonly name: string
  /** 什么场景该用它（检索的主要依据，写清楚"什么时候用"）。 */
  readonly scenario: string
  readonly language: string
  readonly code: string
  /** 可能为对象/数组：变量名 → 说明/默认值（原样存，不强制形状）。 */
  readonly variables: unknown
  readonly tags: readonly string[]
  readonly notes: string
  readonly sourceTaskId: string
  readonly usageCount: number
  readonly createdAt: string
  readonly updatedAt: string
  /** 空串 = 从没用过。 */
  readonly lastUsedAt: string
  /** 停用后 `find/get` 不再返回（模型不会再用），但记录保留可审计。 */
  readonly enabled: boolean
  /** 来源：agent 自动保存 / console 人工新建或编辑。 */
  readonly origin: string
  readonly updatedBy: string
}

/** 保存脚本的输入。 */
export interface ScriptInput {
  readonly name: string
  readonly scenario: string
  readonly code: string
  readonly language?: string
  readonly variables?: unknown
  readonly tags?: readonly string[]
  readonly notes?: string
  readonly sourceTaskId?: string
  readonly enabled?: boolean
  readonly origin?: string
  readonly updatedBy?: string
}

/** 检索条件（空串 = 不过滤）。 */
export interface ScriptQuery {
  readonly query: string
  readonly tag: string
  readonly limit: number
  /** 只看启用的（模型侧默认 true；控制台 false = 全部）。 */
  readonly enabledOnly?: boolean
}

export interface ScriptStore {
  readonly kind: 'memory' | 'postgres'
  /** 同名覆盖；返回写后的完整记录。 */
  upsert(input: ScriptInput, nowIso: string): Promise<AnalysisScript>
  /** 按 id 或 name 取一条（停用的默认取不到）。 */
  get(nameOrId: string): Promise<AnalysisScript | null>
  /** 控制台详情：停用的也要能看（含 enabled/origin/updatedBy）。 */
  getAny(nameOrId: string): Promise<AnalysisScript | null>
  /** 按场景/名字/标签检索，usage_count 降序。 */
  find(query: ScriptQuery): Promise<AnalysisScript[]>
  /** 控制台列表：分页 + 关键词（含停用）。 */
  list(query: { search: string; limit: number; offset: number }): Promise<{ total: number; items: AnalysisScript[] }>
  /** 控制台：设置启用/停用。 */
  setEnabled(nameOrId: string, enabled: boolean): Promise<boolean>
  /** 控制台：删除。 */
  remove(nameOrId: string): Promise<boolean>
  bumpUsage(id: string, nowIso: string): Promise<void>
  countScripts(): Promise<number>
}

/* ------------------------------------------------------------------ */
/* 抑制记忆                                                            */
/* ------------------------------------------------------------------ */

/** 抑制记忆面：把「这类现象已被精准抑制」这件事记在智能体自己这边。 */
export interface TaskSeenStore {
  /** 记一次"这个任务的现象身份是什么、判成了什么"。 */
  recordTaskSeen(record: TaskSeenRecord): Promise<void>
  /** 按任务 id 标记"已被抑制"（抑制条目带 source_task_id 时用）。 */
  markSuppressed(taskId: string, name: string): Promise<boolean>
  /** 按现象身份标记"已被抑制"（抑制条目没有任务 id 时用）。 */
  markSuppressedByIdentity(identity: TaskIdentity, name: string): Promise<number>
  /** 查这个现象是不是已被抑制。 */
  findSuppressed(identity: TaskIdentity): Promise<SuppressedTask | null>
}

/* ------------------------------------------------------------------ */
/* 结论留档（控制台「分析记录」的数据源）                                */
/* ------------------------------------------------------------------ */

export interface ConclusionStore {
  /** 交回结论时留一份（控制台读它；NDR 侧那份是它自己的数据源）。 */
  saveConclusion(record: ConclusionRecord): Promise<void>
  listConclusions(query: ConclusionQuery): Promise<ConclusionPage>
  getConclusion(id: string): Promise<ConclusionRecord | null>
  countConclusions(): Promise<number>
}

/* ------------------------------------------------------------------ */
/* 运行参数（按项目）                                                   */
/* ------------------------------------------------------------------ */

export interface SettingsStore {
  loadSettings(): Promise<RuntimeSettings | null>
  saveSettings(settings: RuntimeSettings): Promise<boolean>
}

/* ------------------------------------------------------------------ */
/* 过程索引的读面（控制台）                                             */
/* ------------------------------------------------------------------ */

export interface ProcessStore {
  startProcess(start: ProcessStart): Promise<void>
  finishProcess(finish: ProcessFinish): Promise<void>
  listProcesses(query: { limit: number; offset: number; search: string; outcome: string }): Promise<{
    total: number
    items: ProcessRecord[]
  }>
  getProcess(taskId: string): Promise<ProcessRecord | null>
}

/* ------------------------------------------------------------------ */
/* 内存实现（PG 未配置/不可用时的兜底）                                  */
/* ------------------------------------------------------------------ */

export class MemoryStateStore
implements TaskResultStore, ScriptStore, TaskSeenStore, ConclusionStore, SettingsStore, ProcessStore {
  readonly kind = 'memory' as const
  readonly projectId: string

  constructor(projectId = 'default') {
    this.projectId = projectId
  }

  private readonly results = new Map<string, TaskResultRecord>()
  private readonly scripts = new Map<string, AnalysisScript>()
  private readonly seen = new Map<string, TaskSeenRecord & { readonly suppressedBy: string }>()
  private readonly conclusions = new Map<string, ConclusionRecord>()
  private readonly processes = new Map<string, ProcessRecord>()
  private settings: RuntimeSettings | null = null

  /* ---------- 结论复用 ---------- */

  async load(key: string): Promise<TaskResultRecord | null> {
    return this.results.get(`${this.projectId}:${key}`) ?? null
  }

  async save(record: TaskResultRecord): Promise<boolean> {
    this.results.set(`${this.projectId}:${record.key}`, { ...record })
    return true
  }

  async bump(key: string, _nowIso: string, _taskId: string): Promise<boolean> {
    const current = this.results.get(`${this.projectId}:${key}`)
    if (current === undefined) return false
    this.results.set(`${this.projectId}:${key}`, { ...current, occurrences: current.occurrences + 1 })
    return true
  }

  async prune(nowIso: string): Promise<number> {
    const cutoff = Date.parse(nowIso)
    let removed = 0
    for (const [key, record] of this.results) {
      if (Date.parse(record.expiresAt) <= cutoff) {
        this.results.delete(key)
        removed += 1
      }
    }
    return removed
  }

  async count(): Promise<number> {
    return [...this.results.keys()].filter(key => key.startsWith(`${this.projectId}:`)).length
  }

  /* ---------- 脚本库 ---------- */

  async upsert(input: ScriptInput, nowIso: string): Promise<AnalysisScript> {
    const name = input.name.trim()
    const existing = [...this.scripts.values()].find(item => item.name === name)
    const script: AnalysisScript = {
      id: existing?.id ?? randomUUID(),
      name,
      scenario: input.scenario.trim(),
      language: (input.language ?? 'bash').trim() || 'bash',
      code: input.code,
      variables: input.variables ?? {},
      tags: [...(input.tags ?? [])],
      notes: (input.notes ?? '').trim(),
      sourceTaskId: (input.sourceTaskId ?? '').trim(),
      usageCount: existing?.usageCount ?? 0,
      createdAt: existing?.createdAt ?? nowIso,
      updatedAt: nowIso,
      lastUsedAt: existing?.lastUsedAt ?? '',
      enabled: input.enabled ?? existing?.enabled ?? true,
      origin: (input.origin ?? existing?.origin ?? 'agent').trim() || 'agent',
      updatedBy: (input.updatedBy ?? existing?.updatedBy ?? '').trim(),
    }
    this.scripts.set(script.id, script)
    return script
  }

  async get(nameOrId: string): Promise<AnalysisScript | null> {
    const script = await this.getAny(nameOrId)
    return script !== null && script.enabled ? script : null
  }

  async getAny(nameOrId: string): Promise<AnalysisScript | null> {
    const needle = nameOrId.trim()
    if (needle === '') return null
    for (const script of this.scripts.values()) {
      if (script.id === needle || script.name === needle) return script
    }
    return null
  }

  async find(query: ScriptQuery): Promise<AnalysisScript[]> {
    const needle = query.query.trim().toLowerCase()
    const tag = query.tag.trim()
    const matched = [...this.scripts.values()].filter(script => {
      if ((query.enabledOnly ?? true) && !script.enabled) return false
      const text = `${script.name}\n${script.scenario}\n${script.notes}\n${script.tags.join(' ')}`.toLowerCase()
      if (needle !== '' && !text.includes(needle)) return false
      if (tag !== '' && !script.tags.includes(tag)) return false
      return true
    })
    matched.sort((a, b) => (b.usageCount - a.usageCount) || (a.updatedAt < b.updatedAt ? 1 : -1))
    return matched.slice(0, Math.max(1, query.limit))
  }

  async list(query: { search: string; limit: number; offset: number }): Promise<{ total: number; items: AnalysisScript[] }> {
    const needle = query.search.trim().toLowerCase()
    const all = [...this.scripts.values()]
      .filter(script => needle === '' || `${script.name}\n${script.scenario}\n${script.notes}`.toLowerCase().includes(needle))
      .sort((a, b) => (b.updatedAt < a.updatedAt ? -1 : 1))
    return {
      total: all.length,
      items: all.slice(Math.max(0, query.offset), Math.max(0, query.offset) + Math.max(1, query.limit)),
    }
  }

  async setEnabled(nameOrId: string, enabled: boolean): Promise<boolean> {
    const needle = nameOrId.trim()
    for (const [id, script] of this.scripts) {
      if (script.id === needle || script.name === needle) {
        this.scripts.set(id, { ...script, enabled })
        return true
      }
    }
    return false
  }

  async remove(nameOrId: string): Promise<boolean> {
    const needle = nameOrId.trim()
    for (const [id, script] of this.scripts) {
      if (script.id === needle || script.name === needle) {
        this.scripts.delete(id)
        return true
      }
    }
    return false
  }

  async bumpUsage(id: string, nowIso: string): Promise<void> {
    const script = this.scripts.get(id)
    if (script === undefined) return
    this.scripts.set(id, { ...script, usageCount: script.usageCount + 1, lastUsedAt: nowIso })
  }

  async countScripts(): Promise<number> {
    return this.scripts.size
  }

  /* ---------- 抑制记忆 ---------- */

  async recordTaskSeen(record: TaskSeenRecord): Promise<void> {
    const key = seenKey(record)
    const previous = this.seen.get(key)
    this.seen.set(key, { ...record, suppressedBy: previous?.suppressedBy ?? '' })
  }

  async markSuppressed(taskId: string, name: string): Promise<boolean> {
    const key = taskId.trim()
    if (key === '') return false
    let hit = false
    for (const row of this.seen.values()) {
      if (row.taskId === key) {
        this.seen.set(seenKey(row), { ...row, suppressedBy: name })
        hit = true
      }
    }
    return hit
  }

  async markSuppressedByIdentity(identity: TaskIdentity, name: string): Promise<number> {
    const key = seenKey(identity)
    const row = this.seen.get(key)
    if (row === undefined) return 0
    this.seen.set(key, { ...row, suppressedBy: name })
    return 1
  }

  async findSuppressed(identity: TaskIdentity): Promise<SuppressedTask | null> {
    const row = this.seen.get(seenKey(identity))
    if (row === undefined || row.suppressedBy === '') return null
    return {
      taskId: row.taskId,
      kind: row.kind,
      subjectKind: row.subjectKind,
      subject: row.subject,
      feature: row.feature,
      verdict: row.verdict,
      suppressedBy: row.suppressedBy,
    }
  }

  /* ---------- 结论留档 ---------- */

  async saveConclusion(record: ConclusionRecord): Promise<void> {
    this.conclusions.set(record.id, record)
  }

  async listConclusions(query: ConclusionQuery): Promise<ConclusionPage> {
    const needle = query.search.trim().toLowerCase()
    const all = [...this.conclusions.values()]
      .filter(entry => needle === ''
        || `${entry.subject}\n${entry.summary}\n${entry.verdict}\n${entry.kind}\n${entry.subjectKind}\n${entry.taskId}`
          .toLowerCase().includes(needle))
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
    return {
      total: all.length,
      entries: all.slice(Math.max(0, query.offset), Math.max(0, query.offset) + Math.max(1, query.limit)),
    }
  }

  async getConclusion(id: string): Promise<ConclusionRecord | null> {
    return this.conclusions.get(id.trim()) ?? null
  }

  async countConclusions(): Promise<number> {
    return this.conclusions.size
  }

  /* ---------- 运行参数 ---------- */

  async loadSettings(): Promise<RuntimeSettings | null> {
    return this.settings === null ? null : { ...this.settings }
  }

  async saveSettings(settings: RuntimeSettings): Promise<boolean> {
    this.settings = { ...settings }
    return true
  }

  /* ---------- 过程索引 ---------- */

  async startProcess(start: ProcessStart): Promise<void> {
    this.processes.set(start.taskId, {
      ...start,
      endedAt: '',
      outcome: 'running',
      toolsUsed: 0,
      durationMs: 0,
      verdict: '',
      note: '',
    })
  }

  async finishProcess(finish: ProcessFinish): Promise<void> {
    const previous = this.processes.get(finish.taskId)
    this.processes.set(finish.taskId, {
      taskId: finish.taskId,
      sessionId: previous?.sessionId ?? '',
      kind: previous?.kind ?? '',
      subject: previous?.subject ?? '',
      model: previous?.model ?? '',
      startedAt: previous?.startedAt ?? finish.endedAt,
      endedAt: finish.endedAt,
      outcome: finish.outcome,
      toolsUsed: finish.toolsUsed ?? previous?.toolsUsed ?? 0,
      durationMs: finish.durationMs ?? previous?.durationMs ?? 0,
      verdict: finish.verdict ?? previous?.verdict ?? '',
      note: finish.note ?? previous?.note ?? '',
    })
  }

  async listProcesses(query: { limit: number; offset: number; search: string; outcome: string }): Promise<{
    total: number
    items: ProcessRecord[]
  }> {
    const needle = query.search.trim().toLowerCase()
    const outcome = query.outcome.trim()
    const all = [...this.processes.values()]
      .filter(entry => (outcome === '' || entry.outcome === outcome)
        && (needle === '' || `${entry.taskId}\n${entry.subject}\n${entry.kind}`.toLowerCase().includes(needle)))
      .sort((a, b) => (a.startedAt < b.startedAt ? 1 : -1))
    return {
      total: all.length,
      items: all.slice(Math.max(0, query.offset), Math.max(0, query.offset) + Math.max(1, query.limit)),
    }
  }

  async getProcess(taskId: string): Promise<ProcessRecord | null> {
    return this.processes.get(taskId.trim()) ?? null
  }

  async close(): Promise<void> {
    this.results.clear()
    this.scripts.clear()
    this.seen.clear()
    this.conclusions.clear()
    this.processes.clear()
    this.settings = null
  }
}

/** 现象身份的记忆键（与复用键同一套四元组，字段顺序固定）。 */
export function seenKey(identity: TaskIdentity): string {
  return JSON.stringify([
    identity.kind ?? '',
    identity.subjectKind ?? '',
    identity.subject ?? '',
    identity.feature ?? '',
  ])
}
