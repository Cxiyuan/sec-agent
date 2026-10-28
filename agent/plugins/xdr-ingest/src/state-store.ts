/**
 * 智能体侧的两份持久化状态（与 NDR 的“判定”无关，只属于分析端）：
 *
 * 1. `TaskResultStore`：同类现象的结论复用（见 `task-results.ts` 的策略）；
 * 2. `ScriptStore`：分析过程中写的工具脚本库（带场景描述与变量表，下次改改变量就能用）。
 *
 * 都用同一套“内存兜底 + PostgreSQL 持久化”模式：PG 不可用时脚本仍能在本次
 * 进程内保存/检索（明确告警），不会把分析卡死；但保存到库里的写入失败会
 * 抛错让模型知道“没存上”，不能假装成功。
 *
 * 表结构自管理（CREATE TABLE IF NOT EXISTS），不引入迁移工具；改结构时保持
 * DDL 幂等。所有参数走绑定，禁止拼接用户输入。
 */

import { randomUUID } from 'node:crypto'
import type { TaskResultRecord, TaskResultStore } from './task-results.ts'
import type { SuppressedTask, TaskIdentity, TaskSeenRecord } from './task-results.ts'


/** 脚本库里的一条脚本。 */
export interface AnalysisScript {
  readonly id: string
  /** 唯一名字（工具按名字覆盖/复用）。 */
  readonly name: string
  /** 什么场景该用它（检索的主要依据，写清楚“什么时候用”）。 */
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
}

/** 检索条件（空串 = 不过滤）。 */
export interface ScriptQuery {
  readonly query: string
  readonly tag: string
  readonly limit: number
}

/**
 * 抑制记忆面：把「这类现象已被精准抑制」这件事记在智能体自己这边。
 *
 * 为什么 NDR 拦了还要再记一层：NDR 侧拦的是**规则命中**这条路径，
 * 而同一个现象还可能从别的线索类型（首见 / 基线偏离）再冒出来；本地记忆
 * 可以在起会话之前就把它挡掉 —— 省一次模型会话，也省一次取数。
 */
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

export interface ScriptStore {
  readonly kind: 'memory' | 'postgres'
  /** 同名覆盖；返回写后的完整记录。 */
  upsert(input: ScriptInput, nowIso: string): Promise<AnalysisScript>
  /** 按 id 或 name 取一条。 */
  get(nameOrId: string): Promise<AnalysisScript | null>
  /** 按场景/名字/标签检索，usage_count 降序。 */
  find(query: ScriptQuery): Promise<AnalysisScript[]>
  bumpUsage(id: string, nowIso: string): Promise<void>
  countScripts(): Promise<number>
  close(): Promise<void>
}


/* ------------------------------------------------------------------ */
/* 内存实现（PG 未配置/不可用时的兜底）                                  */
/* ------------------------------------------------------------------ */

export class MemoryStateStore implements TaskResultStore, ScriptStore, TaskSeenStore {
  readonly kind = 'memory' as const
  private readonly results = new Map<string, TaskResultRecord>()
  private readonly scripts = new Map<string, AnalysisScript>()
  private readonly seen = new Map<string, TaskSeenRecord & { readonly suppressedBy: string }>()

  async load(key: string): Promise<TaskResultRecord | null> {
    return this.results.get(key) ?? null
  }

  async save(record: TaskResultRecord): Promise<boolean> {
    this.results.set(record.key, { ...record })
    return true
  }

  async bump(key: string, _nowIso: string, _taskId: string): Promise<boolean> {
    const current = this.results.get(key)
    if (current === undefined) return false
    this.results.set(key, { ...current, occurrences: current.occurrences + 1 })
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
    return this.results.size
  }

  async countScripts(): Promise<number> {
    return this.scripts.size
  }

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
    }
    this.scripts.set(script.id, script)
    return script
  }

  async get(nameOrId: string): Promise<AnalysisScript | null> {
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
      const text = `${script.name}\n${script.scenario}\n${script.notes}\n${script.tags.join(' ')}`.toLowerCase()
      if (needle !== '' && !text.includes(needle)) return false
      if (tag !== '' && !script.tags.includes(tag)) return false
      return true
    })
    matched.sort((a, b) => (b.usageCount - a.usageCount) || (a.updatedAt < b.updatedAt ? 1 : -1))
    return matched.slice(0, Math.max(1, query.limit))
  }

  async bumpUsage(id: string, nowIso: string): Promise<void> {
    const script = this.scripts.get(id)
    if (script === undefined) return
    this.scripts.set(id, { ...script, usageCount: script.usageCount + 1, lastUsedAt: nowIso })
  }

  async close(): Promise<void> {
    this.results.clear()
    this.scripts.clear()
    this.seen.clear()
  }

  /* ---------- 抑制记忆 ---------- */

  async recordTaskSeen(record: TaskSeenRecord): Promise<void> {
    const key = seenKey(record)
    const previous = this.seen.get(key)
    this.seen.set(key, {
      ...record,
      // 已经标了"被抑制"就别被后来的普通记录抹掉
      suppressedBy: previous?.suppressedBy ?? '',
    })
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
