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

export class MemoryStateStore implements TaskResultStore, ScriptStore {
  readonly kind = 'memory' as const
  private readonly results = new Map<string, TaskResultRecord>()
  private readonly scripts = new Map<string, AnalysisScript>()

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
  }
}
