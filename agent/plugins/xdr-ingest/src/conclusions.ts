/**
 * 智能体交回的结论（**只读**）：控制台「分析记录」页的数据源。
 *
 * 为什么单独一个模块：结论的**写**在 NDR 侧（`complete_task` 写 `analysis_results`），
 * 智能体只负责判；控制台要让人看见这些结论，就必须能读那张表。
 * 项目统一用一份 PG（agent 与 ndr 共用同一套库），所以这里直接只读查询 NDR 的
 * `analysis_results` 表——不复制一份数据，也就不会出现两边对不上的第二份真相。
 *
 * 为什么不走 MCP：MCP 的 analyst 档是"分析用的最小集"，结论列表是给人看的运营面，
 * 塞进分析工具面只会让模型多想一件事；而控制台要的是**列表 + 详情 + 搜索**，
 * 一次 SQL 就能给全，比过一趟 MCP 更省。
 *
 * 表不存在（NDR 版本旧/未初始化）时一律降级成"没有结论"，不报错——
 * 控制台必须能打开，只是数据区显示不可用。
 *
 * PostgreSQL 实现在 `pg-conclusions.ts`（单独成文件是为了让本地测试不必装 `pg`）。
 */

/** 一条交回的结论（字段与 NDR 的 `analysis_results` 对齐，只取展示需要的）。 */
export interface ConclusionRecord {
  readonly id: string
  readonly taskId: string
  /** 线索类型（novelty / hit / shift / coverage / structure）。 */
  readonly kind: string
  readonly subjectKind: string
  readonly subject: string
  /** 判定：true_positive / false_positive / benign / suspicious / inconclusive … */
  readonly verdict: string
  readonly confidence: number
  readonly summary: string
  /** 结论里的结构化发现（键值不定，原样透传给界面）。 */
  readonly findings: unknown
  /** 引用的证据 ID 列表。 */
  readonly evidenceRefs: readonly string[]
  /** 本次分析用了多少次工具调用。 */
  readonly toolsUsed: number
  /** 本次分析耗时（毫秒）。 */
  readonly durationMs: number
  /** 同类现象复用交回（0 token，没起会话）：成本不算它，界面标「复用」。 */
  readonly reused: boolean
  /** 复用的原任务 ID（非复用为空串）。 */
  readonly reusedFrom: string
  /** 终态原因：concluded / timeout / tool_error / budget_exhausted / aborted。 */
  readonly terminalReason: string
  readonly createdAt: string
}

/** 列表查询条件。 */
export interface ConclusionQuery {
  readonly limit: number
  readonly offset: number
  /** 搜索词：对象 / 判定 / 摘要 / 类型，空串 = 不过滤。 */
  readonly search: string
}

/** 列表页返回。 */
export interface ConclusionPage {
  readonly total: number
  readonly entries: readonly ConclusionRecord[]
}

/** 结论只读面。 */
export interface ConclusionReader {
  /** 表在不在（PG 没配 / NDR 还没建表 = false）。 */
  available(): boolean
  /** 等初始化（探表）结束；返回是否可用。 */
  ready(): Promise<boolean>
  listRecent(query: ConclusionQuery): Promise<ConclusionPage>
  get(id: string): Promise<ConclusionRecord | null>
  count(): Promise<number>
  close(): Promise<void>
}
/* 内存实现（没有 PG 时的兜底：永远"没有结论"）                          */
export class MemoryConclusionReader implements ConclusionReader {
  available(): boolean {
    return false
  }

  async ready(): Promise<boolean> {
    return false
  }

  async listRecent(_query: ConclusionQuery): Promise<ConclusionPage> {
    return { total: 0, entries: [] }
  }

  async get(_id: string): Promise<ConclusionRecord | null> {
    return null
  }

  async count(): Promise<number> {
    return 0
  }

  async close(): Promise<void> {
    // 没有连接可关
  }
}
