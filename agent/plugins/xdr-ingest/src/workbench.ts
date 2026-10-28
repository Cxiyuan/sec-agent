/**
 * xdrIngest 服务契约：xdr-ingest 向同一进程内其他插件（xdr-ui 工作台）暴露的
 * 只读观测面 + 一点手动控制。纯类型文件，无运行时代码。
 *
 * 消费方不要 import 本包的值，用 `import type` 对齐形状，经
 * `ctx.reflect.get('xdrIngest', false)` 取实例（可选服务：xdr-ingest 没在场
 * 时工作台仍要能打开，只是数据区显示不可用）。
 */

import type { AnalysesPage, AnalysesQuery, ColdEntry } from './store.ts'

export interface XdrIngestService {
  /**
   * 运行观测快照：分析开关、领取循环统计（门铃/领取/启动/失败/连续错误）。
   * 形状与 `GET {basePath}/status` 一致，另有 model 等配置摘录。
   */
  status(): Record<string, unknown>

  /** 两级缓存规模与计数（热层/冷库条数、分析/复用/重分析；对齐 /stats）。 */
  cacheStats(): Promise<unknown>

  /** 智能体侧结论复用计数（进程内计数，重启归零）。 */
  taskReuseStats(projectId?: string): { readonly reused: number, readonly stored: number }

  /** 脚本库规模与存储类型（`store=memory` 表示重启会丢）。 */
  scriptStats(projectId?: string): Promise<{ readonly store: 'memory' | 'postgres', readonly count: number }>

  /** 手动触发一次领取。等同一记门铃：仍受并发与服务端预算约束。返回是否真的叫醒了循环。 */
  wake(projectId?: string): boolean

  /** 项目组织：项目列表（含状态/最近校验时间）。 */
  projects(): Promise<readonly unknown[]>

  /**
   * 新增/更新项目（授权ID = NDR 的 8 位授权ID）。
   * 校验失败返回 `{ok:false, error}`；校验不通过的项目会落库但不起循环（控制台可改）。
   */
  saveProject(body: unknown): Promise<{ ok: boolean, error?: string, project?: unknown }>

  /** 删除项目（连同运行时；该项目的历史数据留在库里，不再展示）。 */
  removeProject(projectId: string): Promise<boolean>

  /** 手动复核绑定（server_info + 授权ID）。返回最新项目记录，不存在返回 null。 */
  verifyProject(projectId: string): Promise<unknown>

  /** 多项目运行态聚合（`{project_count, enabled, projects[]}`）。 */
  projectStatus(): Record<string, unknown>

  /** 分析记录按 last_seen 降序分页（含已过期记录——过期只是"待重分析"）。 */
  listAnalyses(query: AnalysesQuery): Promise<AnalysesPage>

  /** 按分析 ID 取一条记录；没有（或冷库不可用）返回 null。 */
  getAnalysis(analysisId: string): Promise<ColdEntry | null>

  /**
   * 智能体交回的结论（**智能体自己的留档**，按项目隔离），按时间倒序 + 关键词搜索。
   *
   * 与 `listAnalyses` 的区别：后者是**旧摘要契约**的缓存表（新架构下 NDR 不再推摘要，
   * 那张表永远是空的）；结论才是现在真正产出的东西，控制台「分析记录」看它。
   */
  listConclusions(query: { limit: number, offset: number, search: string, project?: string }): Promise<{
    total: number
    entries: readonly unknown[]
  }>

  /** 按结论 ID 取一条（含 findings / 证据引用 / 成本口径）。 */
  getConclusion(id: string, projectId?: string): Promise<unknown>

  /** 结论总数与数据面是否可用（控制台总览用）。 */
  conclusionStats(projectId?: string): Promise<{ available: boolean, total: number }>

  /** 分析过程索引：任务 → 会话（模型/工具数/耗时/状态），按开始时间倒序。 */
  listProcesses(query: { limit: number, offset: number, search: string, outcome: string, project?: string }): Promise<{
    total: number
    items: readonly unknown[]
  }>

  /** 按任务 ID 取过程索引（控制台「分析过程」详情用）。 */
  getProcess(taskId: string, projectId?: string): Promise<unknown>

  /**
   * 分析过程时间线：读 DSH 会话日志，返回压缩投影（任务/思考/工具调用/返回/token/报错）。
   * 运行中的会话可以带 `after`（上次的 `nextSeq`）只取新增事件做实时视图。
   */
  processEvents(taskId: string, projectId?: string, after?: number): Promise<unknown>

  /** 分析脚本列表（含停用；控制台管理用）。 */
  listScripts(query: { search: string, limit: number, offset: number, project?: string }): Promise<{
    total: number
    items: readonly unknown[]
  }>

  /** 按名字或 ID 取脚本（含停用）。 */
  getScript(nameOrId: string, projectId?: string): Promise<unknown>

  /** 控制台新建/编辑脚本（同名覆盖；origin 记为 console）。 */
  saveScript(body: unknown, projectId?: string): Promise<unknown>

  /** 控制台启用/停用脚本。 */
  setScriptEnabled(nameOrId: string, enabled: boolean, projectId?: string): Promise<boolean>

  /** 控制台删除脚本。 */
  removeScript(nameOrId: string, projectId?: string): Promise<boolean>

  /**
   * 当前生效的运行参数：`{poll_seconds, max_concurrent, claim_limit, store}`。
   * 工作台配置页与 status 读同一份（可能已被工作台改过）。
   */
  settings(projectId?: string): Promise<Record<string, unknown>>

  /**
   * 保存运行参数并热更新领取循环；持久化在冷库（重启后仍生效）。
   * 校验失败返回 `{ok:false, error}`，成功返回 `{ok, persisted, settings}`；
   * `persisted:false` 表示只在内存生效（冷库写入失败，不阻断运行）。
   */
  updateSettings(patch: unknown, projectId?: string): Promise<{
    ok: boolean
    error?: string
    persisted?: boolean
    settings?: Record<string, number>
  }>
}
