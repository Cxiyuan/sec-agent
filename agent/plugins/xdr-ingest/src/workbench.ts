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

  /** 手动触发一次领取。等同一记门铃：仍受并发与服务端预算约束。返回是否真的叫醒了循环。 */
  wake(): boolean

  /** 分析记录按 last_seen 降序分页（含已过期记录——过期只是"待重分析"）。 */
  listAnalyses(query: AnalysesQuery): Promise<AnalysesPage>

  /** 按分析 ID 取一条记录；没有（或冷库不可用）返回 null。 */
  getAnalysis(analysisId: string): Promise<ColdEntry | null>
}
