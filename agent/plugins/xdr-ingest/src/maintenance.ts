/**
 * 数据生命周期：结论/过程/事实/外连基线/会话日志的保留期清理。
 *
 * 为什么必须有：这些表只增不减（2026-10 实机：1833 个会话日志 / 80MB，且会随分析次数
 * 线性增长）。没有清理策略时，第一年只是"查询变慢"，第二年是"磁盘满 + 备份无法完成"。
 *
 * 口径：
 * - 结论留档（analysis_results 的智能体侧副本）保留 90 天：排查/复盘的合理窗口；
 * - 过程索引保留 90 天；事实（observations）30 天；外连目的地 90 天；
 * - 任务去重记忆（task_seen）30 天（抑制记忆另有到期时间，不受这里影响）；
 * - 会话日志（/data/dsh/sessions/<ns>/<sessionId>/）14 天：时间线是"当前在干什么"，
 *   历史回看有过程索引与结论，不需要原始日志无限留。
 */

import { promises as fs } from 'node:fs'
import type { Dirent } from 'node:fs'
import path from 'node:path'

export interface RetentionPolicy {
  readonly conclusionsDays: number
  readonly processesDays: number
  readonly observationsDays: number
  readonly egressDays: number
  readonly taskSeenDays: number
  readonly sessionsDays: number
}

export const DEFAULT_RETENTION: RetentionPolicy = {
  conclusionsDays: 90,
  processesDays: 90,
  observationsDays: 30,
  egressDays: 90,
  taskSeenDays: 30,
  sessionsDays: 14,
}

/** 删除超过保留期的会话目录，返回删除数量与释放的字节数（只算被删文件）。 */
export async function pruneSessions(
  root: string,
  days: number,
  now = Date.now(),
): Promise<{ removed: number, bytes: number }> {
  const cutoff = now - Math.max(1, days) * 86_400_000
  let removed = 0
  let bytes = 0
  let namespaces: Dirent[]
  try {
    namespaces = await fs.readdir(root, { withFileTypes: true })
  } catch {
    return { removed: 0, bytes: 0 }
  }
  for (const space of namespaces) {
    if (!space.isDirectory()) continue
    const base = path.join(root, space.name)
    let entries: Dirent[]
    try {
      entries = await fs.readdir(base, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const dir = path.join(base, entry.name)
      const file = path.join(dir, 'session.v4.jsonl.zstd')
      try {
        const stat = await fs.stat(file)
        if (stat.mtimeMs >= cutoff) continue
        // 只删会话目录里的已知文件（不递归删未知内容，避免误伤卷里别的东西）
        const files = await fs.readdir(dir)
        for (const name of files) {
          if (name !== 'session.v4.jsonl.zstd' && name !== 'session.lock') continue
          const target = path.join(dir, name)
          try {
            const info = await fs.stat(target)
            bytes += info.size
            await fs.unlink(target)
          } catch {
            continue
          }
        }
        await fs.rmdir(dir).catch(() => undefined)
        removed += 1
      } catch {
        continue
      }
    }
  }
  return { removed, bytes }
}
