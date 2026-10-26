/**
 * 工作台可改的运行参数（持久化在冷库，重启后覆盖 cordis 配置里的默认值）。
 *
 * 只收「改了立刻生效、又不改变安全语义」的旋钮：领取节奏与并发预算。
 * 配额、租约、保留名额、强度门槛都在 NDR 侧（服务端强制），这里不接受修改——
 * 两侧各算一套配额必然不一致。
 */

/** 运行参数快照（单位与 Config 一致）。 */
export interface RuntimeSettings {
  /** 定时自轮询间隔（秒）。 */
  readonly pollSeconds: number
  /** 本进程最多同时跑几个分析会话。 */
  readonly maxConcurrent: number
  /** 单次领取条数上限。 */
  readonly claimLimit: number
}

/** 各参数的取值范围（与 Config 的 schemastery 校验一致）。 */
export const SETTING_LIMITS = {
  pollSeconds: { min: 30, max: 86_400 },
  maxConcurrent: { min: 1, max: 16 },
  claimLimit: { min: 1, max: 20 },
} as const

/** 冷库/内存两条实现都要提供的最小存储面。 */
export interface SettingsStore {
  /** 读上次保存的参数；从未保存过返回 null。 */
  loadSettings(): Promise<unknown>
  /** 整份保存；返回是否落盘成功（失败时调用方保留内存值并告警）。 */
  saveSettings(settings: RuntimeSettings): Promise<boolean>
}

/** 校验并合并一份补丁；未知键忽略，类型/范围不合法报错。 */
export function mergeSettings(
  current: RuntimeSettings,
  patch: unknown,
): { settings: RuntimeSettings } | { error: string } {
  if (typeof patch !== 'object' || patch === null || Array.isArray(patch)) {
    return { error: '参数必须是 JSON 对象' }
  }
  const input = patch as Record<string, unknown>
  const next: Record<keyof RuntimeSettings, number> = {
    pollSeconds: current.pollSeconds,
    maxConcurrent: current.maxConcurrent,
    claimLimit: current.claimLimit,
  }
  for (const key of Object.keys(SETTING_LIMITS) as Array<keyof RuntimeSettings>) {
    const value = input[key]
    if (value === undefined) continue
    const limits = SETTING_LIMITS[key]
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < limits.min || value > limits.max) {
      const names: Record<keyof RuntimeSettings, string> = {
        pollSeconds: '轮询间隔（秒）',
        maxConcurrent: '并发上限',
        claimLimit: '单次领取条数',
      }
      return { error: `${names[key]}必须是 ${limits.min}~${limits.max} 的整数` }
    }
    next[key] = value
  }
  return { settings: next }
}

/** 把快照拍成工作台/status 用的下划线字段。 */
export function settingsView(settings: RuntimeSettings): Record<string, number> {
  return {
    poll_seconds: settings.pollSeconds,
    max_concurrent: settings.maxConcurrent,
    claim_limit: settings.claimLimit,
  }
}
