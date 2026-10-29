/**
 * 工作台可改的运行参数（持久化在冷库，重启后覆盖 cordis 配置里的默认值）。
 *
 * 只收「改了立刻生效、又不改变安全语义」的旋钮：领取节奏、本进程会话并发，
 * 以及轻量初筛（低阶模型闸门）的配置。
 * 任务租约、队列容量与线索保留期在 NDR 侧；NDR 不设领取额度或并发上限。
 */

/** 轻量初筛（低阶模型）配置：直连 OpenAI 兼容推理服务，单轮判定、无工具无会话。 */
export interface LightTriageConfig {
  /** 总开关（false = 一切任务走付费会话，行为与没有初筛完全一致）。 */
  readonly enabled: boolean
  /** OpenAI 兼容端点根路径（如 `http://192.168.1.10:8080/v1`；空 = 未配置）。 */
  readonly baseUrl: string
  /** 模型名（推理服务侧的名字，如 `Qwen3.5-2B-Q4_K_M`）。 */
  readonly model: string
  /** API Key（本地 llama.cpp/Ollama 通常留空）。 */
  readonly apiKey: string
  /** 置信阈值（0~1）：低于它不算「明显判断」，升级到付费模型。 */
  readonly threshold: number
  /** 抽检率（0~1）：可关单的任务里抽多少比例仍送付费复核（比对校准用）。 */
  readonly auditRate: number
  /** 单次调用超时（毫秒）；超时一律升级（fail-open）。 */
  readonly timeoutMs: number
  /** 适用的任务种类（只这些线索类型做初筛；hit/shift 等安全攸关的默认不进）。 */
  readonly kinds: readonly string[]
}

/** 默认初筛配置：关着，等控制台配好推理服务再打开。 */
export const DEFAULT_LIGHT_TRIAGE: LightTriageConfig = {
  enabled: false,
  baseUrl: '',
  model: '',
  apiKey: '',
  threshold: 0.85,
  auditRate: 0.1,
  timeoutMs: 20_000,
  kinds: ['coverage'],
}

/** 运行参数快照（单位与 Config 一致）。 */
export interface RuntimeSettings {
  /** 定时自轮询间隔（秒）。 */
  readonly pollSeconds: number
  /** 本进程最多同时跑几个分析会话。 */
  readonly maxConcurrent: number
  /** 单次领取条数上限。 */
  readonly claimLimit: number
  /** 轻量初筛配置（undefined = 从没配置过，按 DEFAULT_LIGHT_TRIAGE 算）。 */
  readonly light?: LightTriageConfig
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

/**
 * 校验一份轻量初筛配置（补丁已由调用方与当前值/默认值合并过）。
 *
 * 「启用必须填地址/模型」在这里拦：缺了它启用等于每条任务都撞墙，
 * 而撞墙的代价是全量升级付费 —— 静默烧钱，不如保存时报错。
 */
export function lightTriageOf(value: unknown): { config: LightTriageConfig } | { error: string } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { error: '轻量初筛配置必须是 JSON 对象' }
  }
  const input = value as Record<string, unknown>
  const base = DEFAULT_LIGHT_TRIAGE

  const enabled = input['enabled'] === undefined ? base.enabled : input['enabled']
  if (typeof enabled !== 'boolean') return { error: '轻量初筛开关必须是布尔值' }

  const baseUrl = typeof input['baseUrl'] === 'string'
    ? input['baseUrl'].trim().slice(0, 300) : base.baseUrl
  if (baseUrl !== '' && !/^https?:\/\/\S+$/iu.test(baseUrl)) {
    return { error: '轻量初筛推理服务地址必须是 http(s) URL（OpenAI 兼容，通常以 /v1 结尾）' }
  }

  const model = typeof input['model'] === 'string' ? input['model'].trim().slice(0, 120) : base.model
  const apiKey = typeof input['apiKey'] === 'string' ? input['apiKey'].trim().slice(0, 512) : base.apiKey

  if (enabled && baseUrl === '') return { error: '启用轻量初筛必须先填推理服务地址' }
  if (enabled && model === '') return { error: '启用轻量初筛必须填模型名' }

  const threshold = numberOr(input['threshold'], base.threshold, '轻量初筛置信阈值', 0, 1)
  if ('error' in threshold) return threshold
  const auditRate = numberOr(input['auditRate'], base.auditRate, '轻量初筛抽检率', 0, 1)
  if ('error' in auditRate) return auditRate

  const rawTimeout = input['timeoutMs']
  let timeoutMs = base.timeoutMs
  if (rawTimeout !== undefined) {
    if (typeof rawTimeout !== 'number' || !Number.isSafeInteger(rawTimeout) || rawTimeout < 1_000 || rawTimeout > 600_000) {
      return { error: '轻量初筛超时必须是 1000~600000 的整数（毫秒）' }
    }
    timeoutMs = rawTimeout
  }

  const rawKinds = input['kinds'] === undefined ? base.kinds : input['kinds']
  if (!Array.isArray(rawKinds)) return { error: '轻量初筛适用种类必须是数组' }
  if (rawKinds.length > 10) return { error: '轻量初筛适用种类最多 10 个' }
  const kinds: string[] = []
  for (const item of rawKinds) {
    if (typeof item !== 'string') return { error: '轻量初筛适用种类必须是字符串数组' }
    const kind = item.trim().toLowerCase()
    if (kind === '') continue
    if (!/^[a-z][a-z0-9_]{0,31}$/u.test(kind)) return { error: `轻量初筛种类名不合法：${kind.slice(0, 32)}` }
    if (!kinds.includes(kind)) kinds.push(kind)
  }

  return { config: { enabled, baseUrl, model, apiKey, threshold: threshold.value, auditRate: auditRate.value, timeoutMs, kinds } }
}

/** 数值字段：只收有限数字且在区间内（缺省用默认值；错误信息带中文名）。 */
function numberOr(
  value: unknown,
  fallback: number,
  name: string,
  min: number,
  max: number,
): { value: number } | { error: string } {
  const raw = value === undefined ? fallback : value
  if (typeof raw !== 'number' || !Number.isFinite(raw) || raw < min || raw > max) {
    return { error: `${name}必须是 ${min}~${max} 的数字` }
  }
  return { value: raw }
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
  const next: {
    pollSeconds: number
    maxConcurrent: number
    claimLimit: number
    light?: LightTriageConfig
  } = {
    pollSeconds: current.pollSeconds,
    maxConcurrent: current.maxConcurrent,
    claimLimit: current.claimLimit,
    ...(current.light === undefined ? {} : { light: current.light }),
  }
  for (const key of Object.keys(SETTING_LIMITS) as Array<keyof typeof SETTING_LIMITS>) {
    const value = input[key]
    if (value === undefined) continue
    const limits = SETTING_LIMITS[key]
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < limits.min || value > limits.max) {
      const names: Record<keyof typeof SETTING_LIMITS, string> = {
        pollSeconds: '轮询间隔（秒）',
        maxConcurrent: '并发上限',
        claimLimit: '单次领取条数',
      }
      return { error: `${names[key]}必须是 ${limits.min}~${limits.max} 的整数` }
    }
    next[key] = value
  }
  if (input['light'] !== undefined) {
    const raw = input['light']
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      return { error: '轻量初筛配置必须是 JSON 对象' }
    }
    // 补丁只带部分字段（比如只改阈值）：先与当前值合并再整体校验，
    // 否则「只改一个数」会把端点/模型这些没传的字段冲成默认空值。
    const merged = lightTriageOf({ ...(next.light ?? DEFAULT_LIGHT_TRIAGE), ...(raw as Record<string, unknown>) })
    if ('error' in merged) return merged
    next.light = merged.config
  }
  return { settings: next }
}

/** 把快照拍成工作台/status 用的下划线字段。 */
export function settingsView(settings: RuntimeSettings): Record<string, number> {
  return {
    poll_seconds: settings.pollSeconds,
    max_concurrent: settings.maxConcurrent,
    claim_limit: settings.claimLimit,
    light_enabled: settings.light?.enabled === true ? 1 : 0,
  }
}
