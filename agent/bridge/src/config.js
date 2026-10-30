/**
 * 运行参数（全部来自环境变量；容器里由 compose 注入）。
 *
 * 设计边界：
 * - 只监听回环地址（与 agent 共用网络命名空间后，dsh 用 127.0.0.1 访问）；
 * - 不读任何客户数据卷，不写 agent 的 dsh home；
 * - 所有"可调"项都能用环境变量覆盖，方便排障时临时改而不重建镜像。
 */

function intEnv(env, name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = env[name]
  if (raw === undefined || String(raw).trim() === '') return fallback
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} 必须是 ${min}~${max} 的整数，收到 ${JSON.stringify(raw)}`)
  }
  return value
}

function textEnv(env, name, fallback = '') {
  const raw = env[name]
  return raw === undefined ? fallback : String(raw).trim()
}

export function loadConfig(env = process.env) {
  const apiKey = textEnv(env, 'BRIDGE_API_KEY')
  const allowNoAuth = env.BRIDGE_ALLOW_NO_AUTH === '1'
  if (apiKey === '' && !allowNoAuth) {
    throw new Error('BRIDGE_API_KEY 必须设置（本地代理密钥；测试可设 BRIDGE_ALLOW_NO_AUTH=1）')
  }
  return {
    host: textEnv(env, 'BRIDGE_HOST', '127.0.0.1'),
    port: intEnv(env, 'BRIDGE_PORT', 41980, { min: 1024, max: 65535 }),
    apiKey,
    allowNoAuth,
    dataDir: textEnv(env, 'BRIDGE_DATA_DIR', '/data'),
    // 容器内固定路径；测试可通过 BRIDGE_OPENCODE_URL 注入假服务
    opencodeBin: textEnv(env, 'BRIDGE_OPENCODE_BIN', '/opt/opencode/opencode'),
    opencodeUrl: textEnv(env, 'BRIDGE_OPENCODE_URL'),
    /** 外部 OpenCode 服务用哪个 agent；空 = 用对方默认 agent（自建运行时必须用 xdr-bridge）。 */
    opencodeAgent: textEnv(env, 'BRIDGE_OPENCODE_AGENT', 'xdr-bridge'),
    /**
     * 会话级权限：`ask`（默认，宿主机模式用；原生动作会挂起，桥接层立刻拒绝）、
     * `none`（不带权限声明）、`deny`（全拒绝 —— **实测会触发免费层 429**，别用）。
     */
    opencodePermissions: textEnv(env, 'BRIDGE_OPENCODE_PERMISSIONS', 'ask'),
    /** 从 JSON 文件读取外部 OpenCode 的服务密码（宿主机 service.json）。 */
    opencodePasswordFile: textEnv(env, 'BRIDGE_OPENCODE_PASSWORD_FILE'),
    opencodeUsername: textEnv(env, 'BRIDGE_OPENCODE_USERNAME', 'opencode'),
    opencodePassword: textEnv(env, 'BRIDGE_OPENCODE_PASSWORD'),
    expectedVersion: textEnv(env, 'BRIDGE_OPENCODE_VERSION', ''),
    maxConcurrency: intEnv(env, 'BRIDGE_MAX_CONCURRENCY', 2, { min: 1, max: 8 }),
    maxRequestsPerDay: intEnv(env, 'BRIDGE_MAX_REQUESTS_PER_DAY', 200, { min: 0, max: 1_000_000 }),
    // 免费模型可能很慢；单次 prompt 等待上限（毫秒）
    timeoutMs: intEnv(env, 'BRIDGE_TIMEOUT_MS', 300_000, { min: 10_000, max: 1_800_000 }),
    refreshMs: intEnv(env, 'BRIDGE_MODEL_REFRESH_MS', 10 * 60_000, { min: 60_000, max: 24 * 3600_000 }),
    // 默认只暴露"声明支持工具"的免费模型（dsh 的分析闭环必须有工具）
    includeChatOnly: env.BRIDGE_INCLUDE_CHAT_ONLY === '1',
    logLevel: textEnv(env, 'BRIDGE_LOG_LEVEL', 'info'),
  }
}
