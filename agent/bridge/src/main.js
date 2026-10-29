/**
 * 入口：加载配置 → 启动隔离 OpenCode → 读免费模型目录 → 监听回环端口。
 *
 * 这个进程只与 OpenCode 和 dsh 打交道；出错时退出让容器重启（compose 管）。
 */

import { loadConfig } from './config.js'
import { OpenCodeRuntime } from './opencode.js'
import { Bridge, createServer } from './server.js'

function logger(levelName) {
  const order = { debug: 10, info: 20, warn: 30, error: 40 }
  const threshold = order[levelName] ?? 20
  return (level, message, meta = {}) => {
    if ((order[level] ?? 20) < threshold) return
    const row = { time: new Date().toISOString(), level, msg: message, ...meta }
    process.stdout.write(`${JSON.stringify(row)}\n`)
  }
}

async function main() {
  const config = loadConfig()
  const log = logger(config.logLevel)
  const runtime = new OpenCodeRuntime(config, { log: (message) => log('debug', message) })
  await runtime.start()
  log('info', 'opencode ready', { version: runtime.version, base: runtime.baseUrl })

  const bridge = new Bridge({ config, runtime, log })
  const catalog = await bridge.refreshCatalog()
  log('info', 'bridge ready', { models: catalog.map(model => model.id) })

  const server = createServer(bridge)
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(config.port, config.host, resolve)
  })
  log('info', 'listening', { host: config.host, port: config.port })

  const refresh = setInterval(() => {
    void bridge.refreshCatalog().catch(error => log('warn', 'model refresh failed', { message: String(error?.message ?? error) }))
  }, config.refreshMs)
  refresh.unref?.()

  let stopping = false
  const shutdown = async (signal) => {
    if (stopping) return
    stopping = true
    log('info', 'shutting down', { signal })
    clearInterval(refresh)
    server.close()
    await runtime.stop()
    process.exit(0)
  }
  process.on('SIGTERM', () => void shutdown('SIGTERM'))
  process.on('SIGINT', () => void shutdown('SIGINT'))
  process.on('uncaughtException', error => {
    log('error', 'uncaught exception', { message: String(error?.stack ?? error).slice(0, 800) })
    void shutdown('uncaughtException')
  })
  process.on('unhandledRejection', error => {
    log('error', 'unhandled rejection', { message: String(error?.stack ?? error).slice(0, 800) })
  })
}

main().catch(error => {
  process.stdout.write(`${JSON.stringify({
    time: new Date().toISOString(),
    level: 'error',
    msg: 'bridge failed to start',
    message: String(error?.stack ?? error).slice(0, 1200),
  })}\n`)
  process.exit(1)
})
