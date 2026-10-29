/**
 * 免费模型目录：从 OpenCode 的 v2 模型清单里筛"零成本 + 支持文本输出"的模型。
 *
 * 与 ow-bridge 的差异：我们默认只暴露声明支持工具调用的模型 —— dsh 的分析闭环
 * 必须能调 MCP 工具；纯对话模型进来自动模型会一直失败（可以在部署时用
 * BRIDGE_INCLUDE_CHAT_ONLY=1 放出来做实验）。
 */

export function freeModels(rawModels, { includeChatOnly = false } = {}) {
  const rows = []
  for (const model of rawModels) {
    if (model?.providerID !== 'opencode') continue
    if (model.enabled !== true) continue
    if (typeof model.status === 'string' && model.status === 'deprecated') continue
    const capabilities = model.capabilities ?? {}
    const outputs = Array.isArray(capabilities.output) ? capabilities.output : []
    if (!outputs.includes('text')) continue
    const tools = capabilities.tools === true
    if (!tools && !includeChatOnly) continue
    const cost = Array.isArray(model.cost) ? model.cost : []
    if (cost.length === 0) continue
    const free = cost.every(tier =>
      Number(tier?.input ?? 0) === 0
      && Number(tier?.output ?? 0) === 0
      && Number(tier?.cache?.read ?? 0) === 0
      && Number(tier?.cache?.write ?? 0) === 0)
    if (!free) continue
    const id = String(model.id ?? model.modelID ?? '')
    if (id === '') continue
    rows.push({
      id,
      name: String(model.name ?? id),
      context: Number(model.limit?.context ?? 0) || null,
      output: Number(model.limit?.output ?? 0) || null,
      tools,
    })
  }
  rows.sort((a, b) => a.id.localeCompare(b.id))
  return rows
}

/** 请求里的模型名 → 目录里的模型 id（兼容 `opencode/<id>` 前缀）。 */
export function resolveModel(catalog, requested) {
  const text = String(requested ?? '').trim()
  if (text === '') return null
  const bare = text.startsWith('opencode/') ? text.slice('opencode/'.length) : text
  return (
    catalog.find(model => model.id === bare)
    ?? catalog.find(model => model.name === text)
    ?? null
  )
}
