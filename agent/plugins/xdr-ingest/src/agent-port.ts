/**
 * dsh 宿主服务的最小结构类型（**故意不引 `@deepseek-ai/dsh-agent` 依赖**）。
 *
 * 为什么用结构化类型而不是装依赖：out-of-tree 插件的依赖要在镜像构建期
 * `pnpm install --no-frozen-lockfile` 才有，本地没有 node_modules 时
 * 一旦真的 `import` 那个包，类型检查与单测都跑不起来。这里只声明**我们要用到的那几个方法**，
 * 运行时通过 `(ctx as ...).agents` 取服务——少一个硬依赖，多一份可测性。
 *
 * 契约来自 dsh `packages/core/agent`：`ctx.agents.create()` 返回 handle，
 * handle.agent 上可 `followup()` / `whenIdle()` / `cancel()`，`dispose()` 收尾。
 */

export interface AgentTextPart {
  readonly type: 'text'
  readonly text: string
}

export interface AgentFollowupInput {
  readonly content: readonly AgentTextPart[]
  readonly source: { readonly kind: string }
}

export interface AgentLike {
  followup(input: AgentFollowupInput): void | Promise<void>
  whenIdle(): Promise<void>
  cancel(cause?: unknown): void | Promise<void>
}

export interface AgentHandleLike {
  readonly agent: AgentLike
  dispose(): void | Promise<void>
}

export interface AgentCreateOptions {
  readonly sessionId: string
  readonly agentOptions?: { readonly provider?: string; readonly model?: string }
}

export interface AgentsServiceLike {
  create(options: AgentCreateOptions): Promise<AgentHandleLike>
}

/** 从 cordis Context 上取 agents 服务；没装 `dsh-agent` 时返回 null（插件降级而不是崩）。 */
export function agentsOf(context: unknown): AgentsServiceLike | null {
  if (typeof context !== 'object' || context === null) {
    return null
  }
  const service = (context as { agents?: unknown }).agents
  if (typeof service !== 'object' || service === null) {
    return null
  }
  const create = (service as { create?: unknown }).create
  if (typeof create !== 'function') {
    return null
  }
  return service as AgentsServiceLike
}
