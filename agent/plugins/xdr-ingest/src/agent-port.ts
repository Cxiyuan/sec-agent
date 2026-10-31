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

/** The scoped context dsh hands to `setup` before the agent is published. */
export interface AgentScopedContext {
  readonly tools?: {
    /** Per-agent visibility mask over global tools (dsh ToolRuntime.restrict). */
    restrict?(filter: { readonly allow?: readonly string[]; readonly deny?: readonly string[] }): unknown
  }
  /**
   * Per-agent prompt composition (dsh system-prompt registry). A scoped
   * section is part of the system prompt; a scoped context is materialized as
   * a durable user-role snapshot, ordered with the runtime-context snapshots.
   */
  readonly systemPrompt?: {
    section?(section: {
      readonly name: string
      readonly order: number
      readonly text: string
      readonly interpolate?: boolean
    }): unknown
    context?(context: {
      readonly name: string
      readonly order: number
      readonly text: string
      readonly interpolate?: boolean
      readonly required?: boolean
    }): unknown
  }
}

export interface AgentCreateOptions {
  readonly sessionId: string
  readonly agentOptions?: { readonly provider?: string; readonly model?: string }
  /** Creation-time composition of the agent's scoped world (dsh AgentCreateOptions.setup). */
  readonly setup?: (agentCtx: AgentScopedContext) => void | Promise<void>
}

export interface AgentsServiceLike {
  create(options: AgentCreateOptions): Promise<AgentHandleLike>
}

/**
 * 从 cordis Context 上取 agents 服务；没装 `dsh-agent` 时返回 null（插件降级而不是崩）。
 *
 * **必须走 `ctx.reflect.get(name, false)`，不能直接读 `ctx.agents`**：
 * cordis 的 context 是 Proxy，读一个没在 `inject` 里声明的服务属性会抛
 * `cannot get property "agents" without inject`（2026-10 冒烟实测，插件整条加载失败）。
 * 而不声明 inject 又不行 —— `inject` 在这个版本里是"必需服务"语义，声明了
 * `agents` 就意味着宿主没有该服务时**插件根本不激活**（连门铃都收不了）。
 * `reflect.get(name, strict=false)` 才是"没有就返回 undefined"的那个口子。
 */
export function agentsOf(context: unknown): AgentsServiceLike | null {
  if (typeof context !== 'object' || context === null) {
    return null
  }
  let service: unknown
  try {
    const reflect = (context as { reflect?: { get?: (name: string, strict?: boolean) => unknown } })
      .reflect
    if (typeof reflect?.get !== 'function') {
      return null
    }
    service = reflect.get('agents', false)
  } catch {
    // 宿主没提供反射层或服务未就绪：按"没有 agents 服务"处理，插件仍收门铃
    return null
  }
  if (typeof service !== 'object' || service === null) {
    return null
  }
  const create = (service as { create?: unknown }).create
  if (typeof create !== 'function') {
    return null
  }
  return service as AgentsServiceLike
}
