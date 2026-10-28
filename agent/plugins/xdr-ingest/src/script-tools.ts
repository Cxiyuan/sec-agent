/**
 * 工具脚本库的模型工具：分析过程中写的脚本（Python/Bash/…）存下来，
 * 下次遇到同类场景先检索、取全文、只改变量就能复用。
 *
 * 为什么放在智能体侧而不是 NDR MCP：
 * - 脚本是**分析端**的取数工具，不是 NDR 的数据面；
 * - 场景描述、变量表、使用次数都是分析经验，跟着智能体走；
 * - NDR 只提供元数据与日志，不参与"脚本怎么写"。
 *
 * 三个工具的分工：
 * - `find_analysis_scripts`：按场景/名字/标签找（只回摘要，不塞满上下文）；
 * - `get_analysis_script`：取全文（会累计 usage_count）；
 * - `save_analysis_script`：保存/覆盖（同名默认拒绝，明确 `replace=true` 才覆盖）。
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { AnalysisScript, ScriptInput, ScriptStore } from './state-store.ts'

export interface ScriptToolsOptions {
  /** 单条脚本正文上限（字节）。超了拒绝保存，避免把库变成大文件仓库。 */
  readonly maxCodeBytes: number
  /** find 默认返回条数（调用方仍可调小）。 */
  readonly maxResults: number
  /**
   * 多项目：按**当前分析会话**取该项目的脚本库。
   * 不传 = 单项目（直接用 `store`）。
   */
  readonly storeOf?: (sessionId: string | undefined) => ScriptStore
}

/** Names registered globally for model-facing script-library access. */
export const ANALYSIS_SCRIPT_TOOL_NAMES = [
  'find_analysis_scripts',
  'get_analysis_script',
  'save_analysis_script',
] as const

const TEXT_OUTPUT = {
  schema: { type: 'string' as const },
  render: (_args: unknown, value: string) => [{ type: 'text' as const, text: value }],
}

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function clip(value: string, max: number): string {
  const trimmed = value.trim()
  return trimmed.length <= max ? trimmed : trimmed.slice(0, max)
}

function limitOf(value: unknown, fallback: number, max: number): number {
  const n = typeof value === 'number' && Number.isFinite(value) ? Math.trunc(value) : fallback
  return Math.max(1, Math.min(max, n))
}

function meta(script: AnalysisScript): Record<string, unknown> {
  return {
    id: script.id,
    name: script.name,
    scenario: script.scenario,
    language: script.language,
    tags: script.tags,
    variables: script.variables,
    notes: script.notes,
    usage_count: script.usageCount,
    updated_at: script.updatedAt,
    last_used_at: script.lastUsedAt,
    code_chars: script.code.length,
  }
}

/**
 * Register the script-library tools and return their lifecycle disposer.
 * @param ctx - Cordis context with the shared tool registry.
 * @param store - Memory or PostgreSQL script store.
 * @param options - Script size and search-result limits.
 * @returns An idempotent disposer that unregisters all three tools.
 */
export function registerScriptTools(
  ctx: Context,
  store: ScriptStore,
  options: ScriptToolsOptions,
): () => void {
  const disposers: Array<() => void> = []
  /** 每次调用都按会话解析一次（同一进程里可能同时有多个项目的会话在跑）。 */
  const pick = (exec: unknown): ScriptStore => {
    if (options.storeOf === undefined) return store
    // dsh 的 Agent 把会话标识暴露为 `agent.id`（ReactLoopAgent.id = SessionId）；
    // 兼容其它实现里的 `sessionId`，两者都取不到才回落到默认项目。
    const agent = (exec as { agent?: { id?: string, sessionId?: string } } | null | undefined)?.agent
    return options.storeOf(agent?.id ?? agent?.sessionId)
  }
  try {
    disposers.push(ctx.tools.register(defineTool({
      name: ANALYSIS_SCRIPT_TOOL_NAMES[0],
      description:
        '检索分析工具脚本库：按场景/名字/标签找以前写过的脚本。'
        + '只返回摘要（场景、变量、大小），要看正文用 get_analysis_script。'
        + '准备临时写脚本取数前先查一下，能省一轮编写与调试。',
      parameters: {
        query: {
          type: 'string',
          description: '关键词（匹配名字/场景/备注/标签），例如“DNS 隧道”“连接状态聚合”。留空 = 列全部。',
        },
        tag: { type: 'string', description: '只取带这个标签的脚本（可选）。' },
        limit: { type: 'number', description: '最多返回几条（默认 5）。' },
      },
      output: TEXT_OUTPUT,
      async execute(args: Record<string, unknown>, exec: unknown) {
        const box = pick(exec)
        const found = await box.find({
          query: text(args.query),
          tag: text(args.tag),
          limit: limitOf(args.limit, options.maxResults, Math.max(options.maxResults, 20)),
        })
        return JSON.stringify({
          ok: true,
          total: found.length,
          scripts: found.map(meta),
          note: found.length === 0
            ? '没有匹配的脚本；如果这次写的东西以后还能用，记得用 save_analysis_script 存下来。'
            : '取全文用 get_analysis_script(name=...)，然后只改变量。',
          store: box.kind,
        })
      },
    })))

    disposers.push(ctx.tools.register(defineTool({
      name: ANALYSIS_SCRIPT_TOOL_NAMES[1],
      description:
        '按名字或 id 取一条脚本的完整正文与变量表。'
        + '复用前先看场景描述与变量，只改变量，不要重写整个脚本。',
      parameters: {
        name: { type: 'string', description: '脚本名字或 id（find_analysis_scripts 返回）。', required: true },
      },
      output: TEXT_OUTPUT,
      async execute(args: Record<string, unknown>, exec: unknown) {
        const key = text(args.name)
        if (key === '') return JSON.stringify({ ok: false, error: 'name 必填' })
        const box = pick(exec)
        const script = await box.get(key)
        if (script === null) return JSON.stringify({ ok: false, error: `没有名为 ${key} 的脚本` })
        await box.bumpUsage(script.id, new Date().toISOString())
        return JSON.stringify({
          ok: true,
          ...meta(script),
          code: script.code,
          note: '执行前只改变量表里的值；脚本输出只是原始数据，证据仍要用 raw_evidence 真取回并引用。',
        })
      },
    })))

    disposers.push(ctx.tools.register(defineTool({
      name: ANALYSIS_SCRIPT_TOOL_NAMES[2],
      description:
        '把这次写的取数/处理脚本存进脚本库，供以后同类场景复用。'
        + 'scenario 必须写清“什么情况下用、输入什么、输出什么”；'
        + 'variables 写出可以改的变量（名字、含义、默认值），代码应集中引用这些变量。'
        + '不得保存真实口令、令牌、私钥或原始事件内容；凭据只引用环境变量名。'
        + '同名脚本默认不覆盖；确实要更新旧版本时带 replace=true。',
      parameters: {
        name: {
          type: 'string',
          description: '唯一名字，建议“动词_对象_目的”，例如 aggregate_conn_states_by_src。',
          required: true,
        },
        scenario: {
          type: 'string',
          description: '场景描述：什么时候该用它、需要什么输入、产出什么（检索靠它）。',
          required: true,
        },
        code: { type: 'string', description: '完整脚本正文。', required: true },
        language: { type: 'string', description: '语言/运行方式：bash / python / node / jq（默认 bash）。' },
        variables: {
          type: 'json',
          description: '变量表（任意 JSON）：建议 {"变量名": {"说明": "...", "默认": "..."}}。',
        },
        tags: { type: 'array', items: { type: 'string' }, description: '标签，例如 ["dns","baseline"]。' },
        notes: { type: 'string', description: '踩过的坑 / 依赖（可选）。' },
        source_task_id: { type: 'string', description: '产出这条脚本的任务 id（可选，便于回溯）。' },
        replace: { type: 'boolean', description: '同名时是否覆盖（默认 false）。' },
      },
      output: TEXT_OUTPUT,
      async execute(args: Record<string, unknown>, exec: unknown) {
        const name = clip(text(args.name), 80)
        const scenario = clip(text(args.scenario), 500)
        const code = typeof args.code === 'string' ? args.code : ''
        if (name === '') return JSON.stringify({ ok: false, error: 'name 必填' })
        if (scenario === '') return JSON.stringify({ ok: false, error: 'scenario 必填：写清什么场景用' })
        if (code.trim() === '') return JSON.stringify({ ok: false, error: 'code 必填' })
        const codeBytes = Buffer.byteLength(code, 'utf8')
        if (codeBytes > options.maxCodeBytes) {
          return JSON.stringify({
            ok: false,
            error: `脚本太大（${codeBytes} 字节，上限 ${options.maxCodeBytes}）；请精简或拆成多个脚本`,
          })
        }
        const box = pick(exec)
        const existing = await box.get(name)
        if (existing !== null && args.replace !== true) {
          return JSON.stringify({
            ok: false,
            error: `同名脚本已存在（${name}）。确认要更新旧版本请带 replace=true。`,
            existing: meta(existing),
          })
        }
        const tags = Array.isArray(args.tags)
          ? args.tags.filter((tag: unknown): tag is string => typeof tag === 'string').slice(0, 12)
          : []
        const input: ScriptInput = {
          name,
          scenario,
          code,
          language: clip(text(args.language), 32) || 'bash',
          variables: args.variables ?? {},
          tags,
          notes: clip(text(args.notes), 2000),
          sourceTaskId: clip(text(args.source_task_id), 64),
        }
        try {
          const saved = await box.upsert(input, new Date().toISOString())
          return JSON.stringify({
            ok: true,
            created: existing === null,
            script: meta(saved),
            store: box.kind,
            note: box.kind === 'memory'
              ? '当前是内存脚本库（PG 未配置），进程重启后会丢；请让运维检查 pgUrl。'
              : '已入库，下次同类场景用 find_analysis_scripts 检索。',
          })
        } catch (error) {
          return JSON.stringify({
            ok: false,
            error: error instanceof Error ? error.message : String(error),
          })
        }
      },
    })))
  } catch (error) {
    for (const dispose of [...disposers].reverse()) {
      try {
        dispose()
      } catch (cleanupError) {
        console.warn(
          '[xdr-ingest] script tool registration rollback failed:',
          cleanupError instanceof Error ? cleanupError.message : String(cleanupError),
        )
      }
    }
    throw error
  }
  let active = true
  return () => {
    if (!active) return
    active = false
    for (const dispose of [...disposers].reverse()) {
      try {
        dispose()
      } catch (error) {
        console.warn(
          '[xdr-ingest] script tool disposal failed:',
          error instanceof Error ? error.message : String(error),
        )
      }
    }
  }
}
