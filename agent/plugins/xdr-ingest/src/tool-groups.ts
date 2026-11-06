/**
 * 分析会话的按需工具分组。
 *
 * 默认只把常用取证工具放进模型工具面，罕见能力（文件内容、规则、任务统计、
 * 覆盖率、轨迹等）按组交给 `enable_analysis_tools` 激活。工具本身始终注册在
 * registry 里，只是先被 `tools.restrict` 从当前 agent 的工具面隐藏；因此不会
 * 因为“最近没调用”丢掉未来场景需要的能力。
 */

/** 默认直接暴露的分析工具（MCP 原始名，不含 mcp__ndr__ 前缀）。 */
export const CORE_NDR_TOOLS: readonly string[] = [
  'search_events',
  'aggregate_events',
  'search_hits',
  'prior_findings',
  'task_facts',
  'domain_intel',
  'get_rule',
  'list_filters',
  'asset_context',
  'list_networks',
  'describe_data',
  'timeline',
  'net_flows',
  'web_requests',
  'hit_clusters',
  'entity_profile',
  'raw_evidence',
  'get_event_detail',
  'search_traces',
  'complete_task',
  // 抑制是分析闭环的一部分，必须默认可见；否则误报结论无处交回。
  'submit_suppression',
]

/**
 * 默认直接暴露的宿主工具（不归 NDR MCP 命名空间）。
 *
 * 会话检索不是“罕见能力”：回溯同项目历史分析是每次研判的常规步骤，
 * 藏在 history 组里模型根本不会激活。分组只保留给真正的低频工具。
 */
export const CORE_AGENT_TOOLS: readonly string[] = [
  'session_search',
  'session_event_search',
  'session_trace',
  'session_event_trace',
  'session_event_read',
]

/** obs_case 的窄工具面：先看事实/资产/基线/域名，不做全量调查。 */
export const OBSERVATION_CASE_TOOLS: readonly string[] = [
  'task_facts',
  'asset_context',
  'egress_baseline',
  'domain_intel',
  'prior_findings',
  'get_rule',
  'list_networks',
  'search_hits',
  'complete_task',
  'submit_suppression',
]

/** 分析会话永久禁用的工具：只能处理派给自己的那条任务。 */
export const ALWAYS_DENY_TOOLS: readonly string[] = [
  'mcp__ndr__claim_tasks',
  // 租约心跳是插件运行层职责，模型不需要/不应该改租约。
  'mcp__ndr__renew_task_lease',
  // 摘要分流是插件运行层职责，不能由模型自己扩案。
  'mcp__ndr__escalate_digest',
]

/** 非 NDR 的按需能力组；与 MCP 组一样可通过 enable_analysis_tools 激活。 */
export const NON_NDR_GROUPS: Readonly<Record<string, readonly string[]>> = {
  schedule: [
    'schedule_create',
    'schedule_update',
    'schedule_delete',
  ],
  deliverable: ['present'],
}

/** 按场景分组的罕见工具；未列出的 MCP 工具归入 other。 */
export const NDR_TOOL_GROUPS: Readonly<Record<string, readonly string[]>> = {
  network: [
    'dns_queries',
    'tls_fingerprints',
    'relay_nodes',
    'list_observations',
    'asset_map',
    'baseline_lookup',
    'egress_baseline',
  ],
  identity: [
    'server_info',
    'coverage_report',
  ],
  evidence: [
    'file_content',
  ],
  task: [
    'task_state',
    'task_stats',
    'defer_task',
    'log_step',
    'record_audit',
    'list_rules',
    'get_trace',
  ],
  // 抑制清单结果可能很大，放按需组；提交工具本身在 core。
  suppression: ['list_suppressions'],
}

export interface PlannedToolGroups {
  /** 当前实际存在的核心工具（带 mcp__ndr__ 前缀）。 */
  readonly core: readonly string[]
  /** 当前实际存在、需要按需激活的组；组名 → 带前缀的工具名。 */
  readonly groups: Readonly<Record<string, readonly string[]>>
}

const PREFIX = 'mcp__ndr__'

function withPrefix(name: string): string {
  return name.startsWith(PREFIX) ? name : `${PREFIX}${name}`
}

/**
 * 按当前 registry 中真实存在的工具名规划分组。
 *
 * 只返回实际存在的名字，避免 `tools.restrict` 因未知工具整体失败；
 * `other` 收容未显式分组的新 MCP 工具，保证以后新增能力可通过 `all` 激活。
 */
export function planToolGroups(
  available: readonly string[],
  kind = '',
): PlannedToolGroups {
  const existing = new Set(available)
  const core = [
    ...((kind === 'obs_case' || kind === 'struct_case') ? OBSERVATION_CASE_TOOLS : CORE_NDR_TOOLS).map(withPrefix),
    ...((kind === 'obs_case' || kind === 'struct_case') ? [] : CORE_AGENT_TOOLS),
  ].filter(name => existing.has(name))
  const assigned = new Set(core)
  const groups: Record<string, string[]> = {}

  for (const [group, names] of Object.entries(NDR_TOOL_GROUPS)) {
    const tools = names.map(withPrefix).filter(name => existing.has(name) && !assigned.has(name))
    if (tools.length > 0) {
      groups[group] = tools
      for (const name of tools) assigned.add(name)
    }
  }
  for (const [group, names] of Object.entries(NON_NDR_GROUPS)) {
    const tools = names.filter(name => existing.has(name) && !assigned.has(name))
    if (tools.length > 0) {
      groups[group] = tools
      for (const name of tools) assigned.add(name)
    }
  }

  const other = available.filter(
    name => name.startsWith(PREFIX) && name !== `${PREFIX}claim_tasks` && !assigned.has(name),
  )
  if (other.length > 0) groups.other = other

  return { core, groups }
}

/** `enable_analysis_tools` 的参数可选值。 */
export const TOOL_GROUP_NAMES: readonly string[] = [
  'network',
  'identity',
  'evidence',
  'task',
  'suppression',
  'schedule',
  'deliverable',
  'other',
  'all',
]
