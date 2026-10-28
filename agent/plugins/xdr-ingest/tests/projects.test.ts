/**
 * P2/P3 单测：多项目路由 + 绑定校验 + 会话时间线投影。
 *
 * 只测纯逻辑（不连 PG、不连 DSH）：项目表的读写用内存实现注入，
 * 时间线用一段 JSONL 文本喂进 `parseSessionLog`。
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ProjectManager, SessionProjects } from '../src/projects.ts'
import { parseSessionLog } from '../src/session-timeline.ts'
import { buildAnalysisPrompt } from '../src/prompt.ts'
import { DEFAULT_WORKFLOW_STAGES, resolveWorkflow } from '../src/projects.ts'
import type { ProjectAdminStore, ProjectRuntimeConfig } from '../src/projects.ts'
import type { WorkflowInput, WorkflowRecord } from '../src/state-store.ts'
import { MemoryStateStore } from '../src/state-store.ts'
import type { ProjectInput, ProjectRecord, ProjectStatus } from '../src/state-store.ts'

const CONFIG: ProjectRuntimeConfig = {
  pollSeconds: 300,
  maxConcurrent: 4,
  claimLimit: 4,
  analysisTimeoutSeconds: 1200,
  doorbellDebounceMs: 3000,
  backoffMaxMs: 300000,
  provider: '',
  model: '',
  taskReuseTtlHours: 24,
  taskReuseStrengthDelta: 0.15,
  sessionDir: '/data/dsh/sessions',
}

function project(overrides: Partial<ProjectRecord> = {}): ProjectRecord {
  return {
    projectId: 'ZPL6QQLG',
    name: '南充职业技术学院',
    mcpUrl: 'http://ndr-mcp:8090/mcp',
    mcpToken: 'stmcp_1',
    pushToken: 'push-1',
    enabled: true,
    status: 'unchecked',
    statusDetail: '',
    lastCheckedAt: '',
    createdAt: '',
    updatedAt: '',
    ...overrides,
  }
}

/** 内存项目表：只实现管理器用到的五个方法。 */
class FakeAdmin implements ProjectAdminStore {
  readonly rows = new Map<string, ProjectRecord>()
  readonly workflows = new Map<string, WorkflowRecord>()

  constructor(seed: ProjectRecord[] = []) {
    for (const row of seed) this.rows.set(row.projectId, row)
  }

  async listProjects(): Promise<ProjectRecord[]> {
    return [...this.rows.values()]
  }

  async getProject(projectId: string): Promise<ProjectRecord | null> {
    return this.rows.get(projectId) ?? null
  }

  async upsertProject(input: ProjectInput): Promise<ProjectRecord | null> {
    const row = project({
      projectId: input.projectId,
      name: input.name,
      mcpUrl: input.mcpUrl,
      mcpToken: input.mcpToken,
      pushToken: input.pushToken,
      enabled: input.enabled ?? true,
    })
    this.rows.set(row.projectId, row)
    return row
  }

  async setProjectStatus(projectId: string, status: ProjectStatus, detail: string): Promise<void> {
    const row = this.rows.get(projectId)
    if (row !== undefined) this.rows.set(projectId, { ...row, status, statusDetail: detail })
  }

  async removeProject(projectId: string): Promise<boolean> {
    return this.rows.delete(projectId)
  }

  async listWorkflows(): Promise<WorkflowRecord[]> {
    return [...this.workflows.values()]
  }

  async getWorkflow(workflowId: string): Promise<WorkflowRecord | null> {
    return this.workflows.get(workflowId) ?? null
  }

  async upsertWorkflow(input: WorkflowInput, nowIso: string): Promise<WorkflowRecord> {
    const id = input.isDefault === true ? 'default' : `wf-${this.workflows.size + 1}`
    const row = {
      workflowId: id,
      name: input.name,
      description: input.description ?? '',
      stages: input.stages,
      enabled: input.enabled ?? true,
      isDefault: input.isDefault === true,
      createdAt: nowIso,
      updatedAt: nowIso,
      updatedBy: 'test',
    }
    this.workflows.set(id, row)
    return row
  }

  async setWorkflowEnabled(workflowId: string, enabled: boolean): Promise<boolean> {
    const row = this.workflows.get(workflowId)
    if (row === undefined) return false
    this.workflows.set(workflowId, { ...row, enabled })
    return true
  }

  async removeWorkflow(workflowId: string): Promise<boolean> {
    return this.workflows.delete(workflowId)
  }

  async setProjectWorkflow(projectId: string, workflowId: string): Promise<boolean> {
    const row = this.rows.get(projectId)
    if (row === undefined) return false
    this.rows.set(projectId, { ...row, workflowId })
    return true
  }
}

function makeManager(admin: FakeAdmin) {
  const sessions = new SessionProjects()
  const manager = new ProjectManager({
    config: CONFIG,
    // 不传 agents：startProject 会落「agent 服务不可用」，正好覆盖"校验不过不起循环"
    agents: null,
    admin,
    sessions,
    storeOf: () => ({}) as unknown as MemoryStateStore,
  })
  return { manager, sessions }
}

test('SessionProjects：会话到项目的映射可建立与清理（脚本工具靠它隔离）', () => {
  const sessions = new SessionProjects()
  sessions.set('s-1', 'ZPL6QQLG')
  assert.equal(sessions.get('s-1'), 'ZPL6QQLG')
  assert.equal(sessions.get('s-2'), null)
  sessions.delete('s-1')
  assert.equal(sessions.get('s-1'), null)
})

test('项目保存：授权ID 必须 8 位大写字母或数字（与 NDR 系统授权页同规则）', async () => {
  const admin = new FakeAdmin()
  const { manager } = makeManager(admin)
  const bad = await manager.save({
    projectId: 'abc',
    name: 'x',
    mcpUrl: 'http://ndr-mcp:8090/mcp',
    mcpToken: 't',
    pushToken: 'p',
  })
  assert.equal(bad.ok, false)
  assert.match(bad.error ?? '', /8 位/u)
  const badUrl = await manager.save({
    projectId: 'ZPL6QQLG',
    name: 'x',
    mcpUrl: 'ftp://nope',
    mcpToken: 't',
    pushToken: 'p',
  })
  assert.equal(badUrl.ok, false)
  assert.match(badUrl.error ?? '', /http/u)
})

test('项目保存：合法授权ID 落库；没有 agent 服务时状态为 unreachable（不静默起循环）', async () => {
  const admin = new FakeAdmin()
  const { manager } = makeManager(admin)
  const saved = await manager.save({
    projectId: 'ZPL6QQLG',
    name: '南充职业技术学院',
    mcpUrl: 'http://ndr-mcp:8090/mcp',
    mcpToken: 'stmcp_1',
    pushToken: 'push-1',
  })
  assert.equal(saved.ok, true)
  assert.equal(admin.rows.get('ZPL6QQLG')?.name, '南充职业技术学院')
  assert.equal(saved.project?.status, 'unreachable')
})

test('项目保存：改授权ID 视为换项目（旧项目行删掉，避免同一个 NDR 挂两份）', async () => {
  const admin = new FakeAdmin([project({ projectId: 'AAAAAAAA' })])
  const { manager } = makeManager(admin)
  const saved = await manager.save({
    projectId: 'BBBBBBBB',
    previousId: 'AAAAAAAA',
    name: '换绑后的项目',
    mcpUrl: 'http://ndr-mcp:8090/mcp',
    mcpToken: 'stmcp_1',
    pushToken: 'push-1',
  })
  assert.equal(saved.ok, true)
  assert.equal(admin.rows.has('AAAAAAAA'), false)
  assert.equal(admin.rows.get('BBBBBBBB')?.name, '换绑后的项目')
})

test('门铃路由：按推送令牌找到项目；不认识的令牌返回 null（handler 回 401）', async () => {
  const admin = new FakeAdmin([project()])
  const { manager } = makeManager(admin)
  await manager.init()
  // 没起循环也要能认出令牌：否则 NDR 会一直重推同一记门铃
  assert.equal(manager.resolvePushToken('push-1'), 'ZPL6QQLG')
  assert.equal(manager.get('ZPL6QQLG'), null, '没有 agents 服务时不起循环')
  assert.equal(manager.resolvePushToken('nope'), null)
})

test('时间线：工具调用/返回/思考/token/报错都投影出来，轮次与 step 保留', () => {
  const lines = [
    { type: 'session', version: 4, id: 's-1' },
    { type: 'user/message', seq: 1, time: 1000, data: { content: [{ type: 'text', text: '分析这条线索' }] } },
    { type: 'user/message', seq: 2, time: 1001, data: { content: [{ type: 'text', text: 'Current runtime context. ...' }] } },
    {
      type: 'assistant/message', seq: 3, time: 2000,
      data: { turn: 1, step: 1, message: { role: 'assistant', content: [{ type: 'reasoning', text: '先查连接' }] } },
    },
    { type: 'tool/call', seq: 4, time: 2100, data: { turn: 1, step: 1, callId: 'c1', name: 'mcp__ndr__search_events', arguments: '{"limit":5}' } },
    {
      type: 'tool/result', seq: 5, time: 2600,
      data: { turn: 1, step: 1, message: { role: 'tool', toolCallId: 'c1', content: [{ type: 'text', text: '{"returned":5}' }] } },
    },
    {
      type: 'assistant/attempt', seq: 6, time: 2700,
      data: {
        turn: 1, step: 1,
        stream: [
          { type: 'chunk', time: 2700, chunk: { type: 'usage', usage: { inputTokens: 100, outputTokens: 20, totalTokens: 120 } } },
          { type: 'chunk', time: 2701, chunk: { type: 'finish', reason: { kind: 'error', failure: { message: '429 quota' } } } },
        ],
      },
    },
  ]
  const out = parseSessionLog(lines.map(line => JSON.stringify(line)).join('\n'), 's-1', { running: true })
  assert.equal(out.ok, true)
  assert.equal(out.running, true)
  assert.deepEqual(out.tokens, { input: 100, output: 20, total: 120, reported: true })
  assert.equal(out.tools[0]?.name, 'mcp__ndr__search_events')
  assert.equal(out.tools[0]?.count, 1)
  assert.equal(out.tools[0]?.totalMs, 500)
  const kinds = out.events.map(event => event.kind)
  assert.deepEqual(kinds, ['task', 'thinking', 'tool', 'tool_result', 'usage', 'error'])
  assert.equal(out.events[0]?.detail, '分析这条线索', '运行时上下文不该占时间线')
  assert.equal(out.events.find(event => event.kind === 'error')?.isError, true)
  assert.equal(out.nextSeq, 6)
})

test('时间线：会话日志没记 token 时 reported=false（界面显示"未上报"而不是 0）', () => {
  const lines = [
    { type: 'user/message', seq: 1, time: 1000, data: { content: [{ type: 'text', text: '任务' }] } },
    { type: 'assistant/message', seq: 2, time: 1100, data: { message: { role: 'assistant', content: [{ type: 'text', text: '好' }] } } },
  ]
  const out = parseSessionLog(lines.map(line => JSON.stringify(line)).join('\n'), 's-9')
  assert.equal(out.tokens.reported, false)
  assert.deepEqual(out.events.map(e => e.kind), ['task', 'assistant'])

  // 有些版本把 usage 挂在 message 上（snake_case 也要认）
  const withUsage = [
    { type: 'assistant/message', seq: 1, time: 1000, data: { message: { role: 'assistant', content: [{ type: 'text', text: 'ok' }] }, usage: { input_tokens: 30, output_tokens: 7 } } },
  ]
  const out2 = parseSessionLog(withUsage.map(line => JSON.stringify(line)).join('\n'), 's-9')
  assert.deepEqual(out2.tokens, { input: 30, output: 7, total: 37, reported: true })
})

test('时间线：after 只回增量（实时轮询靠它，不重复渲染整段）', () => {
  const lines = [
    { type: 'user/message', seq: 1, time: 1000, data: { content: [{ type: 'text', text: '任务' }] } },
    { type: 'tool/call', seq: 2, time: 1100, data: { turn: 1, step: 1, callId: 'c1', name: 'x', arguments: '{}' } },
    { type: 'tool/call', seq: 3, time: 1200, data: { turn: 1, step: 2, callId: 'c2', name: 'y', arguments: '{}' } },
  ]
  const out = parseSessionLog(lines.map(line => JSON.stringify(line)).join('\n'), 's-1', { after: 2 })
  assert.deepEqual(out.events.map(event => event.seq), [3])
  assert.equal(out.nextSeq, 3)
})


test('工作流：默认模版解析（绑定优先，停用/不存在回落默认）', async () => {
  const admin = new FakeAdmin()
  await admin.upsertWorkflow({ name: '标准', stages: DEFAULT_WORKFLOW_STAGES, isDefault: true }, '2026-10-29T00:00:00Z')
  const custom = await admin.upsertWorkflow({ name: '外连专项', stages: [{ key: 'x', title: '只看外连', goal: '', guidance: '', tools: [] }] }, '2026-10-29T00:00:00Z')
  assert.equal((await resolveWorkflow(admin, custom.workflowId))?.name, '外连专项')
  assert.equal((await resolveWorkflow(admin, 'nope'))?.name, '标准', '绑定的模版被删了要回落默认')
  await admin.setWorkflowEnabled(custom.workflowId, false)
  assert.equal((await resolveWorkflow(admin, custom.workflowId))?.name, '标准', '停用的模版不能再用')
})

test('工作流：提示词带阶段与进度标记要求（事实在前，阶段不是死步骤）', () => {
  const prompt = buildAnalysisPrompt(
    { id: 't-1', kind: 'observation', strength: 0.6, subject_kind: 'ip', subject: '10.1.2.3' },
    {
      workflowId: 'w1', name: '外连专项', description: '', stages: [
        { key: 'a', title: '先看外连', goal: '确认是否新目标', guidance: '对比历史目的地', tools: ['egress_baseline'] },
      ], enabled: true, isDefault: false, createdAt: '', updatedAt: '', updatedBy: 'test',
    },
  )
  assert.ok(prompt.includes('分析编排：外连专项'))
  assert.ok(prompt.includes('1. 先看外连'))
  assert.ok(prompt.includes('egress_baseline'))
  assert.ok(prompt.includes('【阶段】'))
  assert.ok(prompt.includes('阶段是提纲不是死步骤'))
  // 没绑定模版时不能凭空造一段编排
  const plain = buildAnalysisPrompt(
    { id: 't-2', kind: 'novelty', strength: 0.3, subject_kind: 'ip', subject: '10.1.2.4' },
    null,
  )
  assert.ok(!plain.includes('分析编排'))
})

test('工作流：过程索引存模版快照（模版后来改了，历史仍显示当时的阶段）', async () => {
  const store = new MemoryStateStore('ZPL6QQLG')
  const stages = [{ key: 'a', title: '阶段甲', goal: '', guidance: '', tools: [] }]
  await store.startProcess({
    taskId: 't-1', sessionId: 's-1', kind: 'hit', subject: '10.1.2.3', model: 'm',
    startedAt: '2026-10-29T00:00:00Z', workflowId: 'w1', workflowName: '旧模版', workflowStages: stages,
  })
  const row = await store.getProcess('t-1')
  assert.equal(row?.workflowId, 'w1')
  assert.equal(row?.workflowName, '旧模版')
  assert.deepEqual(row?.workflowStages, stages)
})
