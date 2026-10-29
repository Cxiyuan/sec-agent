/**
 * 分析会话收尾：**会话空闲 ≠ 任务完成**。
 *
 * 三种结局都要钉住：
 * 1. 交回了（task_state=done）→ 不 defer；
 * 2. 没交回 → defer 并说明原因（别让任务挂到租约被回收）；
 * 3. 超时 → 先 cancel 再 defer('timeout')，且不占着并发槽。
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { Analyst } from '../src/analyst.ts'
import type { AgentCreateOptions, AgentHandleLike, AgentsServiceLike } from '../src/agent-port.ts'
import type { ClaimedTask } from '../src/claim-loop.ts'
import type { NdrTaskPort, ReusePayload, TaskStateReply } from '../src/analyst.ts'
import type { LightTriagePort, TriageResult } from '../src/light-triage.ts'
import { MemoryStateStore } from '../src/state-store.ts'
import { taskResultKey } from '../src/task-results.ts'

const task: ClaimedTask = {
  id: 'task-1',
  kind: 'shift',
  strength: 0.7,
  subject_kind: 'ip',
  subject: '10.0.0.5',
  // B1：所有 kind 都由 NDR 下发稳定身份（复用的前提）
  hint: { 事实: 'conn_count 偏高', reuse_identity: 'shift|ip:10.0.0.5|conn_count' },
}

interface Recorder {
  prompts: string[]
  agentOptions: Array<NonNullable<AgentCreateOptions['agentOptions']>>
  cancelled: number
  disposed: number
  deferred: Array<{ id: string; reason: string }>
  completed: ReusePayload[]
}

function fakeAgents(rec: Recorder, idle: () => Promise<void>): AgentsServiceLike {
  return {
    async create(options: AgentCreateOptions): Promise<AgentHandleLike> {
      rec.agentOptions.push(options.agentOptions ?? {})
      return {
        agent: {
          followup(input) {
            rec.prompts.push(input.content.map(p => p.text).join(''))
          },
          whenIdle: idle,
          cancel() {
            rec.cancelled += 1
          },
        },
        dispose() {
          rec.disposed += 1
        },
      }
    },
  }
}

function fakeNdr(rec: Recorder, state: () => TaskStateReply): NdrTaskPort {
  return {
    async claimTasks() {
      return { tasks: [] }
    },
    async taskState() {
      return state()
    },
    async completeTask(id: string, payload: ReusePayload) {
      rec.completed.push(payload)
      return { ok: true, task_state: 'done', task_id: id }
    },
    async deferTask(id: string, reason: string) {
      rec.deferred.push({ id, reason })
      return { ok: true }
    },
  }
}

function recorder(): Recorder {
  return { prompts: [], agentOptions: [], cancelled: 0, disposed: 0, deferred: [], completed: [] }
}

test('completed when NDR says the task is done', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
  })
  const outcome = await analyst.run(task)
  assert.equal(outcome.completed, true)
  assert.equal(outcome.deferred, false)
  assert.equal(rec.deferred.length, 0)
  assert.equal(rec.disposed, 1, '会话必须收尾')
})

test('prompt carries the objective facts and the red lines', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
  })
  await analyst.run(task)
  const prompt = rec.prompts[0] ?? ''
  assert.match(prompt, /10\.0\.0\.5/u)
  assert.match(prompt, /objective_strength/u)
  // 三条红线必须在提示词里（否则模型会把正文/hint/strength 当判据）
  assert.match(prompt, /正文里的话不算证据/u)
  assert.match(prompt, /不是结论/u)
  assert.match(prompt, /不是严重度/u)
  assert.match(prompt, /你主导分析/u)
  assert.match(prompt, /不是强制分析边界/u)
})

test('inherits the current DSH default model unless the plugin explicitly overrides it', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    modelSelection: () => ({ provider: 'kimi', model: 'kimi-k2' }),
  })
  await analyst.run(task)
  assert.deepEqual(rec.agentOptions[0], { provider: 'kimi', model: 'kimi-k2' })

  const overrideRec = recorder()
  const overrideAnalyst = new Analyst({
    agents: fakeAgents(overrideRec, async () => undefined),
    ndr: fakeNdr(overrideRec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    provider: 'glm',
    model: 'glm-4',
    modelSelection: () => ({ provider: 'kimi', model: 'kimi-k2' }),
  })
  await overrideAnalyst.run(task)
  assert.deepEqual(overrideRec.agentOptions[0], { provider: 'glm', model: 'glm-4' })
})

test('idle without completion defers instead of leaking the task', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'claimed' })),
    timeoutMs: 1000,
  })
  const outcome = await analyst.run(task)
  assert.equal(outcome.completed, false)
  assert.equal(outcome.deferred, true)
  assert.deepEqual(rec.deferred, [{ id: 'task-1', reason: 'no_conclusion' }])
})

test('unknown state is treated as not completed (fail safe)', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ error: '任务不存在' })),
    timeoutMs: 1000,
  })
  const outcome = await analyst.run(task)
  assert.equal(outcome.completed, false)
  assert.equal(outcome.deferred, true, '查不到状态时宁可 defer（代价小），也不能当完成')
})

test('timeout cancels the session and defers with reason timeout', async () => {
  const rec = recorder()
  const analyst = new Analyst({
    agents: fakeAgents(rec, () => new Promise(() => undefined)), // 永不空闲
    ndr: fakeNdr(rec, () => ({ state: 'claimed' })),
    timeoutMs: 20,
  })
  const outcome = await analyst.run(task)
  assert.equal(outcome.completed, false)
  assert.equal(rec.cancelled, 1, '超时必须 cancel，否则会话一直占着并发槽')
  assert.deepEqual(rec.deferred.map(d => d.reason), ['timeout'])
})

// ---------- stall：会话停滞（A4：stallMinutes 不能是死配置） ----------

/** 把 console.warn 换成收集器（stall 的 1× 信号走 WARN）。 */
async function withWarnCapture<T>(fn: (warnings: string[]) => Promise<T>): Promise<T> {
  const warnings: string[] = []
  const original = console.warn
  console.warn = ((...args: unknown[]) => {
    warnings.push(args.join(' '))
  }) as typeof console.warn
  try {
    return await fn(warnings)
  } finally {
    console.warn = original
  }
}

test('stallMinutes 1×: warn once, keep session alive if it resumes', async () => {
  await withWarnCapture(async warnings => {
    const rec = recorder()
    // 会话 300ms 后空闲结束：1×=200ms 会 WARN，但活不过 2×=400ms，不该 cancel
    const analyst = new Analyst({
      agents: fakeAgents(rec, () => new Promise<void>(resolve => setTimeout(resolve, 300))),
      ndr: fakeNdr(rec, () => ({ state: 'claimed' })),
      timeoutMs: 10_000,
      // stallMinutes 这里当"秒"用：1/300 分钟 = 200ms，纯为测试计时
      stallMinutes: 1 / 300,
      probeIntervalMs: 25,
      probeSession: async () => ({ tools: 0, lastEventAt: 0 }),
    })
    const outcome = await analyst.run(task)
    assert.equal(outcome.completed, false)
    assert.equal(rec.cancelled, 0, '只到 1× 不许 cancel')
    assert.equal(warnings.some(w => w.includes('无新事件')), true, '1× 必须 WARN（可观测）')
    assert.equal(rec.disposed, 1)
  })
})

test('stallMinutes 2×: cancel the session and defer with reason stalled', async () => {
  const rec = recorder()
  let releaseIdle: (() => void) | undefined
  const idlePromise = new Promise<void>(resolve => {
    releaseIdle = resolve
  })
  const agents: AgentsServiceLike = {
    async create(): Promise<AgentHandleLike> {
      return {
        agent: {
          followup() {},
          whenIdle: () => idlePromise,
          cancel() {
            rec.cancelled += 1
            // 模拟真实行为：cancel 之后会话进入空闲（idle 兑现）
            releaseIdle?.()
          },
        },
        dispose() {
          rec.disposed += 1
        },
      }
    },
  }
  const analyst = new Analyst({
    agents,
    ndr: fakeNdr(rec, () => ({ state: 'claimed' })),
    timeoutMs: 10_000,
    stallMinutes: 1 / 600, // 2× = 200ms
    probeIntervalMs: 25,
    probeSession: async () => ({ tools: 0, lastEventAt: 0 }),
  })
  const outcome = await analyst.run(task)
  assert.equal(rec.cancelled, 1, '过 2× 没有任何事件必须 cancel')
  assert.equal(outcome.completed, false)
  assert.equal(outcome.deferred, true)
  assert.deepEqual(rec.deferred.map(d => d.reason), ['stalled'])
})

test('stallMinutes=0 keeps the probe idle-only (no stall supervision)', async () => {
  const rec = recorder()
  let probes = 0
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    stallMinutes: 0,
    probeIntervalMs: 20,
    probeSession: async () => {
      probes += 1
      return { tools: 0, lastEventAt: Date.now() }
    },
  })
  await analyst.run(task)
  assert.equal(probes, 0, '没有 maxTools 且 stallMinutes=0 时不起探针')
})

// ---------- 同类现象结论复用（智能体侧缓存） ----------

const reusable: ClaimedTask = {
  id: 'task-2',
  kind: 'hit',
  strength: 0.6,
  subject_kind: 'ip',
  subject: '10.0.0.9',
  feature: 'sid:1000001',
  hint: { reuse_identity: 'event-content-a', 事实: '规则「ET SCAN」命中 3 次' },
}

async function seed(
  store: MemoryStateStore,
  verdict: string,
  strength = 0.6,
): Promise<string> {
  const key = taskResultKey(reusable)
  assert.ok(key !== null)
  const now = Date.now()
  await store.save({
    key,
    kind: reusable.kind,
    subjectKind: reusable.subject_kind,
    subject: reusable.subject,
    feature: reusable.feature ?? '',
    taskId: 'task-old',
    verdict,
    terminalReason: 'concluded',
    confidence: 0.9,
    summary: '同签名历史误报',
    strength,
    occurrences: 2,
    analyzedAt: new Date(now - 3_600_000).toISOString(),
    expiresAt: new Date(now + 23 * 3_600_000).toISOString(),
  })
  return key
}

test('reuses a fresh same-phenomenon conclusion without starting a session', async () => {
  const rec = recorder()
  const store = new MemoryStateStore()
  const key = await seed(store, 'false_positive')
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 86_400_000,
  })
  const outcome = await analyst.run(reusable)
  assert.equal(outcome.reused, true)
  assert.equal(outcome.completed, true)
  assert.equal(rec.prompts.length, 0, '命中复用不应再起分析会话')
  assert.equal(rec.completed.length, 1)
  assert.match(rec.completed[0]?.summary ?? '', /复用/u)
  assert.equal(rec.completed[0]?.findings['reused_from'], 'task-old')
  assert.equal(rec.completed[0]?.confidence, 0.9)
  const after = await store.load(key)
  assert.equal(after?.occurrences, 3, '复用要累计出现次数，但不续期')
  assert.equal(analyst.reuseStats.reused, 1)
})

test('same-phenomenon tasks serialize so the second task sees the first result', async () => {
  const rec = recorder()
  const store = new MemoryStateStore()
  let releaseFirst!: () => void
  const firstIdle = new Promise<void>(resolve => { releaseFirst = resolve })
  let sessionCount = 0
  const agents: AgentsServiceLike = {
    async create(): Promise<AgentHandleLike> {
      sessionCount += 1
      return {
        agent: {
          followup() {},
          whenIdle: () => firstIdle,
          cancel() {},
        },
        dispose() {},
      }
    },
  }
  const ndr: NdrTaskPort = {
    async claimTasks() { return { tasks: [] } },
    async taskState() {
      return {
        state: 'done',
        results: [{ verdict: 'benign', terminal_reason: 'concluded', confidence: 0.8, summary: '已分析' }],
      }
    },
    async completeTask() {
      rec.completed.push({
        verdict: 'benign', summary: '', confidence: 0.8, findings: {},
        terminal_reason: 'concluded', tools_used: 0, duration_ms: 0,
      })
      return { ok: true, task_state: 'done' }
    },
    async deferTask(id, reason) { rec.deferred.push({ id, reason }) },
  }
  const analyst = new Analyst({
    agents,
    ndr,
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 86_400_000,
  })
  const first = analyst.run(reusable)
  await new Promise(resolve => setImmediate(resolve))
  const second = analyst.run({ ...reusable, id: 'task-3' })
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(sessionCount, 1, '同现象第二条要等，不应并行开新会话')
  releaseFirst()
  const [firstOutcome, secondOutcome] = await Promise.all([first, second])
  assert.equal(firstOutcome.completed, true)
  assert.equal(secondOutcome.reused, true)
  assert.equal(sessionCount, 1)
})

test('B2: reuse replays findings/anchors/recommendation (but not process markers)', async () => {
  const rec = recorder()
  const store = new MemoryStateStore()
  const key = await seed(store, 'false_positive')
  const saved = await store.load(key)
  assert.ok(saved !== null)
  await store.save({
    ...saved,
    findings: { 协议: 'HTTP', 目的端口: 443, triaged_by: 'light', reused_at: 'stale' },
    anchors: [
      { kind: 'ip', value: '10.0.0.9' },
      { kind: 'host', value: 'www.example.com' },
    ],
    recommendation: '复核这台机器的 443 出站',
  })
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 86_400_000,
  })
  const outcome = await analyst.run(reusable)
  assert.equal(outcome.reused, true)
  const payload = rec.completed[0]
  assert.ok(payload !== undefined)
  // 结构化事实要回放，过程标记不能回放
  assert.equal(payload.findings['协议'], 'HTTP')
  assert.equal(payload.findings['目的端口'], 443)
  assert.equal(payload.findings['reused_from'], 'task-old')
  assert.equal(payload.findings['triaged_by'], undefined, '初筛标记不能漂到复用行')
  assert.notEqual(payload.findings['reused_at'], 'stale', '上次的复用时戳要被这次的覆盖')
  assert.deepEqual(payload.anchors, [
    { kind: 'ip', value: '10.0.0.9' },
    { kind: 'host', value: 'www.example.com' },
  ])
  assert.equal(payload.recommendation, '复核这台机器的 443 出站')
})

test('B2: remember keeps findings/anchors/recommendation for later replay', async () => {
  const rec = recorder()
  const store = new MemoryStateStore()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({
      state: 'done',
      results: [
        {
          verdict: 'true_positive',
          terminal_reason: 'concluded',
          confidence: 0.8,
          summary: '确认扫描',
          findings: { 目的端口: 22, triaged_by: 'light', reused_at: 'x', reused_from: 'old' },
          anchors: [{ kind: 'ip', value: '10.0.0.9' }],
          recommendation: '封禁源地址',
        },
      ],
    })),
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 86_400_000,
  })
  const outcome = await analyst.run(reusable)
  assert.equal(outcome.completed, true)
  const key = taskResultKey(reusable)
  assert.ok(key !== null)
  const saved = await store.load(key)
  assert.equal((saved?.findings ?? {})['目的端口'], 22)
  assert.equal((saved?.findings ?? {})['triaged_by'], undefined)
  assert.equal((saved?.findings ?? {})['reused_at'], undefined)
  assert.equal((saved?.findings ?? {})['reused_from'], undefined)
  assert.deepEqual(saved?.anchors, [{ kind: 'ip', value: '10.0.0.9' }])
  assert.equal(saved?.recommendation, '封禁源地址')
})

test('reuse stats: rejections and missing identity are counted', async () => {
  // 缺身份：任务没有 NDR 下发的 reuse_identity → 跳过复用并计数
  const rec = recorder()
  const store = new MemoryStateStore()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 86_400_000,
  })
  await analyst.run({ ...task, hint: { 事实: 'x' }, feature: 'conn_count' })
  assert.equal(analyst.reuseStats.identityMissing, 1)

  // 有记录但已过期 → 计入拒绝
  const rec2 = recorder()
  const store2 = new MemoryStateStore()
  const key = await seed(store2, 'benign')
  const saved = await store2.load(key)
  assert.ok(saved !== null)
  await store2.save({
    ...saved,
    analyzedAt: new Date(Date.now() - 2 * 86_400_000).toISOString(),
    expiresAt: new Date(Date.now() - 86_400_000).toISOString(),
  })
  const analyst2 = new Analyst({
    agents: fakeAgents(rec2, async () => undefined),
    ndr: fakeNdr(rec2, () => ({ state: 'done' })),
    timeoutMs: 1000,
    taskResults: store2,
    taskReuseTtlMs: 86_400_000,
  })
  await analyst2.run(reusable)
  assert.equal(analyst2.reuseStats.rejected, 1)
})

test('suspicious conclusions are never reused', async () => {
  const rec = recorder()
  const store = new MemoryStateStore()
  await seed(store, 'suspicious')
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done', results: [{ verdict: 'suspicious', terminal_reason: 'concluded' }] })),
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 86_400_000,
  })
  const outcome = await analyst.run(reusable)
  assert.equal(outcome.reused, undefined)
  assert.equal(rec.prompts.length, 1, '可疑必须重查')
  assert.equal(rec.completed.length, 0)
})

test('a stronger signal forces re-analysis', async () => {
  const rec = recorder()
  const store = new MemoryStateStore()
  await seed(store, 'benign', 0.1)
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done', results: [{ verdict: 'benign', terminal_reason: 'concluded' }] })),
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 86_400_000,
    taskReuseStrengthDelta: 0.15,
  })
  await analyst.run(reusable)
  assert.equal(rec.prompts.length, 1, '强度从 0.1 涨到 0.6，旧结论不够用')
})

test('a completed analysis is stored for the next occurrence', async () => {
  const rec = recorder()
  const store = new MemoryStateStore()
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({
      state: 'done',
      results: [{ verdict: 'benign', terminal_reason: 'concluded', confidence: 0.8, summary: '正常业务' }],
    })),
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 86_400_000,
  })
  const outcome = await analyst.run(reusable)
  assert.equal(outcome.completed, true)
  const key = taskResultKey(reusable)
  assert.ok(key !== null)
  const saved = await store.load(key)
  assert.equal(saved?.verdict, 'benign')
  assert.equal(saved?.confidence, 0.8)
  assert.equal(saved?.summary, '正常业务')
  assert.equal(saved?.occurrences, 1)
  assert.equal(analyst.reuseStats.stored, 1)
})

/**
 * 抑制记忆：被精准抑制的现象**不起会话**。
 *
 * 闭环的另一半：NDR 侧拦派工（不按门铃），智能体侧记一份"这类现象不用再看"，
 * 同一现象从别的线索类型再冒出来时直接跳过 —— 省一次模型会话与一轮取数。
 */
test('命中抑制记忆：不起会话、不取数，直接交回', async () => {
  const rec = recorder()
  const store = new MemoryStateStore()
  const identity = { kind: 'hit', subjectKind: 'ip', subject: '10.0.0.5', feature: 'sid:1' }
  await store.recordTaskSeen({ ...identity, taskId: 'task-old', verdict: 'false_positive' })
  await store.markSuppressed('task-old', '已知扫描器噪声')

  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    taskSeen: store,
  })
  const outcome = await analyst.run({
    ...task,
    kind: 'hit',
    feature: 'sid:1',
  })
  assert.equal(outcome.completed, true)
  assert.equal(rec.prompts.length, 0, '不该起分析会话')
  assert.equal(rec.completed.length, 1)
  assert.equal(rec.completed[0]?.verdict, 'false_positive')
  assert.match(String(rec.completed[0]?.summary), /已知扫描器噪声/)
})

test('没有被抑制的现象照常分析（抑制记忆不误伤）', async () => {
  const rec = recorder()
  const store = new MemoryStateStore()
  await store.recordTaskSeen({
    kind: 'hit', subjectKind: 'ip', subject: '10.0.0.5', feature: 'sid:1',
    taskId: 'task-old', verdict: 'false_positive',
  })
  await store.markSuppressed('task-old', '别的现象')

  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done', results: [{ verdict: 'benign', summary: '正常' }] })),
    timeoutMs: 1000,
    taskSeen: store,
  })
  const outcome = await analyst.run({ ...task, kind: 'hit', feature: 'sid:2' })
  assert.equal(outcome.completed, true)
  assert.equal(rec.prompts.length, 1, '不同现象照常起会话')
})

/**
 * 过程索引 + 结论留档：控制台「分析过程 / 分析记录」的数据来源。
 *
 * 正常分析：过程 running → done，结论留档一条；
 * 复用命中：过程 reused（没有会话），结论留档标 reused + 来源任务。
 */
test('正常分析：过程索引 running→done，结论留档', async () => {
  const rec = recorder()
  const store = new MemoryStateStore('PROJ1')
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({
      state: 'done',
      result_id: 'res-1',
      results: [{
        verdict: 'benign', confidence: 0.9, summary: '正常业务', tools_used: 7,
        duration_ms: 1234, terminal_reason: 'concluded', findings: { a: 1 },
        evidence_refs: ['es:idx/1'],
      }],
    })),
    timeoutMs: 1000,
    process: store,
    conclusions: store,
    projectId: 'PROJ1',
  })
  const outcome = await analyst.run({ ...task, id: 'task-9' })
  assert.equal(outcome.completed, true)
  const proc = await store.getProcess('task-9')
  assert.equal(proc?.outcome, 'done')
  assert.ok(proc?.sessionId.startsWith('xdr-analysis-task-9-'), '要记下会话 ID（过程页靠它读时间线）')
  const conclusion = await store.getConclusion('res-1')
  assert.equal(conclusion?.verdict, 'benign')
  assert.deepEqual(conclusion?.evidenceRefs, ['es:idx/1'])
  assert.equal(conclusion?.reused, false)
})

test('复用命中：过程 reused、结论留档标 reused 与来源任务', async () => {
  const rec = recorder()
  const store = new MemoryStateStore('PROJ1')
  const identity = { kind: task.kind, subjectKind: task.subject_kind, subject: task.subject, feature: 'f1' }
  await store.save({
    key: taskResultKey({ ...task, feature: 'f1' }) ?? '',
    kind: identity.kind, subjectKind: identity.subjectKind, subject: identity.subject,
    feature: 'f1', taskId: 'task-old', verdict: 'benign', terminalReason: 'concluded',
    confidence: 0.8, summary: '旧结论', strength: 1, occurrences: 1,
    analyzedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  })
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 3_600_000,
    taskReuseStrengthDelta: 0.15,
    process: store,
    conclusions: store,
    projectId: 'PROJ1',
  })
  const outcome = await analyst.run({ ...task, id: 'task-reuse', feature: 'f1' })
  assert.equal(outcome.reused, true)
  assert.equal(rec.prompts.length, 0, '复用不该起会话')
  const proc = await store.getProcess('task-reuse')
  assert.equal(proc?.outcome, 'reused')
  const page = await store.listConclusions({ limit: 10, offset: 0, search: 'task-reuse' })
  // 结论 ID 是合成键（复用没有 NDR result_id）：projectId:taskId
  const conclusion = await store.getConclusion('PROJ1:task-reuse')
  assert.equal(conclusion?.reused, true)
  assert.equal(conclusion?.reusedFrom, 'task-old')
  assert.ok(page.total >= 0)
})

/* ---------------- 轻量初筛闸门（低阶模型） ---------------- */

function stubTriage(results: TriageResult[]): { port: LightTriagePort, calls: ClaimedTask[] } {
  const queue = [...results]
  const calls: ClaimedTask[] = []
  return {
    calls,
    port: {
      async triage(t: ClaimedTask): Promise<TriageResult> {
        calls.push(t)
        return queue.shift() ?? { kind: 'escalate', reason: 'disabled', ms: 0 }
      },
    },
  }
}

test('初筛关单：不起会话、直接交回、过程 triaged、结论不写复用库', async () => {
  const rec = recorder()
  const store = new MemoryStateStore('PROJ1')
  const triage = stubTriage([{
    kind: 'closed', verdict: 'false_positive', confidence: 0.93,
    summary: '组播保留地址误报', model: 'qwen-2b', ms: 1200,
  }])
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    taskResults: store,
    taskReuseTtlMs: 3_600_000,
    process: store,
    conclusions: store,
    projectId: 'PROJ1',
    lightTriage: triage.port,
  })
  const outcome = await analyst.run({ ...task, id: 'task-light' })
  assert.equal(outcome.completed, true)
  assert.equal(outcome.triaged, true)
  assert.equal(triage.calls.length, 1)
  assert.equal(rec.prompts.length, 0, '初筛关单不该起付费会话')
  assert.equal(rec.completed.length, 1)
  assert.match(rec.completed[0]?.summary ?? '', /轻量初筛/u)
  assert.equal(rec.completed[0]?.findings['triaged_by'], 'light')
  assert.equal(rec.completed[0]?.tools_used, 0, '没取证就如实记 0')
  const proc = await store.getProcess('task-light')
  assert.equal(proc?.outcome, 'triaged')
  assert.equal(proc?.model, 'light:qwen-2b')
  assert.equal(proc?.verdict, 'false_positive')
  const conclusion = await store.getConclusion('PROJ1:task-light')
  assert.equal((conclusion?.findings as Record<string, unknown>)['triaged_by'], 'light')
  // 初筛结论不写复用库：同类第二条必须重新分析，而不是"复用"初筛那条
  const second = await analyst.run({ ...task, id: 'task-light-2' })
  assert.equal(second.reused, undefined, '初筛结论绝不写复用库（防小模型结论被放大）')
})

test('初筛拿不准/升级 → 照常起付费会话（fail-open）', async () => {
  const rec = recorder()
  const store = new MemoryStateStore('PROJ1')
  const triage = stubTriage([{
    kind: 'escalate', reason: 'uncertain', ms: 40,
    preview: { verdict: 'inconclusive', confidence: 0.4, model: 'qwen-2b' },
  }])
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr: fakeNdr(rec, () => ({ state: 'done' })),
    timeoutMs: 1000,
    taskResults: store,
    process: store,
    projectId: 'PROJ1',
    lightTriage: triage.port,
  })
  const outcome = await analyst.run({ ...task, id: 'task-escalate' })
  assert.equal(outcome.triaged, undefined)
  assert.equal(outcome.completed, true)
  assert.equal(rec.prompts.length, 1, '初筛不收就必须升级付费会话')
})

test('初筛交回失败 → 回退付费会话（不许当完成）', async () => {
  const rec = recorder()
  const ndr: NdrTaskPort = {
    async claimTasks() { return { tasks: [] } },
    async taskState() { return { state: 'claimed' } },
    async completeTask() { return { ok: false, error: '交回失败' } },
    async deferTask(id, reason) { rec.deferred.push({ id, reason }) },
  }
  const triage = stubTriage([{
    kind: 'closed', verdict: 'benign', confidence: 0.9,
    summary: '看着正常', model: 'qwen-2b', ms: 900,
  }])
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr,
    timeoutMs: 1000,
    lightTriage: triage.port,
  })
  const outcome = await analyst.run({ ...task, id: 'task-failopen' })
  assert.equal(outcome.completed, false)
  assert.equal(outcome.deferred, true)
  assert.equal(rec.prompts.length, 1, '交回没成功就必须落回付费会话')
})

test('初筛抽检：仍走付费复核，结论带 light_audit、过程留痕', async () => {
  const rec = recorder()
  const store = new MemoryStateStore('PROJ1')
  const triage = stubTriage([{
    kind: 'escalate', reason: 'audit_sample', ms: 800,
    preview: { verdict: 'benign', confidence: 0.92, model: 'qwen-2b' },
  }])
  const ndr: NdrTaskPort = {
    async claimTasks() { return { tasks: [] } },
    async taskState() {
      return {
        state: 'done',
        result_id: 'res-9',
        results: [{ verdict: 'suspicious', terminal_reason: 'concluded', confidence: 0.8, summary: '付费结论：可疑' }],
      }
    },
    async completeTask(id, payload) {
      rec.completed.push(payload)
      return { ok: true, task_state: 'done', task_id: id }
    },
    async deferTask() {},
  }
  const analyst = new Analyst({
    agents: fakeAgents(rec, async () => undefined),
    ndr,
    timeoutMs: 1000,
    process: store,
    conclusions: store,
    projectId: 'PROJ1',
    lightTriage: triage.port,
  })
  const outcome = await analyst.run({ ...task, id: 'task-audit' })
  assert.equal(outcome.completed, true)
  assert.equal(rec.prompts.length, 1, '抽检样本必须真送付费复核')
  const conclusion = await store.getConclusion('res-9')
  const findings = conclusion?.findings as Record<string, unknown>
  const audit = findings['light_audit'] as { verdict: string, confidence: number, model: string }
  assert.equal(audit.verdict, 'benign')
  assert.equal(audit.confidence, 0.92)
  assert.equal(conclusion?.verdict, 'suspicious', '最终判定仍以付费模型为准')
  const proc = await store.getProcess('task-audit')
  assert.match(proc?.note ?? '', /抽检复核/u)
  assert.match(proc?.note ?? '', /初筛判 benign/u)
})
