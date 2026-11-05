import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import {
  CORE_NDR_TOOLS,
  planToolGroups,
  TOOL_GROUP_NAMES,
} from '../src/tool-groups.ts'

const prefix = 'mcp__ndr__'

test('planToolGroups 只返回实际存在的工具，并保留按需分组', () => {
  const available = [
    ...CORE_NDR_TOOLS.map(name => `${prefix}${name}`),
    `${prefix}dns_queries`,
    `${prefix}coverage_report`,
    `${prefix}file_content`,
    `${prefix}task_stats`,
    `${prefix}list_suppressions`,
    `${prefix}claim_tasks`,
    `${prefix}new_capability`,
    'schedule_create',
    'session_search',
    'present',
  ]
  const planned = planToolGroups(available)
  assert.ok(planned.core.includes(`${prefix}search_events`))
  assert.ok(planned.core.includes(`${prefix}complete_task`))
  assert.deepEqual(planned.groups.network, [`${prefix}dns_queries`])
  assert.deepEqual(planned.groups.identity, [`${prefix}coverage_report`])
  assert.deepEqual(planned.groups.evidence, [`${prefix}file_content`])
  assert.deepEqual(planned.groups.task, [`${prefix}task_stats`])
  assert.deepEqual(planned.groups.suppression, [`${prefix}list_suppressions`])
  assert.ok(planned.core.includes(`${prefix}submit_suppression`))
  // 会话检索是默认能力（每个任务都要回溯历史），不再藏在 history 组。
  assert.ok(planned.core.includes('session_search'))
  assert.deepEqual(planned.groups.schedule, ['schedule_create'])
  assert.deepEqual(planned.groups.deliverable, ['present'])
  // 未分组的新能力进入 other；claim_tasks 永远不进入可激活组。
  assert.deepEqual(planned.groups.other, [`${prefix}new_capability`])
  assert.ok(!JSON.stringify(planned).includes('claim_tasks'))
})

test('planToolGroups 对缺失工具不报错，也不产生未知名字', () => {
  const planned = planToolGroups([`${prefix}search_events`])
  assert.deepEqual(planned.core, [`${prefix}search_events`])
  assert.deepEqual(planned.groups, {})
})

test('工具组名覆盖加载工具的参数枚举', () => {
  assert.deepEqual(TOOL_GROUP_NAMES, [
    'network', 'identity', 'evidence', 'task', 'suppression', 'schedule', 'deliverable', 'other', 'all',
  ])
})
