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
    `${prefix}claim_tasks`,
    `${prefix}new_capability`,
    'schedule_create',
  ]
  const planned = planToolGroups(available)
  assert.ok(planned.core.includes(`${prefix}search_events`))
  assert.ok(planned.core.includes(`${prefix}complete_task`))
  assert.deepEqual(planned.groups.network, [`${prefix}dns_queries`])
  assert.deepEqual(planned.groups.identity, [`${prefix}coverage_report`])
  assert.deepEqual(planned.groups.evidence, [`${prefix}file_content`])
  assert.deepEqual(planned.groups.task, [`${prefix}task_stats`])
  // 未分组的新能力进入 other；claim_tasks 永远不进入可激活组。
  assert.deepEqual(planned.groups.other, [`${prefix}new_capability`])
  assert.ok(!JSON.stringify(planned).includes('claim_tasks'))
  assert.ok(!JSON.stringify(planned).includes('schedule_create'))
})

test('planToolGroups 对缺失工具不报错，也不产生未知名字', () => {
  const planned = planToolGroups([`${prefix}search_events`])
  assert.deepEqual(planned.core, [`${prefix}search_events`])
  assert.deepEqual(planned.groups, {})
})

test('工具组名覆盖加载工具的参数枚举', () => {
  assert.deepEqual(TOOL_GROUP_NAMES, ['network', 'identity', 'evidence', 'task', 'other', 'all'])
})
