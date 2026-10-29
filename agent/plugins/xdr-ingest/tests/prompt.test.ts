/**
 * 分析提示词（B1/C2/C3，2026-10-29）：主体/方向/对端要进任务块，网段要固定一句。
 *
 * 为什么要钉：任务块是模型唯一的事实入口；`direction`/`principal_asset` 只放在
 * NDR 回执里而不进提示词，模型仍然会自己猜内外方向、把外部对端当资产。
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { buildAnalysisPrompt } from '../src/prompt.ts'

test('prompt carries principal/direction/affected/peers', () => {
  const text = buildAnalysisPrompt({
    id: 'task-1',
    kind: 'hit_cluster',
    strength: 0.62,
    subject_kind: 'asset',
    subject: '10.1.1.20',
    principal_asset: '10.1.1.20',
    direction: 'out→in',
    affected_assets: [{ kind: 'ip', value: '10.1.1.20' }],
    peers: ['1.1.1.1'],
    hint: { 事实: '规则「端口扫描」命中 12 次' },
  })
  assert.match(text, /"principal_asset": "10\.1\.1\.20"/)
  assert.match(text, /"direction": "out→in"/)
  assert.match(text, /"affected_assets": \[\s*\{\s*"kind": "ip",\s*"value": "10\.1\.1\.20"/)
  assert.match(text, /"peers": \[\s*"1\.1\.1\.1"/)
})

test('prompt tells the agent to confirm networks first', () => {
  const text = buildAnalysisPrompt({
    id: 'task-2',
    kind: 'observation',
    strength: 0.5,
    subject_kind: 'asset',
    subject: '10.1.1.20',
  })
  assert.match(text, /监控网段/)
  assert.match(text, /list_networks/)
})

test('prompt states the evidence rule', () => {
  const text = buildAnalysisPrompt({
    id: 'task-3',
    kind: 'novelty',
    strength: 0.4,
    subject_kind: 'asset',
    subject: '10.1.1.30',
  })
  assert.match(text, /evidence_refs/)
  assert.match(text, /本会话/)
})
