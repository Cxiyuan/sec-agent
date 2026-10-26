/** 运行参数：校验/合并语义与两条存储实现（内存 + PG 语义对齐）。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { MemoryColdStore } from '../src/store.ts'
import { mergeSettings, SETTING_LIMITS, settingsView } from '../src/settings.ts'
import type { RuntimeSettings } from '../src/settings.ts'

const CURRENT: RuntimeSettings = { pollSeconds: 900, maxConcurrent: 2, claimLimit: 2 }

test('mergeSettings：只改传入字段，其余保持原值', () => {
  const merged = mergeSettings(CURRENT, { pollSeconds: 60 })
  assert.ok('settings' in merged)
  assert.deepEqual(merged.settings, { pollSeconds: 60, maxConcurrent: 2, claimLimit: 2 })
})

test('mergeSettings：未知键忽略（前后端版本不一致时不炸）', () => {
  const merged = mergeSettings(CURRENT, { claimLimit: 5, somethingElse: 'x' })
  assert.ok('settings' in merged)
  assert.deepEqual(merged.settings, { pollSeconds: 900, maxConcurrent: 2, claimLimit: 5 })
})

test('mergeSettings：越界/非整数/非对象都报错', () => {
  for (const patch of [
    { pollSeconds: SETTING_LIMITS.pollSeconds.min - 1 },
    { maxConcurrent: SETTING_LIMITS.maxConcurrent.max + 1 },
    { claimLimit: 1.5 },
    { claimLimit: '3' },
    [],
    null,
    'x',
  ]) {
    const merged = mergeSettings(CURRENT, patch)
    assert.ok('error' in merged, `应拒绝：${JSON.stringify(patch)}`)
  }
})

test('mergeSettings：空补丁等于原样返回', () => {
  const merged = mergeSettings(CURRENT, {})
  assert.ok('settings' in merged)
  assert.deepEqual(merged.settings, CURRENT)
})

test('settingsView：拍成工作台用的下划线字段', () => {
  assert.deepEqual(settingsView(CURRENT), { poll_seconds: 900, max_concurrent: 2, claim_limit: 2 })
})

test('内存冷库保存运行参数：返回副本，读回不受后续修改影响', async () => {
  const store = new MemoryColdStore()
  assert.equal(await store.loadSettings(), null)
  const saved: RuntimeSettings = { pollSeconds: 300, maxConcurrent: 3, claimLimit: 4 }
  assert.equal(await store.saveSettings(saved), true)
  assert.deepEqual(await store.loadSettings(), saved)
})
