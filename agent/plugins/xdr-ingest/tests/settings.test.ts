/** 运行参数：校验/合并语义与两条存储实现（内存 + PG 语义对齐）。 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { MemoryColdStore } from '../src/store.ts'
import { DEFAULT_LIGHT_TRIAGE, mergeSettings, SETTING_LIMITS, settingsView } from '../src/settings.ts'
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
  assert.deepEqual(settingsView(CURRENT), { poll_seconds: 900, max_concurrent: 2, claim_limit: 2, light_enabled: 0 })
})

/* ---------- 轻量初筛（低阶模型）配置 ---------- */

test('默认初筛只关 coverage（A3 整改）：novelty/observation 等 2B 小模型无权关单', () => {
  assert.deepEqual([...DEFAULT_LIGHT_TRIAGE.kinds].sort(), ['coverage'])
})

test('mergeSettings.light：补丁只带部分字段时先合并当前值再校验（不冲掉端点/模型）', () => {
  const merged = mergeSettings(CURRENT, {
    light: {
      enabled: true,
      baseUrl: 'http://192.168.1.10:8080/v1',
      model: 'Qwen3.5-2B-Q4_K_M',
      threshold: 0.9,
    },
  })
  assert.ok('settings' in merged)
  assert.equal(merged.settings.light?.enabled, true)
  assert.equal(merged.settings.light?.threshold, 0.9)
  assert.equal(merged.settings.light?.auditRate, DEFAULT_LIGHT_TRIAGE.auditRate, '没传的字段保留默认')

  // 只改阈值：端点/模型不动
  const again = mergeSettings(merged.settings, { light: { threshold: 0.7 } })
  assert.ok('settings' in again)
  assert.equal(again.settings.light?.threshold, 0.7)
  assert.equal(again.settings.light?.baseUrl, 'http://192.168.1.10:8080/v1')
  assert.equal(again.settings.light?.model, 'Qwen3.5-2B-Q4_K_M')
})

test('mergeSettings.light：启用必须有地址和模型（缺了等于每条任务都白白升级付费）', () => {
  const off = mergeSettings(CURRENT, { light: { enabled: false } })
  assert.ok('settings' in off)
  assert.equal(off.settings.light?.enabled, false)

  for (const patch of [
    { light: { enabled: true } },
    { light: { enabled: true, baseUrl: 'http://x:8080/v1' } },
  ]) {
    const merged = mergeSettings(CURRENT, patch)
    assert.ok('error' in merged, JSON.stringify(patch))
  }
})

test('mergeSettings.light：阈值/抽检率越界、地址不是 URL、种类名非法都报错', () => {
  const base = { enabled: false, baseUrl: 'http://x:8080/v1', model: 'm' }
  for (const light of [
    { ...base, threshold: 1.2 },
    { ...base, threshold: -0.1 },
    { ...base, auditRate: 2 },
    { ...base, baseUrl: 'ftp://x/v1' },
    { ...base, baseUrl: '不是地址' },
    { ...base, kinds: ['novelty', 'BAD KIND!'] },
    { ...base, kinds: 'novelty' },
    { ...base, timeoutMs: 5 },
    { ...base, enabled: 'yes' },
  ]) {
    const merged = mergeSettings(CURRENT, { light })
    assert.ok('error' in merged, `应当报错：${JSON.stringify(light)}`)
    assert.ok(typeof merged.error === 'string' && merged.error !== '')
  }
})

test('settingsView：初筛开关反映在 light_enabled', () => {
  const merged = mergeSettings(CURRENT, {
    light: { enabled: true, baseUrl: 'http://x:8080/v1', model: 'm' },
  })
  assert.ok('settings' in merged)
  assert.equal(settingsView(merged.settings).light_enabled, 1)
})

test('内存冷库保存运行参数：返回副本，读回不受后续修改影响', async () => {
  const store = new MemoryColdStore()
  assert.equal(await store.loadSettings(), null)
  const saved: RuntimeSettings = { pollSeconds: 300, maxConcurrent: 3, claimLimit: 4 }
  assert.equal(await store.saveSettings(saved), true)
  assert.deepEqual(await store.loadSettings(), saved)
})
