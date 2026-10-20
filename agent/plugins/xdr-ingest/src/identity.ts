/**
 * 事件分析 ID 生成：从摘要内容元组派生「同类事件」的稳定标识。
 *
 * 指标选择与 NDR 摘要指纹（ndr/backend/app/detector/fingerprint.py）保持同一套
 * 内容元组，但**去掉时间桶**，且规范化规则逐字节对齐 NDR 的字符串排序，使两者
 * 只差时间桶一段——日志里并排可见、便于对照排查：
 *
 *   NDR 指纹   = sha256("{rule}|{src}|{桶起点}|{dsts}|{ports}|{etypes}")[:32]
 *   事件分析ID = "EA-" + sha256("{rule}|{src}|{dsts}|{ports}|{etypes}")[:32]
 *
 * 排除的易变字段：count、first_seen/last_seen、samples、real_client_ips（XFF
 * 随客户端变化）、proxied/conn_states（随流量路径翻转）、rule_severity（规则
 * 配置调整即变）——它们进不了身份元组，但都会存进分析记录供分析器使用。
 */

import { createHash } from 'node:crypto'
import type { EventIdentity, NdrDigest } from './types.ts'

/** 与 NDR 指纹一致的上限：超出的目标/端口/类型不参与身份。 */
const MAX_DSTS = 20
const MAX_PORTS = 20
const MAX_EVENT_TYPES = 10

/** 事件分析 ID 前缀：日志/UI 里与 NDR 指纹一眼区分。 */
export const ANALYSIS_ID_PREFIX = 'EA-'

function normalizeIp(value: unknown): string {
  return String(value ?? '').trim().toLowerCase()
}

function toSortedUniqueStrings(values: readonly unknown[] | undefined, cap: number): string[] {
  const seen = new Set<string>()
  for (const value of values ?? []) {
    if (value === null || value === undefined) continue
    const raw = String(value).trim()
    if (raw !== '') seen.add(raw.toLowerCase())
    if (seen.size >= cap) break
  }
  // 逐字节对齐 NDR 的 sorted(str(x))：字典序，保证两侧可复算对照。
  return [...seen].sort()
}

/**
 * 从摘要规范化出事件身份。`rule` 与 `src_ip` 都缺失时返回 null——这样的摘要
 * 没有任何可判身份的内容，调用方应拒绝并计数，而不是给它一个恒同的 ID。
 */
export function normalizeDigest(digest: NdrDigest): EventIdentity | null {
  const rule = String(digest.rule ?? '').trim()
  const srcIp = normalizeIp(digest.src_ip)
  const dstIps = toSortedUniqueStrings(digest.dst_ips, MAX_DSTS)
  const dstPorts = toSortedUniqueStrings(digest.dst_ports, MAX_PORTS)
  const eventTypes = toSortedUniqueStrings(digest.event_types, MAX_EVENT_TYPES)
  if (rule === '' && srcIp === '' && dstIps.length === 0 && eventTypes.length === 0) return null
  return { rule, srcIp, dstIps, dstPorts, eventTypes }
}

/** 身份元组的规范字符串（与 NDR 指纹同格式、缺时间桶段）。 */
export function identityKey(identity: EventIdentity): string {
  return [
    identity.rule,
    identity.srcIp,
    identity.dstIps.join(','),
    identity.dstPorts.join(','),
    identity.eventTypes.join(','),
  ].join('|')
}

/** 事件分析 ID：`EA-` + sha256(身份元组) 前 32 位十六进制。 */
export function analysisIdOf(identity: EventIdentity): string {
  const hash = createHash('sha256').update(identityKey(identity), 'utf8').digest('hex')
  return ANALYSIS_ID_PREFIX + hash.slice(0, 32)
}
