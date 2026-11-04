/**
 * 分析端动态 RDAP/WHOIS（不走 NDR MCP）。
 *
 * 为什么放 Agent：
 * - 域名注册信息是分析取证，不是 NDR 数据面的能力；
 * - NDR 常常没有外网 DNS/443，Agent 所在分析机才按需出网；
 * - 归属查询失败必须 fail-closed（返回 unknown），不能据此编造恶意。
 */

import { defineTool } from '@deepseek-ai/dsh-tools'

const CACHE_TTL_MS = 60 * 60 * 1000
const TIMEOUT_MS = 6_000
const MULTI_SUFFIXES = new Set([
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'co.uk', 'org.uk', 'ac.uk', 'co.jp', 'com.au', 'net.au',
  'com.hk', 'com.tw', 'com.sg', 'com.br', 'co.kr',
])

interface RdapCacheEntry {
  readonly expiresAt: number
  readonly value: Record<string, unknown>
}

const cache = new Map<string, RdapCacheEntry>()

export function normalizeDomain(value: unknown): string {
  let text = String(value ?? '').trim().replace(/^["']|["']$/g, '')
  if (text === '') return ''
  if (text.includes('://')) {
    try {
      text = new URL(text).hostname
    } catch {
      return ''
    }
  } else {
    text = text.split('/', 1)[0] ?? ''
  }
  return text.trim().replace(/\.$/u, '').replace(/:\d+$/u, '').toLowerCase()
}

export function registrableDomain(domain: string): string {
  const labels = normalizeDomain(domain).split('.').filter(Boolean)
  if (labels.length <= 2) return labels.join('.')
  const lastTwo = labels.slice(-2).join('.')
  if (MULTI_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.')
  return lastTwo
}

function entityName(entities: unknown): string {
  if (!Array.isArray(entities)) return ''
  for (const entity of entities) {
    if (typeof entity !== 'object' || entity === null) continue
    const row = entity as Record<string, unknown>
    const vcard = row['vcardArray']
    if (Array.isArray(vcard) && vcard.length >= 2 && Array.isArray(vcard[1])) {
      for (const item of vcard[1]) {
        if (!Array.isArray(item) || item.length < 4) continue
        const key = String(item[0] ?? '').toLowerCase()
        if (key !== 'fn' && key !== 'org') continue
        const value = item[3]
        const text = Array.isArray(value) ? value.join(' ') : String(value ?? '')
        if (text.trim() !== '') return text.trim()
      }
    }
    const nested = entityName(row['entities'])
    if (nested !== '') return nested
  }
  return ''
}

async function rdapLookup(domain: string): Promise<Record<string, unknown>> {
  const reg = registrableDomain(domain)
  if (reg === '') return { ok: false, error: '域名不合法', domain }
  const cached = cache.get(reg)
  if (cached !== undefined && cached.expiresAt > Date.now()) return cached.value

  const url = `https://rdap.org/domain/${encodeURIComponent(reg)}`
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const response = await fetch(url, {
      headers: { accept: 'application/rdap+json, application/json', 'user-agent': 'shentong-agent/rdap' },
      signal: controller.signal,
      redirect: 'follow',
    })
    if (!response.ok) {
      const value = {
        ok: false,
        domain,
        registrable_domain: reg,
        rdap_url: url,
        http_status: response.status,
        error: `RDAP HTTP ${response.status}`,
      }
      cache.set(reg, { expiresAt: Date.now() + 5 * 60_000, value })
      return value
    }
    const payload: unknown = await response.json()
    const root = typeof payload === 'object' && payload !== null
      ? payload as Record<string, unknown>
      : {}
    const registrant = entityName(root['entities'])
    const value = {
      ok: true,
      domain,
      registrable_domain: reg,
      registrant,
      handle: String(root['handle'] ?? ''),
      rdap_url: url,
      source: 'rdap',
      note: registrant === ''
        ? 'RDAP 返回了对象但没有可读注册人；不要据此判恶意。'
        : '注册人只说明归属，不说明用途；仍需结合 qtype/频次/回包判断。',
    }
    cache.set(reg, { expiresAt: Date.now() + CACHE_TTL_MS, value })
    return value
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const value = {
      ok: false,
      domain,
      registrable_domain: reg,
      rdap_url: url,
      error: `RDAP 查询失败：${message.slice(0, 200)}`,
      note: '失败不是“恶意”证据；保持 unknown/suspicious，继续用 DNS/流量证据判断。',
    }
    // 失败只短缓存，避免每个任务重复打同一个超时。
    cache.set(reg, { expiresAt: Date.now() + 60_000, value })
    return value
  } finally {
    clearTimeout(timer)
  }
}

export function registerRdapTool(ctx: {
  tools?: { register?: (tool: unknown) => unknown }
}): unknown {
  if (typeof ctx.tools?.register !== 'function') return undefined
  return ctx.tools.register(defineTool({
    name: 'rdap_lookup',
    description:
      '查询域名注册人/归属（RDAP，必要时可再查 WHOIS 服务）。'
      + '用于未知域名、DNS 隧道和长随机子域分析：注册人只能说明归属，不能单独证明恶意或良性。'
      + 'RDAP 失败时返回 unknown，不要编造，也不要据此下 TP。',
    parameters: {
      domain: {
        type: 'string',
        required: true,
        description: '域名或完整 DNS 查询名，例如 tfogc.com 或 aafd...v.smtcdns.com',
      },
    },
    output: {
      schema: { type: 'string' as const },
      render: (_args, value) => [{ type: 'text' as const, text: value }],
    },
    async execute(args: Record<string, unknown>) {
      const domain = normalizeDomain(args['domain'])
      if (domain === '') return JSON.stringify({ ok: false, error: 'domain 必填' })
      return JSON.stringify(await rdapLookup(domain))
    },
  }))
}
