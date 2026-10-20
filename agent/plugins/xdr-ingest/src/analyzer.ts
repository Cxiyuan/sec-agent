/**
 * 启发式分诊 v0：不调模型的确定性判断，回答「这是什么类型的活动、多严重、
 * 先做什么」。P1 换成 LLM 分析器时保持同签名替换，缓存结构不受影响。
 */

import type { EventIdentity, NdrDigest, TriageResult } from './types.ts'

/** NDR rule_severity 到统一档位的宽松映射；识别不了按 medium。 */
function normalizeSeverity(raw: unknown): TriageResult['severity'] {
  const value = String(raw ?? '').trim().toLowerCase()
  if (value === 'critical' || value === '4' || value === '严重') return 'critical'
  if (value === 'high' || value === '3' || value === '高') return 'high'
  if (value === 'medium' || value === '2' || value === '中') return 'medium'
  if (value === 'low' || value === '1' || value === '低') return 'low'
  if (value === 'info' || value === '0' || value === '信息') return 'info'
  return 'medium'
}

interface RuleHint {
  readonly pattern: RegExp
  readonly category: string
  readonly severity: TriageResult['severity']
  readonly recommendation: string
}

/** 规则名关键词 → 分类。顺序即优先级，首个命中生效。 */
const RULE_HINTS: readonly RuleHint[] = [
  {
    pattern: /sql\s*inject|sqlmap|xss|webshell|csrf|命令注入|web.?attack/iu,
    category: 'web-attack',
    severity: 'high',
    recommendation: '检查目标 Web 服务的访问日志与 WAF 记录，确认是否存在成功的注入或上传。',
  },
  {
    pattern: /brute|ssh|rdp|smb|爆破|口令|credential/iu,
    category: 'credential-access',
    severity: 'high',
    recommendation: '核对该源 IP 的认证失败/成功序列，确认是否已爆破成功，必要时封禁并重置相关凭据。',
  },
  {
    pattern: /c2|beacon|tor|挖矿|mining|crypto|隧道|tunnel/iu,
    category: 'c2-suspicion',
    severity: 'critical',
    recommendation: '确认内网主机是否外连可疑基础设施，结合会话取证判断是否已失陷，准备隔离预案。',
  },
  {
    pattern: /scan|探测|recon|sweep/iu,
    category: 'recon-scan',
    severity: 'low',
    recommendation: '观察扫描范围是否扩大；持续多窗口出现时升级关注并考虑边界封禁。',
  },
]

function hitsHint(identity: EventIdentity, pattern: RegExp): boolean {
  if (pattern.test(identity.rule)) return true
  return identity.eventTypes.some(eventType => pattern.test(eventType))
}

/**
 * 端口广度优先于规则关键词：同一源在低窗口内打出大量不同端口，即使规则名
 * 没带 scan 字样也是扫描行为的强信号。
 */
const WIDE_PORT_THRESHOLD = 10

export function triageDigest(identity: EventIdentity, digest: NdrDigest): TriageResult {
  const portCount = identity.dstPorts.length
  const baseSeverity = normalizeSeverity(digest.rule_severity)
  const dstHead = identity.dstIps.slice(0, 3).join(', ')
  const scope = `规则「${identity.rule || '未命名'}」，源 ${identity.srcIp || '未知'}` +
    (dstHead ? `，目标 ${dstHead}${identity.dstIps.length > 3 ? ' 等' : ''}` : '')

  if (portCount >= WIDE_PORT_THRESHOLD) {
    return {
      category: 'recon-scan',
      severity: baseSeverity === 'critical' ? 'critical' : 'medium',
      summary: `${scope}：单窗口触及 ${portCount} 个不同端口，呈端口扫描特征。`,
      recommendation: '确认扫描是否在多窗口持续；对确认为攻击源的 IP 评估边界封禁。',
      analyzer: 'heuristic-v0',
    }
  }

  for (const hint of RULE_HINTS) {
    if (hitsHint(identity, hint.pattern)) {
      const severity = rankSeverity(hint.severity, baseSeverity)
      return {
        category: hint.category,
        severity,
        summary: `${scope}：命中「${hint.category}」特征。`,
        recommendation: hint.recommendation,
        analyzer: 'heuristic-v0',
      }
    }
  }

  const eventType = identity.eventTypes[0]
  return {
    category: eventType ? `generic:${eventType}` : 'generic-alert',
    severity: baseSeverity,
    summary: `${scope}：常规告警${eventType ? `（类型 ${eventType}）` : ''}，无更强分类特征。`,
    recommendation: '按规则语义人工复核；若同类事件反复出现，考虑为其补充专用检测规则。',
    analyzer: 'heuristic-v0',
  }
}

/** 分类信号与规则配置各说一个严重档时，取更高者（告警从严）。 */
function rankSeverity(a: TriageResult['severity'], b: TriageResult['severity']): TriageResult['severity'] {
  const order: readonly TriageResult['severity'][] = ['info', 'low', 'medium', 'high', 'critical']
  return order.indexOf(a) >= order.indexOf(b) ? a : b
}
