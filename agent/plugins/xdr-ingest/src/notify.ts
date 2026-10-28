/** 告警外发：项目不可用/熔断打开时 POST 一个 JSON 到配置的 webhook（空 = 只写日志）。 */

export interface AlertPayload {
  readonly event: 'project_degraded' | 'project_auth_mismatch' | 'project_unreachable' | 'breaker_open'
  readonly project: string
  readonly message: string
  readonly detail?: Record<string, unknown>
}

export async function sendAlert(url: string, payload: AlertPayload): Promise<void> {
  const target = String(url || '').trim()
  if (target === '') return
  try {
    await fetch(target, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...payload, ts: new Date().toISOString() }),
    })
  } catch (error) {
    // 告警发不出去不能影响分析主流程，但必须在日志里留下
    console.warn('[xdr-ingest] 告警外发失败：', error instanceof Error ? error.message : String(error))
  }
}
