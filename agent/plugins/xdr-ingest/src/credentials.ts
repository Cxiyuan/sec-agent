/**
 * 从 dsh credentials 服务/同名环境变量解析网关池 Key。
 *
 * 摘要闸门直接走 LLM-AGG 的 /v1，不能用 xdr-llm-agg 内部已经解析好的 Key；
 * 这里复用 dsh 的凭据服务，避免把密钥复制到 xdr-ingest 的设置表里。
 */

interface CredentialHit {
  readonly value?: unknown
}

interface CredentialsServiceLike {
  resolve(ref: string): Promise<CredentialHit | undefined>
}

export function llmAggApiKeyResolver(
  context: unknown,
  ref = 'LLM_AGG_API_KEY',
): () => Promise<string | undefined> {
  return async () => {
    let credentials: CredentialsServiceLike | undefined
    try {
      const get = (context as { get?: (name: string) => unknown } | null)?.get
      const candidate = typeof get === 'function' ? get.call(context, 'credentials') : undefined
      if (typeof candidate === 'object' && candidate !== null
        && typeof (candidate as CredentialsServiceLike).resolve === 'function') {
        credentials = candidate as CredentialsServiceLike
      }
    } catch {
      credentials = undefined
    }
    if (credentials !== undefined) {
      try {
        const hit = await credentials.resolve(ref)
        const value = typeof hit?.value === 'string' ? hit.value : ''
        if (value.trim() !== '') return value.trim()
      } catch {
        // 凭据服务晚于插件激活/暂不可用：回落到同名环境变量。
      }
    }
    const fromEnv = process.env[ref]
    return fromEnv !== undefined && fromEnv.trim() !== '' ? fromEnv.trim() : undefined
  }
}
