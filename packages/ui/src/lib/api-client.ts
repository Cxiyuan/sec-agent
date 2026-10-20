"use client";

const TOKEN_KEY = "shentong_token";
const LOGIN_PATH = "/login";

export function storage(): Storage | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  return storage()?.getItem(TOKEN_KEY) ?? null;
}

export function setToken(token: string) {
  storage()?.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  storage()?.removeItem(TOKEN_KEY);
}

/** 结构化错误响应体（400/409 时后端返回的字段）。 */
export interface ApiErrorBody {
  detail?: string;
  conflict?: string;
  hint?: string;
  truncated?: boolean;
  field_errors?: { field: string; msg: string }[];
  errors?: { row: number; ip?: string; msg: string }[];
  existing?: ConflictExisting;
  holders?: AssetBrief[];
  ips?: string[];
}

/** 结构化 API 错误：body 里带 conflict / field_errors / errors 等，供界面做提示与决策。 */
export class ApiError extends Error {
  status: number;
  body: ApiErrorBody;

  constructor(status: number, body: ApiErrorBody) {
    super(String(body.detail ?? `请求失败 (${status})`));
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/** 把 field_errors / errors 拼成可读文本。 */
export function errorText(body: ApiErrorBody | undefined): string {
  if (!body) return "请求失败";
  if (body.field_errors?.length) {
    return body.field_errors.map((e) => `${e.field}：${e.msg}`).join("；");
  }
  if (body.errors?.length) {
    const head = body.errors
      .slice(0, 5)
      .map((e) => `第${e.row}行 ${e.msg}`)
      .join("；");
    return body.errors.length > 5 ? `${head} …（共 ${body.errors.length} 处）` : head;
  }
  return String(body.detail ?? "请求失败");
}

async function parseError(res: Response): Promise<ApiError> {
  const text = await res.text();
  let body: ApiErrorBody;
  try {
    body = JSON.parse(text) as ApiErrorBody;
  } catch {
    body = { detail: text };
  }
  return new ApiError(res.status, body);
}

export interface ApiFetchOptions {
  /**
   * 401 时是否强制跳回登录页。默认 true（动作请求：改配置、删资产等，失效就该重新登录）。
   *
   * 传 false 用于**页头 / 侧栏的被动轮询**（/api/auth/me、运行状态、推送状态）：
   * 这类请求在每个页面挂载时都会自动发出，一旦令牌刚好过期，默认行为会在
   * 用户点菜单切换页面的瞬间把整页 `location.replace('/login')` —— 表现出来就是
   * 「菜单点了跳不过去」。被动读只应静默失败，把跳转留给用户真正发起的动作请求。
   */
  redirectOn401?: boolean;
}

export async function apiFetch<T = unknown>(
  path: string,
  options: RequestInit = {},
  apiOpts: ApiFetchOptions = {}
): Promise<T> {
  const token = getToken();
  const headers = new Headers({ "Content-Type": "application/json" });
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const extra = options.headers as Record<string, string> | undefined;
  if (extra) {
    for (const [k, v] of Object.entries(extra)) headers.set(k, v);
  }

  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    // 被动读：不清令牌、不跳转，只把失败交给调用方（调用方一般 catch 掉）
    if (apiOpts.redirectOn401 === false) {
      throw new ApiError(401, { detail: "未登录或凭证失效" });
    }
    clearToken();
    redirectToLogin();
    throw new ApiError(401, { detail: "未登录或凭证失效" });
  }
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as T;
}

/** 带认证的文件上传（multipart，不设 Content-Type，由浏览器补边界）。 */
export async function apiUpload<T = unknown>(path: string, form: FormData): Promise<T> {
  const token = getToken();
  const res = await fetch(path, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: form,
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as T;
}

/** 跳回登录页（仅内部固定路径；用 replace 避免历史堆积）。 */
function redirectToLogin() {
  const loc = globalThis.location as Location | undefined;
  if (!loc || loc.pathname.startsWith(LOGIN_PATH)) return;
  loc.replace(LOGIN_PATH);
}

// ---------- ApiErrorBody 引用的共享类型 ----------

export interface AssetBrief {
  id?: string;
  ip: string;
  asset_name?: string;
  hostname?: string;
  business_system?: string;
  importance?: string;
  asset_type?: string;
  network_zone?: string;
  owner?: string;
  description?: string;
}

/** 409 冲突响应里回带的"已存在"对象：资产或文档都可能。 */
export interface ConflictExisting extends AssetBrief {
  title?: string;
  filename?: string;
  mime_type?: string;
  size?: number;
  status?: string;
  uploaded_at?: string | null;
}
