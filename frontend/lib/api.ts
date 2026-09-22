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

export async function apiFetch<T = unknown>(
  path: string,
  options: RequestInit = {}
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

// ---------- 类型定义（与后端对应） ----------

export interface AttackEvidence {
  id?: number | string;
  type?: string;
  src?: string;
  dst?: string;
  summary?: string;
}

export interface AttackStage {
  stage: string;
  description?: string;
  evidence?: AttackEvidence[];
}

export interface AttackChain {
  stages?: AttackStage[];
  summary?: string;
  confidence?: number;
}

export interface Profile {
  basic?: {
    src_ips?: string[];
    geo?: string;
    tool_stack?: string[];
    assets_targeted?: string[];
  };
  behavior?: {
    ttps?: string[];
    target_preference?: string;
    time_pattern?: string;
    motivation?: string;
  };
}

export interface AnomalyFinding {
  kind?: string;
  reason?: string;
}

export interface Anomaly {
  findings?: AnomalyFinding[];
}

export interface ResponseSuggestion {
  category: string;
  action: string;
  detail: string;
}

export interface EventGroupItem {
  id: string;
  fingerprint: string;
  src_ips: string[];
  dst_ips: string[];
  window_start: string | null;
  window_end: string | null;
  event_count: number;
  triage_score: number;
  status: string;
  severity: string | null;
  business_context: BusinessContext | null;
  attack_chain: AttackChain | null;
  profile: Profile | null;
  anomaly: Anomaly | null;
  response_suggestions: ResponseSuggestion[] | null;
  created_at: string | null;
}

export interface BusinessContext {
  lan_ips?: string[];
  assets?: AssetBrief[];
  knowledge?: { source_type: string; source_id: string; content: string; score: number }[];
  text?: string;
}

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

/** 409 冲突响应里回带的“已存在”对象：资产或文档都可能。 */
export interface ConflictExisting extends AssetBrief {
  title?: string;
  filename?: string;
  mime_type?: string;
  size?: number;
  status?: string;
  uploaded_at?: string | null;
}

export interface AssetItem {
  id: string;
  ip: string;
  extra_ips: string[];
  hostname: string;
  asset_name: string;
  business_system: string;
  owner: string;
  importance: string;
  asset_type: string;
  network_zone: string;
  os: string;
  services: string;
  tags: string[];
  location: string;
  description: string;
  is_external: boolean;
  allow_ip_share: boolean;
  embedding_status: string;
}

export interface DocumentItem {
  id: string;
  title: string;
  filename: string;
  mime_type: string;
  size: number;
  status: string;
  uploaded_at: string | null;
}

export interface RuleCondition {
  field?: string;
  op?: string;
  value?: string | number | boolean | (string | number)[];
  logic?: string;
  rules?: RuleCondition[];
}

export interface RuleConditions {
  logic?: string;
  rules?: RuleCondition[];
}

export interface RuleItem {
  id: string;
  name: string;
  description: string;
  conditions: RuleConditions;
  severity: string;
  source: string;
  enabled: boolean;
  priority: number;
}

/** 事件组详情（含关联事件） */
export interface EventItem {
  id: string;
  source_system?: string;
  ts: string | null;
  event_type: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  severity?: string;
  hit_rule?: string | null;
  edge_score?: number;
  summary?: string;
}

export interface GroupDetail extends EventGroupItem {
  events: EventItem[];
}

/** CSV 导入预览报告 */
export interface ImportPreview {
  ok: boolean;
  truncated: boolean;
  total_rows: number;
  errors: { row: number; ip?: string; msg: string }[];
  new_count: number;
  duplicates: { row: number; ip: string; existing: AssetBrief }[];
  ip_conflicts: { row: number; ip: string; holders: AssetBrief[] }[];
  non_lan: { row: number; ip: string }[];
}

/** CSV 导入结果 */
export interface ImportResult {
  created: number;
  updated: number;
  skipped: number;
  external: number;
}

// ---------- 网络拓扑 ----------

export interface TopologyNodeType {
  key: string;
  name: string;
  icon: string;
  color: string;
  builtin: boolean;
  sort: number;
}

export interface NodeTypeList {
  items: TopologyNodeType[];
  icon_candidates: string[];
}

export interface TopoNodeData extends Record<string, unknown> {
  label: string;
  node_type: string;
  asset_ids: string[];
  zone: string;
  note: string;
}

export interface TopoNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data: TopoNodeData;
}

export interface TopoEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  type?: string;
}

export interface TopoGraph {
  nodes: TopoNode[];
  edges: TopoEdge[];
}

export interface TopologyItem {
  id: string;
  name: string;
  description: string;
  node_count: number;
  edge_count: number;
  enabled: boolean;
  status: string;
  indexed_at: string | null;
  updated_at: string | null;
}

export interface TopologyDetail extends TopologyItem {
  graph: TopoGraph;
}
