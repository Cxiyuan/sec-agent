"use client";

const TOKEN_KEY = "shentong_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export async function apiFetch<T = unknown>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login";
    }
    throw new Error("未登录或凭证失效");
  }
  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || `请求失败 (${res.status})`);
  }
  return (await res.json()) as T;
}

// 类型定义（与后端对应）
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
  attack_chain: any;
  profile: any;
  anomaly: any;
  response_suggestions: any;
  created_at: string | null;
}

export interface BusinessContext {
  lan_ips?: string[];
  assets?: AssetBrief[];
  knowledge?: { source_type: string; source_id: string; content: string; score: number }[];
  text?: string;
}

export interface AssetBrief {
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

export interface RuleItem {
  id: string;
  name: string;
  description: string;
  conditions: any;
  severity: string;
  source: string;
  enabled: boolean;
  priority: number;
}
