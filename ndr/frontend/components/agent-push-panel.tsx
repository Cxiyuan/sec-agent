"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type AgentPushPayload,
  type AgentPushTestResult,
} from "@/lib/api";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";

/** 智能体推送：地址 / 令牌 / 开关 + 送达与失败计数 + 待重发队列 + 一键自检、立即重发。 */
export function AgentPushPanel() {
  const [data, setData] = React.useState<AgentPushPayload | null>(null);
  const [url, setUrl] = React.useState("");
  const [token, setToken] = React.useState("");
  const [enabled, setEnabled] = React.useState(true);
  const [timeout, setTimeoutSeconds] = React.useState(10);
  const [maxPerPush, setMaxPerPush] = React.useState(200);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const apply = React.useCallback((d: AgentPushPayload) => {
    setData(d);
    setUrl(d.config.url);
    setToken("");
    setEnabled(d.config.enabled);
    setTimeoutSeconds(d.config.timeout_seconds);
    setMaxPerPush(d.config.max_per_push);
  }, []);

  async function load() {
    const d = await apiFetch<AgentPushPayload>("/api/agent-push");
    apply(d);
  }

  React.useEffect(() => {
    load().catch(() => setData(null));
  }, []);

  async function save() {
    setBusy(true);
    setMsg("");
    try {
      const d = await apiFetch<AgentPushPayload>("/api/agent-push", {
        method: "PUT",
        // token 空串 = 不改动已保存的令牌（要用新令牌才填）
        body: JSON.stringify({
          url,
          token: token === "" ? null : token,
          enabled,
          timeout_seconds: timeout,
          max_per_push: maxPerPush,
        }),
      });
      apply(d);
      setMsg(
        d.config.active
          ? "已保存 —— 检测器下次投递就改走 HTTP 推送"
          : "已保存，但地址为空或开关关闭：检测器仍走旧的 Redis 队列交接",
      );
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<AgentPushTestResult>("/api/agent-push/test", {
        method: "POST",
        body: JSON.stringify({ url: url || null, token: token === "" ? null : token }),
      });
      setMsg(r.ok ? `连通正常（${r.url}）` : `连不通：${r.detail}`);
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "自检失败");
    } finally {
      setBusy(false);
    }
  }

  async function retry() {
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<{ result: { tried: number; sent: number; failed: number } } & AgentPushPayload>(
        "/api/agent-push/retry",
        { method: "POST" },
      );
      apply(r);
      setMsg(
        r.result.tried === 0
          ? "没有待重发的批"
          : `重发完成：试了 ${r.result.tried} 批，成功 ${r.result.sent} 条，失败 ${r.result.failed} 条`,
      );
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "重发失败");
    } finally {
      setBusy(false);
    }
  }

  const cfg = data?.config;
  const st = data?.status;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">智能体推送（HTTP 交接）</CardTitle>
        <p className="text-xs text-muted-foreground">
          检测器命中后把聚合摘要 <b>POST 给智能体</b>，<b>收到 2xx 就是送达</b>（响应即回执）；
          失败会落在本机持久队列里自动重发，智能体挂掉期间不丢事件。地址留空 = 沿用旧的 Redis 队列交接。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}

        {cfg && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border p-3 text-xs">
            <Badge variant={cfg.active ? "low" : "medium"}>{cfg.active ? "推送已启用" : "未启用（走旧队列）"}</Badge>
            <span className="font-mono">{cfg.url || "(未填地址)"}</span>
            <span className="text-muted-foreground">
              令牌 {cfg.token_set ? `已设置（${cfg.token_masked}）` : "未设置"}
            </span>
            {data?.env.url && <span className="text-muted-foreground">环境默认 {data.env.url}</span>}
          </div>
        )}

        <div className="grid gap-3 md:grid-cols-2">
          <label className="space-y-1 text-xs">
            <span className="text-muted-foreground">推送地址</span>
            <Input
              value={url}
              placeholder="http://agent:8000/api/push/digests"
              onChange={(e) => setUrl(e.target.value)}
            />
          </label>
          <label className="space-y-1 text-xs">
            <span className="text-muted-foreground">
              令牌（与智能体 ST_PUSH_TOKEN 一致；留空表示不改动）
            </span>
            <Input
              value={token}
              type="password"
              placeholder={cfg?.token_set ? "留空 = 保持不变" : "填一个长随机串"}
              onChange={(e) => setToken(e.target.value)}
            />
          </label>
          <label className="space-y-1 text-xs">
            <span className="text-muted-foreground">超时（秒）</span>
            <Input
              value={String(timeout)}
              onChange={(e) => setTimeoutSeconds(Number(e.target.value) || 10)}
            />
          </label>
          <label className="space-y-1 text-xs">
            <span className="text-muted-foreground">单次最多推多少条摘要</span>
            <Input
              value={String(maxPerPush)}
              onChange={(e) => setMaxPerPush(Number(e.target.value) || 200)}
            />
          </label>
        </div>

        <label className="flex items-center gap-2 text-xs">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span>
            启用推送（关掉后摘要只会写进旧队列 shentong:events:dispatch；
            已升级的智能体没有 consumer 进程，不再消费它）
          </span>
        </label>

        <div className="flex flex-wrap gap-2">
          <Button size="sm" disabled={busy} onClick={save}>
            保存
          </Button>
          <Button size="sm" variant="outline" disabled={busy || !url} onClick={test}>
            测试连接
          </Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={retry}>
            立即重发
          </Button>
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => load()}>
            刷新
          </Button>
        </div>

        {st && (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-3 rounded-md border p-3 text-xs">
              <span>已送达 {st.sent}</span>
              <span className={st.queued ? "text-destructive" : "text-muted-foreground"}>
                失败待重发 {st.queued}
              </span>
              <span>重发成功 {st.retried}</span>
              <span className={st.retry_failed ? "text-destructive" : "text-muted-foreground"}>
                重发失败 {st.retry_failed}
              </span>
              <span>待重发批数 {st.queue_depth}</span>
              <span>重发处理中 {st.processing_depth}</span>
            </div>
            <p className="text-xs text-muted-foreground">
              最近成功 {st.last_success_at || "—"}；最近失败 {st.last_error_at || "—"}
              {st.last_error ? `（${st.last_error}）` : ""}
              {st.error ? ` —— 状态不可读：${st.error}` : ""}
            </p>
          </div>
        )}

        {data?.hint && <p className="text-xs text-muted-foreground">{data.hint}</p>}
      </CardContent>
    </Card>
  );
}
