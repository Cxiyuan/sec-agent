"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type AgentPushPayload,
  type AgentPushStatus,
  type AgentPushTestResult,
} from "@/lib/api";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { loadInto, PanelError, usePanelErrors } from "@/components/panel-error";

/** 读取失败的接口名（错误条用）。 */
const SRC = { main: "智能体推送配置与状态（/api/agent-push）" } as const;

/**
 * 真积压批数：后端 `retry_backlog_batches` = queue_depth + processing_depth。
 * 老后端没这个字段时退回两数之和，绝不再用只增不减的累计 `queued` 冒充积压。
 */
function backlog(st: AgentPushStatus): number {
  return st.retry_backlog_batches ?? (st.queue_depth ?? 0) + (st.processing_depth ?? 0);
}

/** 磁盘缓存占用：MB 以上用 MB，否则用 KB。 */
function fmtBytes(n: number): string {
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(n / 1024))} KB`;
}

/** 最老缓存待了多久：分钟以下用秒，小时以上用小时。 */
function fmtAge(seconds: number): string {
  if (seconds >= 3600) return `${(seconds / 3600).toFixed(1)} 小时`;
  if (seconds >= 60) return `${Math.round(seconds / 60)} 分钟`;
  return `${Math.max(1, Math.round(seconds))} 秒`;
}

/** 智能体推送：地址 / 令牌 / 开关 + 送达与失败计数 + 待重发队列 + 一键自检、立即重发。 */
export function AgentPushPanel() {
  const [data, setData] = React.useState<AgentPushPayload | null>(null);
  const [url, setUrl] = React.useState("");
  const [token, setToken] = React.useState("");
  const [clearToken, setClearToken] = React.useState(false);
  const [enabled, setEnabled] = React.useState(true);
  const [timeout, setTimeoutSeconds] = React.useState(10);
  const [maxPerPush, setMaxPerPush] = React.useState(200);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const errs = usePanelErrors();

  const apply = React.useCallback((d: AgentPushPayload) => {
    setData(d);
    setUrl(d.config.url);
    setToken("");
    setClearToken(false);
    setEnabled(d.config.enabled);
    setTimeoutSeconds(d.config.timeout_seconds);
    setMaxPerPush(d.config.max_per_push);
  }, []);

  async function load() {
    await loadInto(errs, SRC.main, "/api/agent-push", apply);
  }

  React.useEffect(() => {
    void load();
    // 只在挂载时读一次；load 内部自己收错误
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * 提交给后端的令牌值（后端约定：null = 不改动，"" = 清空）。
   * 界面上：token 输入框留空 = 不改动；勾「清除已保存令牌」= 传空串清空。
   */
  function tokenPayload(): string | null {
    if (clearToken) return "";
    return token === "" ? null : token;
  }

  async function save() {
    setBusy(true);
    setMsg("");
    try {
      const d = await apiFetch<AgentPushPayload>("/api/agent-push", {
        method: "PUT",
        body: JSON.stringify({
          url,
          token: tokenPayload(),
          enabled,
          timeout_seconds: timeout,
          max_per_push: maxPerPush,
        }),
      });
      apply(d);
      setMsg(
        d.config.active
          ? "已保存 —— 检测器下次投递就改走 HTTP 推送"
          : "已保存，但地址为空或开关关闭：检测器仍走旧的 Redis 队列交接（已退役，不再有人消费）",
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
        body: JSON.stringify({ url: url || null, token: tokenPayload() }),
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
      const r = await apiFetch<
        {
          result: { tried: number; sent: number; failed: number; lost: number; locked: boolean };
          busy: boolean;
          detail: string;
        } & AgentPushPayload
      >("/api/agent-push/retry", { method: "POST" });
      apply(r);
      setMsg(
        r.busy
          ? r.detail
          : r.result.tried === 0
            ? "没有待重发的批（重发队列是空的）"
            : `重发完成：试了 ${r.result.tried} 批，成功 ${r.result.sent} 条，失败 ${r.result.failed} 条` +
              (r.result.lost ? `，判死丢弃 ${r.result.lost} 条` : ""),
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
        <PanelError errors={errs} />

        {cfg && (
          <div className="flex flex-wrap items-center gap-2 rounded-xs bg-surface-1 px-3 py-2 text-xs">
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
              令牌（与智能体 ST_PUSH_TOKEN 一致；留空 = 不改动已保存的令牌）
            </span>
            <Input
              value={token}
              type="password"
              disabled={clearToken}
              placeholder={
                clearToken
                  ? "保存后令牌被清空"
                  : cfg?.token_set
                    ? "留空 = 保持不变"
                    : "填一个长随机串"
              }
              onChange={(e) => setToken(e.target.value)}
            />
            {/* 后端约定：null = 不改动、"" = 清空。光靠输入框留空没法表达「清空」，所以给个显式开关 */}
            {cfg?.token_set && (
              <span className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  checked={clearToken}
                  onChange={(e) => setClearToken(e.target.checked)}
                />
                <span className="text-destructive">清除已保存的令牌（保存后生效）</span>
              </span>
            )}
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
          {/* 配置没读到就禁止保存：空表单点保存会把地址/开关覆盖掉 */}
          <Button size="sm" disabled={busy || !data} onClick={save}>
            保存
          </Button>
          <Button size="sm" variant="outline" disabled={busy || !url} onClick={test}>
            测试连接
          </Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={retry}>
            立即重发
          </Button>
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => void load()}>
            刷新
          </Button>
          {!data && (
            <span className="self-center text-xs text-destructive">
              配置未读到，已禁用保存（避免空表单覆盖现有配置）
            </span>
          )}
        </div>

        {st && (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-3 rounded-xs bg-surface-1 px-3 py-2 text-xs">
              <span>已送达 {st.sent}</span>
              {/* 真积压 = 待重发批数（queue_depth + processing_depth）；st.queued 是累计入队数，只增不减 */}
              <span
                className={backlog(st) ? "text-destructive" : "text-muted-foreground"}
                title="当前真的压在重发队列里没发出去的批数"
              >
                失败待重发 {backlog(st)} 批
              </span>
              <span
                className="text-muted-foreground"
                title="累计值（自 Redis 计数以来落过重发队列的批数），不是当前积压"
              >
                累计失败入队 {st.queued}
              </span>
              <span>重发成功 {st.retried}</span>
              <span className={st.retry_failed ? "text-destructive" : "text-muted-foreground"}>
                重发失败 {st.retry_failed}
              </span>
              {typeof st.retry_lost === "number" && st.retry_lost > 0 && (
                <span
                  className="text-destructive"
                  title="连试多次仍失败、已判死丢弃的批数（不会再自动重发）"
                >
                  判死丢弃 {st.retry_lost}
                </span>
              )}
              {typeof st.retry_dropped === "number" && st.retry_dropped > 0 && (
                <span className="text-destructive" title="重试队列写入失败、当场丢掉的条数">
                  队列写失败丢弃 {st.retry_dropped}
                </span>
              )}
              {typeof st.undelivered === "number" && st.undelivered > 0 && (
                <span className="text-destructive" title="投递失败且没能进重试队列的条数（真丢）">
                  未送达 {st.undelivered}
                </span>
              )}
              <span>待重发批数 {st.queue_depth}</span>
              <span>重发处理中 {st.processing_depth}</span>
              {typeof st.spool_batches === "number" && st.spool_batches > 0 && (
                <span
                  className="text-sev-medium-fg"
                  title="超龄摘要已从队列挪到磁盘缓存（不再占 Redis 内存），智能体恢复后自动按序补推、推成功即删"
                >
                  磁盘缓存 {st.spool_batches} 批（{fmtBytes(st.spool_bytes ?? 0)}）
                  {(st.spool_oldest_age ?? 0) > 0 ? `，最久 ${fmtAge(st.spool_oldest_age ?? 0)}` : ""}
                </span>
              )}
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
