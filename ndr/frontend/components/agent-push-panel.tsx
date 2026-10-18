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
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  EmptyState,
  Field,
  FieldGrid,
  Input,
  Section,
  SettingsGrid,
  SettingsMain,
  SettingsRail,
  Skeleton,
  Stat,
  cn,
} from "@shentong/ui";
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
  /** 结果提示的语义：成功绿条 / 失败红条（连不通、重发失败都算红条） */
  const [msgKind, setMsgKind] = React.useState<"ok" | "err">("ok");
  const [busy, setBusy] = React.useState(false);
  /** 首次读取：先画骨架，别把「正在读」显示成「配置未读到」 */
  const [loading, setLoading] = React.useState(true);
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
    void (async () => {
      await load();
      setLoading(false);
    })();
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
      setMsgKind("ok");
      setMsg(
        d.config.active
          ? "已保存 —— 检测器下次投递就改走 HTTP 推送"
          : "已保存，但地址为空或开关关闭：检测器仍走旧的 Redis 队列交接（已退役，不再有人消费）",
      );
    } catch (e) {
      setMsgKind("err");
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
      setMsgKind(r.ok ? "ok" : "err");
      setMsg(r.ok ? `连通正常（${r.url}）` : `连不通：${r.detail}`);
    } catch (e) {
      setMsgKind("err");
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
      setMsgKind("ok");
      setMsg(
        r.busy
          ? r.detail
          : r.result.tried === 0
            ? "没有待重发的批（重发队列是空的）"
            : `重发完成：试了 ${r.result.tried} 批，成功 ${r.result.sent} 条，失败 ${r.result.failed} 条` +
              (r.result.lost ? `，判死丢弃 ${r.result.lost} 条` : ""),
      );
    } catch (e) {
      setMsgKind("err");
      setMsg(e instanceof ApiError ? errorText(e.body) : "重发失败");
    } finally {
      setBusy(false);
    }
  }

  const cfg = data?.config;
  const st = data?.status;

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />
      <Section
        title="智能体推送（HTTP 交接）"
        description={
          <>
            检测器命中后把聚合摘要 <b>POST 给智能体</b>，<b>收到 2xx 就是送达</b>（响应即回执）；
            失败会落在本机持久队列里自动重发，智能体挂掉期间不丢事件。地址留空 = 沿用旧的 Redis 队列交接。
          </>
        }
      >
        {/* 能改的只有「推送设置」，放主列；当前配置与送达积压都是只读事实，放右侧。
            侧栏只有 19rem，指标格压成 2 列，4 列会把标签挤成竖排。 */}
        <SettingsGrid>
          <SettingsMain>
            <Card>
              <CardHeader>
                <CardTitle>推送设置</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {loading ? (
                  <div className="grid gap-3 sm:grid-cols-2">
                    <Skeleton className="h-14 w-full" />
                    <Skeleton className="h-14 w-full" />
                    <Skeleton className="h-14 w-full" />
                    <Skeleton className="h-14 w-full" />
                  </div>
                ) : (
                  <>
                    <FieldGrid maxCols={4}>
                      <Field
                        label="推送地址"
                        htmlFor="push-url"
                        /* URL 类字段占 2 列：两列等宽时 http://agent:8000/api/push/digests 会被截断，
                           而地址错了整个推送链就断了 */
                        span="lg"
                      >
                        <Input
                          id="push-url"
                          value={url}
                          placeholder="http://agent:8000/api/push/digests"
                          onChange={(e) => setUrl(e.target.value)}
                        />
                      </Field>
                      <Field
                        label="令牌（与智能体 ST_PUSH_TOKEN 一致；留空 = 不改动已保存的令牌）"
                        htmlFor="push-token"
                      >
                        <Input
                          id="push-token"
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
                          <label className="mt-1 flex items-center gap-2 text-xs">
                            <input
                              type="checkbox"
                              className="h-4 w-4"
                              checked={clearToken}
                              onChange={(e) => setClearToken(e.target.checked)}
                            />
                            <span className="text-sev-critical-fg">
                              清除已保存的令牌（保存后生效）
                            </span>
                          </label>
                        )}
                      </Field>
                      <Field label="超时（秒）" htmlFor="push-timeout">
                        <Input
                          id="push-timeout"
                          className="tabular-nums"
                          value={String(timeout)}
                          onChange={(e) => setTimeoutSeconds(Number(e.target.value) || 10)}
                        />
                      </Field>
                      <Field label="单次最多推多少条摘要" htmlFor="push-max">
                        <Input
                          id="push-max"
                          className="tabular-nums"
                          value={String(maxPerPush)}
                          onChange={(e) => setMaxPerPush(Number(e.target.value) || 200)}
                        />
                      </Field>
                    </FieldGrid>

                    <label className="flex items-start gap-2 text-xs">
                      <input
                        type="checkbox"
                        className="mt-0.5 h-4 w-4"
                        checked={enabled}
                        onChange={(e) => setEnabled(e.target.checked)}
                      />
                      <span>
                        启用推送（关掉后摘要只会写进旧队列 shentong:events:dispatch；
                        已升级的智能体没有 consumer 进程，不再消费它）
                      </span>
                    </label>

                    {msg && (
                      <p
                        role={msgKind === "err" ? "alert" : "status"}
                        className={cn(
                          "rounded-xs border px-3 py-2 text-xs",
                          msgKind === "err"
                            ? "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg"
                            : "border-sev-ok-bd bg-sev-ok-bg text-sev-ok-fg"
                        )}
                      >
                        {msg}
                      </p>
                    )}

                    <div className="flex flex-wrap items-center gap-2">
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
                      <Button size="sm" variant="outline" disabled={busy} onClick={() => void load()}>
                        刷新
                      </Button>
                      {!data && !loading && (
                        <span className="self-center text-xs text-sev-critical-fg">
                          配置未读到，已禁用保存（避免空表单覆盖现有配置）
                        </span>
                      )}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </SettingsMain>

          <SettingsRail>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
                <CardTitle>当前配置</CardTitle>
                {cfg ? (
                  <Badge variant={cfg.active ? "low" : "medium"}>
                    {cfg.active ? "推送已启用" : "未启用（走旧队列）"}
                  </Badge>
                ) : null}
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-9 w-full" />
                ) : cfg ? (
                  // 补两行：超时与单批上限 —— 这两个是排查「推送慢 / 一次推不完」时最先要看的数
                  <div className="divide-y divide-border-subtle rounded-xs bg-surface-1 px-3 py-2 text-xs">
                    <p className="pb-1">
                      <span className="text-muted-foreground">推送地址</span>
                      <span className="mt-0.5 block break-all font-mono">{cfg.url || "(未填地址)"}</span>
                    </p>
                    <p className="py-1">
                      <span className="text-muted-foreground">令牌</span>
                      <span className="mt-0.5 block font-mono">
                        {cfg.token_set ? `已设置（${cfg.token_masked}）` : "未设置"}
                      </span>
                    </p>
                    <p className="py-1">
                      <span className="text-muted-foreground">超时</span>
                      <span className="mt-0.5 block tabular-nums">{cfg.timeout_seconds} 秒</span>
                    </p>
                    <p className="py-1">
                      <span className="text-muted-foreground">单批上限</span>
                      <span className="mt-0.5 block tabular-nums">{cfg.max_per_push} 条</span>
                    </p>
                    {data?.env.url ? (
                      <p className="pt-1">
                        <span className="text-muted-foreground">环境默认</span>
                        <span className="mt-0.5 block break-all font-mono">{data.env.url}</span>
                      </p>
                    ) : null}
                  </div>
                ) : (
                  <EmptyState
                    size="compact"
                    tone={errs.isFailed(SRC.main) ? "danger" : "muted"}
                    title={errs.isFailed(SRC.main) ? "读取失败（见上方错误条）" : "还没有读到推送配置"}
                    action={
                      <Button size="sm" variant="outline" onClick={() => void load()}>
                        重新读取
                      </Button>
                    }
                  />
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>送达与积压</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {loading ? (
                  <>
                    <div className="grid grid-cols-2 gap-3">
                      <Skeleton className="h-14 w-full" />
                      <Skeleton className="h-14 w-full" />
                      <Skeleton className="h-14 w-full" />
                      <Skeleton className="h-14 w-full" />
                    </div>
                    <Skeleton className="h-8 w-full" />
                  </>
                ) : st ? (
                  <>
                    <div className="grid grid-cols-2 gap-3">
                      <Stat label="已送达" value={st.sent} hint="收到 2xx 的批数" />
                      <Stat
                        label="失败待重发"
                        value={backlog(st)}
                        tone={backlog(st) ? "critical" : "default"}
                        hint="真积压 = 队列 + 处理中"
                      />
                      <Stat label="重发成功" value={st.retried} />
                      <Stat
                        label="重发失败"
                        value={st.retry_failed}
                        tone={st.retry_failed ? "critical" : "default"}
                      />
                    </div>

                    {/* 真积压 = 待重发批数（queue_depth + processing_depth）；st.queued 是累计入队数，只增不减 */}
                    <div className="flex flex-wrap gap-x-4 gap-y-1 rounded-xs bg-surface-1 px-3 py-2 text-xs tabular-nums">
                      <span
                        className="text-muted-foreground"
                        title="累计值（自 Redis 计数以来落过重发队列的批数），不是当前积压"
                      >
                        累计失败入队 <span className="tabular-nums">{st.queued}</span>
                      </span>
                      <span className="text-muted-foreground">
                        待重发批数 <span className="tabular-nums">{st.queue_depth}</span>
                      </span>
                      <span className="text-muted-foreground">
                        重发处理中 <span className="tabular-nums">{st.processing_depth}</span>
                      </span>
                      {typeof st.retry_lost === "number" && st.retry_lost > 0 && (
                        <span
                          className="text-sev-critical-fg"
                          title="连试多次仍失败、已判死丢弃的批数（不会再自动重发）"
                        >
                          判死丢弃 <span className="tabular-nums">{st.retry_lost}</span>
                        </span>
                      )}
                      {typeof st.retry_dropped === "number" && st.retry_dropped > 0 && (
                        <span className="text-sev-critical-fg" title="重试队列写入失败、当场丢掉的条数">
                          队列写失败丢弃 <span className="tabular-nums">{st.retry_dropped}</span>
                        </span>
                      )}
                      {typeof st.undelivered === "number" && st.undelivered > 0 && (
                        <span className="text-sev-critical-fg" title="投递失败且没能进重试队列的条数（真丢）">
                          未送达 <span className="tabular-nums">{st.undelivered}</span>
                        </span>
                      )}
                      {typeof st.spool_batches === "number" && st.spool_batches > 0 && (
                        <span
                          className="text-sev-medium-fg"
                          title="超龄摘要已从队列挪到磁盘缓存（不再占 Redis 内存），智能体恢复后自动按序补推、推成功即删"
                        >
                          磁盘缓存 <span className="tabular-nums">{st.spool_batches}</span> 批（
                          {fmtBytes(st.spool_bytes ?? 0)}）
                          {(st.spool_oldest_age ?? 0) > 0
                            ? `，最久 ${fmtAge(st.spool_oldest_age ?? 0)}`
                            : ""}
                        </span>
                      )}
                    </div>

                    <p className="text-xs tabular-nums text-muted-foreground">
                      最近成功 {st.last_success_at || "—"}；最近失败 {st.last_error_at || "—"}
                      {st.last_error ? `（${st.last_error}）` : ""}
                      {st.error ? ` —— 状态不可读：${st.error}` : ""}
                    </p>
                  </>
                ) : (
                  <EmptyState
                    size="compact"
                    tone={errs.isFailed(SRC.main) ? "danger" : "muted"}
                    title={errs.isFailed(SRC.main) ? "读取失败（见上方错误条）" : "还没有读到送达状态"}
                    hint="计数来自 /api/agent-push；读不到时这里不做任何推断。"
                  />
                )}

                {data?.hint && <p className="text-xs text-muted-foreground">{data.hint}</p>}
              </CardContent>
            </Card>
          </SettingsRail>
        </SettingsGrid>
      </Section>
    </div>
  );
}
