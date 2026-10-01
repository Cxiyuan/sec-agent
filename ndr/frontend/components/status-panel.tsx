"use client";

import * as React from "react";
import { Badge, Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import {
  apiFetch,
  type AgentPushPayload,
  type DetectorStats,
  type WazuhPayload,
} from "@/lib/api";

/**
 * 运行状态（第 7 期新增页）：把「这条链路现在活着吗」一眼能看到的东西集中起来。
 *
 * 数据都来自既有接口，不新增后端：
 * - `/api/detector/stats`：检测队列深度、投递速率、丢弃计数、选主、Redis 内存体检
 * - `/api/agent-push`：摘要推送的送达 / 待重发 / 最近失败原因
 * - `/api/wazuh`：Wazuh API 可达性与近 24h 入库量（没接 Wazuh 时显示未配置）
 *
 * 队列长度与内存吃满是最真实的故障前兆（历史上 Redis 写满导致整链静默卡死），
 * 所以这一页默认 15 秒自刷新，且 Redis 用量超过告警线时显式标红。
 */
export function StatusPanel() {
  const [stats, setStats] = React.useState<DetectorStats | null>(null);
  const [push, setPush] = React.useState<AgentPushPayload | null>(null);
  const [wazuh, setWazuh] = React.useState<WazuhPayload | null>(null);
  const [err, setErr] = React.useState("");
  const [auto, setAuto] = React.useState(true);
  const [busy, setBusy] = React.useState(false);

  const load = React.useCallback(async () => {
    setBusy(true);
    const next: string[] = [];
    try {
      setStats(await apiFetch<DetectorStats>("/api/detector/stats"));
    } catch {
      next.push("检测器状态（/api/detector/stats）");
    }
    try {
      setPush(await apiFetch<AgentPushPayload>("/api/agent-push"));
    } catch {
      next.push("摘要推送状态（/api/agent-push）");
    }
    try {
      setWazuh(await apiFetch<WazuhPayload>("/api/wazuh"));
    } catch {
      next.push("Wazuh 接入（/api/wazuh）");
    }
    setErr(next.length ? `以下接口读取失败：${next.join("、")}` : "");
    setBusy(false);
  }, []);

  React.useEffect(() => {
    load().catch(() => {});
  }, [load]);

  React.useEffect(() => {
    if (!auto) return;
    const t = setInterval(() => load().catch(() => {}), 15000);
    return () => clearInterval(t);
  }, [auto, load]);

  const redis = stats?.redis;
  const pushActive = push?.config.active ?? false;
  const pending = (push?.status.queue_depth ?? 0) + (push?.status.processing_depth ?? 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">链路运行状态</CardTitle>
        <p className="text-xs text-muted-foreground">
          采集队列积压、投递速率、推送重发、Redis 内存 —— 一眼看清链路有没有卡住。
          {auto ? "每 15 秒自动刷新。" : "自动刷新已关闭。"}
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center gap-3">
          <Button onClick={() => load()} disabled={busy}>
            {busy ? "读取中…" : "刷新"}
          </Button>
          <Button variant="outline" onClick={() => setAuto((v) => !v)}>
            {auto ? "关闭自动刷新" : "开启自动刷新"}
          </Button>
          {stats?.error && <span className="text-xs text-destructive">检测器：{stats.error}</span>}
        </div>
        {err && <p className="text-xs text-destructive">{err}</p>}

        {/* 检测器与队列 */}
        <div className="rounded-md border p-3 text-xs">
          <p className="mb-2 flex items-center gap-2 text-muted-foreground">
            检测器与队列
            <Badge variant={stats?.enabled ? "info" : "outline"}>
              {stats?.enabled ? "检测开启" : "检测关闭（只归一化入库）"}
            </Badge>
            {stats?.leader?.holder ? (
              <Badge variant="secondary">消费者 {stats.leader.holder}</Badge>
            ) : (
              <Badge variant="outline">无消费者（选主键过期）</Badge>
            )}
          </p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-4">
            <span>
              归一化队列 <b>{stats?.queue_raw ?? "—"}</b>
            </span>
            <span>
              待聚合队列 <b>{stats?.queue_digest ?? "—"}</b>
              {stats?.queue_max ? `（上限 ${stats.queue_max}）` : ""}
            </span>
            <span>
              处理中 <b>{stats?.queue_processing ?? "—"}</b>
            </span>
            <span>
              本分钟投递 <b>{stats?.delivered_this_minute ?? "—"}</b>
              {stats?.rate_limit_per_minute ? ` / ${stats.rate_limit_per_minute}` : ""}
            </span>
          </div>
          {stats?.last_dropped_at && (
            <p className="mt-1 text-muted-foreground">
              最近一次丢弃 {stats.last_dropped_at.replace("T", " ").slice(0, 19)}
              {stats.dropped && Object.keys(stats.dropped).length > 0
                ? `（累计：${Object.entries(stats.dropped)
                    .map(([k, v]) => `${k} ${v}`)
                    .join("、")}）`
                : ""}
            </p>
          )}
          {stats?.handled_skipped ? (
            <p className="mt-1 text-muted-foreground">
              单桶超限被丢弃的已处理登记：{stats.handled_skipped} 条（会被兜底重复分析）
            </p>
          ) : null}
        </div>

        {/* Redis 体检 */}
        <div className="rounded-md border p-3 text-xs">
          <p className="mb-2 flex items-center gap-2 text-muted-foreground">
            Redis 体检
            {stats?.redis_warn ? (
              <Badge variant="critical">内存接近上限，整链路会卡死，尽快处理</Badge>
            ) : (
              <Badge variant="info">正常</Badge>
            )}
          </p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-4">
            <span>
              已用 <b>{redis?.used_human ?? (redis ? `${redis.used} B` : "—")}</b>
            </span>
            <span>
              上限 <b>{redis?.max ? `${redis.max} B` : "未设置 maxmemory"}</b>
            </span>
            <span>
              占比 <b>{redis ? `${redis.perc}%` : "—"}</b>
            </span>
            <span>
              淘汰策略 <b>{redis?.policy || "—"}</b>
            </span>
          </div>
        </div>

        {/* 摘要推送 */}
        <div className="rounded-md border p-3 text-xs">
          <p className="mb-2 flex items-center gap-2 text-muted-foreground">
            摘要推送
            <Badge variant={pushActive ? "info" : "outline"}>
              {pushActive ? "HTTP 推送已启用" : "未启用（回落旧队列交接）"}
            </Badge>
            {pending > 0 ? <Badge variant="high">待重发 {pending} 批</Badge> : null}
          </p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-4">
            <span>
              已送达 <b>{push?.status.sent ?? "—"}</b>
            </span>
            <span>
              失败待重发 <b>{push?.status.queued ?? "—"}</b>
            </span>
            <span>
              重发成功 <b>{push?.status.retried ?? "—"}</b>
            </span>
            <span>
              重发失败 <b>{push?.status.retry_failed ?? "—"}</b>
            </span>
          </div>
          <p className="mt-1 text-muted-foreground">
            最近成功 {push?.status.last_success_at?.replace("T", " ").slice(0, 19) || "—"} · 最近失败{" "}
            {push?.status.last_error_at?.replace("T", " ").slice(0, 19) || "—"}
            {push?.status.last_error ? `（${push.status.last_error}）` : ""}
          </p>
          {push?.status.error && <p className="text-destructive">读推送状态失败：{push.status.error}</p>}
        </div>

        {/* Wazuh 入库量 */}
        <div className="rounded-md border p-3 text-xs">
          <p className="mb-2 flex items-center gap-2 text-muted-foreground">
            Wazuh 接入
            {wazuh?.config.configured ? (
              <Badge variant={wazuh.status.reachable ? "info" : "high"}>
                {wazuh.status.reachable
                  ? `API 已连通（${wazuh.status.version || "版本未知"}）`
                  : "已配置但连不上"}
              </Badge>
            ) : (
              <Badge variant="outline">未配置（没接 Wazuh 就不用管）</Badge>
            )}
          </p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-4">
            <span>
              近 24h 告警 <b>{wazuh?.ingest.alerts ?? "—"}</b>
            </span>
            <span>
              近 24h 原始日志 <b>{wazuh?.ingest.archives ?? "—"}</b>
            </span>
            <span>
              Agent 在线 <b>{wazuh?.status.agents.active ?? "—"}</b>
              {wazuh?.status.agents.total ? ` / ${wazuh.status.agents.total}` : ""}
            </span>
            <span>
              最近一条 {wazuh?.ingest.last_at?.replace("T", " ").slice(0, 19) || "—"}
            </span>
          </div>
          {wazuh?.ingest.error && (
            <p className="mt-1 text-destructive">读 ES 失败：{wazuh.ingest.error}</p>
          )}
        </div>

        {/* 判重说明：第 5 期起在智能体侧 */}
        {stats?.dedup && (
          <p className="text-xs text-muted-foreground">
            判重：{stats.dedup.note ?? "已下放到智能体"}
            {stats.dedup.skipped_total > 0
              ? `；闸门退役前累计省下重复分析 ${stats.dedup.skipped_total} 条（历史值，不再增长）`
              : ""}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
