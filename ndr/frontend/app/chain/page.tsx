"use client";

import * as React from "react";
import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/page-shell";
import { PanelError, loadInto, usePanelErrors } from "@/components/panel-error";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  EmptyState,
  Input,
  Skeleton,
  apiFetch,
  ApiError,
  cn,
  errorText,
  formatDateTime,
} from "@shentong/ui";
import type { ChainItem, ChainListPayload } from "@/lib/api";
import { useAliases } from "@/lib/aliases";

/**
 * 攻击链还原：把每次请求还原成「真实请求IP →（中继…）→ 源站」+ 动作事实聚合。
 *
 * 三条口径（与后端一致，界面上也写清楚，避免误读）：
 * 1. 只还原**真正进了检测的那些事件**（通过中继去重的），与检测器/画像看到的完全一致；
 * 2. 真实请求 IP 来自可信代理头（`X-Forwarded-For`/`X-Real-IP`，且直连对端在中继清单里）；
 *    没有中继/跳板时，就是「真实请求IP → 源站IP」两段；
 * 3. 中继路径由「监控网段」页的中继上下级拓扑推导，**逐段标注证据来源**
 *    （直连观测 / 代理头证据 / 纯拓扑推导）——哪里是硬证据、哪里是推理，一眼能看出来。
 */

const SRC = { list: "攻击链（/api/chains）" } as const;

const WINDOWS: Array<{ label: string; minutes: number }> = [
  { label: "近 15 分钟", minutes: 15 },
  { label: "近 1 小时", minutes: 60 },
  { label: "近 6 小时", minutes: 360 },
  { label: "近 24 小时", minutes: 1440 },
];

/** 源站展示名：**IP:端口 优先**，域名/Host 只作补充（默认显示 IP，别名优先）。
 *  为什么要这样：中继链路上 hostname 是 HTTP Host/SNI（如内网服务的 `master:5000`），
 *  只显示它就看不出到底是哪台机器（2026-10 用户反馈）。 */
function originLabel(chain: ChainItem, name: (ip: string) => string): string {
  const ip = chain.origin_ip || "";
  const host = chain.origin_kind === "hostname" ? chain.origin : "";
  if (ip && host && ip !== host) return `${name(ip)}（${host}）`;
  return name(ip || host) || "源站";
}

function segText(seg: ChainItem["segments"][number]): string {
  if (seg.kind === "direct") return "无中继（直连）";
  if (seg.kind === "origin") return `源站${seg.to ? `（${seg.to}）` : ""}`;
  const bits: string[] = [];
  if (seg.direct) bits.push(`直连观测 ${seg.direct}`);
  if (seg.header) bits.push(`代理头 ${seg.header}`);
  if (seg.confirmed) bits.push("已确认");
  if (!bits.length) return "拓扑推导（无直接证据）";
  return bits.join(" · ");
}

function factLine(name: string, data?: Record<string, number>): React.ReactNode {
  const entries = Object.entries(data || {});
  if (!entries.length) return null;
  return (
    <span className="mr-3 inline-block">
      <b>{name}</b>：
      {entries
        .slice(0, 6)
        .map(([k, v]) => `${k}${v > 1 ? `×${v}` : ""}`)
        .join("、")}
    </span>
  );
}

function ChainInner() {
  // 展示层别名：链路上的每一跳都优先显示别名（没起名就是 IP）
  const { displayName } = useAliases();
  const params = useSearchParams();
  const errs = usePanelErrors();
  const [minutes, setMinutes] = React.useState(60);
  const [suspiciousOnly, setSuspiciousOnly] = React.useState(true);
  const [ip, setIp] = React.useState(params.get("ip") || "");
  const [host, setHost] = React.useState(params.get("host") || "");
  const [data, setData] = React.useState<ChainListPayload | null>(null);
  const [open, setOpen] = React.useState<Record<string, boolean>>({});
  const [busy, setBusy] = React.useState("");
  const [msg, setMsg] = React.useState("");
  /** 首次加载：链路还没回来时画骨架，别先显示「该时间窗内没有符合条件的链路」 */
  const [loading, setLoading] = React.useState(true);

  async function load() {
    errs.reset();
    const query = new URLSearchParams({
      minutes: String(minutes),
      suspicious_only: String(suspiciousOnly),
    });
    if (ip.trim()) query.set("ip", ip.trim());
    if (host.trim()) query.set("host", host.trim());
    if (params.get("from")) query.set("from_ts", params.get("from") || "");
    if (params.get("to")) query.set("to_ts", params.get("to") || "");
    await loadInto(errs, SRC.list, `/api/chains?${query.toString()}`, (d: ChainListPayload) => {
      setData(d);
      setOpen({});
    });
    setLoading(false);
  }

  React.useEffect(() => {
    void load();
    // 只在挂载与过滤条件变化时取数（load 内部自己收错误）
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [minutes, suspiciousOnly]);

  async function dispatch(chain: ChainItem) {
    setBusy(`${chain.client}|${chain.origin}`);
    setMsg("");
    try {
      const out = await apiFetch<{ delivered: boolean; error: string }>("/api/chains/dispatch", {
        method: "POST",
        body: JSON.stringify({
          client: chain.client,
          origin: chain.origin,
          path: chain.relay_path,
          minutes,
        }),
      });
      setMsg(
        out.delivered
          ? `已交给智能体深挖：${chain.client} → ${chain.origin}`
          : `交给智能体失败：${out.error || "未知原因"}`,
      );
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "交给智能体失败");
    } finally {
      setBusy("");
    }
  }

  return (
    <PageShell title="攻击链还原" fluid>
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="统计时间窗"
            className="h-9 rounded-sm border border-border bg-surface-2 px-2 text-sm text-foreground"
            value={minutes}
            onChange={(e) => setMinutes(Number(e.target.value))}
          >
            {WINDOWS.map((w) => (
              <option key={w.minutes} value={w.minutes}>
                {w.label}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-xs text-foreground">
            <input
              type="checkbox"
              className="h-4 w-4 accent-brand-500"
              checked={suspiciousOnly}
              onChange={(e) => setSuspiciousOnly(e.target.checked)}
            />
            只看可疑（签名命中 / 可疑事件类型 / 4xx-5xx / 带上传）
          </label>
          <Input
            aria-label="真实请求IP / 中继 / 源站"
            className="w-44"
            placeholder="真实请求IP / 中继 / 源站"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
          />
          <Input
            aria-label="源站域名（可选）"
            className="w-44"
            placeholder="源站域名（可选）"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
          <Button size="sm" onClick={() => void load()}>
            查询
          </Button>
          {data ? (
            <span className="text-xs tabular-nums text-muted-foreground">
              扫描 {data.scanned} 条事件 · 归并出 {data.chains.length} 条链路
              {data.truncated ? "（已截断，缩小时间窗更准）" : ""}
            </span>
          ) : null}
        </div>

        <PanelError errors={errs} />
        {msg ? <p className="text-sm text-primary">{msg}</p> : null}

        {loading && !data ? (
          <div className="space-y-3" aria-busy="true">
            {[0, 1, 2].map((i) => (
              <Card key={i}>
                <CardContent className="space-y-2 p-4">
                  <Skeleton className="h-4 w-1/3" />
                  <Skeleton className="h-3 w-2/3" />
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          <div className="space-y-3">
            {(data?.chains || []).map((chain) => {
              const key = `${chain.client}|${chain.origin}|${chain.relay_path.join(">")}`;
              const expanded = !!open[key];
              const facts = chain.facts || {};
              return (
                <Card
                  key={key}
                  className={cn(
                    // 语义色左边条区分可疑/常规：不用整块彩色背景，长列表里底色会盖过内容
                    "border-l-2",
                    chain.suspicious ? "border-l-sev-critical-fg" : "border-l-border",
                  )}
                >
                  <CardHeader className="space-y-1 pb-2">
                    <CardTitle className="flex flex-wrap items-center gap-2">
                      <Badge variant={chain.suspicious ? "critical" : "outline"}>
                        {chain.suspicious ? "可疑" : "常规"}
                      </Badge>
                      <span className="min-w-0 font-mono text-13 font-normal text-foreground">
                        {displayName(chain.client) || "客户端未记录"}
                        {chain.relay_path.length
                          ? ` → ${chain.relay_path.map(displayName).join(" → ")} → ${originLabel(chain, displayName)}`
                          : ` → ${originLabel(chain, displayName)}`}
                      </span>
                      <div className="ml-auto flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setOpen((prev) => ({ ...prev, [key]: !prev[key] }))}
                        >
                          {expanded ? "收起明细" : "展开明细"}
                        </Button>
                        <Button size="sm" disabled={busy !== ""} onClick={() => void dispatch(chain)}>
                          {busy === `${chain.client}|${chain.origin}` ? "提交中…" : "交给智能体"}
                        </Button>
                      </div>
                    </CardTitle>
                    <p className="text-xs tabular-nums text-muted-foreground">
                      {facts.events ?? 0} 条事件
                      {facts.first_seen ? ` · 起 ${formatDateTime(facts.first_seen)}` : ""}
                      {facts.last_seen ? ` · 止 ${formatDateTime(facts.last_seen)}` : ""}
                      {chain.client_state === "not_recorded" && chain.client_reason
                        ? ` · ${chain.client_reason}`
                        : ""}
                    </p>
                  </CardHeader>
                  {expanded ? (
                    <CardContent className="space-y-4 text-xs">
                      <div>
                        <p className="mb-2 text-xs font-medium text-foreground">链路逐段（按跳序）</p>
                        {/* 竖线 + 序号点表达“从哪来、经过谁、到哪去”，顺序是这张图的信息本身 */}
                        <ol className="space-y-2 border-l border-border-subtle pl-4">
                          {chain.segments.map((seg, idx) => (
                            <li key={`${seg.from}-${seg.to}-${idx}`} className="relative">
                              <span
                                aria-hidden
                                className="absolute -left-6 top-1 flex h-4 w-4 items-center justify-center rounded-full border border-border-subtle bg-surface-1 text-[10px] tabular-nums text-muted-foreground"
                              >
                                {idx + 1}
                              </span>
                              <div className="flex flex-wrap items-baseline gap-2">
                                <span className="font-mono text-foreground">
                                  {seg.from} → {seg.to}
                                </span>
                                <span className="text-muted-foreground">{segText(seg)}</span>
                              </div>
                            </li>
                          ))}
                        </ol>
                      </div>
                      <div>
                        <p className="mb-1 text-xs font-medium text-foreground">
                          攻击动作事实（全部来自 ES 事实）
                        </p>
                        <div className="leading-6">
                          {factLine("事件类型", facts.event_types)}
                          {factLine("状态码", facts.status_codes)}
                          {factLine("请求方法", facts.methods)}
                          {factLine("日志类型", facts.log_types)}
                        </div>
                        <div className="leading-6">
                          {factLine("命中签名", facts.signatures)}
                          {factLine("上传文件", facts.filenames)}
                          {factLine("DNS 查询", facts.dns_queries)}
                          {factLine("请求路径", facts.top_paths)}
                        </div>
                        {facts.clients?.length ? (
                          <p className="mt-1 text-muted-foreground">
                            归并到的请求 IP：{facts.clients.slice(0, 10).join("、")}
                            {facts.clients.length > 10 ? ` …共 ${facts.clients.length} 个` : ""}
                          </p>
                        ) : null}
                      </div>
                    </CardContent>
                  ) : null}
                </Card>
              );
            })}
            {!loading && !(data?.chains || []).length ? (
              <EmptyState
                title={
                  errs.isFailed(SRC.list) ? "链路读取失败" : "该时间窗内没有符合条件的链路"
                }
                hint={
                  errs.isFailed(SRC.list)
                    ? "见上方错误条：后端异常或网络不通时不能当成「没有链路」"
                    : "若「只看可疑」开着，可以关掉看全部链路；也可以放宽时间窗"
                }
                tone={errs.isFailed(SRC.list) ? "danger" : "muted"}
                action={
                  <>
                    <Button size="sm" variant="outline" onClick={() => void load()}>
                      重新查询
                    </Button>
                    {suspiciousOnly ? (
                      <Button size="sm" onClick={() => setSuspiciousOnly(false)}>
                        关闭「只看可疑」
                      </Button>
                    ) : null}
                  </>
                }
              />
            ) : null}
          </div>
        )}
      </div>
    </PageShell>
  );
}

// Next.js 构建要求：用了 useSearchParams() 的客户端组件必须包在 Suspense 边界里
// （否则 `next build` 直接失败：missing-suspense-with-csr-bailout）。
export default function ChainPage() {
  return (
    <React.Suspense fallback={null}>
      <ChainInner />
    </React.Suspense>
  );
}
