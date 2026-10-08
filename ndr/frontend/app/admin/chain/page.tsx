"use client";

import * as React from "react";
import { useSearchParams } from "next/navigation";
import { Nav } from "@/components/nav";
import { TopBar } from "@/components/topbar";
import { PanelError, loadInto, usePanelErrors } from "@/components/panel-error";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Input, apiFetch, ApiError, errorText, formatDateTime } from "@shentong/ui";
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
    <div className="min-h-screen">
      <TopBar />
      <Nav />
      <main className="ml-56 px-6 pb-6 pt-20">
        <h1 className="mb-2 text-2xl font-bold">攻击链还原</h1>
        <p className="mb-4 text-xs text-muted-foreground">
          还原「真实请求IP →（中继…）→ 源站」的完整数据链路与攻击动作事实。只展示**真正进了检测**的事件；
          中继路径由上下级拓扑推导，每段都标注证据来源（直连观测 / 代理头证据 / 拓扑推导）。
        </p>

        <div className="mb-4 flex flex-wrap items-center gap-2">
          <select
            className="h-9 rounded-md border bg-transparent px-2 text-sm"
            value={minutes}
            onChange={(e) => setMinutes(Number(e.target.value))}
          >
            {WINDOWS.map((w) => (
              <option key={w.minutes} value={w.minutes}>
                {w.label}
              </option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              className="h-4 w-4"
              checked={suspiciousOnly}
              onChange={(e) => setSuspiciousOnly(e.target.checked)}
            />
            只看可疑（签名命中 / 可疑事件类型 / 4xx-5xx / 带上传）
          </label>
          <Input
            className="h-9 w-44"
            placeholder="真实请求IP / 中继 / 源站"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
          />
          <Input
            className="h-9 w-44"
            placeholder="源站域名（可选）"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
          <Button size="sm" onClick={() => void load()}>
            查询
          </Button>
          {data ? (
            <span className="text-xs text-muted-foreground">
              扫描 {data.scanned} 条事件 · 归并出 {data.chains.length} 条链路
              {data.truncated ? "（已截断，缩小时间窗更准）" : ""}
            </span>
          ) : null}
        </div>

        <div className="mb-3">
          <PanelError errors={errs} />
        </div>
        {msg ? <p className="mb-3 text-sm">{msg}</p> : null}

        <div className="space-y-3">
          {(data?.chains || []).map((chain) => {
            const key = `${chain.client}|${chain.origin}|${chain.relay_path.join(">")}`;
            const expanded = !!open[key];
            const facts = chain.facts || {};
            return (
              <Card key={key}>
                <CardHeader className="pb-2">
                  <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
                    <Badge variant={chain.suspicious ? "critical" : "outline"}>
                      {chain.suspicious ? "可疑" : "常规"}
                    </Badge>
                    <span className="font-mono">
                      {displayName(chain.client) || "未知请求IP"}
                      {chain.relay_path.length
                        ? ` → ${chain.relay_path.map(displayName).join(" → ")} → ${displayName(chain.origin) || "源站"}`
                        : ` → ${displayName(chain.origin) || "源站"}`}
                    </span>
                    <span className="text-xs font-normal text-muted-foreground">
                      {facts.events ?? 0} 条事件
                      {facts.first_seen ? ` · 起 ${formatDateTime(facts.first_seen)}` : ""}
                      {facts.last_seen ? ` · 止 ${formatDateTime(facts.last_seen)}` : ""}
                    </span>
                    <div className="ml-auto flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() =>
                          setOpen((prev) => ({ ...prev, [key]: !prev[key] }))
                        }
                      >
                        {expanded ? "收起明细" : "展开明细"}
                      </Button>
                      <Button
                        size="sm"
                        disabled={busy !== ""}
                        onClick={() => void dispatch(chain)}
                      >
                        {busy === `${chain.client}|${chain.origin}` ? "提交中…" : "交给智能体"}
                      </Button>
                    </div>
                  </CardTitle>
                </CardHeader>
                {expanded ? (
                  <CardContent className="space-y-3 text-xs">
                    <div>
                      <div className="mb-1 text-muted-foreground">链路逐段（证据来源）</div>
                      <ul className="space-y-1">
                        {chain.segments.map((seg, idx) => (
                          <li key={`${seg.from}-${seg.to}-${idx}`} className="font-mono">
                            {seg.from} → {seg.to}
                            <span className="ml-2 text-muted-foreground">{segText(seg)}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <div className="mb-1 text-muted-foreground">攻击动作事实（全部来自 ES 事实）</div>
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
                        <div className="mt-1 text-muted-foreground">
                          归并到的请求 IP：{facts.clients.slice(0, 10).join("、")}
                          {facts.clients.length > 10 ? ` …共 ${facts.clients.length} 个` : ""}
                        </div>
                      ) : null}
                    </div>
                  </CardContent>
                ) : null}
              </Card>
            );
          })}
          {data && !data.chains.length ? (
            <p className="text-sm text-muted-foreground">
              该时间窗内没有符合条件的链路。若「只看可疑」开着，可以关掉看全部链路。
            </p>
          ) : null}
        </div>
      </main>
    </div>
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
