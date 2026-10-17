"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Chart,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  apiFetch,
  formatDateTime,
} from "@shentong/ui";
import type { EChartsOption } from "echarts";
import { formatBytes } from "@/components/status-charts";
import { ArrowLeftRight, Network, X } from "lucide-react";

import { PanelError, usePanelErrors } from "@/components/panel-error";
import { useAliases } from "@/lib/aliases";

/**
 * 可视化流量（分析中心）：三个视角共用一套表格与抽屉，只是「主语/对方/列」不同。
 *
 * - `outbound` 对外业务流量：公网 → 监控网段资产（看暴露面与访问地域）
 * - `lateral` 横向访问流量：监控网段内部之间的连接（看横向移动面）
 * - `egress` 外连流量：监控网段 → 公网（看外联行为）
 *
 * 表格列严格按用户口径：主机名(IP) / 地域 TOP5 / 总流量 / 上下行 / 应用 TOP10 /
 * 协议端口 TOP10 / 最新活跃；横向与外连额外给「不同对端 IP 数」，点行右侧出拓扑。
 */

type View = "outbound" | "lateral" | "egress";

interface PortRow {
  port: number;
  app: string;
  bytes: number;
}

interface PeerRow {
  ip: string;
  hostname?: string;
  bytes: number;
}

interface RegionRow {
  region: string;
  count: number;
}

interface IpRow {
  ip: string;
  hostname: string;
  bytes_out: number;
  bytes_in: number;
  bytes_total: number;
  conns: number;
  peers: number;
  ports: PortRow[];
  peers_top: PeerRow[];
  log_types: Array<{ value: string; count: number }>;
  last_seen: string;
  regions: RegionRow[];
}

interface IpResult {
  items: IpRow[];
  error?: string;
  warning?: string;
  geo_available?: boolean;
  note?: string;
  minutes?: number;
  monitored_nets?: string[];
}

interface PeerNode {
  ip: string;
  hostname?: string;
  internal?: boolean;
  bytes: number;
  role?: string;
}

interface PeersResult {
  center: string;
  nodes: PeerNode[];
  edges: Array<{ source: string; target: string; bytes: number }>;
  error?: string;
  warning?: string;
}

const VIEW_META: Record<View, { title: string; subject: string; peer: string }> = {
  outbound: { title: "对外业务流量", subject: "被访问资产", peer: "公网客户端" },
  lateral: { title: "横向访问流量", subject: "内网发起方", peer: "内网对端" },
  egress: { title: "外连流量", subject: "内网发起方", peer: "公网目标" },
};

/** 上下行对比条：两个方向按比例画（一眼看出是"下载多"还是"上传多"） */
function UpDownBar({ out, inb }: { out: number; inb: number }) {
  const total = Math.max(1, out + inb);
  const outPct = Math.round((out / total) * 100);
  return (
    <div className="min-w-[110px]">
      <div className="flex h-2 overflow-hidden rounded-full bg-muted">
        <span className="bg-primary" style={{ width: `${outPct}%` }} title={`上行 ${formatBytes(out)}`} />
        <span className="bg-emerald-500" style={{ width: `${100 - outPct}%` }} title={`下行 ${formatBytes(inb)}`} />
      </div>
      <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
        ↑{formatBytes(out)} / ↓{formatBytes(inb)}
      </p>
    </div>
  );
}

function PortChips({ ports }: { ports: PortRow[] }) {
  if (!ports.length) return <span className="text-xs text-muted-foreground">-</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {ports.slice(0, 10).map((p) => (
        <span
          key={`${p.port}-${p.app}`}
          className="rounded border px-1.5 py-0.5 text-[10px] text-muted-foreground"
          title={`${p.app}（${p.port}）${formatBytes(p.bytes)}`}
        >
          {p.app}（{p.port}）· {formatBytes(p.bytes)}
        </span>
      ))}
    </div>
  );
}

export function TrafficPanel({ view }: { view: View }) {
  const errs = usePanelErrors();
  useAliases();
  const [minutes, setMinutes] = React.useState(60);
  const [limit, setLimit] = React.useState(100);
  const [data, setData] = React.useState<IpResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [peers, setPeers] = React.useState<PeersResult | null>(null);
  const [peersLoading, setPeersLoading] = React.useState(false);
  const SRC = React.useMemo(() => ({ ips: `流量聚合（/api/traffic/ips?view=${view}）` }), [view]);

  const load = React.useCallback(async () => {
    setLoading(true);
    const res = await apiFetch<IpResult>(
      `/api/traffic/ips?view=${view}&minutes=${minutes}&limit=${limit}`,
    ).catch(() => null);
    setLoading(false);
    if (res) {
      errs.clear(SRC.ips);
      setData(res);
    } else {
      errs.fail(SRC.ips);
      setData(null);
    }
  }, [errs, limit, minutes, SRC.ips, view]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const openPeers = React.useCallback(
    async (ip: string) => {
      setPeersLoading(true);
      setPeers({ center: ip, nodes: [], edges: [] });
      const res = await apiFetch<PeersResult>(
        `/api/traffic/peers?ip=${encodeURIComponent(ip)}&view=${view}&minutes=${minutes}`,
      ).catch(() => null);
      setPeersLoading(false);
      if (res) setPeers(res);
    },
    [minutes, view],
  );

  const meta = VIEW_META[view];
  const rows = data?.items ?? [];

  const graphOption = React.useMemo<EChartsOption>(() => {
    if (!peers) return {};
    const center = peers.center;
    const nodeData = peers.nodes.map((n) => ({
      id: n.ip,
      name: n.ip,
      symbolSize: n.role === "center" ? 46 : Math.max(14, Math.min(34, 12 + Math.log10(1 + n.bytes) * 3)),
      itemStyle: {
        color:
          n.role === "center"
            ? "#1d4ed8"
            : n.internal
              ? "#0ea5e9"
              : "#94a3b8",
      },
      label: { show: true, fontSize: 9, formatter: n.ip },
    }));
    const linkData = peers.edges.map((e) => ({
      source: e.source === center ? center : e.target === center ? e.source : e.target,
      target: center,
      value: e.bytes,
      lineStyle: { width: Math.max(1, Math.min(6, Math.log10(1 + e.bytes) / 2)), opacity: 0.5 },
    }));
    return {
      tooltip: {
        formatter: (p: unknown) => {
          const item = p as { data?: { name?: string; value?: number }; dataType?: string };
          if (item.dataType === "edge") return formatBytes(Number(item.data?.value || 0));
          return String(item.data?.name || "");
        },
      },
      series: [
        {
          type: "graph" as const,
          layout: "force" as const,
          roam: true,
          draggable: true,
          force: { repulsion: 220, edgeLength: [60, 130], gravity: 0.08 },
          data: nodeData,
          links: linkData,
          emphasis: { focus: "adjacency" },
        },
      ],
    };
  }, [peers]);

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      <Card>
        <CardHeader className="flex-row flex-wrap items-center justify-between gap-2 pb-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <ArrowLeftRight className="h-4 w-4 text-primary" />
            {meta.title}
            <span className="text-xs font-normal text-muted-foreground">
              {meta.subject} ←→ {meta.peer}
            </span>
          </CardTitle>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <label>
              时间范围
              <select
                value={minutes}
                onChange={(e) => setMinutes(Number(e.target.value))}
                className="ml-1 h-8 rounded-md border bg-card px-2 text-sm text-foreground"
              >
                <option value={15}>15 分钟</option>
                <option value={60}>1 小时</option>
                <option value={360}>6 小时</option>
                <option value={1440}>24 小时</option>
              </select>
            </label>
            <label>
              条数
              <select
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="ml-1 h-8 rounded-md border bg-card px-2 text-sm text-foreground"
              >
                {[50, 100, 200, 300].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
            <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
              {loading ? "统计中…" : "刷新"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-2 p-0">
          {data?.error ? (
            <p className="mx-4 mt-3 rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {data.error}
            </p>
          ) : null}
          {data?.warning ? (
            <p className="mx-4 mt-3 rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {data.warning}
            </p>
          ) : null}
          {data?.note ? (
            <p className="mx-4 mt-3 rounded-md border border-amber-300/60 bg-amber-50 px-3 py-2 text-xs text-amber-700">
              {data.note}
            </p>
          ) : null}
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="whitespace-nowrap">主机名（IP）</TableHead>
                  <TableHead className="whitespace-nowrap">总流量</TableHead>
                  <TableHead className="whitespace-nowrap">上/下行</TableHead>
                  {view === "outbound" ? (
                    <TableHead className="whitespace-nowrap">访问地域 TOP5</TableHead>
                  ) : (
                    <TableHead className="whitespace-nowrap">不同对端 IP</TableHead>
                  )}
                  <TableHead className="whitespace-nowrap">应用 TOP10</TableHead>
                  <TableHead className="whitespace-nowrap">
                    {view === "outbound" ? "被访问端口 TOP10" : "对端端口 TOP10"}
                  </TableHead>
                  <TableHead className="whitespace-nowrap">最新活跃</TableHead>
                  <TableHead className="whitespace-nowrap">拓扑</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((row) => (
                  <TableRow key={row.ip}>
                    <TableCell className="whitespace-nowrap">
                      <span className="font-medium">{row.hostname || "-"}</span>
                      <span className="ml-1 font-mono text-xs text-muted-foreground">({row.ip})</span>
                    </TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs">
                      {formatBytes(row.bytes_total)}
                      <span className="ml-1 text-[10px] text-muted-foreground">
                        {row.conns} 条
                      </span>
                    </TableCell>
                    <TableCell>
                      <UpDownBar out={row.bytes_out} inb={row.bytes_in} />
                    </TableCell>
                    {view === "outbound" ? (
                      <TableCell className="max-w-[200px]">
                        <div className="flex flex-wrap gap-1">
                          {(row.regions.length ? row.regions : [{ region: "未知", count: 0 }])
                            .slice(0, 5)
                            .map((r) => (
                              <span
                                key={r.region}
                                className="rounded border px-1.5 py-0.5 text-[10px] text-muted-foreground"
                              >
                                {r.region}
                                {r.count ? `（${r.count}）` : ""}
                              </span>
                            ))}
                        </div>
                      </TableCell>
                    ) : (
                      <TableCell className="whitespace-nowrap text-xs">
                        <Badge variant="secondary">{row.peers}</Badge>
                      </TableCell>
                    )}
                    <TableCell className="max-w-[260px]">
                      <PortChips ports={row.ports} />
                    </TableCell>
                    <TableCell className="max-w-[260px]">
                      <PortChips ports={row.ports} />
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {formatDateTime(row.last_seen)}
                    </TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" onClick={() => void openPeers(row.ip)}>
                        <Network className="mr-1 h-3.5 w-3.5" />
                        查看
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {rows.length === 0 ? (
            <p className="px-4 py-10 text-center text-sm text-muted-foreground">
              {loading ? "统计中…" : errs.has ? "读取失败（见上方错误条）" : "该时间段内没有匹配的流量"}
            </p>
          ) : null}
        </CardContent>
      </Card>

      {/* 右侧抽屉：某个 IP 与对端的拓扑 */}
      {peers ? (
        <div className="fixed inset-0 z-50 flex justify-end">
          <button
            type="button"
            aria-label="关闭"
            className="flex-1 bg-slate-900/20"
            onClick={() => setPeers(null)}
          />
          <aside className="flex h-full w-[720px] max-w-[94vw] flex-col border-l bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b px-4 py-3">
              <div className="min-w-0">
                <p className="text-sm font-semibold">
                  {meta.title} · 连接拓扑
                </p>
                <p className="truncate font-mono text-[11px] text-muted-foreground">
                  {peers.center} · 最近 {minutes} 分钟 · {peers.nodes.length - 1} 个对端
                </p>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setPeers(null)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="min-h-0 flex-1 p-2">
              {peersLoading ? (
                <p className="p-4 text-xs text-muted-foreground">加载中…</p>
              ) : peers.error ? (
                <p className="p-4 text-xs text-destructive">{peers.error}</p>
              ) : (
                <Chart option={graphOption} height="100%" />
              )}
            </div>
            <div className="max-h-40 overflow-auto border-t px-4 py-2 text-[11px] text-muted-foreground">
              <p className="mb-1">
                中心：<span className="font-mono text-foreground">{peers.center}</span> ·
                蓝 = 中心 · 青 = 网段内 · 灰 = 网段外 · 连线粗细 = 流量
              </p>
              <div className="flex flex-wrap gap-2">
                {peers.edges.slice(0, 20).map((e) => (
                  <span key={`${e.source}-${e.target}`} className="rounded border px-1.5 py-0.5">
                    {e.target === peers.center ? e.source : e.target} · {formatBytes(e.bytes)}
                  </span>
                ))}
              </div>
            </div>
          </aside>
        </div>
      ) : null}
    </div>
  );
}
