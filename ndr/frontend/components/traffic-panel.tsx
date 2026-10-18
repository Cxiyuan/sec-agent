"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Chart,
  ChartSkeleton,
  Drawer,
  EmptyState,
  Section,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
  apiFetch,
  chartTokens,
  formatDateTime,
} from "@shentong/ui";
import type { EChartsOption } from "echarts";
import { formatBytes } from "@/components/status-charts";
import { ArrowLeftRight } from "lucide-react";

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
  edges: Array<{ source: string; target: string; bytes: number; bytes_out?: number; bytes_in?: number }>;
  error?: string;
  warning?: string;
}

const VIEW_META: Record<View, { title: string; subject: string; peer: string }> = {
  outbound: { title: "对外业务流量", subject: "被访问资产", peer: "公网客户端" },
  lateral: { title: "横向访问流量", subject: "内网发起方", peer: "内网对端" },
  egress: { title: "外连流量", subject: "内网发起方", peer: "公网目标（含外连地域 TOP5）" },
};

/** 上下行对比条：两个方向按比例画（一眼看出是"下载多"还是"上传多"） */
function UpDownBar({ out, inb }: { out: number; inb: number }) {
  const total = Math.max(1, out + inb);
  const outPct = Math.round((out / total) * 100);
  return (
    <div className="min-w-[110px]">
      <div className="flex h-2 overflow-hidden rounded-full bg-surface-1">
        <span className="bg-primary" style={{ width: `${outPct}%` }} title={`上行 ${formatBytes(out)}`} />
        <span className="bg-sev-ok-fg" style={{ width: `${100 - outPct}%` }} title={`下行 ${formatBytes(inb)}`} />
      </div>
      <p className="mt-0.5 font-mono text-xs text-muted-foreground">
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
          className="rounded-xs bg-surface-1 px-1.5 py-0.5 text-xs text-muted-foreground"
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

  // 拓扑图（2026-10 用户要求）：
  // - **以当前选中的 IP 为中心**，其它 IP 环绕排布（手动算坐标，不用 force，位置稳定不飘）；
  // - 节点用**服务器图标**（不是圆圈）；
  // - 线路可读：鼠标移到线路上提示**上行/下行各多少**。
  const graphOption = React.useMemo<EChartsOption>(() => {
    if (!peers) return {};
    // 颜色从 chartTokens() 取（原来是 5 个硬编码 hex）：图表蓝必须等于 UI 蓝，切暗色要跟着变
    const t = chartTokens();
    const center = peers.center;
    const peersOnly = peers.nodes.filter((n) => n.ip !== center);
    const rings = peersOnly.length > 12 ? [230, 360] : [260];
    const perRing = Math.max(1, Math.ceil(peersOnly.length / rings.length));
    const maxBytes = Math.max(1, ...peersOnly.map((n) => n.bytes));
    // 服务器图标（堆叠机箱）：用作 symbol，颜色由 itemStyle 控制
    // 服务器图标：两个叠放的机箱（简单路径，避免小数点在源码里连成 IP 的样子）
    const SERVER_ICON = "path://M2 3h20v7H2zM2 14h20v7H2z";

    const nodeData: Array<Record<string, unknown>> = [
      {
        id: center,
        name: center,
        x: 0,
        y: 0,
        symbol: SERVER_ICON,
        symbolSize: [56, 56],
        symbolOffset: [0, 0],
        itemStyle: { color: t.series[0] },
        label: { show: true, position: "bottom", fontSize: 11, fontWeight: "bold", color: t.fg },
        category: "中心",
      },
    ];
    peersOnly.forEach((node, index) => {
      const ring = Math.floor(index / perRing);
      const radius = rings[Math.min(ring, rings.length - 1)];
      const inRing = Math.min(perRing, peersOnly.length - ring * perRing);
      const slot = index - ring * perRing;
      const angle = (slot / Math.max(1, inRing)) * Math.PI * 2 - Math.PI / 2;
      const weight = Math.log10(1 + node.bytes) / Math.log10(1 + maxBytes);
      nodeData.push({
        id: node.ip,
        name: node.hostname ? `${node.hostname}\n${node.ip}` : node.ip,
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
        symbol: SERVER_ICON,
        symbolSize: [26 + weight * 14, 26 + weight * 14],
        itemStyle: { color: node.internal ? t.series[1] : t.axis },
        label: { show: true, position: "bottom", fontSize: 9, color: t.axis },
        category: node.internal ? "网段内" : "网段外",
      });
    });

    const linkData = peers.edges.map((e) => ({
      source: peers.center,
      target: e.target === peers.center ? e.source : e.target,
      value: e.bytes,
      bytesOut: (e as { bytes_out?: number }).bytes_out ?? 0,
      bytesIn: (e as { bytes_in?: number }).bytes_in ?? 0,
      lineStyle: {
        width: Math.max(1, Math.min(7, Math.log10(1 + e.bytes) / 1.6)),
        color: t.track,
        opacity: 0.55,
        curveness: 0.06,
      },
    }));

    return {
      tooltip: {
        confine: true,
        formatter: (params: unknown) => {
          const item = params as {
            dataType?: string;
            data?: { name?: string; value?: number; bytesOut?: number; bytesIn?: number };
          };
          if (item.dataType === "edge") {
            // 线路：上下行分开报（用户明确要求）
            return [
              "<b>链路流量</b>",
              `上行 ↑ ${formatBytes(Number(item.data?.bytesOut || 0))}`,
              `下行 ↓ ${formatBytes(Number(item.data?.bytesIn || 0))}`,
              `合计 ${formatBytes(Number(item.data?.value || 0))}`,
            ].join("<br/>");
          }
          return `<b>${item.data?.name ?? ""}</b><br/>流量 ${formatBytes(Number(item.data?.value || 0))}`;
        },
      },
      series: [
        {
          type: "graph" as const,
          // 位置全部手算（以中心 IP 为原点画同心圆），不用 force：拖拽后不飘、刷新不跳
          layout: "none" as const,
          roam: true,
          draggable: true,
          symbolKeepAspect: true,
          edgeSymbol: ["none", "arrow"],
          edgeSymbolSize: [0, 6],
          data: nodeData,
          links: linkData,
          labelLayout: { hideOverlap: true },
          emphasis: { focus: "adjacency", lineStyle: { width: 3, opacity: 0.9 } },
        },
      ],
    };
  }, [peers]);

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      {/* L1 区块：视图名 + 口径说明交给 Section，时间范围/条数/刷新放 extra。
          三个视图共用这一套工具条，切换视图时控件位置不跳（原来标题和控件挤在卡片头部）。 */}
      <Section
        title={
          <span className="flex items-center gap-2">
            <ArrowLeftRight className="h-4 w-4 text-primary" aria-hidden="true" />
            {meta.title}
          </span>
        }
        description={`${meta.subject} ←→ ${meta.peer}`}
        extra={
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-xs text-muted-foreground">
              时间范围
              <select
                value={minutes}
                onChange={(e) => setMinutes(Number(e.target.value))}
                className="ml-1 h-8 rounded-sm border border-input bg-surface-2 px-2 text-sm text-foreground"
              >
                <option value={15}>15 分钟</option>
                <option value={60}>1 小时</option>
                <option value={360}>6 小时</option>
                <option value={1440}>24 小时</option>
                <option value={10080}>最近 7 天</option>
                <option value={21600}>最近 15 天</option>
                <option value={43200}>最近 30 天</option>
              </select>
            </label>
            <label className="text-xs text-muted-foreground">
              条数
              <select
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="ml-1 h-8 rounded-sm border border-input bg-surface-2 px-2 text-sm text-foreground"
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
        }
      >
        <Card>
          <CardContent className="space-y-2 p-0 pt-3">
            {/* 告警条用严重度三件套（原来的 destructive 透明度叠色在暗色端不可控） */}
            {data?.error ? (
              <p className="mx-4 rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg">
                {data.error}
              </p>
            ) : null}
            {data?.warning ? (
              <p className="mx-4 rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg">
                {data.warning}
              </p>
            ) : null}
            {data?.note ? (
              <p className="mx-4 rounded-xs border border-sev-medium-bd bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium-fg">
                {data.note}
              </p>
            ) : null}

            {!data && !errs.has ? (
              /* 首次加载：画表格骨架，不要把「正在统计」显示成「没有流量」 */
              <TableSkeleton rows={8} cols={6} />
            ) : rows.length === 0 ? (
              <EmptyState
                title={errs.isFailed(SRC.ips) ? "读取失败（见上方错误条）" : "该时间段内没有匹配的流量"}
                hint={
                  errs.isFailed(SRC.ips)
                    ? "点「刷新」重试；后端异常或网络不通时页面上的数字可能不是最新状态"
                    : "换一个时间范围，或把「条数」调大再试"
                }
                tone={errs.isFailed(SRC.ips) ? "danger" : "muted"}
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="whitespace-nowrap">主机名（IP）</TableHead>
                    <TableHead className="whitespace-nowrap">总流量</TableHead>
                    <TableHead className="whitespace-nowrap">上/下行</TableHead>
                    {view === "lateral" ? null : (
                      <TableHead className="whitespace-nowrap">
                        {view === "outbound" ? "访问地域 TOP5" : "外连地域 TOP5"}
                      </TableHead>
                    )}
                    {view === "outbound" ? null : (
                      <TableHead className="whitespace-nowrap">不同对端 IP</TableHead>
                    )}
                    <TableHead className="whitespace-nowrap">应用 TOP10</TableHead>
                    <TableHead className="whitespace-nowrap">
                      {view === "outbound" ? "被访问端口 TOP10" : "对端端口 TOP10"}
                    </TableHead>
                    <TableHead className="whitespace-nowrap">最新活跃</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((row) => (
                    <TableRow key={row.ip}>
                      <TableCell className="whitespace-nowrap">
                        {/* 主机名(IP) 整块可点：点开右侧抽屉看连接拓扑（2026-10 用户要求，
                            不再单独给一列「拓扑」按钮） */}
                        <button
                          type="button"
                          title="点击查看该 IP 的连接拓扑"
                          onClick={() => void openPeers(row.ip)}
                          className="cursor-pointer text-left text-primary underline-offset-2 hover:underline"
                        >
                          <span className="font-medium">{row.hostname || row.ip}</span>
                          {row.hostname ? (
                            <span className="ml-1 font-mono text-xs text-primary/80">({row.ip})</span>
                          ) : null}
                        </button>
                      </TableCell>
                      <TableCell className="whitespace-nowrap tabular-nums">
                        {formatBytes(row.bytes_total)}
                        <span className="ml-1 text-xs text-muted-foreground">{row.conns} 条</span>
                      </TableCell>
                      <TableCell>
                        <UpDownBar out={row.bytes_out} inb={row.bytes_in} />
                      </TableCell>
                      {view === "lateral" ? null : (
                        <TableCell className="max-w-[200px]">
                          {/* 对外业务：客户端的访问地域；外连：**目的 IP** 的地域（用户 2026-10 要求） */}
                          <div className="flex flex-wrap gap-1">
                            {(row.regions.length ? row.regions : [{ region: "未知", count: 0 }])
                              .slice(0, 5)
                              .map((r) => (
                                <span
                                  key={r.region}
                                  className="rounded-xs bg-surface-1 px-1.5 py-0.5 text-xs text-muted-foreground"
                                  title={
                                    view === "egress"
                                      ? "按对端目的 IP 统计的地域出现次数"
                                      : "按客户端 IP 统计的地域出现次数"
                                  }
                                >
                                  {r.region}
                                  {r.count ? `（${r.count}）` : ""}
                                </span>
                              ))}
                          </div>
                        </TableCell>
                      )}
                      {view === "outbound" ? null : (
                        <TableCell className="whitespace-nowrap tabular-nums">
                          <Badge variant="secondary">{row.peers}</Badge>
                        </TableCell>
                      )}
                      <TableCell className="max-w-[260px]">
                        <PortChips ports={row.ports} />
                      </TableCell>
                      <TableCell className="max-w-[260px]">
                        <PortChips ports={row.ports} />
                      </TableCell>
                      <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                        {formatDateTime(row.last_seen)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </Section>

      {/* 右侧抽屉：某个 IP 与对端的拓扑。换共享 Drawer 后焦点陷阱/Esc/锁滚动都齐了；
          图例放 footer，抽屉正文只放图，滚动条不会和图抢位置。 */}
      <Drawer
        open={!!peers}
        onClose={() => setPeers(null)}
        widthClass="w-[720px]"
        title={
          /* 标题节点用 span：Drawer 把 title 放进 <h2>，块级元素套在标题里不合语法 */
          <span className="flex min-w-0 flex-col">
            <span className="text-sm font-medium">{meta.title} · 连接拓扑</span>
            <span className="truncate font-mono text-xs font-normal text-muted-foreground">
              {peers?.center} · 最近 {minutes} 分钟 · {(peers?.nodes.length ?? 1) - 1} 个对端
            </span>
          </span>
        }
        footer={
          peers ? (
            <div className="max-h-40 overflow-auto text-xs text-muted-foreground">
              <p className="mb-1">
                中心：<span className="font-mono text-foreground">{peers.center}</span> · 深蓝 =
                中心 · 青 = 网段内 · 灰 = 网段外 · 连线粗细 = 流量 · 悬停线路看上下行
              </p>
              <div className="flex flex-wrap gap-2">
                {peers.edges.slice(0, 20).map((e) => (
                  <span key={`${e.source}-${e.target}`} className="rounded-xs bg-surface-1 px-1.5 py-0.5">
                    {e.target === peers.center ? e.source : e.target} · {formatBytes(e.bytes)}
                  </span>
                ))}
              </div>
            </div>
          ) : null
        }
      >
        {peersLoading ? (
          <ChartSkeleton height={360} />
        ) : peers?.error ? (
          <EmptyState title="拓扑读取失败" hint={peers.error} tone="danger" />
        ) : (
          <Chart option={graphOption} height={420} />
        )}
      </Drawer>
    </div>
  );
}
