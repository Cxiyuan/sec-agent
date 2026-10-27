"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Chart,
  Dialog,
  EmptyState,
  LoadingBlock,
  Section,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  apiFetch,
  chartTokens,
  formatDateTime,
} from "@shentong/ui";
import type { EChartsOption } from "echarts";
import { formatBytes } from "@/components/status-charts";
import { ArrowLeftRight } from "lucide-react";

import { PanelError, usePanelErrors } from "@/components/panel-error";
import { useAliases } from "@/lib/aliases";
import { layoutTopology, type NodeKind } from "@/lib/topology-layout";
import {
  EXTERNAL_HOST_ASPECT,
  EXTERNAL_HOST_SRC,
  EXTERNAL_HOST_SYMBOL,
  INTERNAL_HOST_SRC,
  INTERNAL_HOST_SYMBOL,
} from "@/lib/topology-icons";

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
  // 中心节点的主机名（后端 nodes[0] 不带 hostname，从表格行带进来，标签才不用只显示 IP）
  const [centerHost, setCenterHost] = React.useState("");
  // 画布实测尺寸：graph 的坐标是画布像素，必须知道容器多大才能铺满
  const [canvasSize, setCanvasSize] = React.useState({ w: 0, h: 0 });
  const canvasRef = React.useRef<HTMLDivElement | null>(null);
  const SRC = React.useMemo(() => ({ ips: `流量聚合（/api/traffic/ips?view=${view}）` }), [view]);
  // 图例色块复用图表色（与节点保持一致，切暗色跟着变）
  const t = chartTokens();

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
    async (ip: string, hostname?: string) => {
      setPeersLoading(true);
      setCenterHost(hostname && hostname !== ip ? hostname : "");
      // 先占位再请求：Dialog 立刻弹出来（骨架态），不会等一下才"咔"地出现
      setPeers({ center: ip, nodes: [], edges: [] });
      const res = await apiFetch<PeersResult>(
        `/api/traffic/peers?ip=${encodeURIComponent(ip)}&view=${view}&minutes=${minutes}&limit=${limit}`,
      ).catch(() => null);
      setPeersLoading(false);
      if (res) setPeers(res);
    },
    [minutes, view, limit],
  );

  // 画布尺寸跟随容器（Dialog 可拉伸、窗口可改大小、侧栏宽度是 CSS 变量）
  React.useEffect(() => {
    if (!peers) return;
    const el = canvasRef.current;
    if (!el) return;
    let raf = 0;
    const read = () => {
      const w = Math.round(el.clientWidth);
      const h = Math.round(el.clientHeight);
      // 首帧还没布局时是 0，等 ResizeObserver 下一轮，别用 0 去算坐标
      if (w < 4 || h < 4) return;
      setCanvasSize((prev) => (prev.w === w && prev.h === h ? prev : { w, h }));
    };
    raf = requestAnimationFrame(read);
    const ro = new ResizeObserver(read);
    ro.observe(el);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [peers]);

  const meta = VIEW_META[view];
  const rows = data?.items ?? [];

  // 标题与空态都要用到：内/外网各几个对端（后端 `internal` 按监控网段判定，恒为布尔）
  const peerList = peers ? peers.nodes.filter((n) => n.ip !== peers.center) : [];
  const internalCount = peerList.filter((n) => n.internal === true).length;
  const externalCount = peerList.length - internalCount;
  const peerCount = peerList.length;

  // 连接拓扑（2026-10 用户要求：**居中大画布**，不再是右侧抽屉）：
  // - 坐标直接算成**画布像素**；配合 series 四边钉 0 + 四角锚点，让 ECharts 的 view
  //   坐标系退化成 1:1 恒等映射（默认 viewRect 会留一圈边距，把整张图缩到 80% 居中）；
  // - **外网对端在上、内网对端在下**，各自连回中间那台中心服务器；
  // - 图标用桌面原稿：内网 = 服务器.svg（等距 3D 机架），外网 = bindBox.svg（云 + 链路）。
  //   两份稿子都是多色的，所以走 `image://` data URI 而不是单色 `path://`（见 lib/topology-icons.ts）；
  // - 直线；实线 = 双向流量已捕获，虚线 = 尝试连接但对方无响应回包（推测/未直接抓到）。
  const graphOption = React.useMemo<EChartsOption>(() => {
    if (!peers || canvasSize.w < 4 || canvasSize.h < 4) return {};
    // 颜色从 chartTokens() 取：图表蓝必须等于 UI 蓝，切暗色要跟着变
    const t = chartTokens();
    const center = peers.center;
    const peersOnly = peers.nodes.filter((n) => n.ip !== center);
    // 内外网分翼：`internal` 由后端按监控网段判定（恒为布尔）；缺字段时按外网处理，
    // 因为"不确定"的节点放在上翼不会污染内网那一侧的语义
    const internalNodes = peersOnly.filter((n) => n.internal === true);
    const externalNodes = peersOnly.filter((n) => n.internal !== true);
    const centerBytes = peers.nodes.find((n) => n.ip === center)?.bytes ?? 0;
    const placed = layoutTopology(
      canvasSize.w,
      canvasSize.h,
      center,
      centerHost,
      centerBytes,
      internalNodes,
      externalNodes,
    );

    // 四角透明锚点：只为把 view 坐标系的 boundingRect 钉成 [0,0,画布宽,画布高]。
    // 没有它们，bbox 只包住真实节点 → ECharts 会等比放大到铺满，图标尺寸跟着失真。
    // symbolSize:0 + silent 让它既不被画出来、也不吃 hover。
    const anchors = (
      [
        [0, 0],
        [canvasSize.w, 0],
        [0, canvasSize.h],
        [canvasSize.w, canvasSize.h],
      ] as const
    ).map(([x, y], i) => ({
      id: `__bbox_${i}`,
      name: "",
      x,
      y,
      symbol: "circle",
      symbolSize: 0,
      itemStyle: { opacity: 0 },
      label: { show: false },
      silent: true,
    }));

    const nodeData = placed.map((n) => ({
      id: n.ip,
      name: n.label,
      x: n.x,
      y: n.y,
      value: n.bytes,
      kind: n.kind,
      // 内网（含中心）用机架图标，外网用云图标 —— 区分靠**形状**，不靠色相：
      // 两份原稿都是蓝色系，再叠一层颜色语义只会让人以为颜色在说威胁等级
      symbol: n.kind === "external" ? EXTERNAL_HOST_SYMBOL : INTERNAL_HOST_SYMBOL,
      symbolSize: n.size,
      symbolKeepAspect: true,
      z: n.kind === "center" ? 20 : 10,
      label: {
        show: true,
        position: "bottom" as const,
        distance: n.kind === "center" ? 9 : 7,
        fontSize: n.kind === "center" ? 12 : 10,
        fontWeight: (n.kind === "center" ? "bold" : "normal") as "bold" | "normal",
        color: t.fg,
        lineHeight: n.kind === "center" ? 15 : 13,
        // 文字压到连线上也要读得清：给标签加一圈背景色描边当底衬
        textBorderColor: t.surface,
        textBorderWidth: 2,
      },
    }));

    const linkData = peers.edges.map((e) => {
      const bytesOut = (e as { bytes_out?: number }).bytes_out ?? 0;
      const bytesIn = (e as { bytes_in?: number }).bytes_in ?? 0;
      // 虚线 = 尝试连接但对方无响应回包（bytes_in === 0，推测/未直接抓到）
      const noResponse = bytesIn === 0;
      return {
        source: peers.center,
        target: e.target === peers.center ? e.source : e.target,
        value: e.bytes,
        bytesOut,
        bytesIn,
        inferred: noResponse,
        lineStyle: {
          width: Math.max(1, Math.min(7, Math.log10(1 + e.bytes) / 1.6)),
          color: t.series[0],
          opacity: noResponse ? 0.5 : 0.8,
          type: (noResponse ? "dashed" : "solid") as "dashed" | "solid",
          curveness: 0,
        },
      };
    });

    return {
      tooltip: {
        confine: true,
        formatter: (params: unknown) => {
          const item = params as {
            dataType?: string;
            data?: {
              name?: string;
              value?: number;
              kind?: NodeKind;
              bytesOut?: number;
              bytesIn?: number;
              inferred?: boolean;
            };
          };
          if (item.dataType === "edge") {
            // 线路：上下行分开报（用户明确要求）
            const inferred = Boolean(item.data?.inferred);
            return [
              "<b>链路流量</b>",
              `上行 ↑ ${formatBytes(Number(item.data?.bytesOut || 0))}`,
              `下行 ↓ ${formatBytes(Number(item.data?.bytesIn || 0))}`,
              `合计 ${formatBytes(Number(item.data?.value || 0))}`,
              inferred ? "⚠ 尝试连接但对方无响应回包（推测）" : "",
            ]
              .filter(Boolean)
              .join("<br/>");
          }
          const kind = item.data?.kind;
          // 四角锚点没有 kind：tooltip 直接返回空串，不弹一个只有流量 0 的空气泡
          if (kind !== "center" && kind !== "internal" && kind !== "external") return "";
          const where =
            kind === "center" ? "中心服务器" : kind === "internal" ? "内网（监控网段内）" : "外网（监控网段外）";
          return [
            `<b>${(item.data?.name ?? "").replace(/\n/g, "<br/>")}</b>`,
            where,
            `流量 ${formatBytes(Number(item.data?.value || 0))}`,
          ].join("<br/>");
        },
      },
      series: [
        {
          type: "graph" as const,
          // 位置全部手算成画布像素，不用 force：拖拽后不飘、刷新不跳
          layout: "none" as const,
          // 四条边钉死 0：viewRect 默认会内缩一圈（实测 1200×700 时是 80% 居中），
          // 钉死之后 viewRect == 容器，配合四角锚点，坐标映射就是恒等的
          left: 0,
          top: 0,
          right: 0,
          bottom: 0,
          roam: true,
          // 缩放范围收紧：默认能拉到看不出来是什么，画布已经铺满，只需要小幅微调
          scaleLimit: { min: 0.7, max: 3 },
          draggable: true,
          symbolKeepAspect: true,
          edgeSymbol: ["none", "arrow"],
          edgeSymbolSize: [0, 5],
          data: [...nodeData, ...anchors],
          links: linkData,
          labelLayout: { hideOverlap: true },
          emphasis: { focus: "adjacency", lineStyle: { width: 3, opacity: 1 } },
        },
      ],
    };
  }, [peers, canvasSize, centerHost]);

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
        help="按 IP 统计的流量排行"
        extra={
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-xs text-muted-foreground">
              时间范围
              <select
                value={minutes}
                onChange={(e) => setMinutes(Number(e.target.value))}
                className="ml-1 h-8 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
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
                className="ml-1 h-8 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
              >
                {[50, 100, 200, 300].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
            <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
              {loading ? "加载中…" : "刷新"}
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
              /* 首次加载：圆点转圈 + 加载中，不要把「正在读」显示成「没有流量」 */
              <LoadingBlock className="py-20" />
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
                    <TableHead className="w-10 select-none text-center">#</TableHead>
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
                  {rows.map((row, i) => (
                    <TableRow key={row.ip}>
                      <TableCell className="w-10 select-none text-center tabular-nums text-muted-foreground">
                        {i + 1}
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        {/* 主机名(IP) 整块可点：点开居中画布看连接拓扑（2026-10 用户要求，
                            不再单独给一列「拓扑」按钮）。hostname 一起带进去当中心标签 */}
                        <button
                          type="button"
                          title="点击查看该 IP 的连接拓扑"
                          onClick={() => void openPeers(row.ip, row.hostname)}
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

      {/* 居中大画布（2026-10 用户要求，原来是右侧 720px 抽屉）：
          抽屉只有 720×420 一块画布，节点全挤在中间；改成居中弹窗后画布随窗口走，
          「外网上翼 / 内网下翼」这种横向铺开的排布也才放得下。
          图例放 footer、正文只放画布 —— 画布内浮一层图例会盖住节点。 */}
      <Dialog
        open={!!peers}
        onClose={() => setPeers(null)}
        wrapperClassName="w-[min(1440px,94vw)]"
        widthClass="w-full h-[min(880px,88vh)] max-h-none"
        bodyClassName="flex-1 min-h-0 overflow-hidden p-0"
        title={
          <span className="flex min-w-0 flex-col">
            <span className="text-sm font-medium">{meta.title} · 连接拓扑</span>
            <span className="truncate font-mono text-xs font-normal text-muted-foreground">
              {peers?.center}
              {centerHost && centerHost !== peers?.center ? `（${centerHost}）` : ""} · 最近 {minutes}{" "}
              分钟 · {peerCount} 个对端
              {peerCount > 0 ? `（内网 ${internalCount} · 外网 ${externalCount}）` : ""}
            </span>
          </span>
        }
        footer={
          peers && peerCount > 0 ? (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <span
                  aria-hidden="true"
                  className="inline-block h-4 w-4 bg-contain bg-center bg-no-repeat"
                  style={{ backgroundImage: `url("${INTERNAL_HOST_SRC}")` }}
                />
                内网（监控网段内）
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span
                  aria-hidden="true"
                  className="inline-block h-4 w-[23px] bg-contain bg-center bg-no-repeat"
                  style={{ backgroundImage: `url("${EXTERNAL_HOST_SRC}")` }}
                />
                外网（监控网段外）
              </span>
              <span className="inline-flex items-center gap-1.5">
                <svg width="24" height="6" className="inline-block align-middle" aria-hidden="true">
                  <line x1="0" y1="3" x2="24" y2="3" stroke={t.series[0]} strokeWidth="2" />
                </svg>
                已捕获双向流量
              </span>
              <span className="inline-flex items-center gap-1.5">
                <svg width="24" height="6" className="inline-block align-middle" aria-hidden="true">
                  <line x1="0" y1="3" x2="24" y2="3" stroke={t.series[0]} strokeWidth="2" strokeDasharray="5 3" />
                </svg>
                对方无响应回包（推测）
              </span>
              <span className="ml-auto hidden sm:inline">线粗 = 流量 · 滚轮缩放 · 拖拽节点</span>
            </div>
          ) : null
        }
      >
        {/* 画布容器必须有确定高度：Chart 的 height="100%" 靠它，父级塌了图就成 0 高 */}
        <div ref={canvasRef} className="h-full w-full">
          {peersLoading ? (
            <LoadingBlock className="h-full" />
          ) : peers?.error ? (
            <div className="flex h-full items-center justify-center p-6">
              <EmptyState title="拓扑读取失败" hint={peers.error} tone="danger" />
            </div>
          ) : peerCount === 0 ? (
            <div className="flex h-full items-center justify-center p-6">
              <EmptyState
                title="该时间段内没有对端连接"
                hint="换一个时间范围再试；也可能是这条会话只有单向报文、对端地址没落进日志"
                tone="muted"
              />
            </div>
          ) : (
            <Chart option={graphOption} height="100%" />
          )}
        </div>
      </Dialog>
    </div>
  );
}
