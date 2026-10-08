"use client";

import * as React from "react";
import type { EChartsOption } from "echarts";
import { Nav } from "@/components/nav";
import { TopBar } from "@/components/topbar";
import { PanelError, loadInto, usePanelErrors } from "@/components/panel-error";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Chart,
  Dialog,
  Input,
  apiFetch,
  ApiError,
  errorText,
  formatDateTime,
} from "@shentong/ui";
import { aliasOf, applyAliases, displayName, loadAliases } from "@/lib/aliases";
import type { TopologyNode, TopologyPayload } from "@/lib/api";

/**
 * 拓扑发现：自动发现并画出网络拓扑。
 *
 * 两个视图（同一份数据、两种看法）：
 * - **转发链路**（默认）：以**流量转发的逻辑**为准 —— 客户端 →（中继…）→ 源站，多级串联一定体现；
 * - **全量通信**：所有 src→dst 按流量 TopN，节点多，用来在整张网里看中继的位置。
 *
 * 节点默认显示名**就是 IP**（host 名不可靠，只作提示）；点节点可起自定义名，**全局生效**
 * （其它页面展示该 IP 时也显示别名，真实 IP 仍在图标/提示里）。
 */

const SRC = { graph: "拓扑图（/api/topology）", aliases: "节点别名" } as const;

const WINDOWS: Array<{ label: string; minutes: number }> = [
  { label: "近 15 分钟", minutes: 15 },
  { label: "近 1 小时", minutes: 60 },
  { label: "近 6 小时", minutes: 360 },
  { label: "近 24 小时", minutes: 1440 },
];

const KIND_LABEL: Record<string, string> = {
  relay: "中继",
  client: "入口（客户端侧）",
  origin: "源站",
  transit: "两端都出现",
  endpoint: "普通端点",
  internal: "内网",
  external: "公网",
};

function kindLabel(kind: string): string {
  return KIND_LABEL[kind] || kind || "未知";
}

export default function TopologyPage() {
  const errs = usePanelErrors();
  const [mode, setMode] = React.useState<"forward" | "full">("forward");
  const [minutes, setMinutes] = React.useState(60);
  const [data, setData] = React.useState<TopologyPayload | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [query, setQuery] = React.useState("");
  /** 正在改名的节点（null = 对话框关闭） */
  const [editing, setEditing] = React.useState<{ ip: string; name: string } | null>(null);

  async function load() {
    errs.reset();
    await loadAliases();
    await loadInto(
      errs,
      SRC.graph,
      `/api/topology?mode=${mode}&minutes=${minutes}&hours=${Math.max(1, Math.round(minutes / 60))}`,
      (d: TopologyPayload) => setData(d),
    );
  }

  React.useEffect(() => {
    void load();
    // 只在视图/时间窗变化时取数（load 内部自己收错误）
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, minutes]);

  async function saveAlias() {
    if (!editing) return;
    setBusy(true);
    setMsg("");
    try {
      const out = await apiFetch<{ aliases: Record<string, string> }>("/api/topology/aliases", {
        method: "PUT",
        body: JSON.stringify({ ip: editing.ip, name: editing.name }),
      });
      // 立即全局生效：其它页面（攻击链、资产/画像）也跟着显示别名
      applyAliases(out.aliases || {});
      setMsg(editing.name.trim() ? `已把 ${editing.ip} 命名为「${editing.name.trim()}」` : `已清除 ${editing.ip} 的别名`);
      setEditing(null);
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  const nodes = data?.nodes || [];
  const edges = data?.edges || [];
  const filtered = query.trim()
    ? nodes.filter((n) => n.id.includes(query.trim()) || aliasOf(n.id).includes(query.trim()))
    : nodes;

  const option: EChartsOption = React.useMemo(() => {
    const maxEvents = Math.max(1, ...nodes.map((n) => n.events));
    const categoryOf = (kind: string): number => {
      const order = ["relay", "origin", "client", "transit", "endpoint", "internal", "external"];
      const idx = order.indexOf(kind);
      return idx < 0 ? order.length - 1 : idx;
    };
    return {
      tooltip: {
        formatter: (p: unknown) => {
          const node = (p as { data?: { id?: string; events?: number; kind?: string } }).data;
          if (!node || !node.id) {
            const edge = (p as { data?: { source?: string; target?: string; value?: number } }).data;
            return edge?.source ? `${edge.source} → ${edge.target}<br/>事件 ${edge.value ?? 0}` : "";
          }
          const alias = aliasOf(node.id);
          return [
            `<b>${alias || node.id}</b>`,
            alias ? `真实 IP：${node.id}` : "",
            `类型：${kindLabel(String(node.kind || ""))}`,
            `事件：${node.events ?? 0}`,
            "点击可改显示名",
          ]
            .filter(Boolean)
            .join("<br/>");
        },
      },
      legend: [{ data: ["中继", "源站", "入口（客户端侧）", "普通端点"], textStyle: { fontSize: 11 } }],
      series: [
        {
          type: "graph",
          layout: "force",
          roam: true,
          draggable: true,
          force: { repulsion: 260, edgeLength: [90, 170], gravity: 0.06 },
          label: { show: true, fontSize: 11, position: "right" },
          edgeSymbol: ["none", "arrow"],
          edgeSymbolSize: 6,
          lineStyle: { width: 1.2, curveness: 0.06, opacity: 0.7 },
          emphasis: { focus: "adjacency", lineStyle: { width: 3 } },
          categories: [
            { name: "中继", itemStyle: { color: "#f59e0b" } },
            { name: "源站", itemStyle: { color: "#0ea5e9" } },
            { name: "入口（客户端侧）", itemStyle: { color: "#22c55e" } },
            { name: "普通端点", itemStyle: { color: "#94a3b8" } },
          ],
          data: nodes.map((n: TopologyNode) => ({
            id: n.id,
            name: n.id,
            // label 用展示名（别名优先，没有别名就是 IP —— 绝不用 host 名）
            label: { formatter: displayName(n.id) },
            category: Math.min(3, categoryOf(n.kind)),
            events: n.events,
            kind: n.kind,
            symbolSize: 12 + 26 * Math.sqrt(Math.max(0, n.events) / maxEvents),
          })),
          links: edges.map((e) => ({
            source: e.source,
            target: e.target,
            value: e.events,
            // 推导出来的转发关系（没直接抓到）用虚线，别让人以为是实测
            lineStyle: e.kind === "inferred" ? { type: "dashed" } : undefined,
          })),
        },
      ],
    };
  }, [nodes, edges]);

  return (
    <div className="min-h-screen">
      <TopBar />
      <Nav />
      <main className="ml-56 px-6 pb-6 pt-20">
        <h1 className="mb-2 text-2xl font-bold">拓扑发现</h1>
        <p className="mb-4 text-xs text-muted-foreground">
          自动发现网络拓扑：<b>转发链路</b>视图以流量转发的逻辑为准（客户端 →（中继…）→ 源站，多级串联都体现）；
          <b>全量通信</b>视图按流量把整张网画出来。节点默认显示 IP，点节点可起自定义名（全局生效，真实 IP 始终可查）。
        </p>

        <div className="mb-4 flex flex-wrap items-center gap-2">
          <div className="flex gap-1">
            <Button
              size="sm"
              variant={mode === "forward" ? "default" : "outline"}
              onClick={() => setMode("forward")}
            >
              转发链路
            </Button>
            <Button
              size="sm"
              variant={mode === "full" ? "default" : "outline"}
              onClick={() => setMode("full")}
            >
              全量通信
            </Button>
          </div>
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
          <Input
            className="h-9 w-48"
            placeholder="搜索 IP 或别名"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <Button size="sm" variant="outline" onClick={() => void load()}>
            刷新
          </Button>
          <Badge variant="outline">
            {nodes.length} 节点 / {edges.length} 边
          </Badge>
          {data?.scanned ? (
            <span className="text-xs text-muted-foreground">扫描 {data.scanned} 条事件</span>
          ) : null}
          {data?.cached ? <Badge variant="outline">缓存结果</Badge> : null}
          {data?.computed_at ? (
            <span className="text-xs text-muted-foreground">
              计算于 {formatDateTime(data.computed_at)}
            </span>
          ) : null}
        </div>

        <div className="mb-3">
          <PanelError errors={errs} />
        </div>
        {data?.note ? (
          <p className="mb-3 rounded-md border border-amber-900 bg-amber-950/30 px-3 py-2 text-xs">
            {data.note}
          </p>
        ) : null}
        {data?.error ? (
          <p className="mb-3 rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            取图失败：{data.error}
          </p>
        ) : null}
        {msg ? <p className="mb-3 text-sm">{msg}</p> : null}

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">
              {mode === "forward" ? "转发链路图（按流量转发关系）" : "全量通信图（按流量 TopN）"}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {nodes.length ? (
              <Chart
                option={option}
                height={560}
                onEvents={{
                  click: (params: unknown) => {
                    const id = (params as { data?: { id?: string } })?.data?.id;
                    if (id) setEditing({ ip: id, name: aliasOf(id) });
                  },
                }}
              />
            ) : (
              <p className="py-10 text-center text-sm text-muted-foreground">
                {mode === "forward"
                  ? "这个时间窗内没有转发关系（没配中继清单时转发视图为空，可切「全量通信」看全部通信）"
                  : "这个时间窗内没有可画的通信关系"}
              </p>
            )}
          </CardContent>
        </Card>

        {nodes.length ? (
          <Card className="mt-3">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">节点（点一行即可改名）</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {filtered.map((n) => (
                  <button
                    key={n.id}
                    type="button"
                    className="rounded-md border px-2 py-1 text-left text-xs hover:bg-muted/40"
                    onClick={() => setEditing({ ip: n.id, name: aliasOf(n.id) })}
                  >
                    <span className="font-mono">{displayName(n.id)}</span>
                    {aliasOf(n.id) ? (
                      <span className="ml-1 font-mono text-muted-foreground">{n.id}</span>
                    ) : null}
                    <span className="ml-2 text-muted-foreground">
                      {kindLabel(n.kind)}
                      {typeof n.level === "number" && n.level >= 0 ? ` · L${n.level}` : ""} · {n.events} 事件
                    </span>
                  </button>
                ))}
              </div>
              {query && !filtered.length ? (
                <p className="text-xs text-muted-foreground">没有匹配的节点</p>
              ) : null}
            </CardContent>
          </Card>
        ) : null}

        <Dialog
          open={editing !== null}
          title="节点显示名"
          onClose={() => setEditing(null)}
          footer={
            <div className="flex items-center gap-2">
              <Button disabled={busy} onClick={() => void saveAlias()}>
                保存
              </Button>
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => setEditing((prev) => (prev ? { ...prev, name: "" } : prev))}
              >
                清除别名
              </Button>
              <Button variant="ghost" onClick={() => setEditing(null)}>
                取消
              </Button>
            </div>
          }
        >
          <div className="space-y-3 text-sm">
            <div>
              <div className="text-xs text-muted-foreground">真实 IP（不可改）</div>
              <div className="font-mono">{editing?.ip}</div>
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                显示名（默认就是 IP；留空 = 恢复显示 IP；最长 64 字）
              </label>
              <Input
                autoFocus
                value={editing?.name || ""}
                placeholder={editing?.ip || ""}
                onChange={(e) =>
                  setEditing((prev) => (prev ? { ...prev, name: e.target.value } : prev))
                }
                onKeyDown={(e) => {
                  if (e.key === "Enter") void saveAlias();
                }}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              别名是展示层数据：保存后<b>全局生效</b>（拓扑图、攻击链还原、资产/画像里都显示别名），
              真实 IP 始终保留可查。
            </p>
          </div>
        </Dialog>
      </main>
    </div>
  );
}
