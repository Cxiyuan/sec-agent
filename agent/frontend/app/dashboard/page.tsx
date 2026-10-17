"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Chart } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Badge, severityVariant } from "@shentong/ui";
import { apiFetch, type EventGroupItem, type PersistentItem } from "@/lib/api";
import { chartTokens, formatDateTime, severityText } from "@shentong/ui";
import type { EChartsOption } from "echarts";

export default function DashboardPage() {
  const [groups, setGroups] = React.useState<EventGroupItem[]>([]);
  const [persistent, setPersistent] = React.useState<PersistentItem[]>([]);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    let alive = true;
    apiFetch<{ items: EventGroupItem[] }>("/api/events/groups?limit=200")
      .then((d) => alive && setGroups(d.items))
      .catch(() => {})
      .finally(() => alive && setLoading(false));

    apiFetch<{ items: PersistentItem[] }>("/api/memories/persistent")
      .then((d) => alive && setPersistent(d.items))
      .catch(() => {});

    // 实时推送
    let ws: WebSocket | null = null;
    try {
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${window.location.host}/api/ws`);
      ws.onmessage = () => {
        apiFetch<{ items: EventGroupItem[] }>("/api/events/groups?limit=200")
          .then((d) => alive && setGroups(d.items))
          .catch(() => {});
      };
    } catch {
      /* WebSocket 不可用则仅靠轮询 */
    }
    return () => {
      alive = false;
      ws?.close();
    };
  }, []);

  const severityCount: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const srcCount: Record<string, number> = {};
  groups.forEach((g) => {
    const s = g.severity || "info";
    if (s in severityCount) severityCount[s] += 1;
    g.src_ips?.forEach((ip) => {
      srcCount[ip] = (srcCount[ip] || 0) + 1;
    });
  });

  // 图表颜色与徽章同源（sev-* 变量）：暗色下自动变亮，不再是 ECharts 默认那套彩虹色
  const t = chartTokens();

  const pieOption: EChartsOption = {
    tooltip: { trigger: "item", formatter: "{b}: {c} 个 ({d}%)" },
    series: [
      {
        type: "pie",
        // 实心饼 + 指引线标签：与运营中心总览页的严重度分布保持同一种读法
        radius: "58%",
        avoidLabelOverlap: true,
        label: { show: true, formatter: "{b} {c}" },
        labelLine: { show: true, length: 8, length2: 10, smooth: true },
        labelLayout: { hideOverlap: true },
        data: [
          { name: "严重", value: severityCount.critical, itemStyle: { color: t.sev.critical } },
          { name: "高危", value: severityCount.high, itemStyle: { color: t.sev.high } },
          { name: "中危", value: severityCount.medium, itemStyle: { color: t.sev.medium } },
          { name: "低危", value: severityCount.low, itemStyle: { color: t.sev.low } },
          { name: "信息", value: severityCount.info, itemStyle: { color: t.sev.info } },
        ].filter((d) => d.value > 0),
      },
    ],
  };

  const topIpOption: EChartsOption = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: 8, right: 12, top: 8, bottom: 8, containLabel: true },
    xAxis: { type: "category", data: Object.keys(srcCount).slice(0, 10) },
    yAxis: { type: "value" },
    series: [
      { type: "bar", barMaxWidth: 16, data: Object.values(srcCount).slice(0, 10), itemStyle: { color: t.series[0] } },
    ],
  };

  const scoreOption: EChartsOption = {
    tooltip: { trigger: "axis" },
    grid: { left: 8, right: 12, top: 8, bottom: 8, containLabel: true },
    xAxis: {
      type: "category",
      data: groups.slice(0, 20).map((g) => g.src_ips?.[0] || "?").map((s) => s.slice(0, 12)),
    },
    yAxis: { type: "value", max: 1 },
    series: [
      {
        type: "line",
        smooth: true,
        symbolSize: 4,
        data: groups.slice(0, 20).map((g) => g.triage_score),
        lineStyle: { width: 1.8, color: t.series[0] },
        itemStyle: { color: t.series[0] },
      },
    ],
  };

  const highGroups = groups
    .filter((g) => g.attack_chain?.stages?.length)
    .slice(0, 5);

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="mb-4 text-xl font-medium">驾驶舱</h1>
        {loading ? (
          <p className="text-muted-foreground">加载中…</p>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <Card><CardHeader className="pb-2"><CardTitle className="text-sm">事件组总数</CardTitle></CardHeader><CardContent className="text-28 font-medium tabular-nums">{groups.length}</CardContent></Card>
              <Card><CardHeader className="pb-2"><CardTitle className="text-sm">高危及以上</CardTitle></CardHeader><CardContent className="text-28 font-medium tabular-nums text-sev-critical-fg">{severityCount.critical + severityCount.high}</CardContent></Card>
              <Card><CardHeader className="pb-2"><CardTitle className="text-sm">待确认</CardTitle></CardHeader><CardContent className="text-28 font-medium tabular-nums text-sev-medium-fg">{groups.filter((g) => g.status === "pending_confirmation").length}</CardContent></Card>
              <Card><CardHeader className="pb-2"><CardTitle className="text-sm">涉及源 IP</CardTitle></CardHeader><CardContent className="text-28 font-medium tabular-nums">{Object.keys(srcCount).length}</CardContent></Card>
            </div>

            <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
              <Card><CardHeader className="pb-2"><CardTitle className="text-sm">定级分布</CardTitle></CardHeader><CardContent><Chart option={pieOption} height={224} /></CardContent></Card>
              <Card><CardHeader className="pb-2"><CardTitle className="text-sm">TOP 源 IP</CardTitle></CardHeader><CardContent><Chart option={topIpOption} height={224} /></CardContent></Card>
              <Card><CardHeader className="pb-2"><CardTitle className="text-sm">初筛得分</CardTitle></CardHeader><CardContent><Chart option={scoreOption} height={224} /></CardContent></Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle className="text-sm">持续性威胁（反复出现的 IP）</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {persistent.slice(0, 8).map((p) => (
                  <div key={p.ip} className="flex items-center justify-between text-sm">
                    <span className="font-mono">{p.ip}</span>
                    <span className="text-muted-foreground">
                      {p.count} 次
                      {p.last_seen ? ` · 最近 ${formatDateTime(p.last_seen)}` : ""}
                    </span>
                  </div>
                ))}
                {persistent.length === 0 && (
                  <p className="text-sm text-muted-foreground">暂无反复出现的 IP</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-sm">账号 / 会话基线</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <p className="text-sm text-muted-foreground">
                  基线（数值 2σ + 账号/会话画像）已在 NDR 侧计算，异常打到摘要标签上。
                </p>
                <p className="text-sm text-muted-foreground">
                  查看维度与异常排行请到 NDR 管理后台的「运行状态」页。
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="text-sm">攻击链概览</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                {highGroups.length === 0 && <p className="text-muted-foreground">暂无攻击链</p>}
                {highGroups.map((g) => (
                  <div key={g.id} className="rounded-md border p-3">
                    <div className="mb-2 flex items-center gap-2">
                      <Badge variant={severityVariant(g.severity)}>{severityText(g.severity)}</Badge>
                      <span className="text-sm font-medium">{g.src_ips?.join(", ")} → {g.dst_ips?.join(", ")}</span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {(g.attack_chain?.stages || []).map((s: any, i: number) => (
                        <span key={i} className="rounded bg-secondary px-2 py-1 text-xs">{s.stage}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        )}
      </main>
    </div>
  );
}
