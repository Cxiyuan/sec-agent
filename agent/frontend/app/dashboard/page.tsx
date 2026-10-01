"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Chart } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Badge, severityVariant } from "@shentong/ui";
import { apiFetch, type EventGroupItem, type PersistentItem } from "@/lib/api";
import { formatDateTime, severityText } from "@shentong/ui";
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

  const pieOption: EChartsOption = {
    tooltip: { trigger: "item" },
    series: [
      {
        type: "pie",
        radius: ["40%", "70%"],
        data: [
          { name: "紧急", value: severityCount.critical },
          { name: "高危", value: severityCount.high },
          { name: "中危", value: severityCount.medium },
          { name: "低危", value: severityCount.low },
          { name: "提示", value: severityCount.info },
        ],
      },
    ],
  };

  const topIpOption: EChartsOption = {
    tooltip: {},
    xAxis: { type: "category", data: Object.keys(srcCount).slice(0, 10) },
    yAxis: { type: "value" },
    series: [{ type: "bar", data: Object.values(srcCount).slice(0, 10) }],
  };

  const scoreOption: EChartsOption = {
    tooltip: {},
    xAxis: { type: "category", data: groups.slice(0, 20).map((g) => g.src_ips?.[0] || "?").map((s) => s.slice(0, 12)) },
    yAxis: { type: "value", max: 1 },
    series: [{ type: "line", data: groups.slice(0, 20).map((g) => g.triage_score) }],
  };

  const highGroups = groups
    .filter((g) => g.attack_chain?.stages?.length)
    .slice(0, 5);

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="mb-4 text-2xl font-bold">驾驶舱</h1>
        {loading ? (
          <p className="text-muted-foreground">加载中…</p>
        ) : (
          <>
            <div className="mb-4 grid grid-cols-4 gap-4">
              <Card><CardHeader><CardTitle className="text-sm">事件组总数</CardTitle></CardHeader><CardContent className="text-3xl font-bold">{groups.length}</CardContent></Card>
              <Card><CardHeader><CardTitle className="text-sm">高危及以上</CardTitle></CardHeader><CardContent className="text-3xl font-bold text-red-400">{severityCount.critical + severityCount.high}</CardContent></Card>
              <Card><CardHeader><CardTitle className="text-sm">待确认</CardTitle></CardHeader><CardContent className="text-3xl font-bold text-amber-400">{groups.filter((g) => g.status === "pending_confirmation").length}</CardContent></Card>
              <Card><CardHeader><CardTitle className="text-sm">涉及源 IP</CardTitle></CardHeader><CardContent className="text-3xl font-bold">{Object.keys(srcCount).length}</CardContent></Card>
            </div>

            <div className="mb-4 grid grid-cols-3 gap-4">
              <Card><CardHeader><CardTitle className="text-sm">定级分布</CardTitle></CardHeader><CardContent><Chart option={pieOption} height={260} /></CardContent></Card>
              <Card><CardHeader><CardTitle className="text-sm">TOP 源 IP</CardTitle></CardHeader><CardContent><Chart option={topIpOption} height={260} /></CardContent></Card>
              <Card><CardHeader><CardTitle className="text-sm">初筛得分</CardTitle></CardHeader><CardContent><Chart option={scoreOption} height={260} /></CardContent></Card>
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
          </>
        )}
      </main>
    </div>
  );
}
