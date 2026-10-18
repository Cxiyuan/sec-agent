"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import {
  Badge,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Chart,
  ChartSkeleton,
  EmptyState,
  Section,
  Skeleton,
  Stat,
  StatSkeleton,
  chartTokens,
  formatDateTime,
  severityText,
  severityVariant,
} from "@shentong/ui";
import { apiFetch, type EventGroupItem, type PersistentItem } from "@/lib/api";
import type { EChartsOption } from "echarts";

/** 图表卡：标题 14px + 固定三档高度，与 NDR 总览页的读法一致。 */
function ChartCard({
  title,
  height = 224,
  children,
}: {
  title: string;
  height?: number;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent style={{ minHeight: height }}>{children}</CardContent>
    </Card>
  );
}

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

  const noGroups = !loading && groups.length === 0;

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="mb-4 text-xl font-medium">驾驶舱</h1>

        <div className="space-y-4">
          <Section title="态势总览" description="最近 200 个事件组的定级、来源与初筛得分">
            <div className="space-y-3">
              {loading ? (
                <StatSkeleton count={4} />
              ) : (
                <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                  <Stat label="事件组总数" value={groups.length} hint="最近 200 个事件组" />
                  <Stat
                    label="高危及以上"
                    value={severityCount.critical + severityCount.high}
                    tone="critical"
                  />
                  <Stat
                    label="待确认"
                    value={groups.filter((g) => g.status === "pending_confirmation").length}
                    tone="medium"
                  />
                  <Stat label="涉及源 IP" value={Object.keys(srcCount).length} />
                </div>
              )}

              <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
                <ChartCard title="定级分布">
                  {loading ? (
                    <ChartSkeleton height={224} />
                  ) : noGroups ? (
                    <EmptyState size="compact" title="暂无事件组" hint="检测器产出后这里会显示定级分布" />
                  ) : (
                    <Chart option={pieOption} height={224} />
                  )}
                </ChartCard>
                <ChartCard title="TOP 源 IP">
                  {loading ? (
                    <ChartSkeleton height={224} />
                  ) : noGroups ? (
                    <EmptyState size="compact" title="暂无事件组" hint="没有可用于统计的来源地址" />
                  ) : (
                    <Chart option={topIpOption} height={224} />
                  )}
                </ChartCard>
                <ChartCard title="初筛得分">
                  {loading ? (
                    <ChartSkeleton height={224} />
                  ) : noGroups ? (
                    <EmptyState size="compact" title="暂无事件组" hint="没有可用于绘制的初筛得分" />
                  ) : (
                    <Chart option={scoreOption} height={224} />
                  )}
                </ChartCard>
              </div>
            </div>
          </Section>

          <Section title="持续性威胁" description="同一来源反复出现时进入这里">
            <Card>
              <CardContent className="space-y-2 pt-4">
                {loading ? (
                  <>
                    {Array.from({ length: 4 }).map((_, i) => (
                      <div key={i} className="flex items-center justify-between">
                        <Skeleton className="h-3 w-40" />
                        <Skeleton className="h-3 w-28" />
                      </div>
                    ))}
                  </>
                ) : persistent.length === 0 ? (
                  <EmptyState
                    size="compact"
                    title="暂无反复出现的 IP"
                    hint="同一来源在多轮检测中重复出现后会在这里列出"
                  />
                ) : (
                  persistent.slice(0, 8).map((p) => (
                    <div key={p.ip} className="flex items-center justify-between text-13">
                      <span className="font-mono">{p.ip}</span>
                      <span className="tabular-nums text-muted-foreground">
                        {p.count} 次
                        {p.last_seen ? ` · 最近 ${formatDateTime(p.last_seen)}` : ""}
                      </span>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </Section>

          <Section title="账号 / 会话基线">
            <Card>
              <CardContent className="space-y-2 pt-4 text-13 text-muted-foreground">
                <p>基线（数值 2σ + 账号/会话画像）已在 NDR 侧计算，异常打到摘要标签上。</p>
                <p>查看维度与异常排行请到 NDR 管理后台的「运行状态」页。</p>
              </CardContent>
            </Card>
          </Section>

          <Section title="攻击链概览" description="已有阶段结论的事件组（最多 5 组）">
            <Card>
              <CardContent className="space-y-3 pt-4">
                {loading ? (
                  <>
                    {Array.from({ length: 3 }).map((_, i) => (
                      <div key={i} className="space-y-2 rounded-xs bg-surface-1 p-3">
                        <Skeleton className="h-3 w-1/3" />
                        <Skeleton className="h-3 w-2/3" />
                      </div>
                    ))}
                  </>
                ) : highGroups.length === 0 ? (
                  <EmptyState
                    size="compact"
                    title="暂无攻击链"
                    hint="深度分析产出阶段结论后会在这里汇总"
                  />
                ) : (
                  highGroups.map((g) => (
                    <div key={g.id} className="rounded-xs bg-surface-1 p-3">
                      <div className="mb-2 flex flex-wrap items-center gap-2">
                        <Badge variant={severityVariant(g.severity)}>{severityText(g.severity)}</Badge>
                        <span className="text-13 font-medium">
                          {g.src_ips?.join(", ")} → {g.dst_ips?.join(", ")}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {(g.attack_chain?.stages || []).map((s: any, i: number) => (
                          <span
                            key={i}
                            className="rounded-xs border border-border-subtle bg-card px-2 py-0.5 text-xs"
                          >
                            {s.stage}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </Section>
        </div>
      </main>
    </div>
  );
}
