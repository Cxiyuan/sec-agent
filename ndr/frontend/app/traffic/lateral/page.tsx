"use client";

import { PageShell } from "@/components/page-shell";
import { TrafficPanel } from "@/components/traffic-panel";

/** 分析中心 → 可视化流量 → 横向访问流量（有侧边栏，属于流量视角分区）。 */
export default function Page() {
  return (
    <PageShell title="横向访问流量" desc="监控网段内部之间的连接：看谁在横向访问谁（点「查看」出拓扑）。" fluid>
      <TrafficPanel view="lateral" />
    </PageShell>
  );
}
