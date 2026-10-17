"use client";

import { PageShell } from "@/components/page-shell";
import { TrafficPanel } from "@/components/traffic-panel";

/** 分析中心 → 可视化流量 → 外连流量（有侧边栏，属于流量视角分区）。 */
export default function Page() {
  return (
    <PageShell title="外连流量" desc="监控网段主动访问公网：看内网主机联到了哪些外部地址。" fluid>
      <TrafficPanel view="egress" />
    </PageShell>
  );
}
