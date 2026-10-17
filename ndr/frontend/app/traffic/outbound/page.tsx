"use client";

import { PageShell } from "@/components/page-shell";
import { TrafficPanel } from "@/components/traffic-panel";

/** 分析中心 → 可视化流量 → 对外业务流量（有侧边栏，属于流量视角分区）。 */
export default function Page() {
  return (
    <PageShell title="对外业务流量" desc="公网 → 监控网段资产的业务访问：地域、暴露端口、上下行与活跃时间。" fluid>
      <TrafficPanel view="outbound" />
    </PageShell>
  );
}
