"use client";

import { PageShell } from "@/components/page-shell";
import { ZeekPanel } from "@/components/zeek-panel";
import { WazuhPanel } from "@/components/wazuh-panel";

/** 采集接入：Zeek 抓包的网卡 + Wazuh 主机的告警接入（两路数据最终都进同一份归一化队列）。 */
export default function CollectPage() {
  return (
    <PageShell
      title="采集接入"
      desc="数据从哪来：网络采集器抓包（网卡）与主机监控日志。抓包范围在「监控网段」页单独配置。"
    >
      <ZeekPanel section="iface" />
      <WazuhPanel />
    </PageShell>
  );
}
