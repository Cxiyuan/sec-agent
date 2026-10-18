"use client";

import { PageShell } from "@/components/page-shell";
import { ZeekPanel } from "@/components/zeek-panel";

export default function CollectPage() {
  return (
    <PageShell
      title="采集接入"
      width="standard"
      desc="数据从哪来：网络采集器抓包（网卡）与主机监控日志。抓包范围在「监控网段」页单独配置。"
    >
      <ZeekPanel section="iface" />
    </PageShell>
  );
}
