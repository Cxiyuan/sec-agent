"use client";

import { PageShell } from "@/components/page-shell";
import { RelayNodesPanel } from "@/components/relay-nodes-panel";
import { ZeekPanel } from "@/components/zeek-panel";

/**
 * 监控网段：两件事 —— 上面是「抓什么」（网段 → BPF 与 Site::local_nets），
 * 下面是「怎么理解抓到的流量」（中继节点清单：代理头信任 + 中继去重）。
 */
export default function NetworksPage() {
  return (
    <PageShell
      title="监控网段"
      width="wide"
      desc="网络采集器只抓这些网段内的流量，检测也只分析它们。改动会同时更新抓包过滤器与本地网段定义。注意：这份清单只约束网络采集器抓包，不影响主机监控采到的主机日志。"
    >
      <ZeekPanel section="networks" />
      <RelayNodesPanel />
    </PageShell>
  );
}
