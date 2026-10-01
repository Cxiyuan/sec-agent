"use client";

import { PageShell } from "@/components/page-shell";
import { ZeekPanel } from "@/components/zeek-panel";

/** 监控网段：抓包范围与检测分析范围的唯一来源（BPF 与 Site::local_nets 都由它生成）。 */
export default function NetworksPage() {
  return (
    <PageShell
      title="监控网段"
      desc="Zeek 只抓这些网段内的流量，检测也只分析它们。改动会同时更新抓包过滤器与本地网段定义。注意：这份清单只约束 Zeek 抓包，不影响 Wazuh 采到的主机日志。"
    >
      <ZeekPanel section="networks" />
    </PageShell>
  );
}
