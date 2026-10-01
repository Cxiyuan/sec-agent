"use client";

import { PageShell } from "@/components/page-shell";
import { StatusPanel } from "@/components/status-panel";

/** 运行状态：队列积压、投递速率、推送重发、Redis 内存、Wazuh 入库量。 */
export default function StatusPage() {
  return (
    <PageShell
      title="运行状态"
      desc="链路活着没有、卡在哪一环。队列长度与 Redis 内存是最真实的故障前兆，这一页每 15 秒自动刷新。"
    >
      <StatusPanel />
    </PageShell>
  );
}
