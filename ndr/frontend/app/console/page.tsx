"use client";

import { PageShell } from "@/components/page-shell";
import { StatusPanel } from "@/components/status-panel";

/**
 * 总览（默认落地页）：服务器状态 / 组件呼吸灯 / 威胁事件 / 24h 流量与协议 / 链路细节。
 * 正式路由 `/console`；旧地址 `/admin/status` 由 next.config.mjs 的 307 兜住（兼容书签与文档引用）。
 */
export default function StatusPage() {
  return (
    <PageShell title="总览" desc="" fluid>
      <StatusPanel />
    </PageShell>
  );
}
