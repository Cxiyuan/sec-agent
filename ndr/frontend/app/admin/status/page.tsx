"use client";

import { PageShell } from "@/components/page-shell";
import { StatusPanel } from "@/components/status-panel";

/**
 * 总览（默认落地页）：服务器状态 / 组件呼吸灯 / 威胁事件 / 24h 流量与协议 / 链路细节。
 * 路由仍是 `/admin/status`（第 7 期拆页时定的地址，不改以免破坏书签与文档引用）。
 */
export default function StatusPage() {
  return (
    <PageShell
      title="总览"
      desc="服务器资源、各组件连接状态、威胁事件、24 小时流量与协议占比、链路细节 —— 每 15 秒自动刷新；ES 侧的 24h 聚合与组件探测在后端各自缓存，不会每轮都打 ES。"
    >
      <StatusPanel />
    </PageShell>
  );
}
