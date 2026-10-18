"use client";

import { PageShell } from "@/components/page-shell";
import { EventsPanel } from "@/components/events-panel";

/**
 * 事件中心（一级菜单，位于资产中心之前；无侧边栏）：
 * 概览（stats）→ 筛选 → 列表 → 详情/处置。宽表工作台，所以 `width="full"`。
 *
 * 命中事件列表从运营中心迁到这里（UX 规范 §10）；运营中心保留三张趋势图，
 * 并在「威胁事件」区块留了跳转链接。
 */
export default function EventsPage() {
  return (
    <PageShell
      title="事件中心"
      desc="命中事件 · 检索 · 详情 · 处置"
      width="full"
    >
      <EventsPanel />
    </PageShell>
  );
}
