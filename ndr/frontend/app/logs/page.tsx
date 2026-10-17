"use client";

import { PageShell } from "@/components/page-shell";
import { LogsPanel } from "@/components/logs-panel";

/**
 * 分析中心 → 日志检索（无侧边栏）：上面检索条件、下面日志列表，点一行右侧出详情。
 * 大表格铺满宽度，所以 `fluid`。
 */
export default function LogsPage() {
  return (
    <PageShell
      title="日志检索"
      desc="按归一化后的字段检索 ES 日志：时间窗 + 关键字 + 字段过滤，点任意一行看完整内容。"
      fluid
    >
      <LogsPanel />
    </PageShell>
  );
}
