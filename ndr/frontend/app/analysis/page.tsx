"use client";

import { AnalysisPanel } from "@/components/analysis-panel";
import { PageShell } from "@/components/page-shell";

/**
 * 派工队列（`/analysis`）：客观线索队列 + 智能体结论 + 覆盖率 + 对象清单 + 预算参数。
 *
 * 为什么单页不拆子路由：这一页是「盯屏 + 偶尔深挖」，把「队列」和「验收指标」拆开会让
 * 运维在两个地址之间来回跳；结论量再大（>5k）才值得拆出 `/analysis/results`。
 *
 * 无侧边栏（单页 + 三个浮层），与行为画像一致 —— 宽表需要整幅宽度。
 */
export default function AnalysisPage() {
  return (
    <PageShell
      title="派工队列"
      width="wide"
      desc="分析机制：队列里是客观线索（首见 / 自身基线偏离 / 盲区 / 规则命中），只含事实与客观强度，不含严重度与结论。界面只做浏览与人工派工 —— 领取/交回/延后走智能体的 MCP 通道，这里不提供。"
    >
      <AnalysisPanel />
    </PageShell>
  );
}
