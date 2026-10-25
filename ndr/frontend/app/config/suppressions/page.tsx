"use client";

import { PageShell } from "@/components/page-shell";
import { SuppressionsPanel } from "@/components/suppressions-panel";

/**
 * 精准抑制（`/config/suppressions`）：误报抑制条目的登记、复核、撤销与参数门槛。
 *
 * 与「降噪过滤 / 排除过滤」的分工（按作用点由轻到重）：
 * - 降噪过滤 = 不进检测器（事件仍进 ES）；
 * - 排除过滤 = 跳过模型与报告（事件仍落库）；
 * - 精准抑制 = 智能体带证据确认误报后，**不再生成事件/不再派工**，可随时撤销。
 *
 * 抑制是自动生效的，所以这一页最重的交互是「保存前必须试算影响面」。
 */
export default function SuppressionsPage() {
  return (
    <PageShell
      title="精准抑制"
      width="wide"
      desc="命中条件后不再派工、不再推送（最重的一档连事件都不生成）。原始数据（ES）永不受影响 —— 抑制错了也能用日志检索与原始证据事后重建。新建或改条件前必须过试算：影响面过大时后端会自动降级为「只不派工」。"
    >
      <SuppressionsPanel />
    </PageShell>
  );
}
