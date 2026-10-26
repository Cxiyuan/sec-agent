"use client";

import { BehaviorPanel } from "@/components/behavior-panel";
import { PageShell } from "@/components/page-shell";

/**
 * 行为分析：把基线与画像的**明细**摊开看，并提供判据参数的编辑区。
 *
 * 与「总览」的分工：总览是运维概览（图 + 关键数字），这页是深挖（表 + 参数），
 * 所以这里不画图，重点在「能查、能翻、能改」。
 */
export default function BehaviorPage() {
  return (
    <PageShell
      title="行为分析"
      desc="长期行为基线（数值 2σ）与账号/会话画像：学习进度、判定明细、可调参数。风险分按「当前窗口」计算 —— 本轮没有理由就归零，所以每行都标了判定时间；参数改完即时生效（检测器下一个窗口用新值），不需要重启容器。"
    >
      <BehaviorPanel />
    </PageShell>
  );
}
