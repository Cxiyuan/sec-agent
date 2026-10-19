import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 页内区块（L1 容器）：**有标题、无边框、无底色**。
 *
 * 为什么要有它：全站 20 多个面板各写各的区块标题 —— 有的是 14px 灰字、有的是
 * `text-base` 的 CardTitle、有的干脆没有标题直接铺表格。结果同一套产品里，
 * 「这一屏分几块」的视觉锚点在每个页面长得都不一样。
 *
 * 2026-10 复刻深信服 SIP：标题前加 3px 蓝色竖条（深信服分区标题的经典样式）——
 * 扫一屏时先读到「标尺」再读文字，分区边界比原来的一条底线更早被看到。
 *
 * 层级约定（与卡片、内联格配套）：
 *   L1 Section  = 16px 标题 + 蓝竖条 + 1px 底线，负责"分区"        ← 本组件
 *   L2 Card     = 14px 标题 + 描边 + 极浅投影，负责"一坨内容"
 *   L3 Inline   = 无标题、底色块，负责"一个数字/一条状态"
 *
 * 三者只在各自的层级上出现，不要交叉（例如别把 Card 套在 Section 里再套 Card）。
 */
export function Section({
  id,
  title,
  description,
  extra,
  children,
  className,
  divided = true,
}: {
  /** 锚点 id：页内跳转用（配合 scroll-mt 避开固定页头） */
  id?: string;
  title: React.ReactNode;
  /** 标题下的一句话说明：解释口径、时间窗、数据来源，比塞到图例里好读 */
  description?: React.ReactNode;
  /** 标题行右侧：筛选、时间范围、统计数、操作按钮 */
  extra?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  /** 是否画标题底线（嵌套在卡片内部时不画） */
  divided?: boolean;
}) {
  return (
    <section id={id} className={cn("scroll-mt-20 space-y-3", className)}>
      <div
        className={cn(
          "flex flex-wrap items-end justify-between gap-x-3 gap-y-2",
          divided && "border-b border-border pb-2",
        )}
      >
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-base font-medium leading-6 text-foreground">
            {/* 深信服式分区标尺：3px 圆角竖条 + 标题。shrink-0 防长标题把竖条压扁 */}
            <span aria-hidden className="h-3.5 w-[3px] shrink-0 rounded-full bg-primary" />
            {title}
          </h2>
          {description ? (
            <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {extra ? <div className="flex flex-wrap items-center gap-2">{extra}</div> : null}
      </div>
      {children}
    </section>
  );
}
