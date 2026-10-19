import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * Windows 风格的「等待」指示：一圈圆点绕中心旋转，每个圆点错相脉冲。
 *
 * 为什么不直接用骨架屏：骨架屏适合「即将出现结构化内容」（表格/图表）的占位；
 * 但这些列表要从后端拉大量数据、首屏要等几百毫秒到几秒，用户更想要一个
 * 明确在「转」的标记，而不是一片灰块。两者语义不同：
 *   - 骨架屏 = 「这里将长出一张表」（结构占位）
 *   - 圆点转圈 = 「正在读，请等」（动作占位）
 * 这一组是后者，统一替换各处散落的「统计中… / 查询中…」文字提示。
 *
 * 圆点颜色取 `text-*`：外层传 `text-primary` 即钢蓝，切暗色跟着变。
 * 尊重系统「减少动态效果」：`motion-reduce:animate-none` 关闭旋转与脉冲。
 */

export interface LoadingDotsProps {
  /** 整圈直径（px） */
  size?: number;
  /** 圆点数量 */
  count?: number;
  /** 单个圆点相对整圈的比例（0~1） */
  dotScale?: number;
  className?: string;
}

export function LoadingDots({
  size = 28,
  count = 5,
  dotScale = 0.22,
  className,
}: LoadingDotsProps) {
  const dot = Math.max(3, Math.round(size * dotScale));
  const radius = (size - dot) / 2;
  const dots = Array.from({ length: count });
  return (
    <span
      role="status"
      aria-label="加载中"
      className={cn("relative inline-flex shrink-0", className)}
      style={{ width: size, height: size }}
    >
      <span className="absolute inset-0 animate-spin motion-reduce:animate-none" style={{ animationDuration: "1.2s" }}>
        {dots.map((_, i) => {
          const angle = (-90 + (i * 360) / count) * (Math.PI / 180);
          const x = Math.cos(angle) * radius;
          const y = Math.sin(angle) * radius;
          return (
            <span
              key={i}
              className="absolute rounded-full bg-current animate-pulse motion-reduce:animate-none"
              style={{
                width: dot,
                height: dot,
                left: `calc(50% + ${x}px - ${dot / 2}px)`,
                top: `calc(50% + ${y}px - ${dot / 2}px)`,
                animationDelay: `${i * 0.16}s`,
              }}
            />
          );
        })}
      </span>
    </span>
  );
}

export interface LoadingBlockProps {
  /** 下方说明文字，默认「加载中」 */
  label?: string;
  /** 是否带语义色：默认 `text-primary`（圆点钢蓝）；传 false 用中性灰 */
  primary?: boolean;
  className?: string;
}

/** 读数据处的统一加载态：圆点转圈 + 下方「加载中」。放在列表/区域的读取位置。 */
export function LoadingBlock({ label = "加载中", primary = true, className }: LoadingBlockProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "flex flex-col items-center justify-center gap-3",
        primary ? "text-primary" : "text-muted-foreground",
        className,
      )}
    >
      <LoadingDots />
      <span className="text-sm text-muted-foreground">{label}</span>
    </div>
  );
}
