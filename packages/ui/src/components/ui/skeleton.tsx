import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 骨架屏：**全站原来一个加载态都没有**。
 *
 * 这个产品是自托管 + 内网部署，接口 200ms~2s 很常见；没有骨架时，页面首帧
 * 就是"区块标题 + 一片空白 + 空态文案"，用户的第一印象是"打不开"。
 * 空态和加载态必须分开 —— 把"正在读"画成"暂无数据"是这个项目以前最大的体验坑
 * （见 `PanelError` 注释里记录的同类问题）。
 *
 * 用 `motion-reduce:animate-none` 尊重系统的"减少动态效果"设置：
 * 盯屏 8 小时的人里，持续闪烁的占位块是真实干扰。
 */
export function Skeleton({
  className,
  style,
}: {
  className?: string;
  /** 需要精确高度（图表柱状轮廓）时用；优先用 className 里的档位高度 */
  style?: React.CSSProperties;
}) {
  return (
    <div
      aria-hidden
      style={style}
      className={cn("animate-pulse rounded-xs bg-surface-1 motion-reduce:animate-none", className)}
    />
  );
}

/** 表格首屏占位：列宽按比例分，看起来像"正在填这张表"而不是一块灰。 */
export function TableSkeleton({
  rows = 6,
  cols = 4,
  className,
}: {
  rows?: number;
  cols?: number;
  className?: string;
}) {
  const widths = ["w-full", "w-4/5", "w-2/3", "w-3/5", "w-1/2"];
  return (
    <div className={cn("divide-y divide-border-subtle", className)} aria-busy="true">
      <div className="flex items-center gap-4 bg-surface-1 px-3 py-2">
        {Array.from({ length: cols }).map((_, i) => (
          <Skeleton key={i} className={cn("h-3", widths[i % widths.length])} />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex items-center gap-4 px-3 py-3">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} className={cn("h-3", widths[(r + c) % widths.length])} />
          ))}
        </div>
      ))}
    </div>
  );
}

/** 图表首屏占位：高度与 Chart 的三档高度（176 / 224 / 288）对齐，加载完不跳版。 */
export function ChartSkeleton({
  height = 224,
  className,
}: {
  height?: number;
  className?: string;
}) {
  return (
    <div
      aria-busy="true"
      className={cn("flex items-end gap-2 px-1", className)}
      style={{ height }}
    >
      {/* 柱状轮廓比一整块灰更快让人认出"这里将出现一张图" */}
      {[0.45, 0.7, 0.35, 0.9, 0.6, 0.8, 0.3, 0.65, 0.5, 0.75].map((h, i) => (
        <Skeleton key={i} className="w-full" style={{ height: `${Math.round(h * 100)}%` }} />
      ))}
    </div>
  );
}

/** 指标格占位：一排 n 个，尺寸与 Stat 对齐。 */
export function StatSkeleton({ count = 4, className }: { count?: number; className?: string }) {
  return (
    <div className={cn("grid grid-cols-2 gap-3 md:grid-cols-4", className)} aria-busy="true">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded-xs bg-surface-1 px-3 py-2">
          <Skeleton className="h-3 w-1/2" />
          <Skeleton className="mt-2 h-6 w-2/3" />
        </div>
      ))}
    </div>
  );
}
