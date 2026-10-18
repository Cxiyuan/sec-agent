import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 空态：**"没有数据"要看起来像一个状态，而不是一段没人管的灰字**。
 *
 * 原来全站 15 处空态各写各的 `<p className="py-8 text-center text-xs text-muted-foreground">`，
 * 表格下方挂一句话就完了 —— 运维看到的第一反应是"页面加载坏了"。
 *
 * 三种语气（tone）对应三种真实情况，别混用：
 *   muted  真的没有数据（还没产生、时间窗内没有）  → 中性灰
 *   danger 读取失败（后端/网络挂了）               → 语义红，配合 PanelError 使用
 *   loading 正在读（首次加载）                     → 配合 `busy` 显示脉冲，不要写成"暂无"
 *
 * 用法：
 * ```tsx
 * <EmptyState
 *   title={errs.isFailed(SRC.list) ? "列表读取失败" : "还没有命中记录"}
 *   hint="命中记录会在检测器跑完一轮后出现；也可以放宽左侧时间范围"
 *   tone={errs.isFailed(SRC.list) ? "danger" : "muted"}
 *   action={<Button size="sm" variant="outline" onClick={reload}>重新读取</Button>}
 * />
 * ```
 */
export function EmptyState({
  title,
  hint,
  action,
  tone = "muted",
  size = "default",
  className,
  children,
}: {
  title: React.ReactNode;
  /** 第二行：解释为什么空、能做什么（最长两行，别写成说明书） */
  hint?: React.ReactNode;
  /** 操作：重新读取 / 去配置 / 新建 */
  action?: React.ReactNode;
  tone?: "muted" | "danger" | "loading";
  /** compact 用于卡片内部、图表位；default 用于整块表格区 */
  size?: "default" | "compact";
  className?: string;
  children?: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center text-center",
        size === "compact" ? "gap-1 px-4 py-8" : "gap-1.5 px-4 py-12",
        className,
      )}
      role={tone === "loading" ? "status" : undefined}
      aria-live={tone === "loading" ? "polite" : undefined}
    >
      <div
        aria-hidden
        className={cn(
          "mb-1 rounded-full border",
          size === "compact" ? "h-7 w-7" : "h-9 w-9",
          tone === "danger"
            ? "border-sev-critical-bd bg-sev-critical-bg"
            : "border-border-subtle bg-surface-1",
          tone === "loading" && "st-pulse",
        )}
      />
      <p
        className={cn(
          "font-medium",
          size === "compact" ? "text-xs" : "text-sm",
          tone === "danger" ? "text-sev-critical-fg" : "text-foreground",
        )}
      >
        {title}
      </p>
      {hint ? (
        <p className="max-w-md text-xs leading-relaxed text-muted-foreground">{hint}</p>
      ) : null}
      {action ? <div className="mt-2 flex items-center gap-2">{action}</div> : null}
      {children}
    </div>
  );
}
