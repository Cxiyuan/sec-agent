import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 卡片 = L2 层容器。**全站唯一允许画描边的容器**。
 *
 * 内边距从 p-6 收到 p-4：原尺寸对运维表格页太松（一屏少看 3~4 行），
 * 收紧后密度上来、仍保留呼吸感。标题从 text-lg 降到 text-sm/medium —— 卡片
 * 标题不该和区块标题抢层级。
 */
export const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("rounded-md border border-border bg-card text-card-foreground shadow-1", className)}
      {...props}
    />
  )
);
Card.displayName = "Card";

export const CardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("flex flex-col space-y-1 p-4 pb-2", className)} {...props} />
  )
);
CardHeader.displayName = "CardHeader";

export const CardTitle = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("text-sm font-medium leading-5 text-foreground", className)}
      {...props}
    />
  )
);
CardTitle.displayName = "CardTitle";

export const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("p-4 pt-0", className)} {...props} />
  )
);
CardContent.displayName = "CardContent";
