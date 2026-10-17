import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "../../lib/utils";

/**
 * 徽章：严重度语义色。
 *
 * 这里原来是**暗色主题的遗留**（critical 用 bg-red-950 配 text-red-300），
 * 在已经改成亮色的页面上就是"黑底贴片"——这是白卡片上最扎眼的脏色块，
 * 也是"质感差"最直接的来源之一。
 *
 * 现在全部改用 sev-{级}-bg / -fg / -bd 三件套语义变量：
 *   亮色下是"浅底 + 深字 + 同色系描边"，暗色下自动跟着 .dark 变量走，
 *   两个前端（NDR 亮 / agent 暗）共用同一份组件，不再各写一套。
 *
 * low 由绿改蓝：低危不等于安全，绿只留给 ok / success。
 */
const badgeVariants = cva(
  "inline-flex items-center gap-1 whitespace-nowrap rounded-xs border px-2 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        critical: "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg",
        high: "border-sev-high-bd bg-sev-high-bg text-sev-high-fg",
        medium: "border-sev-medium-bd bg-sev-medium-bg text-sev-medium-fg",
        low: "border-sev-low-bd bg-sev-low-bg text-sev-low-fg",
        info: "border-sev-info-bd bg-sev-info-bg text-sev-info-fg",
        success: "border-sev-ok-bd bg-sev-ok-bg text-sev-ok-fg",
        outline: "border-border bg-transparent text-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export function severityVariant(severity: string | null): "critical" | "high" | "medium" | "low" | "info" {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}
