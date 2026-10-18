import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 指标格（L3 内联容器）：**一个数字 + 一句解释**。
 *
 * 关键点是**用底色而不是描边**表达边界 —— 原来 KPI 用裸的
 * `rounded-md border p-3`，和卡片、区块凑在同一屏里就是三种盒子语言；
 * 改成 surface-1 底色块之后，盒子感消失，同样的信息密度下页面"安静"很多。
 *
 * 数字一律 `tabular-nums`：一排 4 个指标里，`1,284` 和 `96` 的位数不同，
 * 不用等宽数字就会左对齐错位，扫读时眼睛要重新找基准线。
 *
 * 用法：
 * ```tsx
 * <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
 *   <Stat label="24h 命中" value={hit24h} hint="各区间增量之和" />
 *   <Stat label="未投递累计" value={n} tone="critical" hint="推送未启用" />
 * </div>
 * ```
 */
export function Stat({
  label,
  value,
  hint,
  tone = "default",
  size = "lg",
  className,
}: {
  label: React.ReactNode;
  value: React.ReactNode;
  /** 单位、口径、变化原因：一句话，别写成一整行 */
  hint?: React.ReactNode;
  /** 语义色：与徽章、图表共用一套 token，不要用 Tailwind 原色 */
  tone?: "default" | "critical" | "high" | "medium" | "low" | "ok" | "info";
  /** lg = 主指标（28px）；md = 次级（20px）；sm = 表格上方的小计（16px） */
  size?: "lg" | "md" | "sm";
  className?: string;
}) {
  const toneClass =
    tone === "default"
      ? "text-foreground"
      : tone === "critical"
        ? "text-sev-critical-fg"
        : tone === "high"
          ? "text-sev-high-fg"
          : tone === "medium"
            ? "text-sev-medium-fg"
            : tone === "low"
              ? "text-sev-low-fg"
              : tone === "ok"
                ? "text-sev-ok-fg"
                : "text-sev-info-fg";

  return (
    <div className={cn("rounded-xs bg-surface-1 px-3 py-2", className)}>
      <p className="text-xs leading-4 text-muted-foreground">{label}</p>
      <p
        className={cn(
          "mt-1 font-medium tabular-nums",
          size === "lg" ? "text-28" : size === "md" ? "text-xl" : "text-base",
          toneClass,
        )}
      >
        {value}
      </p>
      {hint ? <p className="mt-0.5 text-xs leading-4 text-muted-foreground">{hint}</p> : null}
    </div>
  );
}
