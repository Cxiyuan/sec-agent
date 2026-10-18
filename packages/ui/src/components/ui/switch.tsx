"use client";

import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 开关（Switch）：表达**控件状态**，不表达业务状态。
 *
 * 为什么放共享包：agent 前端也有开关需求；`<input type="checkbox">` 在暗色端是系统原生的
 * 白底方块（`accent-color` 之外的部分改不了），两边各自写就会在同一个产品里出现两种开关语言。
 * 这里统一成一个 `<button role="switch">`，颜色全部走既有语义变量，NDR 亮 / agent 暗各自生效。
 *
 * 语义边界（写在这里，避免后面有人拿它画别的语义）：
 * - 「开」用 `bg-primary` —— globals.css 的约定是品牌蓝表示「可操作 / 选中 / 焦点」，
 *   而开关的开合正是用户做出的选择，不是数据也不是状态；
 * - 业务状态（启用 / 停用 / 在线 / 离线）**不要**用开关去画，它属于 `Badge` + 行底色。
 *   规则树里「已停用」除了开关拨到关，还要整行退回 `surface-1`，正因为开关只能表达
 *   「用户现在把它拨到了哪」，表达不了「它曾经是什么」。
 *
 * 暗色分支：`--primary` 在 `.dark` 下是 212 82% 58%（亮蓝）、`--surface-2` 是 220 24% 12%（深），
 * 滑块深 / 轨道亮，对比足够 —— 不需要为 `.dark` 单独写分支。
 */
export interface SwitchProps {
  checked: boolean;
  onCheckedChange: (next: boolean) => void;
  /** 必填：作为 `aria-label` 与默认 `title`。图标轨 / 图标按钮场景下读屏与悬停都靠它 */
  label: string;
  /** 悬停文案；不传就用 label（行内开关的 title 通常比 label 短） */
  title?: string;
  disabled?: boolean;
  size?: "sm" | "md";
  className?: string;
  id?: string;
  /** 待定态（请求在飞）：视觉上的「等待」由调用方的行底色表达，这里只通报给读屏 */
  busy?: boolean;
}

export function Switch({
  checked,
  onCheckedChange,
  label,
  title,
  disabled,
  size = "sm",
  className,
  id,
  busy,
}: SwitchProps) {
  return (
    <button
      type="button"
      id={id}
      role="switch"
      aria-checked={checked}
      aria-label={label}
      aria-busy={busy || undefined}
      title={title ?? label}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cn(
        "relative inline-flex shrink-0 items-center rounded-full border transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
        "disabled:cursor-not-allowed disabled:opacity-50 motion-reduce:transition-none",
        size === "sm" ? "h-4 w-7" : "h-5 w-9",
        checked ? "border-primary bg-primary" : "border-border bg-surface-1",
        className,
      )}
    >
      {/* 滑块：一点投影是为了让"可以拨动"这件事看得出来，不是装饰 —— 轨道已经是糖面色块，
          纯平的话会读成"两个色块排在一起"而不是"一个可以拨的开关" */}
      <span
        aria-hidden
        className={cn(
          "absolute rounded-full bg-surface-2 shadow-1 transition-transform motion-reduce:transition-none",
          size === "sm" ? "left-0.5 h-3 w-3" : "left-0.5 h-4 w-4",
          checked ? (size === "sm" ? "translate-x-3" : "translate-x-4") : "translate-x-0",
        )}
      />
    </button>
  );
}
