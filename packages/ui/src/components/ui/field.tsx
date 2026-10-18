"use client";

import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 表单字段：**上标签 + 控件 + 一行口径说明**。
 *
 * 为什么需要它：全站 `<label class="mb-1 block text-xs text-muted-foreground">` 这行重复了
 * 60 多次，改一次要动十来个文件；而且 `htmlFor` / `id` 手工配对很容易漏（规则抽屉里
 * `rule-id` 曾在三处重复使用）。这里同一处生成 id，调用方不必再记忆「配对了没有」。
 *
 * 标签一律在上，不做左右分栏 —— 左标签要求一列固定宽（通常 8rem），4 列网格里标签列要
 * 重复 4 次吃掉 512px，而且标签右对齐后「监听网卡」和「附加 BPF 条件（可选，如 not port 22）」
 * 这种长短差异会让控件起点参差。
 */
const SPAN = {
  /** 跟随网格列宽：端口 / 数量 / 级别下拉 / 优先级 */
  sm: "",
  /** 单值文本（网卡名、主机名）：超宽屏时收到 30rem，避免眼睛从标签扫到输入框时落点丢失 */
  md: "min-[1600px]:max-w-[30rem]",
  /** URL / 令牌：占 2 列，行内还能再放一个短字段（比 `full` 少留一半空白） */
  lg: "col-span-2",
  /** textarea / 代码编辑器 / 条件编辑器：整行 */
  full: "col-span-full",
} as const;

export interface FieldProps {
  label: React.ReactNode;
  /** 控件的 id；不传则用 `React.useId()` 生成（同一个抽屉里重名标签也不会串） */
  htmlFor?: string;
  /** 控件下方的口径说明，一行 */
  hint?: React.ReactNode;
  /** 校验失败文案：出现时 hint 让位，整块转语义红 */
  error?: React.ReactNode;
  /** 必填：标签后补一个 aria-hidden 的红色星号（不用原生 required，避免触发浏览器气泡） */
  required?: boolean;
  /** 宽度档位，见 SPAN 常量 */
  span?: "sm" | "md" | "lg" | "full";
  className?: string;
  children: React.ReactNode;
}

export function Field({
  label,
  htmlFor,
  hint,
  error,
  required,
  span = "sm",
  className,
  children,
}: FieldProps) {
  const auto = React.useId();
  const id = htmlFor ?? auto;
  return (
    <div className={cn("min-w-0", SPAN[span], className)}>
      <label htmlFor={id} className="mb-1 block text-xs text-muted-foreground">
        {label}
        {required ? (
          <span aria-hidden className="ml-0.5 text-sev-critical-fg">
            *
          </span>
        ) : null}
      </label>
      {children}
      {error ? (
        <p role="alert" className="mt-1 text-xs text-sev-critical-fg">
          {error}
        </p>
      ) : hint ? (
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{hint}</p>
      ) : null}
    </div>
  );
}

const COLS = {
  2: "grid-cols-1 md:grid-cols-2",
  3: "grid-cols-1 md:grid-cols-2 min-[1600px]:grid-cols-3",
  4: "grid-cols-1 md:grid-cols-2 min-[1600px]:grid-cols-3 min-[1920px]:grid-cols-4",
} as const;

/**
 * 字段网格：**用列数吃多余宽度，而不是用列宽**。
 *
 * 这是本次改版收益最大的一条。宽屏下把两个输入框从 566px 拉到 872px，换来的只是
 * "一个 4 个字的下拉框躺在半屏空白里"；这里让列数随宽度阶梯增长（1 → 2 → 3 → 4），
 * 单字段净宽稳定在 316–427px 的舒适区。
 *
 * 阈值推导（M = 主列宽）：
 *   < 768              → 1 列（手机上不并排）
 *   768–1599  M 480–992  → 2 列，单字段 232–488
 *   1600–1919 M 992–1312 → 3 列，单字段 320–427  ← 舒适区
 *   ≥ 1920    M 1312–1760 → 4 列，单字段 316–424  ← 舒适区
 *
 * 为什么封进组件而不是让每个面板自己写：这串 class 有 4 个断点、20 个单词，
 * 复制十次一定会写错或写漏某一档。
 */
export function FieldGrid({
  children,
  /** 最宽处（min-[1920px]）的列数；窄处自动降级 */
  maxCols = 3,
  className,
}: {
  children: React.ReactNode;
  maxCols?: 2 | 3 | 4;
  className?: string;
}) {
  return (
    <div className={cn("grid gap-x-4 gap-y-3", COLS[maxCols], className)}>{children}</div>
  );
}
