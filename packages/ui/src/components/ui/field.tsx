"use client";

import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 表单字段：**上标签 + 控件 + 一行口径说明**（默认），或 **左标签 + 控件**（设置页模式）。
 *
 * 为什么需要它：全站 `<label class="mb-1 block text-xs text-muted-foreground">` 这行重复了
 * 60 多次，改一次要动十来个文件；而且 `htmlFor` / `id` 手工配对很容易漏（规则抽屉里
 * `rule-id` 曾在三处重复使用）。这里同一处生成 id，调用方不必再记忆「配对了没有」。
 *
 * 两种排布（由 `SettingsForm` 提供上下文自动切换，调用方无需逐个改 Field）：
 * - **stacked（默认）**：标签在上，配 `FieldGrid` 多列并排 —— 适合监听网卡、端口、阈值
 *   这种「一屏要看到很多项」的配置区；
 * - **row**：左标签右控件、单列纵向 —— 对照桌面「深信服界面」实拍图的**设置页**排法。
 *   纵向设置表单若标签在上，每个字段占两行、8 项就是 16 行，且控件起始 x 不断变化；
 *   左标签把控件起点钉在同一条竖线上，眼睛只上下移动。
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

/** 字段排布模式：stacked = 标签在上（多列网格）；row = 左标签 + 右控件（设置页单列纵向）。 */
type FieldLayout = "stacked" | "row";
const FieldLayoutContext = React.createContext<FieldLayout>("stacked");

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
  /** 宽度档位，见 SPAN 常量（仅 stacked 模式生效） */
  span?: "sm" | "md" | "lg" | "full";
  /** row 模式下标签列的宽度：短标签 sm / 常规 md / 长标签 lg */
  labelWidth?: "sm" | "md" | "lg";
  /**
   * row 模式下**控件区**的宽度档位：控件只占自己需要的宽度，不铺满剩余空间。
   *
   * 深信服设置页的做法：标签钉在一条竖线上，控件按内容取宽（端口框就一柞宽，
   * URL 框才拉长），剩下的空白留给下一行 —— 而不是每个输入框都横跨整块板。
   * 不传（或 `full`）= 铺满，给 textarea / 代码编辑器这类确实需要横向空间的内容。
   *
   * 提示与报错文案**不受这个宽度影响**，仍占满标签之后的剩余宽度（见 row 模式实现）。
   */
  controlWidth?: "xs" | "sm" | "md" | "lg" | "full";
  className?: string;
  children: React.ReactNode;
}

const LABEL_W = {
  sm: "w-20", // 80px
  md: "w-[6.5rem]", // 104px
  lg: "w-32", // 128px
} as const;

/**
 * row 模式控件区宽度档位：按**内容需要**取宽，不铺满。
 *
 * 取值标尺（控件内文字约 14px）：
 *   xs 96px   端口 / 小数字（1~1024 这种四位数）
 *   sm 144px  端口组 / KB 数 / 枚举下拉
 *   md 256px  IP / 网段 / 主机名（`192.168.0.0/16` 约 15 字符 ≈ 130px，留余量）
 *   lg 416px  URL / 令牌 / ES 地址（`http://host:9200` 起）
 *   full      铺满：textarea / 代码编辑器 / 条件编辑器
 */
const CONTROL_W = {
  xs: "w-24",
  sm: "w-36",
  md: "w-64",
  lg: "w-[26rem]",
  full: "w-full",
} as const;

function FieldMessage({ error, hint }: { error?: React.ReactNode; hint?: React.ReactNode }) {
  if (error) {
    return (
      <p role="alert" className="mt-1 text-xs text-sev-critical-fg">
        {error}
      </p>
    );
  }
  if (hint) {
    return <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{hint}</p>;
  }
  return null;
}

export function Field({
  label,
  htmlFor,
  hint,
  error,
  required,
  span = "sm",
  labelWidth = "md",
  controlWidth,
  className,
  children,
}: FieldProps) {
  const layout = React.useContext(FieldLayoutContext);
  const auto = React.useId();
  const id = htmlFor ?? auto;

  const labelNode = (
    <>
      {label}
      {required ? (
        <span aria-hidden className="ml-0.5 text-sev-critical-fg">
          *
        </span>
      ) : null}
    </>
  );

  // 设置页模式：左标签 + 右控件。标签右对齐、控件左边缘成一条竖线。
  if (layout === "row") {
    return (
      <div className={cn("flex items-start gap-4", className)}>
        <label
          htmlFor={id}
          // pt-1.5：把标签文字基线对齐到 32px 控件的文字基线（不是容器顶端）
          className={cn(
            "shrink-0 pt-1.5 text-right text-13 leading-5 text-muted-foreground",
            LABEL_W[labelWidth],
          )}
        >
          {labelNode}
        </label>
        <div className="min-w-0 flex-1">
          {/* 控件按需取宽（`controlWidth`），提示/报错仍占满标签之后的剩余宽度。
              窄控件 + 宽提示不会互相挤压：两者各占一行内各自的区域。 */}
          <div className={cn(controlWidth ? CONTROL_W[controlWidth] : "w-full")}>
            {children}
          </div>
          <FieldMessage error={error} hint={hint} />
        </div>
      </div>
    );
  }

  return (
    <div className={cn("min-w-0", SPAN[span], className)}>
      <label htmlFor={id} className="mb-1 block text-xs text-muted-foreground">
        {labelNode}
      </label>
      {children}
      <FieldMessage error={error} hint={hint} />
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
 * 在 `SettingsForm`（row 模式）内部自动退化为单列纵向堆叠（`space-y-3`），
 * 这样调用方把 `<FieldGrid>` 包进 `<SettingsForm>` 即可，不用改字段本身。
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
  const layout = React.useContext(FieldLayoutContext);
  if (layout === "row") {
    return <div className={cn("space-y-3", className)}>{children}</div>;
  }
  return (
    <div className={cn("grid gap-x-4 gap-y-3", COLS[maxCols], className)}>{children}</div>
  );
}

/**
 * 设置页表单容器：把其内部的 `Field` / `FieldGrid` 切成「左标签 + 右控件」的单列纵向排布。
 *
 * 用法（改造一个设置页只需三步，**不用逐个改 Field**）：
 *   <Card><CardContent>
 *     <SettingsForm>            ← ① 包一层
 *       <FieldGrid maxCols={2}> ← ② 原样保留（内部自动退化成纵向）
 *         <Field label="…">…</Field>
 *       </FieldGrid>
 *     </SettingsForm>
 *   </CardContent></Card>
 *
 * 只影响被包裹的子树，列表页 / 抽屉里的 `Field` 不受影响（上下文默认 stacked）。
 */
export function SettingsForm({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <FieldLayoutContext.Provider value="row">
      <div className={cn("space-y-3", className)}>{children}</div>
    </FieldLayoutContext.Provider>
  );
}

/**
 * 独立使用的「左标签字段行」（不想引入 `SettingsForm` 上下文时的显式写法）。
 * 语义与 row 模式下的 `Field` 完全一致。
 */
export function FieldRow(props: FieldProps) {
  return (
    <FieldLayoutContext.Provider value="row">
      <Field {...props} />
    </FieldLayoutContext.Provider>
  );
}

/** 左标签设置表单的纵向堆叠容器（行距 12px，与深信服设置页一致）。 */
export function FieldRows({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <div className={cn("space-y-3", className)}>{children}</div>;
}
