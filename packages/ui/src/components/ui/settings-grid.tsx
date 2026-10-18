import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 配置页正文的双列编排：**主列放「能改的」，侧栏放「只能看的」**。
 *
 * 为什么需要它：配置页原来是「一张卡接一张卡」的竖排，改一个字段要滚三屏，
 * 而只读的「当前生效 / 集群状态 / 连接信息」和可编辑的表单混在一列里 ——
 * 运维的眼睛得在同一列里反复分辨「这条能不能改」，看错就会去点只读卡片找输入框。
 *
 * 编排名：主列宽（表单、列表要横向空间），侧栏窄（只读事实，两行一条）。
 * 只读块永远在右侧同一列，位置固定之后扫视成本是 0；窄屏（<1280）自动叠成一列，
 * 主列仍在前 —— 手机上先看到的是能操作的东西。
 *
 * 用法：
 *   <Section title="…">
 *     <SettingsGrid>
 *       <SettingsMain>…可编辑的 Card / 操作条…</SettingsMain>
 *       <SettingsRail>…只读的 Card…</SettingsRail>
 *     </SettingsGrid>
 *   </Section>
 *
 * 需要占满两列的块（大表格、管道全文编辑器）不要塞进任何一列，直接放在
 * `SettingsGrid` 的前面或后面当 Section 的兄弟节点，它们的宽度就是整幅。
 */
export function SettingsGrid({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        // items-start：两列各自按内容高度排，侧栏不会被主列拉长成一整块空白底板
        "grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_19rem]",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** 主列：可编辑表单、列表、操作条。`min-w-0` 保证表格能在列内正常收缩。 */
export function SettingsMain({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <div className={cn("min-w-0 space-y-3", className)}>{children}</div>;
}

/**
 * 侧栏：只读状态与说明。
 * 里面请放只读 Card（当前生效值、连接信息、运行状态），不要放表单 ——
 * 一旦侧栏出现输入框，「右侧=只读」这个约定就废了。
 */
export function SettingsRail({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <div className={cn("min-w-0 space-y-3", className)}>{children}</div>;
}
