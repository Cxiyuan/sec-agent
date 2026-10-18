import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 面板工具条：卡片内的第一条，`border-b` 与下面的内容分开。
 *
 * 为什么需要它：8 个配置页里 6 个有「检索 / 刷新 / 新建」这一条，原来各写在 `Section.extra`
 * 里 —— 宽度、间距、换行规则各写各的，而且控件离它作用的对象隔着一个区块标题行。
 * 搬进卡片第一条后，所有「作用于这块内容」的控件在同一个条上成组。
 *
 * **不加 `role="toolbar"`**：toolbar role 隐含方向键导航的义务（← → 移动焦点），做一半比不做更糟 ——
 * 读屏会宣布「工具栏」，用户按方向键却没反应。用普通容器 + 原生 Tab 顺序即可。
 */
export function PanelToolbar({
  search,
  children,
  className,
}: {
  /** 左侧检索区；不传则不渲染左侧槽位 */
  search?: React.ReactNode;
  /** 右侧操作组 */
  children?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-2 border-b border-border-subtle px-3 py-2",
        className,
      )}
    >
      {search ? <div className="min-w-0 flex-1 sm:max-w-[20rem]">{search}</div> : null}
      <div className="ml-auto flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}
