"use client";

/**
 * 右侧抽屉：列表页的「详情」用它弹出内容。
 *
 * 为什么不再用表格下方的卡片：列表一长（事件列表动辄上百行），卡片会被挤到
 * 屏幕外，点了「详情」看起来像没反应 —— 运维反馈的正是这个问题。
 * 抽屉从右侧滑出、内容独立滚动，点遮罩/按 Esc/点关闭都能收起。
 *
 * 无障碍：与 Dialog 共用 `useModalBehavior`（焦点陷阱 + Esc + 关闭后归位），
 * 并用 `aria-labelledby` 把抽屉和标题绑定起来。
 *
 * 不引第三方依赖（项目 ui 组件只有 badge/button/card/input/table），
 * 这里用原生 div + 已有 Button 实现，避免新增包影响构建。
 */

import * as React from "react";
import { X } from "lucide-react";

import { Button } from "./button";
import { useModalBehavior } from "../../lib/use-modal";
import { cn } from "../../lib/utils";

export interface DrawerProps {
  open: boolean;
  title: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  /** 底部固定区（放操作按钮） */
  footer?: React.ReactNode;
  /** 宽度类，默认 640px */
  widthClass?: string;
}

export function Drawer({ open, title, onClose, children, footer, widthClass }: DrawerProps) {
  const panelRef = useModalBehavior<HTMLElement>(open, onClose);
  const titleId = React.useId();

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      {/* 遮罩：点击关闭 */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} aria-hidden="true" />
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={cn(
          "absolute right-0 top-0 flex h-full w-[640px] max-w-[94vw] flex-col border-l border-border bg-surface-2 shadow-3 outline-none",
          widthClass
        )}
      >
        <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <h2 id={titleId} className="min-w-0 text-sm font-medium text-foreground">
            {title}
          </h2>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="关闭">
            <X className="h-4 w-4" />
          </Button>
        </header>
        <div className="flex-1 overflow-y-auto p-4">{children}</div>
        {footer ? <footer className="border-t border-border p-3">{footer}</footer> : null}
      </aside>
    </div>
  );
}
