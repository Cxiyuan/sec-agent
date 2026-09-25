"use client";

/**
 * 右侧抽屉：列表页的「详情」用它弹出内容。
 *
 * 为什么不再用表格下方的卡片：列表一长（事件列表动辄上百行），卡片会被挤到
 * 屏幕外，点了「详情」看起来像没反应 —— 运维反馈的正是这个问题。
 * 抽屉从右侧滑出、内容独立滚动，点遮罩/按 Esc/点关闭都能收起。
 *
 * 不引第三方依赖（项目 ui 组件只有 badge/button/card/input/table），
 * 这里用原生 div + 已有 Button 实现，避免新增包影响构建。
 */

import * as React from "react";
import { X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

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
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true">
      {/* 遮罩：点击关闭 */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-[1px]"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside
        className={cn(
          "absolute right-0 top-0 flex h-full w-[640px] max-w-[94vw] flex-col border-l bg-card shadow-2xl",
          widthClass
        )}
      >
        <header className="flex items-start justify-between gap-3 border-b p-4">
          <div className="min-w-0">{title}</div>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="关闭">
            <X className="h-4 w-4" />
          </Button>
        </header>
        <div className="flex-1 overflow-y-auto p-4">{children}</div>
        {footer ? <footer className="border-t p-3">{footer}</footer> : null}
      </aside>
    </div>
  );
}
