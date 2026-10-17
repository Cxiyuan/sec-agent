"use client";

/**
 * 居中对话框：需要「停下来确认/编辑一个东西」时用它。
 *
 * 与 `Drawer`（右侧抽屉）的分工：
 * - 抽屉用于**浏览详情**（列表页点详情，内容长、可滚动、随时可以扫一眼）；
 * - 对话框用于**聚焦操作**（改个名字、填一个值、确认一次），居中弹出不遮挡上下文，
 *   点遮罩/按 Esc/点关闭都能取消。
 *
 * 无障碍：`role="dialog"` + `aria-modal` + `aria-labelledby` 指向标题，
 * 焦点陷阱与关闭后归位由 `useModalBehavior` 负责（原来只有 Esc，Tab 会跑到背景页上）。
 *
 * 与 Drawer 一样不引第三方依赖：原生 div + 已有 Button 实现。
 */

import * as React from "react";
import { X } from "lucide-react";

import { Button } from "./button";
import { useModalBehavior } from "../../lib/use-modal";
import { cn } from "../../lib/utils";

export interface DialogProps {
  open: boolean;
  title: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  /** 底部固定区（放操作按钮） */
  footer?: React.ReactNode;
  /** 宽度类，默认 480px */
  widthClass?: string;
}

export function Dialog({ open, title, onClose, children, footer, widthClass }: DialogProps) {
  const panelRef = useModalBehavior<HTMLElement>(open, onClose);
  const titleId = React.useId();

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      {/* 遮罩：点击关闭 */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} aria-hidden="true" />
      <div className="absolute left-1/2 top-1/2 w-[480px] max-w-[94vw] -translate-x-1/2 -translate-y-1/2">
        <section
          ref={panelRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
          tabIndex={-1}
          className={cn(
            "flex max-h-[85vh] flex-col overflow-hidden rounded-xl border border-border bg-surface-2 shadow-3 outline-none",
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
        </section>
      </div>
    </div>
  );
}
