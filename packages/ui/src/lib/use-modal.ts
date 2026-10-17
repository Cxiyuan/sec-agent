"use client";

import * as React from "react";

/**
 * 弹层行为（Dialog / Drawer 共用）：**焦点陷阱 + Esc 关闭 + 关闭后焦点归位**。
 *
 * 为什么要有：原来这两个组件只有一句 `document.addEventListener("keydown")` 监听 Esc，
 * 打开后按 Tab 会一路走到背后的页面上（键盘用户直接迷路），关闭后焦点掉回 body
 * （读屏用户得从头再找一遍自己刚才点的是哪一行）。`aria-modal="true"` 只是声明，
 * 真正把焦点锁住还得靠代码。
 *
 * 另外顺手锁住 body 滚动：抽屉开着时背景还能滚，是「内容错位」的常见来源。
 */

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "textarea:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function focusable(scope: HTMLElement): HTMLElement[] {
  return Array.from(scope.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    // offsetParent 为 null 表示被 display:none 或祖先隐藏，不能进 Tab 序列
    (el) => el.offsetParent !== null || el === document.activeElement,
  );
}

export function useModalBehavior<T extends HTMLElement>(open: boolean, onClose: () => void) {
  const ref = React.useRef<T>(null);
  // onClose 通常是内联箭头函数，每次渲染都是新引用；放进 ref 避免 effect 反复重跑
  // （重跑就会重新抢焦点，把用户在弹窗里选中的输入框顶掉）。
  const closeRef = React.useRef(onClose);
  closeRef.current = onClose;

  React.useEffect(() => {
    if (!open) return;
    const node = ref.current;
    const previous = document.activeElement as HTMLElement | null;

    // 等一帧再抢焦点：内容可能是刚挂载的，此时子节点还没进 DOM
    const raf = requestAnimationFrame(() => {
      if (!node) return;
      const items = focusable(node);
      (items[0] ?? node).focus();
    });

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        closeRef.current();
        return;
      }
      if (e.key !== "Tab" || !node) return;
      const items = focusable(node);
      if (!items.length) {
        e.preventDefault();
        node.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement as HTMLElement | null;
      const outside = !active || !node.contains(active);
      if (e.shiftKey && (active === first || outside)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || outside)) {
        e.preventDefault();
        first.focus();
      }
    };

    // capture：先于页面上的其他 keydown 处理，避免 Esc 被表单/下拉吞掉
    document.addEventListener("keydown", onKey, true);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      cancelAnimationFrame(raf);
      document.removeEventListener("keydown", onKey, true);
      document.body.style.overflow = previousOverflow;
      // 焦点归位：回到触发弹层的那个按钮上
      if (previous && document.contains(previous)) previous.focus();
    };
  }, [open]);

  return ref;
}
