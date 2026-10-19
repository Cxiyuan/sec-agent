"use client";

import * as React from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { cn } from "../../lib/utils";
import { Button } from "./button";

/**
 * 编号分页条（2026-10 复刻深信服 SIP 的分页）：共 X 条 · 每页 · < 1 2 3 … N > · 跳至 __ 页。
 *
 * 为什么换掉原来的「上一页 / 第 X / Y 页 / 下一页」：深信服（及国内安全平台通用做法）
 * 是**编号页码**——10 页以内全部列出、当前页蓝底，翻第 3 页是一步到位；原来的四按钮
 * 结构翻到第 3 页要按两下，而且「第 X / Y 页」读起来要先做除法。
 *
 * 页码窗口算法：总页数 ≤7 全列；否则首尾恒显、当前页 ±1，中间折成省略号
 * （1 … 4 5 6 … 12）。当前页按钮 pointer-events-none —— onPage 会真的重新取数，
 * 点当前页没有意义，但不禁用（禁用的按钮读屏会宣布 disabled，且移出 Tab 顺序）。
 */
export interface PaginationProps {
  /** 当前页，0 起 */
  page: number;
  /** 总页数（调用方算好；内部兜底 Math.max(1, pages)） */
  pages: number;
  /** 总条数（「共 X 条」用） */
  total: number;
  /** 每页条数；与 onSize 同时传才渲染「每页」选择器 */
  size?: number;
  onPage: (next: number) => void;
  onSize?: (n: number) => void;
  pageSizes?: number[];
  /** 取数中：整条禁用，避免连点造成重复请求 */
  disabled?: boolean;
  className?: string;
}

const DEFAULT_PAGE_SIZES = [20, 50, 100, 200];

function pageWindow(current: number, total: number): Array<number | "gap"> {
  const out: Array<number | "gap"> = [];
  for (let i = 0; i < total; i += 1) {
    if (i === 0 || i === total - 1 || Math.abs(i - current) <= 1) out.push(i);
    else if (out[out.length - 1] !== "gap") out.push("gap");
  }
  return out;
}

export function Pagination({
  page,
  pages,
  total,
  size,
  onPage,
  onSize,
  pageSizes = DEFAULT_PAGE_SIZES,
  disabled = false,
  className,
}: PaginationProps) {
  const [jump, setJump] = React.useState("");
  const totalPages = Math.max(1, pages);
  const atFirst = page <= 0;
  const atLast = page >= totalPages - 1;

  function submitJump(e: React.FormEvent) {
    e.preventDefault();
    const n = Number(jump);
    if (!Number.isFinite(n) || n < 1) return;
    onPage(Math.min(totalPages - 1, Math.max(0, Math.floor(n) - 1)));
    setJump("");
  }

  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-x-3 gap-y-2 text-xs tabular-nums text-muted-foreground",
        className
      )}
    >
      <span className="whitespace-nowrap">共 {total} 条</span>
      {size && onSize ? (
        <label className="flex items-center gap-1 whitespace-nowrap">
          每页
          <select
            className="h-7 rounded-sm border border-input bg-surface-2 px-1 text-xs text-foreground"
            value={size}
            disabled={disabled}
            onChange={(e) => onSize(Number(e.target.value))}
          >
            {pageSizes.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
      ) : null}
      <div className="flex items-center gap-1">
        <Button
          size="sm"
          variant="outline"
          className="h-7 w-7 px-0"
          aria-label="上一页"
          disabled={disabled || atFirst}
          onClick={() => onPage(page - 1)}
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </Button>
        {pageWindow(page, totalPages).map((p, i) =>
          p === "gap" ? (
            <span key={`gap-${i}`} className="px-1" aria-hidden>
              …
            </span>
          ) : (
            <Button
              key={p}
              size="sm"
              variant={p === page ? "default" : "outline"}
              className={cn(
                "h-7 min-w-7 px-1.5 text-xs tabular-nums",
                // 当前页不可点（点了也是重复取数），但不 disabled：保持 Tab 可达 + aria-current 可被读屏宣读
                p === page && "pointer-events-none"
              )}
              aria-current={p === page ? "page" : undefined}
              disabled={disabled}
              onClick={() => onPage(p)}
            >
              {p + 1}
            </Button>
          )
        )}
        <Button
          size="sm"
          variant="outline"
          className="h-7 w-7 px-0"
          aria-label="下一页"
          disabled={disabled || atLast}
          onClick={() => onPage(page + 1)}
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
      </div>
      {totalPages > 1 ? (
        <form className="flex items-center gap-1 whitespace-nowrap" onSubmit={submitJump}>
          <label className="flex items-center gap-1">
            跳至
            <input
              className="h-7 w-10 rounded-sm border border-input bg-surface-2 px-1 text-center text-xs tabular-nums text-foreground"
              value={jump}
              disabled={disabled}
              onChange={(e) => setJump(e.target.value.replace(/\D/g, ""))}
              inputMode="numeric"
              aria-label="跳转页码"
            />
          </label>
          <span>页</span>
          <Button
            size="sm"
            variant="outline"
            className="h-7 px-2 text-xs"
            type="submit"
            disabled={disabled || !jump}
          >
            跳转
          </Button>
        </form>
      ) : null}
    </div>
  );
}
