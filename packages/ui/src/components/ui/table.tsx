import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 表格：运维盯屏时间最长的元素，密度与扫读反馈优先。
 *
 * 三处关键调整：
 * 1. 表头加 surface-1 实底（原来只有一条边框，和内容分不开，滚动时容易看串行）；
 * 2. 行 hover 从 `bg-muted/50` 换成 `bg-brand-50` —— muted 和卡片几乎同色，
 *    原来的 hover 基本看不出来，"点到了没有"全靠猜；
 * 3. 正文 13px / 行高 36px（py-2），比原来的 p-3 + text-sm 更紧凑但不挤。
 */
export const Table = React.forwardRef<HTMLTableElement, React.HTMLAttributes<HTMLTableElement>>(
  ({ className, ...props }, ref) => (
    <div className="relative w-full overflow-auto">
      <table ref={ref} className={cn("w-full caption-bottom text-13", className)} {...props} />
    </div>
  )
);
Table.displayName = "Table";

export const TableHeader = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <thead ref={ref} className={cn("[&_tr]:border-b [&_tr]:border-border", className)} {...props} />
));
TableHeader.displayName = "TableHeader";

export const TableBody = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tbody ref={ref} className={cn("[&_tr:last-child]:border-0", className)} {...props} />
));
TableBody.displayName = "TableBody";

export const TableRow = React.forwardRef<HTMLTableRowElement, React.HTMLAttributes<HTMLTableRowElement>>(
  ({ className, ...props }, ref) => (
    <tr
      ref={ref}
      className={cn(
        // focus-visible 环：整行可点的表格（事件中心、日志检索）给行加了 tabIndex={0}，
        // 没有焦点环的话键盘用户 Tab 到行上看不出停在哪一行，tabIndex 反而变成陷阱。
        // 与 Input / Switch 同一款 ring；全站表格行一起受益。
        "border-b border-border-subtle transition-colors hover:bg-brand-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-inset data-[state=selected]:bg-accent",
        className
      )}
      {...props}
    />
  )
);
TableRow.displayName = "TableRow";

export const TableHead = React.forwardRef<
  HTMLTableCellElement,
  React.ThHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <th
    ref={ref}
    className={cn(
      "h-8 whitespace-nowrap bg-surface-1 px-3 text-left align-middle text-xs font-medium text-muted-foreground",
      className
    )}
    {...props}
  />
));
TableHead.displayName = "TableHead";

export const TableCell = React.forwardRef<
  HTMLTableCellElement,
  React.TdHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <td ref={ref} className={cn("px-3 py-2 align-middle", className)} {...props} />
));
TableCell.displayName = "TableCell";
