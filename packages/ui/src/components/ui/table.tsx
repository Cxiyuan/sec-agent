import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 表格：运维盯屏时间最长的元素，密度与扫读反馈优先。
 *
 * 2026-10 复刻深信服 SIP 列表样式（用户要求，保持浅色主题、只改结构）：
 * 1. **全边框网格**：每格都画 border-r（末列去掉）、行间 border-b —— 深信服列表是
 *    「横竖都有线」的密集网格，不是只有横线的现代简约风。配 border-collapse 让线合并成 1px；
 * 2. 表头文字从 muted-foreground 提到 foreground：深信服表头是深色粗感文字 + 浅灰底，
 *    扫读时列名先读到；原来浅灰表头在 #f5f7f9 底上对比度只有 ~3:1；
 * 3. 行 hover 保持 bg-brand-50（品牌淡蓝），与深信服 hover 同色系；
 * 4. 正文 13px / 行高 36px（py-2）不变。
 */
export const Table = React.forwardRef<HTMLTableElement, React.HTMLAttributes<HTMLTableElement>>(
  ({ className, ...props }, ref) => (
    <div className="relative w-full overflow-auto">
      <table ref={ref} className={cn("w-full border-collapse caption-bottom text-13", className)} {...props} />
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
        "border-b border-border transition-colors hover:bg-brand-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-inset data-[state=selected]:bg-accent",
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
      // border-r + last:border-r-0：竖线只画在列与列之间，最右一列不画（贴卡片描边）
      "h-8 whitespace-nowrap border-r border-border bg-surface-1 px-3 text-left align-middle text-xs font-medium text-foreground last:border-r-0",
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
  <td ref={ref} className={cn("border-r border-border px-3 py-2 align-middle last:border-r-0", className)} {...props} />
));
TableCell.displayName = "TableCell";
