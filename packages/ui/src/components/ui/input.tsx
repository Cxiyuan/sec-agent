import * as React from "react";
import { cn } from "../../lib/utils";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, type, ...props }, ref) => (
    <input
      type={type}
      ref={ref}
      className={cn(
        // 输入框不加投影：这是"零装饰材质"原则里最容易被忽略的一处 ——
        // 表单一多，每个输入框底下一道阴影，整片区域会显脏。聚焦态用 2px ring，
        // 比 1px 更容易看见（键盘用户靠它定位）。
        "flex h-9 w-full rounded-sm border border-input bg-surface-2 px-3 py-1 text-13 transition-colors placeholder:text-muted-foreground focus-visible:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-50",
        className
      )}
      {...props}
    />
  )
);
Input.displayName = "Input";
