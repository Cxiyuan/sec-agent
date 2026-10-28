"use client";

import * as React from "react";
import { ChevronRight } from "lucide-react";
import { cn } from "@shentong/ui";

/**
 * 树形列表原语（规则页专用）。
 *
 * 树形在本项目里只有「检测规则」这一处使用，所以放 NDR 前端而不是 `packages/ui` ——
 * 放进共享包会要求它同时服务 agent 前端（那边没有同样的层级结构），通用化会引入
 * 用不到的 props 与分支。
 *
 * ## 明确不做 ARIA tree
 *
 * 不用 `role="tree"` / `role="treeitem"` / 方向键导航 / roving tabindex。
 * 完整的 tree role 要求 `aria-level`、`aria-setsize`、`aria-posinset`、`aria-selected`、
 * 容器内只有一个 `tabindex=0`、以及 ← → ↑ ↓ Home End 全部实现。**做一半的 tree role 比不做更糟**：
 * 读屏会宣布「树，3 项」，用户按方向键没反应、Tab 又跳不到子项。本项目现有页面没有一处用了
 * tree role，引入它会让规则页成为唯一「键盘行为不一致」的页面。
 *
 * 这里用 `<ul>/<li>` + 原生 Tab 顺序：DOM 顺序 = 视觉顺序，行为可预测。
 * 代价是 Tab 停靠点多（默认展开约 54 个），减免手段是搜索框放在 Tab 顺序第一位（见 rules/page.tsx）。
 */

/**
 * 子级列表容器。渲染为 `<ul>`，读屏会宣布"列表，N 项"。
 *
 * 注意：**调用方要始终渲染它**（收起时内容为空），只是不填 children ——
 * 这样父级按钮的 `aria-controls` 永远指向一个真实存在的元素。
 */
export function TreeChildren({
  id,
  children,
  className,
}: {
  /** 供父级按钮的 `aria-controls` 引用 */
  id?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <ul id={id} className={cn("relative", className)}>
      {children}
    </ul>
  );
}

/** 肘线的 y 与「本组最后一行时树干的高度」：跟着行高走，别手填数字。 */
const MID = {
  20: { line: "h-5", elbow: "top-5" }, // L2 行高 40 的中线
  22: { line: "h-[22px]", elbow: "top-[22px]" }, // L3 行高 44 的中线（恒定两行内容）
} as const;

/**
 * 一行（L2 / L3 通用）。自动画树干与肘线。
 *
 * 为什么**每行自画一段**而不是容器画一根通长竖线：通长线的末行会一直画到容器底部，
 * 超过最后一个子项的中线 20px，出现一段"悬空的线头"；而且线长要按最后一个子项的高度反算，
 * 一旦最后一项展开详情就会错位。每行自画一段，末行 `h-5` 自然收在肘线处，
 * 天生对齐，对变高行（展开详情）完全免疫。
 */
export function TreeRow({
  last = false,
  mid = 20,
  className,
  children,
}: {
  /** 是否本组最后一行：决定树干只画到肘线（└）还是贯穿（├） */
  last?: boolean;
  /** 行中线 y（px）：L2 子级用 20、L3 子级用 22（叶子行恒定两行、行高 44） */
  mid?: 20 | 22;
  className?: string;
  children: React.ReactNode;
}) {
  const m = MID[mid];
  return (
    <li className={cn("relative pl-5", className)}>
      {/* 树干：x=8（left-2），非末行贯穿整行（含展开的详情），末行只画到肘线 */}
      <span
        aria-hidden
        className={cn("absolute left-2 top-0 w-px bg-border-subtle", last ? m.line : "h-full")}
      />
      {/* 肘线：从 x=8 画到 x=20，正好接到内容起点（pl-5） */}
      <span
        aria-hidden
        className={cn("absolute left-2 h-px w-3 bg-border-subtle", m.elbow)}
      />
      {children}
    </li>
  );
}

/**
 * 展开/收起 chevron，节点行与叶子行共用。
 *
 * 用 SVG 旋转而不是 `▸ / ▾` 字符：这两个字符属于几何图形区（U+25B8 / U+25BE），
 * 很多中文字体（PingFang / 思源黑体）里没有或字形不一致，会掉进 fallback 字体、基线偏移；
 * 而且它们的宽度和汉字不同，展开/收起切换时整行会左右抖 2px。
 * `ChevronRight` 尺寸固定、靠 `transform` 旋转不触发重排。
 */
export function TreeChevron({ open, className }: { open: boolean; className?: string }) {
  return (
    <ChevronRight
      aria-hidden
      className={cn(
        "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-150",
        "motion-reduce:transition-none",
        open && "rotate-90",
        className,
      )}
    />
  );
}

/**
 * 叶子行的列模板（列头与数据行共用，保证一一对齐）。
 *
 * ① 展开 20px ／ ② 开关 28px ／ ③ 名称+描述 minmax(0,1fr) ／
 * ④ 类型 112px ／ ⑤ 级别 88px ／ ⑥ 优先级 56px ／ ⑦ 操作 72px
 *
 * 两档切换（**恒定两套，不要加第三套**）：
 * - 默认（<xl）：只保留前 3 列，类型/级别/优先级/操作塌到名称下面的第二行。
 *   阈值是 `xl`(1280) 而不是 `lg`(1024) —— 1024 视口下 ③ 列只有约 592px，
 *   但 7 列模板在同一视口只剩约 216px（约 18 个汉字），还不如原来的"硬切 60 字符"。
 * - ≥xl：7 列，③ 列 472px（1280）～1112px（1920）。
 *
 * 叶子行**恒定两行内容**（名称行 + 描述行），行高 44px、`MID`=22：
 * 描述行 `line-clamp-1`（≥xl）/ `line-clamp-2`（<xl）。单行方案不采用 ——
 * 实测 `BUILTIN_RULES` 描述最长 **90 字符**（"内网漏洞利用探测"；该规则已退役不播种、
 * 不出现在规则树里，但源码清单仍保留其判据供撤回，布局按此上限设计），
 * 单行需 90×12 + 151(名称占位) = 1231px，而 1920 的 ③ 列只有 1112px，
 * **任何屏宽都放不下**，连 1920 都不够。两行是内容本身的要求，不是窄屏降级。
 *
 * **不加第 8 列（规则 ID）**：ID 是排查时才用的低频字段，常驻列是噪音；且
 * `LEAF_COLS` 被列头行 / 数据行 / 窄屏 meta 行三处引用，多一套模板就多三个
 * 列头失配点。ID 改放 ③ 列描述行末尾（flex + shrink-0），窄屏自然挤掉。
 */
export const LEAF_COLS =
  "grid-cols-[1.25rem_1.75rem_minmax(0,1fr)] xl:grid-cols-[1.25rem_1.75rem_minmax(0,1fr)_7rem_5.5rem_3.5rem_4.5rem]";

/** 只在 ≥1280 出现的单元格（类型 / 级别 / 优先级 / 操作共用）。 */
export const LEAF_CELL_XL = "hidden xl:block";
/** 只在 <1280 出现的第二行（把上面那些列折下来）。 */
export const LEAF_ROW_NARROW = "xl:hidden";
