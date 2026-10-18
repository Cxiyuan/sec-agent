"use client";

import * as React from "react";
import { usePathname } from "next/navigation";
import { Nav } from "@/components/nav";
import { TopBar } from "@/components/topbar";
import { sidebarOf } from "@/lib/nav-config";
import { cn } from "@shentong/ui";

/**
 * 页面外壳：全局页头（logo + **一级菜单** + 告警铃铛 + 用户/退出）+ 可选的分区侧边栏 + 内容区。
 *
 * 2026-10 改版要点：
 * - 一级菜单在**页头**（运营中心 / 分析中心 / 资产中心 / 行为画像 / 配置管理），
 *   侧边栏只显示当前页面的子导航；运营中心、日志检索、行为画像**没有侧边栏**，正文占满宽度。
 * - 明亮企业风：白底 + 浅灰边框 + 主色描边，不再用暗色底。
 *
 * 偏移量与页头 `h-14` 对应（侧边栏 `top-14`、正文 `pt-` 另算）——改页头高度时一起改。
 *
 * ## 内容宽度三档（2026-10 用户反馈「左右两边大量空白」的修法）
 *
 * 可用宽 `W = 视口 − 侧栏(240) − 48(px-6 两侧)`，内容宽 `C = min(W, max-w)`，外槽 `g = (W − C) / 2`。
 * 侧栏是**先吃掉 240px 再居中**的，所以外槽不能拿视口直接减：（1920 − 1500）/2 = 210 是错的，
 * 真正的外槽在 1920 上是 90、在 2560 上是 410 —— 痛点在宽屏，1366/1600 本来就是 0。
 *
 * | 档位 | 1920 外槽 | 2560 外槽 | 用于 |
 * |---|---|---|---|
 * | standard | 0 | 96 | 表单 / 混合页（默认） |
 * | wide | 0 | 0 | 宽表页（≥6 列） |
 * | full | 0 | 0 | 拓扑图、规则树（越宽越好） |
 *
 * 为什么 `standard` 不全放开到 `max-w-none`：表单的舒适宽度有上限。主列到 1760px 时两列字段
 * 各 872px，填完「监听网卡」要把眼睛从标签扫到输入框再扫回来，800px 的横向往返是真实成本。
 * 多余宽度由**列数**吃掉（`FieldGrid`），不由列宽吃掉。
 */
export function PageShell({
  title,
  desc,
  children,
  /** @deprecated 用 `width="full"`；保留是因为还有 10 多个页面在用 */
  fluid = false,
  /** 撑满一屏且不滚动（拓扑图这类要吃掉剩余高度的页面）：正文列变成 flex 列，子元素用 flex-1 */
  fill = false,
  /** standard = 表单/混合页（默认）；wide = 宽表页；full = 拓扑图与规则树 */
  width = fluid ? "full" : "standard",
}: {
  title: string;
  desc?: React.ReactNode;
  children: React.ReactNode;
  fluid?: boolean;
  fill?: boolean;
  width?: "standard" | "wide" | "full";
}) {
  const pathname = usePathname();
  const hasSidebar = sidebarOf(pathname).length > 0;

  // 内容容器三档：只有 full 不加 mx-auto 与 max-w —— 把宽度交给内容自己决定，
  // 树的叶子行是「自适应列名 + 固定列」混排，限宽只会让固定列把名称列挤扁。
  const widthCls =
    width === "full"
      ? "w-full"
      : width === "wide"
        ? "mx-auto w-full max-w-[1600px] 2xl:max-w-[1800px] min-[1920px]:max-w-[2080px] min-[2200px]:max-w-none"
        : "mx-auto w-full max-w-[1440px] 2xl:max-w-[1600px] min-[1920px]:max-w-[1800px] min-[2200px]:max-w-[2080px]";

  return (
    <div className="min-h-screen bg-background">
      <TopBar />
      <Nav />
      <main
        className={cn(
          // 顶部偏移 4.25rem = 页头 h-14（3.5rem）+ 0.75rem 呼吸；改页头高度时一起改。
          // 左右留白在窄屏收到 16px：1366 宽的笔记本上挂着 240px 侧栏时，24px 内边距
          // 会明显吃掉表格列宽。
          // 侧栏宽度走 CSS 变量：`w-` 与 `ml-` 必须同源，改一处即可（见 globals.css）。
          // motion-reduce：跨 1024 断点拖拽窗口时，减少横向位移动画（与 .st-pulse 同一先例）。
          "pb-6 pt-[4.25rem] transition-[margin] duration-150 motion-reduce:transition-none",
          hasSidebar ? "ml-[var(--sidebar-w)]" : "ml-0",
          fluid ? "px-3" : "px-4 md:px-6",
          fill && "flex h-screen flex-col overflow-hidden",
        )}
      >
        {/* 2026-10 用户要求：页面不再**显示** h1 标题与说明段落（信息都在页头菜单与卡片标题里），
            正文直接铺满。但 h1 不能真的没有 —— 读屏与浏览器大纲靠它识别"这一页是什么"，
            所以用 sr-only 保留：视觉上不可见，语义上存在。 */}
        <h1 className="sr-only">{title}</h1>
        {desc ? <p className="sr-only">{desc}</p> : null}
        <div
          className={cn(
            fill ? "flex min-h-0 flex-1 flex-col gap-3" : "space-y-6",
            widthCls,
          )}
        >
          {children}
        </div>
      </main>
    </div>
  );
}
