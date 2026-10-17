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
 */
export function PageShell({
  title,
  desc,
  children,
  /** 铺满整块区域（大表格 / 拓扑图用）：去掉最大宽度与额外留白 */
  fluid = false,
}: {
  title: string;
  desc?: React.ReactNode;
  children: React.ReactNode;
  fluid?: boolean;
}) {
  const pathname = usePathname();
  const hasSidebar = sidebarOf(pathname).length > 0;

  return (
    <div className="min-h-screen bg-background">
      <TopBar />
      <Nav />
      <main
        className={cn(
          "pb-8 pt-[4.75rem] transition-[margin] duration-150",
          hasSidebar ? "ml-60" : "ml-0",
          fluid ? "px-4" : "px-6",
        )}
      >
        <div className={cn("mb-4", !fluid && "mx-auto max-w-[1500px]")}>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">{title}</h1>
          {desc ? <p className="mt-1 text-sm text-muted-foreground">{desc}</p> : null}
        </div>
        <div className={cn("space-y-4", !fluid && "mx-auto max-w-[1500px]")}>{children}</div>
      </main>
    </div>
  );
}
