"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { TopBar } from "@/components/topbar";

/**
 * 后台页面的统一外壳：全局页头（logo / 告警铃铛 / 当前用户 / 退出）+ 左侧导航 + 标题 + 面板堆叠。
 *
 * 第 7 期把原来挤在一页里的面板按主题拆成多页（采集接入 / 监控网段 / 数据存储 /
 * 过滤规则 / 智能体对接 / 运行状态），每页都用这个外壳，标题与说明只在页面里写一次。
 *
 * 偏移量对应页头的 `h-14`（侧边栏 `top-14`、正文 `pt-20`）——改页头高度时这三处一起改。
 */
export function PageShell({
  title,
  desc,
  children,
}: {
  title: string;
  desc?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen">
      <TopBar />
      <Nav />
      <main className="ml-56 px-6 pb-6 pt-20">
        <div className="mb-4">
          <h1 className="text-2xl font-bold">{title}</h1>
          {desc ? <p className="mt-1 text-sm text-muted-foreground">{desc}</p> : null}
        </div>
        <div className="space-y-4">{children}</div>
      </main>
    </div>
  );
}
