"use client";

import * as React from "react";
import { Nav } from "@/components/nav";

/**
 * 后台页面的统一外壳：左侧导航 + 标题 + 面板纵向堆叠。
 *
 * 第 7 期把原来挤在一页里的面板按主题拆成多页（采集接入 / 监控网段 / 数据存储 /
 * 过滤规则 / 智能体对接 / 运行状态），每页都用这个外壳，标题与说明只在页面里写一次。
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
      <Nav />
      <main className="ml-56 p-6">
        <div className="mb-4">
          <h1 className="text-2xl font-bold">{title}</h1>
          {desc ? <p className="mt-1 text-sm text-muted-foreground">{desc}</p> : null}
        </div>
        <div className="space-y-4">{children}</div>
      </main>
    </div>
  );
}
