"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Brain,
  FileText,
  Fingerprint,
  LayoutDashboard,
  ListOrdered,
  Network,
  ScrollText,
  Server,
  Settings,
  Shield,
  Sparkles,
} from "lucide-react";
import { cn, Button } from "@shentong/ui";
import { clearToken } from "@/lib/api";

const items = [
  { href: "/dashboard", label: "驾驶舱", icon: LayoutDashboard },
  { href: "/admin", label: "事件列表", icon: ListOrdered },
  { href: "/admin/cases", label: "攻击者案件", icon: Fingerprint },
  { href: "/admin/assets", label: "资产管理", icon: Server },
  { href: "/admin/documents", label: "知识文档", icon: FileText },
  { href: "/admin/topology", label: "网络拓扑", icon: Network },
  { href: "/admin/memories", label: "分析记忆", icon: Brain },
  { href: "/admin/skills", label: "技能库", icon: Sparkles },
  { href: "/admin/reports", label: "报告", icon: ScrollText },
  { href: "/admin/settings", label: "系统配置", icon: Settings },
];

export function Nav() {
  const pathname = usePathname();
  const router = useRouter();

  return (
    <aside className="fixed left-0 top-0 flex h-screen w-56 flex-col border-r bg-card">
      <div className="flex items-center gap-2 border-b p-4">
        <Shield className="h-6 w-6 text-primary" />
        <span className="text-base font-medium">深瞳</span>
      </div>
      <nav className="flex-1 space-y-1 overflow-auto p-3">
        {items.map((it) => {
          const active =
            pathname === it.href ||
            (it.href !== "/admin" && pathname.startsWith(it.href + "/"));
          return (
            <Link
              key={it.href}
              href={it.href}
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                // 选中态用"淡主色底 + 主色字"，与 NDR 侧边栏同一套：整块实心主色填充
                // 在暗色主题下是一大块高亮蓝，会把旁边的告警色全压掉。
                active
                  ? "bg-primary/10 font-medium text-primary"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              )}
            >
              <it.icon className="h-4 w-4" />
              {it.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t p-3">
        <Button
          variant="ghost"
          className="w-full justify-start"
          onClick={() => {
            clearToken();
            router.push("/login");
          }}
        >
          退出登录
        </Button>
      </div>
    </aside>
  );
}
