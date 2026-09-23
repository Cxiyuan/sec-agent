"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Brain,
  FileText,
  LayoutDashboard,
  ListOrdered,
  Network,
  ScrollText,
  Server,
  Settings,
  Shield,
  SlidersHorizontal,
  Sparkles,
  UserSearch,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { apiFetch, clearToken, type ScopeStatus } from "@/lib/api";
import { Button } from "@/components/ui/button";

const items = [
  { href: "/dashboard", label: "驾驶舱", icon: LayoutDashboard },
  { href: "/admin", label: "事件列表", icon: ListOrdered },
  { href: "/admin/assets", label: "资产管理", icon: Server },
  { href: "/admin/documents", label: "知识文档", icon: FileText },
  { href: "/admin/topology", label: "网络拓扑", icon: Network },
  { href: "/admin/memories", label: "分析记忆", icon: Brain },
  { href: "/admin/profiles", label: "账号会话画像", icon: UserSearch },
  { href: "/admin/rules", label: "规则配置", icon: SlidersHorizontal },
  { href: "/admin/skills", label: "技能库", icon: Sparkles },
  { href: "/admin/reports", label: "报告", icon: ScrollText },
  { href: "/admin/settings", label: "系统配置", icon: Settings },
];

export function Nav() {
  const pathname = usePathname();
  const router = useRouter();
  const [scopeWarn, setScopeWarn] = React.useState(false);

  // 首次使用强制向导：未配置任何分析网段 -> 跳 /setup
  React.useEffect(() => {
    if (pathname.startsWith("/setup")) return;
    let alive = true;
    apiFetch<ScopeStatus>("/api/analysis-scopes/status")
      .then((s) => {
        if (!alive) return;
        if (!s.configured) {
          router.replace("/setup");
          return;
        }
        setScopeWarn(s.enabled_count === 0);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [pathname, router]);

  return (
    <>
      {scopeWarn && (
        <div className="fixed left-56 right-0 top-0 z-40 bg-destructive px-4 py-1 text-center text-xs text-destructive-foreground">
          未启用任何分析网段，智能体不会分析任何日志 —— 请到「系统配置 → 分析网段」启用
        </div>
      )}
      <aside className="fixed left-0 top-0 flex h-screen w-56 flex-col border-r bg-card">
        <div className="flex items-center gap-2 border-b p-4">
          <Shield className="h-6 w-6 text-primary" />
          <span className="text-lg font-bold">深瞳</span>
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
                  active
                    ? "bg-primary text-primary-foreground"
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
    </>
  );
}
