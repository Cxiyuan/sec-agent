"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { FileText, LayoutDashboard, ListOrdered, ScrollText, Server, Shield, SlidersHorizontal } from "lucide-react";
import { cn } from "@/lib/utils";
import { clearToken } from "@/lib/api";
import { Button } from "@/components/ui/button";

const items = [
  { href: "/dashboard", label: "驾驶舱", icon: LayoutDashboard },
  { href: "/admin", label: "事件列表", icon: ListOrdered },
  { href: "/admin/assets", label: "资产管理", icon: Server },
  { href: "/admin/documents", label: "知识文档", icon: FileText },
  { href: "/admin/rules", label: "规则配置", icon: SlidersHorizontal },
  { href: "/admin/reports", label: "报告", icon: ScrollText },
];

export function Nav() {
  const pathname = usePathname();
  const router = useRouter();

  return (
    <aside className="fixed left-0 top-0 flex h-screen w-56 flex-col border-r bg-card">
      <div className="flex items-center gap-2 border-b p-4">
        <Shield className="h-6 w-6 text-primary" />
        <span className="text-lg font-bold">深瞳</span>
      </div>
      <nav className="flex-1 space-y-1 p-3">
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
  );
}
