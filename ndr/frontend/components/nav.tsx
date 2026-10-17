"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldAlert } from "lucide-react";
import { cn } from "@shentong/ui";
import { apiFetch, type AuthMe } from "@/lib/api";
import { loadAliases } from "@/lib/aliases";
import { sidebarOf } from "@/lib/nav-config";

/**
 * 分区侧边栏：只显示**当前页面所属分区**的子页。
 *
 * 2026-10 改版：一级菜单搬到页头（components/topbar.tsx），这里不再是全局导航 ——
 * 运营中心 / 日志检索 / 行为画像 都没有侧边栏（`sidebarOf()` 返回空数组时本组件直接不渲染），
 * 页面正文因此能占满宽度（大表格、拓扑图都需要）。
 */
export function SideNav() {
  const pathname = usePathname();
  const items = sidebarOf(pathname);
  const [me, setMe] = React.useState<AuthMe | null>(null);

  // 节点别名是全局展示层数据：侧边栏在每个页面都挂载，顺手拉一次（已拉过就不再请求）
  React.useEffect(() => {
    void loadAliases();
  }, []);

  // 还在用出厂口令的话，一直挂一条提醒（点进「配置管理 → 账户」改）
  React.useEffect(() => {
    let alive = true;
    apiFetch<AuthMe>("/api/auth/me")
      .then((m) => {
        if (alive) setMe(m);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [pathname]);

  if (items.length === 0) return null;

  return (
    <aside className="fixed left-0 top-14 flex h-[calc(100vh-3.5rem)] w-60 flex-col border-r bg-card">
      <nav className="flex-1 space-y-0.5 overflow-auto p-3">
        {items.map((it) => {
          const active = pathname === it.href || pathname.startsWith(it.href + "/");
          return (
            <Link
              key={it.href}
              href={it.href}
              title={it.desc}
              className={cn(
                "group flex items-start gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-primary/10 font-medium text-primary"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
              )}
            >
              {it.icon ? (
                <it.icon
                  className={cn("mt-0.5 h-4 w-4 shrink-0", active ? "text-primary" : "text-muted-foreground/70")}
                />
              ) : null}
              <span className="min-w-0">
                <span className="block truncate">{it.label}</span>
                {it.desc ? (
                  <span className="mt-0.5 block truncate text-[11px] font-normal text-muted-foreground/80">
                    {it.desc}
                  </span>
                ) : null}
              </span>
            </Link>
          );
        })}
      </nav>
      {me?.default_password_in_use && (
        <div className="border-t p-3">
          <Link
            href="/config/account"
            className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/5 px-2 py-2 text-xs text-destructive hover:bg-destructive/10"
          >
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>仍在使用出厂口令 —— 点这里去改</span>
          </Link>
        </div>
      )}
    </aside>
  );
}


/** 兼容旧引用（`app/admin/*` 里有页面直接渲染 `<Nav />`）：语义与 `SideNav` 相同。 */
export const Nav = SideNav;
