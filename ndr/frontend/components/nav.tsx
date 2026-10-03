"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Bot,
  Database,
  Filter,
  Network,
  Radio,
  Settings,
  Shield,
  SlidersHorizontal,
  UserRound,
} from "lucide-react";
import { cn, Button } from "@shentong/ui";
import { apiFetch, clearToken, type AuthMe, type NetworksStatus } from "@/lib/api";

// 第 7 期拆页：左侧导航按链路分段，配置总览（/admin/settings）挂在左上角标题上。
const items = [
  { href: "/admin/rules", label: "规则配置", icon: SlidersHorizontal },
  { href: "/admin/collect", label: "采集接入", icon: Radio },
  { href: "/admin/networks", label: "监控网段", icon: Network },
  { href: "/admin/storage", label: "数据存储", icon: Database },
  { href: "/admin/filters", label: "过滤规则", icon: Filter },
  { href: "/admin/agent", label: "智能体对接", icon: Bot },
  { href: "/admin/status", label: "运行状态", icon: Activity },
  { href: "/admin/account", label: "账户", icon: UserRound },
];

export function Nav() {
  const pathname = usePathname();
  const router = useRouter();
  const [me, setMe] = React.useState<AuthMe | null>(null);

  // 首次使用强制向导：未配置监控网段 -> 跳 /setup（网段同时也是 Zeek 的抓包范围）
  React.useEffect(() => {
    if (pathname.startsWith("/setup")) return;
    let alive = true;
    apiFetch<NetworksStatus>("/api/zeek/networks/status")
      .then((s) => {
        if (alive && !s.configured) router.replace("/setup");
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [pathname, router]);

  // 还在用出厂口令的话，导航栏一直挂一条红字提醒（点进「账户」改）
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

  return (
    <>
      <aside className="fixed left-0 top-0 flex h-screen w-56 flex-col border-r bg-card">
        <Link
          href="/admin/settings"
          title="系统配置总览"
          className="flex items-center gap-2 border-b p-4 hover:bg-accent"
        >
          <Shield className="h-6 w-6 text-primary" />
          <span className="text-lg font-bold">深瞳 · NDR</span>
          <Settings className="ml-auto h-4 w-4 text-muted-foreground" />
        </Link>        <nav className="flex-1 space-y-1 overflow-auto p-3">
          {items.map((it) => {
            const active =
              pathname === it.href || pathname.startsWith(it.href + "/");
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
          {me?.default_password_in_use && (
            <Link
              href="/admin/account"
              className="mb-2 block rounded-md border border-destructive/40 bg-destructive/5 px-2 py-2 text-xs text-destructive hover:bg-destructive/10"
            >
              仍在使用出厂口令 admin123 —— 点这里去改
            </Link>
          )}
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
