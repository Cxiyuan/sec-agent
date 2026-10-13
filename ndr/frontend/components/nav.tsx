"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Bot,
  Database,
  Settings,
  Filter,
  GitBranch,
  Share2,
  LayoutDashboard,
  Network,
  Radio,
  SlidersHorizontal,
  UserRound,
} from "lucide-react";
import { cn } from "@shentong/ui";
import { apiFetch, type AuthMe, type NetworksStatus } from "@/lib/api";
import { loadAliases } from "@/lib/aliases";

// 第 7 期拆页：左侧导航按链路分段。
// 第一项「总览」（运行状态页，路由仍是 /admin/status）同时是默认落地页（`/` 重定向到这里）；
// logo、当前用户、退出登录、告警铃铛都在全局页头（components/topbar.tsx）。
const items = [
  { href: "/admin/status", label: "总览", icon: LayoutDashboard },
  // 行为分析：基线与画像的「看得见的明细 + 可调参数」（与总览的概览图互补）
  { href: "/admin/behavior", label: "行为分析", icon: Activity },
  // 攻击链还原：真实请求IP →（中继…）→ 源站的链路与动作事实
  { href: "/admin/chain", label: "攻击链还原", icon: GitBranch },
  { href: "/admin/rules", label: "检测规则", icon: SlidersHorizontal },
  { href: "/admin/collect", label: "采集接入", icon: Radio },
  { href: "/admin/networks", label: "监控网段", icon: Network },
  // 拓扑发现：自动发现网络拓扑（转发链路 / 全量通信两视图）
  { href: "/admin/topology", label: "拓扑发现", icon: Share2 },
  { href: "/admin/storage", label: "数据存储", icon: Database },
  { href: "/admin/config", label: "配置体检", icon: Settings },
  { href: "/admin/filters", label: "过滤规则", icon: Filter },
  { href: "/admin/agent", label: "智能体对接", icon: Bot },
  { href: "/admin/account", label: "账户", icon: UserRound },
];

export function Nav() {
  const pathname = usePathname();
  const router = useRouter();
  const [me, setMe] = React.useState<AuthMe | null>(null);

  // 节点别名是全局展示层数据：导航在每个页面都挂载，顺手在全局拉一次（已拉过就不再请求）
  React.useEffect(() => {
    void loadAliases();
  }, []);

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
    <aside className="fixed left-0 top-14 flex h-[calc(100vh-3.5rem)] w-56 flex-col border-r bg-card">
      <nav className="flex-1 space-y-1 overflow-auto p-3">
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
      {me?.default_password_in_use && (
        <div className="border-t p-3">
          <Link
            href="/admin/account"
            className="block rounded-md border border-destructive/40 bg-destructive/5 px-2 py-2 text-xs text-destructive hover:bg-destructive/10"
          >
            仍在使用出厂口令 admin123 —— 点这里去改
          </Link>
        </div>
      )}
    </aside>
  );
}
