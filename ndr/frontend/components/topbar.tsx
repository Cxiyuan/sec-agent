"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Bell, ChevronDown, LogOut, Shield } from "lucide-react";
import { formatDateTime } from "@shentong/ui";
import { apiFetch, clearToken, type AgentPushPayload, type AuthMe, type DetectorStats } from "@/lib/api";
import { NAV_SECTIONS, sectionActive } from "@/lib/nav-config";
import { cn } from "@shentong/ui";

/**
 * 全局页头：左侧 logo（**纯展示**）+ **一级菜单**（运营中心 / 分析中心 / 资产中心 / 行为画像 / 配置管理），
 * 右侧依次是告警铃铛 / 当前用户 / 退出登录。
 *
 * 2026-10 改版：一级菜单从侧边栏搬到页头；「分析中心」鼠标停留即展开二级菜单
 * （日志检索 / 可视化流量），其余分区点一下进默认子页，由侧边栏切换子页。
 *
 * 为什么把 logo 从侧边栏搬到页头：侧边栏只管「去哪个页面」，页头承担「我是谁、现在有没有事」
 * —— 告警与账号是一眼要看到的东西，固定在最上方、宽度铺满，滚动时不跟着走。
 *
 * 「系统配置总览」页与齿轮入口已取消（用户 2026-10 要求）：配置项都在左侧各页里，
 * 不需要一层索引页。
 *
 * 2026-10 复刻深信服 SIP：页头与侧边栏同为深藏青（`--sidebar-*`），连成一整块深色
 * chrome（深信服就是「深顶栏 + 深侧栏 + 浅内容」）。下拉/铃铛浮层仍是浅色卡片 ——
 * 深色栏上挂浅色浮层是正常模式，阴影已经表达了层级。
 *
 * 铃铛的语义（本页自己聚合，不新增后端接口）：把**需要马上处理**的运行告警汇成一个数，
 * 点开每条都能跳到对应页面。数据源都是既有的只读接口，取不到就当没有（不报错、不挡住页面）。
 */

interface Notice {
  key: string;
  text: string;
  href: string;
  danger?: boolean;
}

/** 把检测器 / 摘要推送的现状折成「需要注意的事项」。只收真正需要动作的，避免铃铛常亮。 */
function noticesOf(stats: DetectorStats | null, push: AgentPushPayload | null): Notice[] {
  const out: Notice[] = [];
  if (stats?.paused) {
    const since = stats.paused_since ? `（自 ${formatDateTime(stats.paused_since)}）` : "";
    out.push({ key: "paused", text: `检测器已暂停消费${since}`, href: "/console", danger: true });
  }
  if (stats?.queue_failed) {
    out.push({
      key: "failed",
      text: `隔离队列 ${stats.queue_failed} 条待人工处理`,
      href: "/console",
      danger: true,
    });
  }
  if (stats?.redis_warn) {
    out.push({
      key: "redis",
      text: `Redis 内存接近上限（${stats.redis?.perc ?? "—"}%），整链路可能卡死`,
      href: "/console",
      danger: true,
    });
  }
  const queueMax = stats?.queue_max ?? 0;
  const queueRaw = stats?.queue_raw ?? 0;
  if (queueMax > 0 && queueRaw > queueMax * 0.8) {
    out.push({
      key: "backlog",
      text: `归一化队列积压 ${queueRaw}（接近上限 ${queueMax}）`,
      href: "/console",
      danger: true,
    });
  }
  if (push && !push.config.active) {
    out.push({
      key: "push-off",
      text: "摘要推送未启用：命中的摘要不会进入分析",
      href: "/config/agent",
      danger: true,
    });
  }
  const pending =
    push?.status.retry_backlog_batches ??
    (push?.status.queue_depth ?? 0) + (push?.status.processing_depth ?? 0);
  if (pending > 0) {
    out.push({ key: "pending", text: `摘要推送待重发 ${pending} 批`, href: "/console" });
  }
  return out;
}

export function TopBar() {
  const pathname = usePathname();
  const router = useRouter();
  const [me, setMe] = React.useState<AuthMe | null>(null);
  const [stats, setStats] = React.useState<DetectorStats | null>(null);
  const [push, setPush] = React.useState<AgentPushPayload | null>(null);
  const [open, setOpen] = React.useState(false);
  const boxRef = React.useRef<HTMLDivElement | null>(null);

  const load = React.useCallback(async () => {
    const [meRes, statsRes, pushRes] = await Promise.allSettled([
      // 页头的三类数据都是**被动轮询**：401 时不要把人踢回登录页
      // （否则切菜单的瞬间会被整页替换走，表现得像「菜单点不动」）。
      apiFetch<AuthMe>("/api/auth/me", {}, { redirectOn401: false }),
      apiFetch<DetectorStats>("/api/detector/stats", {}, { redirectOn401: false }),
      apiFetch<AgentPushPayload>("/api/agent-push", {}, { redirectOn401: false }),
    ]);
    if (meRes.status === "fulfilled") setMe(meRes.value);
    if (statsRes.status === "fulfilled") setStats(statsRes.value);
    if (pushRes.status === "fulfilled") setPush(pushRes.value);
  }, []);

  React.useEffect(() => {
    void load();
  }, [load, pathname]);

  // 30 秒一轮：告警栏要「一眼看到」，但不值得像运行状态页那样 15 秒刷一次
  React.useEffect(() => {
    const t = setInterval(() => void load(), 30000);
    return () => clearInterval(t);
  }, [load]);

  // 点空白 / Esc 收起铃铛面板
  React.useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const notices = noticesOf(stats, push);

  return (
    <header className="fixed inset-x-0 top-0 z-40 flex h-14 items-center gap-3 border-b border-border bg-card px-4">
      <div className="flex items-center gap-2 px-1">
        <Shield className="h-6 w-6 text-primary" />
        <span className="whitespace-nowrap text-base font-semibold tracking-tight">深瞳 · NDR</span>
      </div>

      {/* 一级菜单：分析中心鼠标停留展开二级菜单，其余直接进默认子页 */}
      <nav className="ml-4 flex items-center gap-0.5">
        {NAV_SECTIONS.map((section) => {
          const active = sectionActive(pathname, section);
          return (
            <div key={section.key} className="group relative">
              <Link
                href={section.href}
                title={section.desc}
                className={cn(
                  "flex items-center gap-1 rounded-sm px-3 py-1.5 text-sm transition-colors",
                  active
                    ? "bg-primary/10 font-medium text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )}
              >
                {section.label}
                {section.dropdown ? (
                  <ChevronDown className="h-3.5 w-3.5 opacity-60 transition group-hover:rotate-180" />
                ) : null}
              </Link>
              {section.dropdown ? (
                <div className="invisible absolute left-0 top-full z-50 w-72 pt-1 opacity-0 transition-opacity duration-100 group-hover:visible group-hover:opacity-100 group-focus-within:visible group-focus-within:opacity-100">
                  <div className="rounded-xl border border-border bg-card p-1.5 shadow-3">
                    {section.dropdown.map((item) => (
                      <Link
                        key={item.href}
                        href={item.href}
                        className="flex items-start gap-2 rounded-sm px-3 py-2 hover:bg-accent"
                      >
                        {item.icon ? <item.icon className="mt-0.5 h-4 w-4 shrink-0 text-primary" /> : null}
                        <span className="min-w-0">
                          <span className="block text-sm font-medium text-foreground">{item.label}</span>
                          {item.desc ? (
                            <span className="mt-0.5 block text-xs text-muted-foreground">{item.desc}</span>
                          ) : null}
                        </span>
                      </Link>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          );
        })}
      </nav>

      <div className="ml-auto flex items-center gap-2">
        <div className="relative" ref={boxRef}>
          <button
            type="button"
            aria-label={notices.length ? `告警 ${notices.length} 条` : "告警"}
            title={notices.length ? "有需要处理的事项" : "暂无告警"}
            onClick={() => setOpen((v) => !v)}
            className="relative rounded-sm p-2 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          >
            <Bell className="h-5 w-5" />
            {notices.length > 0 && (
              <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-xs font-medium leading-none text-destructive-foreground">
                {notices.length > 9 ? "9+" : notices.length}
              </span>
            )}
          </button>
          {open && (
            <div className="absolute right-0 mt-2 w-80 rounded-lg border border-border bg-card p-2 shadow-3">
              <p className="px-2 py-1 text-xs text-muted-foreground">
                {notices.length ? `需要处理的运行告警（${notices.length}）` : "暂无需要处理的运行告警"}
              </p>
              {notices.map((n) => (
                <Link
                  key={n.key}
                  href={n.href}
                  onClick={() => setOpen(false)}
                  className={
                    "block rounded-sm px-2 py-2 text-13 hover:bg-accent " +
                    (n.danger ? "text-sev-critical-fg" : "text-muted-foreground")
                  }
                >
                  {n.text}
                </Link>
              ))}
            </div>
          )}
        </div>

        <span className="hidden text-sm text-muted-foreground sm:inline" title="当前登录用户">
          {me?.username ?? "—"}
        </span>

        <button
          type="button"
          className="rounded-sm px-2 py-1 text-sm text-muted-foreground hover:bg-accent hover:text-foreground"
          onClick={() => {
            clearToken();
            router.push("/login");
          }}
        >
          <LogOut className="mr-1 inline h-3.5 w-3.5" />
          退出登录
        </button>
      </div>
    </header>
  );
}
