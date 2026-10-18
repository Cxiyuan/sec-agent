"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldAlert } from "lucide-react";
import { cn } from "@shentong/ui";
import { apiFetch, type AuthMe } from "@/lib/api";
import { loadAliases } from "@/lib/aliases";
import { sidebarOf, sidebarSectionOf } from "@/lib/nav-config";

/**
 * 分区侧边栏：只显示**当前页面所属分区**的子页。
 *
 * 2026-10 改版：一级菜单搬到页头（components/topbar.tsx），这里不再是全局导航 ——
 * 运营中心 / 日志检索 / 行为画像 都没有侧边栏（`sidebarOf()` 返回空数组时本组件直接不渲染），
 * 页面正文因此能占满宽度（大表格、拓扑图都需要）。
 *
 * 2026-10 二次改版（用户要求「侧边栏要常驻」）：
 * - 归属判断改用分区前缀（`NavSection.match`），配置管理 8 个二级页切换时侧边栏不再消失 ——
 *   原来按 `href`（/config/collect）判断，只有第一个子页命中，切走就整块消失、正文还会横向跳动。
 * - 顶部写明分区名、子页按 `group` 分组：8 条平铺时找「配置体检」要逐条读，
 *   分成「接入与范围 / 检测与过滤 / 存储与对接 / 诊断与账号」之后是扫一眼定位。
 */
export function SideNav() {
  const pathname = usePathname();
  const items = sidebarOf(pathname);
  const section = sidebarSectionOf(pathname);
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
    <aside className="fixed left-0 top-14 flex h-[calc(100vh-3.5rem)] w-60 flex-col border-r border-border bg-card">
      {/* 分区名：页头的一级菜单只标「选中」，侧边栏顶部再写一次，是为了让这块面板有主语 —— 
          8 个二级页来回切的时候，标题不动、只有下面高亮在动，位置感才稳。 */}
      {section ? (
        <div className="shrink-0 border-b border-border-subtle px-4 py-2.5">
          <p className="text-xs font-medium text-muted-foreground">{section.label}</p>
        </div>
      ) : null}
      <nav aria-label={section?.label} className="flex-1 overflow-auto px-2 py-2">
        {items.map((it, i) => {
          const active = pathname === it.href || pathname.startsWith(it.href + "/");
          const groupHead = !!it.group && it.group !== items[i - 1]?.group;
          return (
            <React.Fragment key={it.href}>
              {groupHead ? (
                <p
                  className={cn(
                    "px-3 pb-1 text-xs font-medium text-muted-foreground/70",
                    i === 0 ? "pt-0" : "pt-4",
                  )}
                >
                  {it.group}
                </p>
              ) : null}
              <Link
                href={it.href}
                title={it.desc}
                aria-current={active ? "page" : undefined}
                className={cn(
                  // 选中态：淡主色底 + 左侧 2px 竖条。只靠底色的话，一屏 8 个条目里
                  // "现在在哪"要靠颜色深浅去猜；竖条是位置信号，扫一眼就知道。
                  // 竖条常驻（未选中时透明），切换时文字不会横向跳动。
                  "group mb-0.5 flex items-start gap-2.5 rounded-sm border-l-2 px-3 py-2 text-sm transition-colors",
                  active
                    ? "border-primary bg-primary/10 font-medium text-primary"
                    : "border-transparent text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                )}
              >
                {it.icon ? (
                  <it.icon
                    className={cn(
                      "mt-0.5 h-4 w-4 shrink-0",
                      active ? "text-primary" : "text-muted-foreground/70",
                    )}
                  />
                ) : null}
                <span className="min-w-0">
                  <span className="block truncate">{it.label}</span>
                  {it.desc ? (
                    <span className="mt-0.5 block truncate text-xs font-normal text-muted-foreground/80">
                      {it.desc}
                    </span>
                  ) : null}
                </span>
              </Link>
            </React.Fragment>
          );
        })}
      </nav>
      {me?.default_password_in_use && (
        <div className="border-t border-border-subtle p-3">
          <Link
            href="/config/account"
            className="flex items-start gap-2 rounded-sm border border-sev-critical-bd bg-sev-critical-bg px-2 py-2 text-xs text-sev-critical-fg hover:brightness-[0.98]"
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
