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
 *
 * 2026-10 三次改版（用户反馈「功能配置菜单不美观简洁」）：
 * - 条目从「图标 + 标题 + 描述」三行改成**单行**（`h-8`，32px）。8 条从 620px 降到约 380px，
 *   1080p 上不再需要滚动。描述搬到 `title`（鼠标悬停出原生提示），并补一行 `sr-only`
 *   —— `title` 在键盘聚焦时不弹、读屏支持也不一致，只给 `title` 等于把描述丢给了鼠标用户。
 * - 选中态从 5 个信号减到 2 个（去掉左侧竖条），hover 从「色相差」改成「表面差」
 *   （`bg-surface-1`），让 hover 与选中分属两个视觉通道（详见下方注释）。
 * - 宽度改吃 CSS 变量 `--sidebar-w`，与 `page-shell` 的 `ml-` 同源（见 globals.css）。
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
    // 侧栏宽必须吃 CSS 变量：对面 page-shell 的 `ml-[var(--sidebar-w)]` 是同一个值，
    // 写两处硬编码（w-60 / ml-60）时改一边就会错位。
    <aside className="fixed left-0 top-14 flex h-[calc(100vh-3.5rem)] w-[var(--sidebar-w)] flex-col border-r border-border bg-card">
      {/* 分区名：页头的一级菜单只标「选中」，侧边栏顶部再写一次，是为了让这块面板有主语 ——
          8 个二级页来回切的时候，标题不动、只有下面高亮在动，位置感才稳。
          图标轨（<1024）下 56px 放不下 4 个中文字符（会挤成竖排），整块隐藏。 */}
      {section ? (
        <div className="shrink-0 border-b border-border-subtle px-4 py-2.5 max-lg:hidden">
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
                <>
                  {/* 图标轨下组名放不下，分组的「隔断」语义用 1px 分隔线表达 */}
                  <div
                    aria-hidden
                    className="mx-2 my-2 border-t border-border-subtle lg:hidden"
                  />
                  <p
                    className={cn(
                      "px-3 pb-1.5 text-xs font-medium text-muted-foreground/70 max-lg:hidden",
                      // 分组用「1px 线 + 12px」而不是「16px 空白」：32px 的密集条目之间，
                      // 只用间距表达的分组会被读成「一条特别宽的空隙」而不是分组边界。
                      i === 0 ? "pt-0" : "mt-2 border-t border-border-subtle pt-3",
                    )}
                  >
                    {it.group}
                  </p>
                </>
              ) : null}
              <Link
                href={it.href}
                // 图标轨下只剩图标，`title` 里必须带上名字；图标轨以外也读得到完整描述 ——
                // 两种状态都合理的写法，不用 JS 判断当前是不是窄屏。
                title={it.desc ? `${it.label} · ${it.desc}` : it.label}
                aria-current={active ? "page" : undefined}
                className={cn(
                  // 选中态信号从 5 个减到 2 个：`bg-brand-50` + `text-primary`（图标继承
                  // currentColor 算同一个信号）。去掉了左侧 2px 竖条 —— 32px 单行条目下
                  // 眼睛落在文字上（x≈12）而不是最左边缘（x=0..2），竖条基本看不见，
                  // 而它 + 底色 + 双色文字在亮色主题上读起来偏重。
                  // hover 从「色相差」改成「表面差」（bg-surface-1）：原来 `--accent` 与
                  // `--brand-50` 是同一个值，扫过侧栏时当前页那一条会「消失」在其余 7 条里。
                  // 表面层级 vs 品牌色是两个通道，不可能混淆。
                  "group mb-0.5 flex h-8 items-center gap-2 rounded-sm px-3 text-13 transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
                  // 图标轨（<1024）：居中图标、取消横向 padding
                  "max-lg:justify-center max-lg:gap-0 max-lg:px-0",
                  active
                    ? "bg-brand-50 font-medium text-primary"
                    : "text-muted-foreground hover:bg-surface-1 hover:text-foreground",
                )}
              >
                {it.icon ? (
                  // 颜色继承 currentColor，不单独染色：选中/未选中的变化由上面的 text-* 统一带出来
                  <it.icon className="h-4 w-4 shrink-0" />
                ) : null}
                {/* sr-only 不是 hidden：`hidden` 会把标签从无障碍树里一起移除，
                    图标轨下这条导航就只剩一个无名的 SVG，读屏会宣读「链接」。
                    sr-only 是 position:absolute + clip，视觉上等于隐藏但保留可访问名。 */}
                <span className="truncate max-lg:sr-only">{it.label}</span>
                {it.desc ? <span className="sr-only">{it.desc}</span> : null}
              </Link>
            </React.Fragment>
          );
        })}
      </nav>
      {me?.default_password_in_use && (
        <div className="border-t border-border-subtle p-3">
          <Link
            href="/config/account"
            title="仍在使用出厂口令 —— 点这里去改"
            className="flex items-start gap-2 rounded-sm border border-sev-critical-bd bg-sev-critical-bg px-2 py-2 text-xs text-sev-critical-fg hover:brightness-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 max-lg:justify-center max-lg:gap-0 max-lg:px-0"
          >
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 max-lg:mt-0" />
            {/* 图标轨下文字会挤成竖排，只留图标 + title */}
            <span className="max-lg:sr-only">仍在使用出厂口令 —— 点这里去改</span>
          </Link>
        </div>
      )}
    </aside>
  );
}


/** 兼容旧引用（`app/admin/*` 里有页面直接渲染 `<Nav />`）：语义与 `SideNav` 相同。 */
export const Nav = SideNav;
