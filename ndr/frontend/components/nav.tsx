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
 * - 归属判断改用分区前缀（`NavSection.match`），配置管理 8 个二级页切换时侧边栏不再消失；
 * - 顶部写明分区名、子页按 `group` 分组，8 条平铺时找「配置体检」要逐条读。
 *
 * 2026-10 五次改版（**对照桌面「深信服界面」实拍图**，纠正四次改版的误判）：
 * - 深信服 SIP 的实际结构是「**深色顶栏 + 浅色侧栏 + 浅色内容**」——四次改版把侧栏也翻深了，
 *   与实拍不符。这里把侧栏**回到浅色**：白底、浅灰描边，只有页头保持深藏青。
 * - 激活项：**浅蓝底 + 主色文字 + 左侧 3px 主色竖条**（深信服激活态），与白色侧栏形成
 *   「选中一块浅蓝」的块面感，而不是深底上的蓝底白字。
 * - 未激活项深灰字、hover 抬一档表面（`surface-1`），文字转深 —— 表面差而非色相差。
 * - 分组标题沿用「3px 竖条 + 灰字」，与激活项同一根标尺。
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

  // 还在用出厂口令的话，一直挂一条提醒（点进「配置管理 → 账户」改）。
  // 这是**被动**读：令牌失效时不要把人踢回登录页（否则每切一个菜单就被弹一次），
  // 只把告警条收起来，导航照常可用。
  React.useEffect(() => {
    let alive = true;
    apiFetch<AuthMe>("/api/auth/me", {}, { redirectOn401: false })
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
                      // 分组标题前的 3px 小竖条与激活项左侧那根同款：分组边界靠「一根标尺」
                      // 表达，不靠多加的灰字层级
                      "flex items-center gap-1.5 px-3 pb-1.5 text-xs font-medium text-muted-foreground max-lg:hidden",
                      // 分组用「1px 线 + 12px」而不是「16px 空白」：32px 的密集条目之间，
                      // 只用间距表达的分组会被读成「一条特别宽的空隙」而不是分组边界。
                      i === 0 ? "pt-0" : "mt-2 border-t border-border-subtle pt-3",
                    )}
                  >
                    <span aria-hidden className="h-2.5 w-[3px] shrink-0 rounded-full bg-primary" />
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
                  // relative：给激活项的 before 竖条当定位锚（见下）
                  "group relative mb-0.5 flex h-8 items-center gap-2 rounded-sm px-3 text-13 transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40",
                  // 图标轨（<1024）：居中图标、取消横向 padding
                  "max-lg:justify-center max-lg:gap-0 max-lg:px-0",
                  active
                    ? // 深信服激活态：浅蓝底 + 主色文字 + 左侧 3px 主色竖条。竖条 before:-left-2
                      // 抵消 nav 的 px-2，贴在侧栏左缘（overflow 裁剪发生在 padding box，
                      // -2 落进 padding 区，不会被滚动容器切掉）。
                      "bg-brand-50 font-medium text-primary before:absolute before:-left-2 before:top-1/2 before:h-4 before:-translate-y-1/2 before:w-[3px] before:rounded-full before:bg-primary max-lg:before:left-0"
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


/** 兼容别名：`Nav` 与 `SideNav` 是同一组件，`PageShell` 仍按 `Nav` 导入使用。 */
export const Nav = SideNav;
