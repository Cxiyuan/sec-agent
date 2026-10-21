import * as React from "react";
import { HelpCircle } from "lucide-react";
import { cn } from "../../lib/utils";

/**
 * 配置页「背景板」：一块铺满正文区域的底板，所有设置分区**内嵌**在它里面。
 *
 * 为什么要有它：改版前每块配置各自一张 `Card`（描边 + 圆角 + 投影 + 彼此留 gap），
 * 一屏里出现好几个互不相连的盒子，盒子周围和右半边全是空白，读起来像补丁拼出来的。
 * 深信服 SIP 的设置区是**一整块底板**：分区之间只有 1px 分隔线、没有独立盒子，
 * 分区标题是一条贴着板边的浅灰标题条 —— 视觉上是「嵌进板里」，不是「摆了几个盒子」。
 *
 * 用法（与 `SettingsBlock` 配套，不要在里面再套 Card）：
 *   <SettingsBoard>
 *     <SettingsBlock title="采集网卡">…表单…</SettingsBlock>
 *     <SettingsBlock title="当前生效" rail={…}>…表单…</SettingsBlock>
 *   </SettingsBoard>
 *
 * 需要占满整幅的块（大表格、管道全文编辑器）也直接当它的子节点，宽度就是整幅。
 */
export function SettingsBoard({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        // overflow-hidden：分区标题条要贴着板边，圆角不能被内部直角顶破
        "overflow-hidden rounded-sm border border-border bg-card",
        className,
      )}
    >
      {/* divide-y：分区之间只有一条 1px 分隔线 —— 内嵌感的来源 */}
      <div className="divide-y divide-border">{children}</div>
    </div>
  );
}

/**
 * 内嵌在 `SettingsBoard` 里的一个设置分区。
 *
 * 结构 = 标题条（浅灰、贴板边、蓝竖条）+ 内容区（白底），没有自己的描边/圆角/投影，
 * 所以看起来是「板上的一段」而不是「又一个盒子」。
 *
 * 需要「可编辑 + 只读」双列时传 `rail`：右侧一列用一条竖分隔线隔开（不是第二张卡），
 * 窄屏（<1280）自动叠成一列、中间用横线分隔。
 */
export function SettingsBlock({
  id,
  title,
  description,
  extra,
  help,
  rail,
  children,
  className,
  bodyClassName,
}: {
  /** 锚点 id：页内跳转用 */
  id?: string;
  /** 分区标题（不传 = 只有内容区，没有标题条） */
  title?: React.ReactNode;
  /** 标题下的一句话说明 */
  description?: React.ReactNode;
  /** 标题行右侧：按钮、徽章、统计数 */
  extra?: React.ReactNode;
  /** 标题右侧的「?」说明图标（深信服风格）：传字符串 = 悬浮提示文案 */
  help?: React.ReactNode;
  /** 右侧只读列（当前生效值 / 运行状态），不传则为单列 */
  rail?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  /** 内容区的附加类（例如内容本身是表格时要去掉内边距） */
  bodyClassName?: string;
}) {
  const body = (
    <div className={cn("px-4 py-3", bodyClassName)}>{children}</div>
  );

  return (
    <section id={id} className={cn("scroll-mt-20", className)}>
      {title ? (
        <div className="flex flex-wrap items-end justify-between gap-x-3 gap-y-1 bg-surface-1 px-4 py-2.5">
          <div className="min-w-0">
            <h2 className="flex items-center gap-2 text-13 font-medium leading-5 text-foreground">
              {/* 深信服式分区标尺：3px 圆角竖条 + 标题 */}
              <span aria-hidden className="h-3.5 w-[3px] shrink-0 rounded-full bg-primary" />
              {title}
              {help ? (
                <button
                  type="button"
                  aria-label={typeof help === "string" ? help : "本区说明"}
                  title={typeof help === "string" ? help : undefined}
                  className="ml-1 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-sm text-muted-foreground transition-colors hover:bg-surface-1 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
                >
                  <HelpCircle className="h-4 w-4" />
                </button>
              ) : null}
            </h2>
            {description ? (
              <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{description}</p>
            ) : null}
          </div>
          {extra ? <div className="flex flex-wrap items-center gap-2">{extra}</div> : null}
        </div>
      ) : null}

      {rail ? (
        <div className="grid items-start gap-0 xl:grid-cols-[minmax(0,1fr)_19rem]">
          {body}
          {/* 竖线分隔而不是第二张卡：两列同属一块板 */}
          <div className="min-w-0 border-t border-border bg-surface-1/50 px-4 py-3 xl:border-l xl:border-t-0">
            {rail}
          </div>
        </div>
      ) : (
        body
      )}
    </section>
  );
}
