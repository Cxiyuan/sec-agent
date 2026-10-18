import * as React from "react";
import { cn } from "../../lib/utils";

/**
 * 配置页正文的双列编排：**主列放「能改的」，侧栏放「只能看的」**。
 *
 * 为什么需要它：配置页原来是「一张卡接一张卡」的竖排，改一个字段要滚三屏，
 * 而只读的「当前生效 / 集群状态 / 连接信息」和可编辑的表单混在一列里 ——
 * 运维的眼睛得在同一列里反复分辨「这条能不能改」，看错就会去点只读卡片找输入框。
 *
 * 编排名：主列宽（表单、列表要横向空间），侧栏窄（只读事实，两行一条）。
 * 只读块永远在右侧同一列，位置固定之后扫视成本是 0；窄屏（<1280）自动叠成一列，
 * 主列仍在前 —— 手机上先看到的是能操作的东西。
 *
 * 用法：
 *   <Section title="…">
 *     <SettingsGrid>
 *       <SettingsMain>…可编辑的 Card / 操作条…</SettingsMain>
 *       <SettingsRail>…只读的 Card…</SettingsRail>
 *     </SettingsGrid>
 *   </Section>
 *
 * 需要占满两列的块（大表格、管道全文编辑器）不要塞进任何一列，直接放在
 * `SettingsGrid` 的前面或后面当 Section 的兄弟节点，它们的宽度就是整幅。
 */
export function SettingsGrid({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        // items-start：两列各自按内容高度排，侧栏不会被主列拉长成一整块空白底板
        "grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_19rem]",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** 主列：可编辑表单、列表、操作条。`min-w-0` 保证表格能在列内正常收缩。 */
export function SettingsMain({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <div className={cn("min-w-0 space-y-3", className)}>{children}</div>;
}

/**
 * 侧栏：只读状态与说明。
 *
 * 里面请放只读 Card（当前生效值、连接信息、运行状态），不要放表单 ——
 * 一旦侧栏出现输入框，「右侧=只读」这个约定就废了。
 *
 * 白名单（超出即违规）：
 *   ✅ 当前生效值的 key/value（一行一条，`divide-y divide-border-subtle`）
 *   ✅ 运行状态徽章组（≤ 4 个 Badge）
 *   ✅ `Stat size="sm"` 小格，最多 4 个
 *   ✅ `sev-*` 三件套提示条
 *   ✅ 至多**一个**按钮，且必须是作用于整页的动作（刷新 / 立即检查更新），不能是表单提交
 * 黑名单：
 *   ❌ 列数 > 3 的表（304px 里放 3 列 ⇒ 每列 90px，单元格内容全变成竖排省略号）
 *   ❌ textarea / 代码编辑器 / 长样本（304px 宽的 textarea 里一行 CIDR 要折两次）
 *   ❌ 行数 > 8 且行内含 `font-mono` 或 > 20 字中文的列表
 *   ❌ 任何需要横向滚动的内容（滚动区域只有半指宽，几乎拖不动）
 *   ❌ 表单控件
 *
 * 卡数上限 3 张：超过就合并成一张「当前状态」卡内部 `divide-y` 分段 —— 4 张以上时 rail 高度
 * 超过主列，视觉上变成「右栏才是主内容」，和「主列放能改的」这个编排列矛盾。
 *
 * `xl:sticky`：滚动长表单时「当前生效值」一直在视野里，填字段不用滚上去对。
 * 前置条件是 `SettingsGrid` 必须保持 `items-start`（见上文），否则两列等高、sticky 失效。
 * 高度预算：1080p 上可用约 932px，3 张卡 ≈ 624px；超了就合并 / 删行，**不要**加
 * `overflow-auto`（页面滚动条 + rail 内滚动条 = 双重滚动，304px 宽里拖不动）。
 *
 * `max-xl:max-w-[34rem]`：堆叠态（<1280）下主列不再被 rail 挤，只读卡会被拉到 991px 宽、
 * 右半边全空。收到 544px（≈ 主列两列字段 + 一个 gap）后，视觉上和上方表单是同一套栅格。
 */
export function SettingsRail({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "min-w-0 space-y-3",
        // 堆叠态收窄：只读卡不被拉满整幅
        "max-xl:max-w-[34rem]",
        // 两列态粘在页头下方（4.25rem = 页头 3.5rem + 0.75rem，与 PageShell 的 pt 同值）
        "xl:sticky xl:top-[4.25rem]",
        className,
      )}
    >
      {children}
    </div>
  );
}
