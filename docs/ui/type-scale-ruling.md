# 字号层级裁定：侧边栏 + 配置页（视觉档位，不含代码改动）

> 任务来源：用户反馈「调整侧边栏 配置页面的字体 他们显示的太大了与页面整体风格不匹配」。
> 本文只做**档位裁定 + 改动清单**，不落代码。落地由 fe-engineer 按第 3 节执行。
> 依据：team-lead 给的代码事实表（已逐条复核，行号一致）+ 桌面「深信服界面」6 张 1920×911 实拍图的**逐行像素实测**。
> 合法档位（不可扩充）：`text-xs`(12) / `text-13`(13) / `text-sm`(14) / `text-base`(16) / `text-28`(28)。禁 `font-bold`。

---

## 0. 结论：三个问题的直接回答

| 问题 | 裁定 | 一句话理由 |
|---|---|---|
| 输入框该不该降到 13？ | **该，14 → 13** | 它是配置页里唯一比自己的标签、比块标题都大的文字，**层级是倒的**；实测图中标签与值是同一号 |
| 侧栏该不该降到 12？ | **该，13 → 12**（连带：侧栏分区名 12 → 13） | 侧栏是**二级导航**（一级在顶栏 14），13 与正文同重，导航在跟内容抢；降一档后「顶栏 14 > 正文 13 > 侧栏项 12」成立 |
| `Section` 16 要不要动？ | **不动，保留 16** | 页面 `h1` 是 `sr-only`（`page-shell.tsx:86`），16 是**唯一的可见页级锚点**；实测图页标题/正文 = 1.38，我们 16/13 = 1.23，已经比参考更克制 |

一句话总结：**问题不是「整体偏大」，是一次层级错位**——控件（14）压过了标签（13）和块标题（13），侧栏（13）压过了它应有的位置。修法是把这两处**归位**，不是乘系数。

---

## 1. 实拍图实测：为什么是这三个答案

方法：取 `深信服界面/d000c6e7-….png`（1920×911，通报设置页，同时含侧栏 + 表单 + 主按钮 + 页标题），对指定区域逐行统计暗像素（luma < 150）得到**字面 ink 高度**。绝对像素受对方浏览器缩放影响，**只用同一张图内的比值**。

| 元素 | ink 高（图像 px） | 相对表单正文 |
|---|---|---|
| 页标题「通报设置」 | 20 | 1.38 |
| 区块标题「研判方式 / 通报下级资产组模板 / 处置时间设置」 | 17（三处一致） | 1.17 |
| 主按钮「确定」白字（按钮 105×37） | 17 | 1.17 |
| 侧栏项「通报中心 / 预警中心 / 公告栏」 | 17–18 | 1.20 |
| 侧栏分区名「通报预览」 | 19 | 1.31 |
| 表单正文：标签「要求处理天数」「剩余处理时间提醒」、复选文字「邮件 / 短信」 | 14–15 | 1.00 |

三条读数：

1. **表单里所有文字是同一号**：标签 = 值 = 复选文字 = 14–15。没有「控件字比标签大」这回事。
2. **容器标题、按钮、侧栏项共处一级**：都是 1.17–1.20 倍正文。
3. **页标题再高一级**：1.38 倍。

校准推断（仅作参照，不当结论用）：若对方浏览器是 120% 缩放，换算成 CSS 约为 **正文 12 / 标题·按钮·导航 14 / 页标题 16.7**——一套「chrome 14 / content 12」的两层系统。

对照我们现在的配置页：

| | 参考图 | 我们（改前） |
|---|---|---|
| 表单标签 vs 值 | 同号 | **标签 13 / 值 14（值大一号）** |
| 块标题 vs 正文 | 高一级（1.17） | **13 vs 14（标题比正文小）** |
| 侧栏项 vs 正文 | 高一级（1.20） | **13 vs 13（同号，导航与内容抢）** |
| 页标题 vs 正文 | 1.38 | 1.23（`Section` 16，保留） |

**结论**：参考图里「层级差」是稳定的 1.17–1.38；我们的问题是三处**倒挂**，其中两处正是用户点名的侧栏与配置页。所以裁定方向是「把标题抬回一级、把控件与侧栏压回它该在的位置」，而不是整体缩放。

### 1.1 侧栏：为什么最终选 12，尽管参考图的侧栏更大

参考图的侧栏项（1.20 倍正文）比我们现在的 13 还**大**。照抄它只会让侧栏更大，所以这不是「对齐参考图」，是三个我方条件共同决定的：

- 我们的一级导航是顶栏 **14**，侧栏是**二级**；同尺寸的两级导航里，下级不能和正文同重。
- 我们的正文是 **13**（`tailwind.config.ts:163` 已写明「12 偏小、14 太松，13 是密集表格的平衡点」），侧栏项 13 = 正文 13，没有「导航比内容高一档」的余地，只能往下走。
- 参考图侧栏行距 61px（≈51 CSS）、宽 295px，我们的行距 34px、宽 240px——**在更紧的容器里放同样的字号，读起来就是更大**。要么加行距/加宽，要么降字号。用户要的是后者，且 12 是合法档位的地板。

**如果 12 仍觉得大，下一根杠杆不是字号而是行距/宽度**（`h-8` → `h-9`、`--sidebar-w` 240 → 256）——那时要按布局改，不要再造 `text-[11px]`。

12px 不影响可读性下限：侧栏未选中项走 `--muted-foreground`（`213 16% 32%`，白底约 **7.4:1**，`globals.css` 注释已标 AAA 档），WCAG 对字号本身没有最小要求，只要求 4.5:1；选中项是 `text-primary` + `bg-brand-50`，对比更高。

---

## 2. 新字号阶梯（唯一真源，五档不动）

| 档 | 语义 | 元素 |
|---|---|---|
| **16** | 页级分区 | `Section` L1 标题（`h2`）；页头品牌（独立层，不动） |
| **14** | L2 容器标题 / 动作 / 主导航 | `CardTitle`、`SettingsBlock` 标题（**13→14**）、`Dialog`/`Drawer` 标题、`Button` default、顶栏一级菜单、规则树根行（`spec §4.3` L1）、成功/错误消息条 |
| **13** | 内容与控件 | 表格正文、`Input`（**14→13**）、所有 select（**14→13**）、普通 textarea、checkbox/radio 标签、`Button size="sm"`、树 L2/L3 名称、侧栏分区名（**12→13**） |
| **12** | 元信息与次级导航 | 表格表头、hint、description、stacked 标签、**`Field` row 模式标签（13→12，2026-10-28 用户裁定，见 §7）**、chips、`Badge`、分页文字、侧栏项（**13→12**）、侧栏分组标题 |
| **28** | 唯一英雄数字 | KPI 首格（`auditor §5.2`：只给事实，不给判断） |

变化只有四处：`Input` 与 select 14→13、`SettingsBlock` 13→14、侧栏项 13→12、侧栏分区名 12→13。其余档位全部原地不动。

**为什么 `SettingsBlock` 要抬到 14（不是压到 13）**：`CardTitle` 已经是 `text-sm`（`card.tsx:33`）、`Dialog`/`Drawer` 标题也是 `text-sm`，`section.tsx` 头注释写明「L2 Card = 14px 标题」——**L2 容器标题 = 14 是既有约定，`SettingsBlock` 的 13 是实现偏离**。同时这也是唯一能让「标题 > 正文」重新成立的取值（正文 13，标题只能 14）。

**两条配套约束见 §4.7**（表头锁 12、12 与 13 相邻的最小间距）——它们是本批次验收项，不加就等于没定。

### 2.1 文档写法分工（避免两份文档对同一段代码各说一次）

- **叙述与档位表写语义数字**（12/13/14/16/28），不写 `text-xs`/`text-sm` 这类实现别名——别名将来一动，四份文档全飘；
- **代码样本写真实类名**（必须能直接抄进 tsx）；
- **类名 ↔ 档位的映射只在本节（§2）维护一处**，其他文档引用本节，不复制定义。

---

## 3. 落地清单（`文件:行 → 现 → 改`）

### A. 组件基类（4 行，必改）

| 文件:行 | 现 | 改 | 备注 |
|---|---|---|---|
| `packages/ui/src/components/ui/input.tsx:13` | `… px-3 py-1 text-sm …` | `text-sm` → `text-13` | 全站输入框一处生效 |
| `packages/ui/src/components/ui/settings-board.tsx:88` | `text-13 font-medium leading-5` | `text-13` → `text-sm` | 连带 `:90` 蓝条 `h-3.5` → `h-3`（见 4.4） |
| `ndr/frontend/components/nav.tsx:107` | `… px-3 text-13 transition-colors` | `text-13` → `text-xs` | 侧栏项 |
| `ndr/frontend/components/nav.tsx:68` | `text-xs font-medium text-muted-foreground` | `text-xs` → `text-13` | 侧栏分区名（层级归位，见 1.1） |

### B. 共享下拉类常量（2 行）

| 文件:行 | 现 | 改 | 备注 |
|---|---|---|---|
| `ndr/frontend/components/condition-editor.tsx:38` | `export const SELECT_CLS = "h-9 … text-sm …"` | `text-sm` → `text-13` | 规则页条件编辑器 + `config/rules/page.tsx:1158` 共用，改一处 |
| `ndr/frontend/components/zeek-panel.tsx:22` | `const SELECT_CLS = "h-9 … text-sm …"` | `text-sm` → `text-13` | 与上面是**重复定义**（不是 import）；同批改，暂不合并 |

### C. 内联控件（19 行，全部 `text-sm` → `text-13`）

| 文件:行 | 备注 |
|---|---|
| `ndr/frontend/components/analysis-panel.tsx:1519` | h-9 select |
| `ndr/frontend/components/analysis-panel.tsx:1533` | h-9 select |
| `ndr/frontend/components/behavior-panel.tsx:539` | h-8 select |
| `ndr/frontend/components/behavior-panel.tsx:702` | h-9 select |
| `ndr/frontend/components/behavior-panel.tsx:718` | h-9 select |
| `ndr/frontend/components/behavior-panel.tsx:802` | h-9 select |
| `ndr/frontend/components/behavior-panel.tsx:825` | h-9 select |
| `ndr/frontend/components/behavior-panel.tsx:1263` | textarea h-20（普通文本域，非 mono） |
| `ndr/frontend/components/logs-panel.tsx:252` | h-9 select |
| `ndr/frontend/components/logs-panel.tsx:281` | h-9 select |
| `ndr/frontend/components/logs-panel.tsx:296` | h-9 select |
| `ndr/frontend/components/logs-panel.tsx:395` | h-8 select |
| `ndr/frontend/components/logs-panel.tsx:409` | h-8 select |
| `ndr/frontend/components/traffic-panel.tsx:421` | h-8 select |
| `ndr/frontend/components/traffic-panel.tsx:437` | h-8 select |
| `ndr/frontend/components/events-panel.tsx:738` | h-9 select |
| `ndr/frontend/components/events-panel.tsx:767` | h-9 select |
| `ndr/frontend/components/events-panel.tsx:782` | h-9 select |
| `ndr/frontend/components/events-panel.tsx:832` | h-8 select |

### D. 配置页内容收口（4 行，与 A/B/C 同批，否则配置页会剩这几处 14 显眼）

| 文件:行 | 现 | 改 | 说明 |
|---|---|---|---|
| `ndr/frontend/app/config/rules/page.tsx:1104` | `<label className="flex items-center gap-2 text-sm">` | `text-13` | checkbox 标签；旁边 `Field`+`Input` 变 13 后会倒挂 |
| `ndr/frontend/app/config/rules/page.tsx:1178` | `<label className="flex h-9 items-center gap-2 text-sm">` | `text-13` | 同上（状态复选框） |
| `ndr/frontend/components/ingest-filters-panel.tsx:505` | `<p className="text-sm">` | `text-13` | 试运行结果块正文 |
| `ndr/frontend/components/es-panel.tsx:234` | `<span className="font-mono text-sm">` | `text-13` | `Stat size="sm"` 的 mono 值 |

### E. 明确不动（防"顺手改回去"）

`CardTitle` 14 ／ `Dialog`/`Drawer` 标题 14 ／ `Button` default 14 ／ 顶栏一级菜单 14 ／ `Button size="sm"` 13 ／ 表格正文 13、**表头 12（锁死，见 2.1①，`SettingsBlock` 内也不抬）** ／ `Badge` 12 ／ `EmptyState`（default 14 / compact 12）／ `Loading` 14 ／ 规则树三档（14/13/13，`spec §4.3`）／ 规则树根行 `config/rules/page.tsx:949` 14 ／ **成功/错误消息条 14**（各面板的 `text-sm text-primary` 提示行，全站临时反馈层，故意比内容大一档、出现才可见，本批不动）。

---

## 4. 连带的尺寸问题（逐条回答 team-lead）

### 4.1 `h-9` 不跟到 `h-8`

高度是**点击目标**属性，不是排版属性：`Input` 36px 与 `Button` default 36px 同高，表单行里控件与按钮才对齐；且 21 处 select/textarea 类（2 处常量 + 19 处内联）里 `h-9`/`h-8` 混着写，只改 `Input` 会让「同一条筛选行里 select 与 input 不等高」。要压密度就**三件套一起动**（`Input` `h-9` + `SELECT_CLS` `h-9` + `Button` default `h-9` → `h-8`），那是另一次「密度」改造，不在本次。

### 4.2 `LABEL_W`（80/104/128）不动

~~标签字号保持 13（row 模式标签属于内容层），字宽没变，列宽无需收。~~ **2026-10-28 用户裁定：标签降到 12（见 §7）**，字宽变窄、列宽更宽松，`LABEL_W` 维持原值不动——标签列短了反而给控件区让出余量，无需重排。

### 4.3 `CONTROL_W` 注释要改（`field.tsx:72`）

注释写「控件内文字约 14px」，改后是 13px；宽度档位（96/144/256/416）不用动——13px 只会让同样的宽度更宽松，不会挤。

### 4.4 `SettingsBlock` 的 3px 蓝条 `h-3.5` → `h-3`（建议同批）

标题从 13 抬到 14 后，蓝条相对字号变粗：`Section` 是 14px 条 / 16px 字（0.875），块是 14px 条 / 14px 字（1.0）。改成 `h-3`(12px) 后为 0.857，与 `Section` 基本同比例。**这条只影响 `settings-board.tsx:90` 一个类，不改结构。**

另外：标题条高度**不会变**。`SettingsBlock` 标题写死 `leading-5`（20px），13→14 只改字面不改行盒；侧栏项写死 `h-8`（32px），`text-13`(20px 行高) → `text-xs`(16px 行高) 也不改行高。**本次四处字号改动零布局位移**，不需要跟着调 padding。

### 4.5 侧栏图标保持 `h-4`(16)

12px 字 / 16px 图标 = 1.33（原来是 1.23）。图标是行锚点也是点击区的一部分，缩到 14px 会让 32px 行显得空。**不动。**

### 4.6 行距/内边距全部不动

改字号不改 `h-8`/`px-3`/`py-2.5`/`gap-2`。理由：本次只修层级，密度另议；同时避免「字号改了、行高没跟」导致的二次返工。

---

## 5. 与既有规范的冲突核对

| 既有条目 | 是否冲突 | 处置 |
|---|---|---|
| `config-layout-visual-spec.md:557`「L1 与 L2 只差 1px（14 vs 13）」 | **不冲突** | 那条讲的是**检测规则树**的三级行（`§4.3`：根 14 / 组 13 / 叶 13），本次不碰树。别把它误读成「全站 L1=14」 |
| `config-layout-visual-spec.md:1497` 合法档位表 | **不冲突** | 本次只用 12/13/14/16，未新增档位，也未出现 `text-11/14/15` |
| `card.tsx:33` `CardTitle` = 14 | **同向** | 证明「L2 容器标题 = 14」是既有约定；`SettingsBlock` 的 13 是**实现偏离约定**，本次是把它改回来 |
| `section.tsx` 头注释「L1 Section 16 / L2 Card 14」 | **同向** | 同上；本次不新增层级，只让 `SettingsBlock` 归位到 L2 |
| `events-center-visual-spec.md` 的 `text-sm` 控件样本 | **文档需同步（3 处）** | `:144` 档位表「筛选控件（Input / select）＝14」→ 13；`:329` 筛选 select 样本、`:531` 分页 select 样本 → `text-13`。这三处抄的是日志页旧类。**我在你确认后一并改** |
| `ndr-fact-vs-judgment-visual.md §5.2`（KPI 28 / 字重 500） | **不冲突** | KPI 与「不许 700」都不在本批 |
| `analysis-suppression-ux-spec.md`（8 处「12px muted」） | **不冲突，0 处要改** | 那 8 处（列表第二行 meta、抽屉只读说明、footer mode 小字等）正好落在 12 档；且该文档写的是**语义档位**，不绑类名别名（见 2.2 分工） |

**所以"改规范还是改实现"的答案是：规范要加一节，实现要改一处。** 规范不用改档位（§557/§1497 都还成立），但要**新增一节「全局字号阶梯表」**（就是本文第 2 节），因为现在这些档位散落在四份文档里，谁都能定义一次；实现侧要改的是 `SettingsBlock` 那一处偏离（13 → 14）。

---

## 6. 不做的事

- 不做「整体 ×0.9」之类的缩放；不改 `tailwind.config.ts` 的字号定义。
- 不加 `font-bold` / 700；不新增 `text-[11px]`。
- 不动表格、表头、`Badge`、`KPI`、顶栏、`Section` 16、消息条 14。
- 不动 `h-9` / `LABEL_W` / `CONTROL_W` / 侧栏行高与宽度。
- 不合并两个 `SELECT_CLS`（重构另议，避免本次盘点失真）。

## 7. 验收（可直接跑）

```bash
# 1) 控件不得再有 14px（期望：0 行；消息条不在此列，它们不带 border-input）
grep -rn "border-input" ndr/frontend packages/ui --include=*.tsx | grep "text-sm"
# 2) 表头锁 12（期望：table.tsx:65 为 text-xs；第 2 条期望 0 行——当前确实无人覆写表头字号）
grep -n "text-xs" packages/ui/src/components/ui/table.tsx
grep -rn "<TableHead" -A2 ndr/frontend --include=*.tsx | grep "text-1[34]"
# 3) 侧栏不得再有 13px 的项（期望：仅 :68 分区名为 text-13）
grep -n "text-13\|text-xs" ndr/frontend/components/nav.tsx
# 4) 块标题必须是 14（期望：1 行 text-sm）
grep -n "text-sm" packages/ui/src/components/ui/settings-board.tsx
# 5) 合法档位：不得出现 text-11 / text-14 / text-15
grep -rn "text-14\|text-15\|text-11" ndr/frontend packages/ui --include=*.tsx
# 6) 类型与构建纪律
npx tsc --noEmit
```

肉眼验收（1366 与 1920 各看一次）：~~配置页一屏里**输入框文字不再比它的标签和块标题大**~~（§7 补：标签降 12 后「值 13 > 标签 12」为**用户明示接受的口径**，不再视为倒挂）；侧栏 8 条比正文更安静；`Section` 与 `SettingsBlock` 两级标题一眼分得开（16 vs 14）。

## 8. 2026-10-28 补充裁定：`Field` row 模式标签 13 → 12

- **背景**：用户反馈配置编辑区「字体太大」，要求标签与 hint（12px）同号。经 Console 实测，渲染链路正常（.text-13=13px、.text-xs=12px 精确生效），为用户主观密度偏好，非渲染缺陷。
- **裁定**：`field.tsx` row 模式标签 `text-13` → `text-xs`，与 hint 同号。层级不再靠字号区分，靠**位置**（标签右对齐于左列、hint 在控件下方）与**颜色**（均 muted-foreground，同一灰度）。
- **已知取舍**：输入框文字（13）大于标签（12）——§2 表里「标签=值同号」的深信服口径改为「值略大于标签」，用户明示接受；后续如有人按 §2 把标签「归位」回 13，先看本节，那是被用户否掉的方向。
- **零布局位移**：`leading-5`（20px 行盒）与 `LABEL_W`、`pt-1.5` 基线对齐全部不动，仅字面缩小。stacked 模式标签本就是 `text-xs`，无需改。
