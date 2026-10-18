/**
 * ECharts 装配表 —— **全项目唯一的图表模块注册点**。
 *
 * 为什么要有这个文件：原来 `chart.tsx` 里是 `import * as echarts from "echarts"`，
 * 走的是 echarts 的全量入口（`index.js` 里有一个 `use([...])` 把 20+ 种图表和
 * 30+ 个组件全部注册进去）。结果是：
 *   1. 首屏 JS 里常驻约 1MB 的 echarts，实际只用得上其中几种；
 *   2. 每次新增图表类型都"自动可用"，没人知道到底注册了什么。
 *
 * 现在改成按需装配：只注册项目里**实际用到**的模块（见下表）。缺哪个就会在
 * 控制台刷 `Series xxx is not exists`，图表区域直接空白 —— 所以这张表就是
 * 「加新图表时要改的唯一地方」。
 *
 * ┌─ 图表（charts）───────────────────────────────────────────────┐
 * │ LineChart    折线：流量趋势、队列深度、命中趋势、初筛得分        │
 * │ BarChart     柱状：协议占比、TOP 源 IP、规则 TOP、丢弃原因       │
 * │ PieChart     饼/环：严重度分布、覆盖率、索引占用                 │
 * │ GraphChart   关系图：资产拓扑、agent 拓扑                       │
 * │ GaugeChart   仪表/环：主机资源占用、队列容量、投递容量           │
 * └──────────────────────────────────────────────────────────────┘
 * ┌─ 组件（components）──────────────────────────────────────────┐
 * │ GridComponent      直角坐标系：xAxis/yAxis 全靠它定位           │
 * │ TooltipComponent   悬浮提示（内部已自带 AxisPointer，无需单引） │
 * │ LegendComponent    图例                                        │
 * │ MarkLineComponent  标线：队列上限、字节阶梯刻度                 │
 * │ TitleComponent     标题（共享组件留给后续页面的余量，体积很小） │
 * └──────────────────────────────────────────────────────────────┘
 *
 * 明确**没有**注册、用到时需要自己加的：DataZoom / VisualMap / MarkPoint /
 * MarkArea / Toolbox / Graphic / Dataset / Polar / Radar / Geo / Map / 3D 系列。
 * 这些当前全项目零使用，注册进来纯属白付体积。
 *
 * 渲染器只用 Canvas（项目里没有一处 `renderer: "svg"`）。
 */

import { use } from "echarts/core";
import { LineChart, BarChart, PieChart, GraphChart, GaugeChart } from "echarts/charts";
import {
  GridComponent,
  TooltipComponent,
  LegendComponent,
  MarkLineComponent,
  TitleComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";

/**
 * `use()` 是幂等的：同一份模块重复注册不会报错也不会重复安装，
 * 所以两个前端各自打包时各调一次没有问题（NDR 与 agent 是独立 bundle）。
 */
use([
  LineChart,
  BarChart,
  PieChart,
  GraphChart,
  GaugeChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  MarkLineComponent,
  TitleComponent,
  CanvasRenderer,
]);

// 业务侧只该从这里拿运行时 API，不要再 import "echarts"（那是全量入口）。
export { init, registerTheme, getInstanceByDom, dispose } from "echarts/core";
export type { EChartsType, EChartsCoreOption } from "echarts/core";
