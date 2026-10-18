import type { EChartsOption } from "echarts";
import { chartTokens, formatClock, formatDateTime, formatHourSlot } from "@shentong/ui";
// 类型定义在 lib/api.ts，lib/hits.ts 再导出（视觉规范 4.0）；这里取定义处
import type { HitTrendPoint } from "@/lib/api";
import { AXIS, GRID, valueAxis } from "@/components/status-charts";

/**
 * 事件中心（`/events`）的图表选项：**一个**工厂（视觉规范 4.0）。
 *
 * 与 `status-charts.ts` 的关系：栅格 / 数值轴常量从那边加 `export` 后 import——
 * 「栅格/图例/字号只有一套」是总览页图表文件立的规矩，新文件遵守而不是绕过。
 * 面板与图表文件 1:1 配对（`status-panel` ↔ `status-charts`，`events-panel` ↔ `event-charts`）。
 *
 * 空数据由调用方判断（`trend` 为空数组时面板走空态），这里的函数只负责有数据时的形状。
 */

/**
 * 命中趋势（视觉规范 4.1）：折线 + 浅面积，颜色与运营中心「24h 命中与摘要趋势」同色同形。
 *
 * 三个必须写对的点：
 * 1. **补零**：后端 `trend[]` 只含有事件的桶（断桶），直接画类目轴会让安静的一小时
 *    「消失」、左右两根柱子贴到一起，折线形状是假的。按 `bucket_seconds` 从首桶补到尾桶。
 * 2. **X 轴标签由 `bucket_seconds` 决定**（≥3600 → `formatHourSlot` 整点档，否则
 *    `formatClock`）：不能由用户选的时间范围反推——「最近 6 小时」恰好是小时桶的边界
 *    （后端 `>= 360` 判小时桶，见视觉规范 0.3）。
 * 3. **不用 `smooth`**：平滑曲线会在峰谷之间鼓起来，10 分钟桶下尤其明显。
 *    「突然掉到 0」和「缓慢下降」是两件事，视觉上必须可分辨。
 */
export function hitTrendOption(points: HitTrendPoint[], bucketSeconds: number): EChartsOption {
  const t = chartTokens();
  const step = Math.max(60, bucketSeconds) * 1000;
  const first = Date.parse(points[0].ts);
  const last = Date.parse(points[points.length - 1].ts);
  const byBucket = new Map(points.map((p) => [Date.parse(p.ts), p.count]));
  const filled: Array<{ ts: number; count: number }> = [];
  for (let ms = first; ms <= last; ms += step) filled.push({ ts: ms, count: byBucket.get(ms) ?? 0 });
  const hourBucket = bucketSeconds >= 3600;
  const xs = filled.map((p) => (hourBucket ? formatHourSlot(p.ts) : formatClock(p.ts)));
  return {
    grid: GRID,
    tooltip: {
      trigger: "axis",
      formatter: (params: unknown) => {
        const idx = (params as Array<{ dataIndex: number }>)?.[0]?.dataIndex ?? 0;
        const p = filled[idx];
        if (!p) return "";
        return [
          formatDateTime(new Date(p.ts)),
          `${p.count} 条`,
          hourBucket ? "桶长 1 小时" : `桶长 ${Math.round(bucketSeconds / 60)} 分钟`,
        ].join("<br/>");
      },
    },
    xAxis: {
      ...AXIS,
      boundaryGap: false,
      data: xs,
      // 7 天 = 168 个小时桶，让 ECharts 自己抽稀（视觉规范 4.1：不手写 interval: 12）
      axisLabel: { interval: "auto" },
    },
    yAxis: valueAxis({ name: "条", nameTextStyle: { color: t.axis } }),
    series: [
      {
        type: "line",
        data: filled.map((p) => p.count),
        // 点少才画点（沿用 status-charts 的同一阈值）；点多时点会连成一条实心带
        showSymbol: filled.length < 40,
        symbolSize: 4,
        lineStyle: { width: 1.8, color: t.series[0] },
        itemStyle: { color: t.series[0] },
        areaStyle: { opacity: 0.12, color: t.series[0] },
      },
    ],
  };
}
