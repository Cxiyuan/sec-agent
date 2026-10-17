import type { EChartsOption } from "echarts";
import { formatClock, formatHourSlot, formatShort } from "@shentong/ui";
import type {
  AgentPushPayload,
  BaselinePayload,
  DetectorCoverage,
  DetectorHistoryPoint,
  DetectorRate,
  DetectorStats,
  EsIndexInfo,
  LogstashStatus,
  ProtocolShare,
  StatsOverview,
  SystemMetrics,
} from "@/lib/api";
import type { TrafficMinutes } from "@/lib/api";

/**
 * 总览页的图表选项：**纯函数**（数据进、EChartsOption 出），不碰 React、不发请求。
 *
 * 为什么单独一个文件：`status-panel.tsx` 只管取数与排版；把 option 构造留在这儿，
 * 面板文件不会膨胀成几百行，加图/改图也不必读组件逻辑。
 *
 * 约定：
 * - 单位统一。速率类一律「条/分钟」，字节类一律「字节/秒」，不要让两个量纲的柱子并排比。
 * - 空数据由调用方判断（面板里显示「暂无采样」文案），这里的函数只负责有数据时的形状。
 */

const AXIS = { type: "category" as const, axisLabel: { fontSize: 10 } };
const VAL = { type: "value" as const, axisLabel: { fontSize: 10 }, splitLine: { lineStyle: { opacity: 0.15 } } };

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#64748b",
};

// 容量尺（仪表盘左边 Y 轴）：用户口径 200KB → 1M → 5M → 50M → 100M → 200M → 500M → 1G
// 左边只放字节刻度；右边那根轴只放掉包。
// 轴用**对数刻度**（1KB ~ 1G）：线性刻度时几百 KB/s 会贴着 X 轴，看着像没数据。
// 容量尺最下面那一档（200KB）放在轴高多少比例处：
// 用户口径「200KB 刻度太高了，减少一半的高度」→ 原来（下限固定 1KB 时）在 38.5%，砍一半 = 19% 左右。
// 所以下限**不是常数**，而是由「200KB 落在轴高 19%」反推（对数轴上解一元一次）。
// 好处：峰值撑开轴时，200KB 仍稳定停在低位，不再往上跑。
const LADDER_BOTTOM_FRACTION = 0.19;
const RATE_TICKS_BYTES: number[] = [200, 1024, 5120, 25600, 51200, 102400, 256000, 1048576].map(
  (k) => k * 1024,
);
const RATE_TICK_LABELS: string[] = ["200KB", "1M", "5M", "50M", "100M", "200M", "500M", "1G"];
// 峰值超过 1G 时按真实值撑开轴（不裁数据）
function flowAxisMax(maxValue: number): number {
  const top = RATE_TICKS_BYTES[RATE_TICKS_BYTES.length - 1];
  return Math.max(top, Math.ceil(maxValue * 1.2));
}

// 对数轴下限：让最低那档（200KB）刚好落在 LADDER_BOTTOM_FRACTION 处
//   (log10(200KB) - a) / (log10(max) - a) = f   →   a = (log10(200KB) - f*log10(max)) / (1 - f)
function flowAxisMin(axisMax: number): number {
  const lowest = RATE_TICKS_BYTES[0];
  const f = LADDER_BOTTOM_FRACTION;
  const a = (Math.log10(lowest) - f * Math.log10(axisMax)) / (1 - f);
  return Math.pow(10, a);
}

const PALETTE = [
  "#0ea5e9",
  "#22c55e",
  "#eab308",
  "#f97316",
  "#ef4444",
  "#a855f7",
  "#14b8a6",
  "#e879f9",
  "#84cc16",
  "#f43f5e",
];

export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let n = Math.abs(value);
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  const sign = value < 0 ? "-" : "";
  return `${sign}${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${units[i]}`;
}

/** 时间戳（毫秒）→ `HH:mm`（北京时间）；采样点的 ts 是秒或毫秒都要能用。 */
function clockOf(ts: number | undefined): string {
  if (!ts) return "";
  const ms = ts > 1e12 ? ts : ts * 1000;
  return formatClock(ms);
}

/** ISO 时间戳 → `MM-DD HH:MM`（北京时间，画像风险的判定时间）。空值/脏值一律给 `-`，不显示 NaN。 */
function stampOf(iso: string | null | undefined): string {
  if (!iso) return "-";
  return formatShort(iso);
}

function hourOf(iso: string): string {
  if (!iso) return "";
  return formatHourSlot(iso);
}

/** 采样点 → 每分钟值（**用该点自己的 interval_seconds**：检测器重启后首段可能只有几十秒）。 */
function perMinute(point: DetectorHistoryPoint, key: keyof DetectorHistoryPoint): number {
  const raw = Number(point[key] ?? 0);
  const interval = Number(point.interval_seconds || 0);
  if (!Number.isFinite(raw) || interval <= 0) return 0;
  return Math.round((raw / interval) * 60 * 100) / 100;
}

// ---------- 服务器圆环 ----------

/** CPU / 内存 / 磁盘的圆环：≥85% 红、≥70% 橙（阈值与运维口径一致）。 */
export function ringOption(value: number | null, name: string): EChartsOption {
  const v = value === null || value === undefined ? 0 : Math.max(0, Math.min(100, value));
  const color = v >= 85 ? "#ef4444" : v >= 70 ? "#f59e0b" : "#0ea5e9";
  return {
    series: [
      {
        type: "gauge",
        startAngle: 90,
        endAngle: -270,
        radius: "92%",
        pointer: { show: false },
        progress: { show: true, width: 12, roundCap: true, itemStyle: { color } },
        axisLine: { lineStyle: { width: 12, color: [[1, "rgba(148,163,184,0.18)"]] } },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        title: { show: true, offsetCenter: [0, "34%"], fontSize: 12, color: "#475569" },
        detail: {
          offsetCenter: [0, 0],
          fontSize: 22,
          fontWeight: "bold",
          formatter: value === null || value === undefined ? "—" : "{value}%",
          color,
        },
        data: [{ value: v, name }],
      },
    ],
  };
}

/**
 * 服务器资源：**一个仪表盘画三个指标**（CPU / 内存 / 磁盘）。
 *
 * 为什么合并（2026-10 用户要求）：三个独立圆环占三张卡片、留白多、小屏要滚动；
 * 合成一张后一屏能看全，比例也更好对齐。
 */
export function resourceGaugesOption(
  cpu: number | null | undefined,
  mem: number | null | undefined,
  disk: number | null | undefined,
): EChartsOption {
  const items: Array<[string, number | null | undefined, string]> = [
    ["CPU", cpu, "22%"],
    ["内存", mem, "50%"],
    ["磁盘", disk, "78%"],
  ];
  return {
    series: items.map(([name, raw, x]) => {
      const value = raw === null || raw === undefined ? 0 : Math.max(0, Math.min(100, raw));
      const color = value >= 85 ? "#ef4444" : value >= 70 ? "#f59e0b" : "#1d4ed8";
      return {
        type: "gauge" as const,
        center: [x, "52%"],
        radius: "34%",
        startAngle: 90,
        endAngle: -270,
        pointer: { show: false },
        progress: { show: true, width: 10, roundCap: true, itemStyle: { color } },
        axisLine: { lineStyle: { width: 10, color: [[1, "rgba(148,163,184,0.18)"]] } },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        title: { show: true, offsetCenter: [0, "52%"], fontSize: 12, color: "#475569" },
        detail: {
          offsetCenter: [0, 0],
          fontSize: 20,
          fontWeight: "bold",
          formatter: raw === null || raw === undefined ? "—" : "{value}%",
          color,
        },
        data: [{ value, name }],
      };
    }),
  };
}

/**
 * 资源状态：**温度计式横条**（2026-10 用户口径）。
 *
 * 一行一个指标：左边是类型（CPU/内存/磁盘），中间是仪表条，右边是百分比。
 * 用横向 bar + `showBackground`（底槽）实现，圆环不用 —— 一行行读起来比三个圆环快，
 * 而且纵向排列正好塞进 1/3 宽的卡片里。
 */
export function resourceBarsOption(
  cpu: number | null | undefined,
  mem: number | null | undefined,
  disk: number | null | undefined,
): EChartsOption {
  const rows: Array<[string, number | null | undefined]> = [
    ["磁盘", disk],
    ["内存", mem],
    ["CPU", cpu],
  ];
  // yAxis 的类目顺序是自下而上，所以上面用倒序（磁盘在下、CPU 在上）
  return {
    grid: { left: 46, right: 46, top: 8, bottom: 8 },
    xAxis: { type: "value", max: 100, show: false },
    yAxis: {
      type: "category",
      data: rows.map(([name]) => name),
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: "#334155", fontSize: 12 },
    },
    series: [
      {
        type: "bar",
        barWidth: 14,
        showBackground: true,
        backgroundStyle: { color: "rgba(148,163,184,0.18)", borderRadius: 7 },
        itemStyle: { borderRadius: 7 },
        label: {
          show: true,
          position: "right",
          fontSize: 12,
          fontWeight: "bold",
          formatter: (item: unknown) => {
            const value = Number((item as { value?: number })?.value ?? 0);
            return `${value}%`;
          },
          color: "#0f172a",
        },
        data: rows.map(([, raw]) => {
          const value = raw === null || raw === undefined ? 0 : Math.max(0, Math.min(100, raw));
          const color = value >= 85 ? "#ef4444" : value >= 70 ? "#f59e0b" : "#1d4ed8";
          return raw === null || raw === undefined
            ? { value: 0, itemStyle: { color: "#cbd5e1" }, label: { formatter: "—" } }
            : { value, itemStyle: { color } };
        }),
      },
    ],
  };
}

// ---------- 威胁事件 ----------

/** 命中 / 摘要的 24h 趋势（多条折线，单位统一为条/分钟）。 */
export function rateTrendOption(items: DetectorHistoryPoint[]): EChartsOption {
  const xs = items.map((p) => clockOf(p.ts));
  const series = (
    [
      ["扫描", "d_scanned", "#0ea5e9"],
      ["命中", "d_hit", "#f97316"],
      ["摘要", "d_digest", "#a855f7"],
      ["投递", "d_delivered", "#22c55e"],
    ] as const
  ).map(([name, key, color]) => ({
    name,
    type: "line" as const,
    smooth: true,
    showSymbol: xs.length < 40,
    symbolSize: 4,
    lineStyle: { width: 1.6, color },
    itemStyle: { color },
    data: items.map((p) => perMinute(p, key)),
  }));
  return {
    tooltip: { trigger: "axis", valueFormatter: (v: unknown) => `${v} 条/分钟` },
    legend: { top: 0, textStyle: { fontSize: 10 } },
    grid: { left: 40, right: 12, top: 26, bottom: 22 },
    xAxis: { ...AXIS, boundaryGap: false, data: xs, axisLabel: { fontSize: 10, interval: "auto" } },
    yAxis: { ...VAL, name: "条/分钟", nameTextStyle: { fontSize: 10 } },
    series,
  };
}

/** 24h 摘要的严重度分布（环图）。 */
export function severityOption(items: DetectorHistoryPoint[]): EChartsOption {
  const keys = ["critical", "high", "medium", "low", "info"] as const;
  const labels: Record<string, string> = {
    critical: "紧急",
    high: "高危",
    medium: "中危",
    low: "低危",
    info: "提示",
  };
  const data = keys.map((k) => ({
    name: labels[k],
    value: Math.round(items.reduce((sum, p) => sum + Number(p[`d_digest_sev_${k}` as keyof DetectorHistoryPoint] ?? 0), 0)),
    itemStyle: { color: SEVERITY_COLORS[k] },
  }));
  return {
    tooltip: { trigger: "item", formatter: "{b}: {c} 条 ({d}%)" },
    legend: { bottom: 0, textStyle: { fontSize: 10 } },
    series: [
      {
        type: "pie",
        // 实心饼图（用户口径：严重度分布要实心圆，不要圆环）
        // 半径收小是给外面的指引线+文字留位置（原先无标签时是 68%）
        radius: "52%",
        center: ["50%", "46%"],
        avoidLabelOverlap: true,
        // 指针（指引线）+ 旁边文字：直接标出每块是什么、占多少
        label: {
          show: true,
          fontSize: 10,
          formatter: "{b} {c} 条 ({d}%)",
        },
        labelLine: { show: true, length: 8, length2: 10, smooth: true },
        labelLayout: { hideOverlap: true },
        data: data.filter((d) => d.value > 0),
      },
    ],
  };
}

/** 命中最多的规则 TOP N（横向条）。 */
export function ruleTopOption(items: DetectorHistoryPoint[], top = 15): EChartsOption {
  const totals: Record<string, number> = {};
  for (const point of items) {
    for (const [rule, count] of Object.entries(point.by_rule || {})) {
      totals[rule] = (totals[rule] || 0) + Number(count || 0);
    }
  }
  const sorted = Object.entries(totals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, top)
    .reverse();
  return {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
    xAxis: { ...VAL },
    yAxis: { ...AXIS, data: sorted.map(([name]) => name.replace(/^内置-/, "")), axisLabel: { fontSize: 10, width: 130, overflow: "truncate" } },
    series: [{ type: "bar", data: sorted.map(([, n]) => n), itemStyle: { color: "#0ea5e9" }, barMaxWidth: 14 }],
  };
}

// ---------- 流量与协议 ----------

/** 24h 流量曲线：**字节/秒**（tooltip 里给该小时总字节与条数）。 */
export function trafficOption(overview: StatsOverview): EChartsOption {
  const points = overview.traffic?.points || [];
  return {
    tooltip: {
      trigger: "axis",
      formatter: (params: unknown) => {
        const arr = Array.isArray(params) ? params : [params];
        const first = arr[0] as { dataIndex?: number } | undefined;
        const idx = first?.dataIndex ?? 0;
        const p = points[idx];
        if (!p) return "";
        return `${hourOf(p.ts)}<br/>${p.bytes_per_sec} 字节/秒<br/>合计 ${formatBytes(
          p.bytes_total
        )}<br/>连接 ${p.docs} 条`;
      },
    },
    grid: { left: 52, right: 12, top: 16, bottom: 22 },
    xAxis: { ...AXIS, boundaryGap: false, data: points.map((p) => hourOf(p.ts)), axisLabel: { fontSize: 10, interval: "auto" } },
    yAxis: {
      ...VAL,
      name: "字节/秒",
      nameTextStyle: { fontSize: 10 },
      axisLabel: { fontSize: 10, formatter: (v: number) => formatBytes(v) },
    },
    series: [
      {
        type: "line",
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.18 },
        lineStyle: { width: 1.8, color: "#0ea5e9" },
        itemStyle: { color: "#0ea5e9" },
        data: points.map((p) => p.bytes_per_sec),
      },
    ],
  };
}

/** 24h 协议占比（圆图）：top 12 + 其他。 */
export function protocolPieOption(share: ProtocolShare | undefined): EChartsOption {
  const items = (share?.items || []).slice(0, 12);
  const data = items.map((it, i) => ({
    name: it.log_type || "(空)",
    value: it.docs,
    itemStyle: { color: PALETTE[i % PALETTE.length] },
  }));
  if (share && share.other_docs > 0) {
    data.push({ name: "其他", value: share.other_docs, itemStyle: { color: "#64748b" } });
  }
  return {
    tooltip: { trigger: "item", formatter: "{b}: {c} 条 ({d}%)" },
    legend: { type: "scroll", bottom: 0, textStyle: { fontSize: 10 } },
    series: [
      {
        type: "pie",
        // 实心饼图（用户口径：协议占比要实心圆，不要圆环）
        // 半径收小是给外面的指引线+文字留位置（原先无标签时是 66%）
        radius: "50%",
        center: ["50%", "46%"],
        avoidLabelOverlap: true,
        // 指针（指引线）+ 旁边文字。协议是长尾：**太小的塊不标**（否则 quic 0.02%
        // 这类标签会把图糊满），它们仍留在图上，看 tooltip/图例即可
        minShowLabelAngle: 6,
        label: {
          show: true,
          fontSize: 10,
          formatter: "{b} {d}%",
        },
        labelLine: { show: true, length: 8, length2: 10, smooth: true },
        labelLayout: { hideOverlap: true },
        data,
      },
    ],
  };
}

// ---------- 链路细节 ----------

/** 容量圆环（队列占用比 / 投递额度占用）。 */
export function capacityRingOption(percent: number | null, name: string): EChartsOption {
  return ringOption(percent, name);
}

/** 五段速率漏斗（横向条，单位统一条/分钟）：最小的一段就是瓶颈。 */
export function rateFunnelOption(rate: DetectorRate | null): EChartsOption {
  const stages = [
    ["入队", (rate?.ingest_per_sec_est ?? 0) * 60, "#0ea5e9"],
    ["扫描", (rate?.scanned_per_sec ?? 0) * 60, "#22d3ee"],
    ["命中", rate?.hits_per_min ?? 0, "#f97316"],
    ["摘要", rate?.digests_per_min ?? 0, "#a855f7"],
    ["投递", rate?.delivered_per_min ?? 0, "#22c55e"],
  ] as const;
  return {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" }, valueFormatter: (v: unknown) => `${Math.round(Number(v))} 条/分钟` },
    grid: { left: 8, right: 40, top: 8, bottom: 8, containLabel: true },
    xAxis: { ...VAL },
    yAxis: { ...AXIS, data: stages.map(([name]) => name).reverse() },
    series: [
      {
        type: "bar",
        barMaxWidth: 16,
        data: stages
          .map(([name, value, color]) => ({ value: Math.round(value), itemStyle: { color }, name }))
          .reverse(),
      },
    ],
  };
}

/** 队列深度趋势（折线 + 上限线）。 */
export function queueTrendOption(items: DetectorHistoryPoint[], queueMax: number): EChartsOption {
  const xs = items.map((p) => clockOf(p.ts));
  return {
    tooltip: { trigger: "axis" },
    legend: { top: 0, textStyle: { fontSize: 10 } },
    grid: { left: 46, right: 12, top: 26, bottom: 22 },
    xAxis: { ...AXIS, boundaryGap: false, data: xs },
    yAxis: { ...VAL, name: "条", nameTextStyle: { fontSize: 10 } },
    series: [
      {
        name: "归一化队列",
        type: "line",
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1.6, color: "#0ea5e9" },
        itemStyle: { color: "#0ea5e9" },
        data: items.map((p) => Number(p.queue_raw ?? 0)),
        markLine: queueMax
          ? {
              silent: true,
              symbol: "none",
              label: { formatter: `上限 ${queueMax}`, fontSize: 10 },
              lineStyle: { color: "#ef4444", type: "dashed" },
              data: [{ yAxis: queueMax }],
            }
          : undefined,
      },
      {
        name: "处理中",
        type: "line",
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1.6, color: "#eab308" },
        itemStyle: { color: "#eab308" },
        data: items.map((p) => Number(p.queue_processing ?? 0)),
      },
    ],
  };
}

/** 丢弃原因分布（横向条，按值降序，0 不显示）。 */
export function droppedOption(stats: DetectorStats | null): EChartsOption {
  const entries = Object.entries(stats?.dropped || {})
    .map(([k, v]) => [k, Number(v) || 0] as [string, number])
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .reverse();
  const labels: Record<string, string> = {
    undelivered: "未投递（没配推送）",
    rule_capped: "单规则限速",
    expired: "超龄",
    trimmed: "队列裁剪",
    raw_trimmed: "raw 裁剪",
    handle_failed: "处理失败",
    agg_full: "聚合满",
  };
  return {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: 8, right: 30, top: 8, bottom: 8, containLabel: true },
    xAxis: { ...VAL },
    yAxis: { ...AXIS, data: entries.map(([k]) => labels[k] || k) },
    series: [{ type: "bar", barMaxWidth: 14, itemStyle: { color: "#ef4444" }, data: entries.map(([, v]) => v) }],
  };
}

/** 投递 / 重发计数（累计口径，图上注明）。 */
export function pushCountersOption(push: AgentPushPayload | null): EChartsOption {
  const st = push?.status;
  const items: [string, number][] = [
    ["已送达", st?.sent ?? 0],
    ["重发成功", st?.retried ?? 0],
    ["重发失败", st?.retry_failed ?? 0],
    ["判死", st?.retry_lost ?? 0],
    ["超限丢弃", st?.retry_dropped ?? 0],
    ["未投递", st?.undelivered ?? 0],
  ];
  return {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
    xAxis: { ...VAL },
    yAxis: { ...AXIS, data: items.map(([name]) => name).reverse() },
    series: [
      {
        type: "bar",
        barMaxWidth: 14,
        data: items
          .map(([name, value], i) => ({
            name,
            value,
            itemStyle: { color: i === items.length - 1 && value > 0 ? "#ef4444" : "#0ea5e9" },
          }))
          .reverse(),
      },
    ],
  };
}

/** ES 各索引（按天）文档数与占用（柱 + 双轴折线）。 */
export function esIndicesOption(indices: EsIndexInfo[] | undefined): EChartsOption {
  const rows = (indices || []).slice(-14);
  return {
    tooltip: { trigger: "axis" },
    legend: { top: 0, textStyle: { fontSize: 10 } },
    grid: { left: 52, right: 56, top: 26, bottom: 22 },
    xAxis: { ...AXIS, data: rows.map((r) => r.index.replace("shentong-events-", "")) },
    yAxis: [
      { ...VAL, name: "文档数", nameTextStyle: { fontSize: 10 } },
      { ...VAL, name: "占用", nameTextStyle: { fontSize: 10 }, axisLabel: { fontSize: 10, formatter: (v: number) => formatBytes(v) } },
    ],
    series: [
      {
        name: "文档数",
        type: "bar",
        barMaxWidth: 18,
        itemStyle: { color: "#0ea5e9" },
        data: rows.map((r) => Number(r.docs || 0)),
      },
      {
        name: "占用",
        type: "line",
        yAxisIndex: 1,
        smooth: true,
        symbolSize: 4,
        lineStyle: { width: 1.6, color: "#22c55e" },
        itemStyle: { color: "#22c55e" },
        data: rows.map((r) => Number(r.store || 0)),
      },
    ],
  };
}

/** Logstash 吞吐（in / filtered / out）与采集队列积压。 */
export function logstashOption(logstash: LogstashStatus | null): EChartsOption {
  const ls = logstash?.logstash;
  const items: [string, number, string][] = [
    ["入", ls?.events_in ?? 0, "#0ea5e9"],
    ["过滤", ls?.events_filtered ?? 0, "#a855f7"],
    ["出", ls?.events_out ?? 0, "#22c55e"],
    ["采集队列积压", logstash?.queue_depth ?? 0, "#f97316"],
  ];
  return {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
    xAxis: { ...VAL },
    yAxis: { ...AXIS, data: items.map(([name]) => name).reverse() },
    series: [
      {
        type: "bar",
        barMaxWidth: 14,
        data: items.map(([, value, color]) => ({ value, itemStyle: { color } })).reverse(),
      },
    ],
  };
}

/** 基线维度结构（已过观测期 vs 观测中）。 */
export function baselineOption(baseline: BaselinePayload | null): EChartsOption {
  const warmed = baseline?.stats.warmed_keys ?? 0;
  const learning = baseline?.stats.learning_keys ?? 0;
  return {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    legend: { top: 0, textStyle: { fontSize: 10 } },
    grid: { left: 8, right: 24, top: 26, bottom: 8, containLabel: true },
    xAxis: { ...VAL },
    yAxis: { ...AXIS, data: ["维度"] },
    series: [
      { name: "已过观测期", type: "bar", stack: "d", barMaxWidth: 20, itemStyle: { color: "#22c55e" }, data: [warmed] },
      { name: "观测中", type: "bar", stack: "d", barMaxWidth: 20, itemStyle: { color: "#eab308" }, data: [learning] },
    ],
  };
}

/** 画像风险 TOP N（横向条 + 阈值线）。
 *
 * tooltip 里带**判定时间**：风险分是「当前窗口」的值（本轮无异常就归零），没有这个时间
 * 就无法区分「现在异常」和「几小时前的陈旧结果」。
 */
export function anomalyOption(baseline: BaselinePayload | null, top = 8): EChartsOption {
  const rows = (baseline?.anomalies.items || [])
    .slice(0, top)
    .map((p) => {
      const servers = Object.keys(p.dst_ips || {}).slice(0, 5);
      const name = String(p.entity_display || p.entity_key || "?");
      return {
        // 标签直接带服务端 IP：运维看的不是哈希，而是「哪个账号在哪台上活动」
        name: servers.length ? `${name} · ${servers.slice(0, 2).join("/")}` : name,
        kind: p.kind === "account" ? "账号" : "会话",
        risk: Number(p.risk_score || 0),
        at: stampOf(p.risk_at),
        reasons: p.anomalies || [],
        servers,
        clients: Object.keys(p.src_ips || {}).slice(0, 5),
      };
    })
    .reverse();
  const threshold = baseline?.risk_threshold ?? 0.6;
  return {
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params: unknown) => {
        const list: unknown[] = Array.isArray(params) ? params : [params];
        const first = list[0] as { dataIndex?: number } | undefined;
        const row = rows[first?.dataIndex ?? 0];
        if (!row) return "";
        const why = row.reasons.length ? `<br/>${row.reasons.slice(0, 3).join("；")}` : "";
        const where = [
          row.servers.length ? `服务端 ${row.servers.join(", ")}` : "",
          row.clients.length ? `来源 ${row.clients.join(", ")}` : "",
        ]
          .filter(Boolean)
          .join(" · ");
        return (
          `${row.kind} ${row.name}<br/>风险 ${row.risk.toFixed(2)}（判定 ${row.at}）` +
          (where ? `<br/>${where}` : "") +
          why
        );
      },
    },
    grid: { left: 8, right: 30, top: 8, bottom: 8, containLabel: true },
    xAxis: { ...VAL, max: 1 },
    yAxis: { ...AXIS, data: rows.map((r) => r.name) },
    series: [
      {
        type: "bar",
        barMaxWidth: 14,
        itemStyle: { color: "#f97316" },
        data: rows.map((r) => r.risk),
        markLine: {
          silent: true,
          symbol: "none",
          label: { formatter: "阈值", fontSize: 10 },
          lineStyle: { color: "#ef4444", type: "dashed" },
          data: [{ xAxis: threshold }],
        },
      },
    ],
  };
}

/** 覆盖率（窗口内投递量 / 窗口内事件量）：只画一根条 + 告警线，看的是趋势突变。 */
export function coverageOption(coverage: DetectorCoverage | null): EChartsOption {
  const ratio = coverage?.coverage_ratio;
  return {
    tooltip: { trigger: "item" },
    series: [
      {
        type: "gauge",
        startAngle: 200,
        endAngle: -20,
        radius: "92%",
        pointer: { show: false },
        progress: { show: true, width: 12, roundCap: true, itemStyle: { color: coverage?.warn ? "#ef4444" : "#0ea5e9" } },
        axisLine: { lineStyle: { width: 12, color: [[1, "rgba(148,163,184,0.18)"]] } },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        title: { show: true, offsetCenter: [0, "36%"], fontSize: 12, color: "#475569" },
        detail: {
          offsetCenter: [0, 0],
          fontSize: 20,
          fontWeight: "bold",
          formatter: ratio === null || ratio === undefined ? "—" : `${Math.round(Number(ratio) * 100)}%`,
        },
        data: [{ value: ratio === null || ratio === undefined ? 0 : Math.round(Number(ratio) * 100), name: "投递覆盖率" }],
      },
    ],
  };
}

/** 内存 / 磁盘原始字节的展示文本（圆环下方那一行）。 */
export function bytesLine(metrics: SystemMetrics | null): string {
  if (!metrics) return "";
  const parts: string[] = [];
  if (metrics.load_1m !== null && metrics.load_1m !== undefined) {
    parts.push(`负载 ${metrics.load_1m}${metrics.cpu_count ? ` / ${metrics.cpu_count} 核` : ""}`);
  }
  if (metrics.mem_used_bytes !== null && metrics.mem_total_bytes !== null) {
    parts.push(`内存 ${formatBytes(metrics.mem_used_bytes)}/${formatBytes(metrics.mem_total_bytes)}`);
  }
  if (metrics.disk_used_bytes !== null && metrics.disk_total_bytes !== null) {
    parts.push(
      `磁盘 ${formatBytes(metrics.disk_used_bytes)}/${formatBytes(metrics.disk_total_bytes)}${
        metrics.disk_path ? `（${metrics.disk_path}）` : ""
      }`
    );
  }
  return parts.join(" · ");
}

/** 每秒字节数 → Mbps（网络口径用 bit） */
export function mbpsOf(bytes: number): number {
  return (Number(bytes) * 8) / 1e6;
}

/** 速率显示：0 显示 0bps、小的显示 Kbps、大的显示 Gbps（与参考图一致） */
export function formatMbps(bytes: number): string {
  const bps = Number(bytes) * 8;
  if (!Number.isFinite(bps) || bps <= 0) return "0bps";
  if (bps < 1e3) return `${bps.toFixed(0)}bps`;
  if (bps < 1e6) return `${(bps / 1e3).toFixed(1)}Kbps`;
  if (bps < 1e9) return `${(bps / 1e6).toFixed(2)}Mbps`;
  return `${(bps / 1e9).toFixed(2)}Gbps`;
}


/**
 * 近期流量图（口径与观感都是 2026-10 用户逐条定过的，别再凭印象改回去）：
 * - 数据：**每秒**口径（`bytes_per_sec` = 20 秒桶内总量 ÷ 桶秒数）。曾经直接画桶内总量、
 *   却按"/秒"标注 → 虚高 20 倍（用户看到的"瞬间几个 G"就是这个）；
 * - 掉包：Zeek `stats.log` 每 5 分钟上报一条的**增量**（偶发爆量），走**右轴**（黄色），
 *   否则会被流量压成一条平线；
 * - 线条：**波浪线**（`smooth: true`），**不填充区域**；流量绿、掉包黄；
 * - 左轴：容量尺 = **对数刻度**（下限由「200KB 落在轴高 19%」反推，见
 *   `LADDER_BOTTOM_FRACTION`），8 档阶梯用 markLine 画在**左侧**真实字节位置
 *   （档位不等距，不能用轴的 interval）；
 * - X 轴：**每 5 分钟一个时间标签**，不画刻度线（`axisTick.show = false`）。
 */
export function minuteTrafficOption(data: TrafficMinutes | null): EChartsOption {
  // 末尾那个"进行中的 20 秒"桶**不画**：它刚出现时，这个窗口里已落库的会话只有零星几条
  // （Zeek 的 conn 记录是连接**关闭**后才写的），速率必然偏低 —— 视觉上就是
  // 「新点一冒出来先掉到 0、过一会儿再涨回去」。丢掉它，曲线永远只画已过完的完整桶。
  const raw = data?.points || [];
  const points = raw.length && raw[raw.length - 1].partial ? raw.slice(0, -1) : raw;
  const labels = points.map((p) => clockOf(Date.parse(p.ts)));
  // 两条线都是"每秒/每次上报"的真实口径（不是桶内总量）
  const flow = points.map((p) => Math.round(p.bytes_per_sec ?? 0));
  const drops = points.map((p) => Math.round(p.pkts_dropped ?? 0));
  const interval = Math.max(1, Number(data?.interval_seconds ?? 20));
  const segment = Math.max(1, Number(data?.segment_minutes ?? 5));
  const everyPoints = Math.max(1, Math.round((segment * 60) / interval));
  const flowMax = flowAxisMax(Math.max(0, ...flow));
  const flowMin = flowAxisMin(flowMax);
  // 低于下限的值贴底（对数轴不能画 0；贴底就不会把线打断）
  const flowData = flow.map((v) => Math.max(flowMin, v));
  return {
    animation: true,
    animationDuration: 0,
    animationDurationUpdate: 350,
    animationEasingUpdate: "linear",
    legend: {
      top: 0,
      right: 0,
      itemWidth: 12,
      itemHeight: 8,
      textStyle: { fontSize: 10, color: "#475569" },
      data: ["流量", "丢包"],
    },
    tooltip: {
      trigger: "axis",
      formatter: (params: unknown) => {
        const idx = (params as Array<{ dataIndex: number }>)?.[0]?.dataIndex ?? 0;
        const p = points[idx];
        if (!p) return "";
        const per = (p.pkts_dropped ?? 0) + (p.pkts_proc ?? 0);
        const rate = per ? (((p.pkts_dropped ?? 0) / per) * 100).toFixed(3) : "0.000";
        return [
          `<b>${clockOf(Date.parse(p.ts))}</b>`,
          `合计 ${formatBytes(p.bytes_per_sec ?? 0)}/秒`,
          `发送 ${formatBytes(p.bytes_out_per_sec ?? 0)}/秒 · 接收 ${formatBytes(p.bytes_in_per_sec ?? 0)}/秒`,
          `连接 ${p.docs} 条`,
          `丢包 ${p.pkts_dropped ?? 0} 包（Zeek 每 5 分钟上报，掉包率 ${rate}%）`,
        ].join("<br/>");
      },
    },
    // 右边留出空间放掉包刻度，左边放容量尺
    grid: { left: 64, right: 62, top: 22, bottom: 20 },
    xAxis: {
      ...AXIS,
      boundaryGap: false,
      data: labels,
      axisTick: { show: false },
      axisLabel: {
        fontSize: 10,
        interval: everyPoints - 1,
        color: "#475569",
        formatter: (value: string) => value.slice(0, 5),
      },
    },
    yAxis: [
      // 左：容量尺（字节/秒）。对数刻度 + 自定义阶梯标注（阶梯不等距，不能用轴的 interval）
      {
        type: "log",
        logBase: 10,
        min: flowMin,
        max: flowMax,
        // 刻度文字由 markLine 画（位置是真实字节位置），轴自身不出刻度
        axisLabel: { show: false },
        splitLine: { show: false },
        axisLine: { show: false },
        axisTick: { show: false },
      },
      // 右：只放掉包（包数）
      {
        type: "value",
        position: "right",
        min: 0,
        axisLabel: { fontSize: 10, color: "#eab308", formatter: (v: number) => `${v}` },
        splitLine: { show: false },
        axisLine: { show: false },
        axisTick: { show: false },
      },
    ],
    series: [
      {
        name: "流量",
        type: "line",
        // 用户口径：**波浪线**（平滑曲线），**不填充区域**
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1.8, color: "#22c55e" },
        itemStyle: { color: "#22c55e" },
        data: flowData,
        // 容量尺：画在**左侧**（label position: "start"），位置是真实字节位置
        markLine: {
          silent: true,
          symbol: "none",
          lineStyle: { color: "#e2e8f0", type: "dashed", width: 1 },
          label: { position: "start", fontSize: 9, color: "#64748b" },
          data: RATE_TICKS_BYTES.map((value, i) => ({
            yAxis: value,
            label: { formatter: RATE_TICK_LABELS[i] },
          })),
        },
      },
      {
        name: "丢包",
        type: "line",
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1.8, color: "#eab308" },
        itemStyle: { color: "#eab308" },
        data: drops,
        yAxisIndex: 1,
      },
    ],
  };
}
