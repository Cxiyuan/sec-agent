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

// 数据大小阶梯（仪表盘 Y 轴专用，用户口径）：200KB → 1M → 5M → 50M → 100M → 200M → 500M → 1G
// 1K = 1024，逐档换算成字节；档位不等距，所以不用轴的 interval，而是用 markLine 画在**真实位置**上
const RATE_TICKS_BYTES: number[] = [200, 1024, 5120, 25600, 51200, 102400, 256000, 1048576].map(
  (k) => k * 1024,
);
const RATE_TICK_LABELS: string[] = ["200KB", "1M", "5M", "50M", "100M", "200M", "500M", "1G"];
// 曲线峰值可能超过 1G（真超过就按真实比例撑开轴，不裁数据）
function flowAxisMax(maxValue: number): number {
  const top = RATE_TICKS_BYTES[RATE_TICKS_BYTES.length - 1];
  return Math.max(top, Math.ceil(maxValue * 1.05));
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
        title: { show: true, offsetCenter: [0, "34%"], fontSize: 12, color: "#94a3b8" },
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
        title: { show: true, offsetCenter: [0, "36%"], fontSize: 12, color: "#94a3b8" },
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

/**
 * 近 N 分钟流量（**心电图式折线**）：每分钟一个点、不平滑、不填充。
 *
 * 为什么这么画（2026-10 用户要求）：原来的 24h 波浪/面积图看不出"现在在不在传"，而且
 * 未过完的那个小时会让右端假性塌陷；换成按分钟打点，进行中的那一分钟用虚线点单独标出来。
 */
/** 滑动平均（trailing window）：把秒级尖刺抹平，曲线才像参考图那样平滑攀升/下降。 */
function movingAverage(values: number[], window: number): number[] {
  const w = Math.max(1, Math.floor(window));
  const out: number[] = [];
  let sum = 0;
  for (let i = 0; i < values.length; i += 1) {
    sum += values[i];
    if (i >= w) sum -= values[i - w];
    out.push(sum / Math.min(i + 1, w));
  }
  return out;
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

const TRAFFIC_GRID = "#e5e7eb"; // 网格线（横竖同一色，参考图就是浅灰）
const TRAFFIC_LINE = "#5f9e52"; // 线条：绿色
// 滑动平均窗口（秒）：窗口越长越平滑；20 秒能把尖刺抹平又留得住趋势
const TRAFFIC_SMOOTH_SECONDS = 20;
const TRAFFIC_SERIES_NAME = "合计流量（20 秒均）";
const TRAFFIC_HOVER = "#3b82f6"; // 悬停点/指示线/提示框边框：蓝色

/**
 * 近期流量图 —— **完全按 2026-10 用户给的参考图实现**：
 * - 左上角单位 `Mbps`，横线每档一条（0/100/200…），竖线每分钟一条（正好 N 条 = 刻度）；
 * - 线条：绿色**折线**（直连各点、不平滑、不填充、平时不打点）；
 * - 悬停：白底 + 蓝框圆角提示框，内容两行 —— 第一行粗体「接收」，第二行「时间,值Mbps」；
 *   悬停处显示一个蓝点（参考图里那个小蓝点）；
 * - 滚动更新：只换数据不整份重画（Chart 传 merge）+ 线性更新动画。
 */
/**
 * 近期流量图 —— **沿用本页原有仪表样式**（跟 24h 那张同一套配色/单位/提示框）：
 * 蓝色面积折线（`#0ea5e9`，不透明度 0.18）、Y 轴「字节/秒」用 formatBytes 标签、
 * 提示框多行（时间 / 速率 / 合计 / 连接条数）、打点关闭。
 *
 * 两处是这张图特有、不改的口径（都在上一轮需求里定过）：
 * - X 轴只显示**整分钟**的刻度文字（15 分钟 = 15 个刻度）；
 * - 值做 **20 秒滑动平均**（`TRAFFIC_SMOOTH_SECONDS`）：秒级原始值中位数 1.7Mbps、尖峰 2564Mbps，
 *   直接画会变成"平段贴轴 + 一根根尖刺"；原来的 24h 图看着顺，是因为小时桶本身就是平均值。
 */
export function minuteTrafficOption(data: TrafficMinutes | null): EChartsOption {
  const points = data?.points || [];
  const labels = points.map((p) => clockOf(Date.parse(p.ts)));
  // 两条线都是**每秒**口径：流量 = bytes_per_sec（桶内总量 ÷ 桶秒数，不是桶内总量！），
  // 掉包 = Zeek 上报的原值（stats.log 每 5 分钟一条,没上报的格子是 0）
  const flow = points.map((p) => Math.round(p.bytes_per_sec ?? 0));
  const drops = points.map((p) => Math.round(p.pkts_dropped ?? 0));
  const interval = Math.max(1, Number(data?.interval_seconds ?? 20));
  const segment = Math.max(1, Number(data?.segment_minutes ?? 5));
  const everyPoints = Math.max(1, Math.round((segment * 60) / interval));
  const flowMax = flowAxisMax(Math.max(0, ...flow));
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
      textStyle: { fontSize: 10, color: "#94a3b8" },
      data: ["流量", "丢包"],
    },
    tooltip: {
      trigger: "axis",
      formatter: (params: unknown) => {
        const idx = (params as Array<{ dataIndex: number }>)?.[0]?.dataIndex ?? 0;
        const p = points[idx];
        if (!p) return "";
        return [
          `<b>${clockOf(Date.parse(p.ts))}</b>`,
          `合计 ${formatBytes(p.bytes_per_sec ?? 0)}/秒`,
          `发送 ${formatBytes(p.bytes_out_per_sec ?? 0)}/秒 · 接收 ${formatBytes(p.bytes_in_per_sec ?? 0)}/秒`,
          `连接 ${p.docs} 条`,
          `丢包 ${p.pkts_dropped ?? 0} 包（Zeek 每 5 分钟上报）`,
        ].join("<br/>");
      },
    },
    grid: { left: 62, right: 58, top: 22, bottom: 20 },
    xAxis: {
      ...AXIS,
      boundaryGap: false,
      data: labels,
      axisTick: { show: false },
      // 时间要看得见：**每 5 分钟一个标签**（interval 是"跳过的点数"，所以是 everyPoints-1）
      axisLabel: {
        fontSize: 10,
        interval: everyPoints - 1,
        color: "#94a3b8",
        formatter: (value: string) => value.slice(0, 5),
      },
    },
    yAxis: [
      // 左：流量（每秒）。刻度不交给 ECharts 自动分，改成固定 8 档阶梯线（画在真实位置上）
      {
        type: "value",
        min: 0,
        max: flowMax,
        axisLabel: { show: false },
        splitLine: { show: false },
        axisLine: { show: false },
        axisTick: { show: false },
      },
      // 右：丢包（包数）——单独一轴，不然掉包曲线会被流量压成一条平线
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
        // 用户口径：**折叠线**（相邻两点之间用水平+垂直线段，不做平滑）
        step: "end",
        showSymbol: false,
        lineStyle: { width: 1.6, color: "#22c55e" },
        itemStyle: { color: "#22c55e" },
        data: flow,
        // Y 轴 8 档阶梯：200KB / 1M / 5M / 50M / 100M / 200M / 500M / 1G（真实字节位置）
        markLine: {
          silent: true,
          symbol: "none",
          lineStyle: { color: "#334155", type: "dashed", width: 1 },
          label: { position: "end", fontSize: 9, color: "#64748b" },
          data: RATE_TICKS_BYTES.map((value, i) => ({
            yAxis: value,
            label: { formatter: RATE_TICK_LABELS[i] },
          })),
        },
      },
      {
        name: "丢包",
        type: "line",
        step: "end",
        showSymbol: false,
        lineStyle: { width: 1.6, color: "#eab308" },
        itemStyle: { color: "#eab308" },
        data: drops,
        yAxisIndex: 1,
      },
    ],
  };
}
