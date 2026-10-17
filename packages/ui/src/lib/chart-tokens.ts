/**
 * 图表色板：**从 CSS 变量读**，不在业务代码里写 hex。
 *
 * 为什么要有这一层：原来 `status-charts.ts` 里散着 27 个硬编码 hex
 * （`#0ea5e9` 16 次、`#1d4ed8` 7 次、绿同时有 `#22c55e` 和 `#10b981`），
 * 结果是「图表的蓝」不是「UI 的蓝」，改主色时图表一动不动；
 * 暗色端也没有对应的第二套色，图表只能永远按亮色画。
 *
 * 现在图表、徽章、状态灯读的是同一组 `--chart-* / --sev-*`，
 * 切换 `.dark` 时图表跟着变。取不到变量（SSR / 首屏）时用同一套亮色值兜底。
 */

export interface ChartTokens {
  /** 分类色板（8 色），用于多系列 / 饼图 */
  series: string[];
  /** 严重度语义色（与徽章同一组变量） */
  sev: { critical: string; high: string; medium: string; low: string; info: string; ok: string };
  /** 中性：网格线 / 轴文字 / 底槽 */
  axis: string;
  grid: string;
  track: string;
  fg: string;
  surface: string;
  border: string;
  font: string;
}

/** 亮色兜底值：与 globals.css 的 :root 一致，仅用于 SSR 首帧与变量缺失 */
const FALLBACK = {
  series: [
    "#207ee9",
    "#1a8fa8",
    "#239560",
    "#6a5fd0",
    "#dc610d",
    "#c93a6f",
    "#1a8b8b",
    "#b4851f",
  ],
  critical: "#b31d1d",
  high: "#b8500c",
  medium: "#a87407",
  low: "#1b5cb2",
  info: "#4d5c6e",
  ok: "#1c7a4f",
  axis: "#5f6b7a",
  grid: "#e9edf2",
  track: "#dde3ea",
  fg: "#17202c",
  surface: "#ffffff",
  border: "#cdd5df",
  font: "system-ui, sans-serif",
};

/**
 * `getComputedStyle` 返回的是**活对象**：换主题（加/去 `.dark`）后读到的值会更新，
 * 所以只缓存这一次调用，不要缓存取出来的字符串 —— 否则切主题图表不变色。
 */
let decl: CSSStyleDeclaration | null = null;
function styleDecl(): CSSStyleDeclaration | null {
  if (typeof window === "undefined") return null;
  if (!decl) decl = getComputedStyle(document.documentElement);
  return decl;
}

/**
 * HSL 三段值（`212 82% 52%`）→ 逗号形式 `hsl(212, 82%, 52%)`。
 *
 * 为什么要转：ECharts 最终交给 canvas 的 fillStyle，逗号形式是 CSS Color 3，
 * 所有浏览器都认；空格形式是 Color 4，个别环境不稳。已经是 hex/rgb 的原样返回。
 */
function toColor(raw: string, fallback: string): string {
  const value = raw.trim();
  if (!value) return fallback;
  if (/^#[0-9a-fA-F]{3,8}$/.test(value) || /^(rgb|hsl|oklch|color)\(/i.test(value)) return value;
  const parts = value.split(/\s+/);
  if (parts.length === 3 && /%$/.test(parts[1]) && /%$/.test(parts[2])) {
    return `hsl(${parts[0]}, ${parts[1]}, ${parts[2]})`;
  }
  return fallback;
}

function read(name: string, fallback: string): string {
  const style = styleDecl();
  if (!style) return fallback;
  return toColor(style.getPropertyValue(name), fallback);
}

/** 非颜色变量（字体栈）：原样取，不要走颜色转换 */
function readRaw(name: string, fallback: string): string {
  const style = styleDecl();
  if (!style) return fallback;
  return style.getPropertyValue(name).trim() || fallback;
}

/** 主题指纹：只读两个变量就能判断亮/暗是否切换过，避免每次取数都读 17 个属性 */
let cachedSig = "";
let cachedTokens: ChartTokens | null = null;

export function chartTokens(): ChartTokens {
  const style = styleDecl();
  if (!style) return build();
  const sig = `${style.getPropertyValue("--chart-1")}|${style.getPropertyValue("--sev-critical-fg")}|${style.getPropertyValue("--surface-2")}`;
  if (cachedTokens && sig === cachedSig) return cachedTokens;
  cachedSig = sig;
  cachedTokens = build();
  return cachedTokens;
}

function build(): ChartTokens {
  return {
    series: [
      read("--chart-1", FALLBACK.series[0]),
      read("--chart-2", FALLBACK.series[1]),
      read("--chart-3", FALLBACK.series[2]),
      read("--chart-4", FALLBACK.series[3]),
      read("--chart-5", FALLBACK.series[4]),
      read("--chart-6", FALLBACK.series[5]),
      read("--chart-7", FALLBACK.series[6]),
      read("--chart-8", FALLBACK.series[7]),
    ],
    sev: {
      critical: read("--sev-critical-fg", FALLBACK.critical),
      high: read("--sev-high-fg", FALLBACK.high),
      medium: read("--sev-medium-fg", FALLBACK.medium),
      low: read("--sev-low-fg", FALLBACK.low),
      info: read("--sev-info-fg", FALLBACK.info),
      ok: read("--sev-ok-fg", FALLBACK.ok),
    },
    axis: read("--chart-axis", FALLBACK.axis),
    grid: read("--chart-grid", FALLBACK.grid),
    track: read("--chart-track", FALLBACK.track),
    fg: read("--foreground", FALLBACK.fg),
    surface: read("--surface-2", FALLBACK.surface),
    border: read("--border", FALLBACK.border),
    font: readRaw("--font-sans", FALLBACK.font),
  };
}
