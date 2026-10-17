"use client";

import * as React from "react";
import * as echarts from "echarts";
import { chartTokens } from "../lib/chart-tokens";

/**
 * ECharts 主题：**跟随 CSS 变量**，不再硬编码亮色。
 *
 * 为什么重写：原来只 `registerTheme` 了一套白底主题（axisLabel #475569、
 * tooltip 白底），而 agent 前端是暗色 —— 轴标签落在 #0a0f1a 的卡面上对比度
 * 只有 2:1，等于不可读；tooltip 还是一块刺眼的白板。两个产品面共用这个组件，
 * 主题不能只照顾其中一边。
 *
 * 现在颜色**全部**从 `chartTokens()`（`lib/chart-tokens.ts`）取，与业务侧的
 * series 颜色是同一个来源，不会再出现"图表蓝 ≠ UI 蓝"。
 */

const THEME_NAME = "shentong";

/** 主题签名：CSS 变量没变就不重复注册（一页 18 张图只读一次） */
let cachedSignature = "";
let themeDone = false;

function buildTheme() {
  const t = chartTokens();

  return {
    color: t.series,
    backgroundColor: "transparent",
    textStyle: { color: t.axis, fontFamily: t.font },
    title: { textStyle: { color: t.fg }, subtextStyle: { color: t.axis } },
    legend: { textStyle: { color: t.axis } },
    tooltip: {
      backgroundColor: t.surface,
      borderColor: t.border,
      borderWidth: 1,
      padding: [8, 10],
      textStyle: { color: t.fg, fontSize: 12, fontFamily: t.font },
      // 与卡片同一套材质语言：1px 描边 + 柔和投影，不用重阴影
      extraCssText: "box-shadow:0 8px 24px -4px rgba(16,24,40,.14);border-radius:6px;",
    },
    categoryAxis: {
      axisLine: { lineStyle: { color: t.border } },
      axisTick: { lineStyle: { color: t.border } },
      axisLabel: { color: t.axis, fontSize: 12 },
      splitLine: { show: false, lineStyle: { color: t.grid } },
    },
    valueAxis: {
      axisLine: { show: false, lineStyle: { color: t.border } },
      axisTick: { show: false },
      axisLabel: { color: t.axis, fontSize: 12 },
      splitLine: { lineStyle: { color: t.grid } },
    },
    logAxis: {
      axisLine: { show: false, lineStyle: { color: t.border } },
      axisTick: { show: false },
      axisLabel: { color: t.axis, fontSize: 12 },
      splitLine: { lineStyle: { color: t.grid } },
    },
    graph: {
      itemStyle: { borderColor: t.surface },
      lineStyle: { color: t.track },
      label: { color: t.fg },
    },
  };
}

function ensureTheme(): string {
  if (typeof window === "undefined") return THEME_NAME;
  const probe = [
    "--chart-1",
    "--chart-axis",
    "--chart-grid",
    "--border",
    "--foreground",
    "--surface-2",
    "--font-sans",
    "--sev-critical-fg",
  ]
    .map((n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim())
    .join("|");
  if (themeDone && probe === cachedSignature) return THEME_NAME;
  cachedSignature = probe;
  themeDone = true;
  echarts.registerTheme(THEME_NAME, buildTheme());
  return THEME_NAME;
}

export interface ChartProps {
  option: echarts.EChartsOption;
  className?: string;
  /** 数值 = 固定像素；字符串（如 "100%"）= 跟着容器走（外层用 flex 填满区域时用） */
  height?: number | string;
  /** true = 合并更新（默认 false：整份替换，避免残留上一次的 series）。滚动类图表用 true，否则每次刷新等于重画。 */
  merge?: boolean;
  /**
   * ECharts 事件回调：`{ click: (params) => ... }`。
   *
   * 拓扑图点节点就靠它（`params.data.id` 就是节点的真实 IP）；没有它的话
   * ECharts 的交互事件没法透出到 React 层。
   */
  onEvents?: Record<string, (params: unknown) => void>;
}

export function Chart({ option, className, height = 300, onEvents, merge = false }: ChartProps) {
  const ref = React.useRef<HTMLDivElement>(null);
  const chartRef = React.useRef<echarts.ECharts | null>(null);
  // 实例只建一次：轮询类页面每 5 秒就会给一份新 option，如果每次变化都 dispose+init，
  // 整页图表会跟着闪一下（且白付重建成本）。
  React.useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, ensureTheme());
    chartRef.current = chart;
    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
      chartRef.current = null;
    };
  }, []);

  React.useEffect(() => {
    // notMerge=true：整份替换，不残留上一次的 series（例如条目数变少时）
    chartRef.current?.setOption(option, !merge);
  }, [option]);

  React.useEffect(() => {
    chartRef.current?.resize();
  }, [height, merge]);

  // 事件注册：图表实例只建一次，这里按**事件名列表**挂/摘。
  // 用 ref 存最新回调：页面每次渲染都会传个新的内联函数，如果直接当依赖重挂，
  // 旧函数（引用已变）就 off 不掉了。改成稳定包装器 + ref，回调永远是最新的。
  const handlersRef = React.useRef(onEvents || {});
  handlersRef.current = onEvents || {};
  const eventNames = Object.keys(onEvents || {}).sort().join(",");
  React.useEffect(() => {
    const chart = chartRef.current;
    if (!chart) return;
    const names = eventNames ? eventNames.split(",") : [];
    const wrappers = names.map((name) => {
      const wrapper = (params: unknown) => handlersRef.current[name]?.(params);
      chart.on(name, wrapper);
      return [name, wrapper] as const;
    });
    return () => {
      for (const [name, wrapper] of wrappers) chart.off(name, wrapper);
    };
  }, [eventNames]);

  // 容器自己变大变小（外层从固定高度改成 flex-1 填满区域）时也得跟着 resize：
  // 只监听 window 不够 —— flex 布局重排不会触发 window 的 resize 事件。
  React.useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => chartRef.current?.resize());
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return <div ref={ref} className={className} style={{ width: "100%", height }} />;
}
