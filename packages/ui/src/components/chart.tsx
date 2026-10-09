"use client";

import * as React from "react";
import * as echarts from "echarts";

export interface ChartProps {
  option: echarts.EChartsOption;
  className?: string;
  /** 数值 = 固定像素；字符串（如 "100%"）= 跟着容器走（外层用 flex 填满区域时用） */
  height?: number | string;
  /**
   * ECharts 事件回调：`{ click: (params) => ... }`。
   *
   * 拓扑图点节点就靠它（`params.data.id` 就是节点的真实 IP）；没有它的话
   * ECharts 的交互事件没法透出到 React 层。
   */
  onEvents?: Record<string, (params: unknown) => void>;
}

export function Chart({ option, className, height = 300, onEvents }: ChartProps) {
  const ref = React.useRef<HTMLDivElement>(null);
  const chartRef = React.useRef<echarts.ECharts | null>(null);
  // 实例只建一次：轮询类页面每 15 秒就会给一份新 option，如果每次变化都 dispose+init，
  // 整页图表会跟着闪一下（且白付重建成本）。
  React.useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, "dark");
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
    chartRef.current?.setOption(option, true);
  }, [option]);

  React.useEffect(() => {
    chartRef.current?.resize();
  }, [height]);

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
