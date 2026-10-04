"use client";

import * as React from "react";
import * as echarts from "echarts";

export interface ChartProps {
  option: echarts.EChartsOption;
  className?: string;
  height?: number;
}

export function Chart({ option, className, height = 300 }: ChartProps) {
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

  return <div ref={ref} className={className} style={{ width: "100%", height }} />;
}
