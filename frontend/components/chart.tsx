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

  React.useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, "dark");
    chart.setOption(option);
    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
    };
  }, [option]);

  return <div ref={ref} className={className} style={{ width: "100%", height }} />;
}
