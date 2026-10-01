"use client";

import * as React from "react";
import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import {
  Activity,
  Bell,
  Box,
  Boxes,
  Bug,
  Building2,
  Cable,
  Camera,
  Cloud,
  Container,
  Cpu,
  Database,
  FileSearch,
  Globe,
  HardDrive,
  KeyRound,
  Layers,
  Lock,
  Monitor,
  Network,
  Radio,
  Router,
  ScanLine,
  ScrollText,
  Search,
  Server,
  Share2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Split,
  Terminal,
  Waypoints,
  Wifi,
} from "lucide-react";

type IconComponent = React.ComponentType<{ size?: number | string; color?: string; className?: string }>;

/** 只登记用得到的图标，避免整包引入 lucide（体积可控）。 */
export const ICONS: Record<string, IconComponent> = {
  Activity,
  Bell,
  Box,
  Boxes,
  Bug,
  Building2,
  Cable,
  Camera,
  Cloud,
  Container,
  Cpu,
  Database,
  FileSearch,
  Globe,
  HardDrive,
  KeyRound,
  Layers,
  Lock,
  Monitor,
  Network,
  Radio,
  Router,
  ScanLine,
  ScrollText,
  Search,
  Server,
  Share2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Split,
  Terminal,
  Waypoints,
  Wifi,
};

export function resolveIcon(name: string | undefined): IconComponent {
  return (name && ICONS[name]) || Box;
}

export interface TopoNodePayload extends Record<string, unknown> {
  label: string;
  node_type: string;
  asset_ids: string[];
  zone: string;
  note: string;
  icon?: string;
  color?: string;
  asset_labels?: string[];
}

export type TopoFlowNode = Node<TopoNodePayload, "topoNode">;

export function TopoNodeView({ data, selected }: NodeProps<TopoFlowNode>) {
  const icon = resolveIcon(data.icon);
  const color = data.color ?? "#64748b";
  const Icon = icon;
  const assetLabels = data.asset_labels ?? [];

  const handleStyle: React.CSSProperties = {
    width: 7,
    height: 7,
    background: color,
    border: "1px solid hsl(var(--background))",
  };

  return (
    <div
      className={[
        "min-w-[150px] rounded-md border bg-card px-3 py-2 shadow-sm",
        selected ? "border-primary ring-1 ring-primary" : "border-border",
      ].join(" ")}
      style={{ borderLeft: `4px solid ${color}` }}
    >
      <Handle id="t" type="source" position={Position.Top} style={handleStyle} />
      <Handle id="r" type="source" position={Position.Right} style={handleStyle} />
      <Handle id="b" type="source" position={Position.Bottom} style={handleStyle} />
      <Handle id="l" type="source" position={Position.Left} style={handleStyle} />

      <div className="flex items-center gap-2">
        <Icon size={18} color={color} />
        <span className="text-sm font-medium">{data.label || "未命名设备"}</span>
      </div>
      {data.zone ? (
        <div className="mt-0.5 text-[11px] text-muted-foreground">区域：{data.zone}</div>
      ) : null}
      {assetLabels.length > 0 ? (
        <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
          {assetLabels.slice(0, 3).join("、")}
          {assetLabels.length > 3 ? ` 等${assetLabels.length}个` : ""}
        </div>
      ) : null}
    </div>
  );
}
