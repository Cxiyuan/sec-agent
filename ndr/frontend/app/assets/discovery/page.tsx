"use client";

import { PageShell } from "@/components/page-shell";
import { AssetsPanel } from "@/components/assets-panel";

/** 资产中心 → 资产发现（有侧边栏）。 */
export default function Page() {
  return (
    <PageShell title="资产发现" desc="被动发现：只统计镜像流量里出现过的网段内主机，不向网段发探测包。" fluid>
      <AssetsPanel mode="discovery" />
    </PageShell>
  );
}
