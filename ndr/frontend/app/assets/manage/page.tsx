"use client";

import { PageShell } from "@/components/page-shell";
import { AssetsPanel } from "@/components/assets-panel";

/** 资产中心 → 资产管理（有侧边栏）。 */
export default function Page() {
  return (
    <PageShell title="资产管理" desc="资产台账：IP、主机名、分组、责任人、重要级别与备注。" fluid>
      <AssetsPanel mode="manage" />
    </PageShell>
  );
}
