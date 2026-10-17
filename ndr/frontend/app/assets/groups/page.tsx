"use client";

import { PageShell } from "@/components/page-shell";
import { AssetsPanel } from "@/components/assets-panel";

/** 资产中心 → 资产分组（有侧边栏）。 */
export default function Page() {
  return (
    <PageShell title="资产分组" desc="按业务/责任维度给资产归类，供资产管理与报表使用。" fluid>
      <AssetsPanel mode="groups" />
    </PageShell>
  );
}
