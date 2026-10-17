"use client";

import { PageShell } from "@/components/page-shell";
import { AssetsPanel } from "@/components/assets-panel";

/** 资产中心 → 资产扫描（有侧边栏）。 */
export default function Page() {
  return (
    <PageShell title="资产扫描" desc="被动扫描：用已发生的访问推断每台主机的暴露面（不主动发包）。" fluid>
      <AssetsPanel mode="scan" />
    </PageShell>
  );
}
