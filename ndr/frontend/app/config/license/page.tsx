"use client";

import { PageShell } from "@/components/page-shell";
import { LicensePanel } from "@/components/license-panel";

/** 系统授权：本机授权ID（项目组织身份），智能体侧用它把项目绑定到这台 NDR。 */
export default function LicensePage() {
  return (
    <PageShell
      title="系统授权"
      width="standard"
      desc="本机授权ID 由硬件机器码派生，是智能体侧「项目组织」的绑定依据；它只做身份识别，鉴权仍靠令牌。"
    >
      <LicensePanel />
    </PageShell>
  );
}
