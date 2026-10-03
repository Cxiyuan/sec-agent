"use client";

import { PageShell } from "@/components/page-shell";
import { AccountPanel } from "@/components/account-panel";

/** 账号：改口令，以及「还在用出厂口令」的提醒。 */
export default function AccountPage() {
  return (
    <PageShell
      title="账户"
      desc="系统只有一个管理员账号；出厂口令是公开的，改掉之后这一页才会显示「口令已修改」。"
    >
      <AccountPanel />
    </PageShell>
  );
}
