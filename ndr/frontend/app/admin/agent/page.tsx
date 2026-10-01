"use client";

import { PageShell } from "@/components/page-shell";
import { AgentPushPanel } from "@/components/agent-push-panel";
import { McpPanel } from "@/components/mcp-panel";

/** 智能体对接：MCP 取数服务（智能体回溯查证据）+ 摘要推送（把事件组推给智能体分析）。 */
export default function AgentPage() {
  return (
    <PageShell
      title="智能体对接"
      desc="智能体这一侧的两个接口：MCP 服务是它回溯取证的唯一取数入口；摘要推送是 NDR 主动把事件组交给它分析。"
    >
      <McpPanel />
      <AgentPushPanel />
    </PageShell>
  );
}
