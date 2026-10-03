"use client";

import Link from "next/link";
import { PageShell } from "@/components/page-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";

/**
 * 系统配置总览（第 7 期拆页）：原来八个面板全堆在这一页，随着 Wazuh 与推送接入已经太长。
 * 现在按「配置的是哪一段链路」拆成六个子页，这里只留索引，旧链接 /admin/settings 不失效。
 */
const entries = [
  {
    href: "/admin/collect",
    title: "采集接入",
    desc: "Zeek 监听网卡；Wazuh 随系统部署，这里看接入状态、下发规则、入库量。",
  },
  {
    href: "/admin/networks",
    title: "监控网段",
    desc: "抓包范围与检测分析范围；BPF 过滤器与本地网段都由这份清单生成。",
  },
  {
    href: "/admin/storage",
    title: "数据存储",
    desc: "Elasticsearch 连接与索引模板、Logstash 入库管道。",
  },
  {
    href: "/admin/filters",
    title: "过滤规则",
    desc: "降噪规则（只挡检测）与排除规则（整条丢弃）。",
  },
  {
    href: "/admin/agent",
    title: "智能体对接",
    desc: "MCP 取数服务（令牌与调用记录）与摘要推送配置。",
  },
  {
    href: "/admin/status",
    title: "运行状态",
    desc: "队列积压、投递速率、推送重发、Redis 内存与 Wazuh 入库量。",
  },
  {
    href: "/admin/account",
    title: "账户",
    desc: "修改管理员口令；还在用出厂口令 admin123 时导航栏和这一页都会红字提醒。",
  },
];

export default function SettingsPage() {
  return (
    <PageShell title="系统配置" desc="按链路分段配置；点卡片进入对应页面。">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {entries.map((e) => (
          <Link key={e.href} href={e.href} className="block">
            <Card className="h-full transition-colors hover:border-primary">
              <CardHeader>
                <CardTitle className="text-sm">{e.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted-foreground">{e.desc}</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </PageShell>
  );
}
