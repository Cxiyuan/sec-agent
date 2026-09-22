"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Badge, severityVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiFetch, type EventGroupItem, type GroupDetail } from "@/lib/api";

export default function AdminEventsPage() {
  const [groups, setGroups] = React.useState<EventGroupItem[]>([]);
  const [selected, setSelected] = React.useState<EventGroupItem | null>(null);
  const [detail, setDetail] = React.useState<GroupDetail | null>(null);

  async function load() {
    const d = await apiFetch<{ items: EventGroupItem[] }>("/api/events/groups?limit=100");
    setGroups(d.items);
  }

  React.useEffect(() => {
    load().catch(() => {});
  }, []);

  async function openDetail(g: EventGroupItem) {
    setSelected(g);
    const d = await apiFetch<GroupDetail>(`/api/events/groups/${g.id}`);
    setDetail(d);
  }

  async function confirm(g: EventGroupItem, action: "confirm" | "dismiss") {
    await apiFetch(`/api/events/groups/${g.id}/confirm`, {
      method: "POST",
      body: JSON.stringify({ action }),
    });
    setSelected(null);
    setDetail(null);
    load();
  }

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="mb-4 text-2xl font-bold">事件列表</h1>
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>级别</TableHead>
                  <TableHead>源 IP</TableHead>
                  <TableHead>目标 IP</TableHead>
                  <TableHead>事件数</TableHead>
                  <TableHead>得分</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>时间</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {groups.map((g) => (
                  <TableRow key={g.id}>
                    <TableCell>
                      <Badge variant={severityVariant(g.severity)}>{g.severity || "info"}</Badge>
                    </TableCell>
                    <TableCell className="max-w-[140px] truncate">{g.src_ips?.join(", ")}</TableCell>
                    <TableCell className="max-w-[140px] truncate">{g.dst_ips?.join(", ")}</TableCell>
                    <TableCell>{g.event_count}</TableCell>
                    <TableCell>{g.triage_score?.toFixed(2)}</TableCell>
                    <TableCell>{g.status}</TableCell>
                    <TableCell>
                      {g.window_start ? new Date(g.window_start).toLocaleString() : "-"}
                    </TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" onClick={() => openDetail(g)}>
                        详情
                      </Button>
                      {g.status === "pending_confirmation" && (
                        <>
                          <Button size="sm" className="ml-2" onClick={() => confirm(g, "confirm")}>
                            确认
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            className="ml-2"
                            onClick={() => confirm(g, "dismiss")}
                          >
                            忽略
                          </Button>
                        </>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {selected && detail && (
          <Card className="mt-4">
            <CardHeader>
              <CardTitle>事件组详情</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {detail.business_context &&
                ((detail.business_context.assets?.length ?? 0) > 0 ||
                  (detail.business_context.knowledge?.length ?? 0) > 0) && (
                  <div>
                    <h3 className="mb-1 font-medium">资产与业务背景</h3>
                    {(detail.business_context.assets || []).map((a, i) => (
                      <p key={i} className="text-sm">
                        <span className="font-mono">{a.ip}</span> · {a.asset_name || a.hostname || "-"} ·{" "}
                        {a.business_system || "-"} · 重要级别 {a.importance || "-"} · 负责人{" "}
                        {a.owner || "-"}
                      </p>
                    ))}
                    {(detail.business_context.knowledge || []).map((k, i) => (
                      <p key={`k${i}`} className="font-mono text-xs text-muted-foreground">
                        {String(k.content || "").slice(0, 200)}
                      </p>
                    ))}
                  </div>
                )}
              {(detail.lookback || detail.memory_hits) && (
                <div>
                  <h3 className="mb-1 font-medium">历史比对</h3>
                  {detail.lookback && (
                    <p className="text-sm">
                      回溯 {detail.lookback.hours} 小时（{detail.lookback.reason || "-"}）：命中历史事件{" "}
                      {detail.lookback.event_count} 条 / 拉取 {detail.lookback.log_count} 条
                    </p>
                  )}
                  {detail.lookback?.summary && (
                    <pre className="mt-1 whitespace-pre-wrap rounded-md border p-2 text-xs text-muted-foreground">
                      {detail.lookback.summary}
                    </pre>
                  )}
                  {detail.memory_hits?.persistence && detail.memory_hits.persistence.count > 0 && (
                    <p className="mt-1 text-sm">
                      {detail.memory_hits.persistence.persistent
                        ? "⚠️ 持续性/反复出现："
                        : "偶发："}
                      最近 {detail.memory_hits.persistence.window_days} 天内出现{" "}
                      {detail.memory_hits.persistence.count} 次
                    </p>
                  )}
                  {(detail.memory_hits?.memories || []).map((m) => (
                    <p key={m.id} className="font-mono text-xs text-muted-foreground">
                      [{String(m.created_at || "").slice(0, 19).replace("T", " ")}][{m.severity || "-"}]
                      {" "}
                      {m.summary}
                    </p>
                  ))}
                </div>
              )}
              <div>
                <h3 className="mb-1 font-medium">攻击链</h3>
                {(detail.attack_chain?.stages || []).map((s, i) => (
                  <div key={i} className="mb-2 rounded-md border p-2">
                    <p className="font-medium">{s.stage}</p>
                    <p className="text-sm text-muted-foreground">{s.description}</p>
                    {s.evidence?.map((e, j) => (
                      <p key={j} className="ml-3 font-mono text-xs text-muted-foreground">
                        {e.type} | {e.src} → {e.dst} | {e.summary}
                      </p>
                    ))}
                  </div>
                ))}
              </div>
              <div>
                <h3 className="mb-1 font-medium">处置建议</h3>
                {(detail.response_suggestions || []).map((s, i) => (
                  <p key={i} className="text-sm">
                    [{s.category}] {s.action}: {s.detail}
                  </p>
                ))}
              </div>
              <div>
                <h3 className="mb-1 font-medium">关联事件</h3>
                {(detail.events || []).slice(0, 20).map((e) => (
                  <p key={e.id} className="font-mono text-xs text-muted-foreground">
                    {e.ts} | {e.event_type} | {e.src_ip} → {e.dst_ip}
                  </p>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  );
}
