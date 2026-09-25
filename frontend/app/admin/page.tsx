"use client";

import * as React from "react";
import Link from "next/link";
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
  // 被排除的事件默认不看（噪声不刷屏），需要排查时再打开
  const [showExcluded, setShowExcluded] = React.useState(false);

  async function load() {
    const suffix = showExcluded ? "&include_excluded=true" : "";
    const d = await apiFetch<{ items: EventGroupItem[] }>(
      `/api/events/groups?limit=100${suffix}`
    );
    setGroups(d.items);
  }

  React.useEffect(() => {
    load().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showExcluded]);

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
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold">事件列表</h1>
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <input
              type="checkbox"
              checked={showExcluded}
              onChange={(e) => setShowExcluded(e.target.checked)}
            />
            显示已排除的事件（被排除过滤命中，不跑模型）
          </label>
        </div>
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
                    <TableCell>
                      {g.event_count}
                      {(g.aggregate?.hits ?? 0) > 0 && (
                        <span className="text-xs text-muted-foreground">
                          {" / 聚合 "}
                          {g.aggregate?.hits}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>{g.triage_score?.toFixed(2)}</TableCell>
                    <TableCell>
                      {g.excluded ? (
                        <Badge variant="outline">已排除</Badge>
                      ) : (
                        g.status
                      )}
                    </TableCell>
                    <TableCell>
                      {g.window_start ? new Date(g.window_start).toLocaleString() : "-"}
                    </TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" onClick={() => openDetail(g)}>
                        详情
                      </Button>
                      {g.status === "pending_confirmation" && !g.excluded && (
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
              {detail.aggregate && (detail.aggregate.hits ?? 0) > 0 && (
                <div>
                  <h3 className="mb-1 font-medium">聚合规模（实时检测）</h3>
                  <p className="text-sm">
                    共命中 <b>{detail.aggregate.hits}</b> 次 · 目标{" "}
                    {detail.aggregate.dst_ips?.length ?? 0} 个 · 端口{" "}
                    {detail.aggregate.dst_ports?.length ?? 0} 个
                    {detail.aggregate.first_seen && (
                      <>
                        {" · "}
                        {String(detail.aggregate.first_seen).slice(0, 19).replace("T", " ")}
                        {" ~ "}
                        {String(detail.aggregate.last_seen || "").slice(0, 19).replace("T", " ")}
                      </>
                    )}
                  </p>
                  {detail.aggregate.rules &&
                    Object.keys(detail.aggregate.rules).length > 0 && (
                      <p className="text-xs text-muted-foreground">
                        规则分布：
                        {Object.entries(detail.aggregate.rules)
                          .map(([r, n]) => `${r}×${n}`)
                          .join("；")}
                      </p>
                    )}
                  {(detail.aggregate.dst_ports?.length ?? 0) > 0 && (
                    <p className="text-xs text-muted-foreground">
                      端口：{(detail.aggregate.dst_ports || []).join(", ")}
                    </p>
                  )}
                </div>
              )}
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
              {(detail.lookback || detail.memory_hits || detail.profile_hits) && (
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
                  {(detail.profile_hits?.entities || []).length > 0 && (
                    <div className="mt-1">
                      <p className="text-sm font-medium">账号 / 会话画像异常</p>
                      {(detail.profile_hits?.entities || []).map((e, i) => (
                        <p key={i} className="text-xs text-muted-foreground">
                          <span className="font-mono">
                            [{e.kind === "account" ? "账号" : "会话"}] {e.display}
                          </span>
                          风险 {e.risk}：{(e.reasons || []).join("；")}
                        </p>
                      ))}
                    </div>
                  )}
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
              {detail.attack_chain?.case_id && (
                <div>
                  <h3 className="mb-1 font-medium">自主取证调查</h3>
                  <p className="text-sm">
                    该事件组已归入攻击者案件 ——{" "}
                    <Link
                      className="text-primary hover:underline"
                      href={`/admin/cases/${detail.attack_chain.case_id}`}
                    >
                      查看完整路径与证据
                    </Link>
                  </p>
                  {(detail.attack_chain.iocs || []).length > 0 && (
                    <p className="text-xs text-muted-foreground">
                      IOC：
                      {(detail.attack_chain.iocs || [])
                        .slice(0, 8)
                        .map((v) => `${v.type}:${v.value}`)
                        .join("、")}
                    </p>
                  )}
                  {(detail.attack_chain.gaps || []).length > 0 && (
                    <p className="text-xs text-amber-500">
                      未解缺口 {(detail.attack_chain.gaps || []).length} 处（案件页可下追问指令）
                    </p>
                  )}
                </div>
              )}
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
                    {e.excluded ? " | 已排除" : ""}
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
