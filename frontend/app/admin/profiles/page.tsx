"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Drawer } from "@/components/ui/drawer";
import { ApiError, apiFetch, errorText, type EntityProfileItem } from "@/lib/api";
import { formatDateTime } from "@/lib/format";

const SELECT_CLS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm";

function topPairs(dist: Record<string, number> | undefined, n = 5): string {
  return Object.entries(dist || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k, v]) => `${k}×${v}`)
    .join("，");
}

function hourBar(hist: Record<string, number> | undefined): string {
  const h = hist || {};
  return Array.from({ length: 24 }, (_, i) => (h[String(i)] ? "█" : "·")).join("");
}

export default function ProfilesPage() {
  const [items, setItems] = React.useState<EntityProfileItem[]>([]);
  const [total, setTotal] = React.useState(0);
  const [kind, setKind] = React.useState("");
  const [minRisk, setMinRisk] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [detail, setDetail] = React.useState<EntityProfileItem | null>(null);

  async function load() {
    const qs = new URLSearchParams();
    if (kind) qs.set("kind", kind);
    if (minRisk) qs.set("min_risk", minRisk);
    qs.set("limit", "100");
    const d = await apiFetch<{ total: number; items: EntityProfileItem[] }>(`/api/profiles?${qs}`);
    setItems(d.items);
    setTotal(d.total);
  }

  React.useEffect(() => {
    load().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, minRisk]);

  async function cleanup() {
    try {
      const r = await apiFetch<{ deleted: number }>("/api/profiles/cleanup", { method: "POST" });
      setMsg(`清理完成：删除 ${r.deleted} 条长期无观测画像`);
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "清理失败");
    }
  }

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold">
            账号 / 会话画像 <span className="text-sm text-muted-foreground">（共 {total} 条）</span>
          </h1>
          <div className="flex gap-2">
            <select value={kind} onChange={(e) => setKind(e.target.value)} className={SELECT_CLS}>
              <option value="">全部类型</option>
              <option value="account">账号</option>
              <option value="session">会话</option>
            </select>
            <select
              value={minRisk}
              onChange={(e) => setMinRisk(e.target.value)}
              className={SELECT_CLS}
            >
              <option value="">全部风险</option>
              <option value="0.6">仅高风险（≥0.6）</option>
              <option value="0.3">中风险以上（≥0.3）</option>
            </select>
            <Button variant="outline" onClick={() => load()}>
              刷新
            </Button>
            <Button variant="secondary" onClick={cleanup}>
              清理过期
            </Button>
          </div>
        </div>
        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">
              跨窗口长期基线（源 IP / UA / 时段 / 路径 的累积分布）
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>类型</TableHead>
                  <TableHead>账号 / 会话</TableHead>
                  <TableHead>风险分</TableHead>
                  <TableHead>观测数</TableHead>
                  <TableHead>常见源 IP</TableHead>
                  <TableHead>最近出现</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell>
                      <Badge variant={p.kind === "account" ? "info" : "secondary"}>
                        {p.kind === "account" ? "账号" : "会话"}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono">{p.entity_display || p.entity_key}</TableCell>
                    <TableCell>
                      <Badge variant={p.risk_score >= 0.6 ? "high" : p.risk_score >= 0.3 ? "medium" : "low"}>
                        {Number(p.risk_score || 0).toFixed(2)}
                      </Badge>
                    </TableCell>
                    <TableCell>{p.obs_count}</TableCell>
                    <TableCell className="max-w-[240px] truncate text-xs text-muted-foreground">
                      {topPairs(p.src_ips, 3)}
                    </TableCell>
                    <TableCell className="text-xs">
                      {p.last_seen ? formatDateTime(p.last_seen) : "-"}
                    </TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" onClick={() => setDetail(p)}>
                        明细
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground">
                      暂无画像（每轮分析后自动累积基线）
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Drawer
          open={detail !== null}
          onClose={() => setDetail(null)}
          title={
            detail ? (
              <div className="flex flex-col gap-1">
                <span className="font-semibold">
                  {detail.kind === "account" ? "账号" : "会话"}画像明细
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  {detail.entity_display || detail.entity_key}
                </span>
              </div>
            ) : null
          }
        >
          {detail && (
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <p className="mb-1 text-muted-foreground">常见源 IP</p>
                <p className="font-mono">{topPairs(detail.src_ips, 10) || "-"}</p>
                <p className="mb-1 mt-3 text-muted-foreground">常见 User-Agent</p>
                <p className="break-all">{topPairs(detail.user_agents, 3) || "-"}</p>
                <p className="mb-1 mt-3 text-muted-foreground">访问路径 TOP</p>
                <p className="font-mono">{topPairs(detail.paths, 8) || "-"}</p>
              </div>
              <div>
                <p className="mb-1 text-muted-foreground">时段分布（0-23 时）</p>
                <p className="font-mono tracking-tight">{hourBar(detail.hour_hist)}</p>
                <p className="mb-1 mt-3 text-muted-foreground">认证统计</p>
                <p>
                  成功 {detail.success_count} 次 / 失败 {detail.fail_count} 次
                </p>
                <p className="mb-1 mt-3 text-muted-foreground">观测</p>
                <p>
                  首次 {formatDateTime(detail.first_seen)} · 最近 {formatDateTime(detail.last_seen)} · 共{" "}
                  {detail.obs_count} 次
                </p>
                {detail.anomalies?.length > 0 && (
                  <>
                    <p className="mb-1 mt-3 text-muted-foreground">异常记录</p>
                    {detail.anomalies.map((a, i) => (
                      <p key={i} className="text-destructive">
                        {typeof a === "string" ? a : JSON.stringify(a)}
                      </p>
                    ))}
                  </>
                )}
              </div>
            </div>
          )}
        </Drawer>
      </main>
    </div>
  );
}
