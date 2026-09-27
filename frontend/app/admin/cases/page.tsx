"use client";

import * as React from "react";
import Link from "next/link";
import { Nav } from "@/components/nav";
import { Badge, severityVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiFetch, getToken, type AttackerCaseItem, type InvestigationStats } from "@/lib/api";
import { STATUS_LABEL, formatDateTime, severityText, statusText } from "@/lib/format";

async function downloadEvidence(c: AttackerCaseItem, format: "zip" | "json") {
  const token = getToken();
  const res = await fetch(`/api/cases/${c.id}/evidence?format=${format}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return;
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = format === "zip" ? `case_${c.attacker_key}_evidence.zip` : `case_${c.attacker_key}_evidence.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function CasesPage() {
  const [items, setItems] = React.useState<AttackerCaseItem[]>([]);
  const [stats, setStats] = React.useState<InvestigationStats | null>(null);
  const [status, setStatus] = React.useState("");
  const [keyword, setKeyword] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState("");

  const load = React.useCallback(async () => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (keyword) params.set("keyword", keyword);
    const [list, st] = await Promise.all([
      apiFetch<{ items: AttackerCaseItem[] }>(`/api/cases?${params.toString()}`),
      apiFetch<InvestigationStats>("/api/investigation/stats").catch(() => null),
    ]);
    setItems(list.items);
    if (st) setStats(st);
  }, [status, keyword]);

  React.useEffect(() => {
    load().catch(() => {});
  }, [load]);

  async function investigate(c: AttackerCaseItem) {
    setBusy(c.id);
    setMsg("");
    try {
      const r = await apiFetch<{ ok: boolean; error?: string }>(`/api/cases/${c.id}/investigate`, {
        method: "POST",
        body: JSON.stringify({ instruction: "", followup: false }),
      });
      setMsg(r.ok ? `已派发调查：${c.attacker_key}（进 investigation 队列）` : `派发失败：${r.error}`);
      await load();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "派发失败");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold">攻击者案件</h1>
          <div className="flex items-center gap-2">
            <Input
              placeholder="按攻击者标识/标题搜索"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              className="w-56"
            />
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
            >
              <option value="">全部状态</option>
              {Object.entries(STATUS_LABEL).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
            <Button variant="outline" size="sm" onClick={() => load().catch(() => {})}>
              刷新
            </Button>
          </div>
        </div>

        {stats && (
          <div className="mb-4 flex flex-wrap gap-3 text-sm text-muted-foreground">
            <span>
              自主调查：{stats.enabled ? "已开启" : "已关闭"}（准入 ≥ {stats.min_severity}）
            </span>
            <span>案件 {stats.cases_total}</span>
            <span>
              今日轮次 {stats.rounds_today} / 单案上限 {stats.max_rounds_per_day}
            </span>
            <span>冷却 {stats.cooldown_minutes} 分钟</span>
            <span>队列积压 {stats.queue_depth ?? "-"}</span>
            <span>估算 token 累计 {stats.tokens_est_total}</span>
          </div>
        )}

        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">案件列表（按最近活动倒序）</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>编号</TableHead>
                  <TableHead>攻击者标识</TableHead>
                  <TableHead>级别</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>路径阶段</TableHead>
                  <TableHead>组/事件</TableHead>
                  <TableHead>最近活动</TableHead>
                  <TableHead>轮次</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-mono text-xs">
                      <Link className="text-muted-foreground hover:underline" href={`/admin/cases/${c.id}`}>
                        {c.display_id}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      <Link className="text-primary hover:underline" href={`/admin/cases/${c.id}`}>
                        {c.attacker_key}
                      </Link>
                      {c.merge_suggestion?.case_ids?.length ? (
                        <span className="ml-2 text-[11px] text-amber-500">建议合并</span>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      {c.severity ? (
                        <Badge variant={severityVariant(c.severity)}>{severityText(c.severity)}</Badge>
                      ) : (
                        "-"
                      )}
                    </TableCell>
                    <TableCell>
                      {statusText(c.status)}
                      {c.last_error ? (
                        <span className="ml-1 text-[11px] text-destructive" title={c.last_error}>
                          ⚠
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-xs">
                      {(c.path_stages || []).join(" → ") || "-"}
                      {c.confidence !== undefined && c.confidence !== null ? (
                        <span className="ml-1 text-muted-foreground">（置信 {c.confidence}）</span>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-xs">
                      {c.group_count} / {c.event_count}
                    </TableCell>
                    <TableCell className="text-xs">
                      {formatDateTime(c.last_seen)}
                    </TableCell>
                    <TableCell className="text-xs">
                      {c.rounds_total}
                      {c.rounds_today ? `（今日 ${c.rounds_today}）` : ""}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busy === c.id || c.status === "closed"}
                          onClick={() => investigate(c)}
                        >
                          {busy === c.id ? "派发中…" : "立即调查"}
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => downloadEvidence(c, "zip").catch(() => {})}
                        >
                          证据包
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {!items.length && (
                  <TableRow>
                    <TableCell colSpan={8} className="text-sm text-muted-foreground">
                      还没有案件。案件由升级事件组自动归集产生（需 severity ≥{" "}
                      {stats?.min_severity ?? "high"}）。
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
