"use client";

import * as React from "react";
import Link from "next/link";
import { Nav } from "@/components/nav";
import {
  Badge,
  Button,
  Card,
  CardContent,
  EmptyState,
  Input,
  Section,
  Stat,
  StatSkeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
  formatDateTime,
  severityText,
  severityVariant,
  statusText,
} from "@shentong/ui";
import { RebuildPanel } from "@/components/rebuild-panel";
import {
  apiFetch,
  getToken,
  type AttackerCaseItem,
  type InvestigationStats,
} from "@/lib/api";
import { STATUS_LABEL } from "@shentong/ui";

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
  const [items, setItems] = React.useState<AttackerCaseItem[] | null>(null);
  const [stats, setStats] = React.useState<InvestigationStats | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [status, setStatus] = React.useState("");
  const [keyword, setKeyword] = React.useState("");
  // 空壳案件默认隐藏：列表被零轮次的 info 级案件刷满过（实测 25 个里 20 个）
  const [showShelved, setShowShelved] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState("");
  // 勾选删除：批量清理误报/测试案件
  const [picked, setPicked] = React.useState<string[]>([]);

  const load = React.useCallback(async () => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (keyword) params.set("keyword", keyword);
    if (showShelved) params.set("include_shelved", "true");
    const [list, st] = await Promise.all([
      apiFetch<{ items: AttackerCaseItem[] }>(`/api/cases?${params.toString()}`),
      apiFetch<InvestigationStats>("/api/investigation/stats").catch(() => null),
    ]);
    setItems(list.items);
    if (st) setStats(st);
  }, [status, keyword, showShelved]);

  React.useEffect(() => {
    load()
      .catch((e) => {
        setItems((x) => x ?? []);
        setMsg(e instanceof Error ? e.message : "案件列表读取失败");
      })
      .finally(() => setLoaded(true));
  }, [load]);

  async function removePicked() {
    if (!picked.length) return;
    if (!window.confirm(`确认删除选中的 ${picked.length} 个案件？（连带其调查轮次与报告；事件组会保留，只清掉案件指针）`)) return;
    setBusy("del");
    setMsg("");
    try {
      const r = await apiFetch<{ deleted: number }>("/api/cases/delete", {
        method: "POST",
        body: JSON.stringify({ ids: picked }),
      });
      setMsg(`已删除 ${r.deleted} 个案件`);
      setPicked([]);
      await load();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "删除失败");
    } finally {
      setBusy("");
    }
  }

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

  const list = items ?? [];

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="sr-only">攻击者案件</h1>
        <div className="space-y-4">
          <Section
            title="攻击者案件"
            description="案件由升级事件组自动归集；零轮次空壳默认隐藏"
            extra={
              <>
                <Input
                  placeholder="按攻击者标识/标题搜索"
                  aria-label="搜索案件"
                  value={keyword}
                  onChange={(e) => setKeyword(e.target.value)}
                  className="h-8 w-56"
                />
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  aria-label="按状态筛选"
                  className="h-8 rounded-sm border border-input bg-surface-2 px-2 text-13"
                >
                  <option value="">全部状态</option>
                  {Object.entries(STATUS_LABEL).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v}
                    </option>
                  ))}
                </select>
                <Button
                  variant="destructive"
                  size="sm"
                  disabled={busy !== "" || picked.length === 0}
                  onClick={() => removePicked().catch(() => {})}
                >
                  {busy === "del" ? "删除中…" : `删除选中（${picked.length}）`}
                </Button>
                <Button variant="outline" size="sm" onClick={() => load().catch(() => {})}>
                  刷新
                </Button>
                <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={showShelved}
                    onChange={(e) => setShowShelved(e.target.checked)}
                  />
                  显示已搁置/已关闭
                </label>
              </>
            }
          >
            <div className="space-y-3">
              {!loaded || !stats ? (
                <StatSkeleton count={4} className="md:grid-cols-4" />
              ) : (
                <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
                  <Stat
                    size="sm"
                    label="自主调查"
                    value={stats.enabled ? "已开启" : "已关闭"}
                    hint={`准入 ≥ ${stats.min_severity}`}
                  />
                  <Stat size="sm" label="案件总数" value={stats.cases_total} />
                  <Stat
                    size="sm"
                    label="今日轮次"
                    value={stats.rounds_today}
                    hint={`单案上限 ${stats.max_rounds_per_day}`}
                  />
                  <Stat
                    size="sm"
                    label="队列积压"
                    value={stats.queue_depth ?? "-"}
                    hint={`冷却 ${stats.cooldown_minutes} 分钟`}
                  />
                  <Stat size="sm" label="估算 token" value={stats.tokens_est_total} />
                  <Stat
                    size="sm"
                    label="零轮次案件"
                    value={stats.cases_empty ?? 0}
                    hint={`${stats.cases_empty_perc ?? 0}% ｜ 搁置 ${stats.cases_shelved ?? 0} / 已关闭 ${
                      stats.cases_closed ?? 0
                    }`}
                  />
                </div>
              )}
              {stats?.guards && (
                <p className="text-xs text-muted-foreground">
                  护栏：无效输出 {stats.guards.invalid_json ?? 0} ｜ 截断 {stats.guards.truncated ?? 0} ｜
                  收束 {stats.guards.salvaged ?? 0} ｜ 无进展 {stats.guards.no_progress ?? 0} ｜ 重复{" "}
                  {stats.guards.repeat ?? 0}
                </p>
              )}
            </div>
          </Section>

          <RebuildPanel />

          {msg && <p className="text-xs text-primary">{msg}</p>}

          <Section title="案件列表" description="按最近活动倒序">
            <Card>
              <CardContent className="p-0">
                {!loaded ? (
                  <TableSkeleton rows={8} cols={8} />
                ) : list.length === 0 ? (
                  <EmptyState
                    title="还没有案件"
                    hint={`案件由升级事件组自动归集产生（需 severity ≥ ${stats?.min_severity ?? "high"}）`}
                    action={
                      <Button size="sm" variant="outline" onClick={() => load().catch(() => {})}>
                        重新读取
                      </Button>
                    }
                  />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-8">
                          <input
                            type="checkbox"
                            aria-label="全选案件"
                            checked={list.length > 0 && picked.length === list.length}
                            onChange={(e) => setPicked(e.target.checked ? list.map((x) => x.id) : [])}
                          />
                        </TableHead>
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
                      {list.map((c) => (
                        <TableRow key={c.id}>
                          <TableCell className="w-8">
                            <input
                              type="checkbox"
                              aria-label={`选择案件 ${c.display_id}`}
                              checked={picked.includes(c.id)}
                              onChange={(e) =>
                                setPicked((prev) =>
                                  e.target.checked ? [...prev, c.id] : prev.filter((x) => x !== c.id)
                                )
                              }
                            />
                          </TableCell>
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
                              <span className="ml-2 font-sans text-xs font-normal text-sev-medium-fg">
                                建议合并
                              </span>
                            ) : null}
                            {c.contradiction ? (
                              <span
                                className="ml-2 font-sans text-xs font-normal text-sev-medium-fg"
                                title="结论声称高级攻击行为，但缺少对应结构化证据（一致性校验）"
                              >
                                结论存疑
                              </span>
                            ) : null}
                            {(c.group_count || 0) > 40 ? (
                              <span
                                className="ml-2 font-sans text-xs font-normal text-sev-medium-fg"
                                title="成员组超过规模上限，建议用下方「存量重建」拆分"
                              >
                                超大案件
                              </span>
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
                              <span className="ml-1 text-sev-critical-fg" title={c.last_error}>
                                ⚠
                              </span>
                            ) : null}
                          </TableCell>
                          <TableCell>
                            {(c.path_stages || []).join(" → ") || "-"}
                            {c.confidence !== undefined && c.confidence !== null ? (
                              <span className="ml-1 text-xs text-muted-foreground">
                                （置信 <span className="tabular-nums">{c.confidence}</span>）
                              </span>
                            ) : null}
                          </TableCell>
                          <TableCell className="tabular-nums">
                            {c.group_count} / {c.event_count}
                          </TableCell>
                          <TableCell className="font-mono text-xs tabular-nums">
                            {formatDateTime(c.last_seen)}
                          </TableCell>
                          <TableCell className="tabular-nums">
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
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </Section>
        </div>
      </main>
    </div>
  );
}
