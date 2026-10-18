"use client";

import * as React from "react";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent } from "@shentong/ui";
import { Dialog } from "@shentong/ui";
import { Section } from "@shentong/ui";
import { apiFetch, type RebuildDryRun, type RebuildRun } from "@/lib/api";
import { formatDateTime, statusText } from "@shentong/ui";

/**
 * 存量重建面板：dry-run（只算不写）→ 人工核对 → 执行 → 可回滚。
 *
 * 为什么必须先把 dry-run 摆在界面上：重建会把现有案件整体退场（status=superseded），
 * 属于不可逆操作。先看到"会拆成多少案件、最大成员组多少、哪些旧案件会退场"再决定，
 * 比直接执行安全得多（本轮 dry-run 就先后暴露了"一组一案"和"公共域名当攻击者"两个设计问题）。
 */
export function RebuildPanel() {
  const [dry, setDry] = React.useState<RebuildDryRun | null>(null);
  const [runs, setRuns] = React.useState<RebuildRun[]>([]);
  const [busy, setBusy] = React.useState("");
  const [msg, setMsg] = React.useState("");
  /**
   * 待确认的不可逆动作：重建会整体退场现有案件，回滚会删掉整批新案件。
   * 两者都走共享 Dialog 二次确认（原来用 window.confirm，与全站弹层材质对不上）。
   */
  const [ask, setAsk] = React.useState<{ kind: "apply" } | { kind: "rollback"; runId: string } | null>(
    null
  );

  const loadRuns = React.useCallback(async () => {
    try {
      const r = await apiFetch<{ items: RebuildRun[] }>("/api/cases/rebuild/runs?limit=10");
      setRuns(r.items);
    } catch {
      setRuns([]);
    }
  }, []);

  React.useEffect(() => {
    loadRuns().catch(() => {});
  }, [loadRuns]);

  async function runDry() {
    setBusy("dry");
    setMsg("");
    try {
      const r = await apiFetch<RebuildDryRun>("/api/cases/rebuild?dry_run=true", { method: "POST" });
      setDry(r);
      setMsg("dry-run 完成：只算不写，下面是最新计划");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "dry-run 失败");
    } finally {
      setBusy("");
    }
  }

  async function apply() {
    setBusy("apply");
    setMsg("");
    try {
      const r = await apiFetch<{ ok: boolean; run_id: string }>("/api/cases/rebuild?dry_run=false", {
        method: "POST",
      });
      setMsg(`已派发重建（批次 ${r.run_id?.slice(0, 8)}…）—— 完成后刷新页面查看`);
      await loadRuns();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "派发失败");
    } finally {
      setBusy("");
      setAsk(null);
    }
  }

  async function rollback(runId: string) {
    setBusy(runId);
    setMsg("");
    try {
      const r = await apiFetch<{ ok: boolean; removed: number; restored: number }>(
        `/api/cases/rebuild?rollback_run_id=${runId}`,
        { method: "POST" }
      );
      setMsg(`回滚完成：删除新案件 ${r.removed} 个，恢复旧案件 ${r.restored} 个`);
      await loadRuns();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "回滚失败");
    } finally {
      setBusy("");
      setAsk(null);
    }
  }

  return (
    <Section
      title="存量重建（按新规则重算归并）"
      description="先 dry-run 核对，再执行；执行后可用批次号回滚"
      extra={
        <>
          <Button
            size="sm"
            variant="outline"
            disabled={busy !== ""}
            onClick={() => runDry().catch(() => {})}
          >
            {busy === "dry" ? "计算中…" : "① Dry-run（只算不写）"}
          </Button>
          <Button size="sm" disabled={busy !== "" || !dry} onClick={() => setAsk({ kind: "apply" })}>
            {busy === "apply" ? "派发中…" : "② 执行重建"}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => loadRuns().catch(() => {})}>
            刷新批次
          </Button>
        </>
      }
    >
      {dry && (
        <Card>
          <CardContent className="space-y-3 pt-4">
            <div className="flex flex-wrap gap-3 text-xs tabular-nums">
              <span>事件组 {dry.groups}</span>
              <span>
                案件：旧 {dry.old_cases} → 新 <b>{dry.new_cases}</b>
              </span>
              <span>
                单案最大成员组：旧 {dry.old_max_groups} → 新 <b>{dry.new_max_groups}</b>
              </span>
              <span className={dry.oversized_after > 0 ? "text-sev-medium-fg" : "text-muted-foreground"}>
                超上限案件：旧 {dry.oversized_before} → 新 {dry.oversized_after}
              </span>
              <span className="text-muted-foreground">脏域名键案件（旧）：{dry.junk_keys_before}</span>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded-xs bg-surface-1 p-2">
                <p className="mb-1 text-xs text-muted-foreground">旧案件（成员组最多 10 个）</p>
                <div className="space-y-1 text-xs">
                  {dry.sample_old.map((o) => (
                    <div key={o.id} className="flex items-center gap-2">
                      <Badge variant="outline">{o.groups} 组</Badge>
                      <span className="font-mono">{o.attacker_key}</span>
                      <span className="text-muted-foreground">{o.id.slice(0, 8)}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded-xs bg-surface-1 p-2">
                <p className="mb-1 text-xs text-muted-foreground">新案件（成员组最多 15 个）</p>
                <div className="space-y-1 text-xs">
                  {dry.sample_new.map((p) => (
                    <div key={`${p.attacker_key}-${p.groups}`} className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline">{p.groups} 组</Badge>
                      <span className="font-mono">{p.attacker_key}</span>
                      {p.split_reason ? (
                        <span className="text-xs text-sev-medium-fg">{p.split_reason.slice(0, 30)}</span>
                      ) : null}
                      {p.merge_basis?.length ? (
                        <span className="text-xs text-muted-foreground">
                          依据 {p.merge_basis.slice(0, 2).join("、")}
                        </span>
                      ) : null}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {runs.length > 0 && (
        <Card>
          <CardContent className="space-y-1 pt-4">
            <p className="text-xs text-muted-foreground">最近批次</p>
            {runs.map((r) => (
              <div key={r.id} className="flex flex-wrap items-center gap-2 text-xs">
                <span className="font-mono">{r.id.slice(0, 8)}</span>
                <Badge variant={r.status === "finished" ? "outline" : "high"}>{statusText(r.status)}</Badge>
                {r.dry_run ? <span className="text-muted-foreground">dry-run</span> : null}
                <span className="text-muted-foreground">
                  {r.started_at ? formatDateTime(r.started_at) : "-"}
                </span>
                {!r.dry_run && r.status === "finished" && (
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy !== ""}
                    onClick={() => setAsk({ kind: "rollback", runId: r.id })}
                  >
                    回滚
                  </Button>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {msg && <p className="text-13 text-primary">{msg}</p>}

      <Dialog
        open={!!ask}
        title={ask?.kind === "apply" ? "执行存量重建？" : "回滚这个批次？"}
        onClose={() => setAsk(null)}
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button size="sm" variant="outline" onClick={() => setAsk(null)}>
              取消
            </Button>
            <Button
              size="sm"
              variant="destructive"
              disabled={busy !== ""}
              onClick={() => {
                if (!ask) return;
                if (ask.kind === "apply") void apply();
                else void rollback(ask.runId);
              }}
            >
              {ask?.kind === "apply" ? "执行重建" : "回滚"}
            </Button>
          </div>
        }
      >
        {ask?.kind === "apply" ? (
          <ul className="space-y-1.5 text-13 leading-relaxed text-muted-foreground">
            <li>现有案件会全部置为「已退场（superseded）」，不再出现在默认列表里。</li>
            <li>新案件按当前规则重新归并生成，旧案件的数据不会被删除。</li>
            <li>执行后可在下方按批次号回滚恢复。</li>
          </ul>
        ) : (
          <ul className="space-y-1.5 text-13 leading-relaxed text-muted-foreground">
            <li>会删除该批次新建的案件。</li>
            <li>会恢复该批次执行前退场的旧案件。</li>
            <li>回滚本身不可再撤销。</li>
          </ul>
        )}
      </Dialog>
    </Section>
  );
}
