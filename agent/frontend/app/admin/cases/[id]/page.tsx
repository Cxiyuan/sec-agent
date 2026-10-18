"use client";

import * as React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Nav } from "@/components/nav";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  EmptyState,
  Input,
  Section,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  formatDateTime,
  severityText,
  severityVariant,
  statusText,
} from "@shentong/ui";
import {
  apiFetch,
  getToken,
  type AttackerCaseDetail,
  type EvidenceItem,
  type InvestigationResult,
  type InvestigationRound,
} from "@/lib/api";

async function downloadFile(path: string, filename: string, method = "GET", body?: unknown) {
  const token = getToken();
  const res = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) return false;
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  return true;
}

export default function CaseDetailPage() {
  const params = useParams<{ id: string }>();
  const caseId = params?.id ?? "";
  const [data, setData] = React.useState<AttackerCaseDetail | null>(null);
  const [rounds, setRounds] = React.useState<InvestigationRound[]>([]);
  const [evidence, setEvidence] = React.useState<EvidenceItem[]>([]);
  const [pickedRound, setPickedRound] = React.useState<number | null>(null);
  const [openRef, setOpenRef] = React.useState<string>("");
  const [instruction, setInstruction] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const load = React.useCallback(async () => {
    if (!caseId) return;
    const [detail, rs] = await Promise.all([
      apiFetch<AttackerCaseDetail>(`/api/cases/${caseId}`),
      apiFetch<{ items: InvestigationRound[] }>(`/api/cases/${caseId}/rounds`).catch(() => ({ items: [] })),
    ]);
    setData(detail);
    setRounds(rs.items);
    if (detail.investigation) {
      apiFetch<{ items: EvidenceItem[] }>(`/api/cases/${caseId}/evidence?format=json`)
        .then((r) => setEvidence(r.items))
        .catch(() => setEvidence([]));
    }
  }, [caseId]);

  React.useEffect(() => {
    load().catch(() => {});
  }, [load]);

  async function act(label: string, fn: () => Promise<unknown>) {
    setBusy(true);
    setMsg("");
    try {
      await fn();
      setMsg(label);
      await load();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "操作失败");
    } finally {
      setBusy(false);
    }
  }

  const current: InvestigationResult | null = React.useMemo(() => {
    if (pickedRound === null) return data?.investigation ?? null;
    const found = rounds.find((r) => r.round === pickedRound);
    return found?.result ?? data?.investigation ?? null;
  }, [pickedRound, rounds, data]);

  const evidenceByRef = React.useMemo(() => {
    const map: Record<string, EvidenceItem> = {};
    for (const item of evidence) map[item.ref] = item;
    return map;
  }, [evidence]);

  // 首屏：接口没回来之前画骨架，而不是把「加载中」当成一个页面状态
  if (!data) {
    return (
      <div className="min-h-screen">
        <Nav />
        <main className="ml-56 p-6">
          <div className="space-y-4" aria-busy="true">
            <Skeleton className="h-6 w-1/3" />
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
              <Skeleton className="h-40 lg:col-span-2" />
              <Skeleton className="h-40" />
            </div>
            <Skeleton className="h-28 w-full" />
            <Skeleton className="h-64 w-full" />
          </div>
        </main>
      </div>
    );
  }

  const keys = Object.entries(data.keys || {}).filter(([, v]) => (v || []).length);

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <Link href="/admin/cases" className="text-13 text-muted-foreground hover:underline">
              ← 攻击者案件
            </Link>
            <h1 className="font-mono text-xl font-medium">{data.attacker_key}</h1>
            {data.display_id && (
              <span className="font-mono text-xs text-muted-foreground">{data.display_id}</span>
            )}
            {/* 归并依据：凭什么并在一起（否则案件看起来像凭空出现） */}
            {data.merge_basis?.length ? (
              <span className="text-xs text-muted-foreground" title="真正促成归并的键">
                归并依据 {data.merge_basis.slice(0, 3).join("、")}
              </span>
            ) : null}
            {data.split_reason ? (
              <span className="text-xs text-sev-medium-fg" title={data.split_reason}>
                自动拆分
              </span>
            ) : null}
            {data.contradiction ? (
              <span className="text-xs text-sev-medium-fg" title="结论声称高级行为但缺少结构化证据，仅作参考">
                结论存疑（不作为定级依据）
              </span>
            ) : null}
            {data.severity && (
              <Badge variant={severityVariant(data.severity)}>{severityText(data.severity)}</Badge>
            )}
            <Badge variant="outline">{statusText(data.status)}</Badge>
            {current && current.confidence !== undefined && (
              <span className="text-xs tabular-nums text-muted-foreground">
                置信度 {current.confidence}
              </span>
            )}
          </div>

          <Section title="处置" description="重新调查、追问、报告导出与案件状态">
            <div className="flex flex-wrap items-center gap-2">
              <Button
                size="sm"
                disabled={busy || data.status === "closed"}
                onClick={() => act("已派发重新调查", () =>
                  apiFetch(`/api/cases/${caseId}/investigate`, {
                    method: "POST",
                    body: JSON.stringify({ instruction, followup: false }),
                  })
                )}
              >
                重新调查
              </Button>
              <Input
                placeholder="追问指令（如：重点查 10.1.2.3 近 3 天行为）"
                aria-label="追问指令"
                value={instruction}
                onChange={(e) => setInstruction(e.target.value)}
                className="h-8 w-80"
              />
              <Button
                size="sm"
                variant="outline"
                disabled={busy || !instruction.trim() || data.status === "closed"}
                onClick={() => act("已派发追问（单独留档）", () =>
                  apiFetch(`/api/cases/${caseId}/investigate`, {
                    method: "POST",
                    body: JSON.stringify({ instruction, followup: true }),
                  })
                )}
              >
                追问
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onClick={() => act("已生成取证报告", () =>
                  apiFetch(`/api/cases/${caseId}/report`, {
                    method: "POST",
                    body: JSON.stringify({ include_trail: true }),
                  })
                )}
              >
                生成取证报告
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => downloadFile(`/api/cases/${caseId}/report`, `取证报告_${data.attacker_key}.pdf`).catch(() => {})}
              >
                下载报告
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => downloadFile(`/api/cases/${caseId}/evidence?format=zip`, `证据包_${data.attacker_key}.zip`).catch(() => {})}
              >
                证据包 ZIP
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() =>
                  act(data.status === "closed" ? "已重新打开" : "已关闭案件", () =>
                    apiFetch(`/api/cases/${caseId}/${data.status === "closed" ? "reopen" : "close"}`, { method: "POST" })
                  )
                }
              >
                {data.status === "closed" ? "重新打开" : "关闭案件"}
              </Button>
            </div>

            {msg && <p className="text-xs text-primary">{msg}</p>}
            {data.last_error && (
              <p className="text-xs text-sev-critical-fg">上次错误：{data.last_error}</p>
            )}
            {data.merge_suggestion?.case_ids?.length ? (
              <p className="text-xs text-sev-medium-fg">
                归集提示：{data.merge_suggestion.reason}（候选案件 {data.merge_suggestion.case_ids.join(", ")}）
              </p>
            ) : null}
          </Section>

          <Section title="基础信息" description="归并键、规模与时间窗">
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardContent className="space-y-3 pt-4">
                  <div className="grid grid-cols-1 gap-3 text-13 sm:grid-cols-2">
                    <div>
                      <p className="text-xs text-muted-foreground">源地址</p>
                      <p className="font-mono">{data.src_ips.join(", ") || "-"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">目标地址</p>
                      <p className="font-mono">{data.dst_ips.join(", ") || "-"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">成员组 / 事件</p>
                      <p className="tabular-nums">
                        {data.group_count} / {data.event_count}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">轮次</p>
                      <p className="tabular-nums">
                        共 {data.rounds_total}（今日 {data.rounds_today}）
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">首次</p>
                      <p className="tabular-nums">{formatDateTime(data.first_seen)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">最近</p>
                      <p className="tabular-nums">{formatDateTime(data.last_seen)}</p>
                    </div>
                  </div>
                  {keys.length > 0 && (
                    <div className="border-t border-border-subtle pt-3">
                      <span className="text-xs text-muted-foreground">已确认的键：</span>
                      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
                        {keys.map(([k, v]) => (
                          <span key={k} className="inline-flex items-center gap-1">
                            <Badge variant="outline">{k}</Badge>
                            <span className="font-mono text-xs">{v.slice(0, 4).join(", ")}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
              <Card>
                <CardContent className="space-y-2 pt-4 text-xs">
                  <label htmlFor="round-pick" className="block text-muted-foreground">
                    调查轮次
                  </label>
                  <select
                    id="round-pick"
                    value={pickedRound ?? ""}
                    onChange={(e) => setPickedRound(e.target.value ? Number(e.target.value) : null)}
                    className="h-8 w-full rounded-sm border border-input bg-surface-2 px-2 text-13"
                  >
                    <option value="">最新结果</option>
                    {rounds.map((r) => (
                      <option key={r.id} value={r.round}>
                        第 {r.round} 轮 · {statusText(r.status)} · {r.kind}
                      </option>
                    ))}
                  </select>
                  {rounds.find((r) => r.round === pickedRound)?.instruction ? (
                    <p className="text-muted-foreground">
                      指令：{rounds.find((r) => r.round === pickedRound)?.instruction}
                    </p>
                  ) : null}
                  {current?.budget && (
                    <div className="space-y-1 tabular-nums text-muted-foreground">
                      <div>
                        步数 {current.budget.steps ?? 0}/{current.budget.limits?.max_steps ?? "-"}、查询{" "}
                        {current.budget.queries ?? 0}/{current.budget.limits?.max_queries ?? "-"}、模型{" "}
                        {current.budget.llm_calls ?? 0}/{current.budget.limits?.max_llm_calls ?? "-"}
                      </div>
                      <div>
                        估算 token {current.budget.tokens_est ?? "-"}、耗时{" "}
                        {current.budget.elapsed_ms ? `${Math.round(current.budget.elapsed_ms / 1000)}s` : "-"}
                      </div>
                      {current.budget.stop_reason && <div>结束原因：{current.budget.stop_reason}</div>}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </Section>

          {current?.summary && (
            <Section title="调查结论">
              <Card>
                <CardContent className="whitespace-pre-wrap pt-4 text-13">{current.summary}</CardContent>
              </Card>
            </Section>
          )}

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <div className="space-y-4 lg:col-span-2">
              <Section title="攻击路径" description="每个阶段的结论都带证据引用">
                <Card>
                  <CardContent className="space-y-3 pt-4">
                    {(current?.path || []).map((s, i) => (
                      <div key={i} className="rounded-xs border border-border-subtle bg-surface-1 p-3">
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <span className="text-13 font-medium">
                            {i + 1}. {s.stage}
                          </span>
                          {(s.start || s.end) && (
                            <span className="text-xs tabular-nums text-muted-foreground">
                              {s.start || ""} ~ {s.end || ""}
                            </span>
                          )}
                        </div>
                        <p className="text-13">{s.description}</p>
                        {s.assets?.length ? (
                          <p className="mt-1 text-xs text-muted-foreground">
                            涉及资产：{s.assets.join(", ")}
                          </p>
                        ) : null}
                        <div className="mt-1 space-y-1">
                          {(s.evidence_refs || []).map((ref) => (
                            <div key={ref}>
                              <button
                                className="font-mono text-xs text-primary hover:underline"
                                onClick={() => setOpenRef(openRef === ref ? "" : ref)}
                              >
                                证据 {ref} {openRef === ref ? "▲" : "▼"}
                              </button>
                              {openRef === ref && (
                                <pre className="mt-1 max-h-64 overflow-auto rounded-xs border border-border-subtle bg-card p-2 text-xs">
                                  {JSON.stringify(evidenceByRef[ref] ?? { ref, note: "证据未在清单中（可能超出导出上限）" }, null, 2)}
                                </pre>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                    {!current?.path?.length && (
                      <EmptyState
                        size="compact"
                        title="还没有可验证的阶段结论"
                        hint="可能证据不足，或该案件尚未完成调查"
                      />
                    )}
                  </CardContent>
                </Card>
              </Section>

              {(current?.timeline || []).length > 0 && (
                <Section
                  title="事件时间线"
                  description={`共 ${current?.timeline?.length ?? 0} 条，显示前 100`}
                >
                  <Card>
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>时间</TableHead>
                            <TableHead>类型</TableHead>
                            <TableHead>源</TableHead>
                            <TableHead>目的</TableHead>
                            <TableHead>摘要</TableHead>
                            <TableHead>证据</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {(current?.timeline || []).slice(0, 100).map((t, i) => (
                            <TableRow key={i}>
                              <TableCell className="font-mono text-xs tabular-nums">{t.ts || "-"}</TableCell>
                              <TableCell>{t.type}</TableCell>
                              <TableCell className="font-mono text-xs">{t.src}</TableCell>
                              <TableCell className="font-mono text-xs">{t.dst}</TableCell>
                              <TableCell>{t.summary}</TableCell>
                              <TableCell className="font-mono text-xs">{t.ref}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </Section>
              )}

              {(current?.lateral?.length || current?.exfil?.length) ? (
                <Section title="横向移动与数据外泄">
                  <Card>
                    <CardContent className="space-y-2 pt-4 text-13">
                      {(current?.lateral || []).map((l, i) => (
                        <div key={`l${i}`} className="rounded-xs bg-surface-1 p-2">
                          横向：<span className="font-mono text-xs">{l.src}</span> →{" "}
                          <span className="font-mono text-xs">{l.dst}</span>　方式：{l.method}
                          <div className="font-mono text-xs text-muted-foreground">
                            {(l.evidence_refs || []).join(" ")}
                          </div>
                        </div>
                      ))}
                      {(current?.exfil || []).map((e, i) => (
                        <div key={`e${i}`} className="rounded-xs bg-surface-1 p-2">
                          外泄：<span className="font-mono text-xs">{e.dst}</span>　字节{" "}
                          <span className="tabular-nums">{e.bytes}</span>
                          <div className="font-mono text-xs text-muted-foreground">
                            {(e.evidence_refs || []).join(" ")}
                          </div>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                </Section>
              ) : null}

              {(current?.gaps || []).length > 0 && (
                <Section title="未解缺口" description="可据此下追问指令">
                  <Card>
                    <CardContent className="space-y-2 pt-4 text-13">
                      {(current?.gaps || []).map((g, i) => (
                        <div key={i} className="rounded-xs border border-sev-medium-bd bg-sev-medium-bg p-2">
                          <p className="text-13 font-medium text-sev-medium-fg">{g.missing}</p>
                          <p className="text-xs text-muted-foreground">原因：{g.why || "-"}</p>
                          <p className="text-xs text-muted-foreground">建议：{g.next_action || "-"}</p>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                </Section>
              )}

              {(current?.dropped || []).length > 0 && (
                <Section title="因证据不足被丢弃的结论" description="保留可审计记录">
                  <Card>
                    <CardContent className="space-y-1 pt-4 font-mono text-xs text-muted-foreground">
                      {(current?.dropped || []).map((d, i) => (
                        <div key={i}>{d}</div>
                      ))}
                    </CardContent>
                  </Card>
                </Section>
              )}
            </div>

            <div className="space-y-3">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle>攻击者画像</CardTitle>
                </CardHeader>
                <CardContent className="space-y-1 text-xs">
                  <div>身份：{current?.attacker?.identity || "-"}</div>
                  <div>源 IP：{(current?.attacker?.basic?.src_ips || []).join(", ") || "-"}</div>
                  <div>地理位置：{current?.attacker?.basic?.geo || "-"}</div>
                  <div>工具栈：{(current?.attacker?.basic?.tool_stack || []).join(", ") || "-"}</div>
                  <div>TTP：{(current?.attacker?.behavior?.ttps || current?.attacker?.ttps || []).join(", ") || "-"}</div>
                  <div>动机：{current?.attacker?.behavior?.motivation || "-"}</div>
                </CardContent>
              </Card>

              {(current?.iocs || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle>IOC 与情报</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2 text-xs">
                    {(current?.iocs || []).map((v, i) => (
                      <div key={i} className="rounded-xs bg-surface-1 p-2">
                        <div className="font-mono">
                          [{v.type}] {v.value}
                        </div>
                        {v.intel && Object.keys(v.intel).length > 0 && (
                          <pre className="mt-1 max-h-24 overflow-auto text-xs text-muted-foreground">
                            {JSON.stringify(v.intel)}
                          </pre>
                        )}
                        <div className="font-mono text-xs text-muted-foreground">
                          {(v.evidence_refs || []).join(" ")}
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}

              {(current?.assets_impacted || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle>受影响资产</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1 text-xs">
                    {(current?.assets_impacted || []).map((a, i) => (
                      <div key={i}>
                        <span className="font-mono">{a.ip}</span>　{a.asset || "-"}　
                        <span className="text-muted-foreground">
                          {a.importance || "-"} / {a.role}
                        </span>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle>成员事件组</CardTitle>
                </CardHeader>
                <CardContent className="space-y-1 text-xs">
                  {data.groups.map((g) => (
                    <div key={g.fingerprint} className="rounded-xs bg-surface-1 p-2">
                      <div className="font-mono text-xs text-muted-foreground">{g.fingerprint}</div>
                      <div className="tabular-nums">
                        {formatDateTime(g.window_start)}　事件 {g.event_count}　{severityText(g.severity)}
                      </div>
                      <div className="font-mono text-xs text-muted-foreground">
                        {g.src_ips.join(", ")} → {g.dst_ips.join(", ")}
                      </div>
                    </div>
                  ))}
                  {!data.groups.length && <EmptyState size="compact" title="无成员组" />}
                </CardContent>
              </Card>

              {(current?.query_trail || []).length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle>取证查询轨迹（审计）</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1 text-xs">
                    {(current?.query_trail || []).map((q, i) => (
                      <div key={i} className="rounded-xs bg-surface-1 p-1">
                        <span className="font-mono tabular-nums">
                          {q.step}. {q.tool}
                        </span>
                        {q.result_count !== undefined && q.result_count !== null ? (
                          <span className="tabular-nums text-muted-foreground"> → {q.result_count} 条</span>
                        ) : null}
                        {q.error ? <span className="text-sev-critical-fg"> 错误：{q.error}</span> : null}
                        <div className="max-h-16 overflow-auto font-mono text-xs text-muted-foreground">
                          {JSON.stringify(q.params)}
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
