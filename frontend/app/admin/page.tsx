"use client";

import * as React from "react";
import Link from "next/link";
import { Nav } from "@/components/nav";
import { Badge, severityVariant } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Drawer } from "@/components/ui/drawer";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiFetch, type EventGroupItem, type GroupDetail, type EvidenceChain } from "@/lib/api";
import { formatDateTime, severityText, statusText } from "@/lib/format";

export default function AdminEventsPage() {
  const [groups, setGroups] = React.useState<EventGroupItem[]>([]);
  const [selected, setSelected] = React.useState<EventGroupItem | null>(null);
  const [detail, setDetail] = React.useState<GroupDetail | null>(null);
  const [detailError, setDetailError] = React.useState("");
  const [loadingDetail, setLoadingDetail] = React.useState(false);
  // 证据链：单独拉（带原始记录，体积大），不阻塞详情
  const [evidence, setEvidence] = React.useState<EvidenceChain | null>(null);
  const [evidenceError, setEvidenceError] = React.useState("");
  const [loadingEvidence, setLoadingEvidence] = React.useState(false);
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

  // 打开右侧抽屉并拉详情。
  // 详情请求失败时必须**看得见**：以前只在表格下面渲染卡片，
  // 请求失败或列表很长时都表现为"点了详情没反应"。
  async function openDetail(g: EventGroupItem) {
    setSelected(g);
    setDetail(null);
    setDetailError("");
    setEvidence(null);
    setEvidenceError("");
    setLoadingDetail(true);
    setLoadingEvidence(true);
    // 两个请求各自容错：证据拉失败不能让详情也看不见（反之亦然）
    await Promise.allSettled([
      apiFetch<GroupDetail>(`/api/events/groups/${g.id}`)
        .then(setDetail)
        .catch((e) => setDetailError(e instanceof Error ? e.message : "详情加载失败"))
        .finally(() => setLoadingDetail(false)),
      apiFetch<EvidenceChain>(`/api/events/groups/${g.id}/evidence`)
        .then(setEvidence)
        .catch((e) => setEvidenceError(e instanceof Error ? e.message : "证据链加载失败"))
        .finally(() => setLoadingEvidence(false)),
    ]);
  }

  function closeDetail() {
    setSelected(null);
    setDetail(null);
    setDetailError("");
    setEvidence(null);
    setEvidenceError("");
  }

  async function confirm(g: EventGroupItem, action: "confirm" | "dismiss") {
    await apiFetch(`/api/events/groups/${g.id}/confirm`, {
      method: "POST",
      body: JSON.stringify({ action }),
    });
    closeDetail();
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
                  <TableHead>时间（北京时间）</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {groups.map((g) => (
                  <TableRow
                    key={g.id}
                    className="cursor-pointer"
                    onClick={() => openDetail(g)}
                    title="点击查看详情"
                  >
                    <TableCell>
                      <Badge variant={severityVariant(g.severity)}>{severityText(g.severity)}</Badge>
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
                      {g.excluded ? <Badge variant="outline">已排除</Badge> : statusText(g.status)}
                    </TableCell>
                    <TableCell>{formatDateTime(g.window_start)}</TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          openDetail(g);
                        }}
                      >
                        详情
                      </Button>
                      {g.status === "pending_confirmation" && !g.excluded && (
                        <>
                          <Button
                            size="sm"
                            className="ml-2"
                            onClick={(e) => {
                              e.stopPropagation();
                              confirm(g, "confirm");
                            }}
                          >
                            确认
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            className="ml-2"
                            onClick={(e) => {
                              e.stopPropagation();
                              confirm(g, "dismiss");
                            }}
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

        <Drawer
          open={selected !== null}
          onClose={closeDetail}
          title={
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-semibold">事件组详情</span>
              {selected && (
                <Badge variant={severityVariant(selected.severity)}>
                  {severityText(selected.severity)}
                </Badge>
              )}
              {selected && (
                <span className="text-xs text-muted-foreground">
                  {selected.excluded ? "已排除" : statusText(selected.status)} · 得分{" "}
                  {selected.triage_score?.toFixed(2)}
                </span>
              )}
            </div>
          }
          footer={
            selected && selected.status === "pending_confirmation" && !selected.excluded ? (
              <div className="flex gap-2">
                <Button size="sm" onClick={() => confirm(selected, "confirm")}>
                  确认
                </Button>
                <Button size="sm" variant="destructive" onClick={() => confirm(selected, "dismiss")}>
                  忽略
                </Button>
              </div>
            ) : null
          }
        >
          {loadingDetail && <p className="text-sm text-muted-foreground">加载中…</p>}
          {detailError && <p className="text-sm text-destructive">加载失败：{detailError}</p>}
          {selected && !detail && !loadingDetail && !detailError && (
            <p className="text-sm text-muted-foreground">无详情数据</p>
          )}

          {selected && detail && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>
                  源地址：<span className="font-mono text-xs">{detail.src_ips?.join(", ") || "-"}</span>
                </div>
                <div>
                  目标地址：
                  <span className="font-mono text-xs">{detail.dst_ips?.join(", ") || "-"}</span>
                </div>
                <div>
                  窗口：<span className="text-xs">{formatDateTime(detail.window_start)}</span>
                </div>
                <div>
                  事件数：{detail.event_count}
                  {(detail.aggregate?.hits ?? 0) > 0 && ` / 聚合 ${detail.aggregate?.hits}`}
                </div>
              </div>

              {detail.aggregate && (detail.aggregate.hits ?? 0) > 0 && (
                <div>
                  <h3 className="mb-1 font-medium">聚合规模（实时检测）</h3>
                  <p className="text-sm">
                    共命中 <b>{detail.aggregate.hits}</b> 次 · 目标{" "}
                    {detail.aggregate.dst_ips?.length ?? 0} 个 · 端口{" "}
                    {detail.aggregate.dst_ports?.length ?? 0} 个
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {formatDateTime(detail.aggregate.first_seen)} ~{" "}
                    {formatDateTime(detail.aggregate.last_seen)}
                  </p>
                  {detail.aggregate.rules && Object.keys(detail.aggregate.rules).length > 0 && (
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
                        {a.business_system || "-"} · 重要级别 {severityText(a.importance)} · 负责人{" "}
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
                      {detail.memory_hits.persistence.persistent ? "⚠️ 持续性/反复出现：" : "偶发："}
                      最近 {detail.memory_hits.persistence.window_days} 天内出现{" "}
                      {detail.memory_hits.persistence.count} 次
                    </p>
                  )}
                  {(detail.memory_hits?.memories || []).map((m) => (
                    <p key={m.id} className="font-mono text-xs text-muted-foreground">
                      [{formatDateTime(m.created_at)}][{severityText(m.severity)}] {m.summary}
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
                {!detail.attack_chain?.stages?.length && (
                  <p className="text-sm text-muted-foreground">尚无攻击链（未升级或深度分析未完成）</p>
                )}
              </div>

              <div>
                <h3 className="mb-1 font-medium">
                  证据链
                  {evidence && (
                    <span className="ml-2 text-xs font-normal text-muted-foreground">
                      共 {evidence.counts.total} 条（组内日志 {evidence.counts.events} · 调查引用{" "}
                      {evidence.counts.investigation_refs}）
                      {evidence.counts.stages > 0 && ` · 覆盖 ${evidence.counts.stages} 个阶段`}
                      {evidence.counts.linked > 0 && ` · ${evidence.counts.linked} 条已链到阶段`}
                    </span>
                  )}
                </h3>
                {loadingEvidence && <p className="text-sm text-muted-foreground">证据加载中…</p>}
                {evidenceError && (
                  <p className="text-sm text-destructive">证据链加载失败：{evidenceError}</p>
                )}
                {evidence?.investigation.case_id && (
                  <p className="text-xs text-muted-foreground">
                    含自主取证证据（第 {evidence.investigation.round ?? "-"} 轮，置信{" "}
                    {evidence.investigation.confidence ?? "-"}）——{" "}
                    <Link
                      className="text-primary hover:underline"
                      href={`/admin/cases/${evidence.investigation.case_id}`}
                    >
                      查看案件
                    </Link>
                  </p>
                )}
                {evidence && evidence.counts.events_truncated && (
                  <p className="text-xs text-amber-500">
                    该组事件较多，仅列出前 100 条证据（完整数据在 ES 索引里）
                  </p>
                )}

                {evidence && evidence.stages.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {evidence.stages.map((st, i) => (
                      <div key={i} className="rounded border p-2 text-xs">
                        <span className="font-medium">{st.stage}</span>
                        <span className="ml-2 text-muted-foreground">
                          {st.evidence_refs.length > 0
                            ? `引用 ${st.evidence_refs.length} 条证据`
                            : "无直接证据（阶段描述仅供参考）"}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="mt-2 space-y-1">
                  {(evidence?.items || []).map((it, i) => (
                    <details key={`${it.ref}-${i}`} className="rounded border p-2 text-xs">
                      <summary className="cursor-pointer">
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {it.ts ? formatDateTime(it.ts) : "时间未知"}
                        </span>
                        {" | "}
                        {it.event_type || it.kind}
                        {it.src ? ` | ${it.src} → ${it.dst}` : ""}
                        {it.hit_rule ? ` | ${it.hit_rule}` : ""}
                        {it.edge_score !== null && it.edge_score !== undefined
                          ? ` | 分 ${it.edge_score}`
                          : ""}
                        {it.stages?.length ? (
                          <span className="ml-1 text-primary">［{it.stages.join("·")}］</span>
                        ) : null}
                        {it.error ? <span className="ml-1 text-destructive">（{it.error}）</span> : null}
                      </summary>
                      <div className="mt-1 space-y-1">
                        {it.summary && <p className="text-muted-foreground">{it.summary}</p>}
                        <p className="font-mono text-[10px] text-muted-foreground">
                          证据引用 {it.ref || "-"}
                          {it.source_system ? ` · 来源 ${it.source_system}` : ""}
                          {it.protocol ? ` · ${it.protocol}` : ""}
                        </p>
                        <pre className="max-h-56 overflow-auto rounded bg-muted p-2 text-[10px]">
                          {JSON.stringify(it.raw ?? {}, null, 2)}
                        </pre>
                      </div>
                    </details>
                  ))}
                  {evidence && !evidence.items.length && (
                    <p className="text-sm text-muted-foreground">无证据</p>
                  )}
                </div>
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
                {!detail.response_suggestions?.length && (
                  <p className="text-sm text-muted-foreground">无处置建议</p>
                )}
              </div>

              <div>
                <h3 className="mb-1 font-medium">
                  关联事件（共 {detail.events?.length ?? 0} 条，显示前 50）
                </h3>
                {(detail.events || []).slice(0, 50).map((e) => (
                  <p key={e.id} className="font-mono text-xs text-muted-foreground">
                    {formatDateTime(e.ts)} | {e.event_type} | {e.src_ip} → {e.dst_ip}
                    {e.hit_rule ? ` | ${e.hit_rule}` : ""}
                    {e.excluded ? " | 已排除" : ""}
                  </p>
                ))}
              </div>
            </div>
          )}
        </Drawer>
      </main>
    </div>
  );
}
