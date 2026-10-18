"use client";

import * as React from "react";
import Link from "next/link";
import { Nav } from "@/components/nav";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Dialog,
  Drawer,
  EmptyState,
  Section,
  Skeleton,
  Stat,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
  directionText,
  formatDateTime,
  ruleText,
  severityText,
  severityVariant,
  statusText,
} from "@shentong/ui";
import { apiFetch, type EventGroupItem, type GroupDetail, type EvidenceChain } from "@/lib/api";

export default function AdminEventsPage() {
  // null = 首屏还没读到（画骨架）；[] = 读到了但没有数据（画空态）
  const [groups, setGroups] = React.useState<EventGroupItem[] | null>(null);
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
  // 误报治理：同一个源 IP 反复成组会把列表刷屏（实测一个源能出十几组）。
  // 展示层按「同主源」折叠成一行（不动归组指纹、零迁移）；点开看最新那组，其余组在抽屉里列出。
  const [foldSameSrc, setFoldSameSrc] = React.useState(true);
  const [foldSiblings, setFoldSiblings] = React.useState<EventGroupItem[]>([]);
  // 勾选删除：批量清理误报/测试事件组（只删 PG 分析产物，ES 原始日志保留）
  const [picked, setPicked] = React.useState<string[]>([]);
  /** 批量删除的二次确认与结果提示：原来用 window.confirm / window.alert，与全站弹层和提示条材质都不一致 */
  const [askDel, setAskDel] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [msgErr, setMsgErr] = React.useState(false);

  async function load() {
    const suffix = showExcluded ? "&include_excluded=true" : "";
    const d = await apiFetch<{ items: EventGroupItem[] }>(
      `/api/events/groups?limit=100${suffix}`
    );
    setGroups(d.items);
  }

  React.useEffect(() => {
    load().catch(() => setGroups((g) => g ?? []));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showExcluded]);

  // 打开右侧抽屉并拉详情。
  // 详情请求失败时必须**看得见**：以前只在表格下面渲染卡片，
  // 请求失败或列表很长时都表现为"点了详情没反应"。
  async function openDetail(g: EventGroupItem, siblings: EventGroupItem[] = []) {
    setSelected(g);
    setFoldSiblings(siblings);
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

  async function removePicked() {
    if (!picked.length) return;
    setLoadingDetail(false);
    setMsg("");
    setMsgErr(false);
    try {
      const r = await apiFetch<{ deleted: number }>("/api/events/groups/delete", {
        method: "POST",
        body: JSON.stringify({ ids: picked }),
      });
      setPicked([]);
      await load();
      // 反馈走页面提示条（原来用 window.alert，会打断操作且不跟随主题）
      setMsg(`已删除 ${r.deleted} 个事件组`);
    } catch (e) {
      setMsgErr(true);
      setMsg(e instanceof Error ? e.message : "删除失败");
    } finally {
      setAskDel(false);
    }
  }

  async function confirm(g: EventGroupItem, action: "confirm" | "dismiss") {
    await apiFetch(`/api/events/groups/${g.id}/confirm`, {
      method: "POST",
      body: JSON.stringify({ action }),
    });
    closeDetail();
    load();
  }

  // 折叠行：同主源 → 一行；代表行取该源最新的一组
  const rows = React.useMemo(() => {
    const list = groups ?? [];
    if (!foldSameSrc) return list.map((g) => ({ key: g.id, row: g, siblings: [g] }));
    const bySrc = new Map<string, EventGroupItem[]>();
    for (const g of list) {
      const src = (g.src_ips || [])[0] || "(无源 IP)";
      const bucket = bySrc.get(src);
      if (bucket) bucket.push(g);
      else bySrc.set(src, [g]);
    }
    return [...bySrc.entries()].map(([src, list]) => {
      const sorted = [...list].sort((a, b) =>
        String(b.window_start || "").localeCompare(String(a.window_start || ""))
      );
      return { key: `src:${src}`, row: sorted[0], siblings: sorted };
    });
  }, [groups, foldSameSrc]);

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="sr-only">事件列表</h1>
        <div className="space-y-4">
          {msg && (
            <p
              role={msgErr ? "alert" : "status"}
              className={msgErr ? "text-13 text-sev-critical-fg" : "text-13 text-primary"}
            >
              {msg}
            </p>
          )}
          <Section
            title="事件列表"
            description="点击任意行查看详情与证据链；默认按同源折叠重复组"
            extra={
              <>
                <Button
                  variant="destructive"
                  size="sm"
                  disabled={picked.length === 0}
                  onClick={() => setAskDel(true)}
                >
                  删除选中（{picked.length}）
                </Button>
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={foldSameSrc}
                    onChange={(e) => setFoldSameSrc(e.target.checked)}
                  />
                  按同源折叠重复组
                </label>
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={showExcluded}
                    onChange={(e) => setShowExcluded(e.target.checked)}
                  />
                  显示已排除的事件（被排除过滤命中，不跑模型）
                </label>
              </>
            }
          >
            <Card>
              <CardContent className="p-0">
                {groups === null ? (
                  <TableSkeleton rows={10} cols={8} />
                ) : groups.length === 0 ? (
                  <EmptyState
                    title="暂无事件组"
                    hint="检测器产出事件组后会出现在这里；也可以放宽左侧时间范围或打开「显示已排除」"
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
                            aria-label="全选事件组"
                            checked={groups.length > 0 && picked.length === groups.length}
                            onChange={(e) =>
                              setPicked(e.target.checked ? groups.map((x) => x.id) : [])
                            }
                          />
                        </TableHead>
                        <TableHead>编号</TableHead>
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
                      {rows.map(({ key, row: g, siblings }) => (
                        <TableRow
                          key={key}
                          className="cursor-pointer"
                          onClick={() => openDetail(g, siblings)}
                          title="点击查看详情"
                        >
                          <TableCell className="w-8">
                            <input
                              type="checkbox"
                              aria-label={`选择事件组 ${g.display_id}`}
                              checked={siblings.every((s) => picked.includes(s.id))}
                              onChange={(e) =>
                                setPicked((prev) => {
                                  const ids = siblings.map((s) => s.id);
                                  return e.target.checked
                                    ? [...new Set([...prev, ...ids])]
                                    : prev.filter((x) => !ids.includes(x));
                                })
                              }
                            />
                          </TableCell>
                          <TableCell className="font-mono text-xs">{g.display_id}</TableCell>
                          <TableCell>
                            <Badge variant={severityVariant(g.severity)}>{severityText(g.severity)}</Badge>
                          </TableCell>
                          <TableCell className="max-w-[140px] truncate">
                            {g.src_ips?.join(", ")}
                            {siblings.length > 1 && (
                              <Badge variant="outline" className="ml-2">
                                同源 {siblings.length} 组
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell className="max-w-[140px] truncate">{g.dst_ips?.join(", ")}</TableCell>
                          <TableCell className="tabular-nums">
                            {siblings.length > 1
                              ? siblings.reduce((n, x) => n + (x.event_count || 0), 0)
                              : g.event_count}
                            {(g.aggregate?.hits ?? 0) > 0 && (
                              <span className="text-xs text-muted-foreground">
                                {" / 聚合 "}
                                {g.aggregate?.hits}
                              </span>
                            )}
                          </TableCell>
                          <TableCell className="tabular-nums">{g.triage_score?.toFixed(2)}</TableCell>
                          <TableCell>
                            {g.excluded ? <Badge variant="outline">已排除</Badge> : statusText(g.status)}
                          </TableCell>
                          <TableCell className="font-mono text-xs tabular-nums">
                            {formatDateTime(g.window_start)}
                          </TableCell>
                          <TableCell>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={(e) => {
                                e.stopPropagation();
                                openDetail(g, siblings);
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
                )}
              </CardContent>
            </Card>
          </Section>
        </div>

        <Drawer
          open={selected !== null}
          onClose={closeDetail}
          title={
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">事件组详情</span>
              {selected?.display_id && (
                <span className="font-mono text-xs text-muted-foreground">{selected.display_id}</span>
              )}
              {selected && (
                <Badge variant={severityVariant(selected.severity)}>
                  {severityText(selected.severity)}
                </Badge>
              )}
              {selected && (
                <span className="text-xs text-muted-foreground">
                  {selected.excluded ? "已排除" : statusText(selected.status)} · 得分{" "}
                  <span className="tabular-nums">{selected.triage_score?.toFixed(2)}</span>
                </span>
              )}
              {selected?.direction && (
                <Badge variant="outline">{directionText(selected.direction)}</Badge>
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
          {loadingDetail && (
            <div className="space-y-3" aria-busy="true">
              <Skeleton className="h-4 w-1/3" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-4 w-1/4" />
              <Skeleton className="h-24 w-full" />
            </div>
          )}
          {detailError && (
            <EmptyState tone="danger" size="compact" title="详情读取失败" hint={detailError} />
          )}
          {selected && !detail && !loadingDetail && !detailError && (
            <EmptyState size="compact" title="无详情数据" hint="该事件组可能刚被删除，返回列表刷新后再试" />
          )}

          {selected && detail && (
            <div className="space-y-4">
              <Section title="基础信息" description="检测窗口、规模与归组指纹">
                <div className="grid grid-cols-2 gap-3">
                  <Stat
                    size="sm"
                    label="检测窗口"
                    value={
                      <span className="font-mono text-13">{formatDateTime(detail.window_start)}</span>
                    }
                  />
                  <Stat
                    size="sm"
                    label="事件数"
                    value={
                      <span className="tabular-nums">
                        {detail.event_count}
                        {(detail.aggregate?.hits ?? 0) > 0 ? ` / 聚合 ${detail.aggregate?.hits}` : ""}
                      </span>
                    }
                  />
                </div>
                <p className="font-mono text-xs text-muted-foreground">
                  {selected.display_id} · 指纹 {selected.fingerprint}
                </p>
              </Section>

              {/* 误报治理：为什么被跳过、为什么被降级 —— 必须能解释清楚（不允许静默降噪）。
                  方向、跳过理由、定级约束理由都在后端落库，这里只负责展示。 */}
              {(selected.direction || selected.exclude_reason || selected.severity_cap_reason) && (
                <Section title="处理依据" description="跳过与降级都会在这里写明原因">
                  <div className="space-y-1 rounded-xs border border-border-subtle bg-surface-1 p-2 text-xs">
                    {selected.direction && (
                      <p className="text-muted-foreground">
                        流量方向：{directionText(selected.direction)}（外网按是否公网地址判定，与具体网段无关）
                      </p>
                    )}
                    {selected.exclude_reason && (
                      <p className="text-sev-medium-fg">跳过模型分析：{selected.exclude_reason}</p>
                    )}
                    {selected.severity_cap_reason && (
                      <p className="text-sev-medium-fg">定级被约束：{selected.severity_cap_reason}</p>
                    )}
                  </div>
                </Section>
              )}

              {/* 案件视角：本组所属案件 + 案件叙事副本。
                  案件结论不再覆盖本组攻击链（以前会，等于让调查结果给自己作证）。 */}
              {(selected.case_id || selected.case_context) && (
                <Section
                  title="案件视角"
                  description={`${selected.case_id
                    ? `属于案件 AC-${selected.case_id.slice(0, 8).toUpperCase()}`
                    : "无案件指针"}${selected.case_context?.superseded ? " · 该副本已因重建退场" : ""}`}
                >
                  {selected.case_context ? (
                    <div className="space-y-1 text-xs">
                      {selected.case_context.severity && (
                        <p>案件级别：{severityText(selected.case_context.severity)}</p>
                      )}
                      {selected.case_context.summary && (
                        <p className="text-muted-foreground">{selected.case_context.summary}</p>
                      )}
                      {(selected.case_context.path || []).length > 0 && (
                        <p className="text-muted-foreground">
                          案件阶段：
                          {(selected.case_context.path || [])
                            .map((p) => p.stage)
                            .filter(Boolean)
                            .join(" → ")}
                        </p>
                      )}
                      {selected.case_context.rounds ? (
                        <p className="tabular-nums">调查轮次：{selected.case_context.rounds}</p>
                      ) : null}
                    </div>
                  ) : (
                    <EmptyState size="compact" title="暂无案件视角副本" />
                  )}
                </Section>
              )}

              {/* 同源重复组：展示层折叠了它们，这里给出全貌（归组指纹未动） */}
              {foldSiblings.length > 1 && (
                <Section
                  title={`同一来源的其它事件组（${foldSiblings.length - 1}）`}
                  description="列表按同源折叠，归组指纹未变；这里只展示最新那组"
                >
                  <div className="space-y-1 text-xs">
                    {foldSiblings.slice(1, 9).map((s) => (
                      <div key={s.id} className="flex flex-wrap items-center gap-2">
                        <Badge variant={severityVariant(s.severity)}>{severityText(s.severity)}</Badge>
                        <span className="font-mono">{(s.dst_ips || []).slice(0, 3).join(", ")}</span>
                        <span className="tabular-nums text-muted-foreground">{s.event_count} 条</span>
                        <span className="text-muted-foreground">{statusText(s.status)}</span>
                        <span className="text-muted-foreground">{formatDateTime(s.window_start)}</span>
                      </div>
                    ))}
                  </div>
                </Section>
              )}

              {/* 关键 IP：事件组是按 IP 集合归并的，一个组可能涉及十几个 IP ——
                  详情只突出**真正有问题的**（外网来源置顶、按命中排序），其余折叠。 */}
              {detail.key_ips && (
                <Section
                  title="关键 IP"
                  description={`本组共涉及 ${detail.key_ips.total_src} 个源 IP / ${detail.key_ips.total_dst} 个目标 IP，下面只列命中的`}
                >
                  <div className="space-y-3 text-xs">
                    <div>
                      <p className="mb-1 text-muted-foreground">
                        疑似来源（{detail.key_ips.actors.length}）
                      </p>
                      {detail.key_ips.actors.length === 0 && (
                        <p className="text-muted-foreground">（无命中来源）</p>
                      )}
                      {detail.key_ips.actors.map((a) => (
                        <div key={a.ip} className="mb-1 flex flex-wrap items-center gap-2">
                          {a.external && <Badge variant="high">外网</Badge>}
                          <span className="font-mono">{a.ip}</span>
                          <span className="tabular-nums text-muted-foreground">命中 {a.hits} 次</span>
                          <span className="text-muted-foreground">
                            {(a.rules || []).slice(0, 2).join("、")}
                          </span>
                          <span className="text-muted-foreground">{formatDateTime(a.first)}</span>
                        </div>
                      ))}
                    </div>
                    <div>
                      <p className="mb-1 text-muted-foreground">
                        被打目标（{detail.key_ips.targets.length}）
                      </p>
                      {detail.key_ips.targets.length === 0 && (
                        <p className="text-muted-foreground">（无命中目标）</p>
                      )}
                      {detail.key_ips.targets.map((t) => (
                        <div key={t.ip} className="mb-1 flex flex-wrap items-center gap-2">
                          <span className="font-mono">{t.ip}</span>
                          <span className="tabular-nums text-muted-foreground">命中 {t.hits} 次</span>
                          {(t.ports || []).length > 0 && (
                            <span className="text-muted-foreground">
                              端口 {(t.ports || []).slice(0, 8).join(",")}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                    {(detail.key_ips.other_src.length > 0 ||
                      detail.key_ips.other_dst.length > 0) && (
                      <details className="text-muted-foreground">
                        <summary className="cursor-pointer">
                          展开查看本组其余 IP（本批涉及但未命中事件）
                        </summary>
                        <p className="mt-1 font-mono">
                          源：{(detail.key_ips.other_src || []).join(", ") || "-"}
                        </p>
                        <p className="mt-1 font-mono">
                          目标：{(detail.key_ips.other_dst || []).join(", ") || "-"}
                        </p>
                      </details>
                    )}
                  </div>
                </Section>
              )}

              {detail.aggregate && (detail.aggregate.hits ?? 0) > 0 && (
                <Section title="聚合规模（实时检测）">
                  <p className="text-13 tabular-nums">
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
                </Section>
              )}

              {detail.business_context &&
                ((detail.business_context.assets?.length ?? 0) > 0 ||
                  (detail.business_context.knowledge?.length ?? 0) > 0) && (
                  <Section title="资产与业务背景">
                    {(detail.business_context.assets || []).map((a, i) => (
                      <p key={i} className="text-13">
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
                  </Section>
                )}

              {(detail.lookback || detail.memory_hits || detail.profile_hits) && (
                <Section title="历史比对">
                  {detail.lookback && (
                    <p className="text-13 tabular-nums">
                      回溯 {detail.lookback.hours} 小时（{detail.lookback.reason || "-"}）：命中历史事件{" "}
                      {detail.lookback.event_count} 条 / 拉取 {detail.lookback.log_count} 条
                    </p>
                  )}
                  {detail.lookback?.summary && (
                    <pre className="mt-1 whitespace-pre-wrap rounded-xs border border-border-subtle bg-surface-1 p-2 text-xs text-muted-foreground">
                      {detail.lookback.summary}
                    </pre>
                  )}
                  {detail.memory_hits?.persistence && detail.memory_hits.persistence.count > 0 && (
                    <p className="mt-1 text-13 tabular-nums">
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
                    <div className="mt-1 space-y-1">
                      <p className="text-13 font-medium">账号 / 会话画像异常</p>
                      {(detail.profile_hits?.entities || []).map((e, i) => (
                        <p key={i} className="text-xs text-muted-foreground">
                          <span className="font-mono">
                            [{e.kind === "account" ? "账号" : "会话"}] {e.display}
                          </span>
                          <span className="tabular-nums"> 风险 {e.risk}</span>：
                          {(e.reasons || []).join("；")}
                        </p>
                      ))}
                    </div>
                  )}
                </Section>
              )}

              <Section title="攻击链">
                {(detail.attack_chain?.stages || []).map((s, i) => (
                  <div key={i} className="mb-2 rounded-xs border border-border-subtle bg-surface-1 p-2">
                    <p className="text-13 font-medium">{s.stage}</p>
                    <p className="text-13 text-muted-foreground">{s.description}</p>
                    {s.evidence?.map((e, j) => (
                      <p key={j} className="ml-3 font-mono text-xs text-muted-foreground">
                        {e.type} | {e.src} → {e.dst} | {e.summary}
                      </p>
                    ))}
                  </div>
                ))}
                {!detail.attack_chain?.stages?.length && (
                  <EmptyState
                    size="compact"
                    title="尚无攻击链"
                    hint="未升级或深度分析未完成时没有阶段结论"
                  />
                )}
              </Section>

              <Section
                title="证据链"
                description={
                  evidence
                    ? `共 ${evidence.counts.total} 条（组内日志 ${evidence.counts.events} · 调查引用 ${evidence.counts.investigation_refs}）${
                        evidence.counts.stages > 0 ? ` · 覆盖 ${evidence.counts.stages} 个阶段` : ""
                      }${evidence.counts.linked > 0 ? ` · ${evidence.counts.linked} 条已链到阶段` : ""}`
                    : undefined
                }
              >
                {loadingEvidence && (
                  <div className="space-y-2" aria-busy="true">
                    <Skeleton className="h-3 w-2/3" />
                    <Skeleton className="h-3 w-1/2" />
                    <Skeleton className="h-3 w-3/5" />
                  </div>
                )}
                {evidenceError && (
                  <EmptyState tone="danger" size="compact" title="证据链读取失败" hint={evidenceError} />
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
                  <p className="text-xs text-sev-medium-fg">
                    该组事件较多，仅列出前 100 条证据（完整数据在 ES 索引里）
                  </p>
                )}

                {evidence && evidence.stages.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {evidence.stages.map((st, i) => (
                      <div key={i} className="rounded-xs bg-surface-1 p-2 text-xs">
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
                    <details key={`${it.ref}-${i}`} className="rounded-xs bg-surface-1 p-2 text-xs">
                      <summary className="cursor-pointer">
                        <span className="font-mono text-xs text-muted-foreground">
                          {it.ts ? formatDateTime(it.ts) : "时间未知"}
                        </span>
                        {" | "}
                        {it.event_type || it.kind}
                        {it.src ? ` | ${it.src} → ${it.dst}` : ""}
                        {it.hit_rule ? ` | ${ruleText(it.hit_rule)}` : ""}
                        {it.edge_score !== null && it.edge_score !== undefined
                          ? ` | 分 ${it.edge_score}`
                          : ""}
                        {it.stages?.length ? (
                          <span className="ml-1 text-primary">［{it.stages.join("·")}］</span>
                        ) : null}
                        {it.error ? <span className="ml-1 text-sev-critical-fg">（{it.error}）</span> : null}
                      </summary>
                      <div className="mt-1 space-y-1">
                        {it.note && <p className="text-xs text-sev-medium-fg">{it.note}</p>}
                        {it.summary && <p className="text-muted-foreground">{it.summary}</p>}
                        <p className="font-mono text-xs text-muted-foreground">
                          证据引用 {it.ref || "-"}
                          {it.source_system ? ` · 来源 ${it.source_system}` : ""}
                          {it.protocol ? ` · ${it.protocol}` : ""}
                        </p>
                        <pre className="max-h-56 overflow-auto rounded-xs border border-border-subtle bg-card p-2 text-xs">
                          {JSON.stringify(it.raw ?? {}, null, 2)}
                        </pre>
                      </div>
                    </details>
                  ))}
                  {evidence && !evidence.items.length && (
                    <EmptyState size="compact" title="无证据" hint="该组还没有可引用的原始记录" />
                  )}
                </div>
              </Section>

              {detail.attack_chain?.case_id && (
                <Section title="自主取证调查">
                  <p className="text-13">
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
                    <p className="text-xs text-sev-medium-fg">
                      未解缺口 {(detail.attack_chain.gaps || []).length} 处（案件页可下追问指令）
                    </p>
                  )}
                </Section>
              )}

              <Section title="处置建议">
                {(detail.response_suggestions || []).map((s, i) => (
                  <p key={i} className="text-13">
                    [{s.category}] {s.action}: {s.detail}
                  </p>
                ))}
                {!detail.response_suggestions?.length && (
                  <EmptyState size="compact" title="无处置建议" hint="深度分析未产出建议时为空" />
                )}
              </Section>

              <Section
                title={`关联事件（共 ${detail.events?.length ?? 0} 条，显示前 50）`}
              >
                {(detail.events || []).slice(0, 50).map((e) => (
                  <p key={e.id} className="font-mono text-xs tabular-nums text-muted-foreground">
                    {formatDateTime(e.ts)} | {e.event_type} | {e.src_ip} → {e.dst_ip}
                    {e.hit_rule ? ` | ${ruleText(e.hit_rule)}` : ""}
                    {e.excluded ? " | 已排除" : ""}
                  </p>
                ))}
              </Section>
            </div>
          )}
        </Drawer>

        {/* 批量删除确认：标题给数量，正文逐条写清「会删什么、不会删什么」 */}
        <Dialog
          open={askDel}
          title={`删除选中的 ${picked.length} 个事件组？`}
          onClose={() => setAskDel(false)}
          footer={
            <div className="flex items-center justify-end gap-2">
              <Button size="sm" variant="outline" onClick={() => setAskDel(false)}>
                取消
              </Button>
              <Button size="sm" variant="destructive" onClick={() => void removePicked()}>
                删除
              </Button>
            </div>
          }
        >
          <ul className="space-y-1.5 text-13 leading-relaxed text-muted-foreground">
            <li>会删除：事件组本身，连带其事件与报告。</li>
            <li>保留：ES 里的原始日志仍可按时间检索。</li>
          </ul>
        </Dialog>
      </main>
    </div>
  );
}
