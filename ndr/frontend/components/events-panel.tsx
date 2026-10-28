"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Chart,
  Dialog,
  Drawer,
  EmptyState,
  Input,
  Pagination,
  Section,
  Skeleton,
  Stat,
  StatSkeleton,
  ChartSkeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
  apiFetch,
  ApiError,
  agentVerdictText,
  cn,
  errorText,
  formatClock,
  formatDateTime,
  formatShort,
  ruleText,
  severityText,
} from "@shentong/ui";
import { ChevronRight, RotateCcw, RotateCw, Search } from "lucide-react";

import { PanelError, emptyOrFailed, usePanelErrors } from "@/components/panel-error";
import { hitTrendOption } from "@/components/event-charts";
import {
  EMPTY_HIT_FORM,
  IP_SUBLIST_PAGE,
  SRC,
  actionErrorText,
  aggregateByIp,
  agentVerdictBadge,
  bodyErrorText,
  buildHitsQuery,
  buildIpEventsQuery,
  eventTime,
  fieldLabel,
  hiddenFields,
  ignoreOkText,
  severityBadge,
  statsMinutes,
  whitelistOkText,
  type HitEventItem,
  type HitEventStats,
  type HitEventList,
  type HitForm,
  type IpAggRow,
} from "@/lib/hits";

/**
 * 事件中心（2026-10 新建）：`/events`，一级菜单，位于资产中心之前。
 *
 * 三个区块 + 两个浮层（与日志检索页同构：筛选区 / 控件 / 分页 / Drawer / 骨架 / 空态同源）：
 * - 事件概览（`/api/detector/hits/stats`）：3 Stat + 来源 chips + 趋势图 + TOP 10（可钻取筛选）
 * - 筛选条件：六维度（离散项立即重查、文本项 Enter 提交）
 * - 事件列表（`/api/detector/hits`）：**以主机 IP 为中心聚合**——同一 `client` 的多条命中收成一行，
 *   事件类型/来源/归类均多条聚合、次数以 `（数字）` 跟随；事件 ID 不进主列表；首现顺序稳定；
 *   主页按事件级 offset 分页。
 * - 详情抽屉：点 IP 行打开，先给聚合摘要，下面是「该 IP 的命中事件」——嵌入侧栏的**固定窗口滚动
 *   列表栏 + 客户端分页**；每行可展开看单个事件的字段与证据，并就地忽略 / 加白。
 */

/** 时间范围四档（无「不限」——后端 minutes=0 会被静默改成 1440，UI 不能承诺表达不了的口径） */
const TIME_RANGES: Array<[number, string]> = [
  [60, "最近 1 小时"],
  [360, "最近 6 小时"],
  [1440, "最近 24 小时"],
  [10080, "最近 7 天"],
];

/** 事件来源三类：值与后端 `SOURCE_LABELS` 的 key 对应（精确匹配），标签与后端中文名一致 */
const SOURCE_KINDS: Array<[string, string]> = [
  ["feature_match", "特征匹配"],
  ["behavior_analysis", "行为分析"],
  ["baseline_deviation", "基线偏离"],
];

/**
 * 来源三类配色（2026-10 复刻深信服：类型标签走**紫 / 青 / 品红**，刻意避开严重度的
 * 红橙金蓝绿 —— 否则「中危」和「基线偏离」两个金/黄标签在列表里会读成同一件事）。
 * 样式与严重度徽章同构：浅底 + 深字 + 同色系 1px 描边。
 */
const SRC_TONE: Record<string, string> = {
  feature_match: "border-src-feature-bd bg-src-feature-bg text-src-feature-fg",
  behavior_analysis: "border-src-behavior-bd bg-src-behavior-bg text-src-behavior-fg",
  baseline_deviation: "border-src-baseline-bd bg-src-baseline-bg text-src-baseline-fg",
};

/** 列表 / 抽屉里的来源来自后端 `source_label`（是中文），只能按中文取色。 */
const SRC_LABEL_TONE: Record<string, string> = Object.fromEntries(
  SOURCE_KINDS.map(([key, label]) => [label, SRC_TONE[key]])
);

/** 一个来源名的小徽章（列表「来源」列与抽屉共用） */
function SourceChip({ label }: { label: string }) {
  return (
    <span
      className={cn(
        "whitespace-nowrap rounded-xs border px-1.5 py-0.5 text-xs",
        SRC_LABEL_TONE[label] ?? "border-border-subtle text-muted-foreground"
      )}
    >
      {label}
    </span>
  );
}

/** 严重度：值必须小写英文（后端 == 精确匹配）；文案与共享库 `severityText` 同源 */
const SEVERITIES: Array<[string, string]> = [
  ["critical", "严重"],
  ["high", "高危"],
  ["medium", "中危"],
  ["low", "低危"],
  ["info", "信息"],
];

const SORTS: Array<[HitForm["sort"], string]> = [
  ["recent", "最近发生在前"],
  ["oldest", "最早发生在前"],
  ["count", "按命中次数"],
];

/** 窗口分钟数 → 概览标题里的中文档位 */
const WINDOW_LABEL: Record<number, string> = {
  60: "1 小时",
  360: "6 小时",
  1440: "24 小时",
  10080: "7 天",
};

/**
 * 主列表列定义（IP 中心视图）。
 * 宽列写法与事件中心原 8 列表一致（视觉规范 6.1）：固定列宽度写在 `headCls`（`th`），
 * 截断列 `min-w-0 + max-w` 同在 `cellCls`（`td`）。
 */
const IP_COLUMNS: Array<{
  key: string;
  label: string;
  headCls: string;
  cellCls: string;
}> = [
  { key: "ip", label: "主机 IP", headCls: "", cellCls: "" },
  {
    key: "types",
    label: "事件类型（次数）",
    headCls: "",
    cellCls: "min-w-0 max-w-[22rem]",
  },
  { key: "sources", label: "来源", headCls: "w-[8rem]", cellCls: "" },
  {
    key: "agent",
    label: "智能体结论",
    headCls: "w-[14rem]",
    cellCls: "min-w-0",
  },
  { key: "severity", label: "严重度", headCls: "w-[5rem]", cellCls: "" },
  { key: "hits", label: "命中次数", headCls: "w-[5rem] text-right", cellCls: "text-right tabular-nums" },
  {
    key: "events",
    label: "事件数",
    headCls: "w-[4rem] text-right",
    cellCls: "text-right tabular-nums text-muted-foreground",
  },
  { key: "last_seen", label: "最近", headCls: "w-[6rem] whitespace-nowrap", cellCls: "whitespace-nowrap" },
];

const fmt = (n: number) => n.toLocaleString("zh-CN");

/**
 * 聚合后的「事件类型（次数）」：类型名 + `（次数）`，最多 3 类、超出给「等 N 类」。
 * 例子：`Web 攻击（12） / 端口扫描（3） 等 5 类`。
 */
function AggTypes({ parts, className }: { parts: Array<[string, number]>; className?: string }) {
  const MAX = 3;
  const shown = parts.slice(0, MAX);
  const overflow = parts.length - shown.length;
  return (
    <span
      className={cn("block truncate", className)}
      title={parts.map(([t, c]) => `${t}（${c}）`).join(" / ")}
    >
      {shown.map(([t, c], i) => (
        <span key={t} className="inline">
          {i > 0 ? " / " : ""}
          {t}
          <span className="text-muted-foreground">（{c}）</span>
        </span>
      ))}
      {overflow > 0 ? ` 等 ${parts.length} 类` : ""}
    </span>
  );
}

/** 抽屉里单条命中的字段网格（与运营中心原表逐行对齐，一条不增一条不减） */
function detailFieldRows(detail: HitEventItem): Array<[string, React.ReactNode, boolean]> {
  const rows: Array<[string, React.ReactNode, boolean]> = [
    ["事件 ID", detail.id, true],
    ["规则", ruleText(detail.rule) || "—", false],
    ["来源", detail.source_label || "—", false],
    ["首次", formatDateTime(detail.first_seen), false],
    ["最近", formatDateTime(detail.last_seen), false],
    ["次数", detail.count, false],
    [
      "请求方",
      <span
        title={
          detail.client_source === "xff" ? "来自可信代理头（XFF/X-Real-IP）" : "直连对端"
        }
      >
        {detail.client || detail.src_ip || "—"}
        {detail.via ? `（经 ${detail.via}）` : ""}
      </span>,
      true,
    ],
    ["目的", detail.dst_pairs?.length ? detail.dst_pairs.join("、") : "无", true],
    ["事件类型", detail.event_types?.length ? detail.event_types.join("、") : "无", false],
    [
      "连接状态",
      detail.conn_states?.length
        ? detail.conn_states.join("、")
        : detail.log_types?.includes("suricata")
          ? "不适用（签名引擎告警不带连接状态）"
          : "未记录",
      false,
    ],
  ];
  if (detail.real_client_ips?.length) {
    rows.push(["代理头里的真实客户端", detail.real_client_ips.join("、"), true]);
  }
  if (detail.ignored_reason) {
    rows.push(["处理记录", detail.ignored_reason, false]);
  }
  return rows;
}

/** 主列表单元格：IP 中心视图的四列聚合渲染 */
function renderIpCell(key: string, row: IpAggRow): React.ReactNode {
  switch (key) {
    case "ip":
      return (
        <span className="flex min-w-0 items-center gap-1">
          <span className="truncate font-mono text-13" title={row.ip}>
            {row.ip}
          </span>
          {row.ignored > 0 ? (
            <Badge variant="outline" className="shrink-0">
              已忽略 {row.ignored}
            </Badge>
          ) : null}
        </span>
      );
    case "types":
      return (
        <span className="flex min-w-0 items-center gap-1">
          <AggTypes parts={row.eventTypeCounts} />
          {row.via ? (
            <span
              className="shrink-0 truncate text-xs text-muted-foreground"
              title={`这一跳经过 ${row.via}（代理/中继），它不是发起方`}
            >
              经 {row.via}
            </span>
          ) : null}
        </span>
      );
    case "sources":
      // 三类各有固定色：扫"来源"这一列时先看到色块再读字，跟上面的筛选 chips 同一套色
      return row.sourceCounts.length ? (
        <span
          className="flex flex-wrap items-center gap-1"
          title={row.sourceCounts.map(([s]) => s).join(" / ")}
        >
          {row.sourceCounts.map(([label]) => (
            <SourceChip key={label} label={label} />
          ))}
        </span>
      ) : (
        <span className="text-muted-foreground">—</span>
      );
    case "agent": {
      // 智能体结论是判定权威来源（NDR 规则判定只是初判）：徽章给结论态，
      // 摘要正文给智能体的分析内容本身——这一列读的是「智能体说了什么」，
      // 而不只是规则命中描述。整个 IP 都没结论时显示「—」，不给误导性空徽章。
      if (!row.agentStatuses.length && !row.latestAgentSummary) {
        return (
          <span className="text-muted-foreground" title="智能体尚未返回结论">
            —
          </span>
        );
      }
      return (
        <span className="flex min-w-0 flex-col gap-0.5">
          {row.agentStatuses.length ? (
            <span
              className="flex flex-wrap items-center gap-1"
              title={row.agentStatuses.map((s) => agentVerdictText(s)).join(" / ")}
            >
              {row.agentStatuses.slice(0, 3).map((s) => (
                <React.Fragment key={s}>{agentVerdictBadge(s)}</React.Fragment>
              ))}
              {row.agentStatuses.length > 3 ? (
                <span className="text-xs text-muted-foreground">
                  等 {row.agentStatuses.length} 种
                </span>
              ) : null}
            </span>
          ) : null}
          {row.latestAgentSummary ? (
            <span className="block truncate text-13" title={row.latestAgentSummary}>
              {row.latestAgentSummary}
            </span>
          ) : null}
        </span>
      );
    }
    case "severity":
      // 判定权威在智能体：有 agent_severity 显示智能体严重度，否则回退检测器 severity，
      // 悬停注明是「NDR 初判」还是「智能体结论」，两种口径在界面上分得开
      return severityBadge(
        row.effectiveMaxSeverity,
        row.sevFromAgent ? "智能体结论严重度" : "NDR 初判（智能体尚未给出严重度）",
      );
    case "hits":
      return row.totalHits;
    case "events":
      return row.eventCount;
    case "last_seen":
      return formatShort(row.lastSeen);
    default:
      return null;
  }
}

export function EventsPanel() {
  const errs = usePanelErrors();
  const [form, setForm] = React.useState<HitForm>({ ...EMPTY_HIT_FORM });
  const [offset, setOffset] = React.useState(0);
  const [list, setList] = React.useState<HitEventList | null>(null);
  const [stats, setStats] = React.useState<HitEventStats | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [updatedAt, setUpdatedAt] = React.useState<number | null>(null);
  const listRef = React.useRef<HTMLDivElement>(null);

  // ---------- 抽屉（IP 维度）状态 ----------
  const [detailIp, setDetailIp] = React.useState<string | null>(null);
  /** 该 IP 下的全部命中事件（一次性拉到上限，子列表再客户端分页） */
  const [ipRows, setIpRows] = React.useState<HitEventItem[]>([]);
  const [ipTotal, setIpTotal] = React.useState(0);
  const [ipLoading, setIpLoading] = React.useState(false);
  /** 子列表客户端分页游标（在 ipRows 内切片） */
  const [ipOffset, setIpOffset] = React.useState(0);
  /** 展开的那条单事件（看字段 + 证据 + 就地处置） */
  const [expanded, setExpanded] = React.useState<HitEventItem | null>(null);
  const [expandedLoading, setExpandedLoading] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [scope, setScope] = React.useState<"src" | "src_dst">("src");
  const [msg, setMsg] = React.useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [drawerErr, setDrawerErr] = React.useState<string | null>(null);

  const fetchList = React.useCallback(
    async (nextOffset: number, f: HitForm) => {
      const res = await apiFetch<HitEventList>(
        `/api/detector/hits?${buildHitsQuery(f, nextOffset)}`,
      ).catch(() => null);
      if (res) {
        errs.clear(SRC.list);
        setList(res);
        setOffset(nextOffset);
        setUpdatedAt(Date.now());
      } else {
        errs.fail(SRC.list);
      }
    },
    [errs],
  );

  const fetchStats = React.useCallback(
    async (minutes: number) => {
      const res = await apiFetch<HitEventStats>(
        `/api/detector/hits/stats?minutes=${minutes}`,
      ).catch(() => null);
      if (res) {
        errs.clear(SRC.stats);
        setStats(res);
        setUpdatedAt(Date.now());
      } else {
        errs.fail(SRC.stats);
      }
    },
    [errs],
  );

  const run = React.useCallback(
    async (nextOffset = 0, opts: { form?: HitForm; stats?: boolean } = {}) => {
      const f = opts.form ?? form;
      setLoading(true);
      await Promise.all([
        fetchList(nextOffset, f),
        opts.stats === false ? Promise.resolve() : fetchStats(statsMinutes(f)),
      ]);
      setLoading(false);
    },
    [form, fetchList, fetchStats],
  );

  React.useEffect(() => {
    void run(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** 离散筛选变更：算下一帧表单 → 立即重查 */
  const applyForm = (patch: Partial<HitForm>) => {
    const next = { ...form, ...patch };
    setForm(next);
    void run(0, { form: next });
  };

  const reset = () => {
    const next = { ...EMPTY_HIT_FORM };
    setForm(next);
    void run(0, { form: next });
  };

  /**
   * 打开某 IP 的抽屉：拉该 IP 在窗口内的全部命中（上限 IP_FETCH_LIMIT），用于聚合摘要 +
   * 子列表客户端分页。子列表分页不额外请求，只在已拉取的数据里切片。
   */
  const openIp = React.useCallback(
    async (row: IpAggRow) => {
      setDrawerErr(null);
      setExpanded(null);
      setScope("src");
      setDetailIp(row.ip);
      setIpLoading(true);
      try {
        const res = await apiFetch<HitEventList>(
          `/api/detector/hits?${buildIpEventsQuery(form, row.ip, 0)}`,
        ).catch(() => null);
        if (res) {
          setIpRows(res.items ?? []);
          setIpTotal(res.total ?? 0);
          setIpOffset(0);
        } else {
          setIpRows([]);
          setIpTotal(0);
        }
      } finally {
        setIpLoading(false);
      }
    },
    [form],
  );

  const closeIp = React.useCallback(() => {
    setDetailIp(null);
    setIpRows([]);
    setIpTotal(0);
    setIpOffset(0);
    setExpanded(null);
    setDrawerErr(null);
    setConfirmOpen(false);
  }, []);

  /** 展开 / 收起单条事件：展开时再拉一次详情接口补证据（列表按设计不带 evidence） */
  const toggleExpand = React.useCallback(
    async (ev: HitEventItem) => {
      if (expanded?.id === ev.id) {
        setExpanded(null);
        setDrawerErr(null);
        return;
      }
      setExpanded(ev);
      setExpandedLoading(true);
      setDrawerErr(null);
      try {
        const full = await apiFetch<HitEventItem>(`/api/detector/hits/${ev.id}`).catch(() => null);
        if (full?.error) {
          setDrawerErr(`读取详情失败：${full.error}`);
          return;
        }
        setExpanded(full ?? ev);
      } catch (e) {
        setDrawerErr(
          e instanceof ApiError ? `读取详情失败：${errorText(e.body)}` : "读取详情失败",
        );
      } finally {
        setExpandedLoading(false);
      }
    },
    [expanded],
  );

  /**
   * 处置：忽略（过确认 Dialog）/ 加白（不确认，可撤）。针对当前展开的那条单事件。
   * 成功：关浮层 + 页面级消息 + 重拉该 IP 列表（反映忽略/加白）+ 重拉概览计数。
   * 失败：错误内联在抽屉 footer 上方；重拉该 IP 列表让列表说真话。
   */
  const act = React.useCallback(
    async (kind: "ignore" | "whitelist") => {
      if (!expanded || !detailIp) return;
      setBusy(true);
      setDrawerErr(null);
      try {
        const out = await apiFetch<{ ok?: boolean; error?: string; name?: string }>(
          `/api/detector/hits/${expanded.id}/${kind}`,
          {
            method: "POST",
            body: JSON.stringify(kind === "whitelist" ? { scope } : { reason: "" }),
          },
        ).catch(() => null);
        if (!out) {
          const text = "操作失败：服务暂时不可用，可稍后再试";
          setDrawerErr(text);
          setMsg({ kind: "err", text });
          return;
        }
        if (out.error) {
          const text = bodyErrorText(out.error);
          setDrawerErr(text);
          setMsg({ kind: "err", text });
          await openIp({ ip: detailIp } as IpAggRow);
          return;
        }
        const text =
          kind === "ignore"
            ? ignoreOkText(expanded.id)
            : whitelistOkText(out.name ?? "", expanded, scope);
        setConfirmOpen(false);
        setExpanded(null);
        setDrawerErr(null);
        setMsg({ kind: "ok", text });
        await openIp({ ip: detailIp } as IpAggRow);
        await fetchStats(statsMinutes(form));
      } catch (e) {
        const text = actionErrorText(e);
        setDrawerErr(text);
        setMsg({ kind: "err", text });
        await openIp({ ip: detailIp } as IpAggRow);
      } finally {
        setBusy(false);
      }
    },
    [expanded, scope, detailIp, form, openIp, fetchStats],
  );

  const items = list?.items ?? [];
  // 主列表按主机 IP 聚合（插入序 = 首现顺序，不重排）
  const aggRows = React.useMemo(() => aggregateByIp(items), [items]);
  const total = list?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / form.size));

  const firstLoad = !list && !stats && !errs.has;
  const outOfRange = !!list && total > 0 && items.length === 0;

  const sevCount = (key: string) =>
    stats?.by_severity?.find((g) => g.key === key)?.count ?? 0;
  const crit = sevCount("critical");
  const high = sevCount("high");
  const trend = stats?.trend ?? [];
  const topRules = stats?.top_rules ?? [];

  // 抽屉子列表：在已拉取的 ipRows 内客户端分页
  const ipPageSize = IP_SUBLIST_PAGE;
  const ipPageCount = Math.max(1, Math.ceil(ipRows.length / ipPageSize));
  const ipPageNo = Math.floor(ipOffset / ipPageSize) + 1;
  const ipSlice = ipRows.slice(ipOffset, ipOffset + ipPageSize);
  const ipSummary = ipRows.length ? aggregateByIp(ipRows)[0] : null;

  const ipPrev = () => setIpOffset((o) => Math.max(0, o - ipPageSize));
  const ipNext = () =>
    setIpOffset((o) => Math.min(Math.max(0, ipRows.length - ipPageSize), o + ipPageSize));

  return (
    <div className="space-y-6">
      <PanelError errors={errs} />

      {msg ? (
        <p
          role={msg.kind === "ok" ? "status" : "alert"}
          className={cn(
            "rounded-xs border px-3 py-2 text-xs",
            msg.kind === "ok"
              ? "border-sev-ok-bd bg-sev-ok-bg text-sev-ok-fg"
              : "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg",
          )}
        >
          {msg.text}
        </p>
      ) : null}

      {/* ---------- 一、事件概览 ---------- */}
      <Section
        title="事件概览"
        description={
          <>
            统计窗口随下方时间范围变化；总数不含已忽略；点来源或规则可按它筛选。
            {updatedAt ? ` · 数据时间 ${formatClock(updatedAt)}` : ""}
          </>
        }
      >
        {firstLoad ? (
          <div className="space-y-3">
            <StatSkeleton count={3} />
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardContent className="pt-3">
                  <ChartSkeleton height={224} />
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle>事件归类 TOP 10</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-1.5">
                    {Array.from({ length: 10 }).map((_, i) => (
                      <Skeleton key={i} className="h-3" />
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <Stat
                label="事件总数"
                value={stats ? fmt(stats.total) : "—"}
                hint="窗口内 · 不含已忽略"
              />
              <Stat
                label="高危及以上"
                value={stats ? fmt(crit + high) : "—"}
                tone="high"
                hint={`严重 ${fmt(crit)} · 高危 ${fmt(high)}`}
              />
              <Stat
                label="已忽略"
                value={stats ? fmt(stats.ignored) : "—"}
                hint="默认列表不显示 · 勾选『包含已忽略』可查"
              />
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-muted-foreground">按来源：</span>
              {SOURCE_KINDS.map(([key, label]) => {
                const n = stats?.by_source_kind?.find((g) => g.key === key)?.count ?? 0;
                const active = form.sourceKind === key;
                return (
                  <button
                    key={key}
                    type="button"
                    aria-pressed={active}
                    onClick={() => applyForm({ sourceKind: active ? "" : key })}
                    className={cn(
                      // 未选中保持中性灰（它是筛选器），选中才亮出该类自己的语义色 ——
                      // 这样"当前在看哪一类"和"这类是什么颜色"是同一件事，不用两处对照。
                      "rounded-full border px-2 py-0.5 text-xs transition-colors motion-reduce:transition-none",
                      active
                        ? SRC_TONE[key] ?? "border-primary bg-brand-50 text-primary"
                        : "border-border-subtle text-muted-foreground hover:border-border hover:text-foreground",
                    )}
                  >
                    {label} · {fmt(n)}
                  </button>
                );
              })}
            </div>

            <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardHeader className="pb-2">
                  <CardTitle className="flex flex-wrap items-center gap-2">
                    近 {WINDOW_LABEL[form.minutes] ?? "24 小时"}命中
                    <span className="text-xs font-normal text-muted-foreground">
                      每桶一条数 · 悬停看桶长
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {trend.length ? (
                    <Chart
                      option={hitTrendOption(trend, stats?.bucket_seconds ?? 600)}
                      height={224}
                    />
                  ) : (
                    <EmptyState
                      size="compact"
                      tone="muted"
                      title={emptyOrFailed(errs, SRC.stats, "窗口内没有事件")}
                    />
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="flex flex-wrap items-center gap-2">
                    事件归类 TOP 10
                    <span className="text-xs font-normal text-muted-foreground">点一行按它筛选</span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {topRules.length ? (
                    <div className="divide-y divide-border-subtle">
                      {topRules.map((it) => (
                        <button
                          key={it.rule}
                          type="button"
                          onClick={() => applyForm({ rule: it.rule })}
                          className="flex w-full items-center gap-2 px-1 py-1.5 text-left transition-colors hover:bg-brand-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 motion-reduce:transition-none"
                        >
                          <span
                            className="min-w-0 flex-1 truncate text-13"
                            title={ruleText(it.rule)}
                          >
                            {ruleText(it.rule)}
                          </span>
                          <span className="shrink-0 text-13 tabular-nums text-muted-foreground">
                            {fmt(it.count)}
                          </span>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <EmptyState
                      size="compact"
                      tone="muted"
                      title={emptyOrFailed(errs, SRC.stats, "窗口内没有事件")}
                    />
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        )}
      </Section>

      {/* ---------- 二、筛选条件 ---------- */}
      <Section
        title="筛选条件"
        extra={
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs tabular-nums text-muted-foreground">
              数据时间 {updatedAt ? formatClock(updatedAt) : "—"}
            </span>
            <Button
              size="sm"
              variant="outline"
              disabled={loading}
              onClick={() => void run(offset)}
            >
              <RotateCw className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
              {loading ? "加载中…" : "刷新"}
            </Button>
          </div>
        }
      >
        <Card>
          <CardContent className="space-y-2 pt-4">
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-xs text-muted-foreground">
                时间范围
                <select
                  value={form.minutes}
                  onChange={(e) => applyForm({ minutes: Number(e.target.value) })}
                  className="mt-1 block h-9 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                >
                  {TIME_RANGES.map(([m, label]) => (
                    <option key={m} value={m}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="min-w-[260px] flex-1 text-xs text-muted-foreground">
                关键字（IP / 账号 / URI / UA / 证据全文）
                <Input
                  value={form.q}
                  onChange={(e) => setForm({ ...form, q: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void run(0);
                  }}
                  placeholder="唯一能搜进证据的维度"
                  className="mt-1"
                />
              </label>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <label className="text-xs text-muted-foreground">
                来源
                <select
                  value={form.sourceKind}
                  onChange={(e) => applyForm({ sourceKind: e.target.value })}
                  className="mt-1 block h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                >
                  <option value="">全部来源</option>
                  {SOURCE_KINDS.map(([key, label]) => (
                    <option key={key} value={key}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-muted-foreground">
                严重度
                <select
                  value={form.severity}
                  onChange={(e) => applyForm({ severity: e.target.value })}
                  className="mt-1 block h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                >
                  <option value="">全部严重度</option>
                  {SEVERITIES.map(([key, label]) => (
                    <option key={key} value={key}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-muted-foreground">
                事件归类
                <Input
                  value={form.rule}
                  onChange={(e) => setForm({ ...form, rule: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void run(0);
                  }}
                  placeholder="事件归类名，如：Web 应用攻击"
                  className="mt-1"
                />
              </label>
              <label className="text-xs text-muted-foreground">
                IP
                <Input
                  value={form.ip}
                  onChange={(e) => setForm({ ...form, ip: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void run(0);
                  }}
                  placeholder="请求方 / 中继 / 目的 IP 片段"
                  className="mt-1"
                />
              </label>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={() => void run(0)} disabled={loading}>
                <Search className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                {loading ? "加载中…" : "搜索"}
              </Button>
              <Button size="sm" variant="outline" onClick={reset} disabled={loading}>
                <RotateCcw className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                重置
              </Button>
              <label className="text-xs text-muted-foreground">
                排序
                <select
                  value={form.sort}
                  onChange={(e) => applyForm({ sort: e.target.value as HitForm["sort"] })}
                  className="ml-1 h-8 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                >
                  {SORTS.map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex items-center gap-1 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  checked={form.includeIgnored}
                  onChange={(e) => applyForm({ includeIgnored: e.target.checked })}
                />
                包含已忽略
              </label>
            </div>
          </CardContent>
        </Card>
      </Section>

      {/* ---------- 三、事件列表（IP 中心聚合） ---------- */}
      <Section
        title="事件列表（按主机 IP 聚合）"
        help="命中的安全事件与处置状态，点击行可展开详情"
        extra={
          <div className="flex flex-wrap items-center gap-3" aria-live="polite">
            <Pagination
              page={Math.floor(offset / form.size)}
              pages={pages}
              total={total}
              size={form.size}
              onPage={(p) => void run(p * form.size, { stats: false })}
              onSize={(n) => applyForm({ size: n })}
              disabled={loading}
            />
            <span className="text-xs tabular-nums text-muted-foreground">
              本页聚合 {aggRows.length} 个主机 IP
            </span>
          </div>
        }
      >
        <div ref={listRef} tabIndex={-1} className="outline-none">
          <Card>
            <CardContent className="p-0" aria-busy={loading || undefined}>
              {firstLoad ? (
                <TableSkeleton rows={10} cols={8} />
              ) : aggRows.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10 select-none text-center">#</TableHead>
                      {IP_COLUMNS.map((col) => (
                        <TableHead key={col.key} scope="col" className={col.headCls}>
                          {col.label}
                        </TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {aggRows.map((row, i) => (
                      <TableRow
                        key={row.ip}
                        tabIndex={0}
                        className="cursor-pointer"
                        onClick={() => void openIp(row)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            void openIp(row);
                          }
                        }}
                        aria-label={`主机 ${row.ip}，${severityText(row.effectiveMaxSeverity)}，共 ${row.totalHits} 次命中、${row.eventCount} 个事件，点开看该 IP 的全部命中`}
                      >
                        <TableCell className="w-10 select-none text-center tabular-nums text-muted-foreground">
                          {offset + i + 1}
                        </TableCell>
                        {IP_COLUMNS.map((col) => (
                          <TableCell key={col.key} className={col.cellCls}>
                            {renderIpCell(col.key, row)}
                          </TableCell>
                        ))}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : errs.isFailed(SRC.list) ? (
                <EmptyState
                  title="事件列表读取失败"
                  hint="点『重试』重新读取；后端异常或网络不通时，页面上的数字可能不是最新状态"
                  tone="danger"
                  action={
                    <Button size="sm" variant="outline" onClick={() => void run(0)}>
                      重试
                    </Button>
                  }
                />
              ) : outOfRange ? (
                <EmptyState
                  title="这一页的事件已不在当前口径内"
                  hint="可能刚被忽略或清理。回到第一页重新看。"
                  tone="muted"
                  action={
                    <Button size="sm" variant="outline" onClick={() => void run(0)}>
                      回到第一页
                    </Button>
                  }
                />
              ) : (
                <EmptyState
                  title="没有符合条件的事件"
                  hint="放宽时间范围，或清除部分筛选条件"
                  tone="muted"
                  action={
                    <Button size="sm" variant="outline" onClick={reset}>
                      清除筛选
                    </Button>
                  }
                />
              )}
            </CardContent>
          </Card>
        </div>
      </Section>

      {/* ---------- 详情抽屉：IP 聚合摘要 + 该 IP 命中事件（固定窗口滚动 + 分页） ---------- */}
      <Drawer
        open={!!detailIp}
        onClose={closeIp}
        widthClass="w-[600px] max-w-[94vw]"
        title={
          <span className="flex min-w-0 flex-col">
            <span className="truncate font-mono text-sm font-medium">
              {detailIp}
            </span>
            <span className="truncate text-xs font-normal text-muted-foreground">
              主机维度聚合 · 窗口内共 {fmt(ipTotal)} 条命中
            </span>
          </span>
        }
        footer={
          expanded
            ? (
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => void navigator.clipboard?.writeText(JSON.stringify(expanded, null, 2))}
                >
                  复制事件 JSON
                </Button>
                <Button size="sm" variant="outline" disabled={busy} onClick={() => setConfirmOpen(true)}>
                  忽略这条
                </Button>
                <select
                  aria-label="白名单范围"
                  className="h-7 rounded-md border bg-transparent px-2 text-xs"
                  value={scope}
                  disabled={busy}
                  onChange={(e) => setScope(e.target.value as "src" | "src_dst")}
                >
                  <option value="src">白名单：同源 + 同规则</option>
                  <option value="src_dst">白名单：同源 + 同规则 + 同目的</option>
                </select>
                <Button size="sm" disabled={busy} onClick={() => void act("whitelist")}>
                  加入白名单
                </Button>
                <span className="text-xs text-muted-foreground">
                  只放行该规则的这一来源，不是全放行
                </span>
              </div>
            )
            : undefined
        }
      >
        {detailIp ? (
          <div className="space-y-3">
            {drawerErr ? (
              <p role="alert" className="text-xs text-sev-critical-fg">
                {drawerErr}
              </p>
            ) : null}

            {ipLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-3" />
                ))}
              </div>
            ) : ipRows.length ? (
              <>
                {/* IP 聚合摘要（来自该 IP 全部命中） */}
                {ipSummary ? (
                  <div className="rounded-xs border border-border-subtle bg-surface-1 p-3">
                    <p className="mb-2 text-13 font-medium">聚合摘要</p>
                    <div className="grid grid-cols-1 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-2">
                      <p className="flex gap-1">
                        <span className="shrink-0 text-muted-foreground">主机 IP：</span>
                        <span className="min-w-0 break-all font-mono">{ipSummary.ip}</span>
                      </p>
                      <p className="flex gap-1">
                        <span className="shrink-0 text-muted-foreground">最高严重度：</span>
                        {severityBadge(
                          ipSummary.effectiveMaxSeverity,
                          ipSummary.sevFromAgent
                            ? "智能体结论严重度"
                            : "NDR 初判（智能体尚未给出严重度）",
                        )}
                      </p>
                      <p className="flex gap-1">
                        <span className="shrink-0 text-muted-foreground">总命中次数：</span>
                        <span className="tabular-nums">{fmt(ipSummary.totalHits)}</span>
                      </p>
                      <p className="flex gap-1">
                        <span className="shrink-0 text-muted-foreground">事件数：</span>
                        <span className="tabular-nums">{ipSummary.eventCount}</span>
                      </p>
                      <p className="flex gap-1">
                        <span className="shrink-0 text-muted-foreground">首次：</span>
                        <span>{formatDateTime(ipSummary.firstSeen)}</span>
                      </p>
                      <p className="flex gap-1">
                        <span className="shrink-0 text-muted-foreground">最近：</span>
                        <span>{formatDateTime(ipSummary.lastSeen)}</span>
                      </p>
                    </div>
                    <div className="mt-2 space-y-1 text-xs">
                      <p className="flex gap-1">
                        <span className="shrink-0 text-muted-foreground">事件类型：</span>
                        <span className="min-w-0 break-words">
                          {ipSummary.eventTypeCounts.length
                            ? ipSummary.eventTypeCounts
                                .map(([t, c]) => `${t}（${c}）`)
                                .join(" / ")
                            : "无"}
                        </span>
                      </p>
                      <p className="flex gap-1">
                        <span className="shrink-0 text-muted-foreground">事件归类：</span>
                        <span className="min-w-0 break-words">
                          {ipSummary.ruleCounts.length
                            ? ipSummary.ruleCounts.map(([r]) => ruleText(r)).join(" / ")
                            : "无"}
                        </span>
                      </p>
                      <p className="flex gap-1">
                        <span className="shrink-0 text-muted-foreground">来源：</span>
                        <span className="flex flex-wrap items-center gap-1">
                          {ipSummary.sourceCounts.length ? (
                            ipSummary.sourceCounts.map(([label]) => (
                              <SourceChip key={label} label={label} />
                            ))
                          ) : (
                            <span>无</span>
                          )}
                        </span>
                      </p>
                    </div>
                    {/* 智能体结论概览（判定权威来源）：该 IP 最近一条智能体分析正文 */}
                    {ipSummary.latestAgentSummary ? (
                      <div className="mt-2 rounded-xs bg-surface-2 px-3 py-2">
                        <p className="mb-1 flex flex-wrap items-center gap-2 text-xs">
                          <span className="font-medium">智能体结论（最新）</span>
                          {ipSummary.agentStatuses.map((s) => (
                            <React.Fragment key={s}>{agentVerdictBadge(s)}</React.Fragment>
                          ))}
                        </p>
                        <p className="whitespace-pre-wrap break-words text-xs">
                          {ipSummary.latestAgentSummary}
                        </p>
                      </div>
                    ) : (
                      <p className="mt-2 text-xs text-muted-foreground">
                        智能体尚未返回结论；以上严重度为 NDR 初判。
                      </p>
                    )}
                  </div>
                ) : null}

                {/* 该 IP 的命中事件：嵌入侧栏的固定窗口滚动列表 + 客户端分页 */}
                <div>
                  <p className="mb-1.5 flex items-center justify-between text-13 font-medium">
                    <span>该 IP 的命中事件</span>
                    <span className="text-xs font-normal text-muted-foreground">
                      第 {ipPageNo} / {ipPageCount} 页（共 {ipRows.length} 条）
                    </span>
                  </p>
                  <div className="max-h-[360px] overflow-y-auto rounded-xs border border-border-subtle">
                    {ipSlice.map((ev) => {
                      const open = expanded?.id === ev.id;
                      return (
                        <div key={ev.id} className="border-b border-border-subtle last:border-b-0">
                          <button
                            type="button"
                            onClick={() => void toggleExpand(ev)}
                            aria-expanded={open}
                            className={cn(
                              "flex w-full items-center gap-2 px-2 py-2 text-left transition-colors hover:bg-brand-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 motion-reduce:transition-none",
                              open && "bg-brand-50",
                            )}
                          >
                            <ChevronRight
                              className={cn(
                                "h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
                                open && "rotate-90",
                              )}
                              aria-hidden="true"
                            />
                            <span
                              className="shrink-0 font-mono text-xs text-muted-foreground"
                              title={ev.id}
                            >
                              {ev.id.slice(0, 10)}
                            </span>
                            <span className="min-w-0 flex-1 truncate text-13" title={ruleText(ev.rule)}>
                              {ruleText(ev.rule) || "—"}
                            </span>
                            {/* 智能体结论是判定权威来源：有结论先亮结论徽章，紧跟严重度 */}
                            {agentVerdictBadge(ev.agent_status)}
                            {severityBadge(
                              ev.agent_severity || ev.severity,
                              ev.agent_severity
                                ? "智能体结论严重度"
                                : "NDR 初判（智能体尚未给出严重度）",
                            )}
                            <span className="shrink-0 text-13 tabular-nums text-muted-foreground">
                              {fmt(ev.count)}
                            </span>
                            <span className="hidden shrink-0 text-xs text-muted-foreground whitespace-nowrap sm:inline">
                              {formatShort(ev.last_seen)}
                            </span>
                            {ev.ignored ? (
                              <Badge variant="outline" className="shrink-0">
                                已忽略
                              </Badge>
                            ) : null}
                            {ev.whitelist_id ? (
                              <Badge variant="outline" className="shrink-0">
                                已加白
                              </Badge>
                            ) : null}
                          </button>
                          {open ? (
                            <div className="space-y-3 bg-surface-1 px-3 py-3">
                              {drawerErr ? (
                                <p role="alert" className="text-xs text-sev-critical-fg">
                                  {drawerErr}
                                </p>
                              ) : null}
                              {expandedLoading ? (
                                <div className="space-y-2">
                                  {Array.from({ length: 4 }).map((_, i) => (
                                    <Skeleton key={i} className="h-3" />
                                  ))}
                                </div>
                              ) : expanded ? (
                                <>
                                  <div className="grid grid-cols-1 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-2">
                                    {detailFieldRows(expanded).map(([label, value, mono]) => (
                                      <p key={label} className="flex gap-1">
                                        <span className="shrink-0 text-muted-foreground">
                                          {label}：
                                        </span>
                                        <span className={cn("min-w-0 break-all", mono && "font-mono")}>
                                          {value}
                                        </span>
                                      </p>
                                    ))}
                                  </div>
                                  {/* 智能体分析结论（判定权威来源）：无结论给轻量空态，不用错误样式 */}
                                  <div>
                                    <p className="mb-2 text-13 font-medium">智能体分析结论</p>
                                    {expanded.agent_status || expanded.agent_summary ? (
                                      <div className="space-y-2 rounded-xs bg-surface-2 px-3 py-2">
                                        <div className="flex flex-wrap items-center gap-2">
                                          {agentVerdictBadge(expanded.agent_status) ?? (
                                            <span className="text-xs text-muted-foreground">
                                              未给出结论状态
                                            </span>
                                          )}
                                          {expanded.agent_severity
                                            ? severityBadge(
                                                expanded.agent_severity,
                                                "智能体结论严重度",
                                              )
                                            : null}
                                          {expanded.agent_updated_at ? (
                                            <span className="text-xs text-muted-foreground">
                                              分析时间 {formatDateTime(expanded.agent_updated_at)}
                                            </span>
                                          ) : null}
                                        </div>
                                        {expanded.agent_summary ? (
                                          <p className="whitespace-pre-wrap break-words text-xs">
                                            {expanded.agent_summary}
                                          </p>
                                        ) : null}
                                        {expanded.agent_detail &&
                                        Object.keys(expanded.agent_detail).length ? (
                                          <div className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
                                            {Object.entries(expanded.agent_detail).map(
                                              ([k, v]) => (
                                                <div key={k} className="flex gap-1 text-xs">
                                                  <span className="shrink-0 text-muted-foreground">
                                                    {k}：
                                                  </span>
                                                  <span className="min-w-0 break-all font-mono">
                                                    {typeof v === "string" ? v : JSON.stringify(v)}
                                                  </span>
                                                </div>
                                              ),
                                            )}
                                          </div>
                                        ) : null}
                                      </div>
                                    ) : (
                                      <EmptyState
                                        size="compact"
                                        tone="muted"
                                        title="智能体尚未返回结论"
                                        hint="结论由智能体分析后写回；当前严重度为 NDR 初判。"
                                      />
                                    )}
                                  </div>
                                  <div>
                                    <p className="mb-2 text-13 font-medium">事件内容</p>
                                    {expanded.evidence?.length ? (
                                      <div className="space-y-2">
                                        {expanded.evidence.map((ev2, i) => {
                                          const at = ev2["ts"] ?? ev2["timestamp"];
                                          return (
                                            <div key={i} className="rounded-xs bg-surface-2 px-3 py-2">
                                              <div className="mb-1.5 text-xs text-muted-foreground">
                                                样例 {i + 1}
                                                {at !== undefined && at !== null
                                                  ? ` · ${eventTime(at)}`
                                                  : ""}
                                                {ev2["source"]
                                                  ? ` · 来源 ${String(ev2["source"])}`
                                                  : ""}
                                              </div>
                                              <div className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
                                                {Object.entries(ev2)
                                                  .filter(([k]) => !hiddenFields.has(k))
                                                  .map(([k, v]) => (
                                                    <div key={k} className="flex gap-1 text-xs">
                                                      <span className="shrink-0 text-muted-foreground">
                                                        {fieldLabel(k)}：
                                                      </span>
                                                      <span className="min-w-0 break-all font-mono">
                                                        {String(v)}
                                                      </span>
                                                    </div>
                                                  ))}
                                              </div>
                                              {Array.isArray(ev2["other_fields"]) &&
                                              ev2["other_fields"].length ? (
                                                <div className="mt-1.5 text-xs text-muted-foreground">
                                                  其它字段：
                                                  {(ev2["other_fields"] as string[])
                                                    .map((k) => fieldLabel(k))
                                                    .join("、")}
                                                </div>
                                              ) : null}
                                            </div>
                                          );
                                        })}
                                      </div>
                                    ) : (
                                      <p className="text-xs text-muted-foreground">
                                        这条命中没有留下样例事件
                                      </p>
                                    )}
                                  </div>
                                </>
                              ) : null}
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                  </div>
                  {/* 子列表分页（客户端切片，不额外请求） */}
                  <div className="mt-2 flex flex-wrap items-center justify-end gap-2 text-xs text-muted-foreground">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={ipOffset <= 0}
                      onClick={ipPrev}
                    >
                      上一页
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={ipOffset + ipPageSize >= ipRows.length}
                      onClick={ipNext}
                    >
                      下一页
                    </Button>
                  </div>
                </div>
              </>
            ) : (
              <EmptyState
                size="compact"
                tone="muted"
                title="这个 IP 在窗口内没有命中事件"
                hint="可能刚被全部忽略；勾选『包含已忽略』后重新打开。"
              />
            )}
          </div>
        ) : null}
      </Drawer>

      {/* ---------- 确认忽略 ---------- */}
      <Dialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="确认忽略这条事件？"
        footer={
          <div className="flex justify-end gap-2">
            <Button size="sm" variant="outline" disabled={busy} onClick={() => setConfirmOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={busy} aria-busy={busy} onClick={() => void act("ignore")}>
              确认忽略
            </Button>
          </div>
        }
      >
        <p className="text-xs text-muted-foreground">
          忽略后，这条事件从默认列表消失；忽略不可逆（没有取消端点），勾选『包含已忽略』可查回。
          如果是某条规则的持续误报，更稳妥的做法是「加入白名单」——它落在配置管理 → 过滤规则，可停用可删除。
        </p>
        {expanded ? (
          <p className="mt-2 text-xs text-muted-foreground">
            即将忽略：
            <span className="font-mono">{expanded.id.slice(0, 8)}</span>
            {" · "}
            {ruleText(expanded.rule)}
          </p>
        ) : null}
      </Dialog>
    </div>
  );
}

export default EventsPanel;
