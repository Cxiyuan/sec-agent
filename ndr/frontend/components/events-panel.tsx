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
  cn,
  errorText,
  formatClock,
  formatDateTime,
  formatShort,
  ruleText,
  severityText,
} from "@shentong/ui";
import { RotateCcw, RotateCw, Search } from "lucide-react";

import { PanelError, emptyOrFailed, usePanelErrors } from "@/components/panel-error";
import { hitTrendOption } from "@/components/event-charts";
import {
  EMPTY_HIT_FORM,
  SRC,
  actionErrorText,
  bodyErrorText,
  buildHitsQuery,
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
} from "@/lib/hits";

/**
 * 事件中心（2026-10 新建）：`/events`，一级菜单，位于资产中心之前。
 *
 * 三个区块 + 两个浮层：
 * - 事件概览（`/api/detector/hits/stats`）：3 Stat + 来源 chips + 趋势图 + TOP 10（可钻取筛选）
 * - 筛选条件：六维度（时间范围/关键字/来源/严重度/事件归类/IP），离散项立即重查、文本项 Enter 提交
 * - 事件列表（`/api/detector/hits`）：8 列整行可点 + offset 分页 + 四象限空态
 * - 详情 Drawer：两段式（行内字段先渲染 → `/hits/{id}` 补证据）+ 忽略/加白处置
 *
 * 与日志检索页同构是硬要求：筛选区三段式、控件 class、分页算法、Drawer 容器、骨架与空态
 * 组件全部与 `logs-panel.tsx` 同源；已知的 4 处故意差异见 UX 规范 §13（离散筛选立即生效、
 * 键盘入口、处置错误位置、越界文案）。
 */

/** 时间范围四档（Q-A 裁决：无「不限」——后端 minutes=0 会被静默改成 1440，UI 不能承诺表达不了的口径） */
const TIME_RANGES: Array<[number, string]> = [
  [60, "最近 1 小时"],
  [360, "最近 6 小时"],
  [1440, "最近 24 小时"],
  [10080, "最近 7 天"],
];

const PAGE_SIZES = [20, 50, 100, 200];

/** 事件来源三类：值与后端 `SOURCE_LABELS` 的 key 对应（精确匹配，只认这三个），标签与后端中文名一致 */
const SOURCE_KINDS: Array<[string, string]> = [
  ["feature_match", "特征匹配"],
  ["behavior_analysis", "行为分析"],
  ["baseline_deviation", "基线偏离"],
];

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

/** 窗口分钟数 → 概览标题里的中文档位（趋势卡标题随窗口变） */
const WINDOW_LABEL: Record<number, string> = {
  60: "1 小时",
  360: "6 小时",
  1440: "24 小时",
  10080: "7 天",
};

/**
 * 表格列定义（顺序即展示顺序，与运营中心原表一致）。
 *
 * 两类宽度写法（视觉规范 6.1，混用会静默失效）：
 * - 固定列（时间/ID/来源/严重度/次数）：宽度类写在 `headCls`（`th`）——`td` 上的 `w-*`
 *   会被内容优先权覆盖，只有 `th` 上的宽度在自动布局里稳定成立；
 * - 截断列（事件归类/请求方/目的）：`min-w-0` 与 `max-w-*` 必须同在 `cellCls`（`td`）——
 *   单元格默认 `min-width: auto`，长字符串会把列顶宽，光写 `max-w`/`truncate` 不咬。
 * 窄屏藏列（`sr-only` 不用 `hidden`，读屏不能丢列）：类名 `th` 与 `td` **同时写**——
 * `sr-only` 是 position:absolute 抽离文档流，只藏 `td` 的话表头还占着一列，窄屏会看到
 * 一列有头无数据的空列。
 */
const COLUMNS: Array<{
  key: string;
  label: string;
  headCls: string;
  cellCls: string;
}> = [
  { key: "last_seen", label: "最近时间", headCls: "w-[6rem]", cellCls: "whitespace-nowrap" },
  {
    key: "id",
    label: "事件 ID",
    headCls: "w-[5.5rem] max-lg:sr-only",
    cellCls: "max-lg:sr-only font-mono text-xs text-muted-foreground",
  },
  { key: "rule", label: "事件归类", headCls: "", cellCls: "min-w-0 max-w-[20rem]" },
  {
    key: "source",
    label: "来源",
    headCls: "w-[5.5rem] max-lg:sr-only",
    cellCls: "max-lg:sr-only",
  },
  { key: "severity", label: "严重度", headCls: "w-[4.5rem]", cellCls: "" },
  { key: "client", label: "请求方", headCls: "", cellCls: "min-w-0 max-w-[9rem]" },
  { key: "count", label: "次数", headCls: "w-[4rem] text-right", cellCls: "text-right tabular-nums" },
  {
    key: "dst",
    label: "目的（IP:端口）",
    headCls: "max-md:sr-only",
    cellCls: "max-md:sr-only min-w-0 max-w-[24rem] truncate text-muted-foreground",
  },
];

const fmt = (n: number) => n.toLocaleString("zh-CN");

/**
 * 详情抽屉的字段网格（UX §7.4：与运营中心原表逐行对齐，一条不增一条不减）。
 * 两条特殊分支原样保留：
 * - 请求方：`client || src_ip` 优先（中继链路上 src_ip 是代理/WAF 自己），`via` 拼「（经 {via}）」，
 *   `client_source === "xff"` 时给 title 说明来自可信代理头；
 * - 连接状态：`conn_states` 空且 `log_types` 含 `suricata` 时说「不适用」，否则说「未记录」——
 *   两者不是一回事（签名引擎告警不带连接状态）。
 */
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

/** 列内容：四条从运营中心保留的既有逻辑不许丢（视觉规范 6.2） */
function renderCell(key: string, row: HitEventItem): React.ReactNode {
  switch (key) {
    case "last_seen":
      return formatShort(row.last_seen || row.created_at);
    case "id":
      return <span title={row.id}>{row.id.slice(0, 8)}</span>;
    case "rule":
      return (
        <span className="flex min-w-0 items-center gap-1">
          <span className="truncate" title={ruleText(row.rule)}>
            {ruleText(row.rule) || "—"}
          </span>
          {row.ignored ? (
            <Badge variant="outline" className="shrink-0">
              已忽略
            </Badge>
          ) : null}
          {row.whitelist_id ? (
            <Badge variant="outline" className="shrink-0">
              已加白
            </Badge>
          ) : null}
        </span>
      );
    case "source":
      return row.source_label || "—";
    case "severity":
      return severityBadge(row.severity);
    case "client":
      // 真实请求方优先：中继链路上 src_ip 是代理/WAF 自己；「经谁」与「谁发起」必须分行
      return (
        <>
          <span
            className="block truncate"
            title={row.client_source === "xff" ? "来自可信代理头（XFF/X-Real-IP）" : "直连对端"}
          >
            {row.client || row.src_ip || "—"}
          </span>
          {row.via ? (
            <span
              className="block truncate text-xs text-muted-foreground"
              title={`这一跳经过 ${row.via}（代理/中继），它不是发起方`}
            >
              经 {row.via}
            </span>
          ) : null}
        </>
      );
    case "count":
      return row.count;
    case "dst":
      // dst_pairs 是 IP:端口 成对存的；超过 3 个给总数，不无限撑宽列
      return row.dst_pairs?.length
        ? row.dst_pairs.slice(0, 3).join("、") +
            (row.dst_pairs.length > 3 ? ` 等 ${row.dst_pairs.length} 个` : "")
        : "—";
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
  /** 详情抽屉里打开的那条（先渲染行内字段，再被 /hits/{id} 的整体返回值替换） */
  const [detail, setDetail] = React.useState<HitEventItem | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);
  /** 处置进行中：Drawer 两按钮 + 确认 Dialog 的确认按钮同时 disabled */
  const [busy, setBusy] = React.useState(false);
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [scope, setScope] = React.useState<"src" | "src_dst">("src");
  /** 页面级消息槽（成功 role=status / 失败 role=alert，与 PanelError 同区互斥） */
  const [msg, setMsg] = React.useState<{ kind: "ok" | "err"; text: string } | null>(null);
  /** 处置失败 additionally 内联到 Drawer footer 上方（B1：用户正盯着抽屉，页面级红字在背后看不见） */
  const [drawerErr, setDrawerErr] = React.useState<string | null>(null);
  /** 数据时间：每次成功取数的时刻（北京时间），新鲜度判断权还给用户 */
  const [updatedAt, setUpdatedAt] = React.useState<number | null>(null);
  const listRef = React.useRef<HTMLDivElement>(null);

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

  /**
   * 重取。`opts.form` 给「离散筛选立即重查」用——setForm 是异步的，直接 `setForm(x); run(0)`
   * 会让 run 用上一帧的表单（stale closure），查询与界面不一致。显式传下一帧表单。
   * `opts.stats === false` = 翻页/失败重取：只动列表，概览口径不变。
   */
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

  // 首次进来直接查一次（默认最近 24 小时 / 不含已忽略 / 最近在前），让人一打开就看到东西
  React.useEffect(() => {
    void run(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** 离散筛选变更：算下一帧表单 → 立即重查（UX §13 D1：日志页「改完不点搜索不生效」是 bug） */
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
   * 打开详情：**必须再拉一次详情接口** —— 列表按设计不带证据（`_rows_to_dict` 只在
   * detail=True 时输出 evidence），直接把列表行塞进抽屉会显示「这条命中没有留下样例事件」
   * （2026-10 用户反馈，运营中心原注释随迁移保留）。两段式：行内字段先渲染，不空白等待。
   */
  const openDetail = React.useCallback(async (row: HitEventItem) => {
    setDrawerErr(null);
    setScope("src");
    setDetail(row);
    setDetailLoading(true);
    try {
      const full = await apiFetch<HitEventItem>(`/api/detector/hits/${row.id}`);
      if (full?.error) {
        setDrawerErr(`读取详情失败：${full.error}`);
        return;
      }
      setDetail(full);
    } catch (e) {
      setDrawerErr(
        e instanceof ApiError ? `读取详情失败：${errorText(e.body)}` : "读取详情失败",
      );
    } finally {
      setDetailLoading(false);
    }
  }, []);

  /**
   * 处置：忽略（过确认 Dialog）/ 加白（不确认，可撤）。
   * 成功：关两个浮层 + 页面级消息 + 全量重取 + 焦点落列表容器（不回页面顶部）。
   * 失败：不关 Drawer，错误内联在 footer 上方；重取列表让列表说真话（404 = 行真的没了）。
   * 不做乐观更新：写操作的真相只能来自重取（UX §6.5）。
   */
  const act = React.useCallback(
    async (kind: "ignore" | "whitelist") => {
      if (!detail) return;
      setBusy(true);
      setDrawerErr(null);
      try {
        const out = await apiFetch<{ ok?: boolean; error?: string; name?: string }>(
          `/api/detector/hits/${detail.id}/${kind}`,
          { method: "POST", body: JSON.stringify(kind === "whitelist" ? { scope } : { reason: "" }) },
        );
        if (out.error) {
          const text = bodyErrorText(out.error);
          setDrawerErr(text);
          setMsg({ kind: "err", text });
          await run(offset, { stats: false });
          return;
        }
        const text =
          kind === "ignore"
            ? ignoreOkText(detail.id)
            : whitelistOkText(out.name ?? "", detail, scope);
        setConfirmOpen(false);
        setDetail(null);
        setDrawerErr(null);
        setMsg({ kind: "ok", text });
        await run(offset);
        listRef.current?.focus();
      } catch (e) {
        const text = actionErrorText(e);
        setDrawerErr(text);
        setMsg({ kind: "err", text });
        await run(offset, { stats: false });
      } finally {
        setBusy(false);
      }
    },
    [detail, scope, offset, run],
  );

  const items = list?.items ?? [];
  const total = list?.total ?? 0;
  const page = Math.floor(offset / form.size) + 1;
  const pages = Math.max(1, Math.ceil(total / form.size));
  // 首帧：列表与概览都未返回且无失败才算首帧；刷新时两者必有一个在，永不走骨架（UX §12.3）
  const firstLoad = !list && !stats && !errs.has;
  // 越界态（第五空态）：查询成功、total>0、本页空 —— 别说成「没有符合条件的事件」
  const outOfRange = !!list && total > 0 && items.length === 0;

  // 高危及以上 = by_severity 里 high + critical（后端 label 是英文 key，只用 key 匹配）
  const sevCount = (key: string) =>
    stats?.by_severity?.find((g) => g.key === key)?.count ?? 0;
  const crit = sevCount("critical");
  const high = sevCount("high");
  const trend = stats?.trend ?? [];
  const topRules = stats?.top_rules ?? [];

  return (
    <div className="space-y-6">
      <PanelError errors={errs} />

      {/* 消息槽：成功/失败同一个位置、互斥 */}
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

      {/* ---------- 一、事件概览：回答「这段时间 overall 什么情况」，只钻取不做处置 ---------- */}
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

            {/* 来源三类 chips：全量渲染（count=0 也置灰可点），选中三信号不只靠颜色 */}
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
                      "rounded-full border px-2 py-0.5 text-xs transition-colors motion-reduce:transition-none",
                      active
                        ? "border-primary bg-brand-50 text-primary"
                        : "border-border-subtle text-muted-foreground hover:border-primary/50 hover:text-foreground",
                      n === 0 && !active && "opacity-60",
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

              {/* TOP 10 列表卡（不是横条图）：行是原生 button，键盘与焦点环免费获得 */}
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

      {/* ---------- 二、筛选条件：表单态与查询态分离，离散项立即生效、文本项 Enter 提交 ---------- */}
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
              {loading ? "刷新中…" : "刷新"}
            </Button>
          </div>
        }
      >
        <Card>
          <CardContent className="space-y-2 pt-4">
            {/* 主行：时间范围 + 关键字（唯一能搜进证据的维度） */}
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-xs text-muted-foreground">
                时间范围
                <select
                  value={form.minutes}
                  onChange={(e) => applyForm({ minutes: Number(e.target.value) })}
                  className="mt-1 block h-9 rounded-sm border border-input bg-surface-2 px-2 text-sm text-foreground"
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

            {/* 字段网格：来源 / 严重度 / 事件归类 / IP */}
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <label className="text-xs text-muted-foreground">
                来源
                <select
                  value={form.sourceKind}
                  onChange={(e) => applyForm({ sourceKind: e.target.value })}
                  className="mt-1 block h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-sm text-foreground"
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
                  className="mt-1 block h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-sm text-foreground"
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

            {/* 操作行：搜索 / 重置 / 排序 / 包含已忽略（每页在列表区，与页码同一组决策） */}
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={() => void run(0)} disabled={loading}>
                <Search className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                {loading ? "查询中…" : "搜索"}
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
                  className="ml-1 h-8 rounded-sm border border-input bg-surface-2 px-2 text-sm text-foreground"
                >
                  {SORTS.map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              {/* 「包含已忽略」切的是查询口径（业务语义），不是控件开合 —— 用 checkbox 不用 Switch */}
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

      {/* ---------- 三、事件列表：整行可点，四象限空态，offset 分页 ---------- */}
      <Section
        title="事件列表"
        extra={
          <div
            className="flex flex-wrap items-center gap-2 text-xs tabular-nums text-muted-foreground"
            aria-live="polite"
          >
            <span>
              共 {total} 条{form.includeIgnored ? "（含已忽略）" : ""}
            </span>
            <label className="flex items-center gap-1">
              每页
              <select
                className="h-8 rounded-sm border border-input bg-surface-2 px-2 text-sm text-foreground"
                value={form.size}
                onChange={(e) => applyForm({ size: Number(e.target.value) })}
              >
                {PAGE_SIZES.map((n) => (
                  <option key={n} value={n}>
                    {n} 条
                  </option>
                ))}
              </select>
            </label>
            <span>
              第 {page} / {pages} 页
            </span>
            <Button
              size="sm"
              variant="outline"
              disabled={offset <= 0 || loading}
              onClick={() => void run(Math.max(0, offset - form.size), { stats: false })}
            >
              上一页
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={offset + form.size >= total || loading}
              onClick={() => void run(offset + form.size, { stats: false })}
            >
              下一页
            </Button>
          </div>
        }
      >
        {/* tabIndex=-1 的容器：处置成功后焦点落这里（刚点的那行可能已消失，不回页面顶部） */}
        <div ref={listRef} tabIndex={-1} className="outline-none">
          <Card>
            <CardContent className="p-0" aria-busy={loading || undefined}>
              {firstLoad ? (
                <TableSkeleton rows={10} cols={8} />
              ) : items.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      {COLUMNS.map((col) => (
                        <TableHead key={col.key} scope="col" className={col.headCls}>
                          {col.label}
                        </TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((row) => (
                      <TableRow
                        key={row.id}
                        tabIndex={0}
                        className="cursor-pointer"
                        onClick={() => void openDetail(row)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            void openDetail(row);
                          }
                        }}
                        aria-label={`事件详情：${ruleText(row.rule)}，请求方 ${row.client || row.src_ip || "未知"}，${severityText(row.severity)}，${row.count} 次`}
                      >
                        {COLUMNS.map((col) => (
                          <TableCell
                            key={col.key}
                            className={col.cellCls}
                            title={
                              col.key === "last_seen"
                                ? formatDateTime(row.last_seen || row.created_at)
                                : col.key === "dst"
                                  ? row.dst_pairs?.join("、")
                                  : undefined
                            }
                          >
                            {renderCell(col.key, row)}
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

      {/* ---------- 详情抽屉：两段式数据（行内字段先渲染 → /hits/{id} 补证据） ---------- */}
      <Drawer
        open={!!detail}
        onClose={() => {
          setDetail(null);
          setDrawerErr(null);
        }}
        widthClass="w-[560px] max-w-[94vw]"
        title={
          /* 标题节点用 span 而不是 div/p：Drawer 把 title 放进 <h2>，块级元素套在标题里不合语法
             （logs-panel.tsx 的同一处注释）。主标题是事件归类，扫一眼就知道是哪一类。 */
          <span className="flex min-w-0 flex-col">
            <span className="truncate text-sm font-medium">
              {detail ? ruleText(detail.rule) : ""}
            </span>
            <span className="truncate font-mono text-xs font-normal text-muted-foreground">
              {detail?.id} · {detail?.source_label}
            </span>
          </span>
        }
        footer={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() =>
                void navigator.clipboard?.writeText(JSON.stringify(detail, null, 2))
              }
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
            {/* R2：风险完全不对等的一句话，必须出现在 UI 上 */}
            <span className="text-xs text-muted-foreground">
              只放行该规则的这一来源，不是全放行
            </span>
          </div>
        }
      >
        {detail ? (
          <div className="space-y-3" aria-busy={detailLoading || undefined}>
            {/* 处置失败内联在这里（footer 上方），不是页面级 —— B1 */}
            {drawerErr ? (
              <p role="alert" className="text-xs text-sev-critical-fg">
                {drawerErr}
              </p>
            ) : null}

            {/* 字段网格：与运营中心原表逐行对齐；break-all 不 truncate —— 560px 放得下，值要能复制 */}
            <div className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
              {detailFieldRows(detail).map(([label, value, mono]) => (
                <p key={label} className="flex gap-1">
                  <span className="shrink-0 text-muted-foreground">{label}：</span>
                  <span className={cn("min-w-0 break-all", mono && "font-mono")}>{value}</span>
                </p>
              ))}
            </div>

            {/* 事件内容（证据区）：等宽有助于同一字段在多条样例间纵向对齐 */}
            <div>
              <p className="mb-2 text-13 font-medium">事件内容</p>
              {detailLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-3" />
                  ))}
                </div>
              ) : detail.evidence?.length ? (
                <div className="space-y-2">
                  {detail.evidence.map((ev, i) => {
                    const at = ev["ts"] ?? ev["timestamp"];
                    return (
                      /* L1 内联格：底色成组，不描边（与 Stat、呼吸灯格同一种容器语言） */
                      <div key={i} className="rounded-xs bg-surface-1 px-3 py-2">
                        <div className="mb-1.5 text-xs text-muted-foreground">
                          样例 {i + 1}
                          {at !== undefined && at !== null ? ` · ${eventTime(at)}` : ""}
                          {ev["source"] ? ` · 来源 ${String(ev["source"])}` : ""}
                        </div>
                        <div className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
                          {Object.entries(ev)
                            .filter(([k]) => !hiddenFields.has(k))
                            .map(([k, v]) => (
                              <div key={k} className="flex gap-1 text-xs">
                                <span className="shrink-0 text-muted-foreground">
                                  {fieldLabel(k)}：
                                </span>
                                <span className="min-w-0 break-all font-mono">{String(v)}</span>
                              </div>
                            ))}
                        </div>
                        {Array.isArray(ev["other_fields"]) && ev["other_fields"].length ? (
                          <div className="mt-1.5 text-xs text-muted-foreground">
                            其它字段：
                            {(ev["other_fields"] as string[]).map((k) => fieldLabel(k)).join("、")}
                          </div>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">这条命中没有留下样例事件</p>
              )}
            </div>
          </div>
        ) : null}
      </Drawer>

      {/* ---------- 确认忽略：不可逆操作（无取消端点）必须停一下；加白可逆，不确认 ---------- */}
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
        {detail ? (
          <p className="mt-2 text-xs text-muted-foreground">
            即将忽略：
            <span className="font-mono">{detail.id.slice(0, 8)}</span>
            {" · "}
            {ruleText(detail.rule)}
          </p>
        ) : null}
      </Dialog>
    </div>
  );
}

export default EventsPanel;
