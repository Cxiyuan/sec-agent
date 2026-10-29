"use client";

import * as React from "react";
import { Trash2 } from "lucide-react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Dialog,
  Drawer,
  EmptyState,
  Field,
  Input,
  Pagination,
  Section,
  Skeleton,
  Stat,
  StatSkeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
  ApiError,
  apiFetch,
  errorText,
  formatDateTime,
} from "@shentong/ui";

import { PanelError, emptyOrFailed, loadInto, usePanelErrors } from "@/components/panel-error";
import { displayName, useAliases } from "@/lib/aliases";
import type {
  AlertDisposition,
  AssetListPayload,
  BaselineConfigItem,
  BaselineConfigPayload,
  BaselinePayload,
  BaselineProfile,
  BaselineProfilesPayload,
  DispositionListPayload,
  EgressAllowBody,
  EgressAllowItem,
  EgressBaselineItem,
  NumericGroupedPayload,
  NumericStat,
  ObservationStatsPayload,
  ObservationsPayload,
} from "@/lib/api";

/**
 * 行为分析面板（主页面只做展示，配置在右侧抽屉里改）。
 *
 * 三块：
 * 1. **学习进度与检测器心跳**：观测期还剩多久、检测器有没有在落库、当前风险 TOP；
 * 2. **数值基线 IP 列表**：每个 `源IP:维度` 的均值/方差与状态（生效中 / 观测中）；
 * 3. **画像列表**：账号/会话画像的风险、时间与状态（生效中 / 观测中）。
 *
 * 「分析配置」按钮从右侧滑出抽屉改参数 —— 参数清单由后端给（`GET /api/baseline/config`，
 * 带类型/范围/默认值），前端只渲染与提交，新增可调参数不用改这里。
 *
 * 状态口径：
 * - 数值基线：过了观测期（`warmed`）= **生效中**（参与 2σ 判定）；否则 **观测中**（只学习）；
 * - 画像：观测次数达到冷启动门槛（`profile.min_obs`）= **生效中**（已参与打分）；否则 **观测中**。
 */

const SRC = {
  overview: "基线总览",
  config: "可调参数",
  profiles: "画像列表",
  numeric: "数值基线",
  assets: "被访问方基线",
  observations: "基线事实",
  egress: "外连白名单",
} as const;

/** 事实类型词表（与后端 `app/baseline/observations.py::KIND_LABELS` 同源，界面下拉用） */
const OBSERVATION_KINDS: [string, string][] = [
  ["egress_new", "外连目的地首次出现"],
  ["egress_rare", "外连目的地罕见"],
  ["egress_sustained", "外连目的地持续出现"],
  ["geo_jump", "账号登录地点变化"],
  ["login_bruteforce", "账号被多来源尝试登录"],
  ["path_probe", "客户端大量 404"],
  ["conn_shift", "连接数高于自身基线"],
  ["asset_shift", "被访问资产访问量高于自身基线"],
  ["profile_anomaly", "账号或会话画像异常"],
];

/** 外连白名单的目标类型（与后端 `egress.py` 的 KIND_* 同源） */
const EGRESS_KINDS: [string, string][] = [
  ["dst_ip", "目的 IP"],
  ["domain", "域名"],
  ["port", "端口"],
];

const PAGE_SIZE = 20;
const REFRESH_SECONDS = 30;

function topKeys(map: Record<string, number> | undefined, n: number): string[] {
  return Object.entries(map || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([key]) => key);
}

/** 单个 IP 的展示：有别名时「别名（真实 IP）」，没别名就是 IP（真实 IP 永远可见） */
function ipLabel(ip: string): string {
  const name = displayName(ip);
  return name && name !== ip ? `${name}（${ip}）` : ip;
}

/** IP 列表的展示（比 topKeys 多一步别名替换） */
function ipLabels(map: Record<string, number> | undefined, n: number): string {
  return topKeys(map, n).map(ipLabel).join(", ");
}

/**
 * 维度的中文名：后端给的 key 后缀（`conn_count` …）只做展示映射，未知维度回落原名。
 * 筛选下拉也用这份表，避免两处漂移。
 */
const FEATURE_LABELS: Record<string, string> = {
  conn_count: "连接数",
  distinct_dst_ports: "目的端口数",
  distinct_dst_ips: "目的 IP 数",
};

function featureLabel(feature: string): string {
  return FEATURE_LABELS[feature] || feature || "-";
}

/**
 * 维度标签的悬停提示：均值 / 标准差 / 观测次数 / 状态。
 *
 * 用户要求把「均值」「标准差」两列挪进悬停（列表从 3×IP 行降到 1×IP 行，再加两列数字就浪费地方了）。
 */
function featureTip(feature: NumericStat, observeDays: number): string {
  const state = feature.warmed
    ? "生效中（已过观测期，参与 2σ 判定）"
    : feature.count < 2
      ? "观测中（只观测过 1 次，标准差还不可靠）"
      : `观测中（观测期未满 ${observeDays} 天）`;
  return (
    `${featureLabel(feature.feature)}：均值 ${feature.mean} · 标准差 ${feature.std} · 观测 ${feature.count} 次` +
    `\n状态：${state}\n首见 ${formatDateTime(feature.first_seen)}`
  );
}

/** 这个参数在草稿里被改过吗（类型感知的比较）。 */
function changed(item: BaselineConfigItem, draft: Record<string, string | boolean>): boolean {
  const raw = draft[item.key];
  if (raw === undefined) return false;
  if (item.kind === "bool") return Boolean(raw) !== Boolean(item.value);
  return String(raw) !== String(item.value);
}

/**
 * 生效中 / 观测中 —— 两态是运维最关心的区分（这维度/实体现在能不能出判定）。
 *
 * 配色（用户 2026-10 定的口径）：**生效中=绿色、观测中=黄色**。
 * 中途试过「两态统一绿色」，用户看过后要求观测中仍用黄色 —— 黄色表达「还在学习、没到门槛」，
 * 与「已生效」区分开更直观。
 */
function StateBadge({ judging, hint }: { judging: boolean; hint?: string }) {
  return (
    <Badge variant={judging ? "success" : "medium"} title={hint}>
      {judging ? "生效中" : "观测中"}
    </Badge>
  );
}

/** 画像的时段分布：24 格，颜色按次数深浅（一眼看出「只在上班时间活动」这类形态）。 */
function HourBars({ hist }: { hist: Record<string, number> | undefined }) {
  const values = Object.values(hist || {}).map((v) => Number(v) || 0);
  const max = Math.max(1, ...values);
  // 0 次的格子用最浅的描边色当"空槽"（原来是 bg-muted，和展开行的底色撞在一起看不出格子）
  const shades = [
    "bg-border-subtle",
    "bg-primary/30",
    "bg-primary/50",
    "bg-primary/70",
    "bg-primary",
  ];
  return (
    <div className="flex flex-wrap gap-[3px]">
      {Array.from({ length: 24 }, (_, hour) => {
        const count = Number(hist?.[String(hour)] || 0);
        const level = count === 0 ? 0 : Math.min(4, 1 + Math.floor((count / max) * 3));
        return (
          <span
            key={hour}
            title={`${hour} 时：${count} 次`}
            className={`h-4 w-3 rounded-sm ${shades[level]}`}
          />
        );
      })}
    </div>
  );
}

/** 分页条：2026-10 换成共享编号分页（深信服式，见 packages/ui 的 Pagination）。 */
function Pager({
  total,
  page,
  onPage,
}: {
  total: number;
  page: number;
  onPage: (next: number) => void;
}) {
  return (
    <Pagination
      page={page}
      pages={Math.max(1, Math.ceil(total / PAGE_SIZE))}
      total={total}
      onPage={onPage}
    />
  );
}

/** 画像展开后的细节：理由 / 来源 IP / 服务端 IP / UA / 接口路径 / 时段分布。 */
function ProfileDetail({
  row,
  onDispose,
}: {
  row: BaselineProfile;
  onDispose: (row: BaselineProfile) => void;
}) {
  const reasons = row.anomalies || [];
  return (
    <div className="space-y-2 py-1 text-xs">
      {reasons.length ? (
        <div>
          <span className="text-muted-foreground">判定理由：</span>
          {reasons.map((r, i) => (
            <Badge key={i} variant="outline" className="ml-1">
              {r}
            </Badge>
          ))}
        </div>
      ) : (
        <p className="text-muted-foreground">本轮没有异常理由（风险分已归零）。</p>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        <p>
          <span className="text-muted-foreground">来源 IP：</span>
          <span className="font-mono">{ipLabels(row.src_ips, 5) || "-"}</span>
        </p>
        <p>
          <span className="text-muted-foreground">服务端 IP：</span>
          <span className="font-mono">{ipLabels(row.dst_ips, 5) || "-"}</span>
        </p>
      </div>
      <p className="break-all">
        <span className="text-muted-foreground">User-Agent：</span>
        <span className="font-mono">{topKeys(row.user_agents, 2).join(" | ") || "-"}</span>
      </p>
      <p className="break-all">
        <span className="text-muted-foreground">
          接口路径（{Object.keys(row.paths || {}).length}）：
        </span>
        <span className="font-mono">{topKeys(row.paths, 6).join(", ") || "-"}</span>
      </p>
      <div>
        <p className="mb-1 text-muted-foreground">时段分布（0-23 时，次数越多次色越深）</p>
        <HourBars hist={row.hour_hist} />
      </div>
      <p className="text-muted-foreground">
        认证失败 {row.fail_count ?? 0} / 成功 {row.success_count ?? 0} · 错误响应{}
        {row.error_count ?? 0} 次 · 观测 {row.obs_count ?? 0} 条事件 / {row.window_count ?? 0} 个窗口 ·
        首次 {formatDateTime(row.first_seen)} · 最近 {formatDateTime(row.last_seen)}
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-border pt-2">
        <span className="text-muted-foreground">处置：</span>
        <Button size="sm" variant="outline" onClick={() => onDispose(row)}>
          标记误报 / 确认
        </Button>
        <span className="text-xs text-muted-foreground">
          判误报后该实体在 suppress 天内不再参与打分（理由仍保留展示）
        </span>
      </div>
    </div>
  );
}

export function BehaviorPanel() {
  // 展示层别名：画像/基线里出现的 IP 优先显示别名（真实 IP 以括号补在旁边）
  useAliases();
  const errs = usePanelErrors();
  const [overview, setOverview] = React.useState<BaselinePayload | null>(null);
  const [config, setConfig] = React.useState<BaselineConfigPayload | null>(null);
  const [profiles, setProfiles] = React.useState<BaselineProfilesPayload | null>(null);
  const [numeric, setNumeric] = React.useState<NumericGroupedPayload | null>(null);
  const [assets, setAssets] = React.useState<AssetListPayload | null>(null);
  /** 被访问方归属过滤（口径 C）：内网被访问方 = 异常判定的对象；外部目标只展示 */
  const [ascope, setAscope] = React.useState<"" | "internal" | "external">("");
  const [apage, setApage] = React.useState(0);
  const [aq, setAq] = React.useState("");
  const [auto, setAuto] = React.useState(true);
  const [timeRange, setTimeRange] = React.useState("24h");
  const [configOpen, setConfigOpen] = React.useState(false);

  // 画像筛选 / 分页
  const [kind, setKind] = React.useState("account");
  const [minRisk, setMinRisk] = React.useState("0");
  const [pq, setPq] = React.useState("");
  const [ppage, setPpage] = React.useState(0);
  const [expanded, setExpanded] = React.useState("");

  // 数值基线筛选 / 分页
  const [nq, setNq] = React.useState("");
  const [nfeature, setNfeature] = React.useState("");
  const [nsort, setNsort] = React.useState("count");
  const [npage, setNpage] = React.useState(0);

  // 参数草稿（只放用户改过的键）
  const [draft, setDraft] = React.useState<Record<string, string | boolean>>({});
  const [busy, setBusy] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [fieldErrs, setFieldErrs] = React.useState<Record<string, string>>({});

  // 告警处置（disposition）：单条画像打「误报 / 确认」，以及最近的处置记录
  const [dispOpen, setDispOpen] = React.useState(false);
  const [dispTarget, setDispTarget] = React.useState<BaselineProfile | null>(null);
  const [dispVerdict, setDispVerdict] = React.useState<"false_positive" | "confirm">("false_positive");
  const [dispNote, setDispNote] = React.useState("");
  const [dispBusy, setDispBusy] = React.useState(false);
  const [dispMsg, setDispMsg] = React.useState("");
  const [dispList, setDispList] = React.useState<DispositionListPayload | null>(null);
  const [dispListOpen, setDispListOpen] = React.useState(false);
  const [dispListBusy, setDispListBusy] = React.useState(false);

  // 基线事实（observations）：客观观察，没有 severity/verdict，判断权在智能体
  const [obsStats, setObsStats] = React.useState<ObservationStatsPayload | null>(null);
  const [obs, setObs] = React.useState<ObservationsPayload | null>(null);
  const [obsKind, setObsKind] = React.useState("");
  const [obsSubject, setObsSubject] = React.useState("");
  const [obsMinutes, setObsMinutes] = React.useState(1440);
  const [obsPage, setObsPage] = React.useState(0);
  const [obsBusy, setObsBusy] = React.useState(false);

  // 外连目的地与白名单
  const [egressItems, setEgressItems] = React.useState<EgressBaselineItem[] | null>(null);
  const [egressSrcIp, setEgressSrcIp] = React.useState("");
  const [egressKind, setEgressKind] = React.useState("");
  const [allowItems, setAllowItems] = React.useState<EgressAllowItem[] | null>(null);
  const [allowTombstone, setAllowTombstone] = React.useState(false);
  const [allowBusy, setAllowBusy] = React.useState(false);
  const [allowOpen, setAllowOpen] = React.useState(false);
  /** '' = 新增；否则是被编辑条目的 id（编辑时改 kind/value 会覆盖同键） */
  const [allowEditId, setAllowEditId] = React.useState("");
  const [allowForm, setAllowForm] = React.useState<EgressAllowBody>({
    kind: "dst_ip",
    value: "",
    scope: "global",
    asset: "",
    enabled: true,
    note: "",
  });

  const profilesUrl =
    `/api/baseline/profiles?kind=${encodeURIComponent(kind)}` +
    `&q=${encodeURIComponent(pq)}&min_risk=${Number(minRisk) || 0}` +
    `&limit=${PAGE_SIZE}&offset=${ppage * PAGE_SIZE}`;
  // `scope=entity` 显式钉死：只看「源IP:维度」的实体基线。后端另有 `group` 口径返回
  // `grp:{网段}:维度` 的**组先验**（等组池化的内部统计，不是某个 IP 的基线）——混进这个
  // 「按 IP 列」的列表里会让人以为那一行是这个 IP 自己的行为，所以显式带上而不是依赖默认。
  const numericUrl =
    `/api/baseline/numeric?group=ip&scope=entity&q=${encodeURIComponent(nq)}` +
    `&feature=${encodeURIComponent(nfeature)}&sort=${nsort}` +
    `&limit=${PAGE_SIZE}&offset=${npage * PAGE_SIZE}`;
  const assetsUrl =
    `/api/baseline/assets?q=${encodeURIComponent(aq)}` +
    `&scope=${ascope}` +
    `&sort=visits` +
    `&limit=${PAGE_SIZE}&offset=${apage * PAGE_SIZE}`;
  // 事实列表：独立时间窗（默认 24h）与筛选，不跟页面顶部 timeRange 走——事实是排查入口，
  // 用户常在这里看更长窗口；分页 50/页（后端 cap 200）。
  const OBS_PAGE = 50;
  const obsUrl =
    `/api/baseline/observations?kind=${encodeURIComponent(obsKind)}` +
    `&subject=${encodeURIComponent(obsSubject.trim())}` +
    `&minutes=${obsMinutes}&limit=${OBS_PAGE}&offset=${obsPage * OBS_PAGE}`;

  // 白名单/资产外连在 useEffect 里独立加载（不需要每次整页刷新都拉）
  React.useEffect(() => {
    void loadInto(errs, SRC.observations, "/api/baseline/observations/stats?minutes=1440", setObsStats);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    void loadInto(errs, SRC.observations, obsUrl, setObs);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [obsUrl]);

  async function loadEgress() {
    setEgressItems(null);
    const data = await apiFetch<{ items: EgressBaselineItem[] }>(
      `/api/baseline/egress?src_ip=${encodeURIComponent(egressSrcIp.trim())}&kind=${encodeURIComponent(egressKind)}&limit=200`,
    );
    setEgressItems(data.items || []);
  }

  async function loadAllow() {
    setAllowBusy(true);
    try {
      const data = await apiFetch<{ items: EgressAllowItem[] }>(
        `/api/baseline/egress-allow?include_tombstone=${allowTombstone}`,
      );
      setAllowItems(data.items || []);
    } finally {
      setAllowBusy(false);
    }
  }

  React.useEffect(() => {
    void loadAllow();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allowTombstone]);

  async function saveAllow() {
    setAllowBusy(true);
    try {
      const body: EgressAllowBody = { ...allowForm, value: allowForm.value.trim() };
      if (body.scope === "asset" && !body.asset?.trim()) {
        setMsg("scope=资产 时必须填资产 IP");
        return;
      }
      const data = await apiFetch<{ ok: boolean; error?: string }>("/api/baseline/egress-allow", {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (data.ok === false) {
        setMsg(data.error || "保存失败");
        return;
      }
      setMsg("白名单已保存（手工条目，会覆盖同键的自学习条目）");
      setAllowOpen(false);
      void loadAllow();
    } finally {
      setAllowBusy(false);
    }
  }

  async function deleteAllow(item: EgressAllowItem) {
    if (!window.confirm(`删除白名单「${item.value}」？\n删除会留墓碑：这个目标以后不会再被自动学回来（可用「恢复」撤销）。`)) return;
    setAllowBusy(true);
    try {
      await apiFetch(`/api/baseline/egress-allow/${encodeURIComponent(item.id)}`, { method: "DELETE" });
      setMsg("已删除并留墓碑（勾选「含已删除」可看到，可恢复）");
      void loadAllow();
    } finally {
      setAllowBusy(false);
    }
  }

  async function restoreAllow(item: EgressAllowItem) {
    setAllowBusy(true);
    try {
      await apiFetch(`/api/baseline/egress-allow/${encodeURIComponent(item.id)}/restore`, { method: "POST" });
      setMsg("已撤销墓碑：该目标重新允许自学习");
      void loadAllow();
    } finally {
      setAllowBusy(false);
    }
  }

  async function load() {
    errs.reset();
    await Promise.all([
      loadInto(errs, SRC.overview, "/api/baseline?limit=10", setOverview),
      loadInto(errs, SRC.profiles, profilesUrl, setProfiles),
      loadInto(errs, SRC.numeric, numericUrl, setNumeric),
      loadInto(errs, SRC.assets, assetsUrl, setAssets),
    ]);
  }

  function applyConfig(data: BaselineConfigPayload) {
    setConfig(data);
    setDraft({});
    setFieldErrs({});
  }

  async function loadConfig() {
    await loadInto(errs, SRC.config, "/api/baseline/config", applyConfig);
  }

  // ---------- 告警处置（disposition） ----------
  function openDisposition(row: BaselineProfile) {
    setDispTarget(row);
    setDispVerdict("false_positive");
    setDispNote("");
    setDispMsg("");
    setDispOpen(true);
  }

  async function submitDisposition() {
    if (!dispTarget) return;
    const id = dispTarget.entity_key ?? dispTarget.id ?? "";
    if (!id) {
      setDispMsg("缺少实体标识，无法处置");
      return;
    }
    setDispBusy(true);
    setDispMsg("");
    try {
      await apiFetch(`/api/baseline/alerts/${encodeURIComponent(id)}/disposition`, {
        method: "POST",
        body: JSON.stringify({ verdict: dispVerdict, note: dispNote }),
      });
      setDispOpen(false);
      // 误报后该实体在 suppress 天内不再参与打分，风险可能归零 —— 重拉画像与总览
      void loadInto(errs, SRC.profiles, profilesUrl, setProfiles);
      void loadInto(errs, SRC.overview, "/api/baseline", setOverview);
    } catch (e) {
      setDispMsg(e instanceof ApiError ? errorText(e.body) : "处置失败");
    } finally {
      setDispBusy(false);
    }
  }

  async function openDispositionList() {
    setDispListOpen(true);
    setDispListBusy(true);
    try {
      const data = await apiFetch<DispositionListPayload>(
        "/api/baseline/alerts/dispositions?limit=50",
      );
      setDispList(data);
    } catch (e) {
      setDispList({
        items: [],
        limit: 50,
        error: e instanceof ApiError ? errorText(e.body) : "读取失败",
      });
    } finally {
      setDispListBusy(false);
    }
  }

  React.useEffect(() => {
    void load();
    void loadConfig();
    // 只在挂载时取一次；节奏交给下面的定时器
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 筛选/翻页变化时只重取对应表
  React.useEffect(() => {
    void loadInto(errs, SRC.profiles, profilesUrl, setProfiles);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profilesUrl]);

  React.useEffect(() => {
    void loadInto(errs, SRC.numeric, numericUrl, setNumeric);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [numericUrl]);

  React.useEffect(() => {
    void loadInto(errs, SRC.assets, assetsUrl, setAssets);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [assetsUrl]);

  React.useEffect(() => {
    if (!auto) return;
    const timer = setInterval(() => {
      void loadInto(errs, SRC.overview, "/api/baseline", setOverview);
      void loadInto(errs, SRC.profiles, profilesUrl, setProfiles);
      void loadInto(errs, SRC.numeric, numericUrl, setNumeric);
      void loadInto(errs, SRC.assets, assetsUrl, setAssets);
    }, REFRESH_SECONDS * 1000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, profilesUrl, numericUrl]);

  async function save() {
    if (!config) return;
    setBusy(true);
    setMsg("");
    setFieldErrs({});
    const values: Record<string, string | number | boolean> = {};
    for (const item of config.items) {
      if (!changed(item, draft)) continue;
      const raw = draft[item.key];
      values[item.key] =
        item.kind === "bool"
          ? Boolean(raw)
          : item.kind === "int"
            ? Math.trunc(Number(raw))
            : item.kind === "float"
              ? Number(raw)
              : String(raw);
    }
    if (Object.keys(values).length === 0) {
      setBusy(false);
      setMsg("没有改动");
      return;
    }
    try {
      const data = await apiFetch<BaselineConfigPayload>("/api/baseline/config", {
        method: "PUT",
        body: JSON.stringify({ values }),
      });
      applyConfig(data);
      setMsg(
        `已保存 ${data.written ?? 0} 项 —— 检测器下一个窗口（≤ ${overview?.flush_seconds ?? 60} 秒）就用新值`,
      );
      void load();
    } catch (e) {
      if (e instanceof ApiError) {
        const body = e.body as { field_errors?: { field: string; msg: string }[] } | undefined;
        const map: Record<string, string> = {};
        for (const fe of body?.field_errors ?? []) map[fe.field] = fe.msg;
        setFieldErrs(map);
        setMsg(errorText(e.body));
      } else {
        setMsg("保存失败");
      }
    } finally {
      setBusy(false);
    }
  }

  async function resetConfig(keys: string[]) {
    setBusy(true);
    setMsg("");
    try {
      const data = await apiFetch<BaselineConfigPayload>("/api/baseline/config/reset", {
        method: "POST",
        body: JSON.stringify({ keys }),
      });
      applyConfig(data);
      setMsg(
        keys.length ? `已恢复默认：${keys.join("、")}` : `已全部恢复默认（${data.removed ?? 0} 项）`,
      );
      void load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "恢复默认失败");
    } finally {
      setBusy(false);
    }
  }

  const stats = overview?.stats;
  // 画像的「生效中」口径 = 观测次数到了冷启动门槛（后端 detect() 的同一个判据）
  // 冷启动按**窗口数**看（不是事件条数）：实体被观测到足够多个落库窗口才参与打分
  const minWindows = Number(config?.effective?.["profile.min_windows"] ?? 5);
  const dirtyItems = (config?.items ?? []).filter((item) => changed(item, draft));
  const groups: { title: string; prefix: string; hint: string }[] = [
    {
      title: "数值基线（2σ）",
      prefix: "baseline.",
      hint: "按源 IP 记三个维度（连接数 / 目的端口数 / 目的 IP 数），当前值 > 均值 + Nσ 算偏离。观测期内的维度只学习、不判偏离。",
    },
    {
      title: "账号 / 会话画像判据",
      prefix: "profile.",
      hint: "画像风险分是加权累加，达到阈值才算异常并写进摘要标签推给智能体。",
    },
  ];

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      {/* 工具条：配置在右侧抽屉里改。主操作 default、次要 outline，统一 sm（原来主按钮比旁边的
          outline 高一档，一行里两个高度） */}
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={() => setConfigOpen(true)}>
          分析配置{dirtyItems.length ? `（${dirtyItems.length} 项未保存）` : ""}
        </Button>
        <Button size="sm" variant="outline" onClick={() => void load()}>
          立即刷新
        </Button>
        <label className="flex items-center gap-1 text-xs text-muted-foreground">
          <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
          每 {REFRESH_SECONDS} 秒自动刷新
        </label>
        <label className="text-xs text-muted-foreground">
          时间范围
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="ml-1 h-8 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
          >
            <option value="1h">近1小时</option>
            <option value="6h">近6小时</option>
            <option value="24h">近24小时</option>
            <option value="7d">近7天</option>
          </select>
        </label>
        {overview?.cached ? (
          <span className="text-xs text-muted-foreground">（总览数据来自后端 30 秒缓存）</span>
        ) : null}
      </div>

      {/* ---------- 1. 学习进度与检测器心跳 ---------- */}
      <Section
        title="学习进度与检测器心跳"
        description="观测期还剩多久、检测器有没有在落库、当前风险 TOP。"
      >
        <Card>
          <CardContent className="space-y-2 pt-4">
            {!overview && !errs.has ? (
              /* 首次加载：指标格 + 徽章行先占位。直接渲染会比一排 0，看着像基线没建起来 */
              <>
                <StatSkeleton count={4} />
                <Skeleton className="h-8 w-full" />
              </>
            ) : (
              <>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <Stat label="维度总数" value={stats?.total_keys ?? "-"} />
                  <Stat
                    label="观测中（只学习）"
                    tone="medium"
                    value={stats?.learning_keys ?? "-"}
                  />
                  <Stat
                    label="生效中（可判偏离）"
                    tone="ok"
                    value={stats?.warmed_keys ?? "-"}
                  />
                  {/* 第 4 格不是一个"数"而是一句时间预期：值放时间，口径放 hint，字号降一档 */}
                  <Stat
                    label={`观测期（${stats?.observe_days ?? "-"} 天）后`}
                    size="sm"
                    value={stats?.next_warm_at ? formatDateTime(stats.next_warm_at) : "—"}
                    hint={stats?.next_warm_at ? "起有维度转入判断" : "暂无数据"}
                  />
                </div>
                <div className="flex flex-wrap gap-2 text-xs">
                  <Badge variant={overview?.detector?.alive ? "default" : "outline"}>
                    {overview?.detector?.alive ? "检测器在落库" : "检测器未在跑"}
                  </Badge>
                  <Badge variant="outline">已观测 {overview?.detector?.observed ?? 0} 次</Badge>
                  <Badge variant="outline">落库 {overview?.detector?.flushes ?? 0} 轮</Badge>
                  <Badge variant="outline">
                    上轮落库维度 {overview?.detector?.numeric_keys_last_round ?? 0}
                  </Badge>
                  <Badge variant="outline">
                    上轮异常 {overview?.detector?.anomalies_last_round ?? 0} / 累计{" "}
                    {overview?.detector?.anomalies_total ?? 0}
                  </Badge>
                  <Badge variant={overview?.enabled ? "default" : "outline"}>
                    数值基线{overview?.enabled ? "开" : "关"}
                  </Badge>
                  <Badge variant={overview?.profile_enabled ? "default" : "outline"}>
                    画像{overview?.profile_enabled ? "开" : "关"}
                  </Badge>
                  {/* 中继去重计数：四个数都要看得见（不静默丢数据） */}
                  <Badge variant="outline">
                    客户端侧跳 保留 {overview?.detector?.relay_front ?? 0} / 丢弃{" "}
                    {overview?.detector?.relay_front_dropped ?? 0}
                  </Badge>
                  <Badge variant="outline">
                    源站侧跳 保留 {overview?.detector?.relay_back_kept ?? 0} / 去重{" "}
                    {overview?.detector?.relay_back_dropped ?? 0}
                  </Badge>
                  <Badge variant="outline">
                    中继内部 保留 {overview?.detector?.relay_internal_kept ?? 0} / 丢弃{" "}
                    {overview?.detector?.relay_internal_dropped ?? 0}
                  </Badge>
                  <Badge variant="outline">
                    链续跳去重 {overview?.detector?.relay_chain_continuation_dropped ?? 0}
                  </Badge>
                  <Badge variant="outline">
                    被访问方资产 本轮 {overview?.detector?.assets_last_round ?? 0} / 累计{" "}
                    {overview?.detector?.assets_observed ?? 0}
                  </Badge>
                  <Badge variant="outline">
                    被访问连接 本轮 {overview?.detector?.asset_uids_last_round ?? 0} / 累计{" "}
                    {overview?.detector?.asset_uids_total ?? 0}
                  </Badge>
                  <Badge variant="outline">
                    未进基线 {overview?.detector?.asset_uids_dropped ?? 0}
                  </Badge>
                </div>
                <div>
                  <p className="mb-1 text-xs text-muted-foreground">
                    当前风险 TOP（只列账号；阈值 {overview?.risk_threshold ?? "-"}，判定时间在{" "}
                    {overview?.anomalies?.ttl_minutes ?? 0} 分钟内才算「当前」）
                  </p>
                  {overview?.anomalies?.items?.length ? (
                    <ul className="space-y-1 text-xs">
                      {overview.anomalies.items.map((item, i) => (
                        <li key={item.id || i} className="flex flex-wrap items-center gap-2">
                          <Badge variant="critical">风险 {(item.risk_score ?? 0).toFixed(2)}</Badge>
                          <span className="font-medium">{item.entity_display || item.entity_key}</span>
                          <span className="font-mono text-muted-foreground">
                            {ipLabels(item.dst_ips, 2)}
                          </span>
                          <span className="text-muted-foreground">
                            判定 {formatDateTime(item.risk_at)}
                          </span>
                          <span className="text-muted-foreground">
                            {(item.anomalies || []).slice(0, 2).join("；")}
                          </span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    /* 空态：这里可能是「真的没有过阈值画像」，也可能是总览没读到 —— 分开说 */
                    <EmptyState
                      size="compact"
                      tone={errs.isFailed(SRC.overview) ? "danger" : "muted"}
                      title={
                        overview?.note ||
                        emptyOrFailed(errs, SRC.overview, "暂无过阈值画像")
                      }
                    />
                  )}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </Section>

      {/* ---------- 2. 数值基线 IP 列表（生效中 / 观测中） ---------- */}
      <Section
        title="数值基线 IP 列表"
        help="按 IP 聚合的数值基线维度与偏离状态，点标签看均值/标准差"
        description={
          <>
            一行一个 IP，维度用标签列（悬停标签看均值/标准差/观测次数）；
            <span className="text-sev-ok-fg">生效中</span>=已过观测期参与 2σ 判定，
            <span className="text-sev-medium-fg">观测中</span>=还在学习
          </>
        }
      >
        <Card>
          <CardContent className="space-y-2 pt-4">
            <div className="flex flex-wrap items-center gap-2">
              <Input
                className="h-9 w-52"
                aria-label="按 IP 或 key 搜索"
                placeholder="按 IP 或 key 搜（支持片段）"
                value={nq}
                onChange={(e) => {
                  setNq(e.target.value);
                  setNpage(0);
                }}
              />
              <select
                aria-label="按维度筛选"
                className="h-9 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                value={nfeature}
                onChange={(e) => {
                  setNfeature(e.target.value);
                  setNpage(0);
                }}
              >
                <option value="">全部维度</option>
                {Object.entries(FEATURE_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
              <select
                aria-label="排序方式"
                className="h-9 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                value={nsort}
                onChange={(e) => {
                  setNsort(e.target.value);
                  setNpage(0);
                }}
              >
                <option value="count">按观测次数</option>
                <option value="updated">按最近更新</option>
                <option value="key">按 key</option>
              </select>
              <span className="text-xs tabular-nums text-muted-foreground">
                共 {numeric?.total ?? 0} 个 IP · {numeric?.total_keys ?? 0} 个维度
              </span>
            </div>
            {!numeric && !errs.has ? (
              <TableSkeleton rows={6} cols={3} />
            ) : numeric?.items?.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10 select-none text-center">#</TableHead>
                    <TableHead>IP</TableHead>
                    <TableHead>维度（悬停看均值/标准差）</TableHead>
                    <TableHead>首次观测</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {numeric.items.map((group, i) => (
                    <TableRow key={group.ip}>
                      <TableCell className="w-10 select-none text-center tabular-nums text-muted-foreground">
                        {npage * PAGE_SIZE + i + 1}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{ipLabel(group.ip)}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {group.features.map((f) => (
                            <Badge
                              key={f.feature}
                              variant={f.warmed ? "success" : "medium"}
                              title={featureTip(f, numeric.observe_days)}
                              className="cursor-help"
                            >
                              {featureLabel(f.feature)}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                        {formatDateTime(group.first_seen)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                title={emptyOrFailed(errs, SRC.numeric, "没有符合条件的维度")}
                hint="放宽搜索条件或换一个维度筛选；观测期内的维度会先在这里学习"
                tone={errs.isFailed(SRC.numeric) ? "danger" : "muted"}
              />
            )}
            <Pager total={numeric?.total ?? 0} page={npage} onPage={setNpage} />
          </CardContent>
        </Card>
      </Section>

      {/* ---------- 3. 画像列表（生效中 / 观测中） ---------- */}
      <Section
        title="账号 / 会话画像列表"
        help="账号与会话的长期行为画像与风险分，点行展开细节"
        description={
          <>
            <span className="text-sev-ok-fg">生效中</span>=观测次数已达冷启动门槛（{minWindows}{" "}
            个窗口）参与打分，<span className="text-sev-medium-fg">观测中</span>=还在学习；
            风险分按当前窗口算（本轮无理由即归零），点一行展开细节
          </>
        }
      >
        <Card>
          <CardContent className="space-y-2 pt-4">
            <div className="flex flex-wrap items-center gap-2">
              <select
                aria-label="画像类型"
                className="h-9 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                value={kind}
                onChange={(e) => {
                  setKind(e.target.value);
                  setPpage(0);
                }}
              >
                <option value="account">只看账号</option>
                <option value="session">只看会话</option>
                <option value="">账号 + 会话</option>
              </select>
              <Input
                className="h-9 w-40"
                aria-label="搜账号名 / 会话哈希"
                placeholder="搜账号名 / 会话哈希"
                value={pq}
                onChange={(e) => {
                  setPq(e.target.value);
                  setPpage(0);
                }}
              />
              <select
                aria-label="最低风险"
                className="h-9 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                value={minRisk}
                onChange={(e) => {
                  setMinRisk(e.target.value);
                  setPpage(0);
                }}
              >
                <option value="0">全部风险</option>
                <option value="0.1">风险 &gt; 0</option>
                <option value="0.3">风险 ≥ 0.3</option>
                <option value="0.6">风险 ≥ 0.6（过阈值）</option>
              </select>
              <span className="text-xs tabular-nums text-muted-foreground">
                共 {profiles?.total ?? 0} 条
              </span>
              <Button
                variant="outline"
                size="sm"
                className="ml-auto"
                onClick={openDispositionList}
              >
                处置记录
              </Button>
            </div>
            {!profiles && !errs.has ? (
              <TableSkeleton rows={6} cols={6} />
            ) : profiles?.items?.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10 select-none text-center">#</TableHead>
                    <TableHead>实体</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>风险</TableHead>
                    <TableHead
                      title="似然比后验概率（0~1）；llr 打分时列表按它排序"
                    >
                      后验
                    </TableHead>
                    <TableHead>判定时间</TableHead>
                    <TableHead>最近出现</TableHead>
                    <TableHead>观测</TableHead>
                    <TableHead>服务端 IP</TableHead>
                    <TableHead>认证失败/成功 · 错误</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {profiles.items.map((row, i) => {
                    const rowKey = `${row.kind}|${row.entity_key || i}`;
                    const open = expanded === rowKey;
                    const risk = Number(row.risk_score || 0);
                    return (
                      <React.Fragment key={rowKey}>
                        <TableRow
                          className="cursor-pointer"
                          onClick={() => setExpanded(open ? "" : rowKey)}
                        >
                          <TableCell className="w-10 select-none text-center tabular-nums text-muted-foreground">
                            {ppage * PAGE_SIZE + i + 1}
                          </TableCell>
                          <TableCell className="font-medium">
                            {open ? "▾ " : "▸ "}
                            {row.entity_display || row.entity_key}
                          </TableCell>
                          <TableCell>{row.kind === "account" ? "账号" : "会话"}</TableCell>
                          <TableCell>
                            <StateBadge
                              judging={(row.window_count ?? 0) >= minWindows}
                              hint={
                                (row.window_count ?? 0) >= minWindows
                                  ? "已过冷启动：参与风险打分"
                                  : `已观测 ${row.window_count ?? 0}/${minWindows} 个窗口，还没到冷启动门槛`
                              }
                            />
                          </TableCell>
                          <TableCell>
                            {risk > 0 ? (
                              <Badge
                                variant={
                                  risk >= (overview?.risk_threshold ?? 0.6)
                                    ? "critical"
                                    : "secondary"
                                }
                                className="tabular-nums"
                              >
                                {risk.toFixed(2)}
                              </Badge>
                            ) : (
                              <span className="tabular-nums text-muted-foreground">0</span>
                            )}
                          </TableCell>
                          <TableCell className="tabular-nums text-muted-foreground">
                            {row.posterior != null ? row.posterior.toFixed(3) : "-"}
                          </TableCell>
                          <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                            {formatDateTime(row.risk_at)}
                          </TableCell>
                          <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                            {formatDateTime(row.last_seen)}
                          </TableCell>
                          <TableCell className="tabular-nums">{row.obs_count ?? 0}</TableCell>
                          <TableCell className="font-mono text-xs">
                            {ipLabels(row.dst_ips, 2) || "-"}
                          </TableCell>
                          <TableCell className="tabular-nums">
                            {row.fail_count ?? 0}/{row.success_count ?? 0} ·{" "}
                            <span
                              className={
                                (row.error_count ?? 0) > 0
                                  ? "text-sev-medium-fg"
                                  : "text-muted-foreground"
                              }
                              title="错误响应（status ≥ 400 且非 401/403）：404 风暴这类探测痕迹"
                            >
                              {row.error_count ?? 0}
                            </span>
                          </TableCell>
                        </TableRow>
                        {open ? (
                          <TableRow>
                            {/* 展开行的底：L1 内联底（原来 bg-muted/30 是半透明叠色，暗色端发灰） */}
                            <TableCell colSpan={10} className="bg-surface-1">
                              <ProfileDetail row={row} onDispose={openDisposition} />
                            </TableCell>
                          </TableRow>
                        ) : null}
                      </React.Fragment>
                    );
                  })}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                title={emptyOrFailed(
                  errs,
                  SRC.profiles,
                  "没有符合条件的画像（观测期内的实体还没积累出画像）",
                )}
                hint="点开一轮检测后画像会陆续出现；也可以先把「最低风险」调回全部风险"
                tone={errs.isFailed(SRC.profiles) ? "danger" : "muted"}
              />
            )}
            <Pager total={profiles?.total ?? 0} page={ppage} onPage={setPpage} />
          </CardContent>
        </Card>
      </Section>

      {/* ---------- 4. 被访问方（内网源站 / 内网 DNS） ---------- */}
      <Section
        title="被访问方（内网源站 / 内网 DNS）"
        help="按被访问方（内网源站 / DNS）建基线的波动情况，区分内网与公网目标"
        description={
          <>
            按「被访问方」建基线：看被访问次数 / 不同真实客户端数 / 不同目标数的区间间波动 ——
            源 IP 那份基线看不出「服务器被打」。
            <span className="text-sev-ok-fg">生效中</span>=已过观测期，
            <span className="text-sev-medium-fg">观测中</span>=只学习。 口径：被访问次数 =
            连接数（同一连接只算一次）， 请求数 = 应用层请求（http/dns）；身份优先站点域名（Host/SNI），否则{" "}
            <span className="font-mono">IP:端口</span>；中继自身不计入（内网 DNS 的 53 端口除外）
          </>
        }
      >
        <Card>
          <CardContent className="space-y-2 pt-4">
            <div className="flex flex-wrap items-center gap-2">
              <Input
                className="h-9 w-52"
                aria-label="按 hostname 或 IP:端口 搜索"
                placeholder="按 hostname / IP:端口 搜"
                value={aq}
                onChange={(e) => {
                  setAq(e.target.value);
                  setApage(0);
                }}
              />
              <span className="text-xs tabular-nums text-muted-foreground">
                共 {assets?.total ?? 0} 个资产（内网 {assets?.by_scope?.internal ?? 0} / 外部{" "}
                {assets?.by_scope?.external ?? 0}
                {(assets?.by_scope?.unknown ?? 0) > 0
                  ? ` / 归属未定 ${assets?.by_scope?.unknown ?? 0}（早期数据，后台每小时自愈）`
                  : ""}
                ）· 每个观测区间 {assets?.window_seconds ?? "-"} 秒
              </span>
              <div className="flex gap-1">
                {(
                  [
                    ["", `全部（${assets?.by_scope ? (assets.by_scope.internal ?? 0) + (assets.by_scope.external ?? 0) + (assets.by_scope.unknown ?? 0) : 0}）`],
                    ["internal", `内网被访问方（${assets?.by_scope?.internal ?? 0}）`],
                    ["external", `外部目标（${assets?.by_scope?.external ?? 0}）`],
                  ] as const
                ).map(([value, label]) => (
                  <Button
                    key={value}
                    size="sm"
                    variant={ascope === value ? "default" : "outline"}
                    onClick={() => {
                      setAscope(value);
                      setApage(0);
                    }}
                  >
                    {label}
                  </Button>
                ))}
              </div>
            </div>
            {!assets && !errs.has ? (
              <TableSkeleton rows={6} cols={6} />
            ) : assets?.items?.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10 select-none text-center">#</TableHead>
                    <TableHead>资产</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>平均每区间被访问</TableHead>
                    <TableHead>平均每区间请求</TableHead>
                    <TableHead>不同客户端</TableHead>
                    <TableHead>不同目标</TableHead>
                    <TableHead>首见</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.items.map((row, i) => (
                    <TableRow key={row.asset}>
                      <TableCell className="w-10 select-none text-center tabular-nums text-muted-foreground">
                        {apage * PAGE_SIZE + i + 1}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{row.asset}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{row.role === "dns" ? "内网 DNS" : "站点"}</Badge>
                        <Badge
                          variant={row.scope === "external" ? "outline" : "default"}
                          title={
                            row.scope === "external"
                              ? "公网目标（含公共 DNS 解析器）：只展示，异常判定不看它"
                              : "内网被访问方：异常判定只看这一块"
                          }
                        >
                          {row.scope === "external" ? "外部" : "内网"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <StateBadge
                          judging={row.state === "ready"}
                          hint={
                            row.state === "ready"
                              ? "已过观测期：参与 2σ 规模偏离判定"
                              : `已攒 ${row.windows} 个观测区间，还在学习`
                          }
                        />
                      </TableCell>
                      <TableCell className="tabular-nums">{row.visits_mean}</TableCell>
                      <TableCell className="tabular-nums">{row.requests_mean}</TableCell>
                      <TableCell className="tabular-nums">{row.clients_mean}</TableCell>
                      <TableCell className="tabular-nums">{row.targets_mean}</TableCell>
                      <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                        {formatDateTime(row.first_seen)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                title={emptyOrFailed(errs, SRC.assets, "还没有被访问方数据（观测期内的资产先学习）")}
                hint="被访问方基线按观测区间累积；刚部署时先看「观测中」，过观测期才参与判定"
                tone={errs.isFailed(SRC.assets) ? "danger" : "muted"}
              />
            )}
            <Pager total={assets?.total ?? 0} page={apage} onPage={setApage} />
          </CardContent>
        </Card>
      </Section>

      {/* ---------- 5. 基线事实（observations）：客观观察，没有 severity/verdict ---------- */}
      <Section
        title="基线事实"
        description="行为基线只描述「和平时不一样」的客观事实（外连新目标 / 异地登录 / 爆破 / 大量 404 / 连接数偏离）。没有严重度、没有判定 —— 判断权在智能体。"
        extra={
          <Button size="sm" variant="outline" onClick={() => void loadInto(errs, SRC.observations, obsUrl, setObs)}>
            刷新
          </Button>
        }
      >
        <Card>
          <CardContent className="space-y-3 pt-4">
            {/* 分类型计数 chips：点一下即筛选该类事实（available=false 时显示读取失败而不是 0） */}
            {obsStats?.available === false ? (
              <p className="text-xs text-sev-critical-fg">事实统计读取失败：{obsStats.error || "后端异常"}</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {(obsStats?.kinds ?? []).length ? (
                  obsStats!.kinds.map((k) => (
                    <button
                      key={k.kind}
                      type="button"
                      title={k.last_seen ? `最近一次：${formatDateTime(k.last_seen)}` : undefined}
                      onClick={() => {
                        setObsKind(obsKind === k.kind ? "" : k.kind);
                        setObsPage(0);
                      }}
                      className={
                        "rounded-sm border px-2 py-0.5 text-xs transition-colors " +
                        (obsKind === k.kind
                          ? "border-brand-500 bg-brand-50 text-primary"
                          : "border-border bg-surface-1 text-muted-foreground hover:bg-surface-2")
                      }
                    >
                      {k.label} · <span className="tabular-nums">{k.count}</span>
                    </button>
                  ))
                ) : (
                  <span className="text-xs text-muted-foreground">窗口内没有事实记录。</span>
                )}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <select
                aria-label="事实类型"
                value={obsKind}
                onChange={(e) => {
                  setObsKind(e.target.value);
                  setObsPage(0);
                }}
                className="h-8 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
              >
                <option value="">全部类型</option>
                {OBSERVATION_KINDS.map(([v, label]) => (
                  <option key={v} value={v}>
                    {label}
                  </option>
                ))}
              </select>
              <Input
                className="h-8 w-56"
                aria-label="按对象精确过滤（IP / 账号）"
                placeholder="对象：IP / 账号"
                value={obsSubject}
                onChange={(e) => setObsSubject(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    setObsPage(0);
                    void loadInto(errs, SRC.observations, obsUrl, setObs);
                  }
                }}
              />
              <select
                aria-label="时间窗"
                value={obsMinutes}
                onChange={(e) => {
                  setObsMinutes(Number(e.target.value));
                  setObsPage(0);
                }}
                className="h-8 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
              >
                <option value={60}>近1小时</option>
                <option value={360}>近6小时</option>
                <option value={1440}>近24小时</option>
                <option value={10080}>近7天</option>
                <option value={43200}>近30天</option>
              </select>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setObsPage(0);
                  void loadInto(errs, SRC.observations, obsUrl, setObs);
                }}
              >
                查询
              </Button>
              <span className="text-xs text-muted-foreground">
                {obs?.available === false ? "读取失败" : `共 ${obs?.total ?? 0} 条`}
              </span>
            </div>

            {!obs && !errs.has ? (
              <TableSkeleton rows={6} cols={6} />
            ) : obs?.items?.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-44">事实类型</TableHead>
                    <TableHead className="w-48">对象</TableHead>
                    <TableHead>事实明细</TableHead>
                    <TableHead className="w-16">强度</TableHead>
                    <TableHead className="w-16">次数</TableHead>
                    <TableHead className="w-40">最近出现</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {obs.items.map((it) => (
                    <TableRow key={it.id}>
                      <TableCell>
                        <Badge variant="outline" title={`客观强度 ${it.strength}，仅用于排序，不是严重度`}>
                          {it.kind_label || it.kind}
                        </Badge>
                      </TableCell>
                      <TableCell className="min-w-0">
                        <span className="block truncate font-mono text-xs" title={it.subject}>
                          {it.subject_kind === "account" ? "账号 " : ""}
                          {it.subject}
                        </span>
                      </TableCell>
                      <TableCell className="min-w-0">
                        <span
                          className="block truncate font-mono text-xs text-muted-foreground"
                          title={Object.entries(it.facts || {})
                            .map(([k, v]) => `${k}: ${String(v)}`)
                            .join(" · ")}
                        >
                          {Object.entries(it.facts || {})
                            .map(([k, v]) => `${k}: ${String(v)}`)
                            .join(" · ") || "—"}
                        </span>
                      </TableCell>
                      <TableCell className="tabular-nums text-xs text-muted-foreground">
                        {it.strength.toFixed(2)}
                      </TableCell>
                      <TableCell className="tabular-nums text-xs">{it.count}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {it.last_seen ? formatDateTime(it.last_seen) : "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                tone={obs?.available === false ? "danger" : "muted"}
                title={obs?.available === false ? "事实读取失败" : "窗口内没有基线事实"}
                hint={
                  obs?.available === false
                    ? obs.error || "后端异常或网络不通，不能当成「没有异常」"
                    : "观测期未满或行为都在基线内； facts 是「和平时不一样」的记录，不代表攻击"
                }
              />
            )}
            <Pagination total={obs?.total ?? 0} page={obsPage} pages={Math.max(1, Math.ceil((obs?.total ?? 0) / OBS_PAGE))} onPage={setObsPage} />
          </CardContent>
        </Card>
      </Section>

      {/* ---------- 6. 外连目的地与白名单 ---------- */}
      <Section
        title="外连目的地与白名单"
        description="上表是资产已学到的主动外连（排查「这台机器平时连谁」）；白名单条目命中后不再产出 egress_new / egress_rare / egress_sustained 事实。自动入白名单默认关闭（只能人工新增），开启时也会跳过有真阳性/可疑结论或正被任务跟踪的目标。删除留墓碑 —— 该目标以后不会再被自动学回来。"
        extra={
          <Button size="sm" onClick={() => {
            setAllowEditId("");
            setAllowForm({ kind: "dst_ip", value: "", scope: "global", asset: "", enabled: true, note: "" });
            setAllowOpen(true);
          }}>
            新增白名单
          </Button>
        }
      >
        <Card>
          <CardContent className="space-y-4 pt-4">
            {/* 资产外连查询：默认全部资产，输入 IP 后只看这台机器 */}
            <div className="flex flex-wrap items-center gap-2">
              <Input
                className="h-8 w-56"
                aria-label="资产 IP（留空看全部）"
                placeholder="资产 IP（留空看全部）"
                value={egressSrcIp}
                onChange={(e) => setEgressSrcIp(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void loadEgress();
                }}
              />
              <select
                aria-label="外连类型"
                value={egressKind}
                onChange={(e) => setEgressKind(e.target.value)}
                className="h-8 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
              >
                <option value="">全部类型</option>
                {EGRESS_KINDS.map(([v, label]) => (
                  <option key={v} value={v}>
                    {label}
                  </option>
                ))}
              </select>
              <Button size="sm" variant="outline" onClick={() => void loadEgress()}>
                查询外连
              </Button>
            </div>
            {egressItems === null ? null : egressItems.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-40">资产</TableHead>
                    <TableHead className="w-20">类型</TableHead>
                    <TableHead>目标</TableHead>
                    <TableHead className="w-20">次数</TableHead>
                    <TableHead className="w-40">首次 / 最近</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {egressItems.map((it, i) => (
                    <TableRow key={`${it.src_ip}-${it.kind}-${it.value}-${i}`}>
                      <TableCell className="font-mono text-xs">{it.src_ip}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {EGRESS_KINDS.find(([k]) => k === it.kind)?.[1] || it.kind}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{it.value}</TableCell>
                      <TableCell className="tabular-nums text-xs">{it.count}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {it.first_seen ? formatDateTime(it.first_seen) : "—"}
                        {" / "}
                        {it.last_seen ? formatDateTime(it.last_seen) : "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-xs text-muted-foreground">还没有学到的外连记录（观测期未满或没有主动外连）。</p>
            )}

            {/* 白名单表 */}
            <div className="flex flex-wrap items-center gap-2 border-t border-border-subtle pt-3">
              <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  checked={allowTombstone}
                  onChange={(e) => setAllowTombstone(e.target.checked)}
                />
                含已删除（墓碑）
              </label>
              <span className="text-xs text-muted-foreground">
                {allowItems?.length ?? 0} 条
              </span>
            </div>
            {allowItems === null ? (
              <TableSkeleton rows={3} cols={7} />
            ) : allowItems.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-20">类型</TableHead>
                    <TableHead>目标</TableHead>
                    <TableHead className="w-36">范围</TableHead>
                    <TableHead className="w-20">来源</TableHead>
                    <TableHead className="w-16">命中</TableHead>
                    <TableHead>备注</TableHead>
                    <TableHead className="w-36">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {allowItems.map((it) => (
                    <TableRow key={it.id} className={it.tombstone ? "opacity-60" : undefined}>
                      <TableCell className="text-xs text-muted-foreground">
                        {EGRESS_KINDS.find(([k]) => k === it.kind)?.[1] || it.kind}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {it.value}
                        {it.tombstone ? (
                          <Badge variant="medium" className="ml-1">
                            墓碑
                          </Badge>
                        ) : null}
                        {!it.enabled && !it.tombstone ? (
                          <Badge variant="outline" className="ml-1">
                            停用
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell className="text-xs">
                        {it.scope === "asset" ? `仅资产 ${it.asset || "—"}` : "全局"}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {it.source === "manual" ? "手工" : "自学习"}
                      </TableCell>
                      <TableCell className="tabular-nums text-xs">{it.hit_count}</TableCell>
                      <TableCell className="min-w-0">
                        <span className="block truncate text-xs text-muted-foreground" title={it.note}>
                          {it.note || "—"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 px-2 text-xs"
                            disabled={allowBusy}
                            onClick={() => {
                              setAllowEditId(it.id);
                              setAllowForm({
                                kind: it.kind,
                                value: it.value,
                                scope: it.scope,
                                asset: it.asset || "",
                                enabled: it.enabled,
                                note: it.note || "",
                              });
                              setAllowOpen(true);
                            }}
                          >
                            编辑
                          </Button>
                          {it.tombstone ? (
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 px-2 text-xs"
                              disabled={allowBusy}
                              onClick={() => void restoreAllow(it)}
                            >
                              恢复
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-7 w-7 p-0 text-sev-critical-fg hover:bg-sev-critical-bg"
                              aria-label={`删除白名单 ${it.value}`}
                              title="删除（留墓碑：以后不再自动学回来）"
                              disabled={allowBusy}
                              onClick={() => void deleteAllow(it)}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                tone="muted"
                title="白名单为空"
                hint="自学习条目（稳定 N 天 + N 次出现）会自动入表；也可以手工新增。"
              />
            )}
          </CardContent>
        </Card>
      </Section>

      {/* ---------- 分析配置（右侧抽屉） ---------- */}
      <Drawer
        open={configOpen}
        onClose={() => setConfigOpen(false)}
        widthClass="w-[720px]"
        title={
          /* 标题节点用 span：Drawer 把 title 放进 <h2>，块级元素套在标题里不合语法 */
          <span className="flex flex-col">
            <span className="text-sm font-medium">分析配置</span>
            <span className="text-xs font-normal text-muted-foreground">
              改完即时生效（后端 30 秒内刷新、检测器下一个窗口用新值），不需要重启容器
            </span>
          </span>
        }
        footer={
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" disabled={busy || !dirtyItems.length} onClick={() => void save()}>
              保存改动{dirtyItems.length ? `（${dirtyItems.length}）` : ""}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={busy || !(config?.items ?? []).some((i) => i.overridden)}
              onClick={() => void resetConfig([])}
            >
              全部恢复默认
            </Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => void loadConfig()}>
              重新读取
            </Button>
            {msg ? <span className="text-xs text-muted-foreground">{msg}</span> : null}
          </div>
        }
      >
        <div className="space-y-3">
          {groups.map((group) => {
            const items = (config?.items ?? []).filter((item) => item.key.startsWith(group.prefix));
            if (!items.length) return null;
            return (
              /* 抽屉里的分组也是区块：标题/说明走 Section，divided={false} 因为抽屉自己已有分隔感 */
              <Section
                key={group.prefix}
                title={group.title}
                description={group.hint}
                divided={false}
              >
                <div className="space-y-2">
                  {items.map((item) => {
                    const raw = draft[item.key];
                    const value = raw !== undefined ? raw : item.value;
                    const isDirty = changed(item, draft);
                    return (
                      <div key={item.key} className="rounded-xs bg-surface-1 px-3 py-2">
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <span className="text-sm font-medium">{item.label}</span>
                          {item.overridden ? (
                            <Badge variant="secondary">已改</Badge>
                          ) : (
                            <Badge variant="outline">默认</Badge>
                          )}
                          {isDirty ? <Badge variant="high">未保存</Badge> : null}
                          <span className="font-mono text-xs text-muted-foreground">
                            {item.key}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          {item.kind === "bool" ? (
                            <input
                              type="checkbox"
                              className="h-4 w-4"
                              aria-label={item.label}
                              checked={Boolean(value)}
                              onChange={(e) => setDraft({ ...draft, [item.key]: e.target.checked })}
                            />
                          ) : (
                            <Input
                              type={item.kind === "int" || item.kind === "float" ? "number" : "text"}
                              step={item.kind === "float" ? "0.05" : undefined}
                              min={item.low ?? undefined}
                              max={item.high ?? undefined}
                              aria-label={item.label}
                              value={String(value)}
                              className={item.kind === "regex" ? "font-mono text-xs" : undefined}
                              onChange={(e) => setDraft({ ...draft, [item.key]: e.target.value })}
                            />
                          )}
                          {item.unit ? (
                            <span className="whitespace-nowrap text-xs text-muted-foreground">
                              {item.unit}
                            </span>
                          ) : null}
                          {item.overridden ? (
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={busy}
                              onClick={() => void resetConfig([item.key])}
                            >
                              恢复默认
                            </Button>
                          ) : null}
                        </div>
                        <p className="mt-1 text-xs tabular-nums text-muted-foreground">
                          {item.note}
                          {item.low !== null && item.high !== null
                            ? `（范围 ${item.low} ~ ${item.high}${item.unit}）`
                            : null}
                          {`　默认 ${String(item.default) || "（空）"}`}
                        </p>
                        {fieldErrs[item.key] ? (
                          <p className="mt-1 text-xs text-sev-critical-fg">{fieldErrs[item.key]}</p>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              </Section>
            );
          })}
        </div>
      </Drawer>

      {/* 单条画像处置：标记误报（降权）/ 确认（留档） */}
      <Dialog
        open={dispOpen}
        title={`处置告警 · ${dispTarget?.entity_display || dispTarget?.entity_key || ""}`}
        onClose={() => setDispOpen(false)}
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setDispOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={dispBusy} onClick={submitDisposition}>
              {dispBusy ? "提交中…" : "提交处置"}
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-sm">
          <p className="text-muted-foreground">
            给这条画像告警打上结论，用于后续自动降权。判为误报后，该实体在 suppress
            天内不再参与打分（理由仍会保留展示）。
          </p>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant={dispVerdict === "false_positive" ? "default" : "outline"}
              onClick={() => setDispVerdict("false_positive")}
            >
              误报（降权）
            </Button>
            <Button
              size="sm"
              variant={dispVerdict === "confirm" ? "default" : "outline"}
              onClick={() => setDispVerdict("confirm")}
            >
              确认（留档）
            </Button>
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">备注（可选）</label>
            <textarea
              className="h-20 w-full resize-none rounded-sm border border-input bg-surface-1 p-2 text-13 text-foreground"
              value={dispNote}
              onChange={(e) => setDispNote(e.target.value)}
              placeholder="补充说明这次处置的原因"
            />
          </div>
          {dispMsg ? <p className="text-xs text-sev-critical-fg">{dispMsg}</p> : null}
        </div>
      </Dialog>

      {/* 处置记录：最近的处置结论（核对降权是否生效） */}
      <Dialog
        open={dispListOpen}
        title="处置记录"
        widthClass="w-[560px] max-w-[94vw]"
        onClose={() => setDispListOpen(false)}
        footer={
          <Button variant="ghost" size="sm" onClick={() => setDispListOpen(false)}>
            关闭
          </Button>
        }
      >
        <div className="space-y-3 text-sm">
          {dispListBusy ? (
            <p className="text-muted-foreground">读取中…</p>
          ) : dispList?.error ? (
            <p className="text-sev-critical-fg">{dispList.error}</p>
          ) : dispList?.items?.length ? (
            <div className="max-h-[60vh] space-y-2 overflow-y-auto">
              {dispList.items.map((d: AlertDisposition) => (
                <div
                  key={d.id}
                  className="rounded-xs border border-border bg-surface-1 px-3 py-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">{d.entity_key}</span>
                    <Badge variant={d.verdict === "false_positive" ? "secondary" : "outline"}>
                      {d.verdict === "false_positive" ? "误报·降权" : "确认·留档"}
                    </Badge>
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {d.kind} · 操作人 {d.operator || "-"}
                    {d.signal ? ` · 信号 ${d.signal}` : ""} ·{" "}
                    {d.created_at ? formatDateTime(d.created_at) : "-"}
                  </div>
                  {d.note ? (
                    <p className="mt-1 break-all text-xs text-muted-foreground">备注：{d.note}</p>
                  ) : null}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground">还没有处置记录。</p>
          )}
        </div>
      </Dialog>

      {/* ---------- 外连白名单 新增/编辑 ---------- */}
      <Dialog
        open={allowOpen}
        title={allowEditId ? "编辑白名单条目" : "新增外连白名单"}
        onClose={() => setAllowOpen(false)}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setAllowOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={allowBusy} onClick={() => void saveAllow()}>
              {allowBusy ? "保存中…" : "保存"}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Field label="类型">
              <select
                aria-label="白名单类型"
                value={allowForm.kind}
                onChange={(e) => setAllowForm({ ...allowForm, kind: e.target.value })}
                className="h-9 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
              >
                {EGRESS_KINDS.map(([v, label]) => (
                  <option key={v} value={v}>
                    {label}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="目标值" className="flex-1">
              <Input
                aria-label="白名单目标值"
                placeholder={allowForm.kind === "port" ? "如 8443" : allowForm.kind === "domain" ? "如 cdn.example.com" : "如 203.0.113.7"}
                value={allowForm.value}
                onChange={(e) => setAllowForm({ ...allowForm, value: e.target.value })}
              />
            </Field>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Field label="范围">
              <select
                aria-label="白名单范围"
                value={allowForm.scope}
                onChange={(e) => setAllowForm({ ...allowForm, scope: e.target.value })}
                className="h-9 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
              >
                <option value="global">全局（所有资产）</option>
                <option value="asset">仅某台资产</option>
              </select>
            </Field>
            {allowForm.scope === "asset" ? (
              <Field label="资产 IP">
                <Input
                  aria-label="白名单资产 IP"
                  placeholder="该资产的源 IP"
                  value={allowForm.asset || ""}
                  onChange={(e) => setAllowForm({ ...allowForm, asset: e.target.value })}
                />
              </Field>
            ) : null}
            <label className="flex items-center gap-1.5 text-13 text-muted-foreground">
              <input
                type="checkbox"
                checked={allowForm.enabled !== false}
                onChange={(e) => setAllowForm({ ...allowForm, enabled: e.target.checked })}
              />
              启用
            </label>
          </div>
          <Field label="备注（可选）">
            <Input
              aria-label="白名单备注"
              placeholder="为什么加白（审计看这里）"
              value={allowForm.note || ""}
              onChange={(e) => setAllowForm({ ...allowForm, note: e.target.value })}
            />
          </Field>
          <p className="text-xs leading-relaxed text-muted-foreground">
            白名单命中后不再产出「外连目的地首次出现 / 罕见」事实。手工条目会覆盖同键的自学习条目；
            删除条目会留墓碑（以后不再自动学回来），需要恢复时勾选「含已删除（墓碑）」。
          </p>
        </div>
      </Dialog>
    </div>
  );
}
