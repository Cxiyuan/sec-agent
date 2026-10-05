"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Drawer,
  Input,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  ApiError,
  apiFetch,
  errorText,
  formatDateTime,
} from "@shentong/ui";

import { PanelError, emptyOrFailed, loadInto, usePanelErrors } from "@/components/panel-error";
import type {
  AssetListPayload,
  BaselineConfigItem,
  BaselineConfigPayload,
  BaselinePayload,
  BaselineProfile,
  BaselineProfilesPayload,
  NumericGroupedPayload,
  NumericStat,
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
} as const;

const PAGE_SIZE = 20;
const REFRESH_SECONDS = 30;

function topKeys(map: Record<string, number> | undefined, n: number): string[] {
  return Object.entries(map || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([key]) => key);
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
  const shades = ["bg-muted", "bg-primary/30", "bg-primary/50", "bg-primary/70", "bg-primary"];
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

function Pager({
  total,
  page,
  onPage,
}: {
  total: number;
  page: number;
  onPage: (next: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      <Button size="sm" variant="outline" disabled={page <= 0} onClick={() => onPage(page - 1)}>
        上一页
      </Button>
      <span>
        第 {page + 1} / {pages} 页 · 共 {total} 条
      </span>
      <Button
        size="sm"
        variant="outline"
        disabled={page + 1 >= pages}
        onClick={() => onPage(page + 1)}
      >
        下一页
      </Button>
    </div>
  );
}

/** 画像展开后的细节：理由 / 来源 IP / 服务端 IP / UA / 接口路径 / 时段分布。 */
function ProfileDetail({ row }: { row: BaselineProfile }) {
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
      <div className="grid gap-2 sm:grid-cols-2">
        <p>
          <span className="text-muted-foreground">来源 IP：</span>
          <span className="font-mono">{topKeys(row.src_ips, 5).join(", ") || "-"}</span>
        </p>
        <p>
          <span className="text-muted-foreground">服务端 IP：</span>
          <span className="font-mono">{topKeys(row.dst_ips, 5).join(", ") || "-"}</span>
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
        失败 {row.fail_count ?? 0} / 成功 {row.success_count ?? 0} · 观测 {row.obs_count ?? 0} 次 ·
        首次 {formatDateTime(row.first_seen)} · 最近 {formatDateTime(row.last_seen)}
      </p>
    </div>
  );
}

export function BehaviorPanel() {
  const errs = usePanelErrors();
  const [overview, setOverview] = React.useState<BaselinePayload | null>(null);
  const [config, setConfig] = React.useState<BaselineConfigPayload | null>(null);
  const [profiles, setProfiles] = React.useState<BaselineProfilesPayload | null>(null);
  const [numeric, setNumeric] = React.useState<NumericGroupedPayload | null>(null);
  const [assets, setAssets] = React.useState<AssetListPayload | null>(null);
  const [apage, setApage] = React.useState(0);
  const [aq, setAq] = React.useState("");
  const [auto, setAuto] = React.useState(true);
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

  const profilesUrl =
    `/api/baseline/profiles?kind=${encodeURIComponent(kind)}` +
    `&q=${encodeURIComponent(pq)}&min_risk=${Number(minRisk) || 0}` +
    `&limit=${PAGE_SIZE}&offset=${ppage * PAGE_SIZE}`;
  const numericUrl =
    `/api/baseline/numeric?group=ip&q=${encodeURIComponent(nq)}` +
    `&feature=${encodeURIComponent(nfeature)}&sort=${nsort}` +
    `&limit=${PAGE_SIZE}&offset=${npage * PAGE_SIZE}`;
  const assetsUrl =
    `/api/baseline/assets?q=${encodeURIComponent(aq)}` +
    `&limit=${PAGE_SIZE}&offset=${apage * PAGE_SIZE}`;

  async function load() {
    errs.reset();
    await Promise.all([
      loadInto(errs, SRC.overview, "/api/baseline", setOverview),
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
  const minObs = Number(config?.effective?.["profile.min_obs"] ?? 5);
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

      {/* 工具条：配置在右侧抽屉里改 */}
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
        {overview?.cached ? (
          <span className="text-xs text-muted-foreground">（总览数据来自后端 30 秒缓存）</span>
        ) : null}
      </div>

      {/* ---------- 1. 学习进度与检测器心跳 ---------- */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">学习进度与检测器心跳</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
            <div>
              <p className="text-xs text-muted-foreground">维度总数</p>
              <p className="text-lg font-semibold">{stats?.total_keys ?? "-"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">观测中（只学习）</p>
              <p className="text-lg font-semibold text-amber-500">{stats?.learning_keys ?? "-"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">生效中（可判偏离）</p>
              <p className="text-lg font-semibold text-emerald-500">{stats?.warmed_keys ?? "-"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">
                观测期（{stats?.observe_days ?? "-"} 天）后
              </p>
              <p className="text-sm font-medium">
                {stats?.next_warm_at
                  ? `${formatDateTime(stats.next_warm_at)} 起有维度转入判断`
                  : "暂无数据"}
              </p>
            </div>
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
              中继前跳 {overview?.detector?.relay_front ?? 0}
            </Badge>
            <Badge variant="outline">
              后跳去重 {overview?.detector?.relay_back_dropped ?? 0}
            </Badge>
            <Badge variant="outline">
              后跳保留 {overview?.detector?.relay_back_kept ?? 0}
            </Badge>
            <Badge variant="outline">
              中继内部 {overview?.detector?.relay_internal_dropped ?? 0}
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
                      {topKeys(item.dst_ips, 2).join(", ")}
                    </span>
                    <span className="text-muted-foreground">判定 {formatDateTime(item.risk_at)}</span>
                    <span className="text-muted-foreground">
                      {(item.anomalies || []).slice(0, 2).join("；")}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted-foreground">{overview?.note || "暂无过阈值画像"}</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* ---------- 2. 数值基线 IP 列表（生效中 / 观测中） ---------- */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            数值基线 IP 列表
            <span className="text-xs font-normal text-muted-foreground">
              一行一个 IP，维度用标签列（**悬停标签**看均值/标准差/观测次数）；
              <span className="text-emerald-500">生效中</span>=已过观测期参与 2σ 判定，
              <span className="text-amber-500">观测中</span>=还在学习
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              className="h-9 w-52"
              placeholder="按 IP 或 key 搜（支持片段）"
              value={nq}
              onChange={(e) => {
                setNq(e.target.value);
                setNpage(0);
              }}
            />
            <select
              className="h-9 rounded-md border bg-transparent px-2 text-sm"
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
              className="h-9 rounded-md border bg-transparent px-2 text-sm"
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
            <span className="text-xs text-muted-foreground">
              共 {numeric?.total ?? 0} 个 IP · {numeric?.total_keys ?? 0} 个维度
            </span>
          </div>
          {numeric?.items?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>维度（悬停看均值/标准差）</TableHead>
                  <TableHead>首次观测</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {numeric.items.map((group) => (
                  <TableRow key={group.ip}>
                    <TableCell className="font-mono text-xs">{group.ip}</TableCell>
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
                    <TableCell className="text-xs">{formatDateTime(group.first_seen)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-xs text-muted-foreground">
              {emptyOrFailed(errs, SRC.numeric, "没有符合条件的维度")}
            </p>
          )}
          <Pager total={numeric?.total ?? 0} page={npage} onPage={setNpage} />
        </CardContent>
      </Card>

      {/* ---------- 3. 画像列表（生效中 / 观测中） ---------- */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            账号 / 会话画像列表
            <span className="text-xs font-normal text-muted-foreground">
              <span className="text-emerald-500">生效中</span>=观测次数已达冷启动门槛（
              {minObs} 次）参与打分，<span className="text-amber-500">观测中</span>=还在学习；
              风险分按当前窗口算（本轮无理由即归零），点一行展开细节
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <select
              className="h-9 rounded-md border bg-transparent px-2 text-sm"
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
              placeholder="搜账号名 / 会话哈希"
              value={pq}
              onChange={(e) => {
                setPq(e.target.value);
                setPpage(0);
              }}
            />
            <select
              className="h-9 rounded-md border bg-transparent px-2 text-sm"
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
            <span className="text-xs text-muted-foreground">共 {profiles?.total ?? 0} 条</span>
          </div>
          {profiles?.items?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>实体</TableHead>
                  <TableHead>类型</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>风险</TableHead>
                  <TableHead>判定时间</TableHead>
                  <TableHead>最近出现</TableHead>
                  <TableHead>观测</TableHead>
                  <TableHead>服务端 IP</TableHead>
                  <TableHead>失败/成功</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {profiles.items.map((row, i) => {
                  const rowKey = `${row.kind}|${row.entity_key || i}`;
                  const open = expanded === rowKey;
                  const risk = Number(row.risk_score || 0);
                  const obs = Number(row.obs_count ?? 0);
                  return (
                    <React.Fragment key={rowKey}>
                      <TableRow
                        className="cursor-pointer"
                        onClick={() => setExpanded(open ? "" : rowKey)}
                      >
                        <TableCell className="font-medium">
                          {open ? "▾ " : "▸ "}
                          {row.entity_display || row.entity_key}
                        </TableCell>
                        <TableCell>{row.kind === "account" ? "账号" : "会话"}</TableCell>
                        <TableCell>
                          <StateBadge
                            judging={obs >= minObs}
                            hint={
                              obs >= minObs
                                ? "已过冷启动：参与风险打分"
                                : `观测 ${obs}/${minObs} 次，还没到冷启动门槛`
                            }
                          />
                        </TableCell>
                        <TableCell>
                          {risk > 0 ? (
                            <Badge
                              variant={
                                risk >= (overview?.risk_threshold ?? 0.6) ? "critical" : "secondary"
                              }
                            >
                              {risk.toFixed(2)}
                            </Badge>
                          ) : (
                            <span className="text-muted-foreground">0</span>
                          )}
                        </TableCell>
                        <TableCell className="text-xs">{formatDateTime(row.risk_at)}</TableCell>
                        <TableCell className="text-xs">{formatDateTime(row.last_seen)}</TableCell>
                        <TableCell>{row.obs_count ?? 0}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {topKeys(row.dst_ips, 2).join(", ") || "-"}
                        </TableCell>
                        <TableCell className="text-xs">
                          {row.fail_count ?? 0}/{row.success_count ?? 0}
                        </TableCell>
                      </TableRow>
                      {open ? (
                        <TableRow>
                          <TableCell colSpan={9} className="bg-muted/30">
                            <ProfileDetail row={row} />
                          </TableCell>
                        </TableRow>
                      ) : null}
                    </React.Fragment>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <p className="text-xs text-muted-foreground">
              {emptyOrFailed(errs, SRC.profiles, "没有符合条件的画像（观测期内的实体还没积累出画像）")}
            </p>
          )}
          <Pager total={profiles?.total ?? 0} page={ppage} onPage={setPpage} />
        </CardContent>
      </Card>

      {/* ---------- 4. 被访问方（内网源站 / 内网 DNS） ---------- */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            被访问方（内网源站 / 内网 DNS）
            <span className="text-xs font-normal text-muted-foreground">
              按「**被访问方**」建基线：看被访问次数 / 不同真实客户端数 / 不同目标数的区间间波动
              —— 源 IP 那份基线看不出「服务器被打」。
              <span className="text-emerald-500">生效中</span>=已过观测期，
              <span className="text-amber-500">观测中</span>=只学习。
              口径：被访问次数 = **连接数**（同一连接只算一次），
              请求数 = 应用层请求（http/dns）；身份优先站点域名（Host/SNI），否则{" "}
              <span className="font-mono">IP:端口</span>；中继自身不计入（内网 DNS 的 53 端口除外）
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              className="h-9 w-52"
              placeholder="按 hostname / IP:端口 搜"
              value={aq}
              onChange={(e) => {
                setAq(e.target.value);
                setApage(0);
              }}
            />
            <span className="text-xs text-muted-foreground">
              共 {assets?.total ?? 0} 个资产 · 每个观测区间 {assets?.window_seconds ?? "-"} 秒
            </span>
          </div>
          {assets?.items?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
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
                {assets.items.map((row) => (
                  <TableRow key={row.asset}>
                    <TableCell className="text-xs">{row.asset}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{row.role === "dns" ? "内网 DNS" : "站点"}</Badge>
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
                    <TableCell>{row.visits_mean}</TableCell>
                    <TableCell>{row.requests_mean}</TableCell>
                    <TableCell>{row.clients_mean}</TableCell>
                    <TableCell>{row.targets_mean}</TableCell>
                    <TableCell className="text-xs">{formatDateTime(row.first_seen)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-xs text-muted-foreground">
              {emptyOrFailed(errs, SRC.assets, "还没有被访问方数据（观测期内的资产先学习）")}
            </p>
          )}
          <Pager total={assets?.total ?? 0} page={apage} onPage={setApage} />
        </CardContent>
      </Card>

      {/* ---------- 分析配置（右侧抽屉） ---------- */}
      <Drawer
        open={configOpen}
        onClose={() => setConfigOpen(false)}
        widthClass="w-[720px]"
        title={
          <div>
            <p className="text-sm font-semibold">分析配置</p>
            <p className="text-xs text-muted-foreground">
              改完即时生效（后端 30 秒内刷新、检测器下一个窗口用新值），不需要重启容器
            </p>
          </div>
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
        <div className="space-y-4">
          {groups.map((group) => {
            const items = (config?.items ?? []).filter((item) => item.key.startsWith(group.prefix));
            if (!items.length) return null;
            return (
              <div key={group.prefix} className="space-y-2">
                <div>
                  <p className="text-sm font-medium">{group.title}</p>
                  <p className="text-xs text-muted-foreground">{group.hint}</p>
                </div>
                <div className="space-y-3">
                  {items.map((item) => {
                    const raw = draft[item.key];
                    const value = raw !== undefined ? raw : item.value;
                    const isDirty = changed(item, draft);
                    return (
                      <div key={item.key} className="rounded-md border p-3">
                        <div className="mb-1 flex flex-wrap items-center gap-2">
                          <span className="text-sm font-medium">{item.label}</span>
                          {item.overridden ? (
                            <Badge variant="secondary">已改</Badge>
                          ) : (
                            <Badge variant="outline">默认</Badge>
                          )}
                          {isDirty ? <Badge variant="high">未保存</Badge> : null}
                          <span className="font-mono text-[10px] text-muted-foreground">
                            {item.key}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          {item.kind === "bool" ? (
                            <input
                              type="checkbox"
                              className="h-4 w-4"
                              checked={Boolean(value)}
                              onChange={(e) => setDraft({ ...draft, [item.key]: e.target.checked })}
                            />
                          ) : (
                            <Input
                              type={item.kind === "int" || item.kind === "float" ? "number" : "text"}
                              step={item.kind === "float" ? "0.05" : undefined}
                              min={item.low ?? undefined}
                              max={item.high ?? undefined}
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
                        <p className="mt-1 text-xs text-muted-foreground">
                          {item.note}
                          {item.low !== null && item.high !== null
                            ? `（范围 ${item.low} ~ ${item.high}${item.unit}）`
                            : null}
                          {`　默认 ${String(item.default) || "（空）"}`}
                        </p>
                        {fieldErrs[item.key] ? (
                          <p className="mt-1 text-xs text-red-500">{fieldErrs[item.key]}</p>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </Drawer>
    </div>
  );
}
