"use client";

import * as React from "react";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Chart } from "@shentong/ui";
import type {
  AgentPushPayload,
  BaselinePayload,
  ComponentHealthItem,
  ComponentHealthPayload,
  ComponentState,
  DetectorCoverage,
  DetectorHistory,
  DetectorRate,
  DetectorStats,
  EsStatus,
  LogstashStatus,
  StatsOverview,
  SystemMetrics,
  WazuhPayload,
} from "@/lib/api";
import { PanelError, emptyOrFailed, loadInto, usePanelErrors } from "@/components/panel-error";
import {
  anomalyOption,
  baselineOption,
  bytesLine,
  capacityRingOption,
  coverageOption,
  droppedOption,
  esIndicesOption,
  formatBytes,
  logstashOption,
  protocolPieOption,
  pushCountersOption,
  queueTrendOption,
  rateFunnelOption,
  rateTrendOption,
  ringOption,
  ruleTopOption,
  severityOption,
  trafficOption,
} from "@/components/status-charts";

/**
 * 总览（默认落地页）：服务器状态 → 组件呼吸灯 → 威胁事件 → 24h 流量与协议 → 链路细节。
 *
 * 几个刻意的取舍：
 * - **一次并行取 12 个接口**，单个失败只让对应卡片变「读取失败」，不整页白屏（沿用 PanelError 约定）。
 * - **图表 option 全部 memo**，加上 `Chart` 内部改成原地 `setOption`（见 packages/ui）——
 *   否则 15 秒轮询会让每张图 dispose 重建一次、整页闪。
 * - 取不到数就说「暂无采样 / 暂无数据」，不画空轴：趋势类接口在部署后前 5 分钟本来就是空的。
 * - 页面只读，没有任何写操作。
 */

const SRC = {
  metrics: "服务器指标",
  health: "组件状态",
  history: "检测器历史采样",
  rate: "检测器速率",
  coverage: "投递覆盖率",
  stats: "检测器队列",
  push: "摘要推送",
  wazuh: "主机监控",
  baseline: "基线观测",
  es: "Elasticsearch",
  logstash: "Logstash",
  overview: "流量与协议",
} as const;

const ANCHORS = [
  { id: "server", label: "服务器" },
  { id: "components", label: "组件" },
  { id: "threats", label: "威胁事件" },
  { id: "traffic", label: "流量与协议" },
  { id: "chain", label: "链路细节" },
] as const;

/** 呼吸灯的配色与文案：ok 慢呼吸、degraded 快闪、down 常亮红、unknown 灰。 */
const LIGHT_CLS: Record<ComponentState, string> = {
  ok: "bg-emerald-500 light-breathe",
  degraded: "bg-amber-500 light-blink",
  down: "bg-red-500",
  unknown: "bg-slate-500",
};
const LIGHT_TEXT: Record<ComponentState, string> = {
  ok: "正常",
  degraded: "注意",
  down: "不可用",
  unknown: "未知",
};

function Kpi({
  label,
  value,
  hint,
  danger,
}: {
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  danger?: boolean;
}) {
  return (
    <div className="rounded-md border p-3">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={"mt-1 text-xl font-bold " + (danger ? "text-destructive" : "")}>{value}</p>
      {hint ? <p className="mt-0.5 text-[11px] text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

/** 页内区块：`scroll-mt-20` 让锚点跳转不被固定页头（h-14）挡住标题。 */
function Section({
  id,
  title,
  extra,
  children,
}: {
  id: string;
  title: string;
  extra?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-20 space-y-3">
      <h2 className="flex flex-wrap items-center gap-2 text-sm font-medium text-muted-foreground">
        {title}
        {extra}
      </h2>
      {children}
    </section>
  );
}

function ChartCard({
  title,
  extra,
  option,
  height = 220,
  empty,
}: {
  title: string;
  extra?: React.ReactNode;
  option: React.ComponentProps<typeof Chart>["option"];
  height?: number;
  /** 有值就不画图、显示这段文案（趋势类接口在部署初期本来就是空的） */
  empty?: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          {title}
          {extra}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {empty ? (
          <p className="py-10 text-center text-xs text-muted-foreground">{empty}</p>
        ) : (
          <Chart option={option} height={height} />
        )}
      </CardContent>
    </Card>
  );
}

function Light({ item }: { item: ComponentHealthItem }) {
  return (
    <div className="flex items-start gap-2 rounded-md border p-3">
      <span
        aria-hidden
        className={"mt-1 h-2.5 w-2.5 shrink-0 rounded-full " + (LIGHT_CLS[item.state] || LIGHT_CLS.unknown)}
      />
      <div className="min-w-0">
        <p className="text-sm">
          {item.name}
          <span className="ml-1 text-xs text-muted-foreground">{LIGHT_TEXT[item.state] || item.state}</span>
        </p>
        <p className="break-words text-[11px] text-muted-foreground">{item.detail || "—"}</p>
      </div>
    </div>
  );
}

export function StatusPanel() {
  const errs = usePanelErrors();
  const [metrics, setMetrics] = React.useState<SystemMetrics | null>(null);
  const [health, setHealth] = React.useState<ComponentHealthPayload | null>(null);
  const [history, setHistory] = React.useState<DetectorHistory | null>(null);
  const [rate, setRate] = React.useState<DetectorRate | null>(null);
  const [coverage, setCoverage] = React.useState<DetectorCoverage | null>(null);
  const [stats, setStats] = React.useState<DetectorStats | null>(null);
  const [push, setPush] = React.useState<AgentPushPayload | null>(null);
  const [wazuh, setWazuh] = React.useState<WazuhPayload | null>(null);
  const [baseline, setBaseline] = React.useState<BaselinePayload | null>(null);
  const [esStatus, setEsStatus] = React.useState<EsStatus | null>(null);
  const [logstash, setLogstash] = React.useState<LogstashStatus | null>(null);
  const [overview, setOverview] = React.useState<StatsOverview | null>(null);
  const [auto, setAuto] = React.useState(true);
  const [busy, setBusy] = React.useState(false);

  async function load() {
    setBusy(true);
    errs.reset();
    await Promise.all([
      loadInto(errs, SRC.metrics, "/api/system/metrics", setMetrics),
      loadInto(errs, SRC.health, "/api/health/components", setHealth),
      loadInto(errs, SRC.history, "/api/detector/history?limit=288", setHistory),
      loadInto(errs, SRC.rate, "/api/detector/rate", setRate),
      loadInto(errs, SRC.coverage, "/api/detector/coverage", setCoverage),
      loadInto(errs, SRC.stats, "/api/detector/stats", setStats),
      loadInto(errs, SRC.push, "/api/agent-push", setPush),
      loadInto(errs, SRC.wazuh, "/api/wazuh", setWazuh),
      loadInto(errs, SRC.baseline, "/api/baseline", setBaseline),
      loadInto(errs, SRC.es, "/api/es/status", setEsStatus),
      loadInto(errs, SRC.logstash, "/api/logstash", setLogstash),
      loadInto(errs, SRC.overview, "/api/stats/overview?hours=24", setOverview),
    ]);
    setBusy(false);
  }

  React.useEffect(() => {
    void load();
    // 只在挂载时取一次；后续节奏由下面的定时器控制
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    if (!auto) return;
    const timer = setInterval(() => void load(), 15000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto]);

  // items 每次渲染都是新数组 → 单独 memo，避免下面 charts 的依赖每次都变
  const historyItems = React.useMemo(() => history?.items ?? [], [history]);
  const queueMax = stats?.queue_max ?? 0;
  // 24h 合计 = 各区间增量之和（history 本身就是 24h 窗口；累计计数器是「自进程启动以来」）
  const { hit24h, digest24h } = React.useMemo(() => {
    let hit = 0;
    let digest = 0;
    for (const p of historyItems) {
      hit += Number(p.d_hit ?? 0);
      digest += Number(p.d_digest ?? 0);
    }
    return { hit24h: Math.round(hit), digest24h: Math.round(digest) };
  }, [historyItems]);

  // 一份 memo 产出全部 option：`Chart` 内部现在是原地 setOption，
  // 数据没变时 option 引用不变 → 不会触发任何重绘。
  const charts = React.useMemo(
    () => ({
      cpu: ringOption(metrics?.cpu_percent ?? null, "CPU"),
      mem: ringOption(metrics?.mem_percent ?? null, "内存"),
      disk: ringOption(metrics?.disk_percent ?? null, "磁盘"),
      queueCap: capacityRingOption(rate?.queue_raw_pct ?? null, "队列占用"),
      deliveredCap: capacityRingOption(
        stats?.rate_limit_per_minute
          ? Math.min(100, Math.round(((stats.delivered_this_minute ?? 0) * 100) / stats.rate_limit_per_minute))
          : null,
        "投递额度"
      ),
      rateFunnel: rateFunnelOption(rate),
      rateTrend: rateTrendOption(historyItems),
      queueTrend: queueTrendOption(historyItems, queueMax),
      severity: severityOption(historyItems),
      ruleTop: ruleTopOption(historyItems),
      traffic: overview ? trafficOption(overview) : rateTrendOption([]),
      protocols: protocolPieOption(overview?.protocols),
      dropped: droppedOption(stats),
      pushCounters: pushCountersOption(push),
      esIndices: esIndicesOption(esStatus?.indices),
      logstash: logstashOption(logstash),
      baseline: baselineOption(baseline),
      anomalies: anomalyOption(baseline),
      coverage: coverageOption(coverage),
    }),
    [metrics, rate, stats, push, esStatus, logstash, overview, baseline, coverage, historyItems, queueMax]
  );

  const noHistory = "暂无采样（检测器每 5 分钟写一条，部署后约 5 分钟内出现）";
  const trafficPoints = overview?.traffic?.points ?? [];
  const noTraffic = emptyOrFailed(errs, SRC.overview, "暂无数据（ES 读取失败，或该窗口内没有 conn 日志）");

  return (
    <Card>
      <CardContent className="space-y-5 pt-4">
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={() => void load()} disabled={busy}>
            {busy ? "读取中…" : "刷新"}
          </Button>
          <Button variant="outline" onClick={() => setAuto((v) => !v)}>
            {auto ? "关闭自动刷新" : "开启自动刷新"}
          </Button>
          <span className="text-xs text-muted-foreground">{auto ? "每 15 秒自刷新。" : "自动刷新已关闭。"}</span>
          {health?.checked_at ? (
            <span className="text-xs text-muted-foreground">
              组件探测 {health.checked_at.replace("T", " ").slice(11, 19)}
              {health.cached ? "（缓存）" : ""}
            </span>
          ) : null}
          {overview?.computed_at ? (
            <span className="text-xs text-muted-foreground">
              流量聚合 {overview.computed_at.replace("T", " ").slice(11, 19)}
              {overview.cached ? "（缓存 5 分钟）" : ""}
            </span>
          ) : null}
        </div>

        <PanelError errors={errs} />

        <nav className="flex flex-wrap gap-2 text-xs">
          {ANCHORS.map((a) => (
            <a key={a.id} href={`#${a.id}`} className="rounded-md border px-2 py-1 text-muted-foreground hover:bg-accent">
              {a.label}
            </a>
          ))}
        </nav>

        {/* ---------- A. 服务器状态 ---------- */}
        <Section
          id="server"
          title="服务器状态"
          extra={
            metrics?.notes?.length ? <Badge variant="medium">{metrics.notes.join("；")}</Badge> : null
          }
        >
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Card>
              <CardContent className="pt-4">
                <Chart option={charts.cpu} height={190} />
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <Chart option={charts.mem} height={190} />
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <Chart option={charts.disk} height={190} />
              </CardContent>
            </Card>
          </div>
          <p className="text-xs text-muted-foreground">{bytesLine(metrics) || "指标未读到"}</p>
        </Section>

        {/* ---------- B. 服务与组件状态 ---------- */}
        <Section
          id="components"
          title="服务与组件状态"
          extra={
            errs.isFailed(SRC.health) ? <Badge variant="high">读取失败</Badge> : null
          }
        >
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
            {(health?.items || []).map((item) => (
              <Light key={item.key} item={item} />
            ))}
            {!health?.items?.length ? (
              <p className="text-xs text-muted-foreground">
                {emptyOrFailed(errs, SRC.health, "还没有探测结果")}
              </p>
            ) : null}
          </div>
        </Section>

        {/* ---------- C. 威胁事件 ---------- */}
        <Section id="threats" title="威胁事件">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Kpi label="24h 命中" value={historyItems.length ? hit24h : "—"} hint="各区间增量之和" />
            <Kpi label="24h 摘要" value={historyItems.length ? digest24h : "—"} hint="命中聚合后" />
            <Kpi
              label="投递覆盖率"
              value={
                coverage?.coverage_ratio === null || coverage?.coverage_ratio === undefined
                  ? "—"
                  : `${Math.round(Number(coverage.coverage_ratio) * 100)}%`
              }
              hint={coverage?.stale ? "快照过期，不判警" : `${coverage?.minutes ?? 60} 分钟窗口`}
              danger={Boolean(coverage?.warn)}
            />
            <Kpi
              label="未投递累计"
              value={stats?.dropped?.undelivered ?? push?.status.undelivered ?? "—"}
              hint={push?.config.active ? "推送已启用" : "未配置推送地址"}
              danger={!push?.config.active}
            />
          </div>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <ChartCard title="24h 命中与摘要趋势" option={charts.rateTrend} empty={historyItems.length ? undefined : noHistory} />
            <ChartCard title="24h 严重度分布" option={charts.severity} empty={historyItems.length ? undefined : noHistory} />
            <ChartCard title="规则 TOP 15" option={charts.ruleTop} empty={historyItems.length ? undefined : noHistory} />
          </div>
        </Section>

        {/* ---------- D. 24 小时流量与协议 ---------- */}
        <Section id="traffic" title="24 小时流量与协议">
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <ChartCard
                title="24h 流量捕捉（按小时字节/秒）"
                extra={
                  overview ? (
                    <span className="text-xs font-normal text-muted-foreground">
                      合计 {formatBytes(overview.traffic.total_bytes)} · 均值 {formatBytes(overview.traffic.avg_bytes_per_sec)}/s
                    </span>
                  ) : null
                }
                option={charts.traffic}
                height={260}
                empty={trafficPoints.length ? undefined : noTraffic}
              />
            </div>
            <ChartCard
              title="24h 协议分析占比"
              extra={
                overview && overview.protocols.unclassified_percent > 0 ? (
                  <span className="text-xs font-normal text-muted-foreground">
                    白名单外 {overview.protocols.unclassified_percent}% 只入库不进检测
                  </span>
                ) : null
              }
              option={charts.protocols}
              height={260}
              empty={overview?.protocols?.items?.length ? undefined : noTraffic}
            />
          </div>
        </Section>

        {/* ---------- E. 链路细节 ---------- */}
        <Section id="chain" title="链路细节">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Kpi
              label="归一化队列"
              value={stats?.queue_raw ?? "—"}
              hint={queueMax ? `上限 ${queueMax}` : undefined}
              danger={Boolean(queueMax && (stats?.queue_raw ?? 0) > queueMax * 0.8)}
            />
            <Kpi label="待聚合队列" value={stats?.queue_digest ?? "—"} hint="攒批投递前" />
            <Kpi
              label="本分钟投递"
              value={stats?.delivered_this_minute ?? "—"}
              hint={stats?.rate_limit_per_minute ? `上限 ${stats.rate_limit_per_minute}/分钟` : undefined}
            />
            <Kpi
              label="隔离队列"
              value={stats?.queue_failed ?? "—"}
              hint="处理失败被隔离，不会自动重来"
              danger={Boolean(stats?.queue_failed)}
            />
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <ChartCard title="五段速率（条/分钟）" option={charts.rateFunnel} height={200} />
            <ChartCard title="队列深度趋势" option={charts.queueTrend} empty={historyItems.length ? undefined : noHistory} />
            <div className="grid grid-cols-2 gap-3">
              <Card>
                <CardContent className="pt-4">
                  <Chart option={charts.queueCap} height={180} />
                </CardContent>
              </Card>
              <Card>
                <CardContent className="pt-4">
                  <Chart option={charts.deliveredCap} height={180} />
                </CardContent>
              </Card>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <ChartCard title="丢弃原因分布（累计）" option={charts.dropped} height={200} />
            <ChartCard title="投递 / 重发计数（累计）" option={charts.pushCounters} height={200} />
            <ChartCard title="投递覆盖率" option={charts.coverage} height={200} />
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <ChartCard
              title="ES 索引（按天）文档数与占用"
              option={charts.esIndices}
              empty={esStatus?.indices?.length ? undefined : emptyOrFailed(errs, SRC.es, "暂无索引")}
            />
            <ChartCard title="Logstash 吞吐与采集队列积压" option={charts.logstash} height={220} />
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <ChartCard title="基线维度结构" option={charts.baseline} height={180} />
            <ChartCard
              title="画像风险 TOP"
              option={charts.anomalies}
              height={180}
              empty={baseline?.anomalies.items.length ? undefined : "暂无过阈值画像（观测期内的维度不参与判定）"}
            />
          </div>

          {/* 非量化项：保持文字/徽标，塞进图里反而看不清 */}
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <Badge variant={stats?.enabled ? "info" : "outline"}>{stats?.enabled ? "检测开启" : "检测关闭"}</Badge>
            {stats?.paused ? (
              <Badge variant="critical">
                检测器已暂停消费{stats.paused_since ? `（自 ${stats.paused_since.replace("T", " ").slice(0, 19)}）` : ""}
              </Badge>
            ) : null}
            <span>消费者 {stats?.leader?.holder || "无（选主键过期）"}</span>
            <span>· Redis 淘汰策略 {stats?.redis?.policy || "—"}</span>
            {stats?.handled_skipped ? <span>· 登记丢弃 {stats.handled_skipped}</span> : null}
            {stats?.policy?.internal_routine ? (
              <span>· 策略跳过（内网常规）{stats.policy.internal_routine}</span>
            ) : null}
            {stats?.last_dropped_at ? (
              <span>· 最近丢弃 {stats.last_dropped_at.replace("T", " ").slice(0, 19)}</span>
            ) : null}
            {stats?.dedup ? <span>· 判重：{stats.dedup.note || "已下放到智能体"}</span> : null}
            {wazuh?.status?.agents ? (
              <span>
                · 主机监控 Agent 在线 {wazuh.status.agents.active}/{wazuh.status.agents.total}
              </span>
            ) : null}
            {logstash?.logstash ? (
              <span>
                · Logstash 重载 成功 {logstash.logstash.reloads_successes ?? "—"} / 失败{" "}
                {logstash.logstash.reloads_failures ?? "—"}
              </span>
            ) : null}
            {coverage?.warn_reason ? <span>· {coverage.warn_reason}</span> : null}
          </div>
        </Section>
      </CardContent>
    </Card>
  );
}
