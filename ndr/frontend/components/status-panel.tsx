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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Section,
  Stat,
  EmptyState,
  ChartSkeleton,
  StatSkeleton,
  Skeleton,
  formatDateTime,
  ruleText,
  severityText,
  severityVariant,
  apiFetch,
  ApiError,
  errorText,
} from "@shentong/ui";
import type {
  AgentPushPayload,
  BaselinePayload,
  ComponentHealthItem,
  ComponentHealthPayload,
  ComponentState,
  DetectorCoverage,
  DetectorHistory,
  DetectorRate,
  HitEventItem,
  HitEventList,
  DetectorStats,
  EsStatus,
  LogstashStatus,
  StatsOverview,
  TrafficMinutes,
  SystemMetrics,
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
  resourceBarsOption,
  ruleTopOption,
  severityOption,
  minuteTrafficOption,
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
  hits: "命中事件",
  traffic: "近期流量",
  stats: "检测器队列",
  push: "摘要推送",
  baseline: "基线观测",
  es: "Elasticsearch",
  logstash: "Logstash",
  overview: "流量与协议",
} as const;

/** 呼吸灯的配色与文案：ok 静止常亮、degraded 脉冲、down 常亮红（红本身够醒目，不必再动）、
 *  unknown 灰。颜色取严重度语义变量（sev-*），不再是 emerald/amber/red/slate 这类 Tailwind
 *  原色 —— 原色与主色不在同一明度层级，状态灯看起来像贴纸；语义色和徽章、图表共用一套。
 *  单页只允许一个在动的灯：degraded 脉冲、其余静止。 */
const LIGHT_CLS: Record<ComponentState, string> = {
  ok: "bg-sev-ok-fg",
  degraded: "bg-sev-medium-fg st-pulse",
  down: "bg-sev-critical-fg",
  unknown: "bg-muted-foreground/40",
};
const LIGHT_TEXT: Record<ComponentState, string> = {
  ok: "正常",
  degraded: "注意",
  down: "不可用",
  unknown: "未知",
};

/** 指标格：统一走共享 `Stat`（全站同一个实现，见 packages/ui）。
 *  `danger` 是这一页沿用下来的旧写法，这里映射到严重度语义色，避免改 30 处调用点。 */
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
  return <Stat label={label} value={value} hint={hint} tone={danger ? "critical" : "default"} />;
}

/** 「事件内容」里字段名的中文名（用户要求：显示出来的字段一律中文）。
 *  覆盖实测出现过的全部字段（Zeek 与 Suricata EVE 两套命名），未收录的按原名显示。 */
const FIELD_LABELS: Record<string, string> = {
  proxy_user: "代理认证账号",
  ts: "事件时间",
  timestamp: "事件时间",
  uid: "连接标识（Zeek uid）",
  source: "来源",
  app_proto: "应用协议",
  direction: "方向",
  protocol: "协议",
  conn_state: "连接状态",
  signature: "命中签名",
  signature_id: "签名编号（SID）",
  signature_category: "签名类别",
  signature_severity: "签名严重度",
  signature_threat_type: "威胁类型",
  alert_action: "引擎动作",
  payload_printable: "命中载荷",
  summary: "摘要",
  "tls.sni": "TLS 域名（SNI）",
  "tls.version": "TLS 版本",
  tls_version: "TLS 版本",
  "tls.subject": "证书主体",
  "tls.issuerdn": "证书签发者",
  cert_issuer: "证书签发者",
  "tls.serial": "证书序列号",
  "tls.fingerprint": "证书指纹",
  "tls.notbefore": "证书生效时间",
  "tls.notafter": "证书到期时间",
  "tls.session_resumed": "会话复用",
  ja3: "JA3 客户端指纹",
  ja3s: "JA3S 服务端指纹",
  ja4: "JA4 指纹",
  "http.url": "请求 URL",
  "http.hostname": "域名（Host）",
  "http.http_method": "请求方法",
  "http.status": "状态码",
  "http.length": "响应长度",
  "http.protocol": "HTTP 版本",
  "http.http_user_agent": "User-Agent",
  "http.http_content_type": "内容类型",
  "http.http_refer": "来源页（Referer）",
  "http.xff": "代理头（XFF）",
  "http.http_port": "HTTP 端口",
  uri_path: "请求路径",
  query_string: "查询串",
  method: "方法",
  status_code: "状态码",
  user_agent: "User-Agent",
  referer: "来源页",
  content_type: "内容类型",
  body: "请求体",
  resp_body: "响应体",
  req_headers: "请求头",
  account: "账号",
  session_id: "会话 ID",
  query: "DNS 查询名",
  qtype: "查询类型",
  filename: "文件名",
  md5: "MD5",
  sha1: "SHA1",
  sha256: "SHA256",
  // Zeek 原始字段（出现在「其它字段」里）
  client_version: "客户端版本",
  client_ciphers: "客户端密码套件",
  client_comp_methods: "客户端压缩方法",
  client_curves: "客户端曲线",
  client_key_share_groups: "客户端密钥共享组",
  client_supported_versions: "客户端支持版本",
  cipher: "密码套件",
  curve: "椭圆曲线",
  hashalgs: "哈希算法",
  established: "握手完成",
  server_name: "服务器名",
  resumed: "会话复用",
};

/** 不在「事件内容」里重复显示的字段（详情别处已有，或属实现细节）——用户 2026-10 指定。 */
const HIDDEN_FIELDS = new Set([
  "src_ip",
  "src_port",
  "dst_ip",
  "dst_port",
  "dest_ip",
  "dest_port",
  "flow_id",
  "log_type",
  "event_type",
  "timestamp",
  "alert_action",
  "community_id",
  "other_fields",
  "source",
]);

/** 字段名 → 中文名（未收录的按原名，界面其它地方不会出现纯英文标签） */
function fieldLabel(key: string): string {
  return FIELD_LABELS[key] ?? key;
}

/** 事件时间：Zeek 的 `ts` 可能是数字、也可能是字符串化的秒级时间戳（实测 "1791816302.15616"），
 *  统一按北京时间显示；不是时间戳就按原字符串交给共享格式化。 */
function eventTime(value: unknown): string {
  const num = typeof value === "number" ? value : Number(value);
  if (Number.isFinite(num) && num > 1e9) return formatDateTime(new Date(num * 1000));
  return formatDateTime(String(value));
}

/** 严重度文案统一走 `severityText`（共享库唯一来源）。
 *  这里原来自己维护了一份 `{critical:"紧急", info:"提示"}`，和共享库的
 *  `{critical:"严重", info:"信息"}` 不一致 —— 同一条告警在总览页叫"紧急"、
 *  在规则页叫"严重"，运维对不上话。 */
function severityBadge(sev: string): React.ReactElement {
  const key = (sev || "info").toLowerCase();
  return <Badge variant={severityVariant(key)}>{severityText(key)}</Badge>;
}

/** 图表卡片：**统一的高度只有三档**（176 微图 / 224 默认 / 288 主图）。
 *  原来 180/200/220/280/300 五档并存，同一行两张图底部对不齐，整页看起来像
 *  随手拼的。三档配合栅格（ChartCard 内部不再自己算边距），行行等高。
 *
 *  注：页内区块（`Section`）已抽到共享库 —— 全站 20 多个面板以前各写各的区块
 *  标题，同一个产品里"这一屏分几块"的视觉锚点每页都不一样。 */
function ChartCard({
  title,
  extra,
  option,
  height = 224,
  empty,
  merge = false,
}: {
  title: string;
  extra?: React.ReactNode;
  option: React.ComponentProps<typeof Chart>["option"];
  height?: number;
  /** 滚动类图表传 true：合并更新，看起来是连续滚动而不是每次重画 */
  merge?: boolean;
  /** 有值就不画图、显示这段文案（趋势类接口在部署初期本来就是空的） */
  empty?: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-2">
          {title}
          {extra}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {empty ? (
          <EmptyState size="compact" title={empty} />
        ) : (
          <Chart option={option} height={height} />
        )}
      </CardContent>
    </Card>
  );
}

function Light({ item }: { item: ComponentHealthItem }) {
  return (
    <div className="flex items-start gap-2 rounded-xs bg-surface-1 px-3 py-2">
      <span
        aria-hidden
        className={`mt-1 h-2 w-2 shrink-0 rounded-full ${LIGHT_CLS[item.state] || LIGHT_CLS.unknown}`}
      />
      <div className="min-w-0">
        <p className="text-13 text-foreground">
          {item.name}
          <span className="ml-1 text-xs text-muted-foreground">{LIGHT_TEXT[item.state] || item.state}</span>
        </p>
        <p className="break-words text-xs text-muted-foreground">{item.detail || "—"}</p>
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
  const [hits, setHits] = React.useState<HitEventList | null>(null);
  /** 近期流量（线条按秒画，X 轴每分钟一个刻度） */
  const [traffic, setTraffic] = React.useState<TrafficMinutes | null>(null);
  /** 详情弹窗：打开的那条命中事件（含证据） */
  const [hitDetail, setHitDetail] = React.useState<HitEventItem | null>(null);
  const [hitBusy, setHitBusy] = React.useState(false);
  const [hitMsg, setHitMsg] = React.useState("");
  const [whitelistScope, setWhitelistScope] = React.useState<"src" | "src_dst">("src");
  const [stats, setStats] = React.useState<DetectorStats | null>(null);
  const [push, setPush] = React.useState<AgentPushPayload | null>(null);
  const [baseline, setBaseline] = React.useState<BaselinePayload | null>(null);
  const [esStatus, setEsStatus] = React.useState<EsStatus | null>(null);
  const [logstash, setLogstash] = React.useState<LogstashStatus | null>(null);
  const [overview, setOverview] = React.useState<StatsOverview | null>(null);

  /**
   * 打开详情：**必须再拉一次详情接口** —— 列表按设计不带证据（证据只随详情返回），
   * 直接把列表行塞进弹窗会显示「这条命中没有留下样例事件」（2026-10 用户反馈）。
   */
  async function openHitDetail(row: HitEventItem) {
    setHitMsg("");
    setWhitelistScope("src");
    setHitDetail(row); // 先显示已有字段，避免空白等待
    setHitBusy(true);
    try {
      const full = await apiFetch<HitEventItem>(`/api/detector/hits/${row.id}`);
      if (full?.error) {
        setHitMsg(full.error);
        return;
      }
      setHitDetail(full);
    } catch (e) {
      setHitMsg(e instanceof ApiError ? errorText(e.body) : "读取详情失败");
    } finally {
      setHitBusy(false);
    }
  }

  /** 详情弹窗里的动作：忽略 / 加白名单（加白会自动刷新列表与消息） */
  async function hitAction(kind: "ignore" | "whitelist") {
    if (!hitDetail) return;
    setHitBusy(true);
    setHitMsg("");
    try {
      const out = await apiFetch<{
        ok?: boolean;
        filter_id?: string;
        name?: string;
        note?: string;
        error?: string;
      }>(`/api/detector/hits/${hitDetail.id}/${kind}`, {
        method: "POST",
        body: JSON.stringify(kind === "whitelist" ? { scope: whitelistScope } : { reason: "" }),
      });
      if (out.error) {
        setHitMsg(out.error);
        return;
      }
      setHitMsg(
        kind === "ignore"
          ? `已忽略事件 ${hitDetail.id.slice(0, 8)}（行保留，可在数据库/接口查回）`
          : `已加白名单「${out.name || ""}」：库里降噪 → 排除过滤器可查可撤`,
      );
      setHitDetail(null);
      await load();
    } catch (e) {
      setHitMsg(e instanceof ApiError ? errorText(e.body) : "操作失败");
    } finally {
      setHitBusy(false);
    }
  }

  async function load() {
    errs.reset();
    await Promise.all([
      loadInto(errs, SRC.metrics, "/api/system/metrics", setMetrics),
      loadInto(errs, SRC.health, "/api/health/components", setHealth),
      loadInto(errs, SRC.history, "/api/detector/history?limit=288", setHistory),
      loadInto(errs, SRC.rate, "/api/detector/rate", setRate),
      loadInto(errs, SRC.coverage, "/api/detector/coverage", setCoverage),
      loadInto(errs, SRC.hits, "/api/detector/hits?limit=50", setHits),
      loadInto(errs, SRC.traffic, "/api/stats/traffic?minutes=30", setTraffic),
      loadInto(errs, SRC.stats, "/api/detector/stats", setStats),
      loadInto(errs, SRC.push, "/api/agent-push", setPush),
      loadInto(errs, SRC.baseline, "/api/baseline", setBaseline),
      loadInto(errs, SRC.es, "/api/es/status", setEsStatus),
      loadInto(errs, SRC.logstash, "/api/logstash", setLogstash),
      loadInto(errs, SRC.overview, "/api/stats/overview?hours=24", setOverview),
    ]);
  }

  React.useEffect(() => {
    void load();
    // 只在挂载时取一次；后续节奏由下面的定时器控制
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 运营中心**强制 5 秒**刷新（用户口径：不给刷新/关闭按钮，避免有人关掉后看到陈旧数据）。
  // 服务端对流量聚合有 30 秒进程内缓存，所以 5 秒轮询不会把 ES 打穿。
  React.useEffect(() => {
    const timer = setInterval(() => void load(), 5000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
      // 温度计式横条：左边类型、中间条、右边百分比，CPU/内存/磁盘自上而下
      resource: resourceBarsOption(
        metrics?.cpu_percent ?? null,
        metrics?.mem_percent ?? null,
        metrics?.disk_percent ?? null,
      ),
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
      traffic: minuteTrafficOption(traffic),
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
  // 仪表盘右上角的大数字：最近一格（跳过不完整的那格）+ 峰值
  const { trafficSendRate, trafficRecvRate, trafficPeak, trafficDropsTotal, trafficDropRate } =
    React.useMemo(() => {
    const pts = traffic?.points ?? [];
    const last = [...pts].reverse().find((p) => !p.partial) ?? pts[pts.length - 1];
    return {
      // 每秒口径：桶内总量 ÷ 桶秒数（原来直接用桶内总量，虚高 20 倍）
      trafficSendRate: last?.bytes_out_per_sec ?? Math.round((last?.bytes_out ?? 0) / (traffic?.interval_seconds || 20)),
      trafficRecvRate: last?.bytes_in_per_sec ?? Math.round((last?.bytes_in ?? 0) / (traffic?.interval_seconds || 20)),
      trafficPeak: traffic?.peak_bytes_per_sec ?? 0,
      trafficDropsTotal: traffic?.pkts_dropped_total ?? 0,
      trafficDropRate: traffic?.drop_rate ?? 0,
    };
  }, [traffic]);

  const noTraffic = emptyOrFailed(errs, SRC.overview, "暂无数据（ES 读取失败，或该窗口内没有 conn 日志）");

  /**
   * 首次加载：十几个接口一个都还没回来、也没有失败。这时**不能**按「暂无数据」渲染 ——
   * 运维看到 18 个空图 + 一排 "—"，会以为采集链路断了。画骨架，等数据到了再换成真图。
   * （这一页强制 5 秒轮询，所以只有第一次会命中；后续刷新保持旧数据不闪。）
   */
  const firstLoad =
    !metrics &&
    !health &&
    !history &&
    !overview &&
    !stats &&
    !esStatus &&
    !logstash &&
    !traffic &&
    !errs.has;

  if (firstLoad) {
    return (
      <div className="space-y-6" aria-busy="true">
        <Section id="overview" title="态势总览">
          <StatSkeleton count={4} />
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-3">
            <Card>
              <CardContent className="pt-3">
                <ChartSkeleton height={176} />
              </CardContent>
            </Card>
            <Card className="xl:col-span-2">
              <CardContent className="grid grid-cols-2 gap-2 pt-3 sm:grid-cols-4">
                {Array.from({ length: 8 }).map((_, i) => (
                  <Skeleton key={i} className="h-12" />
                ))}
              </CardContent>
            </Card>
          </div>
        </Section>
        <Section id="threats" title="威胁事件">
          <StatSkeleton count={4} />
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Card key={i}>
                <CardContent className="pt-4">
                  <ChartSkeleton height={288} />
                </CardContent>
              </Card>
            ))}
          </div>
        </Section>
      </div>
    );
  }

  return (
    /* L0 页面容器：这里**不再包一层 Card**。原来外层 Card 只是给整页加了一圈描边，
       结果每个区块又各自是 Card —— 三层描边叠在一起，桌面像被切成一块块贴纸。
       页面本身就是容器，区块直接落在 canvas 上；留白给 24px（区间距）。 */
    <div className="space-y-6">
        <PanelError errors={errs} />

        {/* ---------- 一、态势总览：先回答「现在好不好、有没有事」 ----------
            原来这一屏被拆成「资源状态 / 服务与组件状态 / 威胁事件 KPI」三个独立区块，
            各自带标题、各自留白，一屏只能看到三个孤立的数字，读不出关系。
            现在合成一条态势带：上面四个关键指标横向对齐，下面左边资源、右边组件，
            眼睛自上而下一次扫完，再往下才是需要逐项排查的细节。 */}
        <Section
          id="overview"
          title="态势总览"
          extra={
            metrics?.notes?.length ? <Badge variant="medium">{metrics.notes.join("；")}</Badge> : null
          }
        >
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

          <div className="grid grid-cols-1 gap-3 xl:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle>服务器资源</CardTitle>
              </CardHeader>
              <CardContent>
                <Chart option={charts.resource} height={176} />
                <p className="mt-2 text-xs text-muted-foreground">{bytesLine(metrics) || "指标未读到"}</p>
              </CardContent>
            </Card>

            <Card className="xl:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="flex flex-wrap items-center gap-2">
                  服务与组件
                  {errs.isFailed(SRC.health) ? <Badge variant="high">读取失败</Badge> : null}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {(health?.items || []).map((item) => (
                    <Light key={item.key} item={item} />
                  ))}
                  {health?.items?.length ? null : (
                    <p className="text-xs text-muted-foreground">
                      {emptyOrFailed(errs, SRC.health, "还没有探测结果")}
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </Section>

        {/* ---------- 二、威胁事件 ---------- */}
        <Section id="threats" title="威胁事件">
          {/* 一张主图 + 一张配套图：趋势占 2/3，严重度分布占 1/3。
              原来是三张等宽等高的图并排，读者分不清先看哪张。 */}
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <ChartCard
                title="24h 命中与摘要趋势"
                option={charts.rateTrend}
                height={288}
                empty={historyItems.length ? undefined : noHistory}
              />
            </div>
            <ChartCard
              title="24h 严重度分布"
              option={charts.severity}
              height={288}
              empty={historyItems.length ? undefined : noHistory}
            />
          </div>
          {/* 规则 TOP 15 独占一行：规则名长，横条图给足宽度才不用截断 */}
          <ChartCard
            title="规则 TOP 15"
            option={charts.ruleTop}
            height={224}
            empty={historyItems.length ? undefined : noHistory}
          />

          {/* 命中事件：每条都有**系统唯一事件 ID**（存 PG），可看详情/证据、可忽略、可加白名单。
              为什么不再用 Redis 流水：事件要能被长期引用与关联分析（用户 2026-10 要求）。 */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex flex-wrap items-center gap-2">
                命中事件（最近）
                {hits?.total ? (
                  <span className="text-xs font-normal text-muted-foreground">
                    共 {hits.total} 条 · 每条有唯一事件 ID · 点「详情」看证据
                  </span>
                ) : null}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {hitMsg ? <p className="mb-2 text-xs text-muted-foreground">{hitMsg}</p> : null}
              {hits?.items?.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>最近时间</TableHead>
                      <TableHead>事件 ID</TableHead>
                      <TableHead>规则</TableHead>
                      <TableHead>严重度</TableHead>
                      <TableHead>请求方</TableHead>
                      <TableHead className="text-right">次数</TableHead>
                      <TableHead>目的（IP:端口）</TableHead>
                      <TableHead className="text-right">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {hits.items.map((row) => (
                      <TableRow key={row.id}>
                        <TableCell className="whitespace-nowrap">
                          {formatDateTime(row.last_seen || row.created_at)}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          <span title={row.id}>{row.id.slice(0, 8)}</span>
                        </TableCell>
                        <TableCell>
                          {ruleText(row.rule) || "—"}
                          {row.ignored ? (
                            <Badge variant="outline" className="ml-1">
                              已忽略
                            </Badge>
                          ) : null}
                          {row.whitelist_id ? (
                            <Badge variant="outline" className="ml-1">
                              已加白
                            </Badge>
                          ) : null}
                        </TableCell>
                        <TableCell>{severityBadge(row.severity)}</TableCell>
                        <TableCell>
                          {/* 真实请求方优先：中继链路上 src_ip 是代理/WAF 自己 */}
                          <span title={row.client_source === "xff" ? "来自可信代理头（XFF/X-Real-IP）" : "直连对端"}>
                            {row.client || row.src_ip || "—"}
                          </span>
                          {row.via ? (
                            <span
                              className="ml-1 text-muted-foreground"
                              title={`这一跳经过 ${row.via}（代理/中继），它不是发起方`}
                            >
                              经 {row.via}
                            </span>
                          ) : null}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {row.count}
                        </TableCell>
                        <TableCell className="max-w-[20rem] text-muted-foreground">
                          {row.dst_pairs?.length
                            ? row.dst_pairs.slice(0, 3).join("、") +
                              (row.dst_pairs.length > 3 ? ` 等 ${row.dst_pairs.length} 个` : "")
                            : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void openHitDetail(row)}
                          >
                            详情
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <p className="text-xs text-muted-foreground">
                  {hits?.error ? `读取失败：${hits.error}` : "还没有命中事件（检测器未运行，或还没到聚合窗口）"}
                </p>
              )}

              {/* 详情弹窗：事件信息 + 证据样例 + 忽略 / 加白名单 */}
              <Dialog
                open={hitDetail !== null}
                title="命中事件详情"
                onClose={() => setHitDetail(null)}
                footer={
                  <div className="flex flex-wrap items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={hitBusy}
                      onClick={() => void hitAction("ignore")}
                    >
                      忽略这条
                    </Button>
                    <select
                      className="h-8 rounded-md border bg-transparent px-2 text-xs"
                      value={whitelistScope}
                      onChange={(e) => setWhitelistScope(e.target.value as "src" | "src_dst")}
                    >
                      <option value="src">白名单：同源 + 同规则</option>
                      <option value="src_dst">白名单：同源 + 同规则 + 同目的</option>
                    </select>
                    <Button size="sm" disabled={hitBusy} onClick={() => void hitAction("whitelist")}>
                      加入白名单
                    </Button>
                  </div>
                }
              >
                {hitDetail ? (
                  <div className="space-y-3 text-xs">
                    <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
                      <div>
                        <span className="text-muted-foreground">事件 ID：</span>
                        <span className="font-mono">{hitDetail.id}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">规则：</span>
                        {ruleText(hitDetail.rule)}
                        <span className="ml-1 text-muted-foreground">
                          （{severityText(hitDetail.severity)}）
                        </span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">首次/最近：</span>
                        {formatDateTime(hitDetail.first_seen)} / {formatDateTime(hitDetail.last_seen)}
                      </div>
                      <div>
                        <span className="text-muted-foreground">次数：</span>
                        {hitDetail.count}
                      </div>
                      <div>
                        <span className="text-muted-foreground">请求方：</span>
                        {hitDetail.client || hitDetail.src_ip}
                        {hitDetail.via ? `（经 ${hitDetail.via}）` : ""}
                      </div>
                      <div>
                        <span className="text-muted-foreground">目的：</span>
                        {hitDetail.dst_pairs?.length ? hitDetail.dst_pairs.join("、") : "无"}
                      </div>
                      <div>
                        <span className="text-muted-foreground">事件类型：</span>
                        {hitDetail.event_types?.length ? hitDetail.event_types.join("、") : "无"}
                      </div>
                      <div>
                        <span className="text-muted-foreground">连接状态：</span>
                        {hitDetail.conn_states?.length
                          ? hitDetail.conn_states.join("、")
                          : hitDetail.log_types?.includes("suricata")
                            ? "不适用（签名引擎告警不带连接状态）"
                            : "未记录"}
                      </div>
                      {hitDetail.real_client_ips?.length ? (
                        <div className="sm:col-span-2">
                          <span className="text-muted-foreground">代理头里的真实客户端：</span>
                          {hitDetail.real_client_ips.join("、")}
                        </div>
                      ) : null}
                      {hitDetail.ignored_reason ? (
                        <div className="sm:col-span-2">
                          <span className="text-muted-foreground">处理记录：</span>
                          {hitDetail.ignored_reason}
                        </div>
                      ) : null}
                    </div>
                    <div>
                      <p className="mb-1 font-medium">事件内容</p>
                      {hitDetail.evidence?.length ? (
                        <div className="space-y-2">
                          {hitDetail.evidence.map((ev, i) => {
                            const at = ev["ts"] ?? ev["timestamp"];
                            return (
                              <div key={i} className="rounded-md border px-2 py-1">
                                <div className="mb-1 text-muted-foreground">
                                  样例 {i + 1}
                                  {at !== undefined && at !== null ? ` · ${eventTime(at)}` : ""}
                                  {ev["source"] ? ` · 来源 ${String(ev["source"])}` : ""}
                                </div>
                                <div className="grid grid-cols-1 gap-x-3 sm:grid-cols-2">
                                  {Object.entries(ev)
                                    .filter(([k]) => !HIDDEN_FIELDS.has(k))
                                    .map(([k, v]) => (
                                      <div key={k} className="truncate" title={`${fieldLabel(k)}：${String(v)}`}>
                                        <span className="text-muted-foreground">{fieldLabel(k)}：</span>
                                        <span className="font-mono">{String(v)}</span>
                                      </div>
                                    ))}
                                </div>
                                {Array.isArray(ev["other_fields"]) && ev["other_fields"].length ? (
                                  <div className="mt-1 text-muted-foreground">
                                    其它字段：
                                    {(ev["other_fields"] as string[]).map((k) => fieldLabel(k)).join("、")}
                                  </div>
                                ) : null}
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <p className="text-muted-foreground">这条命中没有留下样例事件</p>
                      )}
                    </div>
                  </div>
                ) : null}
              </Dialog>
            </CardContent>
          </Card>
        </Section>

        {/* ---------- 三、24 小时流量与协议 ---------- */}
        <Section id="traffic" title="24 小时流量与协议">
          {/* 原来 6 项口径数字全塞在卡片标题右边，标题被挤成一长条灰字，
              读者不知道从哪看起。拆成 4 个指标格，口径说明降到提示行。 */}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Kpi
              label="实时发送"
              value={`${formatBytes(trafficSendRate)}/s`}
              hint="最近一个完整采样桶"
            />
            <Kpi
              label="实时接收"
              value={`${formatBytes(trafficRecvRate)}/s`}
              hint="最近一个完整采样桶"
            />
            <Kpi
              label="峰值"
              value={`${formatBytes(trafficPeak)}/s`}
              hint={`近半小时均值 ${formatBytes(traffic?.avg_recent_bytes_per_sec ?? 0)}/s`}
            />
            <Kpi
              label="掉包率"
              value={`${trafficDropRate}%`}
              hint={`近半小时 ${trafficDropsTotal} 包 · 24h ${overview?.traffic?.day_drop_rate ?? 0}%（丢包 ${overview?.traffic?.pkts_dropped_total ?? 0} 包）`}
              danger={Number(trafficDropRate) >= 1}
            />
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <ChartCard
                title="近期流量"
                option={charts.traffic}
                merge
                height={288}
                empty={trafficPoints.length ? undefined : noTraffic}
              />
            </div>
            <ChartCard
              title="24h 协议分析占比"
              extra={
                overview && overview.protocols.excluded_percent > 0 ? (
                  /* 口径说明：这张图只算「协议识别」类日志，另有 conn 流记录/异常/主机
                     日志等非协议日志没算进来——不写明会被当成「漏了」。 */
                  <span className="text-xs font-normal text-muted-foreground">
                    另 {overview.protocols.excluded_percent}% 为非协议日志，未计入
                  </span>
                ) : null
              }
              option={charts.protocols}
              height={288}
              empty={overview?.protocols?.items?.length ? undefined : noTraffic}
            />
          </div>
        </Section>

        {/* ---------- 四、链路细节 ---------- */}
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
            <ChartCard title="五段速率（条/分钟）" option={charts.rateFunnel} height={224} />
            <ChartCard
              title="队列深度趋势"
              option={charts.queueTrend}
              height={224}
              empty={historyItems.length ? undefined : noHistory}
            />
            {/* 两个圆环合并进一张卡：原来是两张独立卡片并排，同样的标题区重复两次，
                视觉上像两张缩略图。现在一张卡两个表盘，读的是同一件事（额度用了多少）。 */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle>容量占用</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-2">
                  <Chart option={charts.queueCap} height={176} />
                  <Chart option={charts.deliveredCap} height={176} />
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            <ChartCard title="丢弃原因分布（累计）" option={charts.dropped} height={224} />
            <ChartCard title="投递 / 重发计数（累计）" option={charts.pushCounters} height={224} />
            <ChartCard title="投递覆盖率" option={charts.coverage} height={224} />
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <ChartCard
              title="ES 索引（按天）文档数与占用"
              option={charts.esIndices}
              height={224}
              empty={esStatus?.indices?.length ? undefined : emptyOrFailed(errs, SRC.es, "暂无索引")}
            />
            <ChartCard title="Logstash 吞吐与采集队列积压" option={charts.logstash} height={224} />
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <ChartCard
              title="基线维度结构"
              extra={
                baseline ? (
                  <span className="text-xs font-normal text-muted-foreground">
                    观测期 {baseline.observe_days} 天 · 已预热 {baseline.stats.warmed_keys} /
                    {baseline.stats.total_keys} 个维度
                  </span>
                ) : null
              }
              option={charts.baseline}
              height={224}
            />
            <ChartCard
              title="画像风险 TOP"
              extra={
                /* 口径：只列账号画像（会话展示名是 cookie 哈希，运维看不懂），
                   标签带服务端 IP；风险分是「当前窗口」的值（本轮无理由就归零）。 */
                <span className="text-xs font-normal text-muted-foreground">
                  只列账号画像；风险分按当前窗口算，本轮无理由即归零
                </span>
              }
              option={charts.anomalies}
              height={224}
              empty={
                baseline?.anomalies.items.length
                  ? undefined
                  : "暂无过阈值画像（风险分按当前窗口算；观测期内的维度不参与判定）"
              }
            />
          </div>

          {/* 非量化项原来是**一整条裸文字**串在图下面（消费者 / 淘汰策略 / 登记丢弃 /
              策略跳过 / 判重 / 重载…），横着排成一长行灰字，混在图表之间既不像图也不像表。
              改成定义列表：左标签右值，多列对齐，扫读时能按标签找。 */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex flex-wrap items-center gap-2">
                运行信息
                <Badge variant={stats?.enabled ? "success" : "outline"}>
                  {stats?.enabled ? "检测开启" : "检测关闭"}
                </Badge>
                {stats?.paused ? (
                  <Badge variant="critical">
                    已暂停消费{stats.paused_since ? `（自 ${formatDateTime(stats.paused_since)}）` : ""}
                  </Badge>
                ) : null}
                {coverage?.warn_reason ? <Badge variant="high">{coverage.warn_reason}</Badge> : null}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-1 gap-x-8 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-3">
                <div className="flex min-w-0 gap-2">
                  <dt className="shrink-0 text-muted-foreground">消费者</dt>
                  <dd className="truncate font-mono">{stats?.leader?.holder || "无（选主键过期）"}</dd>
                </div>
                <div className="flex min-w-0 gap-2">
                  <dt className="shrink-0 text-muted-foreground">Redis 淘汰策略</dt>
                  <dd className="truncate font-mono">{stats?.redis?.policy || "—"}</dd>
                </div>
                <div className="flex min-w-0 gap-2">
                  <dt className="shrink-0 text-muted-foreground">判重</dt>
                  <dd className="truncate">{stats?.dedup ? stats.dedup.note || "已下放到智能体" : "—"}</dd>
                </div>
                {stats?.handled_skipped ? (
                  <div className="flex min-w-0 gap-2">
                    <dt className="shrink-0 text-muted-foreground">登记丢弃</dt>
                    <dd className="truncate tabular-nums">{stats.handled_skipped}</dd>
                  </div>
                ) : null}
                {stats?.policy?.internal_routine ? (
                  <div className="flex min-w-0 gap-2">
                    <dt className="shrink-0 text-muted-foreground">策略跳过（内网常规）</dt>
                    <dd className="truncate tabular-nums">{stats.policy.internal_routine}</dd>
                  </div>
                ) : null}
                {stats?.last_dropped_at ? (
                  <div className="flex min-w-0 gap-2">
                    <dt className="shrink-0 text-muted-foreground">最近丢弃</dt>
                    <dd className="truncate tabular-nums">{formatDateTime(stats.last_dropped_at)}</dd>
                  </div>
                ) : null}
                {logstash?.logstash ? (
                  <div className="flex min-w-0 gap-2">
                    <dt className="shrink-0 text-muted-foreground">Logstash 重载</dt>
                    <dd className="truncate tabular-nums">
                      成功 {logstash.logstash.reloads_successes ?? "—"} / 失败{" "}
                      {logstash.logstash.reloads_failures ?? "—"}
                    </dd>
                  </div>
                ) : null}
              </dl>
            </CardContent>
          </Card>
        </Section>
    </div>
  );
}
