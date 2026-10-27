"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Drawer,
  EmptyState,
  Input,
  LoadingBlock,
  Pagination,
  Section,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  apiFetch,
  formatDateTime,
} from "@shentong/ui";
import { Copy, RotateCcw, Search } from "lucide-react";

import { PanelError, usePanelErrors } from "@/components/panel-error";

/** 错误条上显示的人话名（含路径），失败时用它把「读不到」与「真没有」区分开 */
const SRC = { logs: "日志检索（/api/logs/search）" };
import { useAliases } from "@/lib/aliases";

/**
 * 分析中心 → 日志检索（2026-10 改版）：
 * 上面是**检索条件**（时间窗 + 关键字 + 常用归一化字段 + 排序/分页），下面是**日志列表**，
 * 点任意一行，右侧滑出该条的**完整详情**（走 `/api/logs/doc/{id}`，列表本身不带 raw 省带宽）。
 *
 * 为什么字段不写死在页面里：字段清单由后端 `/api/logs/fields` 给（与归一化结构同源），
 * 以后加字段只改后端一处，前端输入框自动跟上。
 */

interface LogField {
  field: string;
  label: string;
}

interface OptionItem {
  value: string;
  label: string;
  count: number;
}

interface Facets {
  log_types: OptionItem[];
  event_types: OptionItem[];
}

interface LogFields {
  text: LogField[];
  num: LogField[];
  index: string;
}

interface LogItem {
  id: string;
  index: string;
  doc: Record<string, unknown>;
}

interface CountItem {
  value: string;
  count: number;
}

interface LogResult {
  total: number;
  took_ms: number;
  items: LogItem[];
  log_types: CountItem[];
  top_src: CountItem[];
  top_dst: CountItem[];
  minutes: number;
  size: number;
  offset: number;
}

const TIME_RANGES: Array<[number, string]> = [
  [15, "最近 15 分钟"],
  [60, "最近 1 小时"],
  [360, "最近 6 小时"],
  [1440, "最近 24 小时"],
  [10080, "最近 7 天"],
];

const PAGE_SIZES = [20, 50, 100, 200];

/** 列表里展示的列（顺序即展示顺序）：字段名与后端 LIST_SOURCE 对应 */
const COLUMNS: Array<[string, string]> = [
  ["@timestamp", "时间"],
  ["log_type", "日志类型"],
  ["event_type", "事件类型"],
  ["src_ip", "源"],
  ["dst_ip", "目的"],
  ["account", "账号"],
  ["hostname", "主机名"],
  ["summary", "摘要"],
];

function cellText(value: unknown): string {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function endpointLabel(doc: Record<string, unknown>): string {
  const dst = cellText(doc.dst_ip);
  const port = doc.dst_port ?? "";
  const src = cellText(doc.src_ip);
  const sport = doc.src_port ?? "";
  return `${src}${sport ? ":" + sport : ""} → ${dst}${port ? ":" + port : ""}`;
}

const EMPTY_FORM = {
  q: "",
  logType: "",
  srcIp: "",
  dstIp: "",
  account: "",
  hostname: "",
  eventType: "",
  uriPath: "",
  dstPort: "",
  statusCode: "",
};

export function LogsPanel() {
  const errs = usePanelErrors();
  useAliases();
  const [fields, setFields] = React.useState<LogFields | null>(null);
  const [facets, setFacets] = React.useState<Facets | null>(null);
  const [form, setForm] = React.useState({ ...EMPTY_FORM });
  const [minutes, setMinutes] = React.useState(60);
  const [size, setSize] = React.useState(50);
  const [order, setOrder] = React.useState<"desc" | "asc">("desc");
  const [offset, setOffset] = React.useState(0);
  const [result, setResult] = React.useState<LogResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [detail, setDetail] = React.useState<LogItem | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);

  React.useEffect(() => {
    void apiFetch<LogFields>("/api/logs/fields")
      .then(setFields)
      .catch(() => setFields(null));
  }, []);

  // 下拉选项：取 ES 里**实际出现过**的类型（带中文名），随时间窗刷新
  React.useEffect(() => {
    void apiFetch<Facets>(`/api/logs/facets?minutes=${minutes}`)
      .then(setFacets)
      .catch(() => setFacets(null));
  }, [minutes]);

  const buildQuery = React.useCallback(
    (nextOffset: number) => {
      const params = new URLSearchParams();
      const put = (key: string, value: string) => {
        if (value.trim()) params.set(key, value.trim());
      };
      put("q", form.q);
      put("log_type", form.logType);
      put("src_ip", form.srcIp);
      put("dst_ip", form.dstIp);
      put("account", form.account);
      put("hostname", form.hostname);
      put("event_type", form.eventType);
      put("uri_path", form.uriPath);
      put("dst_port", form.dstPort);
      put("status_code", form.statusCode);
      params.set("minutes", String(minutes));
      params.set("size", String(size));
      params.set("offset", String(nextOffset));
      params.set("order", order);
      return params.toString();
    },
    [form, minutes, size, order],
  );

  const run = React.useCallback(
    async (nextOffset = 0) => {
      setLoading(true);
      const res = await apiFetch<LogResult>(`/api/logs/search?${buildQuery(nextOffset)}`).catch(
        () => null,
      );
      setLoading(false);
      if (res) {
        errs.clear(SRC.logs);
        setResult(res);
        setOffset(nextOffset);
      } else {
        errs.fail(SRC.logs);
      }
    },
    [buildQuery, errs],
  );

  // 首次进来直接查一次（默认"最近 1 小时"，让人一打开就看到东西）
  React.useEffect(() => {
    void run(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openDetail = React.useCallback(async (item: LogItem) => {
    setDetailLoading(true);
    const res = await apiFetch<LogItem>(
      `/api/logs/doc/${encodeURIComponent(item.id)}?index=${encodeURIComponent(item.index)}`,
    ).catch(() => null);
    setDetailLoading(false);
    setDetail(res ?? item);
  }, []);

  const total = result?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / size));
  // 首次加载（还没有结果、也没有失败）：画骨架。原来这里直接渲染「没有命中日志」，
  // 首屏看起来像查询坏了 —— 空态和加载态必须分开。
  const firstLoad = !result && !errs.isFailed(SRC.logs);

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      {/* L1 区块：标题与「索引 xxx」都交给 Section —— 原来用 CardTitle 冒充区块标题，
          再在标题行里塞一段 12px 灰字，两个层级混在同一行 */}
      <Section
        title={
          <span className="flex items-center gap-2">
            <Search className="h-4 w-4 text-primary" aria-hidden="true" />
            检索条件
          </span>
        }
        description={fields?.index ? `索引 ${fields.index}` : undefined}
      >
        <Card>
          <CardContent className="space-y-2 pt-4">
            <div className="flex flex-wrap items-end gap-2">
              <label className="text-xs text-muted-foreground">
                时间范围
                <select
                  value={minutes}
                  onChange={(e) => setMinutes(Number(e.target.value))}
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
                关键字（全文：URI / 主机名 / 账号 / UA / 摘要…）
                <Input
                  value={form.q}
                  onChange={(e) => setForm({ ...form, q: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void run(0);
                  }}
                  placeholder="例如 /login、evil.example、某 IP 片段"
                  className="mt-1"
                />
              </label>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <label className="text-xs text-muted-foreground">
                日志类型
                <select
                  value={form.logType}
                  onChange={(e) => setForm({ ...form, logType: e.target.value })}
                  className="mt-1 block h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                >
                  <option value="">全部类型</option>
                  {(facets?.log_types ?? []).map((item) => (
                    <option key={item.value} value={item.value}>
                      {item.label} · {item.count}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-muted-foreground">
                事件类型
                <select
                  value={form.eventType}
                  onChange={(e) => setForm({ ...form, eventType: e.target.value })}
                  className="mt-1 block h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                >
                  <option value="">全部事件</option>
                  {/* 界面只显示中文名；值仍是英文标识（查询用） */}
                  {(facets?.event_types ?? []).map((item) => (
                    <option key={item.value} value={item.value}>
                      {item.label} · {item.count}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-muted-foreground">
                源 IP
                <Input
                  value={form.srcIp}
                  onChange={(e) => setForm({ ...form, srcIp: e.target.value })}
                  placeholder="精确匹配"
                  className="mt-1"
                />
              </label>
              <label className="text-xs text-muted-foreground">
                目的 IP
                <Input
                  value={form.dstIp}
                  onChange={(e) => setForm({ ...form, dstIp: e.target.value })}
                  placeholder="精确匹配"
                  className="mt-1"
                />
              </label>
              <label className="text-xs text-muted-foreground">
                账号
                <Input
                  value={form.account}
                  onChange={(e) => setForm({ ...form, account: e.target.value })}
                  placeholder="登录用户"
                  className="mt-1"
                />
              </label>
              <label className="text-xs text-muted-foreground">
                主机名 / 域名
                <Input
                  value={form.hostname}
                  onChange={(e) => setForm({ ...form, hostname: e.target.value })}
                  placeholder="www.example.com"
                  className="mt-1"
                />
              </label>
              <label className="text-xs text-muted-foreground">
                接口路径
                <Input
                  value={form.uriPath}
                  onChange={(e) => setForm({ ...form, uriPath: e.target.value })}
                  placeholder="/api/v1/login"
                  className="mt-1"
                />
              </label>
              <div className="grid grid-cols-2 gap-3">
                <label className="text-xs text-muted-foreground">
                  目的端口
                  <Input
                    value={form.dstPort}
                    onChange={(e) => setForm({ ...form, dstPort: e.target.value })}
                    placeholder="443"
                    className="mt-1"
                  />
                </label>
                <label className="text-xs text-muted-foreground">
                  状态码
                  <Input
                    value={form.statusCode}
                    onChange={(e) => setForm({ ...form, statusCode: e.target.value })}
                    placeholder="404"
                    className="mt-1"
                  />
                </label>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={() => void run(0)} disabled={loading}>
                <Search className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                {loading ? "加载中…" : "搜索"}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setForm({ ...EMPTY_FORM });
                  void run(0);
                }}
              >
                <RotateCcw className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                重置
              </Button>
              <label className="ml-2 text-xs text-muted-foreground">
                排序
                <select
                  value={order}
                  onChange={(e) => setOrder(e.target.value as "desc" | "asc")}
                  className="ml-1 h-8 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                >
                  <option value="desc">时间倒序（最新在前）</option>
                  <option value="asc">时间正序</option>
                </select>
              </label>
              <label className="text-xs text-muted-foreground">
                每页
                <select
                  value={size}
                  onChange={(e) => {
                    setSize(Number(e.target.value));
                    setOffset(0);
                  }}
                  className="ml-1 h-8 rounded-sm border border-input bg-surface-2 px-2 text-13 text-foreground"
                >
                  {PAGE_SIZES.map((n) => (
                    <option key={n} value={n}>
                      {n} 条
                    </option>
                  ))}
                </select>
              </label>
              {result ? (
                <span className="ml-auto text-xs tabular-nums text-muted-foreground">
                  命中 <b className="text-foreground">{total}</b> 条 · 耗时 {result.took_ms} ms
                </span>
              ) : null}
            </div>

            {result?.log_types?.length ? (
              <div className="flex flex-wrap items-center gap-1.5 border-t border-border-subtle pt-2">
                <span className="text-xs text-muted-foreground">这批结果的日志类型：</span>
                {result.log_types.map((it) => (
                  <button
                    key={it.value}
                    type="button"
                    onClick={() => {
                      setForm({ ...form, logType: it.value });
                      void run(0);
                    }}
                    className="rounded-full border border-border-subtle px-2 py-0.5 text-xs text-muted-foreground hover:border-primary/50 hover:text-primary"
                  >
                    {it.value || "(空)"} · {it.count}
                  </button>
                ))}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </Section>

      {/* 列表区块：标题 + 分页放到 Section 的 extra，表格只负责内容 */}
      <Section
        title="日志列表"
        help="从 ES 检索的原始归一化日志"
        extra={
          <Pagination
            page={Math.floor(offset / size)}
            pages={pages}
            total={total}
            size={size}
            onPage={(p) => void run(p * size)}
            onSize={(n) => {
              setSize(n);
              setOffset(0);
            }}
            disabled={loading}
          />
        }
      >
        <Card>
          <CardContent className="p-0">
            {firstLoad ? (
              <LoadingBlock className="py-20" />
            ) : result && result.items.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10 select-none text-center">#</TableHead>
                    {COLUMNS.map(([field, label]) => (
                      <TableHead key={field} className="whitespace-nowrap">
                        {label}
                      </TableHead>
                    ))}
                    <TableHead className="whitespace-nowrap">源 → 目的</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.items.map((item, i) => (
                    <TableRow
                      key={item.id}
                      className="cursor-pointer"
                      onClick={() => void openDetail(item)}
                    >
                      <TableCell className="w-10 select-none text-center tabular-nums text-muted-foreground">
                        {offset + i + 1}
                      </TableCell>
                      {COLUMNS.map(([field]) => (
                        <TableCell
                          key={field}
                          className={
                            // 只有时间戳这一列保留等宽小字（表格正文默认 13px）
                            field === "@timestamp"
                              ? "whitespace-nowrap font-mono text-xs text-muted-foreground"
                              : "max-w-[280px] truncate"
                          }
                        >
                          {field === "@timestamp"
                            ? formatDateTime(String(item.doc[field] ?? item.doc.ts ?? ""))
                            : cellText(item.doc[field])}
                        </TableCell>
                      ))}
                      <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                        {endpointLabel(item.doc)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                title={errs.isFailed(SRC.logs) ? "读取失败（见上方错误条）" : "没有命中日志"}
                hint={
                  errs.isFailed(SRC.logs)
                    ? "点「搜索」重试；后端异常或网络不通时页面上的数字可能不是最新状态"
                    : "放宽时间范围或减少过滤条件"
                }
                tone={errs.isFailed(SRC.logs) ? "danger" : "muted"}
                action={
                  <Button size="sm" variant="outline" onClick={() => void run(0)}>
                    重新查询
                  </Button>
                }
              />
            )}
          </CardContent>
        </Card>
      </Section>

      {/* 详情抽屉：换共享 Drawer（焦点陷阱 / Esc / 锁滚动 / aria-labelledby 都在里面）。
          原来手写的 fixed 遮罩没有焦点陷阱，按 Tab 会跑到背后表格里。 */}
      <Drawer
        open={!!detail}
        onClose={() => setDetail(null)}
        widthClass="w-[560px]"
        title={
          /* 标题节点用 span 而不是 div/p：Drawer 把 title 放进 <h2>，块级元素套在标题里不合语法 */
          <span className="flex min-w-0 flex-col">
            <span className="text-sm font-medium">日志详情</span>
            <span className="truncate font-mono text-xs font-normal text-muted-foreground">
              {detail?.index} · {detail?.id}
            </span>
          </span>
        }
        footer={
          <div className="flex justify-end">
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                void navigator.clipboard?.writeText(JSON.stringify(detail?.doc ?? {}, null, 2))
              }
            >
              <Copy className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
              复制
            </Button>
          </div>
        }
      >
        {detail ? (
          <div className="space-y-3">
            {detailLoading ? <Skeleton className="h-3 w-40" /> : null}
            <div className="grid grid-cols-2 gap-3 text-xs">
              {[
                ["时间", formatDateTime(String(detail.doc["@timestamp"] ?? detail.doc.ts ?? ""))],
                ["日志类型", cellText(detail.doc.log_type)],
                ["事件类型", cellText(detail.doc.event_type)],
                ["源", cellText(detail.doc.src_ip) + (detail.doc.src_port ? ":" + detail.doc.src_port : "")],
                ["目的", cellText(detail.doc.dst_ip) + (detail.doc.dst_port ? ":" + detail.doc.dst_port : "")],
                ["协议", cellText(detail.doc.protocol)],
                ["主机名", cellText(detail.doc.hostname)],
                ["账号", cellText(detail.doc.account)],
                ["状态码", cellText(detail.doc.status_code)],
                ["上行/下行", `${cellText(detail.doc.bytes_out)} / ${cellText(detail.doc.bytes_in)}`],
                ["连接状态", cellText(detail.doc.conn_state)],
                ["严重度", cellText(detail.doc.severity)],
              ].map(([label, value]) => (
                <p key={label} className="flex gap-1">
                  <span className="shrink-0 text-muted-foreground">{label}：</span>
                  <span className="min-w-0 break-all font-mono">{value}</span>
                </p>
              ))}
            </div>
            {detail.doc.summary ? (
              <p className="text-xs">
                <span className="text-muted-foreground">摘要：</span>
                {String(detail.doc.summary)}
              </p>
            ) : null}
            <div>
              <p className="mb-1 text-xs text-muted-foreground">完整内容（原始文档 JSON）</p>
              <pre className="max-h-[60vh] overflow-auto rounded-sm border border-border-subtle bg-surface-1 p-3 text-xs leading-relaxed">
                {JSON.stringify(detail.doc, null, 2)}
              </pre>
            </div>
            {detail.doc.signature ? (
              <Badge variant="secondary">签名：{String(detail.doc.signature)}</Badge>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}

export default LogsPanel;
