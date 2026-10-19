"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Dialog,
  EmptyState,
  Input,
  LoadingBlock,
  Section,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  apiFetch,
  formatDateTime,
} from "@shentong/ui";
import { formatBytes } from "@/components/status-charts";
import { CheckCircle2, Plus, Trash2, X } from "lucide-react";

import { PanelError, usePanelErrors } from "@/components/panel-error";
import { useAliases } from "@/lib/aliases";

/**
 * 资产中心：发现 / 分组 / 扫描 / 管理 四块共用一份组件（`mode` 决定内容与列）。
 *
 * 口径（2026-10 用户定）：
 * - **发现**：被动发现（只统计镜像流量里出现过的主机，不发探测包）；
 * - **扫描**：同一份被动数据看"暴露面"，不主动发包（生产网段主动扫描需单独授权）；
 * - **分组 / 管理**：人工台账（`asset_groups` / `asset_records`），可增删改。
 *
 * 版式（2026-10 统一到设计体系）：
 * - 每块的标题走共享 `Section`（L1），内容走 `Card`（L2），不再用 `CardTitle` 冒充区块标题；
 * - 表格正文 13px 由 `Table` 内置，`TableCell` 上只保留「等宽 ID / 时间戳」的 `text-xs font-mono`；
 * - 首次加载画骨架，不把"正在读"写成一屏空态。
 */

type Mode = "discovery" | "groups" | "scan" | "manage";

interface PortRow {
  port: number;
  app: string;
  bytes: number;
}

interface HostRow {
  ip: string;
  hostname: string;
  bytes_out: number;
  bytes_in: number;
  bytes_total: number;
  conns: number;
  clients: number;
  ports: PortRow[];
  exposure: number;
  first_seen: string;
  last_seen: string;
  managed: boolean;
}

interface DiscoverResult {
  items: HostRow[];
  managed?: number;
  unmanaged?: number;
  error?: string;
  warning?: string;
  note?: string;
}

interface ScanResult extends DiscoverResult {
  top_ports?: Array<{ label: string; hosts: number }>;
  mode?: string;
}

interface GroupRow {
  id: string;
  name: string;
  color: string;
  note: string;
  assets: number;
}

interface RecordRow {
  id: string;
  ip: string;
  hostname: string;
  group_id: string;
  group_name: string;
  owner: string;
  criticality: string;
  tags: string[];
  note: string;
  updated_at: string;
}

const CRITICALITY_LABEL: Record<string, string> = {
  core: "核心",
  high: "重要",
  normal: "一般",
  test: "测试",
};

const EMPTY_ASSET = {
  ip: "",
  hostname: "",
  group_id: "",
  owner: "",
  criticality: "normal",
  tags: "",
  note: "",
};

export function AssetsPanel({ mode }: { mode: Mode }) {
  const errs = usePanelErrors();
  useAliases();
  const [hosts, setHosts] = React.useState<DiscoverResult | null>(null);
  const [scan, setScan] = React.useState<ScanResult | null>(null);
  const [groups, setGroups] = React.useState<GroupRow[]>([]);
  const [records, setRecords] = React.useState<RecordRow[]>([]);
  const [form, setForm] = React.useState({ ...EMPTY_ASSET });
  const [groupForm, setGroupForm] = React.useState({ name: "", color: "#1d4ed8", note: "" });
  const [q, setQ] = React.useState("");
  const [minutes, setMinutes] = React.useState(1440);
  const [busy, setBusy] = React.useState(false);
  /** 分组 / 台账没有 null 态（初值是空数组），单独记「这一轮读完了没」——首屏骨架据此判断，
   *  否则加载中的 200ms~2s 会被误显示成「还没有分组 / 台账还是空的」。 */
  const [groupsReady, setGroupsReady] = React.useState(false);
  const [recordsReady, setRecordsReady] = React.useState(false);
  /** 台账分页：当前页（0 基）、每页条数、总条数（来自后端 total）。 */
  const [recordsPage, setRecordsPage] = React.useState(0);
  const [recordsSize, setRecordsSize] = React.useState(20);
  const [recordsTotal, setRecordsTotal] = React.useState(0);
  /** 空态里的「新建分组 / 新增资产」直接复用上面的表单：聚焦输入框，不另写创建逻辑。 */
  const groupNameRef = React.useRef<HTMLInputElement>(null);
  const ipInputRef = React.useRef<HTMLInputElement>(null);
  /** 删除类操作统一走共享 `Dialog` 二次确认：原生 `window.confirm` 与全站的弹层材质对不上。 */
  const [pendingDelete, setPendingDelete] = React.useState<
    { kind: "record"; id: string; ip: string } | { kind: "group"; row: GroupRow } | null
  >(null);

  const SRC = {
    hosts: "被动发现（/api/assets/discover）",
    scan: "被动扫描（/api/assets/scan）",
    groups: "资产分组（/api/assets/groups）",
    records: "资产台账（/api/assets/records）",
  };

  const loadGroups = React.useCallback(async () => {
    const res = await apiFetch<{ items: GroupRow[] }>("/api/assets/groups").catch(() => null);
    if (res) {
      errs.clear(SRC.groups);
      setGroups(res.items);
    } else errs.fail(SRC.groups);
    setGroupsReady(true);
  }, [errs, SRC.groups]);

  const loadRecords = React.useCallback(async () => {
    const params = new URLSearchParams();
    if (q.trim()) params.set("q", q.trim());
    params.set("limit", String(recordsSize));
    params.set("offset", String(recordsPage * recordsSize));
    const res = await apiFetch<{ items: RecordRow[]; total: number }>(
      `/api/assets/records?${params.toString()}`,
    ).catch(() => null);
    if (res) {
      errs.clear(SRC.records);
      setRecords(res.items);
      setRecordsTotal(res.total);
    } else errs.fail(SRC.records);
    setRecordsReady(true);
  }, [errs, q, recordsPage, recordsSize, SRC.records]);

  const loadHosts = React.useCallback(async () => {
    const res = await apiFetch<DiscoverResult>(
      `/api/assets/discover?minutes=${minutes}&limit=200`,
    ).catch(() => null);
    if (res) {
      errs.clear(SRC.hosts);
      setHosts(res);
    } else {
      errs.fail(SRC.hosts);
      setHosts(null);
    }
  }, [errs, minutes, SRC.hosts]);

  const loadScan = React.useCallback(async () => {
    const res = await apiFetch<ScanResult>(`/api/assets/scan?minutes=${minutes}&limit=200`).catch(
      () => null,
    );
    if (res) {
      errs.clear(SRC.scan);
      setScan(res);
    } else {
      errs.fail(SRC.scan);
      setScan(null);
    }
  }, [errs, minutes, SRC.scan]);

  React.useEffect(() => {
    if (mode === "discovery") void loadHosts();
    if (mode === "scan") void loadScan();
    if (mode === "groups") void loadGroups();
    if (mode === "manage") {
      void loadRecords();
      void loadGroups();
    }
  }, [mode, loadHosts, loadScan, loadGroups, loadRecords]);

  const addToLedger = React.useCallback(
    async (row: { ip: string; hostname?: string }) => {
      setBusy(true);
      const ok = await apiFetch("/api/assets/records", {
        method: "POST",
        body: JSON.stringify({
          ip: row.ip,
          hostname: row.hostname || "",
          criticality: "normal",
        }),
      })
        .then(() => true)
        .catch(() => false);
      setBusy(false);
      if (ok) {
        if (mode === "discovery") void loadHosts();
        if (mode === "scan") void loadScan();
        if (mode === "manage") void loadRecords();
      }
    },
    [loadHosts, loadRecords, loadScan, mode],
  );

  const deleteRecord = React.useCallback(
    async (id: string) => {
      const ok = await apiFetch(`/api/assets/records/${id}`, { method: "DELETE" })
        .then(() => true)
        .catch(() => false);
      if (ok) void loadRecords();
    },
    [loadRecords],
  );

  const saveRecord = React.useCallback(async () => {
    if (!form.ip.trim()) return;
    setBusy(true);
    const ok = await apiFetch("/api/assets/records", {
      method: "POST",
      body: JSON.stringify(form),
    })
      .then(() => true)
      .catch(() => false);
    setBusy(false);
    if (ok) {
      setForm({ ...EMPTY_ASSET });
      void loadRecords();
    }
  }, [form, loadRecords]);

  const createGroup = React.useCallback(async () => {
    if (!groupForm.name.trim()) return;
    const ok = await apiFetch("/api/assets/groups", {
      method: "POST",
      body: JSON.stringify(groupForm),
    })
      .then(() => true)
      .catch(() => false);
    if (ok) {
      setGroupForm({ name: "", color: "#1d4ed8", note: "" });
      void loadGroups();
    }
  }, [groupForm, loadGroups]);

  const deleteGroup = React.useCallback(
    async (row: GroupRow) => {
      const ok = await apiFetch(`/api/assets/groups/${row.id}`, { method: "DELETE" })
        .then(() => true)
        .catch(() => false);
      if (ok) void loadGroups();
    },
    [loadGroups],
  );

  const timeRangePicker = (
    <label className="text-xs text-muted-foreground">
      统计窗口
      <select
        value={minutes}
        onChange={(e) => setMinutes(Number(e.target.value))}
        className="ml-1 h-8 rounded-md border border-border bg-surface-2 px-2 text-sm text-foreground"
      >
        <option value={60}>1 小时</option>
        <option value={360}>6 小时</option>
        <option value={1440}>24 小时</option>
        <option value={10080}>7 天</option>
      </select>
    </label>
  );

  const hostTable = (rows: HostRow[], showExposure: boolean) => (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>主机名（IP）</TableHead>
          <TableHead>总流量</TableHead>
          <TableHead>连接数</TableHead>
          <TableHead>客户端数</TableHead>
          {showExposure ? <TableHead>暴露端口</TableHead> : null}
          <TableHead>端口 TOP</TableHead>
          <TableHead>首次发现</TableHead>
          <TableHead>最近活跃</TableHead>
          <TableHead>台账</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={row.ip}>
            <TableCell className="whitespace-nowrap">
              <span className="font-medium">{row.hostname || "-"}</span>
              <span className="ml-1 font-mono text-xs text-muted-foreground">({row.ip})</span>
            </TableCell>
            <TableCell className="whitespace-nowrap font-mono tabular-nums">
              {formatBytes(row.bytes_total)}
            </TableCell>
            <TableCell className="tabular-nums">{row.conns}</TableCell>
            <TableCell className="tabular-nums">{row.clients}</TableCell>
            {showExposure ? (
              <TableCell>
                <Badge variant={row.exposure >= 5 ? "critical" : "secondary"}>{row.exposure}</Badge>
              </TableCell>
            ) : null}
            <TableCell className="max-w-[280px]">
              <div className="flex flex-wrap gap-1">
                {row.ports.slice(0, 8).map((p) => (
                  <span
                    key={`${row.ip}-${p.port}`}
                    className="rounded-xs bg-surface-1 px-1.5 py-0.5 text-xs text-muted-foreground"
                  >
                    {p.app}（{p.port}）
                  </span>
                ))}
                {row.ports.length === 0 ? (
                  <span className="text-xs text-muted-foreground">-</span>
                ) : null}
              </div>
            </TableCell>
            <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
              {formatDateTime(row.first_seen)}
            </TableCell>
            <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
              {formatDateTime(row.last_seen)}
            </TableCell>
            <TableCell>
              {row.managed ? (
                <span className="inline-flex items-center gap-1 text-xs text-sev-ok-fg">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  已纳管
                </span>
              ) : (
                <Button size="sm" variant="outline" disabled={busy} onClick={() => void addToLedger(row)}>
                  <Plus className="mr-1 h-3.5 w-3.5" />
                  加入台账
                </Button>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      {mode === "discovery" ? (
        <Section
          title="资产发现（被动）"
          description={
            <>
              已纳管 <span className="tabular-nums">{hosts?.managed ?? "—"}</span> / 未纳管{" "}
              <span className="tabular-nums">{hosts?.unmanaged ?? "—"}</span> · 只统计镜像流量里出现过的主机，不发探测包
            </>
          }
          extra={
            <>
              {timeRangePicker}
              <Button size="sm" variant="outline" onClick={() => void loadHosts()}>
                刷新
              </Button>
            </>
          }
        >
          <Card>
            <CardContent className="p-0">
              {/* 提示条单独包一层内边距：表格要保持「表头贴着卡片上沿」的齐平感 */}
              {hosts?.error || hosts?.warning || hosts?.note ? (
                <div className="space-y-2 px-4 pt-3 pb-3">
                  {hosts?.error ? (
                    <p className="rounded-md border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg">
                      {hosts.error}
                    </p>
                  ) : null}
                  {hosts?.warning ? (
                    <p className="rounded-md border border-sev-medium-bd bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium-fg">
                      {hosts.warning}
                    </p>
                  ) : null}
                  {hosts?.note ? (
                    <p className="rounded-md border border-sev-info-bd bg-sev-info-bg px-3 py-2 text-xs text-sev-info-fg">
                      {hosts.note}
                    </p>
                  ) : null}
                </div>
              ) : null}
              {/* 首屏：接口还没回来、也没有失败 → 画骨架；「正在读」不能写成「没有主机」。 */}
              {hosts === null && !errs.has ? (
                <LoadingBlock className="py-16" />
              ) : (hosts?.items ?? []).length === 0 ? (
                <EmptyState
                  title={
                    errs.isFailed(SRC.hosts)
                      ? "读取失败（见上方错误条）"
                      : "该窗口内没有发现网段内主机"
                  }
                  hint={
                    errs.isFailed(SRC.hosts)
                      ? "后端异常或网络不通，不是「没有数据」"
                      : "被动发现只看镜像流量：确认采集器在跑，或放宽统计窗口后重新读取"
                  }
                  tone={errs.isFailed(SRC.hosts) ? "danger" : "muted"}
                  action={
                    <Button size="sm" variant="outline" onClick={() => void loadHosts()}>
                      重新读取
                    </Button>
                  }
                />
              ) : (
                hostTable(hosts?.items ?? [], false)
              )}
            </CardContent>
          </Card>
        </Section>
      ) : null}

      {mode === "scan" ? (
        <Section
          title="资产扫描（被动模式）"
          description="用已发生的访问推断每台主机的暴露面，不主动发包"
          extra={
            <>
              {timeRangePicker}
              <Button size="sm" variant="outline" onClick={() => void loadScan()}>
                刷新
              </Button>
            </>
          }
        >
          <Card>
            <CardContent className="p-0">
              {scan?.error || scan?.warning || scan?.note || scan?.top_ports?.length ? (
                <div className="space-y-3 px-4 pt-3 pb-3">
                  {scan?.error ? (
                    <p className="rounded-md border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg">
                      {scan.error}
                    </p>
                  ) : null}
                  {scan?.warning ? (
                    <p className="rounded-md border border-sev-medium-bd bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium-fg">
                      {scan.warning}
                    </p>
                  ) : null}
                  {scan?.note ? (
                    <p className="rounded-md border border-sev-medium-bd bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium-fg">
                      {scan.note}
                    </p>
                  ) : null}
                  {scan?.top_ports?.length ? (
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-xs text-muted-foreground">网段内最常见暴露端口：</span>
                      {scan.top_ports.map((p) => (
                        <span
                          key={p.label}
                          className="rounded-xs bg-surface-1 px-2 py-0.5 text-xs text-muted-foreground"
                        >
                          {p.label} · <span className="tabular-nums">{p.hosts}</span> 台
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : null}
              {scan === null && !errs.has ? (
                <LoadingBlock className="py-16" />
              ) : (scan?.items ?? []).length === 0 ? (
                <EmptyState
                  title={
                    errs.isFailed(SRC.scan)
                      ? "读取失败（见上方错误条）"
                      : "该窗口内没有可判定的暴露面"
                  }
                  hint={
                    errs.isFailed(SRC.scan)
                      ? "后端异常或网络不通，不是「没有数据」"
                      : "被动模式只看已发生的访问，不主动发包；可放宽统计窗口后重新读取"
                  }
                  tone={errs.isFailed(SRC.scan) ? "danger" : "muted"}
                  action={
                    <Button size="sm" variant="outline" onClick={() => void loadScan()}>
                      重新读取
                    </Button>
                  }
                />
              ) : (
                hostTable(scan?.items ?? [], true)
              )}
            </CardContent>
          </Card>
        </Section>
      ) : null}

      {mode === "groups" ? (
        <>
          <Section title="新建分组" description="按业务或责任维度给资产归类，供台账与报表使用">
            <Card>
              <CardContent className="flex flex-wrap items-end gap-3 pt-4">
                <label className="text-xs text-muted-foreground">
                  名称
                  <Input
                    ref={groupNameRef}
                    value={groupForm.name}
                    onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })}
                    placeholder="例如：财务系统"
                    className="mt-1 w-52"
                  />
                </label>
                <label className="text-xs text-muted-foreground">
                  色标
                  <Input
                    type="color"
                    value={groupForm.color}
                    onChange={(e) => setGroupForm({ ...groupForm, color: e.target.value })}
                    className="mt-1 h-9 w-16 p-1"
                  />
                </label>
                <label className="min-w-[220px] flex-1 text-xs text-muted-foreground">
                  备注
                  <Input
                    value={groupForm.note}
                    onChange={(e) => setGroupForm({ ...groupForm, note: e.target.value })}
                    placeholder="用途 / 责任人说明"
                    className="mt-1"
                  />
                </label>
                <Button size="sm" onClick={() => void createGroup()}>
                  创建
                </Button>
              </CardContent>
            </Card>
          </Section>
          <Section title={`分组列表（${groups.length}）`}>
            <Card>
              <CardContent className="p-0">
                {!groupsReady ? (
                  <LoadingBlock className="py-16" />
                ) : groups.length === 0 ? (
                  <EmptyState
                    title={
                      errs.isFailed(SRC.groups) ? "读取失败（见上方错误条）" : "还没有分组"
                    }
                    hint={
                      errs.isFailed(SRC.groups)
                        ? "后端异常或网络不通，不是「没有分组」"
                        : '先建一个（例如"办公区""财务系统""对外门户"）'
                    }
                    tone={errs.isFailed(SRC.groups) ? "danger" : "muted"}
                    action={
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => groupNameRef.current?.focus()}
                      >
                        新建分组
                      </Button>
                    }
                  />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>分组</TableHead>
                        <TableHead>色标</TableHead>
                        <TableHead>资产数</TableHead>
                        <TableHead>备注</TableHead>
                        <TableHead>操作</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {groups.map((g) => (
                        <TableRow key={g.id}>
                          <TableCell className="font-medium">{g.name}</TableCell>
                          <TableCell>
                            <span
                              className="inline-block h-3 w-6 rounded-xs border border-border-subtle"
                              style={{ background: g.color || "#cbd5e1" }}
                            />
                          </TableCell>
                          <TableCell className="tabular-nums">{g.assets}</TableCell>
                          <TableCell className="text-muted-foreground">{g.note || "-"}</TableCell>
                          <TableCell>
                            <Button
                              size="sm"
                              variant="ghost"
                              aria-label={`删除分组 ${g.name}`}
                              onClick={() => setPendingDelete({ kind: "group", row: g })}
                            >
                              <Trash2 className="h-3.5 w-3.5 text-sev-critical-fg" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </Section>
        </>
      ) : null}

      {mode === "manage" ? (
        <>
          <Section title="新增资产" description="手工登记的台账：IP、主机名、分组、责任人、重要级别与备注">
            <Card>
              <CardContent className="grid gap-3 pt-4 sm:grid-cols-2 lg:grid-cols-4">
                <label className="text-xs text-muted-foreground">
                  IP
                  <Input
                    ref={ipInputRef}
                    value={form.ip}
                    onChange={(e) => setForm({ ...form, ip: e.target.value })}
                    placeholder="10.1.2.3"
                    className="mt-1 font-mono"
                  />
                </label>
                <label className="text-xs text-muted-foreground">
                  主机名
                  <Input
                    value={form.hostname}
                    onChange={(e) => setForm({ ...form, hostname: e.target.value })}
                    placeholder="portal.example.com"
                    className="mt-1"
                  />
                </label>
                <label className="text-xs text-muted-foreground">
                  分组
                  <select
                    value={form.group_id}
                    onChange={(e) => setForm({ ...form, group_id: e.target.value })}
                    className="mt-1 h-9 w-full rounded-md border border-border bg-surface-2 px-2 text-sm text-foreground"
                  >
                    <option value="">未分组</option>
                    {groups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs text-muted-foreground">
                  重要级别
                  <select
                    value={form.criticality}
                    onChange={(e) => setForm({ ...form, criticality: e.target.value })}
                    className="mt-1 h-9 w-full rounded-md border border-border bg-surface-2 px-2 text-sm text-foreground"
                  >
                    {Object.entries(CRITICALITY_LABEL).map(([k, label]) => (
                      <option key={k} value={k}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs text-muted-foreground">
                  责任人
                  <Input
                    value={form.owner}
                    onChange={(e) => setForm({ ...form, owner: e.target.value })}
                    placeholder="姓名 / 工号"
                    className="mt-1"
                  />
                </label>
                <label className="text-xs text-muted-foreground">
                  标签（逗号分隔）
                  <Input
                    value={form.tags}
                    onChange={(e) => setForm({ ...form, tags: e.target.value })}
                    placeholder="web,prod"
                    className="mt-1"
                  />
                </label>
                <label className="text-xs text-muted-foreground sm:col-span-2">
                  备注
                  <Input
                    value={form.note}
                    onChange={(e) => setForm({ ...form, note: e.target.value })}
                    placeholder="用途说明"
                    className="mt-1"
                  />
                </label>
                <div className="flex items-end">
                  <Button size="sm" disabled={busy} onClick={() => void saveRecord()}>
                    保存
                  </Button>
                </div>
              </CardContent>
            </Card>
          </Section>
          <Section
            title={`资产台账（${recordsTotal}）`}
            extra={
              <>
                <Input
                  aria-label="按 IP / 主机名搜索台账"
                  value={q}
                  onChange={(e) => {
                    setQ(e.target.value);
                    setRecordsPage(0);
                  }}
                  placeholder="按 IP / 主机名搜"
                  className="h-8 w-52"
                />
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setRecordsPage(0);
                    void loadRecords();
                  }}
                >
                  搜索
                </Button>
              </>
            }
          >
            <Card>
              <CardContent className="p-0">
                {!recordsReady ? (
                  <LoadingBlock className="py-16" />
                ) : records.length === 0 ? (
                  <EmptyState
                    title={
                      errs.isFailed(SRC.records)
                        ? "台账读取失败（见上方错误条）"
                        : q.trim()
                          ? "没有匹配的资产"
                          : "台账还是空的"
                    }
                    hint={
                      errs.isFailed(SRC.records)
                        ? "后端异常或网络不通，不是「没有数据」"
                        : q.trim()
                          ? "换个关键词，或清空搜索框看全部"
                          : "去「资产发现」里一键加入，或上面手工新增"
                    }
                    tone={errs.isFailed(SRC.records) ? "danger" : "muted"}
                    action={
                      <Button size="sm" onClick={() => ipInputRef.current?.focus()}>
                        新增资产
                      </Button>
                    }
                  />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>IP</TableHead>
                        <TableHead>主机名</TableHead>
                        <TableHead>分组</TableHead>
                        <TableHead>级别</TableHead>
                        <TableHead>责任人</TableHead>
                        <TableHead>标签</TableHead>
                        <TableHead>更新时间</TableHead>
                        <TableHead>操作</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {records.map((row) => (
                        <TableRow key={row.id}>
                          <TableCell className="font-mono text-xs">{row.ip}</TableCell>
                          <TableCell>{row.hostname || "-"}</TableCell>
                          <TableCell>{row.group_name || "未分组"}</TableCell>
                          <TableCell>
                            <Badge variant={row.criticality === "core" ? "critical" : "secondary"}>
                              {CRITICALITY_LABEL[row.criticality] ?? row.criticality}
                            </Badge>
                          </TableCell>
                          <TableCell>{row.owner || "-"}</TableCell>
                          <TableCell className="text-muted-foreground">
                            {row.tags.length ? row.tags.join(", ") : "-"}
                          </TableCell>
                          <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                            {formatDateTime(row.updated_at)}
                          </TableCell>
                          <TableCell>
                            <Button
                              size="sm"
                              variant="ghost"
                              aria-label={`从台账删除 ${row.ip}`}
                              onClick={() =>
                                setPendingDelete({ kind: "record", id: row.id, ip: row.ip })
                              }
                            >
                              <Trash2 className="h-3.5 w-3.5 text-sev-critical-fg" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                {recordsReady && recordsTotal > 0 ? (
                  <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-3 py-2 text-xs text-muted-foreground">
                    <span>共 {recordsTotal} 条</span>
                    <div className="flex items-center gap-2">
                      <span>每页</span>
                      <select
                        value={recordsSize}
                        onChange={(e) => {
                          setRecordsSize(Number(e.target.value));
                          setRecordsPage(0);
                        }}
                        className="h-7 rounded-md border border-border bg-surface-2 px-1 text-xs text-foreground"
                      >
                        {[20, 50, 100, 200].map((n) => (
                          <option key={n} value={n}>
                            {n}
                          </option>
                        ))}
                      </select>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={recordsPage <= 0}
                        onClick={() => setRecordsPage((p) => Math.max(0, p - 1))}
                      >
                        上一页
                      </Button>
                      <span className="tabular-nums">
                        {recordsPage + 1} / {Math.max(1, Math.ceil(recordsTotal / recordsSize))}
                      </span>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={
                          recordsPage >= Math.max(1, Math.ceil(recordsTotal / recordsSize)) - 1
                        }
                        onClick={() =>
                          setRecordsPage((p) =>
                            Math.min(
                              Math.max(1, Math.ceil(recordsTotal / recordsSize)) - 1,
                              p + 1,
                            ),
                          )
                        }
                      >
                        下一页
                      </Button>
                    </div>
                  </div>
                ) : null}
              </CardContent>
            </Card>
          </Section>
        </>
      ) : null}

      {mode === "manage" && errs.has ? (
        <p className="flex items-center gap-1 text-xs text-muted-foreground">
          <X className="h-3 w-3" />
          读取失败的接口见上方错误条，页面数据可能不是最新。
        </p>
      ) : null}

      <Dialog
        open={pendingDelete !== null}
        title={
          pendingDelete?.kind === "group"
            ? `删除分组「${pendingDelete.row.name}」？`
            : pendingDelete
              ? `从台账删除 ${pendingDelete.ip}？`
              : "确认删除？"
        }
        onClose={() => setPendingDelete(null)}
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button size="sm" variant="outline" onClick={() => setPendingDelete(null)}>
              取消
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => {
                const p = pendingDelete;
                setPendingDelete(null);
                if (!p) return;
                if (p.kind === "record") void deleteRecord(p.id);
                else void deleteGroup(p.row);
              }}
            >
              删除
            </Button>
          </div>
        }
      >
        <p className="text-xs leading-relaxed text-muted-foreground">
          {pendingDelete?.kind === "group" ? (
            <>组内 {pendingDelete.row.assets} 个资产会变成"未分组"。</>
          ) : pendingDelete ? (
            <>不影响流量数据。</>
          ) : null}
        </p>
      </Dialog>
    </div>
  );
}
