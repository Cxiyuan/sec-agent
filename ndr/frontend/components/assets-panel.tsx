"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Input,
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
import { Boxes, CheckCircle2, Plus, ScanSearch, Trash2, X } from "lucide-react";

import { PanelError, usePanelErrors } from "@/components/panel-error";
import { useAliases } from "@/lib/aliases";

/**
 * 资产中心：发现 / 分组 / 扫描 / 管理 四块共用一份组件（`mode` 决定内容与列）。
 *
 * 口径（2026-10 用户定）：
 * - **发现**：被动发现（只统计镜像流量里出现过的主机，不发探测包）；
 * - **扫描**：同一份被动数据看"暴露面"，不主动发包（生产网段主动扫描需单独授权）；
 * - **分组 / 管理**：人工台账（`asset_groups` / `asset_records`），可增删改。
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
  }, [errs, SRC.groups]);

  const loadRecords = React.useCallback(async () => {
    const params = new URLSearchParams();
    if (q.trim()) params.set("q", q.trim());
    const res = await apiFetch<{ items: RecordRow[]; total: number }>(
      `/api/assets/records?${params.toString()}`,
    ).catch(() => null);
    if (res) {
      errs.clear(SRC.records);
      setRecords(res.items);
    } else errs.fail(SRC.records);
  }, [errs, q, SRC.records]);

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
    async (id: string, ip: string) => {
      if (!window.confirm(`从台账里删除 ${ip}？（不影响流量数据）`)) return;
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
      if (!window.confirm(`删除分组「${row.name}」？组内 ${row.assets} 个资产会变成"未分组"。`)) return;
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
        className="ml-1 h-8 rounded-md border bg-card px-2 text-sm text-foreground"
      >
        <option value={60}>1 小时</option>
        <option value={360}>6 小时</option>
        <option value={1440}>24 小时</option>
        <option value={10080}>7 天</option>
      </select>
    </label>
  );

  const hostTable = (rows: HostRow[], showExposure: boolean) => (
    <div className="overflow-x-auto">
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
              <TableCell className="whitespace-nowrap font-mono text-xs">
                {formatBytes(row.bytes_total)}
              </TableCell>
              <TableCell className="text-xs">{row.conns}</TableCell>
              <TableCell className="text-xs">{row.clients}</TableCell>
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
                      className="rounded border px-1.5 py-0.5 text-[10px] text-muted-foreground"
                    >
                      {p.app}（{p.port}）
                    </span>
                  ))}
                  {row.ports.length === 0 ? (
                    <span className="text-xs text-muted-foreground">-</span>
                  ) : null}
                </div>
              </TableCell>
              <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                {formatDateTime(row.first_seen)}
              </TableCell>
              <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                {formatDateTime(row.last_seen)}
              </TableCell>
              <TableCell>
                {row.managed ? (
                  <span className="inline-flex items-center gap-1 text-xs text-emerald-600">
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
    </div>
  );

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      {mode === "discovery" ? (
        <Card>
          <CardHeader className="flex-row flex-wrap items-center justify-between gap-2 pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <ScanSearch className="h-4 w-4 text-primary" />
              资产发现（被动）
              <span className="text-xs font-normal text-muted-foreground">
                已纳管 {hosts?.managed ?? 0} / 未纳管 {hosts?.unmanaged ?? 0}
              </span>
            </CardTitle>
            <div className="flex items-center gap-2">
              {timeRangePicker}
              <Button size="sm" variant="outline" onClick={() => void loadHosts()}>
                刷新
              </Button>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {hosts?.note ? (
              <p className="mx-4 mb-2 mt-2 rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-xs text-sky-700">
                {hosts.note}
              </p>
            ) : null}
            {hostTable(hosts?.items ?? [], false)}
            {(hosts?.items ?? []).length === 0 ? (
              <p className="px-4 py-10 text-center text-sm text-muted-foreground">
                {errs.has ? "读取失败（见上方错误条）" : "该窗口内没有发现网段内主机"}
              </p>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      {mode === "scan" ? (
        <Card>
          <CardHeader className="flex-row flex-wrap items-center justify-between gap-2 pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <ScanSearch className="h-4 w-4 text-primary" />
              资产扫描（被动模式）
            </CardTitle>
            <div className="flex items-center gap-2">
              {timeRangePicker}
              <Button size="sm" variant="outline" onClick={() => void loadScan()}>
                刷新
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3 p-0">
            {scan?.note ? (
              <p className="mx-4 mt-2 rounded-md border border-amber-300/60 bg-amber-50 px-3 py-2 text-xs text-amber-700">
                {scan.note}
              </p>
            ) : null}
            {scan?.top_ports?.length ? (
              <div className="mx-4 flex flex-wrap items-center gap-1.5">
                <span className="text-xs text-muted-foreground">网段内最常见暴露端口：</span>
                {scan.top_ports.map((p) => (
                  <span key={p.label} className="rounded border px-2 py-0.5 text-[11px] text-muted-foreground">
                    {p.label} · {p.hosts} 台
                  </span>
                ))}
              </div>
            ) : null}
            {hostTable(scan?.items ?? [], true)}
          </CardContent>
        </Card>
      ) : null}

      {mode === "groups" ? (
        <>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Plus className="h-4 w-4 text-primary" />
                新建分组
              </CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap items-end gap-2">
              <label className="text-xs text-muted-foreground">
                名称
                <Input
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
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Boxes className="h-4 w-4 text-primary" />
                分组列表（{groups.length}）
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
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
                          className="inline-block h-3 w-6 rounded"
                          style={{ background: g.color || "#cbd5e1" }}
                        />
                      </TableCell>
                      <TableCell className="text-xs">{g.assets}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{g.note || "-"}</TableCell>
                      <TableCell>
                        <Button size="sm" variant="ghost" onClick={() => void deleteGroup(g)}>
                          <Trash2 className="h-3.5 w-3.5 text-destructive" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {groups.length === 0 ? (
                <p className="px-4 py-10 text-center text-sm text-muted-foreground">
                  还没有分组：先建一个（例如"办公区""财务系统""对外门户"）
                </p>
              ) : null}
            </CardContent>
          </Card>
        </>
      ) : null}

      {mode === "manage" ? (
        <>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Plus className="h-4 w-4 text-primary" />
                新增资产
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <label className="text-xs text-muted-foreground">
                IP
                <Input
                  value={form.ip}
                  onChange={(e) => setForm({ ...form, ip: e.target.value })}
                  placeholder="10.1.2.3"
                  className="mt-1"
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
                  className="mt-1 h-9 w-full rounded-md border bg-card px-2 text-sm text-foreground"
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
                  className="mt-1 h-9 w-full rounded-md border bg-card px-2 text-sm text-foreground"
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
          <Card>
            <CardHeader className="flex-row items-center justify-between gap-2 pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Boxes className="h-4 w-4 text-primary" />
                资产台账（{records.length}）
              </CardTitle>
              <div className="flex items-center gap-2">
                <Input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="按 IP / 主机名搜"
                  className="h-8 w-52"
                />
                <Button size="sm" variant="outline" onClick={() => void loadRecords()}>
                  搜索
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
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
                      <TableCell className="text-xs">{row.hostname || "-"}</TableCell>
                      <TableCell className="text-xs">{row.group_name || "未分组"}</TableCell>
                      <TableCell className="text-xs">
                        <Badge variant={row.criticality === "core" ? "critical" : "secondary"}>
                          {CRITICALITY_LABEL[row.criticality] ?? row.criticality}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">{row.owner || "-"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {row.tags.length ? row.tags.join(", ") : "-"}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        {formatDateTime(row.updated_at)}
                      </TableCell>
                      <TableCell>
                        <Button size="sm" variant="ghost" onClick={() => void deleteRecord(row.id, row.ip)}>
                          <Trash2 className="h-3.5 w-3.5 text-destructive" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {records.length === 0 ? (
                <p className="px-4 py-10 text-center text-sm text-muted-foreground">
                  台账还是空的：去「资产发现」里一键加入，或上面手工新增
                </p>
              ) : null}
            </CardContent>
          </Card>
        </>
      ) : null}

      {mode === "manage" && errs.has ? (
        <p className="text-xs text-muted-foreground">
          <X className="mr-1 inline h-3 w-3" />
          读取失败的接口见上方错误条，页面数据可能不是最新。
        </p>
      ) : null}
    </div>
  );
}

