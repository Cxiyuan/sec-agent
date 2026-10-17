"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@shentong/ui";
import {
  ApiError,
  apiFetch,
  apiUpload,
  errorText,
  type ApiErrorBody,
  type AssetBrief,
  type AssetItem,
  type ImportPreview,
  type ImportResult,
} from "@/lib/api";

const IMPORTANCE = [
  { value: "critical", label: "紧急" },
  { value: "high", label: "高" },
  { value: "medium", label: "中" },
  { value: "low", label: "低" },
];

const EMPTY_FORM = {
  ip: "",
  extra_ips: "",
  hostname: "",
  asset_name: "",
  business_system: "",
  owner: "",
  importance: "medium",
  asset_type: "",
  network_zone: "",
  os: "",
  services: "",
  tags: "",
  location: "",
  description: "",
  is_external: false,
  allow_ip_share: false,
};
type FormState = typeof EMPTY_FORM;

interface ConflictState {
  kind: "duplicate_ip" | "ip_conflict";
  body: ApiErrorBody;
  pending: FormState;
}

const SELECT_CLS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm";

function statusVariant(s: string): "low" | "high" | "info" {
  if (s === "indexed") return "low";
  if (s === "failed") return "high";
  return "info";
}

function briefText(a: AssetBrief): string {
  return [a.ip, a.asset_name || "-", a.business_system || "-", `重要级别 ${a.importance || "-"}`].join(" · ");
}

export default function AssetsPage() {
  const [assets, setAssets] = React.useState<AssetItem[]>([]);
  const [q, setQ] = React.useState("");
  const [form, setForm] = React.useState<FormState>(EMPTY_FORM);
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [msg, setMsg] = React.useState("");
  const [fieldErrors, setFieldErrors] = React.useState<{ field: string; msg: string }[]>([]);
  const [conflict, setConflict] = React.useState<ConflictState | null>(null);
  const fileRef = React.useRef<HTMLInputElement>(null);

  // CSV 两阶段导入
  const [importFile, setImportFile] = React.useState<File | null>(null);
  const [preview, setPreview] = React.useState<ImportPreview | null>(null);
  const [overwrite, setOverwrite] = React.useState<string[]>([]);
  const [allowShare, setAllowShare] = React.useState(false);
  const [allowExternal, setAllowExternal] = React.useState(false);
  const [importing, setImporting] = React.useState(false);

  async function load() {
    const d = await apiFetch<{ total: number; items: AssetItem[] }>(
      `/api/assets${q ? `?q=${encodeURIComponent(q)}` : ""}`
    );
    setAssets(d.items);
  }

  React.useEffect(() => {
    load().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function set<K extends keyof FormState>(k: K, v: FormState[K]) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  function resetForm() {
    setForm(EMPTY_FORM);
    setEditingId(null);
    setFieldErrors([]);
  }

  function buildBody(f: FormState) {
    return {
      ...f,
      ip: f.ip.trim(),
      extra_ips: f.extra_ips.split(/[,\n]/).map((s) => s.trim()).filter(Boolean),
      tags: f.tags.split(/[,\n]/).map((s) => s.trim()).filter(Boolean),
    };
  }

  function reportError(e: unknown, pending: FormState) {
    if (e instanceof ApiError) {
      if (e.status === 409 && (e.body.conflict === "duplicate_ip" || e.body.conflict === "ip_conflict")) {
        setConflict({ kind: e.body.conflict, body: e.body, pending });
        return;
      }
      setFieldErrors(e.body.field_errors ?? []);
      setMsg(errorText(e.body));
      return;
    }
    setMsg("保存失败");
  }

  async function submit() {
    const body = buildBody(form);
    setMsg("");
    setFieldErrors([]);
    try {
      if (editingId) {
        await apiFetch(`/api/assets/${editingId}`, { method: "PUT", body: JSON.stringify(body) });
      } else {
        await apiFetch("/api/assets", { method: "POST", body: JSON.stringify(body) });
      }
      resetForm();
      setMsg("已保存，正在异步向量化…");
      load();
    } catch (e) {
      reportError(e, form);
    }
  }

  async function resolveConflict(action: "overwrite" | "cancel") {
    if (!conflict || action === "cancel") {
      setConflict(null);
      return;
    }
    const { kind, body, pending } = conflict;
    const payload = buildBody(pending);
    try {
      if (kind === "duplicate_ip" && body.existing?.id) {
        await apiFetch(`/api/assets/${body.existing.id}`, {
          method: "PUT",
          body: JSON.stringify(payload),
        });
      } else {
        // IP 归属冲突：勾选允许共享后重试并持久化
        const target = editingId ? `/api/assets/${editingId}` : "/api/assets";
        await apiFetch(target, {
          method: editingId ? "PUT" : "POST",
          body: JSON.stringify({ ...payload, allow_ip_share: true }),
        });
      }
      setConflict(null);
      resetForm();
      setMsg("已保存，正在异步向量化…");
      load();
    } catch (e) {
      setConflict(null);
      reportError(e, form);
    }
  }

  function edit(a: AssetItem) {
    setEditingId(a.id);
    setFieldErrors([]);
    setForm({
      ip: a.ip,
      extra_ips: (a.extra_ips || []).join(","),
      hostname: a.hostname,
      asset_name: a.asset_name,
      business_system: a.business_system,
      owner: a.owner,
      importance: a.importance,
      asset_type: a.asset_type,
      network_zone: a.network_zone,
      os: a.os,
      services: a.services,
      tags: (a.tags || []).join(","),
      location: a.location,
      description: a.description,
      is_external: a.is_external,
      allow_ip_share: a.allow_ip_share,
    });
  }

  async function del(a: AssetItem) {
    await apiFetch(`/api/assets/${a.id}`, { method: "DELETE" });
    load();
  }

  async function reindex(a: AssetItem) {
    await apiFetch(`/api/assets/${a.id}/reindex`, { method: "POST" });
    setMsg("已提交重算");
    load();
  }

  async function downloadTemplate() {
    const token = (await import("@/lib/api")).getToken();
    const res = await fetch("/api/assets/template", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "assets_template.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  // ---------- CSV 两阶段 ----------

  async function runPreview(file: File, external: boolean) {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("allow_external", String(external));
    try {
      const report = await apiUpload<ImportPreview>("/api/assets/import/preview", fd);
      setPreview(report);
      setOverwrite([]);
    } catch (e) {
      setPreview(null);
      setMsg(e instanceof ApiError ? errorText(e.body) : "预览失败");
    }
  }

  async function onPickFile(file: File) {
    setImportFile(file);
    setAllowShare(false);
    setAllowExternal(false);
    setMsg("");
    await runPreview(file, false);
  }

  async function commitImport() {
    if (!importFile) return;
    setImporting(true);
    setMsg("");
    try {
      const fd = new FormData();
      fd.append("file", importFile);
      fd.append("overwrite_ips", JSON.stringify(overwrite));
      fd.append("allow_ip_share", String(allowShare));
      fd.append("allow_external", String(allowExternal));
      const r = await apiUpload<ImportResult>("/api/assets/import", fd);
      setMsg(
        `导入完成：新增 ${r.created}，更新 ${r.updated}，跳过 ${r.skipped}，外部资产 ${r.external}`
      );
      setPreview(null);
      setImportFile(null);
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "导入失败");
    } finally {
      setImporting(false);
    }
  }

  const hasNonLan = (preview?.non_lan.length ?? 0) > 0;

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="mb-4 text-xl font-medium">资产管理</h1>
        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}

        {/* 新增 / 编辑 */}
        <Card className="mb-4">
          <CardHeader>
            <CardTitle className="text-sm">{editingId ? "编辑资产" : "新增资产"}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">主 IP / 网段 *</label>
                <Input
                  value={form.ip}
                  onChange={(e) => set("ip", e.target.value)}
                  placeholder="192.168.1.10 或 192.168.1.0/24"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">额外 IP（逗号分隔）</label>
                <Input value={form.extra_ips} onChange={(e) => set("extra_ips", e.target.value)} />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">资产名</label>
                <Input value={form.asset_name} onChange={(e) => set("asset_name", e.target.value)} />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">主机名</label>
                <Input value={form.hostname} onChange={(e) => set("hostname", e.target.value)} />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">业务系统</label>
                <Input
                  value={form.business_system}
                  onChange={(e) => set("business_system", e.target.value)}
                  placeholder="订单系统"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">负责人</label>
                <Input value={form.owner} onChange={(e) => set("owner", e.target.value)} />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">重要级别</label>
                <select
                  value={form.importance}
                  onChange={(e) => set("importance", e.target.value)}
                  className={SELECT_CLS}
                >
                  {IMPORTANCE.map((i) => (
                    <option key={i.value} value={i.value}>
                      {i.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">资产类型</label>
                <Input
                  value={form.asset_type}
                  onChange={(e) => set("asset_type", e.target.value)}
                  placeholder="服务器/数据库"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">网络区域</label>
                <Input
                  value={form.network_zone}
                  onChange={(e) => set("network_zone", e.target.value)}
                  placeholder="生产网/DMZ"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">操作系统</label>
                <Input value={form.os} onChange={(e) => set("os", e.target.value)} />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">开放服务</label>
                <Input
                  value={form.services}
                  onChange={(e) => set("services", e.target.value)}
                  placeholder="3306,6379"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">机房位置</label>
                <Input value={form.location} onChange={(e) => set("location", e.target.value)} />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">标签（逗号分隔）</label>
                <Input value={form.tags} onChange={(e) => set("tags", e.target.value)} />
              </div>
              <div className="col-span-3">
                <label className="mb-1 block text-xs text-muted-foreground">
                  业务描述（参与向量化，与资产名/业务系统至少填一个）
                </label>
                <Input
                  value={form.description}
                  onChange={(e) => set("description", e.target.value)}
                  placeholder="承载订单交易主库，对外提供 3306 服务"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-4 rounded-md border p-3">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.is_external}
                  onChange={(e) => set("is_external", e.target.checked)}
                />
                外部资产记录（IP 不在局域网网段时必须开启）
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.allow_ip_share}
                  onChange={(e) => set("allow_ip_share", e.target.checked)}
                />
                允许该 IP 归属多个资产
              </label>
            </div>

            {fieldErrors.length > 0 && (
              <ul className="space-y-1 rounded-md border border-destructive/50 p-3 text-sm text-destructive">
                {fieldErrors.map((e, i) => (
                  <li key={i}>
                    {e.field}：{e.msg}
                    {e.msg.includes("外部资产") && !form.is_external && (
                      <button
                        className="ml-2 text-primary underline"
                        onClick={() => set("is_external", true)}
                      >
                        开启外部资产记录
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}

            <div className="flex gap-2">
              <Button onClick={submit}>{editingId ? "保存修改" : "新增"}</Button>
              {editingId && (
                <Button variant="outline" onClick={resetForm}>
                  取消
                </Button>
              )}
              <Button variant="secondary" onClick={() => fileRef.current?.click()}>
                导入 CSV
              </Button>
              <Button variant="outline" onClick={downloadTemplate}>
                下载模板
              </Button>
              <input
                ref={fileRef}
                type="file"
                accept=".csv"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) onPickFile(f);
                  e.target.value = "";
                }}
              />
            </div>
          </CardContent>
        </Card>

        {/* CSV 预览与确认 */}
        {preview && (
          <Card className="mb-4 border-primary/40">
            <CardHeader>
              <CardTitle className="text-sm">
                导入预览（共 {preview.total_rows} 行 · 新增 {preview.new_count}）
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              {preview.errors.length > 0 ? (
                <div className="rounded-md border border-destructive/50 p-3">
                  <p className="mb-1 font-medium text-destructive">
                    发现 {preview.errors.length} 处错误，整批不会导入（修正后重试）
                    {preview.truncated && "（错误过多，仅显示前 1000 条）"}
                  </p>
                  <ul className="max-h-40 space-y-0.5 overflow-auto font-mono text-xs text-destructive">
                    {preview.errors.slice(0, 50).map((e, i) => (
                      <li key={i}>
                        第{e.row}行 {e.ip ? `[${e.ip}] ` : ""}
                        {e.msg}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-primary">校验通过，可确认导入。</p>
              )}

              {hasNonLan && (
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={allowExternal}
                    onChange={async (e) => {
                      setAllowExternal(e.target.checked);
                      if (importFile) await runPreview(importFile, e.target.checked);
                    }}
                  />
                  允许外部资产（{preview.non_lan.length} 行 IP 不在局域网，勾选后按外部资产记录）
                </label>
              )}

              {preview.duplicates.length > 0 && (
                <div className="rounded-md border p-3">
                  <div className="mb-2 flex items-center gap-2">
                    <span className="font-medium">主 IP 已存在（{preview.duplicates.length} 项）</span>
                    <Button size="sm" variant="outline" onClick={() => setOverwrite(preview.duplicates.map((d) => d.ip))}>
                      全部覆盖
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setOverwrite([])}>
                      全部不覆盖
                    </Button>
                  </div>
                  <div className="max-h-48 space-y-1 overflow-auto">
                    {preview.duplicates.map((d) => (
                      <label key={d.ip} className="flex items-center gap-2 font-mono text-xs">
                        <input
                          type="checkbox"
                          checked={overwrite.includes(d.ip)}
                          onChange={(e) =>
                            setOverwrite((prev) =>
                              e.target.checked ? [...prev, d.ip] : prev.filter((x) => x !== d.ip)
                            )
                          }
                        />
                        第{d.row}行 {d.ip} —— 已有：{briefText(d.existing)}
                      </label>
                    ))}
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">
                    未勾选的行将被跳过，已有记录保持原值。
                  </p>
                </div>
              )}

              {preview.ip_conflicts.length > 0 && (
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={allowShare}
                    onChange={(e) => setAllowShare(e.target.checked)}
                  />
                  允许 IP 归属多个资产（{preview.ip_conflicts.length} 项冲突）
                </label>
              )}

              <div className="flex gap-2">
                <Button onClick={commitImport} disabled={!preview.ok || importing}>
                  {importing ? "导入中…" : "确认导入"}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    setPreview(null);
                    setImportFile(null);
                  }}
                >
                  取消
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* 冲突弹窗 */}
        {conflict && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
            <Card className="w-[520px]">
              <CardHeader>
                <CardTitle className="text-base">
                  {conflict.kind === "duplicate_ip" ? "IP 已存在" : "IP 归属冲突"}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <p>{conflict.body.detail}</p>
                {conflict.body.existing && (
                  <div className="rounded-md border p-2 font-mono text-xs">
                    {briefText(conflict.body.existing)}
                  </div>
                )}
                {conflict.body.holders?.length ? (
                  <div className="space-y-1">
                    <p className="text-muted-foreground">占用方：</p>
                    {conflict.body.holders.map((h, i) => (
                      <div key={i} className="rounded-md border p-2 font-mono text-xs">
                        {briefText(h)}
                      </div>
                    ))}
                  </div>
                ) : null}
                <p className="text-muted-foreground">{conflict.body.hint}</p>
                <div className="flex gap-2">
                  <Button onClick={() => resolveConflict("overwrite")}>
                    {conflict.kind === "duplicate_ip" ? "覆盖已有资产" : "允许 IP 共享并保存"}
                  </Button>
                  <Button variant="outline" onClick={() => resolveConflict("cancel")}>
                    取消
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* 列表 */}
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="text-sm">资产列表（{assets.length}）</CardTitle>
            <div className="flex gap-2">
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && load()}
                placeholder="搜索 IP/资产名/业务系统/负责人"
                className="w-72"
              />
              <Button variant="outline" onClick={() => load()}>
                搜索
              </Button>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP / 网段</TableHead>
                  <TableHead>资产名</TableHead>
                  <TableHead>业务系统</TableHead>
                  <TableHead>重要级别</TableHead>
                  <TableHead>标记</TableHead>
                  <TableHead>向量状态</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assets.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="font-mono">{a.ip}</TableCell>
                    <TableCell>{a.asset_name || a.hostname || "-"}</TableCell>
                    <TableCell>{a.business_system || "-"}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{a.importance}</Badge>
                    </TableCell>
                    <TableCell className="space-x-1">
                      {a.is_external && <Badge variant="medium">外部</Badge>}
                      {a.allow_ip_share && <Badge variant="info">共享</Badge>}
                    </TableCell>
                    <TableCell>
                      <Badge variant={statusVariant(a.embedding_status)}>{a.embedding_status}</Badge>
                    </TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" onClick={() => edit(a)}>
                        编辑
                      </Button>
                      <Button size="sm" variant="outline" className="ml-2" onClick={() => reindex(a)}>
                        重算
                      </Button>
                      <Button size="sm" variant="destructive" className="ml-2" onClick={() => del(a)}>
                        删除
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {assets.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground">
                      暂无资产，请新增或导入 CSV
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
