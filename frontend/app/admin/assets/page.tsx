"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiFetch, getToken, type AssetItem } from "@/lib/api";

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
};
type FormState = typeof EMPTY_FORM;

function statusVariant(s: string): "critical" | "high" | "medium" | "low" | "info" {
  if (s === "indexed") return "low";
  if (s === "failed") return "high";
  return "info";
}

export default function AssetsPage() {
  const [assets, setAssets] = React.useState<AssetItem[]>([]);
  const [q, setQ] = React.useState("");
  const [form, setForm] = React.useState<FormState>(EMPTY_FORM);
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [msg, setMsg] = React.useState("");
  const fileRef = React.useRef<HTMLInputElement>(null);

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

  function set(k: keyof FormState, v: string) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  function resetForm() {
    setForm(EMPTY_FORM);
    setEditingId(null);
  }

  async function submit() {
    if (!form.ip.trim()) {
      setMsg("IP 不能为空");
      return;
    }
    const body = {
      ...form,
      ip: form.ip.trim(),
      extra_ips: form.extra_ips.split(/[,\n]/).map((s) => s.trim()).filter(Boolean),
      tags: form.tags.split(/[,\n]/).map((s) => s.trim()).filter(Boolean),
    };
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
      setMsg(e instanceof Error ? e.message : "保存失败");
    }
  }

  function edit(a: AssetItem) {
    setEditingId(a.id);
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
    const res = await fetch("/api/assets/template", {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "assets_template.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  async function importCsv(file: File) {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch("/api/assets/import", {
      method: "POST",
      headers: { Authorization: `Bearer ${getToken()}` },
      body: fd,
    });
    if (!res.ok) {
      setMsg("导入失败");
      return;
    }
    const d = await res.json();
    setMsg(`导入完成：新增 ${d.created}，更新 ${d.updated}，失败 ${d.failed}`);
    load();
  }

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="mb-4 text-2xl font-bold">资产管理</h1>
        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}

        <Card className="mb-4">
          <CardHeader>
            <CardTitle className="text-sm">{editingId ? "编辑资产" : "新增资产"}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-4 gap-3">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">主 IP *</label>
                <Input value={form.ip} onChange={(e) => set("ip", e.target.value)} placeholder="192.168.1.10" />
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
                <Input value={form.business_system} onChange={(e) => set("business_system", e.target.value)} placeholder="订单系统" />
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
                  className="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
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
                <Input value={form.asset_type} onChange={(e) => set("asset_type", e.target.value)} placeholder="服务器/数据库" />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">网络区域</label>
                <Input value={form.network_zone} onChange={(e) => set("network_zone", e.target.value)} placeholder="生产网/DMZ" />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">操作系统</label>
                <Input value={form.os} onChange={(e) => set("os", e.target.value)} />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">开放服务</label>
                <Input value={form.services} onChange={(e) => set("services", e.target.value)} placeholder="3306,6379" />
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
                <label className="mb-1 block text-xs text-muted-foreground">业务描述（参与向量化）</label>
                <Input
                  value={form.description}
                  onChange={(e) => set("description", e.target.value)}
                  placeholder="承载订单交易主库，对外提供 3306 服务"
                />
              </div>
            </div>
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
                  if (f) importCsv(f);
                  e.target.value = "";
                }}
              />
            </div>
          </CardContent>
        </Card>

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
                  <TableHead>IP</TableHead>
                  <TableHead>资产名</TableHead>
                  <TableHead>业务系统</TableHead>
                  <TableHead>重要级别</TableHead>
                  <TableHead>负责人</TableHead>
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
                    <TableCell>{a.owner || "-"}</TableCell>
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
