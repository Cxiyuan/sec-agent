"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ApiError, apiFetch, errorText, type MemoryItem } from "@/lib/api";

const SELECT_CLS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm";

export default function MemoriesPage() {
  const [items, setItems] = React.useState<MemoryItem[]>([]);
  const [total, setTotal] = React.useState(0);
  const [kind, setKind] = React.useState("");
  const [severity, setSeverity] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [detail, setDetail] = React.useState<MemoryItem | null>(null);

  async function load() {
    const qs = new URLSearchParams();
    if (kind) qs.set("kind", kind);
    if (severity) qs.set("severity", severity);
    qs.set("limit", "100");
    const d = await apiFetch<{ total: number; items: MemoryItem[] }>(`/api/memories?${qs}`);
    setItems(d.items);
    setTotal(d.total);
  }

  React.useEffect(() => {
    load().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, severity]);

  async function cleanup() {
    try {
      const r = await apiFetch<{ run: number; group: number }>("/api/memories/cleanup", {
        method: "POST",
      });
      setMsg(`清理完成：轮次记忆 ${r.run} 条，对象记忆 ${r.group} 条`);
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "清理失败");
    }
  }

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold">
            分析记忆 <span className="text-sm text-muted-foreground">（共 {total} 条）</span>
          </h1>
          <div className="flex gap-2">
            <select value={kind} onChange={(e) => setKind(e.target.value)} className={SELECT_CLS}>
              <option value="">全部类型</option>
              <option value="group">对象级（事件组）</option>
              <option value="run">轮次级</option>
            </select>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className={SELECT_CLS}
            >
              <option value="">全部定级</option>
              <option value="critical">紧急</option>
              <option value="high">高危</option>
              <option value="medium">中危</option>
              <option value="low">低危</option>
              <option value="info">提示</option>
            </select>
            <Button variant="outline" onClick={() => load()}>
              刷新
            </Button>
            <Button variant="secondary" onClick={cleanup}>
              清理过期
            </Button>
          </div>
        </div>
        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">记忆列表</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>类型</TableHead>
                  <TableHead>定级</TableHead>
                  <TableHead>结论摘要</TableHead>
                  <TableHead>涉及 IP</TableHead>
                  <TableHead>时间</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((m) => (
                  <TableRow key={m.id}>
                    <TableCell>
                      <Badge variant={m.kind === "group" ? "info" : "secondary"}>
                        {m.kind === "group" ? "对象" : "轮次"}
                      </Badge>
                    </TableCell>
                    <TableCell>{m.severity || "-"}</TableCell>
                    <TableCell className="max-w-[420px] truncate" title={m.summary}>
                      {m.summary}
                    </TableCell>
                    <TableCell className="max-w-[200px] truncate font-mono text-xs">
                      {(m.ips || []).slice(0, 3).join(", ")}
                      {(m.ips || []).length > 3 ? ` 等${m.ips.length}个` : ""}
                    </TableCell>
                    <TableCell>{m.created_at ? m.created_at.slice(0, 19).replace("T", " ") : "-"}</TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" onClick={() => setDetail(m)}>
                        明细
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      暂无记忆（每轮分析后自动写入）
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {detail && (
          <Card className="mt-4">
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <CardTitle className="text-sm">记忆明细</CardTitle>
              <Button size="sm" variant="outline" onClick={() => setDetail(null)}>
                关闭
              </Button>
            </CardHeader>
            <CardContent className="space-y-2 text-xs">
              <p>
                <span className="text-muted-foreground">指纹：</span>
                <span className="font-mono">{detail.fingerprint}</span>
              </p>
              <p>
                <span className="text-muted-foreground">窗口：</span>
                {detail.window_start?.slice(0, 19).replace("T", " ") || "-"} ~{" "}
                {detail.window_end?.slice(0, 19).replace("T", " ") || "-"}
              </p>
              <p>
                <span className="text-muted-foreground">关联资产：</span>{" "}
                {(detail.asset_ids || []).length} 个
              </p>
              <p className="whitespace-pre-wrap">{detail.summary}</p>
              {detail.detail && (
                <pre className="max-h-72 overflow-auto rounded-md border p-2 text-[11px]">
                  {JSON.stringify(detail.detail, null, 2)}
                </pre>
              )}
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  );
}
