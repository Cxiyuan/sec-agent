"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@shentong/ui";
import {
  ApiError,
  apiFetch,
  apiUpload,
  errorText,
  type DocumentItem,
} from "@/lib/api";
import { formatDateTime, statusText } from "@shentong/ui";

function statusVariant(s: string): "low" | "high" | "info" {
  if (s === "indexed") return "low";
  if (s === "failed") return "high";
  return "info";
}

function fmtSize(n: number): string {
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

export default function DocumentsPage() {
  const [docs, setDocs] = React.useState<DocumentItem[]>([]);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);

  async function load() {
    const d = await apiFetch<{ items: DocumentItem[] }>("/api/documents");
    setDocs(d.items);
  }

  React.useEffect(() => {
    load().catch(() => {});
  }, []);

  async function upload(file: File) {
    setBusy(true);
    setMsg("");
    try {
      const fd = new FormData();
      fd.append("file", file);
      const d = await apiUpload<DocumentItem>("/api/documents", fd);
      setMsg(`上传成功：${d.title}，正在异步向量化…`);
      load();
    } catch (e) {
      if (e instanceof ApiError && e.body.conflict === "duplicate_content" && e.body.existing) {
        const exist = e.body.existing;
        setMsg(
          `内容重复：已存在「${exist.title}」（${exist.filename}），未重复入库，可在列表中直接使用`
        );
      } else if (e instanceof ApiError) {
        setMsg(errorText(e.body));
      } else {
        setMsg("上传失败");
      }
    } finally {
      setBusy(false);
    }
  }

  async function del(d: DocumentItem) {
    await apiFetch(`/api/documents/${d.id}`, { method: "DELETE" });
    load();
  }

  async function reindex(d: DocumentItem) {
    await apiFetch(`/api/documents/${d.id}/reindex`, { method: "POST" });
    setMsg("已提交重算");
    load();
  }

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="mb-4 text-xl font-medium">知识文档</h1>
        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}

        <Card className="mb-4">
          <CardHeader>
            <CardTitle className="text-sm">上传文档</CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-3">
            <Button disabled={busy} onClick={() => fileRef.current?.click()}>
              {busy ? "上传中…" : "选择文件上传"}
            </Button>
            <span className="text-xs text-muted-foreground">
              支持 txt / md / pdf / docx / xlsx，单文件 ≤ 20MB；按内容去重，改名重复上传会被拒
            </span>
            <input
              ref={fileRef}
              type="file"
              accept=".txt,.md,.markdown,.log,.csv,.pdf,.docx,.xlsx"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) upload(f);
                e.target.value = "";
              }}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">文档列表（{docs.length}）</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>标题</TableHead>
                  <TableHead>文件名</TableHead>
                  <TableHead>大小</TableHead>
                  <TableHead>向量状态</TableHead>
                  <TableHead>上传时间</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {docs.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell>{d.title}</TableCell>
                    <TableCell className="text-muted-foreground">{d.filename}</TableCell>
                    <TableCell>{fmtSize(d.size)}</TableCell>
                    <TableCell>
                      <Badge variant={statusVariant(d.status)}>{statusText(d.status)}</Badge>
                    </TableCell>
                    <TableCell>{formatDateTime(d.uploaded_at)}</TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" onClick={() => reindex(d)}>
                        重算
                      </Button>
                      <Button size="sm" variant="destructive" className="ml-2" onClick={() => del(d)}>
                        删除
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {docs.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      暂无文档
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
