"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import {
  Badge,
  Button,
  Card,
  CardContent,
  EmptyState,
  Section,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
  formatDateTime,
  statusText,
} from "@shentong/ui";
import {
  ApiError,
  apiFetch,
  apiUpload,
  errorText,
  type DocumentItem,
} from "@/lib/api";

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
  // null = 首屏未读（骨架）；[] = 读到空（空态）
  const [docs, setDocs] = React.useState<DocumentItem[] | null>(null);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);

  async function load() {
    const d = await apiFetch<{ items: DocumentItem[] }>("/api/documents");
    setDocs(d.items);
  }

  React.useEffect(() => {
    load().catch((e) => {
      setDocs((x) => x ?? []);
      setMsg(e instanceof Error ? e.message : "文档列表读取失败");
    });
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

  const list = docs ?? [];

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="sr-only">知识文档</h1>
        <div className="space-y-4">
          {msg && <p className="text-xs text-primary">{msg}</p>}

          <Section title="上传文档">
            <Card>
              <CardContent className="flex flex-wrap items-center gap-3 pt-4">
                <Button size="sm" disabled={busy} onClick={() => fileRef.current?.click()}>
                  {busy ? "上传中…" : "选择文件上传"}
                </Button>
                <span className="text-xs text-muted-foreground">
                  支持 txt / md / pdf / docx / xlsx，单文件 ≤ 20MB；按内容去重，改名重复上传会被拒
                </span>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".txt,.md,.markdown,.log,.csv,.pdf,.docx,.xlsx"
                  aria-label="选择要上传的文档"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) upload(f);
                    e.target.value = "";
                  }}
                />
              </CardContent>
            </Card>
          </Section>

          <Section title={`文档列表（${list.length}）`}>
            <Card>
              <CardContent className="p-0">
                {docs === null ? (
                  <TableSkeleton rows={6} cols={6} />
                ) : list.length === 0 ? (
                  <EmptyState
                    title="暂无文档"
                    hint="上传 SOP、预案或资产说明后，分析时会作为知识依据被检索"
                    action={
                      <Button size="sm" variant="outline" onClick={() => fileRef.current?.click()}>
                        选择文件上传
                      </Button>
                    }
                  />
                ) : (
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
                      {list.map((d) => (
                        <TableRow key={d.id}>
                          <TableCell>{d.title}</TableCell>
                          <TableCell className="text-muted-foreground">{d.filename}</TableCell>
                          <TableCell className="tabular-nums">{fmtSize(d.size)}</TableCell>
                          <TableCell>
                            <Badge variant={statusVariant(d.status)}>{statusText(d.status)}</Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs tabular-nums">
                            {formatDateTime(d.uploaded_at)}
                          </TableCell>
                          <TableCell>
                            <Button size="sm" variant="outline" onClick={() => reindex(d)}>
                              重算
                            </Button>
                            <Button
                              size="sm"
                              variant="destructive"
                              className="ml-2"
                              onClick={() => del(d)}
                            >
                              删除
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
        </div>
      </main>
    </div>
  );
}
