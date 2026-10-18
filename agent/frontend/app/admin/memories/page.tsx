"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import {
  Badge,
  Button,
  Card,
  CardContent,
  Drawer,
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
  severityText,
} from "@shentong/ui";
import { ApiError, apiFetch, errorText, type MemoryItem } from "@/lib/api";

const SELECT_CLS = "h-8 rounded-sm border border-input bg-surface-2 px-2 text-13";

export default function MemoriesPage() {
  // null = 首屏未读（骨架）；[] = 读到空（空态）
  const [items, setItems] = React.useState<MemoryItem[] | null>(null);
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
    load().catch((e) => {
      setItems((x) => x ?? []);
      setMsg(e instanceof Error ? e.message : "记忆列表读取失败");
    });
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

  const list = items ?? [];

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="sr-only">分析记忆</h1>
        <div className="space-y-4">
          <Section
            title={`分析记忆（共 ${total} 条）`}
            extra={
              <>
                <select
                  value={kind}
                  onChange={(e) => setKind(e.target.value)}
                  aria-label="按记忆类型筛选"
                  className={SELECT_CLS}
                >
                  <option value="">全部类型</option>
                  <option value="group">对象级（事件组）</option>
                  <option value="run">轮次级</option>
                </select>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  aria-label="按定级筛选"
                  className={SELECT_CLS}
                >
                  <option value="">全部定级</option>
                  <option value="critical">紧急</option>
                  <option value="high">高危</option>
                  <option value="medium">中危</option>
                  <option value="low">低危</option>
                  <option value="info">提示</option>
                </select>
                <Button size="sm" variant="outline" onClick={() => load()}>
                  刷新
                </Button>
                <Button size="sm" variant="outline" onClick={cleanup}>
                  清理过期
                </Button>
              </>
            }
          >
            {msg && <p className="text-xs text-primary">{msg}</p>}

            <Card>
              <CardContent className="p-0">
                {items === null ? (
                  <TableSkeleton rows={8} cols={6} />
                ) : list.length === 0 ? (
                  <EmptyState
                    title="暂无记忆"
                    hint="每轮分析结束后会自动写入；也可以放宽类型或定级筛选"
                    action={
                      <Button size="sm" variant="outline" onClick={() => load()}>
                        重新读取
                      </Button>
                    }
                  />
                ) : (
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
                      {list.map((m) => (
                        <TableRow key={m.id}>
                          <TableCell>
                            <Badge variant={m.kind === "group" ? "info" : "secondary"}>
                              {m.kind === "group" ? "对象" : "轮次"}
                            </Badge>
                          </TableCell>
                          <TableCell>{severityText(m.severity)}</TableCell>
                          <TableCell className="max-w-[420px] truncate" title={m.summary}>
                            {m.summary}
                          </TableCell>
                          <TableCell className="max-w-[200px] truncate font-mono text-xs">
                            {(m.ips || []).slice(0, 3).join(", ")}
                            {(m.ips || []).length > 3 ? ` 等${m.ips.length}个` : ""}
                          </TableCell>
                          <TableCell className="font-mono text-xs tabular-nums">
                            {formatDateTime(m.created_at)}
                          </TableCell>
                          <TableCell>
                            <Button size="sm" variant="outline" onClick={() => setDetail(m)}>
                              明细
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

        <Drawer
          open={detail !== null}
          onClose={() => setDetail(null)}
          title={<span className="font-medium">记忆明细</span>}
        >
          {detail && (
            <div className="space-y-3 text-xs">
              <div className="rounded-xs bg-surface-1 p-3">
                <p className="text-muted-foreground">指纹</p>
                <p className="mt-0.5 font-mono text-13">{detail.fingerprint}</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-muted-foreground">窗口开始</p>
                  <p className="mt-0.5 tabular-nums">{formatDateTime(detail.window_start)}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">窗口结束</p>
                  <p className="mt-0.5 tabular-nums">{formatDateTime(detail.window_end)}</p>
                </div>
              </div>
              <div>
                <p className="text-muted-foreground">关联资产</p>
                <p className="mt-0.5 tabular-nums">{(detail.asset_ids || []).length} 个</p>
              </div>
              <div>
                <p className="text-muted-foreground">结论摘要</p>
                <p className="mt-0.5 whitespace-pre-wrap text-13">{detail.summary}</p>
              </div>
              {detail.detail && (
                <pre className="max-h-72 overflow-auto rounded-xs border border-border-subtle bg-surface-1 p-2 text-xs">
                  {JSON.stringify(detail.detail, null, 2)}
                </pre>
              )}
            </div>
          )}
        </Drawer>
      </main>
    </div>
  );
}
