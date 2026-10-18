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
  severityText,
  severityVariant,
} from "@shentong/ui";
import { apiFetch, getToken } from "@/lib/api";

interface ReportItem {
  id: string;
  group_id: string;
  title: string;
  severity: string;
  pdf_path: string | null;
  created_at: string | null;
}

async function downloadReport(r: ReportItem) {
  const token = getToken();
  const res = await fetch(`/api/reports/${r.id}/download`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return;
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${r.title}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  // null = 首屏未读（骨架）；[] = 读到空（空态）
  const [reports, setReports] = React.useState<ReportItem[] | null>(null);

  React.useEffect(() => {
    apiFetch<{ items: ReportItem[] }>("/api/reports")
      .then((d) => setReports(d.items))
      .catch(() => setReports([]));
  }, []);

  const list = reports ?? [];

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="sr-only">报告</h1>
        <Section title={`报告（${list.length}）`} description="按事件组生成，可下载 PDF">
          <Card>
            <CardContent className="p-0">
              {reports === null ? (
                <TableSkeleton rows={6} cols={3} />
              ) : list.length === 0 ? (
                <EmptyState
                  title="暂无报告"
                  hint="深度分析产出结论后会生成报告；达到「报告最低级别」才会出"
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>标题</TableHead>
                      <TableHead>级别</TableHead>
                      <TableHead>时间</TableHead>
                      <TableHead>操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {list.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell>{r.title}</TableCell>
                        <TableCell>
                          <Badge variant={severityVariant(r.severity)}>{severityText(r.severity)}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs tabular-nums">
                          {formatDateTime(r.created_at)}
                        </TableCell>
                        <TableCell>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={!r.pdf_path}
                            onClick={() => downloadReport(r)}
                          >
                            下载 PDF
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
      </main>
    </div>
  );
}
