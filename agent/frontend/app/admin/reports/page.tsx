"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Badge, severityVariant } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@shentong/ui";
import { apiFetch, getToken } from "@/lib/api";
import { formatDateTime, severityText } from "@shentong/ui";

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
  const [reports, setReports] = React.useState<ReportItem[]>([]);

  React.useEffect(() => {
    apiFetch<{ items: ReportItem[] }>("/api/reports")
      .then((d) => setReports(d.items))
      .catch(() => {});
  }, []);

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="mb-4 text-xl font-medium">报告</h1>
        <Card>
          <CardHeader><CardTitle className="text-sm">事件报告</CardTitle></CardHeader>
          <CardContent className="p-0">
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
                {reports.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>{r.title}</TableCell>
                    <TableCell><Badge variant={severityVariant(r.severity)}>{severityText(r.severity)}</Badge></TableCell>
                    <TableCell>{formatDateTime(r.created_at)}</TableCell>
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
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
