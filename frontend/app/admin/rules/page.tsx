"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiFetch, type RuleItem } from "@/lib/api";

export default function RulesPage() {
  const [rules, setRules] = React.useState<RuleItem[]>([]);
  const [name, setName] = React.useState("");
  const [severity, setSeverity] = React.useState("medium");
  const [priority, setPriority] = React.useState("100");

  async function load() {
    const d = await apiFetch<{ items: RuleItem[] }>("/api/rules");
    setRules(d.items);
  }

  React.useEffect(() => {
    load().catch(() => {});
  }, []);

  async function toggle(r: RuleItem) {
    await apiFetch(`/api/rules/${r.id}`, {
      method: "PUT",
      body: JSON.stringify({
        name: r.name,
        description: r.description,
        conditions: r.conditions,
        severity: r.severity,
        enabled: !r.enabled,
        priority: r.priority,
      }),
    });
    load();
  }

  async function create() {
    if (!name.trim()) return;
    await apiFetch("/api/rules", {
      method: "POST",
      body: JSON.stringify({
        name: name.trim(),
        description: "",
        conditions: { logic: "and", rules: [] },
        severity,
        enabled: true,
        priority: parseInt(priority, 10) || 100,
      }),
    });
    setName("");
    load();
  }

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <h1 className="mb-4 text-2xl font-bold">规则配置</h1>

        <Card className="mb-4">
          <CardHeader><CardTitle className="text-sm">新建规则</CardTitle></CardHeader>
          <CardContent className="flex items-end gap-2">
            <div className="flex-1">
              <label className="mb-1 block text-xs text-muted-foreground">规则名</label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="如：拦截内网到公网 4444 端口" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">级别</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
              >
                <option value="critical">紧急</option>
                <option value="high">高危</option>
                <option value="medium">中危</option>
                <option value="low">低危</option>
                <option value="info">提示</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">优先级</label>
              <Input value={priority} onChange={(e) => setPriority(e.target.value)} className="w-24" />
            </div>
            <Button onClick={create}>添加</Button>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>级别</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>优先级</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>{r.name}</TableCell>
                    <TableCell><Badge variant="outline">{r.severity}</Badge></TableCell>
                    <TableCell>{r.source === "builtin" ? "内置" : "用户"}</TableCell>
                    <TableCell>{r.priority}</TableCell>
                    <TableCell>{r.enabled ? "启用" : "禁用"}</TableCell>
                    <TableCell>
                      <Button size="sm" variant="outline" onClick={() => toggle(r)}>
                        {r.enabled ? "禁用" : "启用"}
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
