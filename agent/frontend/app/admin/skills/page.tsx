"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@shentong/ui";
import { ApiError, apiFetch, errorText, type SkillItem, type SkillTool } from "@/lib/api";

const INPUT_CLS =
  "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm";
const TEXTAREA_CLS =
  "w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono";

// 常见事件类型提示（可自由输入其它）
const EVENT_TYPE_HINTS = [
  "brute_force",
  "port_scan",
  "scan_attempt",
  "ssh_activity",
  "http_login",
  "http_request",
  "web_attack",
  "wazuh_web_attack",
  "wazuh_malware",
  "wazuh_system_change",
  "conn_established",
  "tls_session",
  "file_transfer",
  "http_upload",
  "dns_query",
  "dns_anomaly",
  "smtp_abuse",
  "protocol_anomaly",
  "rejected_connection",
  "generic",
];

export default function SkillsPage() {
  const [items, setItems] = React.useState<SkillItem[]>([]);
  const [tools, setTools] = React.useState<SkillTool[]>([]);
  const [msg, setMsg] = React.useState("");

  // 表单状态
  const [editing, setEditing] = React.useState<SkillItem | null>(null);
  const [isNew, setIsNew] = React.useState(false);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [eventTypes, setEventTypes] = React.useState("");
  const [sop, setSop] = React.useState("");
  const [selTools, setSelTools] = React.useState<string[]>([]);
  const [priority, setPriority] = React.useState("100");
  const [enabled, setEnabled] = React.useState(true);

  async function load() {
    const d = await apiFetch<{ items: SkillItem[]; tools: SkillTool[] }>("/api/skills");
    setItems(d.items);
    setTools(d.tools);
  }

  React.useEffect(() => {
    load().catch(() => {});
  }, []);

  function resetForm() {
    setName("");
    setDescription("");
    setEventTypes("");
    setSop("");
    setSelTools([]);
    setPriority("100");
    setEnabled(true);
  }

  function openNew() {
    resetForm();
    setEditing(null);
    setIsNew(true);
  }

  function openEdit(s: SkillItem) {
    setName(s.name);
    setDescription(s.description);
    setEventTypes((s.event_types || []).join(", "));
    setSop(s.sop);
    setSelTools(s.tools || []);
    setPriority(String(s.priority));
    setEnabled(s.enabled);
    setEditing(s);
    setIsNew(false);
  }

  function closeForm() {
    setEditing(null);
    setIsNew(false);
  }

  async function save() {
    const body = {
      name: name.trim(),
      description: description.trim(),
      event_types: eventTypes.split(/[,，\s]+/).filter(Boolean),
      tools: selTools,
      sop: sop.trim(),
      enabled,
      priority: Number(priority) || 100,
    };
    try {
      if (isNew) {
        await apiFetch("/api/skills", { method: "POST", body: JSON.stringify(body) });
        setMsg("技能已创建");
      } else if (editing) {
        await apiFetch(`/api/skills/${editing.id}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
        setMsg("技能已更新");
      }
      closeForm();
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    }
  }

  async function toggle(s: SkillItem) {
    try {
      await apiFetch(`/api/skills/${s.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name: s.name,
          description: s.description,
          event_types: s.event_types,
          tools: s.tools,
          sop: s.sop,
          enabled: !s.enabled,
          priority: s.priority,
        }),
      });
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "操作失败");
    }
  }

  async function remove(s: SkillItem) {
    if (!confirm(`删除技能「${s.name}」？`)) return;
    try {
      await apiFetch(`/api/skills/${s.id}`, { method: "DELETE" });
      setMsg("已删除");
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "删除失败");
    }
  }

  const showingForm = isNew || editing !== null;

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold">
            技能库{" "}
            <span className="text-sm text-muted-foreground">
              （安全事件分析 SOP + 脚本工具，按事件类型路由）
            </span>
          </h1>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => load()}>
              刷新
            </Button>
            <Button onClick={openNew}>新建技能</Button>
          </div>
        </div>
        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}

        {showingForm && (
          <Card className="mb-4">
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <CardTitle className="text-sm">{isNew ? "新建技能" : `编辑技能：${name}`}</CardTitle>
              <Button size="sm" variant="outline" onClick={closeForm}>
                取消
              </Button>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">技能名 *</label>
                  <Input value={name} onChange={(e) => setName(e.target.value)} className={INPUT_CLS} />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">优先级（越小越先）</label>
                  <Input value={priority} onChange={(e) => setPriority(e.target.value)} className={INPUT_CLS} />
                </div>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">描述</label>
                <Input value={description} onChange={(e) => setDescription(e.target.value)} className={INPUT_CLS} />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  事件类型 *（逗号分隔，命中即路由到本技能）
                </label>
                <Input
                  value={eventTypes}
                  onChange={(e) => setEventTypes(e.target.value)}
                  className={INPUT_CLS}
                  list="event-type-hints"
                  placeholder="如 brute_force, port_scan"
                />
                <datalist id="event-type-hints">
                  {EVENT_TYPE_HINTS.map((t) => (
                    <option key={t} value={t} />
                  ))}
                </datalist>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  关联脚本工具（确定性执行，结果注入分析）
                </label>
                <div className="grid grid-cols-2 gap-2 rounded-md border p-3 md:grid-cols-3">
                  {tools.map((t) => {
                    const checked = selTools.includes(t.name);
                    return (
                      <label key={t.name} className="flex items-start gap-2 text-sm">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) =>
                            setSelTools(
                              e.target.checked
                                ? [...selTools, t.name]
                                : selTools.filter((x) => x !== t.name)
                            )
                          }
                        />
                        <span>
                          <span className="font-mono text-xs">{t.name}</span>
                          <span className="block text-[11px] text-muted-foreground">
                            [{t.category}] {t.description}
                          </span>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  SOP 正文 *（事件背景 / 判断要点 / 取证步骤 / 常见误报 / 处置建议）
                </label>
                <textarea
                  value={sop}
                  onChange={(e) => setSop(e.target.value)}
                  rows={10}
                  className={TEXTAREA_CLS}
                />
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                启用
              </label>
              <div className="flex justify-end">
                <Button onClick={save}>保存</Button>
              </div>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">技能列表（共 {items.length} 个）</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>技能</TableHead>
                  <TableHead>事件类型</TableHead>
                  <TableHead>工具</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="max-w-[280px]">
                      <div className="font-medium">{s.name}</div>
                      <div className="truncate text-xs text-muted-foreground" title={s.description}>
                        {s.description}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-[240px]">
                      {(s.event_types || []).map((t) => (
                        <Badge key={t} variant="secondary" className="mr-1">
                          {t}
                        </Badge>
                      ))}
                    </TableCell>
                    <TableCell className="max-w-[200px] truncate font-mono text-xs">
                      {(s.tools || []).join(", ") || "-"}
                    </TableCell>
                    <TableCell>
                      <Badge variant={s.source === "builtin" ? "info" : "outline"}>
                        {s.source === "builtin" ? "内置" : "自定义"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant={s.enabled ? "secondary" : "outline"}
                        onClick={() => toggle(s)}
                      >
                        {s.enabled ? "启用" : "停用"}
                      </Button>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button size="sm" variant="outline" onClick={() => openEdit(s)}>
                          编辑
                        </Button>
                        {s.source !== "builtin" && (
                          <Button size="sm" variant="destructive" onClick={() => remove(s)}>
                            删除
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      暂无技能
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
