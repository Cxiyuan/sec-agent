"use client";

import * as React from "react";
import { ApiError, apiFetch, errorText, type AnalysisScope } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

const EMPTY = { name: "", description: "", cidrs: "", enabled: true };

/** 分析网段管理：多套网段组，可启用/停用。智能体只分析源或目的 IP 落在启用网段内的日志。 */
export function ScopeManager() {
  const [scopes, setScopes] = React.useState<AnalysisScope[]>([]);
  const [form, setForm] = React.useState(EMPTY);
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [msg, setMsg] = React.useState("");

  async function load() {
    const d = await apiFetch<{ items: AnalysisScope[] }>("/api/analysis-scopes");
    setScopes(d.items);
  }

  React.useEffect(() => {
    load().catch(() => {});
  }, []);

  function reset() {
    setForm(EMPTY);
    setEditingId(null);
  }

  function parseCidrs(): string[] {
    return form.cidrs
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function submit() {
    setMsg("");
    const cidrs = parseCidrs();
    if (!form.name.trim()) {
      setMsg("请填写名称");
      return;
    }
    if (cidrs.length === 0) {
      setMsg("请至少填写一个网段或 IP");
      return;
    }
    const body = {
      name: form.name.trim(),
      description: form.description,
      cidrs,
      enabled: form.enabled,
    };
    try {
      if (editingId) {
        await apiFetch(`/api/analysis-scopes/${editingId}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
      } else {
        await apiFetch("/api/analysis-scopes", { method: "POST", body: JSON.stringify(body) });
      }
      reset();
      setMsg("已保存");
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    }
  }

  async function toggle(s: AnalysisScope) {
    try {
      await apiFetch(`/api/analysis-scopes/${s.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name: s.name,
          description: s.description,
          cidrs: s.cidrs,
          enabled: !s.enabled,
        }),
      });
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "更新失败");
    }
  }

  async function remove(s: AnalysisScope) {
    await apiFetch(`/api/analysis-scopes/${s.id}`, { method: "DELETE" });
    if (editingId === s.id) reset();
    load();
  }

  function edit(s: AnalysisScope) {
    setEditingId(s.id);
    setForm({
      name: s.name,
      description: s.description,
      cidrs: (s.cidrs || []).join("\n"),
      enabled: s.enabled,
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">分析网段（多套，可启用/停用）</CardTitle>
        <p className="text-xs text-muted-foreground">
          智能体只拉取「源或目的 IP 落在启用网段内」的日志；未启用任何网段则不分析。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}

        <div className="grid grid-cols-4 gap-3">
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">名称 *</label>
            <Input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="生产网 / 办公网"
            />
          </div>
          <div className="col-span-2">
            <label className="mb-1 block text-xs text-muted-foreground">
              网段或 IP *（逗号或换行分隔）
            </label>
            <Input
              value={form.cidrs}
              onChange={(e) => setForm({ ...form, cidrs: e.target.value })}
              placeholder="192.168.0.0/16, 10.0.0.0/8"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">说明</label>
            <Input
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          />
          启用该网段组
        </label>
        <div className="flex gap-2">
          <Button onClick={submit}>{editingId ? "保存修改" : "新增网段组"}</Button>
          {editingId && (
            <Button variant="outline" onClick={reset}>
              取消
            </Button>
          )}
        </div>

        <div className="space-y-2">
          {scopes.map((s) => (
            <div key={s.id} className="flex items-start justify-between rounded-md border p-2 text-sm">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{s.name}</span>
                  <Badge variant={s.enabled ? "low" : "info"}>{s.enabled ? "启用" : "停用"}</Badge>
                </div>
                <div className="mt-0.5 font-mono text-xs text-muted-foreground">
                  {(s.cidrs || []).join(", ")}
                </div>
                {s.description && (
                  <div className="text-xs text-muted-foreground">{s.description}</div>
                )}
              </div>
              <div className="ml-3 flex shrink-0 gap-2">
                <Button size="sm" variant="outline" onClick={() => toggle(s)}>
                  {s.enabled ? "停用" : "启用"}
                </Button>
                <Button size="sm" variant="outline" onClick={() => edit(s)}>
                  编辑
                </Button>
                <Button size="sm" variant="destructive" onClick={() => remove(s)}>
                  删除
                </Button>
              </div>
            </div>
          ))}
          {scopes.length === 0 && (
            <p className="text-xs text-destructive">尚未配置任何网段组，智能体不会分析日志。</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
