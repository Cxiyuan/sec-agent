"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { ScopeManager } from "@/components/scope-manager";
import { ZeekPanel } from "@/components/zeek-panel";
import { EsPanel } from "@/components/es-panel";
import { EdgePanel } from "@/components/edge-panel";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { apiFetch } from "@/lib/api";

interface Field {
  key: string;
  label: string;
  type: "text" | "number" | "bool" | "select";
  options?: string[];
  hint?: string;
}

const GROUPS: { name: string; fields: Field[] }[] = [
  {
    name: "模型（角色分工，可运行时修改）",
    fields: [
      { key: "model.flash", label: "flash · 日常分析", type: "text", hint: "异常确认/定级/处置/报告正文" },
      { key: "model.deep", label: "deep · 深度分析", type: "text", hint: "攻击链还原/攻击者画像" },
      { key: "model.embo_db", label: "embo-db · 向量入库", type: "text" },
      { key: "model.embo_query", label: "embo-query · 向量查询", type: "text" },
    ],
  },
  {
    name: "边缘模型思考模式（每场景独立开关）",
    fields: [
      { key: "edge_thinking.semantic_merge", label: "语义关联开思考", type: "bool", hint: "判断两个事件组是否同一次攻击" },
      { key: "edge_thinking.triage_complex", label: "复杂研判开思考", type: "bool", hint: "Web攻击/恶意软件/C2/横向移动等" },
      { key: "edge_thinking.triage_simple", label: "简单研判开思考", type: "bool", hint: "扫描/爆破/常规连接" },
    ],
  },
  {
    name: "分析",
    fields: [
      { key: "escalate_score_threshold", label: "升级阈值（0~1）", type: "number" },
      { key: "report_min_severity", label: "报告最低级别", type: "select", options: ["critical", "high", "medium", "low", "info"] },
      { key: "hitl_enabled", label: "高危人工确认", type: "bool" },
      { key: "hitl_min_severity", label: "人工确认级别", type: "select", options: ["critical", "high", "medium", "low"] },
      { key: "baseline_observe_days", label: "基线观察天数", type: "number" },
    ],
  },
  {
    name: "资产 RAG",
    fields: [
      { key: "rag_enabled", label: "启用资产 RAG", type: "bool" },
      { key: "rag_top_k", label: "检索条数 top-K", type: "number" },
      { key: "rag_min_score", label: "检索相似度下限（0~1）", type: "number" },
    ],
  },
];

const SELECT_CLS =
  "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm";

export default function SettingsPage() {
  const [values, setValues] = React.useState<Record<string, unknown>>({});
  const [saved, setSaved] = React.useState<Record<string, unknown>>({});
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    apiFetch<{ items: Record<string, unknown> }>("/api/config")
      .then((d) => {
        setValues(d.items);
        setSaved(d.items);
      })
      .catch(() => {});
  }, []);

  function set(key: string, v: unknown) {
    setValues((s) => ({ ...s, [key]: v }));
  }

  async function save() {
    setBusy(true);
    setMsg("");
    try {
      const fields = GROUPS.flatMap((g) => g.fields);
      const changed = fields.filter((f) => values[f.key] !== saved[f.key]);
      for (const f of changed) {
        const raw = values[f.key];
        const v = f.type === "number" ? Number(raw) : raw;
        await apiFetch(`/api/config/${encodeURIComponent(f.key)}`, {
          method: "PUT",
          body: JSON.stringify({ value: v }),
        });
      }
      setSaved({ ...values });
      setMsg(changed.length ? `已保存 ${changed.length} 项，立即生效（Worker ≤30 秒）` : "没有改动");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  function renderField(f: Field) {
    const v = values[f.key];
    if (f.type === "bool") {
      return (
        <select
          value={String(v ?? false)}
          onChange={(e) => set(f.key, e.target.value === "true")}
          className={SELECT_CLS}
        >
          <option value="true">开启</option>
          <option value="false">关闭</option>
        </select>
      );
    }
    if (f.type === "select") {
      return (
        <select
          value={String(v ?? "")}
          onChange={(e) => set(f.key, e.target.value)}
          className={SELECT_CLS}
        >
          {(f.options || []).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      );
    }
    if (f.type === "number") {
      return (
        <Input
          type="number"
          step="any"
          value={v === undefined || v === null ? "" : String(v)}
          onChange={(e) => set(f.key, e.target.value)}
        />
      );
    }
    return (
      <Input
        value={v === undefined || v === null ? "" : String(v)}
        onChange={(e) => set(f.key, e.target.value)}
      />
    );
  }

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-6">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold">系统配置</h1>
          <Button onClick={save} disabled={busy}>
            {busy ? "保存中…" : "保存"}
          </Button>
        </div>
        {msg && <p className="mb-3 text-sm text-primary">{msg}</p>}

        <div className="space-y-4">
          <ScopeManager />
          <ZeekPanel />
          <EsPanel />
          <EdgePanel />
          {GROUPS.map((g) => (
            <Card key={g.name}>
              <CardHeader>
                <CardTitle className="text-sm">{g.name}</CardTitle>
              </CardHeader>
              <CardContent className="grid grid-cols-3 gap-4">
                {g.fields.map((f) => (
                  <div key={f.key}>
                    <label className="mb-1 block text-xs text-muted-foreground">{f.label}</label>
                    {renderField(f)}
                    {f.hint && <p className="mt-1 text-[11px] text-muted-foreground">{f.hint}</p>}
                  </div>
                ))}
              </CardContent>
            </Card>
          ))}
        </div>
      </main>
    </div>
  );
}
