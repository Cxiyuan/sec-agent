"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { ScopeManager } from "@/components/scope-manager";
import { ZeekPanel } from "@/components/zeek-panel";
import { EsPanel } from "@/components/es-panel";
import { LogstashPanel } from "@/components/logstash-panel";
import { EdgePanel } from "@/components/edge-panel";
import { CloudPanel } from "@/components/cloud-panel";
import { ExclusionsPanel } from "@/components/exclusions-panel";
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
    name: "边缘模型调用",
    fields: [
      {
        key: "edge_review_concurrency",
        label: "批内并发度（1~16）",
        type: "number",
        hint: "一次研判里同时调用边缘模型的条数。服务器实测：并发 8 → 23 次/分，串行仅 ~5。改大即提速（上限 16 = 服务器槽位数）",
      },
      { key: "edge_thinking.semantic_merge", label: "语义关联开思考", type: "bool", hint: "判断两个事件组是否同一次攻击" },
      { key: "edge_thinking.triage_complex", label: "复杂研判开思考", type: "bool", hint: "Web攻击/恶意软件/C2/横向移动等" },
      { key: "edge_thinking.triage_simple", label: "简单研判开思考", type: "bool", hint: "扫描/爆破/常规连接" },
    ],
  },
  {
    name: "云端模型调用（限流）",
    fields: [
      {
        key: "cloud_max_concurrency",
        label: "云端并发峰值",
        type: "number",
        hint: "同时最多几个云端请求（默认 4）。定级/处置/报告已改成并发调用，这是限流闸门；改大要盯是否吃 429（重试为 3 次指数退避，仅对 429/5xx/超时生效）",
      },
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
  {
    name: "自主取证调查（攻击者案件）",
    fields: [
      { key: "investigation_enabled", label: "启用自主调查", type: "bool", hint: "关闭后不再自动调查，人工也无法发起" },
      { key: "investigation_min_severity", label: "准入级别", type: "select", options: ["critical", "high", "medium", "low"], hint: "只对 ≥ 该级别的案件开调查" },
      { key: "investigation_max_steps", label: "单轮最大步数", type: "number", hint: "每步 = 一次查询 + 一次模型决策" },
      { key: "investigation_max_queries", label: "单轮最大查询数", type: "number" },
      { key: "investigation_cooldown_minutes", label: "重跑冷却（分钟）", type: "number", hint: "冷却内新证据只累积、不重跑" },
      { key: "investigation_max_rounds_per_day", label: "单案每日轮次上限", type: "number" },
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
          id={f.key}
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
          id={f.key}
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
          id={f.key}
          type="number"
          step="any"
          value={v === undefined || v === null ? "" : String(v)}
          onChange={(e) => set(f.key, e.target.value)}
        />
      );
    }
    return (
      <Input
        id={f.key}
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
          <LogstashPanel />
          <CloudPanel />
          <EdgePanel />
          <ExclusionsPanel />
          {GROUPS.map((g) => (
            <Card key={g.name}>
              <CardHeader>
                <CardTitle className="text-sm">{g.name}</CardTitle>
              </CardHeader>
              <CardContent className="grid grid-cols-3 gap-4">
                {g.fields.map((f) => (
                  <div key={f.key}>
                    <label
                      htmlFor={f.key}
                      className="mb-1 block text-xs text-muted-foreground"
                    >
                      {f.label}
                    </label>
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
