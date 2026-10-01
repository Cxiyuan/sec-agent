"use client";

import * as React from "react";
import { Nav } from "@/components/nav";
import { EdgePanel } from "@/components/edge-panel";
import { CloudPanel } from "@/components/cloud-panel";
import { Button, Card, CardContent, CardHeader, CardTitle, Input } from "@shentong/ui";
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
    ],
  },
  {
    name: "误报治理",
    fields: [
      {
        key: "policy_internal_routine_skip",
        label: "内网常规流量跳过分析",
        type: "bool",
        hint: "内→内 + 低危逐条规则 + 单目标 + 无成功连接 → 只落库不出报告（横向移动/扇出照旧分析）。跳过会计数，界面可查",
      },
      {
        key: "policy_internal_routine_min_severity",
        label: "跳过所需规则级别上限",
        type: "select",
        options: ["low", "medium", "high"],
        hint: "规则严重度 ≥ 该值就不跳过（默认 medium：只跳 low/info 的）",
      },
      { key: "policy_internal_routine_max_dst", label: "跳过允许的最大目标数", type: "number", hint: "超过该目标数（疑似扫描/扇出）照旧全量分析" },
      { key: "policy_internal_routine_require_failed", label: "必须无成功连接才跳过", type: "bool" },
      {
        key: "severity_cap_internal",
        label: "内网方向定级封顶",
        type: "select",
        options: ["critical", "high", "medium", "low"],
        hint: "内→内 事件的级别上限（默认 medium）",
      },
      {
        key: "severity_require_evidence_above",
        label: "无证据链不得达到",
        type: "select",
        options: ["critical", "high", "medium"],
        hint: "攻击链为空（没有可验证证据）时，级别封顶到该值以下；每处降级都会写明原因",
      },
      { key: "severity_critical_requires_external", label: "critical 仅限外→内", type: "bool" },
      {
        key: "escalate_require_rule_severity",
        label: "升级所需规则级别",
        type: "select",
        options: ["low", "medium", "high", "critical"],
        hint: "进深度分析除分数达标外，还要求规则严重度 ≥ 该值（防小模型高分全量升级）",
      },
      { key: "escalate_allow_external", label: "外→内事件不受升级闸门限制", type: "bool" },
      { key: "prefilter_penalty_established", label: "预筛：内网已建立会话扣分", type: "number", hint: "内网内部双向有字节的已建立连接（正常业务）。对外已建立连接不扣分——那正是 C2 形状" },
      { key: "prefilter_penalty_common_port", label: "预筛：常用端口扣分", type: "number" },
      { key: "prefilter_penalty_known_asset", label: "预筛：已录资产目标扣分", type: "number" },
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
          <CloudPanel />
          <EdgePanel />
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
