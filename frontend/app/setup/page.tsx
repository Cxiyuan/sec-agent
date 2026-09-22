"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";
import { ApiError, apiFetch, errorText, type AnalysisScope } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

/**
 * 首次设置向导：未配置分析网段时强制停留在此页。
 * 必须至少填写一个网段或 IP，否则智能体不会拉取任何日志。
 */
export default function SetupPage() {
  const router = useRouter();
  const [name, setName] = React.useState("默认分析网段");
  const [desc, setDesc] = React.useState("");
  const [cidrText, setCidrText] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [msg, setMsg] = React.useState("");

  const cidrs = cidrText
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter(Boolean);

  async function submit() {
    setMsg("");
    if (!name.trim()) {
      setMsg("请填写网段组名称");
      return;
    }
    if (cidrs.length === 0) {
      setMsg("请至少填写一个网段或 IP（必填）");
      return;
    }
    setSaving(true);
    try {
      await apiFetch<AnalysisScope>("/api/analysis-scopes", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          description: desc,
          cidrs,
          enabled: true,
        }),
      });
      router.replace("/dashboard");
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <Card className="w-[640px]">
        <CardHeader className="items-center">
          <Shield className="mb-2 h-10 w-10 text-primary" />
          <CardTitle>首次设置 · 分析网段</CardTitle>
          <p className="mt-1 text-center text-xs text-muted-foreground">
            智能体只会分析「源或目的 IP 落在这些网段内」的日志。不配置则不分析任何日志，因此此项为强制必填。
          </p>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">网段组名称 *</label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="如：内网资产 / 生产网" />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              网段或 IP *（逗号或换行分隔，支持 CIDR 与单个 IP）
            </label>
            <textarea
              value={cidrText}
              onChange={(e) => setCidrText(e.target.value)}
              className="h-32 w-full rounded-md border border-input bg-transparent p-2 font-mono text-sm"
              placeholder={"192.168.0.0/16\n10.0.0.0/8\n172.16.1.5"}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              已识别 {cidrs.length} 条；
              {cidrs.length > 0 ? cidrs.slice(0, 6).join("、") + (cidrs.length > 6 ? " …" : "") : "尚未填写"}
            </p>
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">说明（可选）</label>
            <Input value={desc} onChange={(e) => setDesc(e.target.value)} />
          </div>
          {msg && <p className="text-sm text-destructive">{msg}</p>}
          <Button className="w-full" onClick={submit} disabled={saving}>
            {saving ? "保存中…" : "保存并开始分析"}
          </Button>
          <p className="text-center text-xs text-muted-foreground">
            保存后可在「系统配置 → 分析网段」继续维护多套网段组（可启用/停用）。
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
