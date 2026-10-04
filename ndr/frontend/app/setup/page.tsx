"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";
import { ApiError, apiFetch, errorText } from "@/lib/api";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";

/** 与后端 parse_nets 同规则：换行/逗号分隔，忽略空行与 # 注释，去重保序。 */
function parseNets(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.replace(/,/g, "\n").split("\n")) {
    const v = raw.trim();
    if (!v || v.startsWith("#") || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

/**
 * 首次设置向导：未配置监控网段时强制停留在此页。
 * 这份清单既是 Zeek 的抓包范围，也是检测器的分析范围 —— 不配置则什么都不抓、什么都不分析。
 */
export default function SetupPage() {
  const router = useRouter();
  const [netsText, setNetsText] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [msg, setMsg] = React.useState("");

  const nets = parseNets(netsText);

  async function submit() {
    setMsg("");
    if (nets.length === 0) {
      setMsg("请至少填写一个网段或 IP（必填）");
      return;
    }
    setSaving(true);
    try {
      await apiFetch("/api/zeek/interface", {
        method: "PUT",
        body: JSON.stringify({ networks: netsText }),
      });
      router.replace("/");
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
          <CardTitle>首次设置 · 监控网段</CardTitle>
          <p className="mt-1 text-center text-xs text-muted-foreground">
            网络采集器只抓取「源或目的 IP 落在这些网段内」的流量，检测器也只分析这些流量。
            不配置则什么都抓不到、也什么都分析不了，因此此项为强制必填。
          </p>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <label
              htmlFor="setup-nets"
              className="mb-1 block text-xs text-muted-foreground"
            >
              网段或 IP *（一行一条，支持 CIDR 与单个 IP，也可用逗号分隔）
            </label>
            <textarea
              id="setup-nets"
              value={netsText}
              onChange={(e) => setNetsText(e.target.value)}
              className="h-32 w-full rounded-md border border-input bg-transparent p-2 font-mono text-sm"
              placeholder={"192.168.0.0/16\n10.0.0.0/8\n172.16.1.5"}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              已识别 {nets.length} 条；
              {nets.length > 0 ? nets.slice(0, 6).join("、") + (nets.length > 6 ? " …" : "") : "尚未填写"}
            </p>
          </div>
          {msg && <p className="text-sm text-destructive">{msg}</p>}
          <Button className="w-full" onClick={submit} disabled={saving}>
            {saving ? "保存中…" : "保存并开始分析"}
          </Button>
          <p className="text-center text-xs text-muted-foreground">
            网络采集器的抓包范围与本地网段都由这份清单生成；保存后可在左侧「监控网段」页继续调整。
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
