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
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <div className="w-full max-w-[640px] space-y-3">
        <Card>
          <CardHeader>
            {/* 引导：序号 + 标题 + 说明 + 表单，一屏只做一件事 */}
            <div className="flex items-start gap-3">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-sm border border-border-subtle bg-surface-1 text-primary">
                <Shield className="h-4 w-4" />
              </span>
              <div className="min-w-0">
                <p className="text-xs tabular-nums text-muted-foreground">第 1 步 / 共 1 步 · 强制必填</p>
                <CardTitle className="mt-0.5">监控网段</CardTitle>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                  网络采集器只抓取「源或目的 IP 落在这些网段内」的流量，检测器也只分析这些流量。
                  不配置则什么都抓不到、也什么都分析不了。
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <label
                htmlFor="setup-nets"
                className="mb-1 block text-xs font-medium text-foreground"
              >
                网段或 IP <span className="text-sev-critical-fg">*</span>
                <span className="ml-1 font-normal text-muted-foreground">
                  （一行一条，支持 CIDR 与单个 IP，也可用逗号分隔）
                </span>
              </label>
              <textarea
                id="setup-nets"
                value={netsText}
                onChange={(e) => setNetsText(e.target.value)}
                aria-describedby="setup-nets-hint"
                className="h-32 w-full rounded-sm border border-border bg-surface-2 p-2 font-mono text-13 text-foreground transition-colors placeholder:text-muted-foreground focus-visible:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
                placeholder={"192.168.0.0/16\n10.0.0.0/8\n172.16.1.5"}
              />
              <p
                id="setup-nets-hint"
                className="mt-1 text-xs tabular-nums text-muted-foreground"
              >
                已识别 {nets.length} 条；
                {nets.length > 0
                  ? nets.slice(0, 6).join("、") + (nets.length > 6 ? " …" : "")
                  : "尚未填写"}
              </p>
            </div>
            {msg && (
              <p
                role="alert"
                className="rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-2 py-1.5 text-xs text-sev-critical-fg"
              >
                {msg}
              </p>
            )}
            <Button className="w-full" onClick={submit} disabled={saving}>
              {saving ? "保存中…" : "保存并开始分析"}
            </Button>
          </CardContent>
        </Card>
        <p className="text-center text-xs leading-relaxed text-muted-foreground">
          网络采集器的抓包范围与本地网段都由这份清单生成；保存后可在左侧「监控网段」页继续调整。
        </p>
      </div>
    </div>
  );
}
