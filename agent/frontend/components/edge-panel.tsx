"use client";

import * as React from "react";
import { Button } from "@shentong/ui";
import { Card, CardContent } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { Skeleton } from "@shentong/ui";
import { apiFetch } from "@/lib/api";

interface EdgeInfo {
  ip: string;
  base_url: string;
  model_label: string;
  port: number;
  api_key_set: boolean;
}

export function EdgePanel() {
  const [info, setInfo] = React.useState<EdgeInfo | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [ip, setIp] = React.useState("");
  const [testMsg, setTestMsg] = React.useState("");
  const [saveMsg, setSaveMsg] = React.useState("");
  const [testing, setTesting] = React.useState(false);

  React.useEffect(() => {
    apiFetch<EdgeInfo>("/api/edge")
      .then((d) => {
        setInfo(d);
        setIp(d.ip);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  async function test() {
    setTesting(true);
    setTestMsg("测试中…");
    try {
      const r = await apiFetch<{ ok: boolean; detail: string; base_url: string }>(
        "/api/edge/test",
        { method: "POST", body: JSON.stringify({ ip }) }
      );
      setTestMsg(r.ok ? `✅ ${r.detail}（${r.base_url}）` : `❌ ${r.detail}`);
    } catch (e) {
      setTestMsg(e instanceof Error ? `❌ ${e.message}` : "❌ 测试失败");
    } finally {
      setTesting(false);
    }
  }

  async function save() {
    try {
      const r = await apiFetch<{ ip: string; base_url: string }>("/api/edge/ip", {
        method: "PUT",
        body: JSON.stringify({ ip }),
      });
      setInfo((s) => (s ? { ...s, ip: r.ip, base_url: r.base_url } : s));
      setSaveMsg("已保存，立即生效（Worker ≤30 秒）");
    } catch (e) {
      setSaveMsg(e instanceof Error ? e.message : "保存失败");
    }
  }

  return (
    <Card>
      <CardContent className="space-y-3 pt-4">
        {loading && <Skeleton className="h-3 w-64" />}
        {info && (
          <div className="grid grid-cols-1 gap-2 text-xs text-muted-foreground sm:grid-cols-3">
            <span>模型：{info.model_label}（固化）</span>
            <span className="tabular-nums">端口：{info.port}</span>
            <span>认证：{info.api_key_set ? "已启用" : "未启用"}</span>
          </div>
        )}
        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-[260px] flex-1">
            <label htmlFor="edge-ip" className="mb-1 block text-xs text-muted-foreground">
              边缘模型 IP
            </label>
            <Input
              id="edge-ip"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="如 10.0.0.5（本机部署就填 127.0.0.1）"
            />
          </div>
          <Button size="sm" variant="outline" onClick={test} disabled={testing}>
            {testing ? "测试中…" : "测试连接"}
          </Button>
          <Button size="sm" onClick={save}>
            保存
          </Button>
        </div>
        {info && (
          <p className="text-xs font-mono text-muted-foreground">
            base_url：{info.base_url}（自动拼接 http://IP:{info.port}/v1）
          </p>
        )}
        {testMsg && <p className="text-xs text-primary">{testMsg}</p>}
        {saveMsg && <p className="text-xs text-primary">{saveMsg}</p>}
      </CardContent>
    </Card>
  );
}
