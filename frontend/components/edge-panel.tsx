"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
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
      .catch(() => {});
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
      <CardHeader>
        <CardTitle className="text-sm">边缘模型（本地 llama-server）</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {info && (
          <div className="grid grid-cols-3 gap-2 text-xs text-muted-foreground">
            <span>模型：{info.model_label}（固化）</span>
            <span>端口：{info.port}</span>
            <span>认证：{info.api_key_set ? "已启用" : "未启用"}</span>
          </div>
        )}
        <div className="flex items-end gap-2">
          <div className="flex-1">
            <label className="mb-1 block text-xs text-muted-foreground">边缘模型 IP</label>
            <Input
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="如 10.0.0.5（本机部署就填 127.0.0.1）"
            />
          </div>
          <Button variant="outline" onClick={test} disabled={testing}>
            {testing ? "测试中…" : "测试连接"}
          </Button>
          <Button onClick={save}>保存</Button>
        </div>
        {info && (
          <p className="text-xs text-muted-foreground">
            base_url：{info.base_url}（自动拼接 http://IP:{info.port}/v1）
          </p>
        )}
        {testMsg && <p className="text-sm text-primary">{testMsg}</p>}
        {saveMsg && <p className="text-sm text-primary">{saveMsg}</p>}
      </CardContent>
    </Card>
  );
}
