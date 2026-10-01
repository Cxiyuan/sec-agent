"use client";

import * as React from "react";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { apiFetch } from "@/lib/api";

interface CloudInfo {
  api_key_set: boolean;
  api_key_masked: string;
}

export function CloudPanel() {
  const [info, setInfo] = React.useState<CloudInfo | null>(null);
  const [apiKey, setApiKey] = React.useState("");
  const [msg, setMsg] = React.useState("");

  React.useEffect(() => {
    apiFetch<CloudInfo>("/api/cloud")
      .then(setInfo)
      .catch(() => {});
  }, []);

  async function save() {
    if (!apiKey.trim()) {
      setMsg("请输入 API Key");
      return;
    }
    try {
      const r = await apiFetch<CloudInfo>("/api/cloud/key", {
        method: "PUT",
        body: JSON.stringify({ api_key: apiKey.trim() }),
      });
      setInfo(r);
      setApiKey("");
      setMsg("已保存到数据库，立即生效（Worker ≤30 秒）");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "保存失败");
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">云端模型（日常分析 / 深度分析 / 向量）</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">
          状态：{info?.api_key_set ? `已配置（${info.api_key_masked}）` : "未配置"}
        </p>
        <div className="flex items-end gap-2">
          <div className="flex-1">
            <label className="mb-1 block text-xs text-muted-foreground">
              API Key（填入后保存，仅保存到数据库，界面不回显明文）
            </label>
            <Input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="粘贴 API Key"
            />
          </div>
          <Button onClick={save}>保存</Button>
        </div>
        {msg && <p className="text-sm text-primary">{msg}</p>}
      </CardContent>
    </Card>
  );
}
