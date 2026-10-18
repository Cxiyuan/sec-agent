"use client";

import * as React from "react";
import { Button } from "@shentong/ui";
import { Card, CardContent } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { Skeleton } from "@shentong/ui";
import { apiFetch } from "@/lib/api";

interface CloudInfo {
  api_key_set: boolean;
  api_key_masked: string;
}

export function CloudPanel() {
  const [info, setInfo] = React.useState<CloudInfo | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [apiKey, setApiKey] = React.useState("");
  const [msg, setMsg] = React.useState("");

  React.useEffect(() => {
    apiFetch<CloudInfo>("/api/cloud")
      .then(setInfo)
      .catch(() => {})
      .finally(() => setLoading(false));
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
      <CardContent className="space-y-3 pt-4">
        {loading ? (
          <Skeleton className="h-3 w-40" />
        ) : (
          <p className="text-xs text-muted-foreground">
            状态：{info?.api_key_set ? `已配置（${info.api_key_masked}）` : "未配置"}
          </p>
        )}
        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-[260px] flex-1">
            <label htmlFor="cloud-api-key" className="mb-1 block text-xs text-muted-foreground">
              API Key（填入后保存，仅保存到数据库，界面不回显明文）
            </label>
            <Input
              id="cloud-api-key"
              type="password"
              autoComplete="off"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="粘贴 API Key"
            />
          </div>
          <Button size="sm" onClick={save}>
            保存
          </Button>
        </div>
        {msg && <p className="text-xs text-primary">{msg}</p>}
      </CardContent>
    </Card>
  );
}
