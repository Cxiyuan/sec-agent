"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type EsConfigInfo,
  type EsStatus,
} from "@/lib/api";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@shentong/ui";

/** ES 管理：连接配置 / 保留期（ILM）/ 状态。 */
export function EsPanel() {
  const [cfg, setCfg] = React.useState<EsConfigInfo | null>(null);
  const [status, setStatus] = React.useState<EsStatus | null>(null);
  const [url, setUrl] = React.useState("");
  const [user, setUser] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [eventsIndex, setEventsIndex] = React.useState("");
  const [retention, setRetention] = React.useState("30");
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function load() {
    const d = await apiFetch<EsConfigInfo>("/api/es/config");
    setCfg(d);
    setUrl(d.url);
    setUser(d.username || "");
    setEventsIndex(d.events_index || "");
    setRetention(String(d.retention_days));
    apiFetch<EsStatus>("/api/es/status")
      .then(setStatus)
      .catch(() => setStatus(null));
  }

  React.useEffect(() => {
    load().catch(() => {});
  }, []);

  async function save() {
    setBusy(true);
    setMsg("");
    try {
      await apiFetch<EsConfigInfo>("/api/es/config", {
        method: "PUT",
        body: JSON.stringify({
          url,
          username: user,
          // 留空表示不改密码
          password: password || undefined,
          events_index: eventsIndex,
          retention_days: Number(retention) || undefined,
        }),
      });
      setPassword("");
      setMsg("已保存（分析链路即时生效）");
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<{ cluster_name?: string; version?: string }>("/api/es/test", {
        method: "POST",
        body: JSON.stringify({ url, username: user, password: password || undefined }),
      });
      setMsg(`连接成功：${r.cluster_name ?? "-"}（v${r.version ?? "-"}）`);
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "连接失败");
    } finally {
      setBusy(false);
    }
  }

  async function applyRetention() {
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<{ retention_days: number; policy: string; templates: string[] }>(
        "/api/es/apply-retention",
        { method: "POST", body: JSON.stringify({ retention_days: Number(retention) || 30 }) }
      );
      setMsg(
        `已下发 ILM：策略 ${r.policy}，保留 ${r.retention_days} 天；模板 ${r.templates.join(", ")}`
      );
      load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "下发失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Elasticsearch（连接 / 保留 / 状态）</CardTitle>
        <p className="text-xs text-muted-foreground">
          保留期通过 ILM 策略自动下发给 ES，让索引自动 rollover 与删除；
          <b>不得小于回溯封顶（{cfg?.retention_min_days ?? 7} 天）</b>，否则回溯会查不到日志。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}

        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">ES 地址</label>
            <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://es:9200" />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">用户名</label>
            <Input value={user} onChange={(e) => setUser(e.target.value)} placeholder="留空=免认证" />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              密码（{cfg?.password_set ? "已设置，留空不改" : "未设置"}）
            </label>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="留空则不修改"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              索引模式（Zeek 与 Wazuh 统一落这一族）
            </label>
            <Input value={eventsIndex} onChange={(e) => setEventsIndex(e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              保留天数（≥{cfg?.retention_min_days ?? 7}）
            </label>
            <Input
              type="number"
              value={retention}
              onChange={(e) => setRetention(e.target.value)}
              min={cfg?.retention_min_days ?? 7}
            />
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button onClick={save} disabled={busy}>
            保存连接配置
          </Button>
          <Button variant="outline" onClick={test} disabled={busy}>
            测试连接
          </Button>
          <Button variant="secondary" onClick={applyRetention} disabled={busy}>
            下发保留策略（ILM）
          </Button>
          <Button variant="outline" onClick={() => load()}>
            刷新状态
          </Button>
        </div>

        {status && (
          <div className="space-y-2 rounded-md border p-3 text-xs">
            <p className="flex items-center gap-2">
              <span className="text-muted-foreground">集群：</span>
              <span className="font-mono">{status.health.cluster_name ?? "-"}</span>
              <Badge
                variant={
                  status.health.status === "green"
                    ? "low"
                    : status.health.status === "yellow"
                      ? "medium"
                      : "high"
                }
              >
                {status.health.status ?? "unknown"}
              </Badge>
              <span className="text-muted-foreground">节点 {status.health.nodes ?? "-"}</span>
              <Badge variant={status.ilm.exists ? "info" : "medium"}>
                ILM {status.ilm.exists ? "已下发" : "未下发"}
              </Badge>
              <span className="text-muted-foreground">
                保留 {status.ilm.retention_days} 天 · 策略 {status.ilm.policy}
              </span>
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>索引</TableHead>
                  <TableHead>文档数</TableHead>
                  <TableHead>占用</TableHead>
                  <TableHead>创建时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {status.indices.slice(0, 30).map((i) => (
                  <TableRow key={i.index}>
                    <TableCell className="font-mono">{i.index}</TableCell>
                    <TableCell>{i.docs ?? "-"}</TableCell>
                    <TableCell>{i.store ?? "-"}</TableCell>
                    <TableCell>{i.created ?? "-"}</TableCell>
                  </TableRow>
                ))}
                {status.indices.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} className="text-center text-muted-foreground">
                      暂无匹配索引（检查索引模式或数据是否已入 ES）
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
