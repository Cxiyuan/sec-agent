"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type McpCall,
  type McpConclusion,
  type McpStatus,
  type McpToken,
  type McpToolSpec,
} from "@/lib/api";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@shentong/ui";

/** MCP 接入：令牌（生成 / 吊销）、最近调用、写回的结论、暴露的工具。 */
export function McpPanel() {
  const [status, setStatus] = React.useState<McpStatus | null>(null);
  const [tokens, setTokens] = React.useState<McpToken[]>([]);
  const [calls, setCalls] = React.useState<McpCall[]>([]);
  const [conclusions, setConclusions] = React.useState<McpConclusion[]>([]);
  const [tools, setTools] = React.useState<McpToolSpec[]>([]);
  const [name, setName] = React.useState("");
  const [fresh, setFresh] = React.useState("");
  const [showTools, setShowTools] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function load() {
    apiFetch<McpStatus>("/api/mcp/status")
      .then(setStatus)
      .catch(() => setStatus(null));
    apiFetch<{ tokens: McpToken[] }>("/api/mcp/tokens")
      .then((d) => setTokens(d.tokens))
      .catch(() => setTokens([]));
    apiFetch<{ calls: McpCall[] }>("/api/mcp/calls?limit=30")
      .then((d) => setCalls(d.calls))
      .catch(() => setCalls([]));
    apiFetch<{ conclusions: McpConclusion[] }>("/api/mcp/conclusions?limit=20")
      .then((d) => setConclusions(d.conclusions))
      .catch(() => setConclusions([]));
    apiFetch<{ tools: McpToolSpec[] }>("/api/mcp/tools")
      .then((d) => setTools(d.tools))
      .catch(() => setTools([]));
  }

  React.useEffect(() => {
    load().catch(() => {});
  }, []);

  async function createToken() {
    setBusy(true);
    setMsg("");
    setFresh("");
    try {
      const r = await apiFetch<{ token: string }>("/api/mcp/tokens", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      setFresh(r.token);
      setName("");
      setMsg("令牌已生成 —— 明文只显示这一次，请立刻填进智能体配置");
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "生成失败");
    } finally {
      setBusy(false);
    }
  }

  async function toggleToken(t: McpToken) {
    setBusy(true);
    setMsg("");
    try {
      await apiFetch(`/api/mcp/tokens/${t.id}/state`, {
        method: "POST",
        body: JSON.stringify({ enabled: !t.enabled }),
      });
      setMsg(t.enabled ? "已吊销（立即生效，无需重启）" : "已启用");
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "操作失败");
    } finally {
      setBusy(false);
    }
  }

  async function removeToken(t: McpToken) {
    setBusy(true);
    setMsg("");
    try {
      await apiFetch(`/api/mcp/tokens/${t.id}`, { method: "DELETE" });
      setMsg("已删除（仅在从未使用过时才建议删除；用过请用吊销）");
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "删除失败");
    } finally {
      setBusy(false);
    }
  }

  async function copyFresh() {
    try {
      await navigator.clipboard.writeText(fresh);
      setMsg("已复制到剪贴板");
    } catch {
      setMsg("复制失败，请手动选中上面的明文");
    }
  }

  async function clearCalls() {
    setBusy(true);
    try {
      await apiFetch("/api/mcp/calls", { method: "DELETE" });
      setMsg("调用记录已清空");
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "清空失败");
    } finally {
      setBusy(false);
    }
  }

  const prefix = status?.token_prefix ?? "stmcp_";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">MCP 接入（智能体取数入口）</CardTitle>
        <p className="text-xs text-muted-foreground">
          智能体分析事件时的查询、调查、写回结论都走这个服务，<b>不再直连 ES</b>。
          令牌在这里生成与吊销，明文只显示一次（库里只存哈希）；忘了就吊销重建。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}

        {status && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border p-3 text-xs">
            <Badge variant={status.service.reachable ? "low" : "high"}>
              {status.service.reachable ? "服务在线" : "服务不可达"}
            </Badge>
            <span className="font-mono">{status.service.url}</span>
            <span className="text-muted-foreground">工具 {status.tools.count} 个</span>
            <span className="text-muted-foreground">
              令牌 {status.tokens.enabled}/{status.tokens.total} 启用
            </span>
            <span className="text-muted-foreground">
              调用留存 {status.calls.kept}（失败 {status.calls.errors}）
            </span>
            <span className="text-muted-foreground">结论 {status.conclusions.total} 条</span>
            {status.service.error && (
              <span className="text-muted-foreground">（探测失败：{status.service.error}）</span>
            )}
          </div>
        )}

        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              新令牌名称（例如「智能体-生产」）
            </label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="留空也行，只是界面里不好认"
            />
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button onClick={createToken} disabled={busy}>
            生成令牌
          </Button>
          <Button variant="outline" onClick={() => load()} disabled={busy}>
            刷新
          </Button>
          <Button variant="secondary" onClick={clearCalls} disabled={busy}>
            清空调用记录
          </Button>
        </div>

        {fresh && (
          <div className="space-y-2 rounded-md border border-primary/40 p-3 text-xs">
            <p className="font-medium">新令牌明文（只显示这一次）</p>
            <p className="break-all font-mono">{fresh}</p>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={copyFresh}>
                复制
              </Button>
              <Button variant="secondary" onClick={() => setFresh("")}>
                我已保存，隐藏
              </Button>
            </div>
            <p className="text-muted-foreground">
              填进智能体配置：地址 <span className="font-mono">{status?.service.url ?? ""}</span>，
              请求头 <span className="font-mono">Authorization: Bearer &lt;令牌&gt;</span>。
            </p>
          </div>
        )}

        <div className="space-y-2 rounded-md border p-3 text-xs">
          <p className="text-muted-foreground">令牌列表（只显示前缀与用量）</p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>名称</TableHead>
                <TableHead>前缀</TableHead>
                <TableHead>调用次数</TableHead>
                <TableHead>最近使用</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>{t.name || "-"}</TableCell>
                  <TableCell className="font-mono">
                    {prefix}
                    {t.prefix}…
                  </TableCell>
                  <TableCell>{t.call_count}</TableCell>
                  <TableCell>{t.last_used_at ? t.last_used_at.slice(0, 19).replace("T", " ") : "-"}</TableCell>
                  <TableCell>
                    <Badge variant={t.enabled ? "low" : "high"}>{t.enabled ? "启用" : "已吊销"}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button variant="outline" onClick={() => toggleToken(t)} disabled={busy}>
                        {t.enabled ? "吊销" : "启用"}
                      </Button>
                      <Button variant="secondary" onClick={() => removeToken(t)} disabled={busy}>
                        删除
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {tokens.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    还没有令牌 —— 智能体现在连不上（先在上面生成一个）
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>

        <div className="space-y-2 rounded-md border p-3 text-xs">
          <p className="text-muted-foreground">
            最近调用（新的在前；记录放 Redis，重启即清，只作运维可见性）
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>工具</TableHead>
                <TableHead>令牌</TableHead>
                <TableHead>耗时</TableHead>
                <TableHead>结果</TableHead>
                <TableHead>参数摘录 / 错误</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {calls.map((c, i) => (
                <TableRow key={`${c.ts}-${i}`}>
                  <TableCell>{c.time || "-"}</TableCell>
                  <TableCell className="font-mono">{c.tool}</TableCell>
                  <TableCell>{c.token || "-"}</TableCell>
                  <TableCell>{c.duration_ms} ms</TableCell>
                  <TableCell>
                    <Badge variant={c.ok ? "low" : "high"}>{c.ok ? "成功" : "失败"}</Badge>
                  </TableCell>
                  <TableCell className="max-w-md truncate">
                    {c.ok ? c.detail || "-" : c.error || "未知错误"}
                  </TableCell>
                </TableRow>
              ))}
              {calls.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    最近没有调用（智能体还没查过数据，或刚重启过）
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>

        <div className="space-y-2 rounded-md border p-3 text-xs">
          <p className="text-muted-foreground">
            智能体写回的结论（判重仍由智能体侧负责，这里只是镜像，过期自动清理）
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>更新时间</TableHead>
                <TableHead>事件</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>等级</TableHead>
                <TableHead>结论</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {conclusions.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>
                    {c.updated_at ? c.updated_at.slice(0, 19).replace("T", " ") : "-"}
                  </TableCell>
                  <TableCell className="font-mono">{c.event_id || c.fingerprint || "-"}</TableCell>
                  <TableCell>{c.status || "-"}</TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        c.severity === "critical" || c.severity === "high"
                          ? "high"
                          : c.severity === "medium"
                            ? "medium"
                            : "info"
                      }
                    >
                      {c.severity || "-"}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-md truncate">{c.summary || "-"}</TableCell>
                </TableRow>
              ))}
              {conclusions.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    还没有结论写回
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>

        <div className="space-y-2 rounded-md border p-3 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground">
              暴露给智能体的工具（{tools.length} 个，参数说明以服务端为准）
            </span>
            <Button variant="outline" onClick={() => setShowTools((v) => !v)}>
              {showTools ? "收起" : "展开"}
            </Button>
          </div>
          {showTools && (
            <Table>
              <TableBody>
                {tools.map((t) => (
                  <TableRow key={t.name}>
                    <TableCell className="w-48 font-mono align-top">{t.name}</TableCell>
                    <TableCell>
                      {t.desc}
                      <span className="ml-1 text-muted-foreground">
                        （{Object.entries(t.params).map(([k, v]) => `${k}: ${v}`).join("；")}）
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
