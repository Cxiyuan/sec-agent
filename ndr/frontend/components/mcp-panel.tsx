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
import { emptyOrFailed, loadInto, PanelError, usePanelErrors } from "@/components/panel-error";

/** 读取失败的接口名（错误条与空态用，别再让 500 显示成「还没有令牌」）。 */
const SRC = {
  status: "MCP 状态（/api/mcp/status）",
  tokens: "令牌列表（/api/mcp/tokens）",
  calls: "调用记录（/api/mcp/calls）",
  conclusions: "写回结论（/api/mcp/conclusions）",
  tools: "工具清单（/api/mcp/tools）",
} as const;

/** 天数上限，与后端 `ndr/backend/app/api/routes/mcp.py` 的 MAX_TOKEN_DAYS 一致（超了后端会 400）。 */
const MAX_TOKEN_DAYS = 3650;

/** 解析输入框里的天数：留空 = 永不过期（null）；非法 = undefined（界面上报错，不发请求）。 */
function daysFromInput(raw: string): number | null | undefined {
  const s = raw.trim();
  if (!s) return null;
  const n = Number(s);
  if (!Number.isInteger(n) || n < 1 || n > MAX_TOKEN_DAYS) return undefined;
  return n;
}

/** 到期时间显示：ISO 串 → 本地「YYYY-MM-DD HH:mm」；空串 = 永不过期。 */
function fmtExpiry(iso: string | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** 还剩几天（用来在到期前提醒；已过期返回空串，由 Badge 负责说清）。 */
function daysLeft(iso: string | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const days = Math.ceil((t - Date.now()) / 86_400_000);
  return days > 0 ? `剩 ${days} 天` : "";
}

/** MCP 接入：令牌（生成 / 吊销）、最近调用、写回的结论、暴露的工具。 */
export function McpPanel() {
  const [status, setStatus] = React.useState<McpStatus | null>(null);
  const [tokens, setTokens] = React.useState<McpToken[]>([]);
  const [calls, setCalls] = React.useState<McpCall[]>([]);
  const [conclusions, setConclusions] = React.useState<McpConclusion[]>([]);
  const [tools, setTools] = React.useState<McpToolSpec[]>([]);
  const [name, setName] = React.useState("");
  const [expiresDays, setExpiresDays] = React.useState("");
  const [fresh, setFresh] = React.useState("");
  /** 正在改到期时间的令牌 id（空 = 没有在改） */
  const [expiryFor, setExpiryFor] = React.useState("");
  const [expiryDays, setExpiryDays] = React.useState("");
  const [showTools, setShowTools] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const errs = usePanelErrors();

  async function load() {
    errs.reset();
    await Promise.all([
      loadInto(errs, SRC.status, "/api/mcp/status", setStatus),
      loadInto(errs, SRC.tokens, "/api/mcp/tokens", (d: { tokens: McpToken[] }) =>
        setTokens(d.tokens),
      ),
      loadInto(errs, SRC.calls, "/api/mcp/calls?limit=30", (d: { calls: McpCall[] }) =>
        setCalls(d.calls),
      ),
      loadInto(
        errs,
        SRC.conclusions,
        "/api/mcp/conclusions?limit=20",
        (d: { conclusions: McpConclusion[] }) => setConclusions(d.conclusions),
      ),
      loadInto(errs, SRC.tools, "/api/mcp/tools", (d: { tools: McpToolSpec[] }) =>
        setTools(d.tools),
      ),
    ]);
  }

  React.useEffect(() => {
    void load();
    // 只在挂载时读一次；load 内部自己收错误，不再 `.catch(() => {})` 吞掉
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function createToken() {
    setBusy(true);
    setMsg("");
    setFresh("");
    const days = daysFromInput(expiresDays);
    if (days === undefined) {
      setMsg(`有效期要填 1~${MAX_TOKEN_DAYS} 的整数天数，或者留空表示永不过期`);
      setBusy(false);
      return;
    }
    try {
      const r = await apiFetch<{ token: string }>("/api/mcp/tokens", {
        method: "POST",
        // 留空就是永不过期（与既有令牌语义一致）：不传这个字段
        body: JSON.stringify(days === null ? { name } : { name, expires_in_days: days }),
      });
      setFresh(r.token);
      setName("");
      setExpiresDays("");
      setMsg(
        days === null
          ? "令牌已生成（永不过期）—— 明文只显示这一次，请立刻填进智能体配置"
          : `令牌已生成（${days} 天后过期）—— 明文只显示这一次，请立刻填进智能体配置`,
      );
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "生成失败");
    } finally {
      setBusy(false);
    }
  }

  /** 原地轮换：换新明文，旧明文立即失效（名称 / 用量 / 到期时间都保留）。 */
  async function rotateToken(t: McpToken) {
    const who = t.name || `${t.prefix}…`;
    if (
      !window.confirm(
        `轮换令牌「${who}」？会立刻换一个新明文，旧明文马上失效（智能体那边必须同步改，否则会连不上）。`,
      )
    ) {
      return;
    }
    setBusy(true);
    setMsg("");
    setFresh("");
    try {
      const r = await apiFetch<{ token: string }>(`/api/mcp/tokens/${t.id}/rotate`, {
        method: "POST",
      });
      setFresh(r.token);
      setMsg("已轮换 —— 新明文只显示这一次；旧明文已立即失效，请同步更新智能体配置");
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "轮换失败");
    } finally {
      setBusy(false);
    }
  }

  /** 设置 / 清除到期时间；`days === null` = 永不过期。 */
  async function saveExpiry(t: McpToken, days: number | null) {
    setBusy(true);
    setMsg("");
    try {
      await apiFetch(`/api/mcp/tokens/${t.id}/expiry`, {
        method: "POST",
        body: JSON.stringify({ expires_in_days: days }),
      });
      setMsg(
        days === null
          ? `「${t.name || t.prefix}」已设为永不过期`
          : `「${t.name || t.prefix}」已设为 ${days} 天后过期`,
      );
      setExpiryFor("");
      setExpiryDays("");
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "设置到期时间失败");
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
          令牌在这里生成、轮换与吊销，明文只显示一次（库里只存哈希）；忘了或怀疑泄露就轮换。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}
        <PanelError errors={errs} />

        {status && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border p-3 text-xs">
            <Badge variant={status.service.reachable ? "low" : "high"}>
              {status.service.reachable ? "服务在线" : "服务不可达"}
            </Badge>
            <span className="font-mono">{status.service.url}</span>
            <span className="text-muted-foreground">工具 {status.tools.count} 个</span>
            <span className="text-muted-foreground">
              令牌 {status.tokens.enabled}/{status.tokens.total} 启用
              {status.tokens.expired ? `（${status.tokens.expired} 个已过期）` : ""}
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
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              有效期（天，留空 = 永不过期）
            </label>
            <Input
              value={expiresDays}
              onChange={(e) => setExpiresDays(e.target.value)}
              placeholder="例如 90；1~3650"
              inputMode="numeric"
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
          <p className="text-muted-foreground">
            令牌列表（只显示前缀与用量）；过期令牌的调用会被直接拒绝，请先轮换或改到期时间
          </p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>名称</TableHead>
                <TableHead>前缀</TableHead>
                <TableHead>调用次数</TableHead>
                <TableHead>最近使用</TableHead>
                <TableHead>到期</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map((t) => (
                <React.Fragment key={t.id}>
                  <TableRow className={t.expired ? "bg-destructive/5" : undefined}>
                    <TableCell className={t.expired ? "text-destructive" : undefined}>
                      {t.name || "-"}
                    </TableCell>
                    <TableCell className="font-mono">
                      {prefix}
                      {t.prefix}…
                    </TableCell>
                    <TableCell>{t.call_count}</TableCell>
                    <TableCell>{t.last_used_at ? t.last_used_at.slice(0, 19).replace("T", " ") : "-"}</TableCell>
                    <TableCell>
                      {t.expired ? (
                        <Badge variant="high">已过期</Badge>
                      ) : t.expires_at ? (
                        <span>
                          {fmtExpiry(t.expires_at)}
                          {daysLeft(t.expires_at) && (
                            <span className="ml-1 text-muted-foreground">
                              （{daysLeft(t.expires_at)}）
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">永不过期</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant={t.enabled ? "low" : "high"}>{t.enabled ? "启用" : "已吊销"}</Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-2">
                        <Button variant="outline" onClick={() => rotateToken(t)} disabled={busy}>
                          轮换
                        </Button>
                        <Button
                          variant="outline"
                          onClick={() => {
                            setExpiryFor(expiryFor === t.id ? "" : t.id);
                            setExpiryDays("");
                            setMsg("");
                          }}
                          disabled={busy}
                        >
                          设到期
                        </Button>
                        <Button variant="outline" onClick={() => toggleToken(t)} disabled={busy}>
                          {t.enabled ? "吊销" : "启用"}
                        </Button>
                        <Button variant="secondary" onClick={() => removeToken(t)} disabled={busy}>
                          删除
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                  {expiryFor === t.id && (
                    <TableRow>
                      <TableCell colSpan={7} className="bg-muted/40">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-muted-foreground">
                            「{t.name || t.prefix}」的到期时间：
                          </span>
                          <Input
                            className="h-8 w-28"
                            value={expiryDays}
                            onChange={(e) => setExpiryDays(e.target.value)}
                            placeholder="天数，如 90"
                            inputMode="numeric"
                          />
                          <Button
                            variant="outline"
                            disabled={busy}
                            onClick={() => {
                              const d = daysFromInput(expiryDays);
                              if (d === undefined) {
                                setMsg(`有效期要填 1~${MAX_TOKEN_DAYS} 的整数天数`);
                                return;
                              }
                              if (d === null) {
                                setMsg("要「永不过期」请点右边那个按钮（留空不表示不改动）");
                                return;
                              }
                              void saveExpiry(t, d);
                            }}
                          >
                            设为该天数后过期
                          </Button>
                          <Button
                            variant="secondary"
                            disabled={busy}
                            onClick={() => void saveExpiry(t, null)}
                          >
                            永不过期
                          </Button>
                          <Button variant="ghost" onClick={() => setExpiryFor("")} disabled={busy}>
                            取消
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              ))}
              {tokens.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">
                    {emptyOrFailed(
                      errs,
                      SRC.tokens,
                      "还没有令牌 —— 智能体现在连不上（先在上面生成一个）",
                    )}
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
                    {emptyOrFailed(
                      errs,
                      SRC.calls,
                      "最近没有调用（智能体还没查过数据，或刚重启过）",
                    )}
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
                    {emptyOrFailed(errs, SRC.conclusions, "还没有结论写回")}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>

        <div className="space-y-2 rounded-md border p-3 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground">
              {errs.isFailed(SRC.tools)
                ? "工具清单读取失败（见上方错误条）"
                : `暴露给智能体的工具（${tools.length} 个，参数说明以服务端为准）`}
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
