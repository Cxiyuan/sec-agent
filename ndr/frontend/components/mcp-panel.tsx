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
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Dialog,
  EmptyState,
  Field,
  Input,
  Section,
  SettingsForm,
  SettingsGrid,
  SettingsMain,
  SettingsRail,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
  formatDateTime,
  severityVariant,
} from "@shentong/ui";
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

/** 到期时间显示：ISO 串 → 北京时间「YYYY-MM-DD HH:mm:ss」；空串 = 永不过期。 */
function fmtExpiry(iso: string | undefined): string {
  if (!iso) return "";
  return formatDateTime(iso);
}

/** 还剩几天（用来在到期前提醒；已过期返回空串，由 Badge 负责说清）。 */
function daysLeft(iso: string | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const days = Math.ceil((t - Date.now()) / 86_400_000);
  return days > 0 ? `剩 ${days} 天` : "";
}

/**
 * MCP 接入：令牌（生成 / 吊销）、最近调用、写回的结论、暴露的工具。
 *
 * 版式（2026-10 统一到设计体系）：
 * - 区块标题与说明走 `Section`（L1），内容是一张 `Card`（L2），三张表落在 `surface-1`
 *   的内联块（L3）里，不再用 `CardTitle` 当区块标题；
 * - 令牌前缀 / 工具名 / 事件 ID / 时间戳保留 `font-mono text-xs`（等宽是为了对位），
 *   其余单元格吃 `Table` 内置的 13px；
 * - 首屏（status 还没回来且无失败）画骨架 —— 「正在读」不能渲染成「还没有令牌」。
 */
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
  /** 轮换会立刻作废旧明文：走共享 `Dialog` 二次确认，不用 `window.confirm`。 */
  const [rotateAsk, setRotateAsk] = React.useState<McpToken | null>(null);
  /** 这一轮接口读完了没（成功或失败都算读完）——「正在读」要和「真的没有」分开画。 */
  const [ready, setReady] = React.useState(false);
  const errs = usePanelErrors();
  /** 空态里的「去生成令牌」复用上面的表单：聚焦名称输入框，不另写创建逻辑。 */
  const nameRef = React.useRef<HTMLInputElement>(null);

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
    setReady(true);
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

  /**
   * 首次加载：这一轮还没读完、也没有任何失败 —— 这时**不能**按「还没有令牌」渲染，
   * 否则运维第一眼看到的是"服务没配"，而实际只是接口慢（内网 200ms~2s 很常见）。
   */
  if (!ready && !errs.has) {
    return (
      <div className="space-y-4" aria-busy="true">
        <Section
          title="MCP 接入（智能体取数入口）"
          description="智能体分析事件时的查询、调查、写回结论都走这个服务；令牌在这里生成、轮换与吊销。"
        >
          {/* 骨架与加载完的结构同形：主列表单、侧栏服务状态、下面四张整幅表，避免出数时跳版 */}
          <SettingsGrid>
            <SettingsMain>
              <Card>
                <CardHeader>
                  <CardTitle>签发新令牌</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <Skeleton className="h-14" />
                    <Skeleton className="h-14" />
                  </div>
                  <Skeleton className="h-8 w-28" />
                </CardContent>
              </Card>
            </SettingsMain>

            <SettingsRail>
              <Card>
                <CardHeader>
                  <CardTitle>服务状态</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Skeleton className="h-5 w-20" />
                  <Skeleton className="h-3 w-full" />
                  <Skeleton className="h-3 w-2/3" />
                </CardContent>
              </Card>
            </SettingsRail>
          </SettingsGrid>

          <Card>
            <CardContent className="space-y-2">
              <Skeleton className="h-3 w-24" />
              <TableSkeleton rows={3} cols={7} />
            </CardContent>
          </Card>

          <Card>
            <CardContent className="space-y-2">
              <Skeleton className="h-3 w-20" />
              <TableSkeleton rows={4} cols={6} />
            </CardContent>
          </Card>

          {/* 后面还有两张整幅卡（写回结论 5 列、工具清单）：骨架只画前两张的话，
              内容到达时页面会往下长一截，正在读的位置跟着跳。 */}
          <Card>
            <CardContent className="space-y-2">
              <Skeleton className="h-3 w-24" />
              <TableSkeleton rows={3} cols={5} />
            </CardContent>
          </Card>

          <Card>
            <CardContent className="space-y-2">
              <Skeleton className="h-3 w-40" />
              <Skeleton className="h-8 w-16" />
            </CardContent>
          </Card>
        </Section>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />

      <Section
        title="MCP 接入（智能体取数入口）"
        description={
          <>
            智能体分析事件时的查询、调查、写回结论都走这个服务，<b>不再直连 ES</b>。
            令牌在这里生成、轮换与吊销，明文只显示一次（库里只存哈希）；忘了或怀疑泄露就轮换。
          </>
        }
      >
        {/* 能改的只有「签发新令牌」这一张表单，放主列；服务状态只读，放右侧。
            已签发令牌（7 列）、最近调用（6 列）、写回结论（5 列）、工具清单 —— 四张都在
            Grid 之外整幅竖排：它们并排后每张不足 3 列宽，挤在主列里会触发横向滚动。 */}
        <SettingsGrid>
          <SettingsMain>
            <Card>
              <CardHeader>
                <CardTitle>签发新令牌</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {msg ? (
                  <p className="text-13 text-muted-foreground" aria-live="polite">
                    {msg}
                  </p>
                ) : null}
                <SettingsForm>
                  <Field label="新令牌名称（例如「智能体-生产」）" htmlFor="mcp-token-name">
                    <Input
                      id="mcp-token-name"
                      ref={nameRef}
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="留空也行，只是界面里不好认"
                    />
                  </Field>
                  <Field label="有效期（天，留空 = 永不过期）" htmlFor="mcp-token-days">
                    <Input
                      id="mcp-token-days"
                      value={expiresDays}
                      onChange={(e) => setExpiresDays(e.target.value)}
                      placeholder="例如 90；1~3650"
                      inputMode="numeric"
                    />
                  </Field>
                </SettingsForm>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" onClick={createToken} disabled={busy}>
                    生成令牌
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => load()} disabled={busy}>
                    刷新
                  </Button>
                  <Button size="sm" variant="destructive" onClick={clearCalls} disabled={busy}>
                    清空调用记录
                  </Button>
                </div>
                {fresh && (
                  <div className="space-y-2 rounded-md border border-primary/40 bg-surface-1 p-3 text-xs">
                    <p className="font-medium text-foreground">新令牌明文（只显示这一次）</p>
                    <p className="break-all font-mono text-foreground">{fresh}</p>
                    <div className="flex flex-wrap gap-2">
                      <Button size="sm" variant="outline" onClick={copyFresh}>
                        复制
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => setFresh("")}>
                        我已保存，隐藏
                      </Button>
                    </div>
                    <p className="text-muted-foreground">
                      填进智能体配置：地址{" "}
                      <span className="font-mono">{status?.service.url ?? ""}</span>， 请求头{" "}
                      <span className="font-mono">Authorization: Bearer &lt;令牌&gt;</span>。
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </SettingsMain>

          <SettingsRail>
            <Card>
              <CardHeader>
                <CardTitle>服务状态</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {/* 补两行：服务不可达时给出 HTTP 码（排障时第一个要的字段）与最近调用时间。
                    空值一律有文案，不留空白行。 */}
                {status ? (
                  <div className="divide-y divide-border-subtle rounded-xs bg-surface-1 px-3 py-2 text-xs tabular-nums">
                    <p className="flex flex-wrap items-center gap-2 pb-1">
                      <Badge variant={status.service.reachable ? "success" : "critical"}>
                        {status.service.reachable ? "服务在线" : "服务不可达"}
                      </Badge>
                    </p>
                    <p className="py-1">
                      <span className="text-muted-foreground">服务地址</span>
                      <span className="mt-0.5 block break-all font-mono">{status.service.url || "—"}</span>
                    </p>
                    {!status.service.reachable && status.service.status_code ? (
                      <p className="py-1">
                        <span className="text-muted-foreground">HTTP 码</span>
                        <span className="mt-0.5 block">{status.service.status_code}</span>
                      </p>
                    ) : null}
                    <p className="py-1">
                      <span className="text-muted-foreground">工具</span>
                      <span className="mt-0.5 block">{status.tools.count ?? "—"} 个</span>
                    </p>
                    <p className="py-1">
                      <span className="text-muted-foreground">令牌</span>
                      <span className="mt-0.5 block">
                        {status.tokens.enabled}/{status.tokens.total} 启用
                        {status.tokens.expired ? `（${status.tokens.expired} 个已过期）` : ""}
                      </span>
                    </p>
                    <p className="py-1">
                      <span className="text-muted-foreground">调用留存</span>
                      <span className="mt-0.5 block">
                        {status.calls.kept}（失败 {status.calls.errors}）
                      </span>
                    </p>
                    <p className="py-1">
                      <span className="text-muted-foreground">最近调用</span>
                      <span className="mt-0.5 block">
                        {status.calls.last_at ? formatDateTime(status.calls.last_at) : "—"}
                      </span>
                    </p>
                    <p className="py-1">
                      <span className="text-muted-foreground">结论</span>
                      <span className="mt-0.5 block">{status.conclusions.total} 条</span>
                    </p>
                    {status.service.error ? (
                      <p className="pt-1 text-muted-foreground">探测失败：{status.service.error}</p>
                    ) : null}
                  </div>
                ) : (
                  <EmptyState
                    size="compact"
                    tone={errs.isFailed(SRC.status) ? "danger" : "muted"}
                    title={emptyOrFailed(errs, SRC.status, "还没有读到服务状态")}
                    action={
                      <Button size="sm" variant="outline" onClick={() => void load()}>
                        重新读取
                      </Button>
                    }
                  />
                )}
              </CardContent>
            </Card>
          </SettingsRail>
        </SettingsGrid>

        {/* 已签发令牌：7 列表格（名称/前缀/调用次数/最近使用/到期/状态/操作）整幅排。
            它留在主列会让「操作」那一列的三个按钮在 758px 里挤成两行并触发横向滚动，
            而这是本页最常用的表 —— 轮换与吊销都在这里按。 */}
        <Card>
          <CardHeader>
            <CardTitle>已签发令牌</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 rounded-xs bg-surface-1 px-3 py-2">
              <p className="text-xs text-muted-foreground">
                令牌列表（只显示前缀与用量）；过期令牌的调用会被直接拒绝，请先轮换或改到期时间
              </p>
              {!ready ? (
                <TableSkeleton rows={3} cols={5} />
              ) : tokens.length === 0 ? (
                <EmptyState
                  size="compact"
                  title={emptyOrFailed(
                    errs,
                    SRC.tokens,
                    "还没有令牌 —— 智能体现在连不上（先在上面生成一个）",
                  )}
                  hint={
                    errs.isFailed(SRC.tokens)
                      ? "令牌列表读取失败，不是「一个都没有」"
                      : "生成后把明文填进智能体配置，明文只显示这一次"
                  }
                  tone={errs.isFailed(SRC.tokens) ? "danger" : "muted"}
                  action={
                    errs.isFailed(SRC.tokens) ? (
                      <Button size="sm" variant="outline" onClick={() => void load()}>
                        重新读取
                      </Button>
                    ) : (
                      <Button size="sm" variant="outline" onClick={() => nameRef.current?.focus()}>
                        去生成令牌
                      </Button>
                    )
                  }
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>名称</TableHead>
                      <TableHead>前缀</TableHead>
                      <TableHead className="text-right">调用次数</TableHead>
                      <TableHead>最近使用</TableHead>
                      <TableHead>到期</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tokens.map((t) => (
                      <React.Fragment key={t.id}>
                        <TableRow className={t.expired ? "bg-sev-critical-bg" : undefined}>
                          <TableCell
                            className={t.expired ? "font-medium text-sev-critical-fg" : "font-medium"}
                          >
                            {t.name || "-"}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {prefix}
                            {t.prefix}…
                          </TableCell>
                          <TableCell className="text-right tabular-nums">{t.call_count}</TableCell>
                          <TableCell className="whitespace-nowrap font-mono text-xs">
                            {t.last_used_at ? formatDateTime(t.last_used_at) : "-"}
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            {t.expired ? (
                              <Badge variant="high">已过期</Badge>
                            ) : t.expires_at ? (
                              <span>
                                <span className="font-mono text-xs">
                                  {fmtExpiry(t.expires_at)}
                                </span>
                                {daysLeft(t.expires_at) && (
                                  <span className="ml-1 text-xs tabular-nums text-muted-foreground">
                                    （{daysLeft(t.expires_at)}）
                                  </span>
                                )}
                              </span>
                            ) : (
                              <span className="text-xs text-muted-foreground">永不过期</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <Badge variant={t.enabled ? "success" : "critical"}>
                              {t.enabled ? "启用" : "已吊销"}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1.5">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => setRotateAsk(t)}
                                disabled={busy}
                              >
                                轮换
                              </Button>
                              <Button
                                size="sm"
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
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => toggleToken(t)}
                                disabled={busy}
                              >
                                {t.enabled ? "吊销" : "启用"}
                              </Button>
                              <Button
                                size="sm"
                                variant="destructive"
                                onClick={() => removeToken(t)}
                                disabled={busy}
                              >
                                删除
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                        {expiryFor === t.id && (
                          <TableRow>
                            <TableCell colSpan={7} className="bg-surface-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-xs text-muted-foreground">
                                  「{t.name || t.prefix}」的到期时间：
                                </span>
                                <Input
                                  aria-label={`「${t.name || t.prefix}」的到期天数`}
                                  className="h-8 w-28"
                                  value={expiryDays}
                                  onChange={(e) => setExpiryDays(e.target.value)}
                                  placeholder="天数，如 90"
                                  inputMode="numeric"
                                />
                                <Button
                                  size="sm"
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
                                  size="sm"
                                  variant="secondary"
                                  disabled={busy}
                                  onClick={() => void saveExpiry(t, null)}
                                >
                                  永不过期
                                </Button>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => setExpiryFor("")}
                                  disabled={busy}
                                >
                                  取消
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </React.Fragment>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="space-y-2">
            <div className="space-y-2 rounded-xs bg-surface-1 px-3 py-2">
              <p className="text-xs text-muted-foreground">
                最近调用（新的在前；记录放 Redis，重启即清，只作运维可见性）
              </p>
              {!ready ? (
                <TableSkeleton rows={4} cols={5} />
              ) : calls.length === 0 ? (
                <EmptyState
                  size="compact"
                  title={emptyOrFailed(
                    errs,
                    SRC.calls,
                    "最近没有调用（智能体还没查过数据，或刚重启过）",
                  )}
                  tone={errs.isFailed(SRC.calls) ? "danger" : "muted"}
                  action={
                    errs.isFailed(SRC.calls) ? (
                      <Button size="sm" variant="outline" onClick={() => void load()}>
                        重新读取
                      </Button>
                    ) : undefined
                  }
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>时间</TableHead>
                      <TableHead>工具</TableHead>
                      <TableHead>令牌</TableHead>
                      <TableHead className="text-right">耗时</TableHead>
                      <TableHead>结果</TableHead>
                      <TableHead>参数摘录 / 错误</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {calls.map((c, i) => (
                      <TableRow key={`${c.ts}-${i}`}>
                        <TableCell className="whitespace-nowrap font-mono text-xs">
                          {c.time || "-"}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{c.tool}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {c.token || "-"}
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-right tabular-nums">
                          {c.duration_ms} ms
                        </TableCell>
                        <TableCell>
                          <Badge variant={c.ok ? "success" : "critical"}>
                            {c.ok ? "成功" : "失败"}
                          </Badge>
                        </TableCell>
                        <TableCell className="max-w-md truncate">
                          {c.ok ? c.detail || "-" : c.error || "未知错误"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="space-y-2">
            <div className="space-y-2 rounded-xs bg-surface-1 px-3 py-2">
              <p className="text-xs text-muted-foreground">
                智能体写回的结论（判重仍由智能体侧负责，这里只是镜像，过期自动清理）
              </p>
              {!ready ? (
                <TableSkeleton rows={3} cols={5} />
              ) : conclusions.length === 0 ? (
                <EmptyState
                  size="compact"
                  title={emptyOrFailed(errs, SRC.conclusions, "还没有结论写回")}
                  tone={errs.isFailed(SRC.conclusions) ? "danger" : "muted"}
                  action={
                    errs.isFailed(SRC.conclusions) ? (
                      <Button size="sm" variant="outline" onClick={() => void load()}>
                        重新读取
                      </Button>
                    ) : undefined
                  }
                />
              ) : (
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
                        <TableCell className="whitespace-nowrap font-mono text-xs">
                          {c.updated_at ? formatDateTime(c.updated_at) : "-"}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {c.event_id || c.fingerprint || "-"}
                        </TableCell>
                        <TableCell>{c.status || "-"}</TableCell>
                        <TableCell>
                          <Badge variant={severityVariant(c.severity)}>{c.severity || "-"}</Badge>
                        </TableCell>
                        <TableCell className="max-w-md truncate text-muted-foreground">
                          {c.summary || "-"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="space-y-2">
            <div className="space-y-2 rounded-xs bg-surface-1 px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  {errs.isFailed(SRC.tools)
                    ? "工具清单读取失败（见上方错误条）"
                    : `暴露给智能体的工具（${tools.length} 个，参数说明以服务端为准）`}
                </span>
                <Button size="sm" variant="outline" onClick={() => setShowTools((v) => !v)}>
                  {showTools ? "收起" : "展开"}
                </Button>
              </div>
              {showTools &&
                (tools.length === 0 ? (
                  <EmptyState
                    size="compact"
                    title={emptyOrFailed(errs, SRC.tools, "工具清单为空")}
                    tone={errs.isFailed(SRC.tools) ? "danger" : "muted"}
                  />
                ) : (
                  <Table>
                    <TableBody>
                      {tools.map((t) => (
                        <TableRow key={t.name}>
                          <TableCell className="w-48 align-top font-mono text-xs">
                            {t.name}
                          </TableCell>
                          <TableCell>
                            {t.desc}
                            <span className="ml-1 text-xs text-muted-foreground">
                              （
                              {Object.entries(t.params)
                                .map(([k, v]) => `${k}: ${v}`)
                                .join("；")}
                              ）
                            </span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ))}
            </div>
          </CardContent>
        </Card>

      </Section>

      <Dialog
        open={rotateAsk !== null}
        title={rotateAsk ? `轮换令牌「${rotateAsk.name || `${rotateAsk.prefix}…`}」？` : "轮换令牌？"}
        onClose={() => setRotateAsk(null)}
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button size="sm" variant="outline" onClick={() => setRotateAsk(null)}>
              取消
            </Button>
            <Button
              size="sm"
              onClick={() => {
                const t = rotateAsk;
                setRotateAsk(null);
                if (t) void rotateToken(t);
              }}
            >
              确认轮换
            </Button>
          </div>
        }
      >
        <p className="text-xs leading-relaxed text-muted-foreground">
          会立刻换一个新明文，旧明文马上失效（智能体那边必须同步改，否则会连不上）。
        </p>
      </Dialog>
    </div>
  );
}
