"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type EsConfigInfo,
  type EsStatus,
} from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  EmptyState,
  Input,
  Section,
  Skeleton,
  Stat,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  cn,
} from "@shentong/ui";
import { PanelError, emptyOrFailed, loadInto, usePanelErrors } from "@/components/panel-error";

/** 读取失败的接口名（错误条用）。 */
const SRC = {
  config: "ES 接入配置（/api/es/config）",
  status: "ES 状态（/api/es/status）",
} as const;

/** ES 集群健康 → Badge 变体（写成嵌套三元太难读，lint 也直接报 no-nested-ternary）。 */
function healthVariant(health: string | undefined): "low" | "medium" | "high" {
  if (health === "green") return "low";
  if (health === "yellow") return "medium";
  return "high";
}

/**
 * ES 管理：接入状态 / 索引族与保留期（ILM）/ 集群状态。
 *
 * **没有连接配置表单**：Elasticsearch 随 NDR 一起部署，地址与凭据由部署环境固定
 * （`.env` 的 `ES_*` → 后台的 `ST_ES_*`），用户不需要配、也无处可配。这里只把「现在连的是
 * 哪台」显示出来，能改的只有「日志落哪族索引、留多久」这类策略项。
 */
export function EsPanel() {
  const errs = usePanelErrors();
  const [cfg, setCfg] = React.useState<EsConfigInfo | null>(null);
  const [status, setStatus] = React.useState<EsStatus | null>(null);
  const [eventsIndex, setEventsIndex] = React.useState("");
  const [retention, setRetention] = React.useState("30");
  const [msg, setMsg] = React.useState("");
  /** 保存结果提示的语义：成功绿条 / 失败红条 */
  const [msgKind, setMsgKind] = React.useState<"ok" | "err">("ok");
  const [busy, setBusy] = React.useState(false);
  /** 首次读取：先画骨架，避免把「正在读」显示成「没有配置」 */
  const [loading, setLoading] = React.useState(true);

  async function load() {
    errs.reset();
    await Promise.all([
      loadInto(errs, SRC.config, "/api/es/config", (d: EsConfigInfo) => {
        setCfg(d);
        setEventsIndex(d.events_index || "");
        setRetention(String(d.retention_days));
      }),
      loadInto(errs, SRC.status, "/api/es/status", setStatus),
    ]);
  }

  React.useEffect(() => {
    void (async () => {
      await load();
      setLoading(false);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function save() {
    setBusy(true);
    setMsg("");
    try {
      await apiFetch<EsConfigInfo>("/api/es/config", {
        method: "PUT",
        body: JSON.stringify({
          events_index: eventsIndex,
          retention_days: Number(retention) || undefined,
        }),
      });
      setMsgKind("ok");
      setMsg("已保存（分析链路即时生效）");
      void load();
    } catch (e) {
      setMsgKind("err");
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
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
      setMsgKind("ok");
      setMsg(
        `已下发 ILM：策略 ${r.policy}，保留 ${r.retention_days} 天；模板 ${r.templates.join(", ")}`
      );
      void load();
    } catch (e) {
      setMsgKind("err");
      setMsg(e instanceof ApiError ? errorText(e.body) : "下发失败");
    } finally {
      setBusy(false);
    }
  }

  /** 首次读、读失败、读到：三种状态分开画，别把「正在读」和「没有配置」画成同一个空态。 */
  function connectionBody() {
    if (loading) {
      return (
        <div className="grid gap-3 sm:grid-cols-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      );
    }
    if (!cfg) {
      return (
        <EmptyState
          size="compact"
          tone={errs.isFailed(SRC.config) ? "danger" : "muted"}
          title={emptyOrFailed(errs, SRC.config, "还没有读到接入配置")}
          action={
            <Button size="sm" variant="outline" onClick={() => void load()}>
              重新读取
            </Button>
          }
        />
      );
    }
    return (
      <div className="grid gap-3 sm:grid-cols-3">
        <div>
          <p className="text-xs text-muted-foreground">地址</p>
          <p className="mt-1 truncate font-mono text-xs text-foreground" title={cfg.url || "-"}>
            {cfg.url || "-"}
          </p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">用户名</p>
          <p className="mt-1 font-mono text-xs text-foreground">{cfg.username || "（免认证）"}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">密码</p>
          <p className="mt-1 text-xs text-foreground">{cfg.password_set ? "已设置" : "未设置"}</p>
        </div>
      </div>
    );
  }

  /** 集群状态体：骨架 / 空态（区分读取失败）/ 指标格 + 索引表。 */
  function clusterBody() {
    if (loading) {
      return (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
          <Skeleton className="h-32 w-full" />
        </>
      );
    }
    if (!status) {
      return (
        <EmptyState
          size="compact"
          tone={errs.isFailed(SRC.status) ? "danger" : "muted"}
          title={emptyOrFailed(errs, SRC.status, "还没有读到集群状态")}
          hint="下面的集群信息空着是因为状态没读到，不代表 ES 里没有数据。"
          action={
            <Button size="sm" variant="outline" onClick={() => void load()}>
              重新读取
            </Button>
          }
        />
      );
    }
    return (
      <>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <Stat
            size="sm"
            label="集群"
            value={<span className="font-mono text-sm">{status.health.cluster_name ?? "-"}</span>}
          />
          <Stat size="sm" label="节点" value={status.health.nodes ?? "-"} />
          <Stat
            size="sm"
            label="索引保留"
            value={`${status.ilm.retention_days} 天`}
            hint={`策略 ${status.ilm.policy}`}
          />
        </div>
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
                <TableCell className="font-mono text-xs">{i.index}</TableCell>
                <TableCell className="tabular-nums">{i.docs ?? "-"}</TableCell>
                <TableCell className="tabular-nums">{i.store ?? "-"}</TableCell>
                <TableCell className="tabular-nums">{i.created ?? "-"}</TableCell>
              </TableRow>
            ))}
            {status.indices.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} className="p-0">
                  <EmptyState
                    size="compact"
                    tone={errs.isFailed(SRC.status) ? "danger" : "muted"}
                    title={emptyOrFailed(
                      errs,
                      SRC.status,
                      "暂无匹配索引（检查索引模式或数据是否已入 ES）"
                    )}
                  />
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </>
    );
  }

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />
      <Section
        title="Elasticsearch（接入 / 保留 / 状态）"
        description={
          <>
            Elasticsearch 随本项目一起部署，<b>连接信息由部署环境固定</b>
            （`.env` 的 `ES_URL` / `ES_USER` / `ES_PASSWORD` → 后台的 `ST_ES_*`），
            这里只显示现在连的是哪台、没有填写入口；要换 ES 就改 `.env` 再
            `docker compose up -d backend` 重建容器。
            保留期通过 ILM 策略自动下发给 ES，让索引自动 rollover 与删除；
            <b>不得小于回溯封顶（{cfg?.retention_min_days ?? 7} 天）</b>，否则回溯会查不到日志。
          </>
        }
      >
        <Card>
          <CardHeader>
            <CardTitle>连接（部署环境固定）</CardTitle>
          </CardHeader>
          <CardContent>
            {connectionBody()}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>索引与保留</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="es-events-index" className="mb-1 block text-xs text-muted-foreground">
                  索引模式（两类采集统一落这一族）
                </label>
                <Input
                  id="es-events-index"
                  value={eventsIndex}
                  disabled={!cfg}
                  onChange={(e) => setEventsIndex(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="es-retention" className="mb-1 block text-xs text-muted-foreground">
                  保留天数（≥{cfg?.retention_min_days ?? 7}）
                </label>
                <Input
                  id="es-retention"
                  type="number"
                  className="tabular-nums"
                  value={retention}
                  disabled={!cfg}
                  onChange={(e) => setRetention(e.target.value)}
                  min={cfg?.retention_min_days ?? 7}
                />
              </div>
            </div>

            {msg && (
              <p
                role={msgKind === "err" ? "alert" : "status"}
                className={cn(
                  "rounded-xs border px-3 py-2 text-xs",
                  msgKind === "err"
                    ? "border-sev-critical-bd bg-sev-critical-bg text-sev-critical-fg"
                    : "border-sev-ok-bd bg-sev-ok-bg text-sev-ok-fg"
                )}
              >
                {msg}
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              {/* 配置没读到就禁止保存：空表单点保存会把索引模式/保留期覆盖掉 */}
              <Button size="sm" onClick={save} disabled={busy || !cfg}>
                保存索引模式与保留期
              </Button>
              <Button size="sm" variant="outline" onClick={applyRetention} disabled={busy}>
                下发保留策略（ILM）
              </Button>
              <Button size="sm" variant="outline" disabled={busy} onClick={() => void load()}>
                刷新状态
              </Button>
              {!cfg && !loading && (
                <span className="self-center text-xs text-sev-critical-fg">
                  配置未读到，已禁用保存（避免空表单覆盖现有配置）
                </span>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
            <CardTitle>集群状态</CardTitle>
            {status ? (
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={healthVariant(status.health.status)}>
                  {status.health.status ?? "unknown"}
                </Badge>
                <Badge variant={status.ilm.exists ? "info" : "medium"}>
                  ILM {status.ilm.exists ? "已下发" : "未下发"}
                </Badge>
              </div>
            ) : null}
          </CardHeader>
          <CardContent className="space-y-3">
            {clusterBody()}
          </CardContent>
        </Card>
      </Section>
    </div>
  );
}
