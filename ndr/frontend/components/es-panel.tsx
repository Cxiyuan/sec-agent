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
import { PanelError, emptyOrFailed, loadInto, usePanelErrors } from "@/components/panel-error";

/** 读取失败的接口名（错误条用）。 */
const SRC = {
  config: "ES 接入配置（/api/es/config）",
  status: "ES 状态（/api/es/status）",
} as const;

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
  const [busy, setBusy] = React.useState(false);

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
    void load();
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
      setMsg("已保存（分析链路即时生效）");
      void load();
    } catch (e) {
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
      setMsg(
        `已下发 ILM：策略 ${r.policy}，保留 ${r.retention_days} 天；模板 ${r.templates.join(", ")}`
      );
      void load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "下发失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Elasticsearch（接入 / 保留 / 状态）</CardTitle>
        <p className="text-xs text-muted-foreground">
          Elasticsearch 随本项目一起部署，<b>连接信息由部署环境固定</b>
          （`.env` 的 `ES_URL` / `ES_USER` / `ES_PASSWORD` → 后台的 `ST_ES_*`），
          这里只显示现在连的是哪台、没有填写入口；要换 ES 就改 `.env` 再
          `docker compose up -d backend` 重建容器。
          保留期通过 ILM 策略自动下发给 ES，让索引自动 rollover 与删除；
          <b>不得小于回溯封顶（{cfg?.retention_min_days ?? 7} 天）</b>，否则回溯会查不到日志。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}
        <PanelError errors={errs} />

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-md border p-3 text-xs">
          <span className="text-muted-foreground">部署环境给定的连接：</span>
          <span>
            地址 <span className="font-mono">{cfg?.url || "-"}</span>
          </span>
          <span>
            用户名 <span className="font-mono">{cfg?.username || "（免认证）"}</span>
          </span>
          <span>密码 {cfg?.password_set ? "已设置" : "未设置"}</span>
        </div>

        <div className="grid grid-cols-3 gap-3">
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
          {/* 配置没读到就禁止保存：空表单点保存会把索引模式/保留期覆盖掉 */}
          <Button onClick={save} disabled={busy || !cfg}>
            保存索引模式与保留期
          </Button>
          <Button variant="secondary" onClick={applyRetention} disabled={busy}>
            下发保留策略（ILM）
          </Button>
          <Button variant="outline" disabled={busy} onClick={() => void load()}>
            刷新状态
          </Button>
          {!cfg && (
            <span className="self-center text-xs text-destructive">
              配置未读到，已禁用保存（避免空表单覆盖现有配置）
            </span>
          )}
        </div>

        {!status && errs.isFailed(SRC.status) && (
          <p className="text-xs text-muted-foreground">
            下面的集群信息空着是因为状态没读到，不代表 ES 里没有数据。
          </p>
        )}
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
                      {emptyOrFailed(
                        errs,
                        SRC.status,
                        "暂无匹配索引（检查索引模式或数据是否已入 ES）"
                      )}
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
