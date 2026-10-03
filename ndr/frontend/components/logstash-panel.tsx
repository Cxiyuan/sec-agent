"use client";

import * as React from "react";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { ApiError, apiFetch, errorText, type DetectorStats, type LogstashParams, type LogstashStatus } from "@/lib/api";
import { loadInto, PanelError, usePanelErrors } from "@/components/panel-error";

const AREA_CLS =
  "w-full rounded-md border border-input bg-transparent px-3 py-2 text-xs font-mono leading-relaxed";

/** 读取失败的接口名（错误条用）。 */
const SRC = {
  main: "Logstash 状态（/api/logstash）",
  det: "检测器状态（/api/detector/stats）",
  rate: "五段速率（/api/detector/rate）",
} as const;

/** 采集侧（Logstash）：参数表单 + 管道全文编辑。后端写共享卷，Logstash 自动重载（约 10s）。 */
export function LogstashPanel() {
  const [data, setData] = React.useState<LogstashStatus | null>(null);
  const [det, setDet] = React.useState<DetectorStats | null>(null);
  const [params, setParams] = React.useState<LogstashParams | null>(null);
  const [text, setText] = React.useState("");
  const [preview, setPreview] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  // 五段速率（入队/扫描/命中/投递/分析）：哪个环节最窄一眼可见
  const [rate, setRate] = React.useState<Record<string, number | null | undefined> | null>(null);
  const errs = usePanelErrors();

  async function load() {
    errs.reset();
    await Promise.all([
      loadInto(errs, SRC.main, "/api/logstash", (d: LogstashStatus) => {
        setData(d);
        setParams(d.params);
        setText(d.pipeline);
        setPreview("");
      }),
      // 旁路检测器状态（让「事件被丢弃」可见）
      loadInto(errs, SRC.det, "/api/detector/stats", (d: DetectorStats) => setDet(d)),
      // 五段速率（后端已有 /api/detector/rate）
      loadInto(
        errs,
        SRC.rate,
        "/api/detector/rate?minutes=10",
        (d: Record<string, number | null | undefined>) => setRate(d),
      ),
    ]);
  }

  React.useEffect(() => {
    void load();
    // 只在挂载时读一次；load 内部自己收错误
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function set<K extends keyof LogstashParams>(key: K, value: LogstashParams[K]) {
    setParams((s) => (s ? { ...s, [key]: value } : s));
  }

  async function doPreview() {
    if (!params) return;
    try {
      const r = await apiFetch<{ pipeline: string }>("/api/logstash/preview", {
        method: "POST",
        body: JSON.stringify({ es_enabled: params.es_enabled, events_index: params.events_index }),
      });
      setPreview(r.pipeline);
      setMsg("已按参数生成管道预览（未保存）");
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "预览失败");
    }
  }

  async function saveParams() {
    if (!params) return;
    if (!confirm("保存参数会用生成的管道覆盖「全文编辑」的内容，继续？")) return;
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<{ pipeline: string; note: string }>("/api/logstash/params", {
        method: "PUT",
        body: JSON.stringify({ es_enabled: params.es_enabled, events_index: params.events_index }),
      });
      setText(r.pipeline);
      setPreview("");
      setMsg(r.note);
      setTimeout(() => void load(), 12000);
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  async function savePipeline() {
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<{ note: string }>("/api/logstash/pipeline", {
        method: "PUT",
        body: JSON.stringify({ text }),
      });
      setMsg(r.note);
      setTimeout(() => void load(), 12000);
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  async function rollback() {
    if (!confirm("回滚到上一版管道？")) return;
    setBusy(true);
    try {
      const r = await apiFetch<{ pipeline: string; note: string }>("/api/logstash/rollback", {
        method: "POST",
      });
      setText(r.pipeline);
      setMsg(r.note);
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "回滚失败");
    } finally {
      setBusy(false);
    }
  }

  const ls = data?.logstash;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">采集侧 · Logstash 管道</CardTitle>
        <p className="text-xs text-muted-foreground">
          保存后写入共享卷，Logstash 约 <b>10 秒</b> 内自动重载（无需重启容器）。
          每次保存自动备份上一版，可一键回滚。
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {msg && <p className="text-sm text-primary">{msg}</p>}
        <PanelError errors={errs} />

        {/* 状态区 */}
        {data && (
          <div className="rounded-md border p-3 text-xs">
            <div className="mb-1 flex flex-wrap items-center gap-2">
              <Badge variant={ls?.alive ? "info" : "critical"}>
                {ls?.alive ? "运行中" : "不可达"}
              </Badge>
              <Badge variant="secondary">入 {ls?.events_in ?? "-"}</Badge>
              <Badge variant="secondary">出 {ls?.events_out ?? "-"}</Badge>
              <Badge variant={ls?.reloads_failures ? "critical" : "outline"}>
                重载成功 {ls?.reloads_successes ?? "-"} / 失败 {ls?.reloads_failures ?? "-"}
              </Badge>
              <Badge variant="outline">待归一化积压 {data.queue_depth ?? "-"}</Badge>
            </div>
            <p className="text-muted-foreground">
              最近下发：{data.updated_at ? data.updated_at.replace("T", " ").slice(0, 19) : "—"}
              {" · "}
              <span className="font-mono">{data.config_path}</span>
            </p>
            <p className="mt-1 text-muted-foreground">
              采集接入：{data.http.hint}（当前端口 {data.http.port}）
            </p>
            {ls && !ls.alive && ls.error && (
              <p className="mt-1 text-destructive">状态读取失败：{ls.error}</p>
            )}
            {rate && (
              <p className="mt-1 text-muted-foreground">
                五段速率（10 分钟）：扫描 {rate.scanned_per_sec ?? "-"}/秒 · 命中{" "}
                {rate.hits_per_min ?? "-"}/分 · 摘要 {rate.digests_per_min ?? "-"}/分 · 投递{" "}
                {rate.delivered_per_min ?? "-"}/分 · 分析 {rate.analyzed_per_min ?? "-"}/分 · 模型容量{" "}
                {rate.agent_capacity_per_min ?? "-"}/分
                {(rate.limit_saturated ?? 0) > 0 && (
                  <span className="text-amber-500">
                    {" · "}额度饱和 {rate.limit_saturated} 次
                  </span>
                )}
                {(rate.raw_trimmed_total ?? 0) > 0 && (
                  <span className="text-amber-500">
                    {" · "}已裁剪 {rate.raw_trimmed_total} 条（扫描跟不上入队）
                  </span>
                )}
              </p>
            )}
            {det && (
              <p className="mt-1 text-muted-foreground">
                旁路检测器：本分钟投递 {det.delivered_this_minute ?? "-"}/{det.rate_limit_per_minute}
                {" · 待检测 "}
                {det.queue_raw ?? "-"}
                {" · 待分析 "}
                {det.queue_digest ?? "-"}
                {Object.keys(det.dropped).length > 0 && (
                  <>
                    {" · "}
                    <span className="text-amber-500">
                      已丢弃（未进分析）：
                      {Object.entries(det.dropped)
                        .map(([k, v]) => `${k} ${v}`)
                        .join(" / ")}
                    </span>
                  </>
                )}
              </p>
            )}
            {det && (det.dedup || det.task_failed || det.leader || det.policy) && (
              <p className="mt-1 text-muted-foreground">
                判重：{det.dedup?.enabled ? "NDR 侧闸门开" : (det.dedup?.note ?? "已下放到智能体")}
                {(det.dedup?.skipped_total ?? 0) > 0 && (
                  <>
                    {" · 退役前已省重复分析 "}
                    {det.dedup?.skipped_total ?? 0}
                    {" 条"}
                  </>
                )}
                {(det.task_failed?.failed_total ?? 0) > 0 && (
                  <>
                    {" · "}
                    <span className="text-amber-500">
                      分析失败 {det.task_failed?.failed_total} 条（在途超时后会重投）
                    </span>
                  </>
                )}
                {(det.policy?.internal_routine ?? 0) > 0 && (
                  <>
                    {" · "}
                    <span className="text-muted-foreground">
                      策略跳过 {det.policy?.internal_routine} 条（内网常规流量：已落库、不跑模型）
                    </span>
                  </>
                )}
                {det.redis_warn && (
                  <>
                    {" · "}
                    <span className="text-destructive">
                      ⚠ Redis 内存已达 {det.redis?.perc ?? 0}%（吃满后会拒绝写命令，整条分析链会卡死）
                    </span>
                  </>
                )}
                {(det.handled_skipped ?? 0) > 0 && (
                  <>
                    {" · "}
                    <span className="text-amber-500">
                      登记丢弃 {det.handled_skipped} 条（会重复分析）
                    </span>
                  </>
                )}
                {det.leader?.holder ? ` · 主实例 ${det.leader.holder}` : ""}
              </p>
            )}
            {!data.params_applied && (
              <p className="mt-1 text-muted-foreground">
                当前管道为<b>自定义内容</b>（非参数生成）；用下方表单保存会覆盖它。
              </p>
            )}
          </div>
        )}

        {/* 参数表单 */}
        {params && (
          <div className="space-y-3">
            <p className="text-xs font-medium text-muted-foreground">常用参数</p>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Elasticsearch 输出（历史归档）
                </label>
                <p className="text-xs text-muted-foreground">
                  归一化后的文档只有 ES 一个去处，不可停用；原始日志走 Redis 采集队列。
                </p>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  ES 地址（由部署环境固定）
                </label>
                <p className="flex h-9 items-center rounded-md border px-3 font-mono text-xs">
                  {params.es_host}
                </p>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  索引名（Zeek 与 Wazuh 统一落这一族，支持 %&#123;...&#125; 占位）
                </label>
                <Input
                  value={params.events_index}
                  onChange={(e) => set("events_index", e.target.value)}
                  className="h-9"
                />
              </div>
            </div>

            <div className="flex gap-2">
              <Button onClick={saveParams} disabled={busy}>
                保存参数并下发
              </Button>
              <Button variant="outline" onClick={doPreview} disabled={busy}>
                预览生成的管道
              </Button>
              <Button variant="outline" onClick={() => load()} disabled={busy}>
                刷新状态
              </Button>
              <Button variant="ghost" onClick={rollback} disabled={busy}>
                回滚上一版
              </Button>
            </div>
          </div>
        )}

        {/* 全文编辑 */}
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            高级：管道全文（保存前会做静态校验：非空 / 含 input 与 output / 括号配平 / 至少一个输出）
          </label>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={14}
            className={AREA_CLS}
            spellCheck={false}
          />
          <div className="mt-2 flex gap-2">
            <Button onClick={savePipeline} disabled={busy}>
              保存管道全文
            </Button>
            <Button variant="outline" onClick={() => setText(data?.default_pipeline || "")}>
              填入默认模板
            </Button>
          </div>
        </div>

        {preview && (
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">
              参数生成的管道预览（未保存）
            </p>
            <pre className="max-h-64 overflow-auto rounded-md border p-2 text-[11px]">{preview}</pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
