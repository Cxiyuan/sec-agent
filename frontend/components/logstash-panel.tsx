"use client";

import * as React from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ApiError, apiFetch, errorText, type DetectorStats, type LogstashParams, type LogstashStatus } from "@/lib/api";

const SELECT_CLS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm";
const AREA_CLS =
  "w-full rounded-md border border-input bg-transparent px-3 py-2 text-xs font-mono leading-relaxed";

/** 采集侧（Logstash）：参数表单 + 管道全文编辑。后端写共享卷，Logstash 自动重载（约 10s）。 */
export function LogstashPanel() {
  const [data, setData] = React.useState<LogstashStatus | null>(null);
  const [det, setDet] = React.useState<DetectorStats | null>(null);
  const [params, setParams] = React.useState<LogstashParams | null>(null);
  const [text, setText] = React.useState("");
  const [preview, setPreview] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function load() {
    const d = await apiFetch<LogstashStatus>("/api/logstash");
    setData(d);
    setParams(d.params);
    setText(d.pipeline);
    setPreview("");
    // 旁路检测器状态（让「事件被丢弃」可见）
    apiFetch<DetectorStats>("/api/detector/stats")
      .then(setDet)
      .catch(() => {});
  }

  React.useEffect(() => {
    load().catch(() => {});
  }, []);

  function set<K extends keyof LogstashParams>(key: K, value: LogstashParams[K]) {
    setParams((s) => (s ? { ...s, [key]: value } : s));
  }

  async function doPreview() {
    if (!params) return;
    try {
      const r = await apiFetch<{ pipeline: string }>("/api/logstash/preview", {
        method: "POST",
        body: JSON.stringify(params),
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
        body: JSON.stringify(params),
      });
      setText(r.pipeline);
      setPreview("");
      setMsg(r.note);
      setTimeout(() => load().catch(() => {}), 12000);
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
      setTimeout(() => load().catch(() => {}), 12000);
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
              <Badge variant="outline">旁路队列 {data.queue_depth ?? "-"}</Badge>
            </div>
            <p className="text-muted-foreground">
              最近下发：{data.updated_at ? data.updated_at.replace("T", " ").slice(0, 19) : "—"}
              {" · "}
              <span className="font-mono">{data.config_path}</span>
            </p>
            <p className="mt-1 text-muted-foreground">
              采集接入：{data.beats.hint}（当前端口 {data.beats.port}）
            </p>
            {ls && !ls.alive && ls.error && (
              <p className="mt-1 text-destructive">状态读取失败：{ls.error}</p>
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
                去重闸门：{det.dedup?.enabled ? "开" : "关"}
                {" · 已省重复分析 "}
                {det.dedup?.skipped_total ?? 0}
                {" 条（在途 "}
                {det.dedup?.inflight ?? 0}
                {" / 已完结 "}
                {det.dedup?.done ?? 0}
                {"）"}
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
                <select
                  value={String(params.es_enabled)}
                  onChange={(e) => set("es_enabled", e.target.value === "true")}
                  className={SELECT_CLS}
                >
                  <option value="true">启用</option>
                  <option value="false">停用（只做实时检测，不存历史）</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Redis 旁路队列（实时检测）
                </label>
                <select
                  value={String(params.redis_enabled)}
                  onChange={(e) => set("redis_enabled", e.target.value === "true")}
                  className={SELECT_CLS}
                >
                  <option value="true">启用</option>
                  <option value="false">停用（只存历史，不做实时检测）</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">ES 地址</label>
                <Input
                  value={params.es_host}
                  onChange={(e) => set("es_host", e.target.value)}
                  className="h-9"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Redis 地址</label>
                <Input
                  value={params.redis_host}
                  onChange={(e) => set("redis_host", e.target.value)}
                  className="h-9"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Zeek 索引名（支持 %&#123;...&#125; 占位）
                </label>
                <Input
                  value={params.zeek_index}
                  onChange={(e) => set("zeek_index", e.target.value)}
                  className="h-9"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Wazuh 索引名</label>
                <Input
                  value={params.wazuh_index}
                  onChange={(e) => set("wazuh_index", e.target.value)}
                  className="h-9"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">旁路队列键</label>
                <Input
                  value={params.redis_key}
                  onChange={(e) => set("redis_key", e.target.value)}
                  className="h-9"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">Redis 端口</label>
                  <Input
                    value={String(params.redis_port)}
                    onChange={(e) => set("redis_port", Number(e.target.value) || 6379)}
                    className="h-9"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">Redis 库号</label>
                  <Input
                    value={String(params.redis_db)}
                    onChange={(e) => set("redis_db", Number(e.target.value) || 0)}
                    className="h-9"
                  />
                </div>
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
