"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Dialog,
  EmptyState,
  Input,
  Section,
  SettingsGrid,
  SettingsMain,
  SettingsRail,
  Skeleton,
  Stat,
  cn,
  formatDateTime,
} from "@shentong/ui";
import {
  ApiError,
  apiFetch,
  errorText,
  type DetectorStats,
  type LogstashParams,
  type LogstashStatus,
} from "@/lib/api";
import { loadInto, PanelError, usePanelErrors } from "@/components/panel-error";

const AREA_CLS =
  "w-full rounded-sm border border-input bg-surface-2 px-3 py-2 font-mono text-xs leading-relaxed transition-colors focus-visible:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40";

/** 读取失败的接口名（错误条用）。 */
const SRC = {
  main: "Logstash 状态（/api/logstash）",
  det: "检测器状态（/api/detector/stats）",
  rate: "五段速率（/api/detector/rate）",
} as const;

/** 需要二次确认的动作（覆盖管道 / 回滚）：用 Dialog 而不是 window.confirm。 */
interface ConfirmState {
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
}

/** 采集侧（Logstash）：参数表单 + 管道全文编辑。后端写共享卷，Logstash 自动重载（约 10s）。 */
export function LogstashPanel() {
  const [data, setData] = React.useState<LogstashStatus | null>(null);
  const [det, setDet] = React.useState<DetectorStats | null>(null);
  const [params, setParams] = React.useState<LogstashParams | null>(null);
  const [text, setText] = React.useState("");
  const [preview, setPreview] = React.useState("");
  const [msg, setMsg] = React.useState("");
  /** 保存结果提示的语义：成功绿条 / 失败红条 */
  const [msgKind, setMsgKind] = React.useState<"ok" | "err">("ok");
  /** 提示属于哪张卡（两张卡各有一个表单，提示不能同时出现在两处） */
  const [msgScope, setMsgScope] = React.useState<"params" | "pipeline">("params");
  const [busy, setBusy] = React.useState(false);
  /** 首次读取：先画骨架，别把「正在读」显示成「没有管道」 */
  const [loading, setLoading] = React.useState(true);
  const [confirm, setConfirm] = React.useState<ConfirmState | null>(null);
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
    void (async () => {
      await load();
      setLoading(false);
    })();
    // 只在挂载时读一次；load 内部自己收错误
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** 统一写一条结果提示：语义色 + 归属卡片 */
  function showMsg(text: string, kind: "ok" | "err", scope: "params" | "pipeline") {
    setMsgKind(kind);
    setMsg(text);
    setMsgScope(scope);
  }

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
      showMsg("已按参数生成管道预览（未保存）", "ok", "params");
    } catch (e) {
      showMsg(e instanceof ApiError ? errorText(e.body) : "预览失败", "err", "params");
    }
  }

  async function saveParams() {
    if (!params) return;
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<{ pipeline: string; note: string }>("/api/logstash/params", {
        method: "PUT",
        body: JSON.stringify({ es_enabled: params.es_enabled, events_index: params.events_index }),
      });
      setText(r.pipeline);
      setPreview("");
      showMsg(r.note, "ok", "params");
      setTimeout(() => void load(), 12000);
    } catch (e) {
      showMsg(e instanceof ApiError ? errorText(e.body) : "保存失败", "err", "params");
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
      showMsg(r.note, "ok", "pipeline");
      setTimeout(() => void load(), 12000);
    } catch (e) {
      showMsg(e instanceof ApiError ? errorText(e.body) : "保存失败", "err", "pipeline");
    } finally {
      setBusy(false);
    }
  }

  async function rollback() {
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<{ pipeline: string; note: string }>("/api/logstash/rollback", {
        method: "POST",
      });
      setText(r.pipeline);
      showMsg(r.note, "ok", "pipeline");
    } catch (e) {
      showMsg(e instanceof ApiError ? errorText(e.body) : "回滚失败", "err", "pipeline");
    } finally {
      setBusy(false);
    }
  }

  const ls = data?.logstash;

  /** 结果提示条：只在产生它的那张卡里出现 */
  function noticeFor(scope: "params" | "pipeline") {
    if (!msg || msgScope !== scope) return null;
    return (
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
    );
  }

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />
      <Section
        title="采集侧 · Logstash 管道"
        description={
          <>
            保存后写入共享卷，Logstash 约 <b>10 秒</b> 内自动重载（无需重启容器）。
            每次保存自动备份上一版，可一键回滚。
          </>
        }
      >
        {/* 能改的只有「常用参数」表单，放主列；运行状态是只读指标，放右侧侧栏。
            侧栏只有 19rem，指标格压成 2 列，4 列会把标签挤成竖排。
            管道全文是代码块，需要整幅宽度，放成 Grid 的兄弟节点。 */}
        <SettingsGrid>
          <SettingsMain>
            <Card>
              <CardHeader>
                <CardTitle>常用参数</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {loading ? (
                  <Skeleton className="h-24 w-full" />
                ) : params ? (
                  <>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div>
                        <p className="mb-1 text-xs text-muted-foreground">Elasticsearch 输出（历史归档）</p>
                        <p className="text-xs text-muted-foreground">
                          归一化后的文档只有 ES 一个去处，不可停用；原始日志走 Redis 采集队列。
                        </p>
                      </div>
                      <div>
                        <p className="mb-1 text-xs text-muted-foreground">ES 地址（由部署环境固定）</p>
                        <p className="flex h-9 items-center truncate rounded-sm border border-border-subtle bg-surface-1 px-3 font-mono text-xs">
                          {params.es_host}
                        </p>
                      </div>
                      <div>
                        <label
                          htmlFor="ls-events-index"
                          className="mb-1 block text-xs text-muted-foreground"
                        >
                          索引名（两类采集统一落这一族，支持 %&#123;...&#125; 占位）
                        </label>
                        <Input
                          id="ls-events-index"
                          value={params.events_index}
                          onChange={(e) => set("events_index", e.target.value)}
                        />
                      </div>
                    </div>

                    {noticeFor("params")}

                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        size="sm"
                        disabled={busy}
                        onClick={() =>
                          setConfirm({
                            title: "保存参数并下发？",
                            body: "保存参数会用生成的管道覆盖「全文编辑」的内容。",
                            confirmLabel: "覆盖并下发",
                            onConfirm: () => {
                              setConfirm(null);
                              void saveParams();
                            },
                          })
                        }
                      >
                        保存参数并下发
                      </Button>
                      <Button size="sm" variant="outline" onClick={doPreview} disabled={busy}>
                        预览生成的管道
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => void load()} disabled={busy}>
                        刷新状态
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        onClick={() =>
                          setConfirm({
                            title: "回滚到上一版管道？",
                            body: "当前编辑框里的内容会被上一版覆盖（未保存的改动会丢失）。",
                            confirmLabel: "回滚",
                            onConfirm: () => {
                              setConfirm(null);
                              void rollback();
                            },
                          })
                        }
                      >
                        回滚上一版
                      </Button>
                    </div>
                  </>
                ) : (
                  <EmptyState
                    size="compact"
                    tone={errs.isFailed(SRC.main) ? "danger" : "muted"}
                    title={errs.isFailed(SRC.main) ? "读取失败（见上方错误条）" : "还没有读到参数"}
                    hint="参数来自 /api/logstash；读不到时不显示表单，避免空值覆盖现有配置。"
                  />
                )}
              </CardContent>
            </Card>
          </SettingsMain>

          <SettingsRail>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
                <CardTitle>运行状态</CardTitle>
                <div className="flex flex-wrap items-center gap-2">
                  {data ? (
                    <>
                      <Badge variant={ls?.alive ? "success" : "critical"}>
                        {ls?.alive ? "运行中" : "不可达"}
                      </Badge>
                    </>
                  ) : null}
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                {loading ? (
                  <div className="grid grid-cols-2 gap-3">
                    <Skeleton className="h-14 w-full" />
                    <Skeleton className="h-14 w-full" />
                    <Skeleton className="h-14 w-full" />
                    <Skeleton className="h-14 w-full" />
                  </div>
                ) : data ? (
                  <div className="grid grid-cols-2 gap-3">
                    <Stat size="sm" label="入队" value={ls?.events_in ?? "-"} />
                    <Stat size="sm" label="出队" value={ls?.events_out ?? "-"} />
                    <Stat
                      size="sm"
                      label="待归一化积压"
                      value={data.queue_depth ?? "-"}
                      tone={(data.queue_depth ?? 0) > 0 ? "medium" : "default"}
                    />
                    <Stat
                      size="sm"
                      label="重载"
                      value={`${ls?.reloads_successes ?? "-"} / ${ls?.reloads_failures ?? "-"}`}
                      hint="成功 / 失败"
                      tone={ls?.reloads_failures ? "critical" : "default"}
                    />
                  </div>
                ) : (
                  <EmptyState
                    size="compact"
                    tone={errs.isFailed(SRC.main) ? "danger" : "muted"}
                    title={errs.isFailed(SRC.main) ? "读取失败（见上方错误条）" : "还没有读到管道状态"}
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

        {/* 运行明细：数字之外的长句（五段速率、判重口径、Redis 告警）单独通栏放。
            塞进 19rem 侧栏会变成一条又高又窄的文字墙 —— 告警句和正常口径一样长，
            挤在窄栏里就分不出哪条要处理。 */}
        <Card>
          <CardHeader>
            <CardTitle>运行明细</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <Skeleton className="h-16 w-full" />
            ) : data ? (
            <div className="space-y-1 rounded-xs bg-surface-1 px-3 py-2 text-xs tabular-nums">
              <p className="text-muted-foreground">
                最近下发：{data.updated_at ? formatDateTime(data.updated_at) : "—"}
                {" · "}
                <span className="font-mono">{data.config_path}</span>
              </p>
              <p className="text-muted-foreground">
                采集接入：{data.http.hint}（当前端口{" "}
                <span className="tabular-nums">{data.http.port}</span>）
              </p>
              {ls && !ls.alive && ls.error && (
                <p className="text-sev-critical-fg">状态读取失败：{ls.error}</p>
              )}
              {rate && (
                <p className="text-muted-foreground">
                  五段速率（10 分钟）：扫描{" "}
                  <span className="tabular-nums">{rate.scanned_per_sec ?? "-"}</span>/秒 · 命中{" "}
                  <span className="tabular-nums">{rate.hits_per_min ?? "-"}</span>/分 · 摘要{" "}
                  <span className="tabular-nums">{rate.digests_per_min ?? "-"}</span>/分 · 投递{" "}
                  <span className="tabular-nums">{rate.delivered_per_min ?? "-"}</span>/分 · 分析{" "}
                  <span className="tabular-nums">{rate.analyzed_per_min ?? "-"}</span>/分 · 模型容量{" "}
                  <span className="tabular-nums">{rate.agent_capacity_per_min ?? "-"}</span>/分
                  {(rate.limit_saturated ?? 0) > 0 && (
                    <span className="text-sev-medium-fg">
                      {" · "}额度饱和{" "}
                      <span className="tabular-nums">{rate.limit_saturated}</span> 次
                    </span>
                  )}
                  {(rate.raw_trimmed_total ?? 0) > 0 && (
                    <span className="text-sev-medium-fg">
                      {" · "}已裁剪{" "}
                      <span className="tabular-nums">{rate.raw_trimmed_total}</span> 条（扫描跟不上入队）
                    </span>
                  )}
                </p>
              )}
              {det && (
                <p className="text-muted-foreground">
                  旁路检测器：本分钟投递{" "}
                  <span className="tabular-nums">{det.delivered_this_minute ?? "-"}</span>/
                  <span className="tabular-nums">{det.rate_limit_per_minute}</span>
                  {" · 待检测 "}
                  <span className="tabular-nums">{det.queue_raw ?? "-"}</span>
                  {" · 待分析 "}
                  <span className="tabular-nums">{det.queue_digest ?? "-"}</span>
                  {Object.keys(det.dropped).length > 0 && (
                    <>
                      {" · "}
                      <span className="text-sev-medium-fg">
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
                <p className="text-muted-foreground">
                  判重：{det.dedup?.enabled ? "NDR 侧闸门开" : (det.dedup?.note ?? "已下放到智能体")}
                  {(det.dedup?.skipped_total ?? 0) > 0 && (
                    <>
                      {" · 退役前已省重复分析 "}
                      <span className="tabular-nums">{det.dedup?.skipped_total ?? 0}</span>
                      {" 条"}
                    </>
                  )}
                  {(det.task_failed?.failed_total ?? 0) > 0 && (
                    <>
                      {" · "}
                      <span className="text-sev-medium-fg">
                        分析失败{" "}
                        <span className="tabular-nums">{det.task_failed?.failed_total}</span> 条（在途超时后会重投）
                      </span>
                    </>
                  )}
                  {(det.policy?.internal_routine ?? 0) > 0 && (
                    <>
                      {" · "}
                      <span className="text-muted-foreground">
                        策略跳过{" "}
                        <span className="tabular-nums">{det.policy?.internal_routine}</span> 条（内网常规流量：已落库、不跑模型）
                      </span>
                    </>
                  )}
                  {det.redis_warn && (
                    <>
                      {" · "}
                      <span className="text-sev-critical-fg">
                        ⚠ Redis 内存已达 {det.redis?.perc ?? 0}%（吃满后会拒绝写命令，整条分析链会卡死）
                      </span>
                    </>
                  )}
                  {(det.handled_skipped ?? 0) > 0 && (
                    <>
                      {" · "}
                      <span className="text-sev-medium-fg">
                        登记丢弃{" "}
                        <span className="tabular-nums">{det.handled_skipped}</span> 条（会重复分析）
                      </span>
                    </>
                  )}
                  {det.leader?.holder ? ` · 主实例 ${det.leader.holder}` : ""}
                </p>
              )}
              {!data.params_applied && (
                <p className="text-muted-foreground">
                  {data.params_stored ? (
                    <>
                      当前管道为<b>自定义内容</b>（非参数生成）；用表单保存会覆盖它。
                    </>
                  ) : (
                    <>
                      当前管道与<b>默认模板不一致</b>（可能手工改过，或部署升级后模板已变）；
                      保存参数会按模板重写。
                    </>
                  )}
                </p>
              )}
            </div>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>管道全文（高级）</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <label
                htmlFor="ls-pipeline-text"
                className="mb-1 block text-xs text-muted-foreground"
              >
                保存前会做静态校验：非空 / 含 input 与 output / 括号配平 / 至少一个输出
              </label>
              {loading ? (
                <Skeleton className="h-56 w-full" />
              ) : (
                <textarea
                  id="ls-pipeline-text"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  rows={14}
                  className={AREA_CLS}
                  spellCheck={false}
                />
              )}
            </div>
            {noticeFor("pipeline")}
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={savePipeline} disabled={busy || loading}>
                保存管道全文
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setText(data?.default_pipeline || "")}
              >
                填入默认模板
              </Button>
            </div>

            {preview && (
              <div>
                <p className="mb-1 text-xs font-medium text-muted-foreground">
                  参数生成的管道预览（未保存）
                </p>
                <pre className="max-h-64 overflow-auto rounded-sm border border-border-subtle bg-surface-1 p-2 text-xs">
                  {preview}
                </pre>
              </div>
            )}
          </CardContent>
        </Card>

        <Dialog
          open={confirm !== null}
          title={confirm?.title ?? ""}
          onClose={() => setConfirm(null)}
          footer={
            <div className="flex items-center justify-end gap-2">
              <Button size="sm" variant="outline" onClick={() => setConfirm(null)}>
                取消
              </Button>
              <Button size="sm" variant="destructive" onClick={() => confirm?.onConfirm()}>
                {confirm?.confirmLabel ?? "确认"}
              </Button>
            </div>
          }
        >
          <p className="text-xs leading-relaxed text-muted-foreground">{confirm?.body}</p>
        </Dialog>
      </Section>
    </div>
  );
}
