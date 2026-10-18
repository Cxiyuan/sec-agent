"use client";

import * as React from "react";
import { ApiError, apiFetch, errorText, type ZeekStatus } from "@/lib/api";
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
  cn,
  formatDateTime,
} from "@shentong/ui";
import { loadInto, PanelError, usePanelErrors } from "@/components/panel-error";

/** 与 `Input` 同一套边框/底色/聚焦态，下拉框与文本域不能各自一套材质。 */
const SELECT_CLS =
  "h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-sm transition-colors focus-visible:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-50";
const TEXTAREA_CLS =
  "min-h-28 w-full rounded-sm border border-input bg-surface-2 p-2 font-mono text-xs leading-relaxed transition-colors focus-visible:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40";

/** 读取失败的接口名（错误条用）。 */
const SRC = { status: "采集器状态" } as const;

/** 与后端 parse_nets 同规则：换行/逗号分隔，忽略空行与 # 注释，去重保序。 */
function parseNets(text: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of text.replace(/,/g, "\n").split("\n")) {
    const v = raw.trim();
    if (!v || v.startsWith("#") || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

/**
 * Zeek 采集配置：监听网卡 + 监控网段。
 * BPF 过滤器与 Site::local_nets 都由网段清单生成，不再手填 —— 保证「抓什么就分析什么」。
 *
 * 第 7 期拆页后两种情况共用本组件：
 * - `section="networks"`（监控网段页）：只显示网段与附加 BPF 条件；
 * - `section="iface"`（采集接入页）：只显示监听网卡。
 * 两者都读取同一份状态、保存时把没显示的那部分原样回传，因此不会互相覆盖。
 */
export function ZeekPanel({ section = "all" }: { section?: "all" | "iface" | "networks" }) {
  const [status, setStatus] = React.useState<ZeekStatus | null>(null);
  const [iface, setIface] = React.useState("");
  const [netsText, setNetsText] = React.useState("");
  const [bpfExtra, setBpfExtra] = React.useState("");
  const [bodyKb, setBodyKb] = React.useState("");
  const [respKb, setRespKb] = React.useState("");
  const [tlsPorts, setTlsPorts] = React.useState("");
  const [msg, setMsg] = React.useState("");
  /** 保存结果提示的语义：成功绿条 / 失败红条 */
  const [msgKind, setMsgKind] = React.useState<"ok" | "err">("ok");
  const [busy, setBusy] = React.useState(false);
  /** 首次读取：先画骨架，别把「正在读」显示成「状态未读到」 */
  const [loading, setLoading] = React.useState(true);
  const errs = usePanelErrors();

  const nets = parseNets(netsText);
  const showIface = section === "all" || section === "iface";
  const showNets = section === "all" || section === "networks";

  async function load() {
    errs.reset();
    await loadInto(errs, SRC.status, "/api/zeek/status", (d: ZeekStatus) => {
      setStatus(d);
      setIface(d.interface);
      setNetsText(d.networks.join("\n"));
      setBpfExtra(d.bpf_extra || "");
      setBodyKb(String(Math.round((d.body_max_bytes || 0) / 1024)));
      setRespKb(String(Math.round((d.resp_body_max_bytes || 0) / 1024)));
      setTlsPorts(d.tls_ports || "");
    });
  }

  React.useEffect(() => {
    void (async () => {
      await load();
      setLoading(false);
    })();
    // 只在挂载时读一次；load 内部自己收错误
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function save() {
    setBusy(true);
    setMsg("");
    try {
      const payload: Record<string, unknown> = {
        interface: iface,
        networks: netsText,
        bpf_extra: bpfExtra,
      };
      // 上限按 KB 传；留空或非法就不传（后端沿用当前值，不会被清掉）
      const bodyKbNum = Number(bodyKb);
      const respKbNum = Number(respKb);
      if (Number.isFinite(bodyKbNum) && bodyKbNum > 0) payload.body_max_kb = bodyKbNum;
      if (Number.isFinite(respKbNum) && respKbNum > 0) payload.resp_body_max_kb = respKbNum;
      // 按 TLS 解析的端口：整段照发（空串 = 不排除任何端口，回到采集器默认端口表）
      payload.tls_ports = tlsPorts;
      const r = await apiFetch<{ interface: string; note: string }>("/api/zeek/interface", {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      setMsgKind("ok");
      setMsg(`已保存：网卡 ${r.interface}。${r.note}`);
      setTimeout(() => void load(), 12000);
    } catch (e) {
      setMsgKind("err");
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />
      <Section
        title={section === "networks" ? "监控网段（抓包范围）" : "网络采集器（监听网卡）"}
        description={
          <>
            {showNets && (
              <>
                采集器只抓「监控网段」内的流量，其余不抓；抓到的数据才会进 Logstash 与
                Elasticsearch。
              </>
            )}
            {section === "all" && " "}
            {showIface && (
              <>
                改完点保存，采集器容器内的看门狗会在约 10 秒内自动重载（无需重启容器）。
                镜像内硬编码：日志每 <b>24 小时</b> 轮转、本地只保留 <b>3 天</b>。
              </>
            )}
          </>
        }
      >
        {showIface && (
          <Card>
            <CardHeader>
              <CardTitle>抓包口</CardTitle>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="grid gap-3 sm:grid-cols-2">
                  <Skeleton className="h-14 w-full" />
                  {section === "all" && <Skeleton className="h-14 w-full" />}
                </div>
              ) : (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label htmlFor="zeek-iface" className="mb-1 block text-xs text-muted-foreground">
                      监听网卡（{status ? `探测到 ${status.detected.length} 张` : "状态未读到"}）
                    </label>
                    {status && status.detected.length > 0 ? (
                      <select
                        id="zeek-iface"
                        value={iface}
                        onChange={(e) => setIface(e.target.value)}
                        className={SELECT_CLS}
                      >
                        {status.detected.map((i) => (
                          <option key={i.name} value={i.name}>
                            {i.name}（{i.state}
                            {i.mtu ? `, MTU ${i.mtu}` : ""}）
                          </option>
                        ))}
                        {!status.detected.some((i) => i.name === iface) && (
                          <option value={iface}>{iface}</option>
                        )}
                      </select>
                    ) : (
                      <Input
                        id="zeek-iface"
                        value={iface}
                        onChange={(e) => setIface(e.target.value)}
                        placeholder="eth0（未探测到清单，可手填）"
                      />
                    )}
                  </div>
                  {section === "all" && (
                    <div>
                      <label
                        htmlFor="zeek-bpf-extra"
                        className="mb-1 block text-xs text-muted-foreground"
                      >
                        附加 BPF 条件（可选，如 not port 22）
                      </label>
                      <Input
                        id="zeek-bpf-extra"
                        value={bpfExtra}
                        onChange={(e) => setBpfExtra(e.target.value)}
                        placeholder="留空表示附加条件为空"
                      />
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {showNets && (
          <Card>
            <CardHeader>
              <CardTitle>抓包范围</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {loading ? (
                <Skeleton className="h-28 w-full" />
              ) : (
                <div>
                  <label
                    htmlFor="zeek-networks"
                    className="mb-1 block text-xs text-muted-foreground"
                  >
                    监控网段 <span aria-hidden="true">*</span>
                    （一行一条，支持 CIDR 与单个 IP；也可用逗号分隔）
                  </label>
                  <textarea
                    id="zeek-networks"
                    value={netsText}
                    aria-required="true"
                    onChange={(e) => setNetsText(e.target.value)}
                    className={TEXTAREA_CLS}
                    placeholder={"192.168.0.0/16\n10.0.0.0/8\n172.16.1.5"}
                  />
                  <p className="mt-1 text-xs text-muted-foreground">
                    已识别 <span className="tabular-nums">{nets.length}</span> 条；BPF 过滤器与
                    Site::local_nets 由这份清单自动生成（源或目的落在其中即抓取）。不填则无法保存
                    —— 未配置时前端会强制进首次向导。
                  </p>
                </div>
              )}

              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label htmlFor="zeek-body-kb" className="mb-1 block text-xs text-muted-foreground">
                    请求正文上限（KB，1~1024）
                  </label>
                  <Input
                    id="zeek-body-kb"
                    className="tabular-nums"
                    disabled={loading}
                    value={bodyKb}
                    onChange={(e) => setBodyKb(e.target.value)}
                    placeholder="16"
                  />
                </div>
                <div>
                  <label htmlFor="zeek-resp-kb" className="mb-1 block text-xs text-muted-foreground">
                    响应正文上限（KB，1~1024）
                  </label>
                  <Input
                    id="zeek-resp-kb"
                    className="tabular-nums"
                    disabled={loading}
                    value={respKb}
                    onChange={(e) => setRespKb(e.target.value)}
                    placeholder="64"
                  />
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                采集器侧按这两个值截正文再落库（默认 16 KB / 64 KB）；完整字节数仍记在{" "}
                <span className="font-mono">resp_body_len</span> /{" "}
                <span className="font-mono">request_body_len</span>，不受截断影响。改完保存，看门狗会在
                约 10 秒内重载采集器。
              </p>

              {section === "networks" && (
                <div>
                  <label
                    htmlFor="zeek-bpf-extra"
                    className="mb-1 block text-xs text-muted-foreground"
                  >
                    附加 BPF 条件（可选，如 not port 22）
                  </label>
                  <Input
                    id="zeek-bpf-extra"
                    value={bpfExtra}
                    onChange={(e) => setBpfExtra(e.target.value)}
                    placeholder="留空表示附加条件为空"
                  />
                </div>
              )}

              <div>
                <label htmlFor="zeek-tls-ports" className="mb-1 block text-xs text-muted-foreground">
                  按 TLS 解析的端口（可选，如 8000, 8008）
                </label>
                <Input
                  id="zeek-tls-ports"
                  className="tabular-nums"
                  disabled={loading}
                  value={tlsPorts}
                  onChange={(e) => setTlsPorts(e.target.value)}
                  placeholder="留空 = 沿用采集器默认的 HTTP 端口表"
                />
                <p className="mt-1 text-xs text-muted-foreground">
                  列在这里的端口**不再按 HTTP 解析**。采集器默认把 8000/8008 当 HTTP，
                  如果这两个端口实际跑的是 TLS，它会把 TLS 字节当 HTTP 文本行读，刷出大量假协议异常
                  （实测过 15 分钟一万多条）。**明文 HTTP 端口不要填进来**（例如本环境 8013 就是真 HTTP）。
                </p>
              </div>

              <p className="text-xs text-muted-foreground">
                这份网卡与网段配置**同时**用于网络采集器与签名引擎（Suricata）：签名引擎的 HOME_NET
                = 监控网段，抓包口 = 监听网卡，因此两者看到的范围始终一致。
                {status?.suricata
                  ? ` 签名引擎：${status.suricata.alive ? "运行中" : "未运行"}，已加载签名 ${status.suricata.rule_count ?? 0} 条`
                  : " 签名引擎：未部署（没有收到它的状态上报）。"}
              </p>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
            <CardTitle>当前生效</CardTitle>
            <div className="flex flex-wrap items-center gap-2">
              {status ? (
                <>
                  <Badge variant="info">轮转 {status.rotation_hours}h</Badge>
                  <Badge variant="medium">本地保留 {status.retention_days_local} 天</Badge>
                  <Badge variant="info">
                    正文上限 {Math.round(status.body_max_bytes / 1024)} /{" "}
                    {Math.round(status.resp_body_max_bytes / 1024)} KB
                  </Badge>
                </>
              ) : null}
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            {loading ? (
              <Skeleton className="h-16 w-full" />
            ) : status ? (
              <div className="space-y-2 rounded-xs bg-surface-1 px-3 py-2 text-xs">
                <p>
                  网卡 <span className="font-mono">{status.interface}</span>
                  {status.bpf_filter ? (
                    <>
                      {" · BPF "}
                      <span className="font-mono">{status.bpf_filter}</span>
                    </>
                  ) : (
                    " · 无 BPF 过滤（抓全部）"
                  )}
                </p>
                <p>
                  本地网段：
                  <span className="font-mono">
                    {status.local_nets || "（空，用采集器默认判定）"}
                  </span>
                </p>
                <p className="font-mono text-muted-foreground">{status.config_path}</p>
              </div>
            ) : (
              <EmptyState
                size="compact"
                tone={errs.isFailed(SRC.status) ? "danger" : "muted"}
                title={
                  errs.isFailed(SRC.status)
                    ? "读取失败（见上方错误条）"
                    : "状态未读到，当前生效值列不出来"
                }
                action={
                  <Button size="sm" variant="outline" onClick={() => void load()}>
                    重新读取
                  </Button>
                }
              />
            )}
          </CardContent>
        </Card>

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
          {/* 状态没读到就禁止保存：空表单点保存会把现有网段/网卡覆盖掉 */}
          <Button size="sm" onClick={save} disabled={busy || !status}>
            {busy ? "下发中…" : "保存并下发"}
          </Button>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            刷新状态
          </Button>
          {!status && !loading && (
            <span className="text-xs text-sev-critical-fg">
              状态未读到，已禁用保存（避免空表单覆盖现有配置）
            </span>
          )}
          {status && (
            <span className="text-xs tabular-nums text-muted-foreground">
              最近重载：{status.last_reload ? formatDateTime(status.last_reload) : "—"}
            </span>
          )}
        </div>
      </Section>
    </div>
  );
}
