"use client";

import * as React from "react";
import { ApiError, apiFetch, errorText, type ZeekStatus } from "@/lib/api";
import {
  Badge,
  Button,
  EmptyState,
  Field,
  Input,
  SettingsBlock,
  SettingsBoard,
  SettingsForm,
  Skeleton,
  cn,
  formatDateTime,
} from "@shentong/ui";
import { loadInto, PanelError, usePanelErrors } from "@/components/panel-error";

/** 与 `Input` 同一套边框/底色/聚焦态，下拉框与文本域不能各自一套材质。 */
const SELECT_CLS =
  "h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-13 transition-colors focus-visible:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-50";
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
 *
 * 2026-10 排版：表单卡与保存条走主列，「当前生效」是只读事实走右侧侧栏。
 * 保存条必须跟在主列表单下面 —— 放到侧栏底下会让人以为在保存右边那份状态。
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
  /** 所选网卡的运行状态（`ZeekIfaceInfo.state`）：后端没有 PID 字段，用它能表达"这块网卡现在是什么状态" */
  const ifaceState =
    status?.detected.find((i) => i.name === (status.interface || iface))?.state || "";

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

  /** 只读的「当前生效」列：原来是右侧第二张卡，现在作为「抓包口」分区的 `rail`
      （一条竖线分隔，不再是独立盒子）。读不到时那张 EmptyState 与「重新读取」按钮也在这列里 ——
      在右列里「这一块是现状、不是输入」才一眼看得出来。 */
  const currentRail = (
    <div className="space-y-2">
      {/* rail 没有独立标题条：原卡头那三个徽标排在这一列顶部的小标签行里 */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-foreground">当前生效</span>
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
      {loading ? (
        // 骨架分行画：徽标组 + 6 行 key/value，和加载完的形状对上才不跳版
        <div className="space-y-2">
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-5 w-4/5" />
          <div className="space-y-1">
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-2/3" />
            <Skeleton className="h-3 w-1/2" />
          </div>
        </div>
      ) : status ? (
        /* 这里没有「PID」：`ZeekStatus` 根本没有进程 id 字段。
           要真正的进程状态需要后端在 /api/zeek/status 增字段，属业务变更，本轮不做。
           改用真实字段表达同一件事：所选网卡的状态（detected[].state）、最近重载时间、
           探测到的网卡数。 */
        <div className="divide-y divide-border-subtle rounded-xs bg-surface-1 px-3 py-2 text-xs">
          <p className="pb-1">
            监听网卡 <span className="font-mono">{status.interface || "—"}</span>
            {ifaceState ? `（${ifaceState}）` : ""}
          </p>
          <p className="py-1">
            BPF 过滤器{" "}
            <span className="font-mono">
              {status.bpf_filter || "无 BPF 过滤（抓全部）"}
            </span>
          </p>
          <p className="py-1">
            本地网段：
            <span className="font-mono">
              {status.local_nets || "（空，用采集器默认判定）"}
            </span>
          </p>
          <p className="py-1">
            最近重载{" "}
            <span className="tabular-nums">
              {status.last_reload ? formatDateTime(status.last_reload) : "从未重载"}
            </span>
          </p>
          <p className="py-1">
            探测网卡{" "}
            <span className="tabular-nums">
              {status.detected.length
                ? `探测到 ${status.detected.length} 张`
                : "未探测到网卡（可手填）"}
            </span>
          </p>
          <p className="break-all pt-1 font-mono text-muted-foreground">
            {status.config_path || "—"}
          </p>
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
    </div>
  );

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />
      {/* 一块铺满正文区的底板：两块表单各自一个内嵌分区，整页说明拆到对应分区的标题下。 */}
      <SettingsBoard>
        {showIface && (
          <SettingsBlock
            title="抓包口"
            description={
              <>
                改完点保存，采集器容器内的看门狗会在约 10 秒内自动重载（无需重启容器）。
                镜像内硬编码：日志每 <b>24 小时</b> 轮转、本地只保留 <b>3 天</b>。
              </>
            }
            rail={currentRail}
          >
            {loading ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <Skeleton className="h-14 w-full" />
                {section === "all" && <Skeleton className="h-14 w-full" />}
              </div>
            ) : (
              <SettingsForm>
                <Field
                  label={`监听网卡（${status ? `探测到 ${status.detected.length} 张` : "状态未读到"}）`}
                  htmlFor="zeek-iface"
                  span="md"
                  controlWidth="md"
                  /* 下拉退化成手填时要说清楚为什么没得选 —— 原来是静默退化，
                     用户不知道是采集器没跑还是自己配错了 */
                  hint={
                    status && status.detected.length === 0
                      ? "没探测到网卡清单（采集器未运行或权限不足），可手填"
                      : undefined
                  }
                >
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
                </Field>
                {section === "all" && (
                  <Field
                    label="附加 BPF 条件（可选，如 not port 22）"
                    htmlFor="zeek-bpf-extra"
                    span="md"
                    controlWidth="md"
                  >
                    <Input
                      id="zeek-bpf-extra"
                      value={bpfExtra}
                      onChange={(e) => setBpfExtra(e.target.value)}
                      placeholder="留空表示附加条件为空"
                    />
                  </Field>
                )}
              </SettingsForm>
            )}
          </SettingsBlock>
        )}

        {showNets && (
          <SettingsBlock
            title="抓包范围"
            description={
              <>
                采集器只抓「监控网段」内的流量，其余不抓；抓到的数据才会进 Logstash 与
                Elasticsearch。
              </>
            }
            bodyClassName="space-y-3"
            rail={showIface ? undefined : currentRail}
          >
            {loading ? (
              <Skeleton className="h-32 w-full" />
            ) : (
              <SettingsForm>
              <Field
                label="监控网段（一行一条，支持 CIDR 与单个 IP；也可用逗号分隔）"
                htmlFor="zeek-networks"
                span="full"
                controlWidth="md"
                required
                hint={
                  <>
                    已识别 <span className="tabular-nums">{nets.length}</span> 条；BPF
                    过滤器与 Site::local_nets 由这份清单自动生成（源或目的落在其中即抓取）。
                    不填则无法保存 —— 未配置时前端会强制进首次向导。
                  </>
                }
              >
                <textarea
                  id="zeek-networks"
                  value={netsText}
                  aria-required="true"
                  onChange={(e) => setNetsText(e.target.value)}
                  className={TEXTAREA_CLS}
                  placeholder={"192.168.0.0/16\n10.0.0.0/8\n172.16.1.5"}
                />
              </Field>
              <Field label="请求正文上限（KB，1~1024）" htmlFor="zeek-body-kb" controlWidth="sm">
                <Input
                  id="zeek-body-kb"
                  className="tabular-nums"
                  disabled={loading}
                  value={bodyKb}
                  onChange={(e) => setBodyKb(e.target.value)}
                  placeholder="16"
                />
              </Field>
              <Field label="响应正文上限（KB，1~1024）" htmlFor="zeek-resp-kb" controlWidth="sm">
                <Input
                  id="zeek-resp-kb"
                  className="tabular-nums"
                  disabled={loading}
                  value={respKb}
                  onChange={(e) => setRespKb(e.target.value)}
                  placeholder="64"
                />
              </Field>
              {section === "networks" && (
                <Field
                  label="附加 BPF 条件（可选，如 not port 22）"
                  htmlFor="zeek-bpf-extra"
                  controlWidth="md"
                >
                  <Input
                    id="zeek-bpf-extra"
                    value={bpfExtra}
                    onChange={(e) => setBpfExtra(e.target.value)}
                    placeholder="留空表示附加条件为空"
                  />
                </Field>
              )}
              <Field
                label="按 TLS 解析的端口（可选，如 8000, 8008）"
                htmlFor="zeek-tls-ports"
                span="full"
                controlWidth="md"
                hint={
                  <>
                    列在这里的端口<b>不再按 HTTP 解析</b>。采集器默认把 8000/8008 当 HTTP，
                    如果这两个端口实际跑的是 TLS，它会把 TLS 字节当 HTTP 文本行读，
                    刷出大量假协议异常（实测过 15 分钟一万多条）。
                    <b>明文 HTTP 端口不要填进来</b>（例如本环境 8013 就是真 HTTP）。
                  </>
                }
              >
                <Input
                  id="zeek-tls-ports"
                  className="tabular-nums"
                  disabled={loading}
                  value={tlsPorts}
                  onChange={(e) => setTlsPorts(e.target.value)}
                  placeholder="留空 = 沿用采集器默认的 HTTP 端口表"
                />
              </Field>
            </SettingsForm>
          )}
          {/* 两个上限字段的共同口径：跨字段的说明放网格外面，避免被当成某一个字段的 hint */}
          <p className="text-xs text-muted-foreground">
            采集器侧按这两个值截正文再落库（默认 16 KB / 64 KB）；完整字节数仍记在{" "}
            <span className="font-mono">resp_body_len</span> /{" "}
            <span className="font-mono">request_body_len</span>，不受截断影响。改完保存，看门狗会在
            约 10 秒内重载采集器。
          </p>

          <p className="text-xs text-muted-foreground">
            这份网卡与网段配置同时用于网络采集器与签名引擎：签名引擎的 HOME_NET
            = 监控网段，抓包口 = 监听网卡，因此两者看到的范围始终一致。
            {status?.suricata
              ? ` 签名引擎：${status.suricata.alive ? "运行中" : "未运行"}，已加载签名 ${status.suricata.rule_count ?? 0} 条`
              : " 签名引擎：未部署（没有收到它的状态上报）。"}
          </p>
        </SettingsBlock>
      )}

        {/* 保存条：原来排在主列表单后面，现在单独成一段（无标题条）——
            这一页显示的是网卡还是网段，保存都在底板最后一行，位置固定。 */}
        <SettingsBlock bodyClassName="space-y-3">
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
        </SettingsBlock>

      </SettingsBoard>
    </div>
  );
}
