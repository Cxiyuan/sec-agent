"use client";

import * as React from "react";
import { ApiError, apiFetch, errorText, type ZeekStatus } from "@/lib/api";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";

const SELECT_CLS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm";
const TEXTAREA_CLS =
  "h-28 w-full rounded-md border border-input bg-transparent p-2 font-mono text-sm";

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
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const nets = parseNets(netsText);
  const showIface = section === "all" || section === "iface";
  const showNets = section === "all" || section === "networks";

  async function load() {
    const d = await apiFetch<ZeekStatus>("/api/zeek/status");
    setStatus(d);
    setIface(d.interface);
    setNetsText(d.networks.join("\n"));
    setBpfExtra(d.bpf_extra || "");
  }

  React.useEffect(() => {
    load().catch(() => {});
  }, []);

  async function save() {
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<{ interface: string; note: string }>("/api/zeek/interface", {
        method: "PUT",
        body: JSON.stringify({ interface: iface, networks: netsText, bpf_extra: bpfExtra }),
      });
      setMsg(`已保存：网卡 ${r.interface}。${r.note}`);
      setTimeout(() => load().catch(() => {}), 12000);
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">
          {section === "networks" ? "监控网段（Zeek 抓包范围）" : "Zeek 采集（监听网卡）"}
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          {showNets && (
            <>
              Zeek 只抓「监控网段」内的流量，其余不抓；抓到的数据才会进 Logstash 与 Elasticsearch。
            </>
          )}
          {section === "all" && " "}
          {showIface && (
            <>
              改完点保存，Zeek 容器内的看门狗会在约 10 秒内自动重载（无需重启容器）。
              镜像内硬编码：日志每 <b>24 小时</b> 轮转、本地只保留 <b>3 天</b>。
            </>
          )}
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}

        {showIface && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                监听网卡（探测到 {status?.detected.length ?? 0} 张）
              </label>
              {status && status.detected.length > 0 ? (
                <select
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
                  value={iface}
                  onChange={(e) => setIface(e.target.value)}
                  placeholder="eth0（未探测到清单，可手填）"
                />
              )}
            </div>
            {section === "all" && (
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  附加 BPF 条件（可选，如 not port 22）
                </label>
                <Input
                  value={bpfExtra}
                  onChange={(e) => setBpfExtra(e.target.value)}
                  placeholder="留空表示附加条件为空"
                />
              </div>
            )}
          </div>
        )}

        {showNets && (
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              监控网段 *（一行一条，支持 CIDR 与单个 IP；也可用逗号分隔）
            </label>
            <textarea
              value={netsText}
              onChange={(e) => setNetsText(e.target.value)}
              className={TEXTAREA_CLS}
              placeholder={"192.168.0.0/16\n10.0.0.0/8\n172.16.1.5"}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              已识别 {nets.length} 条；BPF 过滤器与 Site::local_nets 由这份清单自动生成（源或目的
              落在其中即抓取）。不填则无法保存 —— 未配置时前端会强制进首次向导。
            </p>
          </div>
        )}

        {section === "networks" && (
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              附加 BPF 条件（可选，如 not port 22）
            </label>
            <Input
              value={bpfExtra}
              onChange={(e) => setBpfExtra(e.target.value)}
              placeholder="留空表示附加条件为空"
            />
          </div>
        )}

        <div className="flex items-center gap-3">
          <Button onClick={save} disabled={busy}>
            {busy ? "下发中…" : "保存并下发"}
          </Button>
          <Button variant="outline" onClick={() => load()}>
            刷新状态
          </Button>
          {status && (
            <span className="text-xs text-muted-foreground">
              最近重载：{status.last_reload ? status.last_reload.replace("T", " ").slice(0, 19) : "—"}
            </span>
          )}
        </div>

        {status && (
          <div className="rounded-md border p-3 text-xs">
            <p className="mb-1 text-muted-foreground">当前生效</p>
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
              本地网段 Site::local_nets：
              <span className="font-mono">
                {status.local_nets || "（空，用 Zeek 默认判定）"}
              </span>
            </p>
            <p className="mt-1 flex items-center gap-2">
              <Badge variant="info">轮转 {status.rotation_hours}h</Badge>
              <Badge variant="medium">本地保留 {status.retention_days_local} 天</Badge>
              <span className="font-mono text-muted-foreground">{status.config_path}</span>
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
