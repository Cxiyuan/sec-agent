"use client";

import * as React from "react";
import { ApiError, apiFetch, errorText, type ZeekStatus } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

const SELECT_CLS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm";

/** Zeek 采集配置：监听网卡 / BPF / 本地网段。后端写共享配置，Zeek 看门狗自动重载。 */
export function ZeekPanel() {
  const [status, setStatus] = React.useState<ZeekStatus | null>(null);
  const [iface, setIface] = React.useState("");
  const [bpf, setBpf] = React.useState("");
  const [nets, setNets] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function load() {
    const d = await apiFetch<ZeekStatus>("/api/zeek/status");
    setStatus(d);
    setIface(d.interface);
    setBpf(d.bpf_filter || "");
    setNets(d.local_nets || "");
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
        body: JSON.stringify({ interface: iface, bpf_filter: bpf, local_nets: nets }),
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
        <CardTitle className="text-sm">Zeek 采集（监听网卡）</CardTitle>
        <p className="text-xs text-muted-foreground">
          改完点保存，Zeek 容器内的看门狗会在约 10 秒内自动重载（无需重启容器）。
          镜像内硬编码：日志每 <b>24 小时</b> 轮转、本地只保留 <b>3 天</b>。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}

        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              监听网卡（探测到 {status?.detected.length ?? 0} 张）
            </label>
            {status && status.detected.length > 0 ? (
              <select value={iface} onChange={(e) => setIface(e.target.value)} className={SELECT_CLS}>
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
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              BPF 过滤器（可选，如 not port 22）
            </label>
            <Input value={bpf} onChange={(e) => setBpf(e.target.value)} placeholder="留空表示不过滤" />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              本地网段 Site::local_nets（留空=取分析网段）
            </label>
            <Input
              value={nets}
              onChange={(e) => setNets(e.target.value)}
              placeholder="10.0.0.0/8,192.168.0.0/16"
            />
          </div>
        </div>

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
              {status.bpf_filter ? ` · BPF ${status.bpf_filter}` : " · 无 BPF 过滤"}
            </p>
            <p>
              本地网段：
              {status.effective_local_nets.length > 0
                ? status.effective_local_nets.join(", ")
                : "（空，用 Zeek 默认判定）"}
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
