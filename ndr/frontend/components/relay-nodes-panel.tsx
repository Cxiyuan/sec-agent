"use client";

import * as React from "react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  ApiError,
  apiFetch,
  errorText,
  formatDateTime,
} from "@shentong/ui";

import { PanelError, loadInto, usePanelErrors } from "@/components/panel-error";
import type { RelayNodesPayload } from "@/lib/api";

/**
 * 中继节点清单（反向代理 / WAF / 内网 DNS 转发器）——「监控网段」页的第二块。
 *
 * 与上面的「监控网段」是两件事：网段决定**抓什么**（Zeek 的 BPF 与 local_nets），
 * 这份清单决定**怎么理解抓到的流量**：
 * - 哪些直连对端带来的 `X-Forwarded-For` / `X-Real-IP` 可以信（→ `real_client_ip`）；
 * - 哪些跳是中继的「接受/转发」，要按「一次业务访问只算一条」去重。
 *
 * 存 PG、只读 PG（没有 env 兜底）：**没配 = 系统认定网络里没有中继** —— 不认代理头、
 * 不做去重。故意单独一个卡片与保存按钮：改清单**不会**触发 Zeek 重载（不打断抓包）。
 * 角色由检测器按实际流量自动推算后回写，这里只读展示。
 */

const SRC = { relay: "中继节点清单" } as const;

function roleText(roles: string[] | undefined): string {
  const list = roles || [];
  if (!list.length) return "未判定";
  return list.map((r) => (r === "dns" ? "DNS 转发" : "反向代理")).join(" / ");
}

export function RelayNodesPanel() {
  const errs = usePanelErrors();
  const [data, setData] = React.useState<RelayNodesPayload | null>(null);
  const [text, setText] = React.useState("");
  const [sides, setSides] = React.useState<Record<string, string>>({});
  const [busy, setBusy] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  const [sideMsg, setSideMsg] = React.useState("");

  function apply(d: RelayNodesPayload) {
    setData(d);
    setText(d.text);
    setSides(d.sides || {});
  }

  async function load() {
    await loadInto(errs, SRC.relay, "/api/zeek/relay-nodes", apply);
  }

  React.useEffect(() => {
    void load();
    // 只在挂载时读一次
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function save() {
    setBusy(true);
    setMsg("");
    try {
      const d = await apiFetch<RelayNodesPayload>("/api/zeek/relay-nodes", {
        method: "PUT",
        body: JSON.stringify({ nodes: text }),
      });
      apply(d);
      setMsg(
        d.configured
          ? `已保存 ${d.count} 项 —— 代理头信任与中继去重立即按新清单生效（后端 30 秒内刷新）`
          : "已清空清单 —— 现在系统认定「网络里没有中继」：不信任任何代理头、不做中继去重",
      );
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  const dirty = (data?.text || "") !== text;
  // 清单里的条目（单地址能手动指定侧向；真正的网段条目按每条 IP 自动判）
  const nodes = data?.nodes || [];
  const sideDirty = nodes.some(
    (ip) => (sides[ip] || "auto") !== ((data?.sides || {})[ip] || "auto"),
  );

  async function saveSides() {
    setBusy(true);
    setSideMsg("");
    try {
      const payload = Object.fromEntries(nodes.map((ip) => [ip, sides[ip] || "auto"]));
      const d = await apiFetch<RelayNodesPayload>("/api/zeek/relay-nodes/sides", {
        method: "PUT",
        body: JSON.stringify({ sides: payload }),
      });
      apply(d);
      setSideMsg("已保存侧向设置 —— 检测器约 30 秒内生效（读取方缓存 TTL）");
    } catch (e) {
      setSideMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  function sideText(side: string | undefined): string {
    return side === "back" ? "保留源站侧" : "保留客户端侧";
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          中继节点清单（反向代理 / WAF / 内网 DNS 转发器）
          <span className="text-xs font-normal text-muted-foreground">
            一行一个 IP 或 CIDR（也支持逗号分隔、<span className="font-mono">#</span> 注释）。
            改它**不会**触发网络采集器重载。
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <PanelError errors={errs} />

        {data && !data.configured ? (
          <p className="rounded-md border border-amber-900 bg-amber-950/40 px-3 py-2 text-xs text-amber-200">
            未配置中继清单：当前**不信任任何代理头**（`real_client_ip` 恒为空），
            也**不做中继去重** —— 经过代理/DNS 转发的同一次访问会在检测与计数里出现两次，
            且告警会归因到代理/DNS 服务器上。填入地址后立即生效。
          </p>
        ) : null}

        <textarea
          className="min-h-[120px] w-full rounded-md border bg-transparent p-2 font-mono text-xs"
          spellCheck={false}
          placeholder={"172.16.199.203\n172.16.196.112\n10.0.0.53   # 内网 DNS 转发器"}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />

        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" disabled={busy || !dirty} onClick={() => void save()}>
            保存清单{dirty ? "（有改动）" : ""}
          </Button>
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => void load()}>
            重新读取
          </Button>
          <Badge variant={data?.configured ? "success" : "medium"}>
            {data?.configured ? `已配置 ${data?.count ?? 0} 项` : "未配置"}
          </Badge>
          {msg ? <span className="text-xs text-muted-foreground">{msg}</span> : null}
        </div>

        <div>
          <p className="mb-1 text-xs text-muted-foreground">
            角色与两侧内容由检测器按实际流量自动统计并回写（
            {data?.detected_at ? `推算时间 ${formatDateTime(data.detected_at)}` : "只读"}）。
            <b>内容</b>指该侧带 Host/URI/请求体的明文日志条数（http/dns 这类）；
            <b>TLS 加密流不算内容</b>。默认按实测自动判（哪侧有内容就保留哪侧），
            拓扑特殊时可手动指定「保留哪一侧」：
          </p>
          {nodes.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>地址</TableHead>
                  <TableHead>推算角色</TableHead>
                  <TableHead>客户端侧内容</TableHead>
                  <TableHead>源站侧内容</TableHead>
                  <TableHead>当前保留</TableHead>
                  <TableHead>保留哪一侧</TableHead>
                  <TableHead>http/ssl 证据</TableHead>
                  <TableHead>dns 证据</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {nodes.map((ip) => {
                  const info = data?.roles?.[ip] || {};
                  const isNet = ip.includes("/");
                  return (
                    <TableRow key={ip}>
                      <TableCell className="font-mono text-xs">{ip}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{roleText(info.roles)}</Badge>
                      </TableCell>
                      <TableCell>{info.front_content ?? 0}</TableCell>
                      <TableCell>{info.back_content ?? 0}</TableCell>
                      <TableCell className="text-xs">
                        {info.side ? sideText(info.side) : "未判定"}
                        {info.side_source === "manual" ? "（手动）" : ""}
                      </TableCell>
                      <TableCell>
                        {isNet ? (
                          <span className="text-xs text-muted-foreground">网段条目按每条 IP 自动判</span>
                        ) : (
                          <select
                            className="h-8 rounded-md border bg-transparent px-2 text-xs"
                            value={sides[ip] || "auto"}
                            onChange={(e) =>
                              setSides((prev) => ({ ...prev, [ip]: e.target.value }))
                            }
                          >
                            <option value="auto">自动（按实测内容）</option>
                            <option value="front">保留客户端侧</option>
                            <option value="back">保留源站侧</option>
                          </select>
                        )}
                      </TableCell>
                      <TableCell>{info.proxy ?? 0}</TableCell>
                      <TableCell>{info.dns ?? 0}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <p className="text-xs text-muted-foreground">
              {data?.configured ? "还没有足够流量做判定（下一个回写周期后出现）" : "配置清单后由系统自动判定"}
            </p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Button size="sm" disabled={busy || !sideDirty} onClick={() => void saveSides()}>
              保存侧向{sideDirty ? "（有改动）" : ""}
            </Button>
            {sideMsg ? <span className="text-xs text-muted-foreground">{sideMsg}</span> : null}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
