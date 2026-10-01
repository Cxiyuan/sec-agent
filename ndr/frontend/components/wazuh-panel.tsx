"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type WazuhPayload,
  type WazuhRuleUploadResult,
  type WazuhRulesPayload,
  type WazuhTestResult,
} from "@/lib/api";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";

const TEXTAREA_CLS =
  "h-40 w-full rounded-md border border-input bg-transparent p-2 font-mono text-xs";

const RULE_TEMPLATE = `<!-- 深瞳：本地自定义告警规则（id 请用 100000-120000 区段） -->
<group name="shentong,">
  <rule id="100100" level="10">
    <decoded_as>json</decoded_as>
    <description>示例规则：请按需修改</description>
  </rule>
</group>
`;

/**
 * Wazuh 4.14 接入：API 凭据 / 连通性 / Agent 清单 / 最近 24 小时入库量 / 自定义规则下发与校验。
 *
 * 「API 通了」不等于「日志接进来了」，所以状态区同时显示 ES 里 `source_system=wazuh`
 * 的告警与原始日志条数：两者都长期为 0 就说明 Filebeat 那一跳没配好。
 */
export function WazuhPanel() {
  const [data, setData] = React.useState<WazuhPayload | null>(null);
  const [url, setUrl] = React.useState("");
  const [user, setUser] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [verifyTls, setVerifyTls] = React.useState(false);
  const [rules, setRules] = React.useState<WazuhRulesPayload | null>(null);
  const [ruleFile, setRuleFile] = React.useState("local_rules.xml");
  const [ruleText, setRuleText] = React.useState(RULE_TEMPLATE);
  const [upload, setUpload] = React.useState<WazuhRuleUploadResult | null>(null);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const apply = React.useCallback((d: WazuhPayload) => {
    setData(d);
    setUrl(d.config.url);
    setUser(d.config.user);
    setPassword("");
    setVerifyTls(d.config.verify_tls);
  }, []);

  async function load() {
    const d = await apiFetch<WazuhPayload>("/api/wazuh");
    apply(d);
  }

  async function loadRules() {
    try {
      setRules(await apiFetch<WazuhRulesPayload>("/api/wazuh/rules"));
    } catch {
      setRules(null);
    }
  }

  React.useEffect(() => {
    load()
      .then(() => loadRules())
      .catch(() => setData(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function save() {
    setBusy(true);
    setMsg("");
    try {
      const d = await apiFetch<WazuhPayload>("/api/wazuh", {
        method: "PUT",
        body: JSON.stringify({
          url,
          user,
          // 空串 = 不改动已保存的密码（要换密码才填）
          password: password === "" ? null : password,
          verify_tls: verifyTls,
        }),
      });
      apply(d);
      setMsg("已保存");
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setBusy(true);
    setMsg("");
    try {
      const r = await apiFetch<WazuhTestResult>("/api/wazuh/test", {
        method: "POST",
        body: JSON.stringify({
          url,
          user,
          password: password === "" ? null : password,
          verify_tls: verifyTls,
        }),
      });
      setMsg(
        r.ok
          ? `连通正常：Wazuh ${r.version || "(版本未知)"}${r.cluster_enabled ? "，集群模式" : ""}`
          : `连不通：${r.detail}`,
      );
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "测试失败");
    } finally {
      setBusy(false);
    }
  }

  async function uploadRule() {
    setBusy(true);
    setMsg("");
    setUpload(null);
    try {
      const r = await apiFetch<WazuhRuleUploadResult>("/api/wazuh/rules", {
        method: "POST",
        body: JSON.stringify({ filename: ruleFile, text: ruleText, verify: true }),
      });
      setUpload(r);
      setMsg(r.verified ? "已下发并校验通过" : r.detail);
      await loadRules();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "下发失败");
    } finally {
      setBusy(false);
    }
  }

  const cfg = data?.config;
  const st = data?.status;
  const ing = data?.ingest;
  const connected = Boolean(st?.reachable);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Wazuh 接入（4.14）</CardTitle>
        <p className="text-xs text-muted-foreground">
          这里配置的是 Wazuh manager 的 <b>API（55000）</b>：看 Agent 在线情况、下发自定义规则。
          日志本身走另外一跳（Filebeat 读 <span className="font-mono">alerts.json</span> /{" "}
          <span className="font-mono">archives.json</span> 后进采集队列），所以下面同时显示
          <b>最近 24 小时实际入库量</b>：API 通了但入库为 0，说明那一跳还没配好。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}

        {cfg && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border p-3 text-xs">
            <Badge variant={connected ? "low" : cfg.configured ? "medium" : "high"}>
              {connected ? "API 已连通" : cfg.configured ? "已配置，连不上" : "未配置"}
            </Badge>
            <span className="font-mono">{cfg.url || "(未填地址)"}</span>
            <span className="text-muted-foreground">用户 {cfg.user || "—"}</span>
            <span className="text-muted-foreground">
              密码 {cfg.password_set ? `已设置（${cfg.password_masked}）` : "未设置"}
            </span>
            {st && <span className="text-muted-foreground">{st.detail}</span>}
          </div>
        )}

        <div className="grid gap-3 md:grid-cols-2">
          <label className="space-y-1 text-xs">
            <span className="text-muted-foreground">API 地址</span>
            <Input
              value={url}
              placeholder="https://wazuh-manager:55000"
              onChange={(e) => setUrl(e.target.value)}
            />
          </label>
          <label className="space-y-1 text-xs">
            <span className="text-muted-foreground">用户名</span>
            <Input value={user} placeholder="wazuh-wui" onChange={(e) => setUser(e.target.value)} />
          </label>
          <label className="space-y-1 text-xs">
            <span className="text-muted-foreground">密码（留空表示不改动）</span>
            <Input
              value={password}
              type="password"
              placeholder={cfg?.password_set ? "留空 = 保持不变" : "管理员密码"}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <label className="flex items-center gap-2 pt-5 text-xs">
            <input
              type="checkbox"
              checked={verifyTls}
              onChange={(e) => setVerifyTls(e.target.checked)}
            />
            <span>校验 TLS 证书（Wazuh 自签证书时不要勾）</span>
          </label>
        </div>

        <div className="flex flex-wrap gap-2">
          <Button size="sm" disabled={busy} onClick={save}>
            保存
          </Button>
          <Button size="sm" variant="outline" disabled={busy || !url} onClick={test}>
            测试连接
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={busy}
            onClick={() => {
              load().catch(() => setData(null));
              void loadRules();
            }}
          >
            刷新
          </Button>
        </div>

        {st && (
          <div className="flex flex-wrap gap-3 rounded-md border p-3 text-xs">
            <span>API 版本 {st.version || "—"}</span>
            <span>{st.cluster_enabled ? "集群模式" : "单机模式"}</span>
            <span>Agent 共 {st.agents.total}</span>
            <span className={st.agents.disconnected ? "text-destructive" : "text-muted-foreground"}>
              在线 {st.agents.active} / 断开 {st.agents.disconnected}
            </span>
            {st.agents.never_connected > 0 && <span>从未连接 {st.agents.never_connected}</span>}
            <span>近 24h 入库：告警 {ing?.alerts ?? 0} 条</span>
            <span>原始日志 {ing?.archives ?? 0} 条</span>
            <span className="text-muted-foreground">最近一条 {ing?.last_at || "—"}</span>
            {ing?.error ? <span className="text-destructive">读 ES 失败：{ing.error}</span> : null}
          </div>
        )}

        {data && data.agents.length > 0 && (
          <div className="overflow-auto rounded-md border">
            <table className="w-full text-xs">
              <thead className="bg-muted/50 text-left">
                <tr>
                  <th className="p-2">ID</th>
                  <th className="p-2">名称</th>
                  <th className="p-2">IP</th>
                  <th className="p-2">状态</th>
                  <th className="p-2">版本</th>
                  <th className="p-2">最近心跳</th>
                </tr>
              </thead>
              <tbody>
                {data.agents.slice(0, 100).map((a) => (
                  <tr key={a.id} className="border-t">
                    <td className="p-2 font-mono">{a.id}</td>
                    <td className="p-2">{a.name || "—"}</td>
                    <td className="p-2 font-mono">{a.ip || "—"}</td>
                    <td className="p-2">
                      <Badge variant={a.status === "active" ? "low" : "medium"}>
                        {a.status || "未知"}
                      </Badge>
                    </td>
                    <td className="p-2">{a.version || "—"}</td>
                    <td className="p-2 text-muted-foreground">{a.lastKeepAlive || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data.agents.length > 100 && (
              <p className="p-2 text-xs text-muted-foreground">
                只显示前 100 个（共 {data.agents.length} 个）
              </p>
            )}
          </div>
        )}

        <div className="space-y-2 rounded-md border p-3">
          <p className="text-xs font-medium">下发自定义规则文件</p>
          <div className="grid gap-3 md:grid-cols-3">
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">文件名（只能一层，.xml 结尾）</span>
              <Input value={ruleFile} onChange={(e) => setRuleFile(e.target.value)} />
            </label>
          </div>
          <textarea
            className={TEXTAREA_CLS}
            value={ruleText}
            onChange={(e) => setRuleText(e.target.value)}
          />
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" disabled={busy} onClick={uploadRule}>
              下发并校验
            </Button>
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => void loadRules()}>
              刷新规则文件列表
            </Button>
          </div>
          {upload && (
            <p className="text-xs text-muted-foreground">
              发出 {upload.sent_rules} 条 / manager 上生效 {upload.applied_rules} 条 ·{" "}
              {upload.verified ? "校验通过" : "未通过校验"}
              {upload.rule_ids.length > 0 ? `（${upload.rule_ids.slice(0, 8).join(", ")}）` : ""}
            </p>
          )}
          {rules && (
            <p className="text-xs text-muted-foreground">
              自定义规则文件 {rules.local.length} 个
              {rules.local.length > 0 ? `：${rules.local.map((f) => f.filename).join("、")}` : ""}
            </p>
          )}
        </div>

        {data?.env.url && (
          <p className="text-xs text-muted-foreground">
            环境默认地址 {data.env.url}（界面保存的值优先）
          </p>
        )}
        {data?.hint && <p className="text-xs text-muted-foreground">{data.hint}</p>}
      </CardContent>
    </Card>
  );
}
