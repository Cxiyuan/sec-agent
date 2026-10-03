"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type WazuhPayload,
  type WazuhRuleUploadResult,
  type WazuhRulesPayload,
} from "@/lib/api";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { PanelError, loadInto, emptyOrFailed, usePanelErrors } from "@/components/panel-error";

/** 读取失败的接口名（错误条用）。 */
const SRC = {
  main: "Wazuh 接入状态（/api/wazuh）",
  rules: "自定义规则文件列表（/api/wazuh/rules）",
} as const;

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
 * Wazuh 4.14 接入状态（只读）+ 自定义规则下发。
 *
 * Wazuh 是**随本项目一起部署**的内置服务，连接信息由部署环境固定（`.env` 的
 * `WAZUH_API_*` → 后台 `ST_WAZUH_API_*`），所以这一页没有「填地址 / 填密码 / 保存」
 * 这类配置项 —— 用户不需要配置 Wazuh 的连接接入，只要看状态。
 *
 * 「API 通了」不等于「日志接进来了」，所以状态区同时显示 ES 里 `source_system=wazuh`
 * 的告警与原始日志条数：两者都长期为 0 就说明 Filebeat 那一跳没配好。
 */
export function WazuhPanel() {
  const errs = usePanelErrors();
  const [data, setData] = React.useState<WazuhPayload | null>(null);
  const [rules, setRules] = React.useState<WazuhRulesPayload | null>(null);
  const [ruleFile, setRuleFile] = React.useState("local_rules.xml");
  const [ruleText, setRuleText] = React.useState(RULE_TEMPLATE);
  const [upload, setUpload] = React.useState<WazuhRuleUploadResult | null>(null);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function load() {
    await loadInto(errs, SRC.main, "/api/wazuh", setData);
  }

  async function loadRules() {
    await loadInto(errs, SRC.rules, "/api/wazuh/rules", setRules);
  }

  React.useEffect(() => {
    void (async () => {
      errs.reset();
      await load();
      await loadRules();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
          Wazuh 随本项目一起部署，连接信息由部署环境固定（<span className="font-mono">.env</span>{" "}
          的 <span className="font-mono">WAZUH_API_*</span>），这里只显示状态，不需要配置。 本页看
          Agent 在线情况与自定义规则下发；日志本身走另外一跳（Filebeat 读{" "}
          <span className="font-mono">alerts.json</span> /{" "}
          <span className="font-mono">archives.json</span> 后进采集队列），所以下面同时显示
          <b>最近 24 小时实际入库量</b>：API 通了但入库为 0，说明那一跳没配好。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {msg && <p className="text-sm text-primary">{msg}</p>}
        <PanelError errors={errs} />

        {cfg && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border p-3 text-xs">
            <Badge variant={connected ? "low" : cfg.configured ? "medium" : "high"}>
              {connected ? "API 已连通" : cfg.configured ? "已配置，连不上" : "未配置"}
            </Badge>
            <span className="font-mono">{cfg.url || "(部署环境没给地址)"}</span>
            <span className="text-muted-foreground">用户 {cfg.user || "—"}</span>
            <span className="text-muted-foreground">
              密码 {cfg.password_set ? "已设置" : "未设置"}
            </span>
            {st && <span className="text-muted-foreground">{st.detail}</span>}
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            variant="ghost"
            disabled={busy}
            onClick={() => {
              void (async () => {
                errs.reset();
                await load();
                await loadRules();
              })();
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
            {/* 读 ES 失败时不能拿 0 冒充「一条都没有」 */}
            <span>近 24h 入库：告警 {ing?.error ? "未读到" : (ing?.alerts ?? 0)} 条</span>
            <span>原始日志 {ing?.error ? "未读到" : (ing?.archives ?? 0)} 条</span>
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

        {data && data.agents.length === 0 && (
          <p className="text-xs text-muted-foreground">
            Agent 清单是空的：
            {connected
              ? "manager 上没有注册任何 Agent"
              : "API 没连通时读不到清单（看上面状态行的 detail）"}
          </p>
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
              {rules.local.length === 0
                ? emptyOrFailed(errs, SRC.rules, "还没有自定义规则文件（下发一个就会出现）")
                : `自定义规则文件 ${rules.local.length} 个：${rules.local.map((f) => f.filename).join("、")}`}
            </p>
          )}
        </div>

        {data?.hint && <p className="text-xs text-muted-foreground">{data.hint}</p>}
      </CardContent>
    </Card>
  );
}
