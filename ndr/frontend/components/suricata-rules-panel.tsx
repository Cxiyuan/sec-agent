"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type SuricataRulesCheck,
  type SuricataRulesStatus,
} from "@/lib/api";
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Input } from "@shentong/ui";
import { PanelError, loadInto, usePanelErrors } from "@/components/panel-error";

/** 读取失败的接口名（错误条用）。 */
const SRC = {
  status: "签名规则状态",
  save: "保存更新配置",
  check: "检查更新",
  apply: "立即更新",
  reset: "清空规则",
} as const;

function fileList(files: string[] | undefined): string {
  if (!files || files.length === 0) return "—";
  return files.join("、");
}

/** 一次检查/更新结果的一句话说明（界面与历史共用）。 */
function resultText(item: SuricataRulesCheck | null | undefined): string {
  if (!item) return "还没检查过";
  if (item.error) return `失败：${item.error}`;
  if (!item.has_update) return `已是最新（版本 ${item.version || "—"}）`;
  const parts: string[] = [];
  if (item.added?.length) parts.push(`新增 ${item.added.length}`);
  if (item.updated?.length) parts.push(`更新 ${item.updated.length}`);
  if (item.removed?.length) parts.push(`删除 ${item.removed.length}`);
  const changes = parts.length ? parts.join("、") : "无差异";
  return item.validated
    ? `有新版本 ${item.version}（${changes}），校验通过，待确认`
    : `有新版本 ${item.version}（${changes}），但校验未通过`;
}

/**
 * 签名规则（Suricata）面板。
 *
 * 两条硬规则（与后端一致）：
 * - 规则由开发人员维护，界面只配置「在线地址（manifest：文件列表 + sha256）」；
 * - **检查 ≠ 生效**：检查只做「拉取 + 下载 + 容器校验」，生效必须人工在这里确认。
 */
export function SuricataRulesPanel() {
  const [status, setStatus] = React.useState<SuricataRulesStatus | null>(null);
  const [url, setUrl] = React.useState("");
  const [token, setToken] = React.useState("");
  const [clearToken, setClearToken] = React.useState(false);
  const [enabled, setEnabled] = React.useState(true);
  const [msg, setMsg] = React.useState("");
  const [busy, setBusy] = React.useState<"" | "save" | "check" | "apply" | "reset">("");
  const errs = usePanelErrors();

  const active = status?.active;
  const pending = status?.pending ?? null;
  const runtime = status?.runtime ?? {};
  const alive = "alive" in runtime ? Boolean(runtime.alive) : false;

  async function load() {
    errs.reset();
    await loadInto(errs, SRC.status, "/api/suricata/rules", (d: SuricataRulesStatus) => {
      setStatus(d);
      setUrl(d.source.url || "");
      setEnabled(d.source.enabled);
      setToken("");
      setClearToken(false);
    });
  }

  React.useEffect(() => {
    void load();
    // 只在挂载时读一次（load 内部自己收错误）
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function run(kind: "save" | "check" | "apply" | "reset", fn: () => Promise<string>) {
    setBusy(kind);
    setMsg("");
    try {
      setMsg(await fn());
      await load();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "操作失败");
    } finally {
      setBusy("");
    }
  }

  const save = () =>
    run("save", async () => {
      const payload: Record<string, unknown> = { url, enabled };
      if (clearToken) payload.token = "";
      else if (token) payload.token = token;
      await apiFetch("/api/suricata/rules/source", {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      const parts = ["已保存更新配置"];
      if (clearToken) parts.push("令牌已清除");
      else if (token) parts.push("令牌已更新");
      return `${parts.join("；")}。`;
    });

  const check = () =>
    run("check", async () => {
      const r = await apiFetch<SuricataRulesCheck>("/api/suricata/rules/check", { method: "POST" });
      return resultText(r);
    });

  const apply = () =>
    run("apply", async () => {
      if (!pending) throw new Error("没有待确认的新版本");
      if (
        !window.confirm(
          `现在把签名规则切到版本 ${pending.version}？\n` +
            `文件：${fileList(pending.files)}\n生效后签名引擎立刻按新规则告警。`,
        )
      ) {
        return "已取消，规则未变更。";
      }
      const r = await apiFetch<{ version: string; rule_count: number }>(
        "/api/suricata/rules/apply",
        { method: "POST" },
      );
      return `已生效：版本 ${r.version}，当前规则 ${r.rule_count} 条。`;
    });

  const reset = () =>
    run("reset", async () => {
      if (!window.confirm("清空全部签名规则？清空后签名引擎不会再产生任何告警（规则可重新在线获取）。")) {
        return "已取消，规则未变更。";
      }
      await apiFetch("/api/suricata/rules/reset", { method: "POST" });
      return "已清空规则（当前 0 条签名）。";
    });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base">签名规则（Suricata）</CardTitle>
        <div className="flex items-center gap-2">
          <Badge variant={alive ? "default" : "secondary"}>
            {alive ? "引擎运行中" : "引擎未运行"}
          </Badge>
          <Badge variant={status?.source.url ? "default" : "secondary"}>
            {status?.source.url ? "在线规则" : "未配置来源"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <PanelError errors={errs} />

        {(active?.rule_count ?? 0) === 0 && (
          <p className="rounded-md border border-sev-medium-bd bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium-fg">
            当前**没有加载任何签名规则**：签名引擎不会产生任何告警。请在下面配置规则更新地址后点
            「立即检查更新」，或在服务器把 *.rules 放进规则卷的 active/ 目录。
          </p>
        )}

        <div className="grid grid-cols-2 gap-3 text-sm">
          <div>
            <div className="text-xs text-muted-foreground">生效版本</div>
            <div className="font-mono">{active?.version || "空占位（无规则）"}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">生效规则条数</div>
            <div>{active?.rule_count ?? 0} 条</div>
          </div>
          <div className="col-span-2">
            <div className="text-xs text-muted-foreground">生效规则文件</div>
            <div className="font-mono text-xs">{fileList(active?.files)}</div>
          </div>
          <div className="col-span-2">
            <div className="text-xs text-muted-foreground">最近检查</div>
            <div className="text-xs">
              {status?.last_check_at || "—"}｜{resultText(status?.last_check)}
            </div>
          </div>
        </div>

        {pending && (
          <div className="space-y-2 rounded-md border border-input p-3">
            <div className="text-sm">
              待确认版本 <span className="font-mono">{pending.version}</span>（
              {pending.validated ? "校验通过" : "校验未通过"}）
            </div>
            <div className="font-mono text-xs text-muted-foreground">
              {fileList(pending.files)}
            </div>
            {!pending.validated && pending.validation_error && (
              <p className="text-xs text-destructive">校验失败：{pending.validation_error}</p>
            )}
            <div className="flex gap-2">
              <Button size="sm" onClick={apply} disabled={!pending.validated || busy !== ""}>
                {busy === "apply" ? "切换中…" : "立即更新（需确认）"}
              </Button>
              <span className="self-center text-xs text-muted-foreground">
                规则变更属检测口径，只有点确认才会生效
              </span>
            </div>
          </div>
        )}

        <div className="space-y-3 border-t border-input pt-3">
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              规则更新地址（manifest：文件列表 + sha256；可填目录，会自动补 manifest.json）
            </label>
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/shentong-rules/manifest.json"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                访问令牌（可选；留空 = 保持不变）
              </label>
              <Input
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder={status?.source.token_set ? "已配置（留空不修改）" : "未配置"}
                type="password"
              />
            </div>
            <div className="flex items-end gap-4 text-xs">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  className="h-4 w-4"
                  checked={clearToken}
                  onChange={(e) => setClearToken(e.target.checked)}
                />
                清除已存令牌
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  className="h-4 w-4"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                />
                启用定时检查（每 12 小时）
              </label>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={save} disabled={busy !== ""}>
              {busy === "save" ? "保存中…" : "保存配置"}
            </Button>
            <Button size="sm" onClick={check} disabled={busy !== "" || !status?.source.url}>
              {busy === "check" ? "检查中…（含下载与校验）" : "立即检查更新"}
            </Button>
            <Button size="sm" variant="outline" onClick={reset} disabled={busy !== ""}>
              {busy === "reset" ? "清空中…" : "清空规则"}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            检查更新会拉取 manifest、按 sha256 比对差异文件并在引擎容器里跑 `suricata -T` 校验；
            <strong>校验通过也不会自动生效</strong>，需要你点「立即更新」确认。
          </p>
        </div>

        {msg && <p className="text-xs">{msg}</p>}

        {(status?.history?.length ?? 0) > 0 && (
          <div className="space-y-1 border-t border-input pt-3">
            <div className="text-xs text-muted-foreground">最近更新记录</div>
            <ul className="space-y-1 text-xs">
              {status?.history.slice(0, 5).map((item, idx) => (
                <li key={`${item.at}-${idx}`} className="font-mono">
                  {item.at}｜{item.scheduled ? "定时" : "手动"}｜{resultText(item)}
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
