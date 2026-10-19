"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  formatDateTime,
  type SuricataRulesCheck,
  type SuricataRulesStatus,
} from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Dialog,
  EmptyState,
  Field,
  FieldGrid,
  Input,
  SettingsGrid,
  SettingsMain,
  SettingsRail,
  Skeleton,
  Stat,
  StatSkeleton,
  cn,
} from "@shentong/ui";
import { PanelError, loadInto, usePanelErrors } from "@/components/panel-error";

/** 读取失败的接口名（错误条用）。 */
const SRC = {
  status: "签名规则状态",
  save: "保存更新配置",
  check: "检查更新",
  apply: "立即更新",
  reset: "清空规则",
} as const;

/** 需要二次确认的动作（切版本 / 清空规则）：用 Dialog 而不是 window.confirm。 */
interface ConfirmState {
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
}

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
 *
 * `variant`：
 * - `"card"`（默认）：独立使用时卡片就是容器；
 * - `"inline"`：挂在检测规则树的 L2 节点下用。整棵树装在一张 Card 里，树内**禁止再出现 Card**
 *   （这是全站层级约定），所以这里把所有 Card 降级成内联格：只留 `bg-surface-1` 底色，
 *   去掉描边与投影。顺带把 SettingsGrid 的 rail 收窄一点 —— 树里还有两级 20px 缩进，
 *   19rem 的 rail 会把主列压到 700px 以下。
 */
export function SuricataRulesPanel({ variant = "card" }: { variant?: "card" | "inline" }) {
  const inline = variant === "inline";
  /** inline 下把 Card 压回树内的内联格（L3）：只有底色、不要描边与投影 */
  const cardCls = inline ? "rounded-sm border-0 bg-surface-1 shadow-none" : undefined;
  const headCls = inline ? "p-0 pb-2" : undefined;
  const bodyCls = inline ? "p-0 pt-2" : undefined;
  const [status, setStatus] = React.useState<SuricataRulesStatus | null>(null);
  const [url, setUrl] = React.useState("");
  const [token, setToken] = React.useState("");
  const [clearToken, setClearToken] = React.useState(false);
  const [enabled, setEnabled] = React.useState(true);
  const [msg, setMsg] = React.useState("");
  /** 结果提示的语义：成功绿条 / 失败红条 */
  const [msgKind, setMsgKind] = React.useState<"ok" | "err">("ok");
  const [busy, setBusy] = React.useState<"" | "save" | "check" | "apply" | "reset">("");
  /** 首次读取：先画骨架，别把「正在读」显示成「没有规则」 */
  const [loading, setLoading] = React.useState(true);
  const [confirm, setConfirm] = React.useState<ConfirmState | null>(null);
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
    void (async () => {
      await load();
      setLoading(false);
    })();
    // 只在挂载时读一次（load 内部自己收错误）
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function run(kind: "save" | "check" | "apply" | "reset", fn: () => Promise<string>) {
    setBusy(kind);
    setMsg("");
    try {
      setMsgKind("ok");
      setMsg(await fn());
      await load();
    } catch (e) {
      setMsgKind("err");
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
      const r = await apiFetch<{ version: string; rule_count: number }>(
        "/api/suricata/rules/apply",
        { method: "POST" },
      );
      return `已生效：版本 ${r.version}，当前规则 ${r.rule_count} 条。`;
    });

  const reset = () =>
    run("reset", async () => {
      await apiFetch("/api/suricata/rules/reset", { method: "POST" });
      return "已清空规则（当前 0 条签名）。";
    });

  // 本面板挂在「检测规则」页的树节点里（节点自己已有区块标题），
  // 所以这里不再套 Section —— 用一组卡片分区，避免标题重复与卡片套卡片。
  return (
    <div className="space-y-4">
      {/* 错误条必须在最顶端：它是「这一页现在不可信」的声明，放在说明段落之后会被当成
          某个具体区块的报错（抢占它的位置也让它更早可见）。 */}
      <PanelError errors={errs} />
      <p className="text-xs text-muted-foreground">
        规则文件由开发人员维护：在线 manifest（文件列表 + sha256）更新，校验通过后人工确认才生效。
      </p>

      {(active?.rule_count ?? 0) === 0 && !loading && (
        <p className="rounded-xs border border-sev-medium-bd bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium-fg">
          <strong>当前没有加载任何签名规则</strong>
          ：签名引擎不会产生任何告警。请在下面配置规则更新地址后点
          「立即检查更新」，或在服务器把 *.rules 放进规则卷的 active/ 目录。
        </p>
      )}

      {/* 主列＝能改的（含版本切换与更新来源表单）；侧栏＝只能看的（更新记录）。 */}
      <SettingsGrid className={inline ? "xl:grid-cols-[minmax(0,1fr)_16rem]" : undefined}>
        <SettingsMain>
          <Card className={cardCls}>
            <CardHeader
              className={cn(
                "flex flex-row items-center justify-between gap-2 space-y-0",
                headCls,
              )}
            >
              <CardTitle className={inline ? "text-13" : undefined}>生效规则</CardTitle>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={alive ? "success" : "secondary"}>
                  {alive ? "引擎运行中" : "引擎未运行"}
                </Badge>
                <Badge variant={status?.source.url ? "info" : "outline"}>
                  {status?.source.url ? "在线规则" : "未配置来源"}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className={cn("space-y-3", bodyCls)}>
              {loading ? (
                <>
                  {/* 骨架用 StatSkeleton：加载完是两个带底色的 Stat 格，
                      只画两块灰会在内容到达时跳版（骨架的形状要等于内容的形状） */}
                  <StatSkeleton count={2} className="grid-cols-2" />
                  <Skeleton className="h-8 w-full" />
                </>
              ) : status ? (
                <>
                  <div className="grid grid-cols-2 gap-3">
                    <Stat
                      size="sm"
                      label="生效版本"
                      value={
                        <span className="font-mono text-sm">
                          {active?.version || "空占位（无规则）"}
                        </span>
                      }
                    />
                    <Stat size="sm" label="生效规则条数" value={`${active?.rule_count ?? 0} 条`} />
                  </div>
                  <div className="space-y-1 rounded-xs bg-surface-1 px-3 py-2 text-xs tabular-nums">
                    <p className="text-muted-foreground">
                      生效规则文件 <span className="font-mono">{fileList(active?.files)}</span>
                    </p>
                    <p className="text-muted-foreground">
                      最近检查 <span className="tabular-nums">{formatDateTime(status.last_check_at) || "—"}</span>｜
                      {resultText(status.last_check)}
                    </p>
                  </div>
                </>
              ) : (
                <EmptyState
                  size="compact"
                  tone={errs.isFailed(SRC.status) ? "danger" : "muted"}
                  title={errs.isFailed(SRC.status) ? "读取失败（见上方错误条）" : "还没有读到规则状态"}
                  action={
                    <Button size="sm" variant="outline" onClick={() => void load()}>
                      重新读取
                    </Button>
                  }
                />
              )}
            </CardContent>
          </Card>

          {pending && (
            <Card className={cardCls}>
              <CardHeader
                className={cn(
                  "flex flex-row items-center justify-between gap-2 space-y-0",
                  headCls,
                )}
              >
                <CardTitle className={inline ? "text-13" : undefined}>待确认版本</CardTitle>
                <Badge variant={pending.validated ? "medium" : "critical"}>
                  {pending.validated ? "校验通过，待确认" : "校验未通过"}
                </Badge>
              </CardHeader>
              <CardContent className={cn("space-y-3", bodyCls)}>
                <div className="space-y-1 rounded-xs bg-surface-1 px-3 py-2 text-xs">
                  <p>
                    版本 <span className="font-mono">{pending.version}</span>
                  </p>
                  <p className="font-mono text-muted-foreground">{fileList(pending.files)}</p>
                  {!pending.validated && pending.validation_error && (
                    <p className="text-sev-critical-fg">校验失败：{pending.validation_error}</p>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    size="sm"
                    disabled={!pending.validated || busy !== ""}
                    onClick={() =>
                      setConfirm({
                        title: "切换到新版本签名规则？",
                        body: (
                          <>
                            现在把签名规则切到版本 <span className="font-mono">{pending.version}</span>？
                            <br />
                            文件：{fileList(pending.files)}
                            <br />
                            生效后签名引擎立刻按新规则告警。
                          </>
                        ),
                        confirmLabel: "确认切换",
                        onConfirm: () => {
                          setConfirm(null);
                          void apply();
                        },
                      })
                    }
                  >
                    {busy === "apply" ? "切换中…" : "立即更新（需确认）"}
                  </Button>
                  <span className="text-xs text-muted-foreground">
                    规则变更属检测口径，只有点确认才会生效
                  </span>
                </div>
              </CardContent>
            </Card>
          )}

          <Card className={cardCls}>
            <CardHeader className={headCls}>
              <CardTitle className={inline ? "text-13" : undefined}>更新来源</CardTitle>
            </CardHeader>
            <CardContent className={cn("space-y-3", bodyCls)}>
              {/* 长字段（URL）整行、短字段（令牌 + 两个开关）并排：
                  两列等宽会让 URL 输入框只剩一半，manifest 地址根本放不进去。 */}
              <FieldGrid maxCols={2}>
                <Field
                  label="规则更新地址（manifest：文件列表 + sha256；可填目录，会自动补 manifest.json）"
                  htmlFor="suricata-url"
                  span="full"
                >
                  <Input
                    id="suricata-url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com/shentong-rules/manifest.json"
                  />
                </Field>
                <Field label="访问令牌（可选；留空 = 保持不变）" htmlFor="suricata-token">
                  <Input
                    id="suricata-token"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder={status?.source.token_set ? "已配置（留空不修改）" : "未配置"}
                    type="password"
                  />
                </Field>
                <div className="flex flex-col justify-end gap-2 pb-1">
                  <label className="flex items-center gap-2 text-xs">
                    <input
                      type="checkbox"
                      className="h-4 w-4"
                      checked={clearToken}
                      onChange={(e) => setClearToken(e.target.checked)}
                    />
                    清除已存令牌
                  </label>
                  <label className="flex items-center gap-2 text-xs">
                    <input
                      type="checkbox"
                      className="h-4 w-4"
                      checked={enabled}
                      onChange={(e) => setEnabled(e.target.checked)}
                    />
                    启用定时检查（每 12 小时）
                  </label>
                </div>
              </FieldGrid>

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
                <Button size="sm" onClick={save} disabled={busy !== ""}>
                  {busy === "save" ? "保存中…" : "保存配置"}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={check}
                  disabled={busy !== "" || !status?.source.url}
                >
                  {busy === "check" ? "检查中…（含下载与校验）" : "立即检查更新"}
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  disabled={busy !== ""}
                  onClick={() =>
                    setConfirm({
                      title: "清空全部签名规则？",
                      body: "清空后签名引擎不会再产生任何告警（规则可重新在线获取）。",
                      confirmLabel: "清空规则",
                      onConfirm: () => {
                        setConfirm(null);
                        void reset();
                      },
                    })
                  }
                >
                  {busy === "reset" ? "清空中…" : "清空规则"}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                检查更新会拉取 manifest、按 sha256 比对差异文件，并在引擎容器内做规则校验；
                <strong>校验通过也不会自动生效</strong>，需要你点「立即更新」确认。
              </p>
            </CardContent>
          </Card>
        </SettingsMain>

        <SettingsRail>
          <Card className={cardCls}>
            <CardHeader className={headCls}>
              <CardTitle className={inline ? "text-13" : undefined}>最近更新记录</CardTitle>
            </CardHeader>
            <CardContent className={cn(bodyCls)}>
              {/* 5 行 font-mono text-xs ≈ 76px，骨架给 80px（原来是 64px，内容到达时会跳 16px） */}
              {loading ? (
                <Skeleton className="h-20 w-full" />
              ) : (status?.history?.length ?? 0) > 0 ? (
                <ul className="space-y-1 text-xs">
                  {status?.history.slice(0, 5).map((item, idx) => (
                    <li key={`${item.at}-${idx}`} className="font-mono tabular-nums">
                      {item.at ? formatDateTime(item.at) : "—"}｜{item.scheduled ? "定时" : "手动"}｜{resultText(item)}
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState
                  size="compact"
                  tone={errs.isFailed(SRC.status) ? "danger" : "muted"}
                  title={errs.isFailed(SRC.status) ? "读取失败（见上方错误条）" : "还没有更新记录"}
                  hint="点「立即检查更新」会留下一条记录。"
                />
              )}
            </CardContent>
          </Card>
        </SettingsRail>
      </SettingsGrid>

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
    </div>
  );
}
