"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type AuthMe,
  type ChangePasswordResult,
} from "@/lib/api";
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
} from "@shentong/ui";
import { emptyOrFailed, loadInto, PanelError, usePanelErrors } from "@/components/panel-error";

/** 读取失败的接口名（错误条用） */
const SRC = { me: "当前账号（/api/auth/me）" } as const;

/** 出厂默认口令：与后端 `ndr/backend/app/config.py` 的 FACTORY_ADMIN_PASSWORD 一致。
 *  在这里写死一份是为了「改成 admin123 也等于没改」能立刻提示，不用等后端 400。 */
const FACTORY_PASSWORD = "admin123";

/**
 * 账号与口令：显示当前账号，并在仍使用出厂口令时红字警告 + 提供改密表单。
 *
 * 之前出厂口令 admin123 只能靠启动日志提醒，界面上一声不吭 —— 部署到现网后没人会注意。
 */
export function AccountPanel() {
  const [me, setMe] = React.useState<AuthMe | null>(null);
  const [oldPwd, setOldPwd] = React.useState("");
  const [newPwd, setNewPwd] = React.useState("");
  const [confirmPwd, setConfirmPwd] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [note, setNote] = React.useState("");
  const [err, setErr] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  /** 首次读取：先画骨架，别把「正在读」显示成「没读到」 */
  const [loading, setLoading] = React.useState(true);
  const errs = usePanelErrors();

  async function load() {
    await loadInto(errs, SRC.me, "/api/auth/me", setMe);
  }

  React.useEffect(() => {
    void (async () => {
      await load();
      setLoading(false);
    })();
    // 只在挂载时读一次；load 自己收错误，不写 `.catch(() => {})`
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const min = me?.password_min_chars ?? 8;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setMsg("");
    setNote("");
    setErr("");
    // 前端先拦一遍最常见的三种错，省一次往返（后端仍然会再校验一遍）
    if (newPwd.length < min) {
      setErr(`新密码至少 ${min} 个字符`);
      return;
    }
    if (newPwd !== confirmPwd) {
      setErr("两次输入的新密码不一致");
      return;
    }
    if (newPwd === oldPwd) {
      setErr("新密码不能与原密码相同");
      return;
    }
    if (newPwd === FACTORY_PASSWORD) {
      setErr("新密码不能是出厂默认口令（admin123）");
      return;
    }
    setBusy(true);
    try {
      const r = await apiFetch<ChangePasswordResult>("/api/auth/change-password", {
        method: "POST",
        body: JSON.stringify({ old_password: oldPwd, new_password: newPwd }),
      });
      setOldPwd("");
      setNewPwd("");
      setConfirmPwd("");
      setMsg("已修改");
      setNote(r.note || "");
      // 重新读 /me：默认口令警告应当随之消失
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? errorText(e.body) : "修改失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <PanelError errors={errs} />
      <Section
        title="账号与口令"
        description={
          <>
            系统只有一个管理员账号；出厂口令是 <span className="font-mono">admin123</span>
            ，只要没改过，这里和启动日志都会一直提醒。
          </>
        }
      >
        {loading ? (
          <Card>
            <CardContent className="space-y-2 pt-4">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="h-6 w-48" />
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-2/3" />
            </CardContent>
          </Card>
        ) : (
          <>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
                <CardTitle>当前账号</CardTitle>
                {me ? (
                  <Badge variant={me.default_password_in_use ? "high" : "low"}>
                    {me.default_password_in_use ? "仍在使用出厂口令" : "口令已修改"}
                  </Badge>
                ) : null}
              </CardHeader>
              <CardContent className="space-y-2">
                {me ? (
                  <div className="flex flex-wrap items-center gap-2 rounded-xs bg-surface-1 px-3 py-2 text-xs">
                    <span className="font-medium text-foreground">{me.username}</span>
                    <Badge variant="outline">{me.role || "admin"}</Badge>
                  </div>
                ) : (
                  <EmptyState
                    size="compact"
                    tone={errs.isFailed(SRC.me) ? "danger" : "muted"}
                    title={emptyOrFailed(errs, SRC.me, "还没有读到账号信息")}
                    hint="下面照样可以改密（改密本身会校验原口令）。"
                  />
                )}
                {me?.default_password_in_use && (
                  <p
                    role="alert"
                    className="rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg"
                  >
                    仍在使用出厂口令 admin123，请立即修改 —— 只要知道部署地址就能登录，
                    日志、配置、推送令牌都归它管。
                  </p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>修改口令</CardTitle>
              </CardHeader>
              <CardContent>
                <form onSubmit={submit} className="space-y-3">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <label
                        htmlFor="account-old-pwd"
                        className="mb-1 block text-xs text-muted-foreground"
                      >
                        原密码 <span aria-hidden="true">*</span>
                      </label>
                      <Input
                        id="account-old-pwd"
                        type="password"
                        autoComplete="current-password"
                        aria-required="true"
                        value={oldPwd}
                        onChange={(e) => setOldPwd(e.target.value)}
                        placeholder="当前口令"
                      />
                    </div>
                    <div>
                      <label
                        htmlFor="account-new-pwd"
                        className="mb-1 block text-xs text-muted-foreground"
                      >
                        新密码（至少 {min} 个字符） <span aria-hidden="true">*</span>
                      </label>
                      <Input
                        id="account-new-pwd"
                        type="password"
                        autoComplete="new-password"
                        aria-required="true"
                        value={newPwd}
                        onChange={(e) => setNewPwd(e.target.value)}
                        placeholder={`至少 ${min} 位，别再用 admin123`}
                      />
                    </div>
                    <div>
                      <label
                        htmlFor="account-confirm-pwd"
                        className="mb-1 block text-xs text-muted-foreground"
                      >
                        再输一遍新密码 <span aria-hidden="true">*</span>
                      </label>
                      <Input
                        id="account-confirm-pwd"
                        type="password"
                        autoComplete="new-password"
                        aria-required="true"
                        value={confirmPwd}
                        onChange={(e) => setConfirmPwd(e.target.value)}
                        placeholder="两次要一致"
                      />
                    </div>
                  </div>

                  {/* 结果提示固定在操作区上方：成功/失败都用一行提示条，不再是一串彩色小字 */}
                  {msg && (
                    <p
                      role="status"
                      className="rounded-xs border border-sev-ok-bd bg-sev-ok-bg px-3 py-2 text-xs text-sev-ok-fg"
                    >
                      {msg}
                    </p>
                  )}
                  {err && (
                    <p
                      role="alert"
                      className="rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-3 py-2 text-xs text-sev-critical-fg"
                    >
                      {err}
                    </p>
                  )}

                  <div className="flex flex-wrap items-center gap-2">
                    <Button type="submit" size="sm" disabled={busy || !oldPwd || !newPwd}>
                      {busy ? "提交中…" : "修改口令"}
                    </Button>
                  </div>
                  {note && <p className="text-xs text-muted-foreground">{note}</p>}
                  <p className="text-xs text-muted-foreground">
                    改完这一次就要用新口令登录；当前浏览器里已签发的令牌仍然有效到它自己过期
                    （无状态 JWT，服务端不做吊销），要立刻全部失效需要更换 ST_JWT_SECRET 并重启后端。
                  </p>
                </form>
              </CardContent>
            </Card>
          </>
        )}
      </Section>
    </div>
  );
}
