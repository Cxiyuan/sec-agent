"use client";

import * as React from "react";
import {
  ApiError,
  apiFetch,
  errorText,
  type AuthMe,
  type ChangePasswordResult,
} from "@/lib/api";
import { Badge } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import { loadInto, PanelError, usePanelErrors } from "@/components/panel-error";

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
  const errs = usePanelErrors();

  async function load() {
    await loadInto(errs, SRC.me, "/api/auth/me", setMe);
  }

  React.useEffect(() => {
    void load();
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
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">账号与口令</CardTitle>
        <p className="text-xs text-muted-foreground">
          系统只有一个管理员账号；出厂口令是 <span className="font-mono">admin123</span>，
          只要没改过，这里和启动日志都会一直提醒。
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        <PanelError errors={errs} />

        {me && (
          <div className="flex flex-wrap items-center gap-2 rounded-xs bg-surface-1 px-3 py-2 text-xs">
            <span className="font-medium">{me.username}</span>
            <Badge variant="outline">{me.role || "admin"}</Badge>
            {me.default_password_in_use ? (
              <Badge variant="high">仍在使用出厂口令</Badge>
            ) : (
              <Badge variant="low">口令已修改</Badge>
            )}
          </div>
        )}

        {me?.default_password_in_use && (
          <p className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            仍在使用出厂口令 admin123，请立即修改 —— 只要知道部署地址就能登录，
            日志、配置、推送令牌都归它管。
          </p>
        )}

        {!me && errs.has && (
          <p className="text-xs text-muted-foreground">
            当前账号没读到，下面照样可以改密（改密本身会校验原口令）。
          </p>
        )}

        <form onSubmit={submit} className="space-y-3 rounded-xs bg-surface-1 px-3 py-2">
          <div className="grid gap-3 md:grid-cols-3">
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">原密码</label>
              <Input
                type="password"
                autoComplete="current-password"
                value={oldPwd}
                onChange={(e) => setOldPwd(e.target.value)}
                placeholder="当前口令"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                新密码（至少 {min} 个字符）
              </label>
              <Input
                type="password"
                autoComplete="new-password"
                value={newPwd}
                onChange={(e) => setNewPwd(e.target.value)}
                placeholder={`至少 ${min} 位，别再用 admin123`}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">再输一遍新密码</label>
              <Input
                type="password"
                autoComplete="new-password"
                value={confirmPwd}
                onChange={(e) => setConfirmPwd(e.target.value)}
                placeholder="两次要一致"
              />
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" disabled={busy || !oldPwd || !newPwd}>
              {busy ? "提交中…" : "修改口令"}
            </Button>
            {msg && <span className="text-xs text-primary">{msg}</span>}
            {err && <span className="text-xs text-destructive">{err}</span>}
          </div>
          {note && <p className="text-xs text-muted-foreground">{note}</p>}
          <p className="text-xs text-muted-foreground">
            改完这一次就要用新口令登录；当前浏览器里已签发的令牌仍然有效到它自己过期
            （无状态 JWT，服务端不做吊销），要立刻全部失效需要更换 ST_JWT_SECRET 并重启后端。
          </p>
        </form>
      </CardContent>
    </Card>
  );
}
