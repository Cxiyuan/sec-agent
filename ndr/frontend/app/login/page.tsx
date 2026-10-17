"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";
import { setToken } from "@/lib/api";
import { Button } from "@shentong/ui";
import { Card, CardContent } from "@shentong/ui";
import { Input } from "@shentong/ui";

/**
 * 登录页：整个产品**唯一**先于主界面出现的画面，观感直接决定第一印象。
 *
 * 之前是居中白卡片 + 40px 图标，标题沿用 CardTitle 的默认字号，表单只有
 * placeholder 没有 label（读屏读不出来、出错也说不出是哪一栏）。
 * 现在品牌区在卡片外、卡片只装表单；输入项带真 label；错误提示用语义色底。
 */
export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const form = new URLSearchParams();
      form.set("username", username);
      form.set("password", password);
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      });
      if (!res.ok) throw new Error("用户名或密码错误");
      const data = await res.json();
      setToken(data.access_token);
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 px-4">
      <div className="flex items-center gap-3">
        <span className="flex h-10 w-10 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <Shield className="h-5 w-5" />
        </span>
        <div>
          <p className="text-base font-medium leading-5 text-foreground">深瞳 · 安全分析平台</p>
          <p className="mt-0.5 text-xs text-muted-foreground">NDR 网络检测与响应 · 运营控制台</p>
        </div>
      </div>

      <Card className="w-full max-w-[380px]">
        <CardContent className="p-6">
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="username" className="block text-xs text-muted-foreground">
                用户名
              </label>
              <Input
                id="username"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div className="space-y-1.5">
              <label htmlFor="password" className="block text-xs text-muted-foreground">
                密码
              </label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            {error ? (
              <p
                role="alert"
                className="rounded-xs border border-sev-critical-bd bg-sev-critical-bg px-2 py-1.5 text-xs text-sev-critical-fg"
              >
                {error}
              </p>
            ) : null}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "登录中…" : "登录"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <p className="text-xs text-muted-foreground">内网部署 · 访问与操作均记入审计日志</p>
    </div>
  );
}
