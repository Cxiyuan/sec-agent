"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { getToken } from "@shentong/ui";

/**
 * 站点入口 = **登录闸门**（2026-10 用户反馈修复）。
 *
 * 原来 `/` 由 `next.config` 直接 307 到 `/admin/status`：于是打开站点先渲染**主页**，
 * 主页再去请求接口、拿到 401 才跳登录 —— 用户看到的就是「先闪一下主页、2~3 秒后自动到登录页」。
 *
 * 现在首屏只渲染这句「正在校验登录…」：登录令牌在（前端持有，服务端看不到），直接去总览；
 * 不在就去登录页。整个过程发生在首帧之后，**不会再闪主页**。
 */
export default function RootGate() {
  const router = useRouter();
  React.useEffect(() => {
    router.replace(getToken() ? "/admin/status" : "/login");
  }, [router]);
  return (
    <div className="flex h-screen items-center justify-center">
      <p className="text-sm text-muted-foreground">正在校验登录…</p>
    </div>
  );
}
