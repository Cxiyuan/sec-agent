"use client";

/**
 * 节点别名的**全局展示层**：凡是要显示一个 IP 的地方，都先问这里有没有别名。
 *
 * 为什么做成模块级小 store 而不是 React Context：页面各自渲染 Nav/TopBar（没有共享的
 * admin layout），套 Provider 得改一堆页面；而且别名是「读多写少、跨页共用」的纯展示数据，
 * 模块级缓存 + useSyncExternalStore 最省事：任何组件调 `displayName(ip)` 就能拿到别名，
 * 保存别名后 `applyAliases()` 立刻全局生效。
 *
 * **fail-open**：读失败就按「没有别名」处理（显示 IP），绝不让别名把页面拖挂。
 */

import * as React from "react";
import { apiFetch } from "@shentong/ui";

import type { TopologyAliasesPayload } from "./api";

let aliases: Record<string, string> = {};
let loaded = false;
let inFlight: Promise<void> | null = null;
const listeners = new Set<() => void>();

function emit(): void {
  for (const fn of listeners) fn();
}

function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** 当前别名表（引用稳定，变了才换对象） */
function snapshot(): Record<string, string> {
  return aliases;
}

/** 这个 IP 的别名；没起过名字返回空串 */
export function aliasOf(ip: string | null | undefined): string {
  const key = String(ip ?? "").trim();
  return key ? aliases[key] || "" : "";
}

/** 展示名：有别名用别名，否则原样返回 IP（永远不返回空） */
export function displayName(ip: string | null | undefined): string {
  const key = String(ip ?? "").trim();
  return (key && aliases[key]) || key;
}

/** 直接写入缓存（保存别名后调用，立即全局生效） */
export function applyAliases(next: Record<string, string> | null | undefined): void {
  aliases = { ...(next || {}) };
  loaded = true;
  emit();
}

/** 拉一次别名表（已加载过就不重复拉；force=true 强制刷新） */
export async function loadAliases(force = false): Promise<void> {
  if (loaded && !force) return;
  if (inFlight) return inFlight;
  inFlight = apiFetch<TopologyAliasesPayload>("/api/topology/aliases")
    .then((d) => {
      applyAliases(d?.aliases);
    })
    .catch(() => {
      // fail-open：读不到就当没有别名
    })
    .finally(() => {
      inFlight = null;
    });
  return inFlight;
}

/** React 侧：拿到别名表并跟随更新（组件会随别名变化重渲染） */
export function useAliases(): {
  aliases: Record<string, string>;
  aliasOf: typeof aliasOf;
  displayName: typeof displayName;
} {
  const snap = React.useSyncExternalStore(subscribe, snapshot, snapshot);
  // 顺手拉一次（全局只拉一次）：任何展示别名的组件挂载后都会自动补上别名
  React.useEffect(() => {
    void loadAliases();
  }, []);
  return React.useMemo(() => ({ aliases: snap, aliasOf, displayName }), [snap]);
}
