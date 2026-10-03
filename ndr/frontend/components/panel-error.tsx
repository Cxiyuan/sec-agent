"use client";

import * as React from "react";
import { apiFetch } from "@/lib/api";

/**
 * 面板级「读取失败」收集器（QA 应修 1 的统一实现）。
 *
 * 之前每个面板都写 `load().catch(() => {})` / `.catch(() => setXxx([]))`：后端 500 或网络
 * 不通时界面进空态，显示成「还没有令牌 / 最近没有调用 / 暂无匹配索引」——把故障说成了
 * 「什么都没有」。这里把失败按接口攒起来，渲染成一条错误条，并让空态能判断「是真的没有，
 * 还是没读到」。
 *
 * 用法：
 * ```tsx
 * const errs = usePanelErrors();
 * const SRC = { main: "主状态（/api/x）", list: "列表（/api/x/list）" };
 * async function load() {
 *   errs.reset();
 *   await loadInto(errs, SRC.main, "/api/x", setData);
 *   await loadInto(errs, SRC.list, "/api/x/list", (d) => setItems(d.items));
 * }
 * ...
 * <PanelError errors={errs} />
 * // 空态不要说谎：
 * {items.length === 0 &&
 *   (errs.isFailed(SRC.list) ? "列表读取失败（见上方错误条）" : "还没有数据")}
 * ```
 */
export interface PanelErrors {
  /** 失败接口的人话名（含路径），用于错误条与空态判断 */
  failed: string[];
  has: boolean;
  /** 错误条文案；无失败时为空串 */
  message: string;
  /** 本轮加载开始：清空上一轮结果 */
  reset: () => void;
  /** 一个接口重新读成功了：把它的失败记录划掉（错误条自己会消失） */
  clear: (label: string) => void;
  /** 记录一个接口读取失败 */
  fail: (label: string) => void;
  /** 该接口本轮是否读取失败（空态据此改用「读取失败」文案） */
  isFailed: (label: string) => boolean;
}

export function usePanelErrors(): PanelErrors {
  const [failed, setFailed] = React.useState<string[]>([]);

  const reset = React.useCallback(() => setFailed([]), []);
  const clear = React.useCallback((label: string) => {
    setFailed((prev) => (prev.includes(label) ? prev.filter((l) => l !== label) : prev));
  }, []);
  const fail = React.useCallback((label: string) => {
    setFailed((prev) => (prev.includes(label) ? prev : [...prev, label]));
  }, []);
  const isFailed = React.useCallback((label: string) => failed.includes(label), [failed]);

  return React.useMemo(
    () => ({
      failed,
      has: failed.length > 0,
      message: failed.length ? `以下接口读取失败：${failed.join("、")}` : "",
      reset,
      clear,
      fail,
      isFailed,
    }),
    [failed, reset, clear, fail, isFailed],
  );
}

/**
 * 取一次接口；失败只记一笔、不抛（调用方不用再写 catch），成功则把该接口的旧失败记录划掉。
 * 返回是否成功。
 */
export async function loadInto<T>(
  errors: PanelErrors,
  label: string,
  url: string,
  apply: (data: T) => void,
  init?: RequestInit,
): Promise<boolean> {
  try {
    apply(await apiFetch<T>(url, init));
    errors.clear(label);
    return true;
  } catch {
    errors.fail(label);
    return false;
  }
}

/** 统一的失败提示条：列出挂掉的接口，并说清「现在看到的可能不是最新状态」。 */
export function PanelError({ errors }: { errors: PanelErrors }) {
  if (!errors.has) return null;
  return (
    <p className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
      {errors.message} —— 页面显示的可能不是最新状态（后端异常或网络不通，不是「没有数据」）。
    </p>
  );
}

/** 单个区块的空态替换文案：接口失败时不要显示「暂无…」。 */
export function emptyOrFailed(errors: PanelErrors, label: string, empty: string): string {
  return errors.isFailed(label) ? "读取失败（见上方错误条）" : empty;
}
