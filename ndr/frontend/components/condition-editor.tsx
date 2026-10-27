"use client";

import * as React from "react";
import { Button, EmptyState, Input, cn } from "@shentong/ui";
import type { RuleCondition, RuleConditions } from "@/lib/api";
import { QTYPE_HINT, qtypeOptions } from "@/lib/qtype";

/** 默认字段清单（规则页用；排除过滤页用后端 /api/exclusions/fields 返回的完整清单）。 */
export const RULE_FIELDS = [
  "event_type",
  "log_type",
  "source_system",
  "src_ip",
  "dst_ip",
  "src_port",
  "dst_port",
  "protocol",
  "hostname",
  "user",
  "process",
  "command",
  "query",
  "qtype",
  "user_agent",
  "status_code",
  "bytes_out",
  "rule_id",
  "rule_groups",
  "mitre",
  "severity",
  "summary",
];

export const OPS = ["eq", "ne", "in", "contains", "regex", "gt", "gte", "lt", "lte", "exists"];

/** 与 `Input` 同一套边框/底色/聚焦态：下拉框和输入框混排时不能是两种材质。 */
export const SELECT_CLS =
  "h-9 w-full rounded-sm border border-input bg-surface-2 px-2 text-13 transition-colors focus-visible:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-50";

/** 条件行的列宽：字段 / 操作符 / 值 / 删除。窄屏（<sm）叠成单列，不挤成一团。 */
const ROW_GRID =
  "grid gap-2 sm:grid-cols-[minmax(0,1fr)_6.5rem_minmax(0,1.6fr)_4rem] sm:items-end";

export interface Cond {
  field: string;
  op: string;
  value: string;
}

export const EMPTY_COND: Cond = { field: "event_type", op: "eq", value: "" };

/** 界面条件 → 后端 conditions.rules（in 拆数组、数值操作符转数字、exists 不带 value）。 */
export function condsToRules(conds: Cond[]): RuleCondition[] {
  return conds
    .filter((c) => c.field && c.op)
    .map((c) => {
      if (c.op === "exists") return { field: c.field, op: c.op };
      if (c.op === "in") {
        return {
          field: c.field,
          op: c.op,
          value: c.value
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
            .map((s) => (/^-?\d+$/.test(s) ? Number(s) : s)),
        };
      }
      if (["gt", "gte", "lt", "lte"].includes(c.op)) {
        return { field: c.field, op: c.op, value: Number(c.value) };
      }
      return { field: c.field, op: c.op, value: c.value };
    });
}

/**
 * 后端 conditions → 界面条件。
 * nested=true 表示含嵌套条件组（界面只支持顶层扁平条件，调用方需据此给提示）。
 */
export function conditionsToConds(conditions: RuleConditions | undefined): {
  logic: string;
  conds: Cond[];
  nested: boolean;
} {
  const logic = String(conditions?.logic || "and");
  const raw = conditions?.rules || [];
  let nested = false;
  const conds: Cond[] = [];
  for (const r of raw) {
    if (r.logic || r.rules) {
      nested = true;
      continue;
    }
    const value = Array.isArray(r.value) ? r.value.join(",") : (r.value ?? "");
    conds.push({
      field: String(r.field || "event_type"),
      op: String(r.op || "eq"),
      value: r.op === "exists" ? "" : String(value),
    });
  }
  return { logic, conds: conds.length ? conds : [EMPTY_COND], nested };
}

/**
 * 条件值输入框（qtype 特殊处理）。
 *
 * 为什么只对 qtype 特殊：ES 里 qtype 落库的是 Zeek 给的**数字码**（1/28/16…），
 * 手敲数字既难记又容易敲错，写名字（A/TXT）当条件又匹配不到。所以 eq/ne 直接给下拉，
 * 值仍然是数字码（映射表在 lib/qtype.ts，真要改成存名字只改那一处）。
 * 其它操作符（in/regex 等）保持文本框，用 QTYPE_HINT 提示。
 */
function QtypeAwareValue({
  cond,
  onChange,
}: {
  cond: Cond;
  onChange: (patch: Partial<Cond>) => void;
}) {
  const options = React.useMemo(() => qtypeOptions(), []);
  if (cond.field === "qtype" && (cond.op === "eq" || cond.op === "ne")) {
    const known = options.some((o) => o.value === cond.value);
    return (
      <select
        value={cond.value}
        aria-label="条件值"
        onChange={(e) => onChange({ value: e.target.value })}
        className={SELECT_CLS}
      >
        <option value="">（选一个类型）</option>
        {/* 老规则里可能有映射表外的值（比如 13），不能因为改前端就把已有条件弄丢 */}
        {!known && cond.value !== "" && (
          <option value={cond.value}>{cond.value}（当前值，不在映射表里）</option>
        )}
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    );
  }
  return (
    <Input
      value={cond.value}
      aria-label="条件值"
      disabled={cond.op === "exists"}
      onChange={(e) => onChange({ value: e.target.value })}
      placeholder={
        cond.field === "qtype"
          ? QTYPE_HINT
          : cond.op === "in"
            ? "逗号分隔，如 4444,5555"
            : cond.op === "regex"
              ? "(?i)(sqlmap|nikto)"
              : "值"
      }
    />
  );
}

export function ConditionEditor({
  fields,
  conds,
  logic,
  onLogic,
  onChange,
  onRemove,
  onAdd,
}: {
  fields: string[];
  conds: Cond[];
  logic: string;
  onLogic: (v: string) => void;
  onChange: (i: number, patch: Partial<Cond>) => void;
  onRemove: (i: number) => void;
  onAdd: () => void;
}) {
  const logicId = React.useId();
  const baseId = React.useId();

  return (
    <div className="space-y-3 rounded-xs bg-surface-1 px-3 py-2">
      <div>
        <label htmlFor={logicId} className="mb-1 block text-xs text-muted-foreground">
          条件组合
        </label>
        <select
          id={logicId}
          value={logic}
          onChange={(e) => onLogic(e.target.value)}
          className={cn(SELECT_CLS, "sm:w-64")}
        >
          <option value="and">全部满足（AND）</option>
          <option value="or">任一满足（OR）</option>
        </select>
      </div>

      {conds.length === 0 ? (
        <EmptyState
          size="compact"
          title="还没有条件"
          hint="至少要有一条条件；空条件会挡下所有事件。"
          action={
            <Button type="button" size="sm" variant="outline" onClick={onAdd}>
              加条件
            </Button>
          }
        />
      ) : (
        <>
          {/* 列标题只在大屏出现：>sm 时一行三列横排，扫读靠表头定位；窄屏叠成单列，靠 aria-label */}
          <div className={cn(ROW_GRID, "hidden sm:grid")} aria-hidden="true">
            <span className="text-xs text-muted-foreground">字段</span>
            <span className="text-xs text-muted-foreground">操作符</span>
            <span className="text-xs text-muted-foreground">值</span>
            <span />
          </div>
          {conds.map((c, i) => (
            <div key={i} className={ROW_GRID}>
              <select
                id={`${baseId}-field-${i}`}
                value={c.field}
                aria-label={`第 ${i + 1} 个条件的字段`}
                onChange={(e) => onChange(i, { field: e.target.value })}
                className={SELECT_CLS}
              >
                {fields.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </select>
              <select
                id={`${baseId}-op-${i}`}
                value={c.op}
                aria-label={`第 ${i + 1} 个条件的操作符`}
                onChange={(e) => onChange(i, { op: e.target.value })}
                className={SELECT_CLS}
              >
                {OPS.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
              <QtypeAwareValue cond={c} onChange={(patch) => onChange(i, patch)} />
              <Button
                type="button"
                size="sm"
                variant="ghost"
                className="justify-self-start"
                aria-label={`删除第 ${i + 1} 个条件`}
                onClick={() => onRemove(i)}
              >
                删
              </Button>
            </div>
          ))}
          <Button type="button" size="sm" variant="outline" onClick={onAdd}>
            加条件
          </Button>
        </>
      )}
    </div>
  );
}
