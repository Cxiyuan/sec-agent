"use client";

import * as React from "react";
import { Button } from "@shentong/ui";
import { Input } from "@shentong/ui";
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

export const SELECT_CLS = "h-9 rounded-md border border-input bg-transparent px-2 text-sm";

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
        onChange={(e) => onChange({ value: e.target.value })}
        className={`${SELECT_CLS} flex-1`}
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
  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted-foreground">条件组合：</span>
        <select value={logic} onChange={(e) => onLogic(e.target.value)} className={SELECT_CLS}>
          <option value="and">全部满足（AND）</option>
          <option value="or">任一满足（OR）</option>
        </select>
      </div>
      {conds.map((c, i) => (
        <div key={i} className="flex items-center gap-2">
          <select
            value={c.field}
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
            value={c.op}
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
          <Button size="sm" variant="ghost" onClick={() => onRemove(i)}>
            删
          </Button>
        </div>
      ))}
      <Button
        size="sm"
        variant="outline"
        onClick={onAdd}
      >
        加条件
      </Button>
    </div>
  );
}
