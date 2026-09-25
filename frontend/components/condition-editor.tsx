"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { RuleCondition, RuleConditions } from "@/lib/api";

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
          <Input
            value={c.value}
            disabled={c.op === "exists"}
            onChange={(e) => onChange(i, { value: e.target.value })}
            placeholder={
              c.op === "in"
                ? "逗号分隔，如 4444,5555"
                : c.op === "regex"
                  ? "(?i)(sqlmap|nikto)"
                  : "值"
            }
          />
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
