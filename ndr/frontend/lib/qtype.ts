"use client";

/**
 * DNS 查询类型：显示名 ↔ 存库值（QA 应修 5）。
 *
 * 背景：Zeek `dns.log` 的 `qtype` 是数字码，归一化优先取它，于是 ES 里存的是
 * `"1"`/`"28"`/`"16"` 而不是 `"A"`/`"AAAA"`/`"TXT"`。用户在过滤条件里手输 `qtype=A`
 * 永远匹配不到（实机聚合值就是 1/28/16/32）。
 *
 * 处理办法：全前端只维护这一份映射表，写入条件的值由 `QTYPE_VALUE_STYLE` 决定：
 * - 后端目前仍存数字码 → `"code"`（当前值）；
 * - A 组把归一化改成存 `qtype_name`（或补充人类可读名）后，把这一个常量改成 `"name"`
 *   即可，别处不用动。
 *
 * ⚠️ 假设（已写进 G 组报告）：A 组交付前按「数字码」写入。若 A 组最终两种都存
 * （新增字段），把 `qtypeOptions()` 的取值字段换掉即可，映射表本身不变。
 */
export const QTYPE_VALUE_STYLE: "code" | "name" = "code";

export interface QtypeEntry {
  /** DNS 报文里的查询类型数字码（Zeek dns.log 的 qtype） */
  code: string;
  /** 人读名（Zeek dns.log 的 qtype_name） */
  name: string;
}

/** 常见查询类型（IANA DNS parameters；按常用度排序，够过滤用，不是全集）。 */
export const QTYPE_TABLE: QtypeEntry[] = [
  { code: "1", name: "A" },
  { code: "28", name: "AAAA" },
  { code: "5", name: "CNAME" },
  { code: "16", name: "TXT" },
  { code: "15", name: "MX" },
  { code: "12", name: "PTR" },
  { code: "2", name: "NS" },
  { code: "6", name: "SOA" },
  { code: "33", name: "SRV" },
  { code: "41", name: "OPT" },
  { code: "43", name: "DS" },
  { code: "46", name: "RRSIG" },
  { code: "48", name: "DNSKEY" },
  { code: "65", name: "HTTPS" },
  { code: "64", name: "SVCB" },
  { code: "255", name: "ANY" },
];

/** 下拉选项：`value` 是真正写进条件的值，`label` 给人看（名字 + 码）。 */
export function qtypeOptions(
  style: "code" | "name" = QTYPE_VALUE_STYLE,
): { value: string; label: string }[] {
  return QTYPE_TABLE.map((e) => ({
    value: style === "name" ? e.name : e.code,
    label: `${e.name}（${e.code}）`,
  }));
}

/** 把库里/条件里的 qtype 值翻成人读文案（不认识的码原样返回）。 */
export function qtypeLabel(value: string): string {
  const v = value.trim();
  if (!v) return "—";
  const hit = QTYPE_TABLE.find(
    (e) => e.code === v || e.name.toLowerCase() === v.toLowerCase(),
  );
  return hit ? `${hit.name}（${hit.code}）` : v;
}

/** 非下拉场景（in / contains / regex）的输入提示。 */
export const QTYPE_HINT =
  "数字码或名字：A=1、AAAA=28、TXT=16、CNAME=5…（多个用逗号分隔）";

/**
 * 条件摘要用：qtype 字段的值翻成人读（`16` → `TXT（16）`），其它字段原样返回。
 * 多个值（in 场景写的 `16,TXT`）逐个翻，翻不出来的原样留着。
 */
export function condValueLabel(field: unknown, value: unknown): string {
  const text = Array.isArray(value) ? value.join(",") : String(value ?? "");
  if (String(field) !== "qtype" || !text) return text;
  return text
    .split(",")
    .map((s) => {
      const t = s.trim();
      return t ? qtypeLabel(t) : t;
    })
    .join("、");
}
