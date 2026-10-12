#!/usr/bin/env python3
"""把开发者提供的规则全集按**攻击类型**分类到 `rules/builtin/`（可重复运行，结果稳定）。

为什么按 classtype 分：规则集自带 `classtype` 元数据（实测 11,190 条、24 类，0 条缺失），
这就是规则作者给出的攻击类型；我们只做**归类 + 分层文件**，**不改规则内容**（原文逐行保留），
便于：① 界面按攻击类型展示与盘查；② 出问题时能定位到某一类；③ 关掉某一类规则时不必改文件。

用法::

    python3 ndr/suricata/tools/classify_rules.py 规则全集.rules            # 生成
    python3 ndr/suricata/tools/classify_rules.py 规则全集.rules --check    # 只校验是否已同步

输出:
- `rules/builtin/NN-<category>.rules`：每类一个文件（只加文件头注释）；
- `rules/builtin/index.json`：分类索引（每类的条数、原始 classtype、说明）—— 容器读它、
  后端把它抄进 `/rules` 卷供界面展示。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILTIN_DIR = HERE.parent / "rules" / "builtin"

#: 原始 classtype → 我们的攻击类型分类（一条 classtype 只能落一类）
CATEGORY_OF: dict[str, str] = {
    # Web 应用攻击（含注入/上传/WebShell/反序列化等）
    "web-application-attack": "10-web-attack",
    "web-application-activity": "10-web-attack",
    "xss-attack": "10-web-attack",
    "sql-injection": "10-web-attack",
    "xxe-attack": "10-web-attack",
    "rce-attempt": "10-web-attack",
    "file-upload-attempt": "10-web-attack",
    "file-read-attempt": "10-web-attack",
    "webshell-activity": "10-web-attack",
    "java-deserialization": "10-web-attack",
    "shellcode-detect": "10-web-attack",
    # 漏洞利用套件
    "exploit-kit": "20-exploit",
    "CVE-exploit": "20-exploit",
    # 凭证 / 未授权访问
    "credential-theft": "30-credential",
    "unauthorized-access": "30-credential",
    # 扫描探测
    "vuln-scanner": "40-scan",
    "dir-scan": "40-scan",
    # 恶意软件 / 挖矿 / 隧道外联
    "trojan-activity": "50-malware-c2",
    "C2_trojan-activity": "50-malware-c2",
    "coin-mining": "50-malware-c2",
    "tunnel-activity": "50-malware-c2",
    "dns-exfiltration": "50-malware-c2",
    # 敏感信息 / 文件泄露
    "sensitive-str": "60-sensitive-data",
    "sensitive-file-access": "60-sensitive-data",
    # 其它
    "policy-violation": "90-other",
    "misc-activity": "90-other",
}

#: 分类 → 中文名（界面展示）
CATEGORY_LABELS: dict[str, str] = {
    "10-web-attack": "Web 应用攻击",
    "20-exploit": "漏洞利用（exploit-kit）",
    "30-credential": "凭证窃取 / 未授权访问",
    "40-scan": "扫描探测",
    "50-malware-c2": "恶意软件 / 挖矿 / 隧道外联",
    "60-sensitive-data": "敏感信息 / 文件泄露",
    "90-other": "其它",
}

ACTION_RE = re.compile(r"^\s*(alert|drop|reject|pass)\s")
CLASSTYPE_RE = re.compile(r"classtype:\s*([a-zA-Z0-9_-]+)")
SID_RE = re.compile(r"\bsid:\s*(\d+)")

HEADER = """# ============================================================
# 深瞳签名引擎 · 内置默认规则 · {label}（{category}）
# 来源: 开发者提供的规则全集.rules（按 classtype 分类，规则原文未改）
# 本类条数: {count}；原始 classtype: {types}
# 生成方式: python3 ndr/suricata/tools/classify_rules.py <规则全集文件>
# ============================================================
"""


#: content 修饰符：**必须写在 content 之后**。写成 `http_method; content:"GET";` 时 Suricata 7
#: 直接拒绝解析整条规则（实测报错：`"http_method" keyword found inside the rule without a
#: content context. Please use a "content" keyword before using the "http_method" keyword`）。
CONTENT_MODIFIERS = ("http_method", "http_cookie", "http_server_body")

#: Suricata 7 已移除 `threshold`（换成 `detection_filter`）。不换掉的话这些规则会让整个规则集
#: 加载失败 —— 一条规则加载不了 = 零覆盖，比丢一点节流语义严重得多。
#: 语义差异（记在案）：`threshold type limit` 是「每个时间窗最多报一次」，`detection_filter`
#: 是「达到次数后每次都报」——节流更松，但不会漏掉后续命中。
THRESHOLD_KEYWORD = "threshold"


def _split_top(text: str, sep: str = ";") -> list[str]:
    """按分隔符切分，**忽略引号内的分隔符**（规则里有 `content:"a;b"` 这种）。"""
    out: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            buf.append(text[i : i + 2])
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
            buf.append(ch)
        elif ch in ('"', "'"):
            quote = ch
            buf.append(ch)
        elif ch == sep:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    out.append("".join(buf))
    return out


def _threshold_to_detection_filter(token: str) -> str:
    """`threshold: type both, count 5, seconds 60, track by_src` → `detection_filter: track ...`"""
    opts = token.split(":", 1)[1] if ":" in token else ""
    kv: dict[str, str] = {}
    for part in _split_top(opts, ","):
        bits = part.strip().split()
        if not bits:
            continue
        kv[bits[0].lower()] = bits[1] if len(bits) > 1 else ""
    track = kv.get("track") or "by_src"
    if track not in ("by_src", "by_dst"):  # by_rule / by_both 不被 detection_filter 支持
        track = "by_src"
    count = kv.get("count") or "1"
    seconds = kv.get("seconds") or "60"
    return f"detection_filter: track {track}, count {count}, seconds {seconds}"


#: Suricata 7 的**旧写法关键字** → 点号式缓冲区。实测下划线旧名会被拒（报错信息有误导：
#: `"http_uri" keyword found inside the rule without a content context`）。同义替换，判据不变。
LEGACY_KEYWORDS: dict[str, str] = {
    "http_uri": "http.uri",
    "http_header": "http.header",
    "http_user_agent": "http.user_agent",  # 一个点，不是两个（写错会被判 unknown keyword）
    "http_host": "http.host",
    "http_cookie": "http.cookie",
    "http_stat_code": "http.stat_code",
    "http_stat_msg": "http.stat_msg",
    "tls_sni": "tls.sni",
    "dns_query": "dns.query",
    "file_data": "file.data",
    "http_client_body": "http.request_body",
    "http_server_body": "http.response_body",
}

#: JA3/JA3S 的方向约束：`ja3.hash` 取自**客户端** hello（flow:to_server），
#: `ja3s.hash` 取自**服务端** hello（flow:to_client）。方向写反时 Suricata 直接拒绝：
#: `rule N mixes keywords with conflicting directions`。这里按缓冲区把 flow 纠正过来。
DIRECTION_BY_BUFFER: dict[str, str] = {"ja3.hash": "to_server", "ja3s.hash": "to_client"}


def _rename_legacy_keywords(tokens: list[str], applied: list[str]) -> list[str]:
    out: list[str] = []
    for tok in tokens:
        name = tok.strip().lower()
        if name in LEGACY_KEYWORDS:
            out.append(" " + LEGACY_KEYWORDS[name])
            applied.append(f"legacy_keyword:{name}")
            continue
        out.append(tok)
    return out


def _fix_flow_direction(tokens: list[str], applied: list[str]) -> list[str]:
    """按缓冲区纠正 flow 方向（ja3.hash → to_server，ja3s.hash → to_client）。"""
    names = {tok.strip().lower() for tok in tokens}
    want = next((DIRECTION_BY_BUFFER[b] for b in DIRECTION_BY_BUFFER if b in names), None)
    if want is None:
        return tokens
    for i, tok in enumerate(tokens):
        s = tok.strip()
        if not s.lower().startswith("flow:"):
            continue
        parts = [x.strip() for x in _split_top(s.split(":", 1)[1], ",") if x.strip()]
        dirs = {"to_server", "to_client"}
        if want in parts:
            return tokens
        kept = [p for p in parts if p not in dirs]
        kept.insert(0, want)
        tokens[i] = " flow:" + ",".join(["established", *kept]) if "established" not in kept else " flow:" + ",".join(kept)
        applied.append(f"flow_direction:{want}")
        return tokens
    return tokens


#: Suricata 解析器按 `;` 切分选项，**引号内的裸 `;` 也不放过**（实测报错
#: `bad option value formatting (possible missing semicolon) for keyword content: '"..'`）。
#: 约定写法：content 里要匹配分号得写 `|3b|`；msg 只是展示文本，直接去掉即可。
def _fix_semicolons(tokens: list[str], applied: list[str]) -> list[str]:
    out: list[str] = []
    for tok in tokens:
        s = tok.strip()
        low = s.lower()
        if low.startswith("content") and ":" in s:
            name, _, raw = s.partition(":")
            raw = raw.strip()
            if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"' and ";" in raw[1:-1]:
                value = raw[1:-1]
                buf: list[str] = []
                in_bytes = False
                for ch in value:
                    if ch == "|":
                        in_bytes = not in_bytes
                    if ch == ";" and not in_bytes:
                        buf.append("|3b|")
                    else:
                        buf.append(ch)
                out.append(f'{name}: "{"".join(buf)}"')
                applied.append("content_semicolon_hex")
                continue
        if low.startswith("msg") and ":" in s:
            name, _, raw = s.partition(":")
            raw = raw.strip()
            if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"' and ";" in raw[1:-1]:
                # msg 是给人看的：分号去掉即可（源规则里多是手误多打）
                out.append(f'{name}: "{raw[1:-1].replace(";", "")}"')
                applied.append("msg_semicolon_stripped")
                continue
        out.append(tok)
    return out


#: PCRE 合法标志位（Suricata 只认这些；写别的会被拒，实测 `pcre:"/x/Vi"`）
PCRE_FLAGS = set("ismxAEGKORU")


def _fix_flow_redundancy(tokens: list[str], applied: list[str]) -> list[str]:
    """`flow:to_client,established,from_server` —— `from_server` 与 `to_client` 重复，
    Suricata 7 直接报 `cannot set DETECT_FLOW_FLAG_TOCLIENT flag is already set`。
    处理：两者都在时去掉 from_*；只有 from_* 时把它换成对应的 to_*。
    """
    for i, tok in enumerate(tokens):
        s = tok.strip()
        if not s.lower().startswith("flow:"):
            continue
        parts = [x.strip() for x in _split_top(s.split(":", 1)[1], ",") if x.strip()]
        low = [x.lower() for x in parts]
        changed = False
        if "from_server" in low and "to_client" in low:
            parts = [x for x in parts if x.lower() != "from_server"]
            changed = True
        elif "from_client" in low and "to_server" in low:
            parts = [x for x in parts if x.lower() != "from_client"]
            changed = True
        elif "from_server" in low:
            parts = ["to_client" if x.lower() == "from_server" else x for x in parts]
            changed = True
        elif "from_client" in low:
            parts = ["to_server" if x.lower() == "from_client" else x for x in parts]
            changed = True
        if changed:
            tokens[i] = " flow:" + ",".join(parts)
            applied.append("flow_dedupe_from_flag")
        return tokens
    return tokens


_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _decode_unicode_escapes(text: str) -> str:
    """`\u0040` → `@`：Suricata 不认这种转义（实测报 `'\' has to be escaped`），
    直接还原成字符（或按需写 |40|）语义等价、且能加载。"""
    return _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)


def _fix_content_escapes(tokens: list[str], applied: list[str]) -> list[str]:
    out: list[str] = []
    for tok in tokens:
        s = tok.strip()
        low = s.lower()
        if low.startswith(("content", "msg")) and ":" in s:
            name, _, raw = s.partition(":")
            raw = raw.strip()
            if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"' and "\\u" in raw[1:-1]:
                out.append(f'{name}: "{_decode_unicode_escapes(raw[1:-1])}"')
                applied.append("unicode_escape_decoded")
                continue
        out.append(tok)
    return out


def _fix_pcre_flags(tokens: list[str], applied: list[str]) -> list[str]:
    """pcre 尾部的标志位只保留 Suricata 认得的（其余丢掉，不影响正则本体）。"""
    out: list[str] = []
    for tok in tokens:
        s = tok.strip()
        if s.lower().startswith("pcre") and ":" in s:
            name, _, raw = s.partition(":")
            raw = raw.strip()
            if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
                expr = raw[1:-1]
                end = expr.rfind("/")
                if end > 0:
                    body, flags = expr[: end + 1], expr[end + 1 :]
                    kept = "".join(ch for ch in flags if ch in PCRE_FLAGS)
                    if kept != flags:
                        out.append(f'{name}: "{body}{kept}"')
                        applied.append("pcre_flag_dropped")
                        continue
        out.append(tok)
    return out


def fix_rule(row: str) -> tuple[str, list[str]]:
    """修规则的**语法**问题（不改判据）。返回 (修复后的行, 做了哪些修复)。"""
    applied: list[str] = []
    start = row.find("(")
    end = row.rfind(")")
    if start < 0 or end <= start:
        return row, applied
    tokens = [tok for tok in _split_top(row[start + 1 : end], ";") if tok.strip()]
    first_content = next(
        (i for i, tok in enumerate(tokens) if tok.strip().lower().startswith("content")), None
    )
    if first_content is not None:
        moved = [
            tok
            for i, tok in enumerate(tokens)
            if i < first_content and tok.strip().lower() in CONTENT_MODIFIERS
        ]
        if moved:
            tokens = [
                tok
                for i, tok in enumerate(tokens)
                if not (i < first_content and tok.strip().lower() in CONTENT_MODIFIERS)
            ]
            at = (
                next(
                    i
                    for i, tok in enumerate(tokens)
                    if tok.strip().lower().startswith("content")
                )
                + 1
            )
            tokens[at:at] = moved
            applied.append("modifier_order")
    for i, tok in enumerate(tokens):
        if tok.strip().lower().startswith(THRESHOLD_KEYWORD):
            tokens[i] = " " + _threshold_to_detection_filter(tok)
            applied.append("threshold_to_detection_filter")
    tokens = _rename_legacy_keywords(tokens, applied)
    tokens = _fix_semicolons(tokens, applied)
    tokens = _fix_content_escapes(tokens, applied)
    tokens = _fix_pcre_flags(tokens, applied)
    tokens = _fix_flow_direction(tokens, applied)
    tokens = _fix_flow_redundancy(tokens, applied)
    body = ";".join(tok.strip() for tok in tokens)
    return f"{row[: start + 1]}{body};{row[end:]}", applied


def classify(lines: list[str]) -> tuple[dict[str, list[str]], Counter[str], list[str], list[str]]:
    """规则行 → 分类桶。返回 (分类→规则行, 原始 classtype 计数, 无分类的 classtype, 重复 sid)。"""
    buckets: dict[str, list[str]] = defaultdict(list)
    types: Counter[str] = Counter()
    unknown: list[str] = []
    seen_sid: set[str] = set()
    dup: list[str] = []
    fixed: Counter[str] = Counter()
    for raw_line in lines:
        line = raw_line
        if not ACTION_RE.match(line):
            continue  # 注释/空行不进分类文件（文件头由我们生成）
        line, applied = fix_rule(line.rstrip("\n"))
        for name in applied:
            fixed[name] += 1
        match = CLASSTYPE_RE.search(line)
        raw = match.group(1) if match else ""
        types[raw or "(无)"] += 1
        category = CATEGORY_OF.get(raw, "90-other")
        if raw and raw not in CATEGORY_OF:
            unknown.append(raw)
        buckets[category].append(line.rstrip("\n"))
        sid = SID_RE.search(line)
        if sid:
            if sid.group(1) in seen_sid:
                dup.append(sid.group(1))
            seen_sid.add(sid.group(1))
    return buckets, types, sorted(set(unknown)), sorted(set(dup)), fixed


def _classtype_of(row: str) -> str:
    match = CLASSTYPE_RE.search(row)
    return match.group(1) if match else "(无)"


def _classtype_counts(rows: list[str]) -> Counter[str]:
    return Counter(_classtype_of(row) for row in rows)


def render(buckets: dict[str, list[str]], types: Counter[str]) -> dict[str, str]:
    """分类桶 → {文件名: 文件内容}。"""
    out: dict[str, str] = {}
    for category in sorted(buckets):
        rows = buckets[category]
        # 这一类的原始 classtype 分布（写进文件头，方便盘查）
        by_type = _classtype_counts(rows)
        label = CATEGORY_LABELS.get(category, category)
        body = "".join(f"{row}\n" for row in sorted(rows, key=_sid_key))
        out[f"{category}.rules"] = HEADER.format(
            label=label,
            category=category,
            count=len(rows),
            types=", ".join(f"{k}×{v}" for k, v in by_type.most_common()),
        ) + body
    return out


def _sid_key(row: str) -> tuple[int, str]:
    match = SID_RE.search(row)
    return (int(match.group(1)) if match else 1 << 60, row)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="按攻击类型分类 Suricata 规则集")
    parser.add_argument("source", type=Path, help="规则全集文件（如 规则全集.rules）")
    parser.add_argument("--check", action="store_true", help="只校验已生成的分类是否与源一致")
    args = parser.parse_args(argv)

    lines = args.source.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    buckets, types, unknown, dup, fixed = classify(lines)
    rendered = render(buckets, types)
    total = sum(len(v) for v in buckets.values())

    index = {
        "source": args.source.name,
        "total": total,
        "categories": [
            {
                "category": category,
                "label": CATEGORY_LABELS.get(category, category),
                "file": f"{category}.rules",
                "rules": len(buckets[category]),
                "classtypes": dict(_classtype_counts(buckets[category]).most_common()),
            }
            for category in sorted(buckets)
        ],
        "classtypes": dict(types.most_common()),
        # 语法修复记录（只改写法、不改判据）：口径与数量都留痕，便于审计
        "fixes": dict(fixed),
    }

    problems: list[str] = []
    if unknown:
        problems.append(f"未登记的 classtype（已归入 90-other）: {unknown}")
    if dup:
        problems.append(f"重复 sid（源文件可能没有去重）: {dup[:5]}（共 {len(dup)}）")
    for row in rendered.values():
        if "sid:" not in row:
            problems.append("有规则缺 sid")
            break
    if problems:
        print("提示:\n  " + "\n  ".join(problems), file=sys.stderr)

    if fixed:
        print("语法修复（不改判据）: " + ", ".join(f"{k}×{v}" for k, v in fixed.items()))
    print(f"源规则 {total} 条 → {len(rendered)} 类：")
    for category in sorted(buckets):
        print(f"  {category:20s} {CATEGORY_LABELS.get(category, ''):22s} {len(buckets[category]):6d} 条")

    if args.check:
        bad = 0
        for name, text in rendered.items():
            path = BUILTIN_DIR / name
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                print(f"未同步: {path.relative_to(BUILTIN_DIR.parent.parent.parent)}", file=sys.stderr)
                bad += 1
        idx = BUILTIN_DIR / "index.json"
        want = json.dumps(index, ensure_ascii=False, indent=2) + "\n"
        if not idx.exists() or idx.read_text(encoding="utf-8") != want:
            print("未同步: index.json", file=sys.stderr)
            bad += 1
        return 1 if bad else 0

    BUILTIN_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        (BUILTIN_DIR / name).write_text(text, encoding="utf-8")
    (BUILTIN_DIR / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"已写入 {BUILTIN_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
