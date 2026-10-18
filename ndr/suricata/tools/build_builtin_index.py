#!/usr/bin/env python3
"""从 `rules/builtin/*.rules` 重建 `index.json`（分类索引）。

为什么需要它（2026-10 规则换代）：内置规则集现在由**开发者直接按攻击类型分好文件**提供
（`01-…15-…rules`），不再需要 `classify_rules.py` 那套"按 classtype 自动分成 7 类"。
容器和界面读的是 `index.json`（每类条数、用到的 classtype、中文名），
所以换代后必须重新生成它，不然索引和文件会不一致。

用法（仓库根执行）：
    python3 ndr/suricata/tools/build_builtin_index.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
BUILTIN = REPO / "ndr" / "suricata" / "rules" / "builtin"

ACTION_RE = re.compile(r"^\s*(alert|drop|reject|pass)\s")
CLASSTYPE_RE = re.compile(r"classtype:\s*([a-zA-Z0-9_-]+)")

#: 文件名（去掉序号与后缀）→ 界面上的中文分类名。改名只改这里，索引会跟着变。
LABELS: dict[str, str] = {
    "recon-tools": "侦察与攻击工具指纹",
    "port-scan": "端口与主机扫描",
    "web-exploit": "Web 漏洞利用",
    "webshell": "WebShell 后门通信",
    "framework-probe": "框架与中间件探测",
    "credential": "凭据攻击",
    "lateral": "横向移动",
    "tunnel-proxy": "隧道与代理",
    "dns-tunnel": "DNS 隧道与带外探测",
    "c2-beacon": "命令与控制信标",
    "malware-delivery": "恶意文件投递",
    "attack-chain": "攻击链关联检测",
    "non-http": "非 HTTP 协议攻击",
    "http-header-chain": "HTTP 头载荷与利用链",
    "non-http-scan": "非 HTTP 通道与扫描器痕迹",
}


def main() -> int:
    files = sorted(BUILTIN.glob("*.rules"))
    if not files:
        print(f"✘ {BUILTIN} 里没有 .rules 文件")
        return 1
    categories = []
    total = 0
    for path in files:
        category = path.stem
        # 去掉 `01-` 这类序号，作为中文名查表的键
        key = re.sub(r"^\d+[-_]", "", category)
        rules = 0
        classtypes: dict[str, int] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            if not ACTION_RE.match(line):
                continue
            rules += 1
            found = CLASSTYPE_RE.search(line)
            if found:
                classtypes[found.group(1)] = classtypes.get(found.group(1), 0) + 1
        total += rules
        categories.append(
            {
                "category": category,
                "label": LABELS.get(key, key),
                "file": path.name,
                "rules": rules,
                "classtypes": dict(sorted(classtypes.items(), key=lambda kv: -kv[1])),
            }
        )
    index = {
        "source": "开发者按攻击类型分好文件的规则包（2026-10）",
        "total": total,
        "categories": categories,
    }
    (BUILTIN / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"✔ 已重建 index.json：{len(categories)} 类 / {total} 条")
    for cat in categories:
        print(f"  {cat['file']:<34} {cat['rules']:>4} 条  {cat['label']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
