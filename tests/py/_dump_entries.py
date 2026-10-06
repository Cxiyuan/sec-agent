"""把某个栈对所有样本的归一化结果 dump 成 JSON（供 ``test_stack_consistency.py`` 用）。

用法::

    python tests/py/_dump_entries.py <仓库根> <ndr|agent>

为什么用子进程：两侧的包都叫 ``app``，同一个进程里 import 不了两遍。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
SIDE = sys.argv[2]
assert SIDE in ("ndr", "agent"), SIDE

sys.path.insert(0, str(ROOT / SIDE / "backend"))

import samples
from app.ingestion.normalizer import normalize

out: dict[str, dict[str, object]] = {}
for name, doc in samples.DOCS.items():
    payload = json.loads(json.dumps(doc))
    entry = normalize(samples.doc_source(payload), payload)
    if entry is None:
        out[name] = {"fields": [], "values": None}
        continue
    out[name] = {
        "fields": sorted(type(entry).model_fields),
        "values": entry.model_dump(mode="json"),
    }

json.dump(out, sys.stdout, sort_keys=True, ensure_ascii=False)
