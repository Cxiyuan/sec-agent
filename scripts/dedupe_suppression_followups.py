#!/usr/bin/env python3
"""把同一抑制的重复 structure 待办折叠成一条（默认 dry-run）。

旧 `enqueue_suppression_followup` 的 dedupe_key 带小时桶，同一抑制每小时
生成一条新任务；这里按 suppression_name（或 dedupe_key 里的名字）分组，
保留最新一条，其余标 expired，保留历史行不删除。
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "ndr" / "backend", ROOT, Path("/app")):
    if (candidate / "app").is_dir():
        sys.path.insert(0, str(candidate))
        break

from app.db.base import SessionLocal
from app.db.models import AnalysisTask
from sqlalchemy import select


def name_of(task: AnalysisTask) -> str:
    hint = dict(task.hint or {})
    name = str(hint.get("suppression_name") or "").strip()
    if name:
        return name
    parts = str(task.dedupe_key or "").split("|")
    if len(parts) >= 2 and parts[1].startswith("suppression:"):
        return parts[1][len("suppression:"):]
    return ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(AnalysisTask)
                .where(
                    AnalysisTask.kind == "structure",
                    AnalysisTask.state.in_(("pending", "deferred", "claimed")),
                )
                .order_by(AnalysisTask.created_at.asc())
            ).all()
        )
        groups: dict[str, list[AnalysisTask]] = defaultdict(list)
        for row in rows:
            name = name_of(row)
            if name:
                groups[name].append(row)
        duplicates = []
        for name, items in groups.items():
            if len(items) <= 1:
                continue
            # 保留最新一条（通常包含最新降级原因），较早的折叠掉。
            keep = items[-1]
            duplicates.extend(item for item in items if item is not keep)
        print(json.dumps({
            "active_structure": len(rows),
            "groups": len(groups),
            "duplicates": len(duplicates),
            "apply": bool(args.apply),
        }, ensure_ascii=False))
        if args.apply and duplicates:
            now = datetime.now(UTC)
            for row in duplicates:
                row.state = "expired"
                row.lease_until = None
                row.note = "重复的抑制收窄待办，已折叠（保留同名最新一条）"
                row.updated_at = now
            db.commit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
