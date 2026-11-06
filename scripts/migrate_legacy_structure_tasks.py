#!/usr/bin/env python3
"""把旧的逐条 structure 任务转成 struct_digest（默认 dry-run）。

结构失败率线索现在走「小时摘要 + 便宜闸门」；升级前已经排队的 `structure`
任务如果继续被领取，会按旧路径跑完整 agent。这里把它们的事实批量折成
`struct_digest`，再标记原任务 expired（保留历史行，不删除）。

suppression_downgrade 任务不迁移：那是人工待办，不是结构噪声。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT / "ndr" / "backend", ROOT, Path("/app")):
    if (candidate / "app").is_dir():
        sys.path.insert(0, str(candidate))
        break

from app.analysis import queue
from app.db.base import SessionLocal
from app.db.models import AnalysisTask
from sqlalchemy import select

BATCH = 30


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    now = datetime.now(UTC)
    stamp = now.strftime("%Y%m%d%H%M%S")
    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(AnalysisTask)
                .where(
                    AnalysisTask.kind == "structure",
                    AnalysisTask.dedupe_key.like("structure|%|fail_ratio|%"),
                    AnalysisTask.state.in_(("pending", "deferred", "claimed")),
                )
                .order_by(AnalysisTask.created_at.asc())
            ).all()
        )
        data = [
            {
                "id": str(row.id),
                "subject_kind": str(row.subject_kind or "ip"),
                "subject": str(row.subject or ""),
                "strength": float(row.strength or 0),
                "facts": dict(row.hint or {}).get("事实") or dict(row.hint or {}),
                "reuse_identity": str((row.hint or {}).get("reuse_identity") or ""),
            }
            for row in rows
        ]
    print(json.dumps({"legacy_structure_tasks": len(data), "apply": bool(args.apply)}, ensure_ascii=False))
    if not args.apply or not data:
        return 0
    migrated = 0
    for offset in range(0, len(data), BATCH):
        batch = data[offset:offset + BATCH]
        items = [
            {
                "item_id": item["id"],
                "subject_kind": item["subject_kind"],
                "subject": item["subject"],
                "strength": item["strength"],
                "facts": item["facts"],
                "reuse_identity": item["reuse_identity"],
            }
            for item in batch
        ]
        result = queue.enqueue(
            kind="struct_digest",
            subject_kind="digest",
            subject=f"structure-digest:legacy-{stamp}-{offset // BATCH}",
            strength=max(item["strength"] for item in items),
            feature="struct_digest",
            hint={
                "任务类型": "struct_digest",
                "窗口": "legacy",
                "条目数": len(items),
                "items": items,
                "要求": "只挑出需要完整调查的 item_id；不直接下结论、不建抑制。",
            },
            client=None,
            force=True,
        )
        if result not in ("new", "merged"):
            print(json.dumps({"batch": offset, "result": result}, ensure_ascii=False))
            continue
        ids = [item["id"] for item in batch]
        with SessionLocal() as db:
            for task_id in ids:
                row = db.get(AnalysisTask, task_id)
                if row is not None:
                    row.state = "expired"
                    row.lease_until = None
                    row.note = "已迁移到 struct_digest（成本整改）"
                    row.updated_at = now
            db.commit()
        migrated += len(ids)
    print(json.dumps({"migrated": migrated}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
