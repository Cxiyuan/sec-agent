#!/usr/bin/env python3
"""退役 coverage 任务（默认 dry-run）。

Coverage 是资产/服务覆盖率问题，不是模型分析案件；2026-11 成本整改后
不再生成 coverage task。这里只删除**尚未被领取/仍在排队的 coverage 行**，
保留已完成历史、AnalysisResult、Observation、原始事件与覆盖率数据。

用法：
  python scripts/retire_coverage_tasks.py            # 只统计
  python scripts/retire_coverage_tasks.py --apply    # 事务删除
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

from app.db.base import SessionLocal
from app.db.models import AnalysisTask
from sqlalchemy import delete, select


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="真正删除；默认只统计")
    parser.add_argument("--manifest", default="", help="可选的 id 清单 JSON 路径")
    args = parser.parse_args()

    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(AnalysisTask).where(
                    AnalysisTask.kind == "coverage",
                    AnalysisTask.state.in_(("pending", "deferred", "claimed")),
                )
            ).all()
        )
        ids = [str(row.id) for row in rows]
        print(json.dumps({
            "coverage_tasks": len(ids),
            "apply": bool(args.apply),
            "states": sorted({str(row.state) for row in rows}),
        }, ensure_ascii=False))
        if args.manifest:
            Path(args.manifest).write_text(
                json.dumps({"retired_at": datetime.now(UTC).isoformat(), "task_ids": ids}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        if not args.apply or not ids:
            return 0
        result = db.execute(delete(AnalysisTask).where(AnalysisTask.id.in_(ids)))
        db.commit()
        print(json.dumps({"deleted": int(result.rowcount or 0)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
