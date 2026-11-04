#!/usr/bin/env python3
"""删除已确认错误的分析历史（默认 dry-run）。

只删 NDR 的分析结论/任务/锚点/事件结论/抑制/摘要/轨迹；
**不删** hit_events 与 ES 原始日志。执行前会写 manifest/备份，apply 需显式确认哈希。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ndr" / "backend"))

from app.db.base import SessionLocal
from app.db.models import (
    AnalysisAnchor,
    AnalysisDigest,
    AnalysisResult,
    AnalysisSuppression,
    AnalysisTask,
    AnalysisTrace,
    ConclusionRecord,
)
from sqlalchemy import delete, select

DEFAULT_TASKS = (
    "29dcf864-078f-43c5-909c-9d62f67b00eb",
    "565a4d93-e374-428d-b262-062052748e08",
    "77a57ba6-ab56-4f91-9b15-83927a4d6b65",
    "e370d74e-998a-4317-8870-415b717001fe",
    "803df3ea-4762-4b34-a705-63835bfa8c38",
    "2fe51efb-2a75-48b7-800c-985e6bb7f1b7",
    "fc355237-3f22-40a9-8a42-557d13283196",
    "551444ca-3cd4-4701-a5a9-90fa855ecd97",
    "c89ee67e-44f0-4d05-bf81-2cf0f767d97b",
    "bf85ce55-c37b-43a9-b3ca-380ce5588cc8",
    "fe09ef8c-8491-4463-92e7-7561e2f79f1b",
)
EXTRA_SUSPICIOUS = (
    "2d78f58a-b4ba-493f-b39f-9f9e53ecf6f0",
    "cadac89a-7949-4489-9453-6ea1876cd88d",
    "09799b32-cd7c-4fde-879b-288b391e192a",
)


def _row_dict(row: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for column in row.__table__.columns:
        value = getattr(row, column.name, None)
        if isinstance(value, datetime):
            value = value.isoformat()
        out[column.name] = value
    return out


def _inventory(db: Any, task_ids: set[str]) -> dict[str, Any]:
    results = list(db.scalars(select(AnalysisResult).where(AnalysisResult.task_id.in_(task_ids))).all())
    result_ids = {str(row.id) for row in results}
    tasks = list(db.scalars(select(AnalysisTask).where(AnalysisTask.id.in_(task_ids))).all())
    anchors = list(
        db.scalars(
            select(AnalysisAnchor).where(
                AnalysisAnchor.task_id.in_(task_ids)
                | AnalysisAnchor.result_id.in_(result_ids)
            )
        ).all()
    ) if result_ids else list(db.scalars(select(AnalysisAnchor).where(AnalysisAnchor.task_id.in_(task_ids))).all())
    conclusions = list(
        db.scalars(
            select(ConclusionRecord).where(
                ConclusionRecord.detail["task_id"].astext.in_(task_ids)
            )
        ).all()
    )
    suppressions = list(
        db.scalars(
            select(AnalysisSuppression).where(AnalysisSuppression.source_task_id.in_(task_ids))
        ).all()
    )
    traces = list(db.scalars(select(AnalysisTrace).where(AnalysisTrace.task_id.in_(task_ids))).all())
    subjects = {(row.subject_kind, row.subject) for row in results}
    digests = []
    for kind, subject in subjects:
        digests.extend(
            db.scalars(
                select(AnalysisDigest).where(
                    AnalysisDigest.subject_kind == kind,
                    AnalysisDigest.subject == subject,
                )
            ).all()
        )
    return {
        "task_ids": sorted(task_ids),
        "results": results,
        "tasks": tasks,
        "anchors": anchors,
        "conclusions": conclusions,
        "suppressions": suppressions,
        "traces": traces,
        "digests": digests,
    }


def _write_backup(out_dir: Path, inventory: dict[str, Any]) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(),
        "task_ids": inventory["task_ids"],
        "counts": {key: len(value) for key, value in inventory.items() if isinstance(value, list)},
        "rows": {},
    }
    for key, rows in inventory.items():
        if not isinstance(rows, list):
            continue
        serialized = [_row_dict(row) for row in rows]
        manifest["rows"][key] = serialized
        (out_dir / f"{key}.jsonl").write_text(
            "\n".join(json.dumps(row, ensure_ascii=False, default=str) for row in serialized) + ("\n" if serialized else ""),
            encoding="utf-8",
        )
    raw = json.dumps(manifest, ensure_ascii=False, sort_keys=True, default=str).encode()
    digest = hashlib.sha256(raw).hexdigest()
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (out_dir / "manifest.sha256").write_text(digest + "\n", encoding="utf-8")
    return digest


def _apply(db: Any, inventory: dict[str, Any]) -> None:
    task_ids = set(inventory["task_ids"])
    result_ids = {str(row.id) for row in inventory["results"]}
    if result_ids:
        db.execute(delete(AnalysisAnchor).where(AnalysisAnchor.result_id.in_(result_ids)))
    db.execute(delete(AnalysisAnchor).where(AnalysisAnchor.task_id.in_(task_ids)))
    if inventory["conclusions"]:
        db.execute(
            delete(ConclusionRecord).where(
                ConclusionRecord.id.in_([row.id for row in inventory["conclusions"]])
            )
        )
    if inventory["digests"]:
        db.execute(delete(AnalysisDigest).where(AnalysisDigest.id.in_([row.id for row in inventory["digests"]])))
    if inventory["traces"]:
        db.execute(delete(AnalysisTrace).where(AnalysisTrace.task_id.in_(task_ids)))
    if inventory["suppressions"]:
        db.execute(
            delete(AnalysisSuppression).where(
                AnalysisSuppression.source_task_id.in_(task_ids)
            )
        )
    if result_ids:
        db.execute(delete(AnalysisResult).where(AnalysisResult.id.in_(result_ids)))
    db.execute(delete(AnalysisTask).where(AnalysisTask.id.in_(task_ids)))
    db.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", action="append", default=[], help="额外要删除的 task id")
    parser.add_argument("--include-suspicious", action="store_true", help="同时清理 3 条 tfogc suspicious")
    parser.add_argument("--apply", action="store_true", help="真正删除（默认 dry-run）")
    parser.add_argument("--manifest", default="", help="apply 时传 dry-run 生成的 manifest.sha256")
    parser.add_argument("--out", default="backups/analysis-cleanup", help="manifest/备份目录")
    args = parser.parse_args()

    task_ids = set(DEFAULT_TASKS) | set(args.task_id)
    if args.include_suspicious:
        task_ids |= set(EXTRA_SUSPICIOUS)
    with SessionLocal() as db:
        inventory = _inventory(db, task_ids)
        counts = {key: len(value) for key, value in inventory.items() if isinstance(value, list)}
        print(json.dumps({"mode": "dry-run" if not args.apply else "apply", "counts": counts, "task_ids": sorted(task_ids)}, ensure_ascii=False, indent=2))
        if not args.apply:
            out_dir = Path(args.out) / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            digest = _write_backup(out_dir, inventory)
            print(f"manifest: {out_dir / 'manifest.json'}")
            print(f"sha256:   {digest}")
            print("确认无误后使用 --apply --manifest <sha256> 执行。")
            return 0
        if not args.manifest:
            print("拒绝执行：apply 必须传 --manifest <dry-run 输出的 sha256>", file=sys.stderr)
            return 2
        # 重新写一份备份，确保 apply 使用的清单与确认哈希一致。
        out_dir = Path(args.out) / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        digest = _write_backup(out_dir, inventory)
        if digest != args.manifest:
            print(f"拒绝执行：manifest 哈希不匹配（当前 {digest}）", file=sys.stderr)
            return 2
        _apply(db, inventory)
        print(f"已删除，备份目录：{out_dir}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
