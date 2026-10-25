"""锚点：把分析结论挂到具体资产上（多对多），让"结论↔资产"双向可查。

为什么需要（借鉴 artex 双图的 `exploration_anchors`）：
结论原来只挂**单个 `subject`**，而现实里一条结论常常覆盖多个资产——
"这台是反向代理"影响它后面的 20 台后端，"这个网段在做例行扫描"影响整段地址。
没有锚点时覆盖度只能回答"分析过没有"，无法回答"**对这台机器我们到底知道什么**"。

分工原则（与全仓一致）：**归一化与去重由服务端做，智能体只提交原始值**。
模型很容易把 `10.0.0.5:8080`、`10.0.0.5`、`::ffff:10.0.0.5` 当成三个不同资产，
这种"看起来能匹配上、其实就是匹配不上"的错误最难查，所以不许它决定归一化口径。
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select

from app.db.models import AnalysisAnchor, AnalysisResult

#: 允许的资产类型。刻意不含 `payload`/`body` 之类的内容字段：
#: 资产是"东西"，内容是"数据"，两者混在一张表里会让影响面算不清。
ANCHOR_KINDS = ("ip", "host", "domain", "endpoint", "service")

#: 单条结论最多挂多少个锚点。上限的作用是**有界**：
#: 一条"整个网段都不正常"的结论如果挂 3000 个 IP，覆盖度统计会比实际安全得多。
MAX_ANCHORS = 50


def _strip_port(value: str) -> str:
    """`1.2.3.4:8080` / `[::1]:8080` → 去掉端口，只留地址。"""
    text = value.strip()
    if text.startswith("["):
        end = text.find("]")
        return text[1:end] if end > 0 else text
    # 只有一个冒号才可能是 IPv4:端口；IPv6 有多个冒号，不能靠冒号切
    if text.count(":") == 1:
        head, _, tail = text.partition(":")
        if tail.isdigit():
            return head
    return text


def normalize_ip(value: str) -> str:
    """IP 归一：去端口、去 `::ffff:` 前缀、压缩 IPv6 写法；解析不了就原样返回。"""
    text = _strip_port(str(value or ""))
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text.lower()
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def normalize_anchor(kind: str, value: str) -> tuple[str, str] | None:
    """归一一条锚点；不认识或空值返回 `None`（由调用方决定报错还是跳过）。"""
    kind_text = str(kind or "").strip().lower()
    raw = str(value or "").strip()
    if kind_text not in ANCHOR_KINDS or not raw:
        return None
    if kind_text == "ip":
        normalized = normalize_ip(raw)
        if not normalized:
            return None
        return kind_text, normalized[:196]
    if kind_text in ("host", "domain"):
        return kind_text, raw.lower().rstrip(".")[:196]
    if kind_text == "service":
        # `IP:端口` 里的 IP 部分也归一，否则同一服务会因写法不同分成两条
        head, sep, tail = raw.partition(":")
        if sep and tail.isdigit() and head.count(":") == 1:
            return kind_text, f"{normalize_ip(head)}:{tail}"[:196]
        return kind_text, raw.lower()[:196]
    # endpoint：URL 或 `host/path`，只做小写与去尾斜杠
    return kind_text, raw.lower().rstrip("/")[:196]


def clean_anchors(items: list[dict[str, Any]] | None) -> tuple[list[tuple[str, str]], list[str]]:
    """校验并归一一批锚点，返回 `(可用列表, 错误列表)`。

    非法项**报错而不是静默丢**：智能体写错 `kind` 时如果悄悄丢掉，
    覆盖度就会少算、而且没人知道为什么少算。
    """
    errors: list[str] = []
    raw_items = items or []
    if not isinstance(raw_items, list):
        return [], ["anchors 必须是数组"]
    if len(raw_items) > MAX_ANCHORS:
        return [], [f"锚点最多 {MAX_ANCHORS} 个，收到 {len(raw_items)} 个"]
    seen: set[tuple[str, str]] = set()
    cleaned: list[tuple[str, str]] = []
    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            errors.append(f"#{index} 不是对象")
            continue
        pair = normalize_anchor(str(item.get("kind") or ""), str(item.get("value") or ""))
        if pair is None:
            kind_text = str(item.get("kind") or "").strip()
            errors.append(
                f"#{index} 无法归一（kind={kind_text or '空'}，可用：{'/'.join(ANCHOR_KINDS)}）"
            )
            continue
        if pair in seen:
            continue
        seen.add(pair)
        cleaned.append(pair)
    return cleaned, errors


def write_anchors(db: Any, *, result_id: str, task_id: str, pairs: list[tuple[str, str]]) -> int:
    """把已归一的锚点写成行（幂等：同结论同资产只留一条）。返回新写入条数。"""
    if not pairs:
        return 0
    written = 0
    for kind, value in pairs:
        exists = db.scalar(
            select(AnalysisAnchor.id).where(
                AnalysisAnchor.result_id == str(result_id),
                AnalysisAnchor.asset_kind == kind,
                AnalysisAnchor.asset_value == value,
            )
        )
        if exists is not None:
            continue
        db.add(
            AnalysisAnchor(
                result_id=str(result_id),
                task_id=str(task_id or ""),
                asset_kind=kind,
                asset_value=value,
            )
        )
        written += 1
    return written


def assets_of_results(result_ids: list[str]) -> dict[str, list[dict[str, str]]]:
    """按结论 ID 批量取它挂的资产（一次查询，避免 N+1）。"""
    ids = [str(x) for x in result_ids if str(x or "").strip()]
    if not ids:
        return {}
    out: dict[str, list[dict[str, str]]] = {}
    with _session() as db:
        rows = db.scalars(select(AnalysisAnchor).where(AnalysisAnchor.result_id.in_(ids))).all()
    for row in rows:
        out.setdefault(str(row.result_id), []).append(
            {"kind": str(row.asset_kind), "value": str(row.asset_value)}
        )
    return out


def results_for_assets(
    pairs: list[tuple[str, str]], *, limit: int = 20
) -> list[tuple[AnalysisResult, str]]:
    """反查：锚到这些资产的结论（"对这台机器我们做过哪些判断"）。

    返回 `(结论行, 命中它的资产键)` 元组 —— 带上 "是通过哪条资产找到的"，
    让调用方能解释这条为什么出现在结果里（不往 ORM 对象上挂临时属性，
    那种写法类型检查看不见、也容易在序列化时丢）。

    只按归一化后的 `(kind, value)` 精确匹配 —— 不做模糊、不做前缀，
    否则"顺带碰到"的结论会被当成"关于它的结论"，反而误导判断。
    """
    if not pairs:
        return []
    cap = max(1, min(int(limit or 20), 50))
    conds = [
        and_(AnalysisAnchor.asset_kind == kind, AnalysisAnchor.asset_value == value)
        for kind, value in pairs
    ]
    anchor_conds = or_(*conds) if len(conds) > 1 else conds[0]
    with _session() as db:
        rows = db.execute(
            select(AnalysisResult, AnalysisAnchor.asset_kind, AnalysisAnchor.asset_value)
            .join(AnalysisAnchor, AnalysisAnchor.result_id == AnalysisResult.id)
            .where(anchor_conds)
            .order_by(AnalysisResult.created_at.desc())
            .limit(cap)
        ).all()
    return [(row[0], f"{row[1]}:{row[2]}") for row in rows]


def conclusion_stats(assets: list[str]) -> dict[str, dict[str, Any]]:
    """按 IP 批量取"结论条数 + 最近结论"，供 `asset_context` 展示（一次聚合）。"""
    keys = [normalize_ip(a) for a in (assets or []) if str(a or "").strip()]
    keys = [k for k in keys if k]
    if not keys:
        return {}
    with _session() as db:
        rows = db.execute(
            select(
                AnalysisAnchor.asset_value,
                func.count(AnalysisResult.id),
                func.max(AnalysisResult.created_at),
            )
            .join(AnalysisResult, AnalysisResult.id == AnalysisAnchor.result_id)
            .where(AnalysisAnchor.asset_kind == "ip", AnalysisAnchor.asset_value.in_(keys))
            .group_by(AnalysisAnchor.asset_value)
        ).all()
        latest: dict[str, str] = {}
        for value, _count, last_at in rows:
            if last_at is None:
                continue
            verdict = db.scalar(
                select(AnalysisResult.verdict)
                .join(AnalysisAnchor, AnalysisAnchor.result_id == AnalysisResult.id)
                .where(
                    AnalysisAnchor.asset_kind == "ip",
                    AnalysisAnchor.asset_value == str(value),
                )
                .order_by(AnalysisResult.created_at.desc())
                .limit(1)
            )
            latest[str(value)] = str(verdict or "")
    out: dict[str, dict[str, Any]] = {}
    for value, count, last_at in rows:
        out[str(value)] = {
            "conclusion_count": int(count or 0),
            "last_verdict": latest.get(str(value), ""),
            "last_conclusion_at": last_at.isoformat() if last_at else None,
        }
    return out


def covered_asset_count(days: int = 7) -> int:
    """近 N 天有结论覆盖的资产数（覆盖率的分母仍是 `observed_subjects(kind="asset")`）。"""
    since = datetime.now(UTC) - timedelta(days=max(1, int(days or 7)))
    with _session() as db:
        value = db.scalar(
            select(func.count(func.distinct(AnalysisAnchor.asset_value)))
            .join(AnalysisResult, AnalysisResult.id == AnalysisAnchor.result_id)
            .where(
                AnalysisAnchor.asset_kind == "ip",
                AnalysisResult.created_at >= since,
            )
        )
    return int(value or 0)


def purge_old(days: int = 180) -> int:
    """清掉跟着结论一起过期的锚点（结论行本身不删，锚点是派生物）。"""
    cutoff = datetime.now(UTC) - timedelta(days=max(30, int(days or 180)))
    with _session() as db:
        rows = db.scalars(
            select(AnalysisAnchor).where(AnalysisAnchor.created_at < cutoff).limit(5000)
        ).all()
        for row in rows:
            db.delete(row)
        db.commit()
        return len(rows)


def _session() -> Any:
    """延迟导入 `SessionLocal`：模块导入期就把 DB 配置拉进来会让纯函数单测难以运行。"""
    from app.db.base import SessionLocal

    return SessionLocal()
