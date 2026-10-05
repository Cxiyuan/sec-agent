"""数值基线的存取与保留期（``ndr/backend/app/baseline/stats.py``）。

只跑 NDR 栈。要钉住的是 2026-10 实机 QA 发现的两件事：

- ``snapshot()`` 原来是**两条** ``COUNT(*)``（其中一条还过滤没有索引的 ``first_seen``），
  而它被总览页每 15 秒轮询一次 —— 现在必须是一条 SQL 出两个数；
- ``baseline_stats`` 原来**没有任何清理**：key 是 ``{src_ip}:{feature}``，被扫过一次的
  IP（尤其外网/攻击者）永久留 3 行，只增不减 —— 现在按 ``updated_at`` + 保留期删。
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from types import ModuleType, SimpleNamespace
from typing import Any, Self

import pytest


@pytest.fixture(scope="module")
def stats_mod(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("数值基线只在 NDR 侧")
    return importlib.import_module("app.baseline.stats")


class _Session:
    """记录被执行的语句，并按需返回结果（不连库）。"""

    def __init__(self, row: Any = None, rowcount: int = 0, rows: list[Any] | None = None) -> None:
        self.statements: list[str] = []
        self._row = row
        self._rowcount = rowcount
        self._rows = rows or []
        self.added: list[Any] = []
        self.commits = 0

    def execute(self, stmt: Any) -> Any:
        self.statements.append(str(stmt))
        return SimpleNamespace(one=lambda: self._row, rowcount=self._rowcount)

    def scalars(self, stmt: Any) -> Any:
        self.statements.append(str(stmt))
        return SimpleNamespace(all=lambda: list(self._rows))

    def add(self, row: Any) -> None:
        self.added.append(row)

    def commit(self) -> None:
        self.commits += 1

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        return False


def test_snapshot_uses_one_round_trip(
    stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """一次 execute 同时拿到 total 与 warmed（回归：以前是两条 COUNT(*)，轮询会打两次库）。"""
    session = _Session(row=(1200, 300, None))
    monkeypatch.setattr(stats_mod, "SessionLocal", lambda: session)
    snap = stats_mod.snapshot()
    assert snap == {
        "observe_days": 7,
        "total_keys": 1200,
        "warmed_keys": 300,
        "learning_keys": 900,
        "oldest_first_seen": None,
        "next_warm_at": None,
    }
    assert len(session.statements) == 1, session.statements
    # 过滤条件必须是「first_seen 不为空且早于观测期边界」
    assert "first_seen" in session.statements[0]


def test_snapshot_reports_observe_countdown(
    stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """观测期倒计时：界面要显示「最早那批维度什么时候过观测期」。"""
    oldest = datetime(2026, 10, 4, 10, 3, 37, tzinfo=UTC)
    monkeypatch.setattr(stats_mod, "SessionLocal", lambda: _Session(row=(5, 0, oldest)))
    snap = stats_mod.snapshot()
    assert snap["oldest_first_seen"] == oldest.isoformat()
    assert snap["next_warm_at"] == (oldest + timedelta(days=7)).isoformat()


def test_snapshot_never_returns_negative_learning(
    stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """脏数据（warmed > total）不能让 learning 变成负数。"""
    monkeypatch.setattr(stats_mod, "SessionLocal", lambda: _Session(row=(10, 12, None)))
    assert stats_mod.snapshot()["learning_keys"] == 0


def test_snapshot_reports_error_without_raising(
    stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom(_Session):
        def execute(self, stmt: Any) -> Any:
            raise RuntimeError("pg down")

    monkeypatch.setattr(stats_mod, "SessionLocal", _Boom)
    snap = stats_mod.snapshot()
    assert snap["total_keys"] == 0 and snap["warmed_keys"] == 0 and "pg down" in snap["error"]


def test_cleanup_deletes_only_stale_keys(
    stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _Session(rowcount=7)
    monkeypatch.setattr(stats_mod, "SessionLocal", lambda: session)
    out = stats_mod.cleanup(30)
    assert out == {"deleted": 7}
    assert session.commits == 1
    sql = session.statements[0]
    assert sql.startswith("DELETE FROM baseline_stats")
    assert "updated_at" in sql


def test_cleanup_can_be_disabled(stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """保留期 0 = 不清理（显式关掉，不该顺手把整张表删了）。"""
    session = _Session(rowcount=999)
    monkeypatch.setattr(stats_mod, "SessionLocal", lambda: session)
    assert stats_mod.cleanup(0) == {"deleted": 0}
    assert session.statements == []


def test_cleanup_swallows_db_errors(stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_Session):
        def execute(self, stmt: Any) -> Any:
            raise RuntimeError("pg down")

    monkeypatch.setattr(stats_mod, "SessionLocal", _Boom)
    assert stats_mod.cleanup(30) == {"deleted": 0}


def test_apply_stats_is_welford(stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """Welford 增量：两次观测 10/20 → count=2、mean=15、样本标准差 sqrt(50)≈7.071。"""
    session = _Session(rows=[])
    monkeypatch.setattr(stats_mod, "SessionLocal", lambda: session)
    out = stats_mod.apply_stats({"10.0.0.1:conn_count": [10.0, 20.0]})
    state = out["10.0.0.1:conn_count"]
    assert state["count"] == 2
    assert state["mean"] == pytest.approx(15.0)
    assert state["std"] == pytest.approx(50**0.5, rel=1e-3)
    assert state["warmed"] is False  # first_seen = 现在，观测期未过
    assert session.commits == 1


def test_apply_stats_skips_empty_values(
    stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _Session(rows=[])
    monkeypatch.setattr(stats_mod, "SessionLocal", lambda: session)
    assert stats_mod.apply_stats({"k": []}) == {}
    assert session.statements == []


def test_lookup_needs_ip_or_key(stats_mod: ModuleType) -> None:
    assert "error" in stats_mod.lookup()


def test_warmed_flips_after_observation_period(stats_mod: ModuleType) -> None:
    """first_seen 早于观测期边界 → warmed=True（这是「能不能判偏离」的开关）。"""
    now = datetime.now(UTC)
    assert stats_mod._warmed(now - timedelta(days=8), now) is True
    assert stats_mod._warmed(now - timedelta(hours=1), now) is False
    assert stats_mod._warmed(None, now) is False


# ---------- 按 IP 分组浏览（行为分析页的列表形态） ----------


def _row(key: str, count: int, mean: float, first_seen: datetime) -> Any:
    return SimpleNamespace(key=key, count=count, mean=mean, m2=0.0, first_seen=first_seen)


def test_group_rows_by_ip_merges_dimensions(stats_mod: ModuleType) -> None:
    """同一 IP 的三个维度合成一行；IPv6 地址不能被切碎（按最后一个冒号拆）。"""
    now = datetime.now(UTC)
    old = now - timedelta(days=9)
    fresh = now - timedelta(hours=2)
    rows = [
        _row("10.0.0.5:conn_count", 10, 1.5, fresh),
        _row("10.0.0.5:distinct_dst_ports", 3, 2.5, old),
        _row("2409:8962:1e68:a8f::2:conn_count", 7, 3.5, old),
    ]
    out = stats_mod.group_rows_by_ip(rows, ["10.0.0.5", "2409:8962:1e68:a8f::2"], now)
    assert [g["ip"] for g in out] == ["10.0.0.5", "2409:8962:1e68:a8f::2"]
    first = out[0]
    assert [f["feature"] for f in first["features"]] == ["conn_count", "distinct_dst_ports"]
    assert first["features"][0]["mean"] == 1.5
    assert first["features"][0]["count"] == 10
    # IP 级首次观测 = 各维度里最早的那个
    assert first["first_seen"] == old.isoformat()
    # IPv6 组也要拆对
    assert out[1]["features"][0]["feature"] == "conn_count"


def test_group_rows_by_ip_orders_features_by_count(stats_mod: ModuleType) -> None:
    """维度按观测次数降序（次数多的在前面，和表格的排序一致）。"""
    now = datetime.now(UTC)
    rows = [
        _row("10.0.0.9:distinct_dst_ips", 2, 1.0, now),
        _row("10.0.0.9:conn_count", 50, 1.0, now),
        _row("10.0.0.9:distinct_dst_ports", 20, 1.0, now),
    ]
    out = stats_mod.group_rows_by_ip(rows, ["10.0.0.9"], now)
    assert [f["feature"] for f in out[0]["features"]] == [
        "conn_count",
        "distinct_dst_ports",
        "distinct_dst_ips",
    ]


def test_group_rows_by_ip_skips_ips_without_rows(stats_mod: ModuleType) -> None:
    """分页拿到的 IP 如果一行都没匹配（并发删除/过滤变化），就跳过而不是给个空行。"""
    now = datetime.now(UTC)
    out = stats_mod.group_rows_by_ip([], ["10.0.0.1", "10.0.0.2"], now)
    assert out == []


def test_list_stats_group_ip_dispatches(
    stats_mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`group="ip"` 必须走按 IP 的那个分支（分页按 IP 走）；默认仍是按 key 一行一条。"""
    calls: list[dict[str, Any]] = []

    def fake_by_ip(conds: Any, **kw: Any) -> dict[str, Any]:
        calls.append({"conds": conds, **kw})
        return {"group": "ip", "total": 0, "total_keys": 0, "returned": 0, "items": []}

    monkeypatch.setattr(stats_mod, "_list_by_ip", fake_by_ip)
    out = stats_mod.list_stats(q="10.0.0", feature="conn_count", group="IP", limit=5, offset=10)
    assert out["group"] == "ip"
    assert len(calls) == 1
    assert calls[0]["cap"] == 5 and calls[0]["start"] == 10
    assert len(calls[0]["conds"]) == 2  # q + feature 两个过滤都传下去了


def test_numeric_conds_escapes_like(stats_mod: ModuleType) -> None:
    """q 里的 `%`/`_` 是通配符，必须转义（不能让别人用 `%` 扫全表）。"""
    conds = stats_mod._numeric_conds("10%_", "")
    assert len(conds) == 1
    compiled = str(conds[0].compile(compile_kwargs={"literal_binds": True}))
    assert "ESCAPE" in compiled.upper()
