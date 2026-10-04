"""账号/会话画像判据与风险写回（``ndr/backend/app/baseline/profile.py``）。

只跑 NDR 栈。这个文件是 2026-10 实机 QA 的直接产物：当时画像已经在生产里跑了 6 小时，
一查库发现「风险>0 的 54 条画像里 40 条的**唯一**理由是非常用时段」，而被判「会话跨 IP
（疑似会话劫持）」的 5 条**全部**是 IPv4+IPv6 双栈 —— 也就是判据本身在批量造假阳性。

钉住的是修好后的行为：

- **非常用时段**要同时满足三个条件（够多观测 / 见过足够多时段 / 画像够老），
  否则分母只算历史出现过的时段 ⇒ 每个整点的新时段恒为 0% < 1%，整点批量误报；
- **会话跨 IP** 只在**同族内** ≥2 个才算：v4+v6 是同一客户端的双栈，不是会话劫持；
- **新源 IP** 对 v6 只看 /64 前缀（RFC 4941 隐私地址在同一 /64 内轮换）；
- **风险分按当前窗口**：本轮没理由就必须归零 + 清空理由 + 风险时间置空
  （不归零的后果是几小时前的陈旧风险一直挂在「画像风险 TOP」上）。
"""

from __future__ import annotations

import importlib
from collections import Counter
from datetime import UTC, datetime, timedelta
from types import ModuleType
from typing import Any, Self

import pytest


@pytest.fixture(scope="module")
def profiles(request: pytest.FixtureRequest) -> ModuleType:
    if request.config.getoption("--stack") != "ndr":
        pytest.skip("画像只在 NDR 侧（第 8 期从智能体侧迁来）")
    return importlib.import_module("app.baseline.profile")


def _profile(
    profiles: ModuleType,
    *,
    obs_count: int = 500,
    src_ips: dict[str, int] | None = None,
    user_agents: dict[str, int] | None = None,
    hour_hist: dict[str, int] | None = None,
    paths: dict[str, int] | None = None,
    age_hours: float = 72.0,
    **extra: Any,
) -> Any:
    """构造一个「已学了一阵子」的画像对象（只带 detect() 会读的字段）。"""
    row = profiles.EntityProfile(
        kind=profiles.SESSION,
        entity_key="k",
        entity_display="disp",
        obs_count=obs_count,
        src_ips=src_ips if src_ips is not None else {"10.0.0.1": 100},
        user_agents=user_agents if user_agents is not None else {"UA/1.0": 100},
        paths=paths if paths is not None else {},
        hour_hist=hour_hist if hour_hist is not None else {str(h): 20 for h in range(12)},
        success_count=100,
        fail_count=0,
        first_seen=datetime.now(UTC) - timedelta(hours=age_hours),
    )
    for key, value in extra.items():
        setattr(row, key, value)
    return row


def _obs(
    *,
    kind: str = "session",
    src_ips: list[str] | None = None,
    dst_ips: list[str] | None = None,
    paths: list[str] | None = None,
    hours: list[int] | None = None,
    fail: int = 0,
    success: int = 1,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "key": "k",
        "display": "disp",
        "src_ips": Counter(src_ips or []),
        "dst_ips": Counter(dst_ips or []),
        "user_agents": Counter(["UA/1.0"]),
        "paths": Counter(paths or []),
        "hours": Counter(str(h) for h in (hours if hours is not None else [3])),
        "success": success,
        "fail": fail,
        "count": max(1, success + fail),
    }


def _reasons(out: dict[str, Any]) -> str:
    return " | ".join(out["reasons"])


# ---------- 非常用时段：三个门槛 ----------


def test_hour_reason_needs_coverage(profiles: ModuleType) -> None:
    """只见过 2 个时段 → 不判时段（第一天必然「新时段」，这是整点批量误报的来源）。"""
    prof = _profile(profiles, hour_hist={"9": 20, "10": 20})
    out = profiles.detect("session", _obs(hours=[15]), prof)
    assert "非常用时段" not in _reasons(out)
    assert out["risk"] == 0.0  # 时段不参与，且 UA/IP 都不是新的


def test_hour_reason_needs_age(profiles: ModuleType) -> None:
    """覆盖面够（12 个时段）但画像只建了 1 小时 → 仍然不判。"""
    prof = _profile(profiles, age_hours=1.0)
    out = profiles.detect("session", _obs(hours=[15]), prof)
    assert "非常用时段" not in _reasons(out)


def test_hour_reason_fires_when_warm_and_rare(profiles: ModuleType) -> None:
    """见过 12 个时段（0~11 时）、画像 3 天前建的、当前 15 时没人来过 → 该报，且 +0.15。"""
    prof = _profile(profiles, hour_hist={str(h): 20 for h in range(12)})
    out = profiles.detect("session", _obs(hours=[15]), prof)
    assert "非常用时段" in _reasons(out)
    assert out["risk"] == pytest.approx(0.15)


def test_hour_reason_skipped_when_hour_is_common(profiles: ModuleType) -> None:
    """当前时段在历史里占比 ≥1% → 不判。"""
    prof = _profile(profiles, hour_hist={str(h): 20 for h in range(12)})
    out = profiles.detect("session", _obs(hours=[5]), prof)
    assert "非常用时段" not in _reasons(out)


# ---------- 跨 IP：只在同族内成立 ----------


def test_dual_stack_v4_v6_is_not_session_hijack(profiles: ModuleType) -> None:
    """实机被判的 5 条全是这种：v4 一个 + v6 一个 = 同一客户端双栈，不是劫持。"""
    prof = _profile(profiles, src_ips={"110.185.129.127": 100})
    out = profiles.detect(
        "session", _obs(src_ips=["110.185.129.127", "240e:398:66b9:7ac0:5e02:14ff:feee:a0e7"]), prof
    )
    assert "会话跨" not in _reasons(out)
    # v6 是新地址但同前缀也没见过 → 会有「新源 IP」，但风险不该到 0.45
    assert out["risk"] < 0.45


def test_two_ipv4_is_session_hijack(profiles: ModuleType) -> None:
    prof = _profile(profiles, src_ips={"10.0.0.1": 100, "10.0.0.2": 100})
    out = profiles.detect("session", _obs(src_ips=["10.0.0.1", "10.0.0.2"]), prof)
    assert "会话跨 2 个同族源 IP" in _reasons(out)
    assert out["risk"] >= 0.45


def test_two_ipv6_in_different_64_is_session_hijack(profiles: ModuleType) -> None:
    prof = _profile(profiles, src_ips={"2001:db8::1": 100, "2001:db9::1": 100})
    out = profiles.detect("session", _obs(src_ips=["2001:db8::1", "2001:db9::1"]), prof)
    assert "会话跨" in _reasons(out)


def test_account_kind_never_gets_session_hijack(profiles: ModuleType) -> None:
    prof = _profile(profiles, src_ips={"10.0.0.1": 100, "10.0.0.2": 100})
    out = profiles.detect("account", _obs(kind="account", src_ips=["10.0.0.1", "10.0.0.2"]), prof)
    assert "会话跨" not in _reasons(out)


# ---------- 新源 IP：v6 看 /64 前缀 ----------


def test_new_ipv6_in_known_64_is_not_new_source(profiles: ModuleType) -> None:
    """同一 /64 内的新隐私地址 = 同一客户端，不算新源 IP。"""
    prof = _profile(profiles, src_ips={"2001:db8:1:2::1": 100})
    out = profiles.detect("session", _obs(src_ips=["2001:db8:1:2::abcd"]), prof)
    assert "新源 IP" not in _reasons(out)
    assert out["risk"] == 0.0


def test_new_ipv6_in_new_64_is_new_source(profiles: ModuleType) -> None:
    prof = _profile(profiles, src_ips={"2001:db8:1:2::1": 100})
    out = profiles.detect("session", _obs(src_ips=["2001:db8:9:9::5"]), prof)
    assert "新源 IP" in _reasons(out)
    assert out["risk"] == pytest.approx(0.35)


def test_new_ipv4_counts(profiles: ModuleType) -> None:
    prof = _profile(profiles, src_ips={"10.0.0.1": 100})
    out = profiles.detect("session", _obs(src_ips=["10.0.0.1", "192.168.5.5"]), prof)
    assert "新源 IP" in _reasons(out)


def test_cold_start_never_reports(profiles: ModuleType) -> None:
    prof = _profile(profiles, obs_count=2, src_ips={})
    out = profiles.detect("session", _obs(src_ips=["10.9.9.9"], hours=[4]), prof)
    assert out["cold_start"] is True
    assert out["reasons"] == []
    assert out["risk"] == 0.0


def test_missing_profile_is_cold_start(profiles: ModuleType) -> None:
    out = profiles.detect("session", _obs(src_ips=["10.9.9.9"]), None)
    assert out["cold_start"] is True


# ---------─ 接口路径：静态资源不计、新路径计分 ----------


def test_api_path_keeps_interfaces_drops_static(profiles: ModuleType) -> None:
    """只留接口、排静态资源与页面（实机 paths 里全是 js/css/png，把 30 条上限占满了）。

    注意接口路径**不一定带 /api/**：实测某环境真实接口是 /seeyon/rest/…、/pty/…，
    所以默认只用排除名单（include 为空）。
    """
    keep = [
        "/seeyon/rest/officePlugins/personal/settings",
        "/pty/mad/user/agyInfo/menuList",
        "/api/v2/users",
        "/api/v2/users?page=2",
    ]
    drop = [
        "/seeyon/common/ctpUi/dist/css/ctpUi.css",
        "/selfservice/common/self/img/index_subpage_content_border_1.png",
        "/static/js/app.60735aa5.js",
        "/assets/fonts/iconfont.e2dfd4b7.woff2",
        "/portal/index.html",
        "/portal/login.jsp",
        "/static/logo.png?hash=1",
        "",
    ]
    for path in keep:
        assert profiles.api_path(path) is True, path
    for path in drop:
        assert profiles.api_path(path) is False, path


def test_observe_records_only_api_paths(profiles: ModuleType) -> None:
    """采集侧就过滤：静态资源不占 30 条上限。"""
    from types import SimpleNamespace

    entry = SimpleNamespace(
        account="zhangsan",
        user="",
        cookie="",
        real_client_ip="",
        src_ip="10.0.0.9",
        dst_ip="10.0.0.80",
        user_agent="UA/1.0",
        uri_path="/static/js/app.js",
        ts=datetime(2026, 10, 4, 15, 0, tzinfo=UTC),
        status_code=200,
    )
    buckets: dict[str, Any] = {}
    profiles.observe_entry(buckets, entry)
    bucket = buckets["account|zhangsan"]
    assert dict(bucket["paths"]) == {}
    # 服务端 IP 记上了（界面要展示「账号 + 关联服务端 IP」）
    assert dict(bucket["dst_ips"]) == {"10.0.0.80": 1}

    entry.uri_path = "/api/v2/orders"
    profiles.observe_entry(buckets, entry)
    assert dict(buckets["account|zhangsan"]["paths"]) == {"/api/v2/orders": 1}


def test_new_api_path_reason(profiles: ModuleType) -> None:
    prof = _profile(profiles, paths={"/api/a": 10, "/api/b": 10, "/api/c": 10})
    out = profiles.detect("account", _obs(kind="account", paths=["/api/a", "/api/new"]), prof)
    assert "新接口路径" in _reasons(out)
    assert out["risk"] == pytest.approx(0.25)


def test_new_api_path_needs_known_baseline(profiles: ModuleType) -> None:
    """刚建的画像「第一条路径就是新的」不该报。"""
    prof = _profile(profiles, paths={"/api/a": 10})
    out = profiles.detect("account", _obs(kind="account", paths=["/api/brand-new"]), prof)
    assert "新接口路径" not in _reasons(out)


def test_known_api_path_is_not_reported(profiles: ModuleType) -> None:
    prof = _profile(profiles, paths={"/api/a": 10, "/api/b": 10, "/api/c": 10})
    out = profiles.detect("account", _obs(kind="account", paths=["/api/a"]), prof)
    assert "新接口路径" not in _reasons(out)


def test_fail_burst_bands(profiles: ModuleType) -> None:
    """认证失败突增的分档（用户 2026-10 定）：≥5 → .25 / ≥10 → .35 / ≥20 且零成功 → .6。"""
    assert profiles.fail_burst_score(4, 0) == (0.0, "")
    assert profiles.fail_burst_score(5, 5) == (0.0, "")  # 失败必须多于成功
    assert profiles.fail_burst_score(5, 4)[0] == 0.25
    assert profiles.fail_burst_score(9, 1)[0] == 0.25
    assert profiles.fail_burst_score(10, 3)[0] == 0.35
    assert profiles.fail_burst_score(19, 1)[0] == 0.35
    # 有成功过 → 不进最高档（可能是用户反复输错，不是脚本在撞）
    assert profiles.fail_burst_score(20, 5)[0] == 0.35
    score, suffix = profiles.fail_burst_score(20, 0)
    assert score == 0.6 and "疑似爆破" in suffix
    assert profiles.fail_burst_score(100, 0)[0] == 0.6  # 封顶在最上一档


def test_top_fail_band_reaches_threshold_alone(profiles: ModuleType) -> None:
    """最高档必须**单独**就达阈值。

    回归背景（用户 2026-10 指出）：原来固定 +0.25、而阈值 0.6 —— 单条永远报不出来，
    真爆破只要没伴随新 IP/新 UA 就漏了。
    """
    score, _ = profiles.fail_burst_score(20, 0)
    assert score >= profiles.settings.profile_risk_threshold


def test_detect_reports_top_fail_band(profiles: ModuleType) -> None:
    """接进 detect()：窗口内 20 次失败零成功时，总分应过阈值。"""
    prof = _profile(profiles)  # 其余特征都是已知的，只有失败突增命中
    out = profiles.detect("session", _obs(fail=20, success=0), prof)
    assert any("认证失败突增" in r for r in out["reasons"]), out
    assert out["risk"] >= profiles.settings.profile_risk_threshold


def test_detect_ignores_mild_failures(profiles: ModuleType) -> None:
    """输错几次不该报（失败 5 次成功 4 次 → 只 0.25 分，不过阈值）。"""
    prof = _profile(profiles)
    out = profiles.detect("session", _obs(fail=5, success=4), prof)
    assert any("认证失败突增" in r for r in out["reasons"]), out
    assert out["risk"] < profiles.settings.profile_risk_threshold


def test_update_profiles_prunes_stale_static_paths(
    profiles: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """自愈：老库里存的静态资源路径要在再次观测时被剔掉（否则 30 条上限永远被占着）。

    实测某环境库里积了 5237 条不合口径的旧值（.css/.png/页面）。
    """
    row = _profile(profiles)
    row.paths = {"/seeyon/rest/keep": 5, "/seeyon/x/ctpUi.css": 99, "/img/a.png": 88}
    monkeypatch.setattr(profiles, "SessionLocal", lambda: _FakeSession(row))
    profiles.update_profiles({"session|k": _obs(paths=["/seeyon/rest/keep"])}, {})
    assert "/seeyon/x/ctpUi.css" not in row.paths
    assert "/img/a.png" not in row.paths
    assert row.paths["/seeyon/rest/keep"] == 6


def test_update_profiles_merges_dst_ips(
    profiles: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _profile(profiles)
    row.dst_ips = {"10.0.0.80": 5}
    monkeypatch.setattr(profiles, "SessionLocal", lambda: _FakeSession(row))
    profiles.update_profiles({"session|k": _obs(dst_ips=["10.0.0.81", "10.0.0.80"])}, {})
    assert row.dst_ips == {"10.0.0.80": 6, "10.0.0.81": 1}


def test_top_anomalies_kind_filter(profiles: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """界面只取账号画像（会话展示名是哈希，看不懂）—— SQL 里必须有 kind 过滤。"""
    session = _FakeSession(row=None, rows=[])
    monkeypatch.setattr(profiles, "SessionLocal", lambda: session)
    profiles.top_anomalies(5, kind=profiles.ACCOUNT)
    assert "kind" in _where_of(session.statements[0])


def test_recall_exposes_server_ips(profiles: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """摘要标签里也要带上服务端 IP（智能体靠它判断「这台服务上是谁在动」）。"""
    profile = _profile(profiles, src_ips={}, user_agents={"UA/1.0": 1}, obs_count=500)
    monkeypatch.setattr(profiles, "load_profiles", lambda _keys: {"session|k": profile})
    out = profiles.recall_from_observations(
        {"session|k": _obs(src_ips=["10.0.0.9"], dst_ips=["10.0.0.80"], hours=[3])}
    )
    assert out["entities"], out
    assert out["entities"][0]["dst_ips"] == ["10.0.0.80"]


# ---------- 风险写回：按当前窗口，无理由就归零 ----------


class _FakeSession:
    """够 ``update_profiles`` / ``top_anomalies`` 用：查一行、改它、commit。"""

    def __init__(self, row: Any, rows: list[Any] | None = None) -> None:
        self.row = row
        self.rows = rows if rows is not None else ([row] if row is not None else [])
        self.statements: list[str] = []
        self.commits = 0

    def scalars(self, stmt: Any = None) -> Any:
        from types import SimpleNamespace

        if stmt is not None:
            self.statements.append(str(stmt))
        return SimpleNamespace(first=lambda: self.row, all=lambda: list(self.rows))

    def commit(self) -> None:
        self.commits += 1

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        return False


def test_update_profiles_resets_risk_when_no_reasons(
    profiles: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """本轮没有理由 → 风险归零、理由清空、风险时间置空（否则陈旧风险永远挂在 TOP 上）。"""
    row = _profile(
        profiles, risk_score=0.9, anomalies=["新源 IP：1.2.3.4"], risk_at=datetime.now(UTC)
    )
    monkeypatch.setattr(profiles, "SessionLocal", lambda: _FakeSession(row))
    result = profiles.update_profiles({"session|k": _obs(src_ips=["10.0.0.1"])}, {})
    assert result == {"created": 0, "updated": 1}
    assert row.risk_score == 0.0
    assert row.anomalies == []
    assert row.risk_at is None


def test_update_profiles_writes_risk_and_time(
    profiles: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = _profile(profiles, risk_score=0.0, anomalies=[])
    monkeypatch.setattr(profiles, "SessionLocal", lambda: _FakeSession(row))
    risks = {"session|k": {"risk": 0.8, "reasons": ["会话跨 2 个同族源 IP（疑似会话劫持）"]}}
    profiles.update_profiles({"session|k": _obs(src_ips=["10.0.0.1"])}, risks)
    assert row.risk_score == pytest.approx(0.8)
    assert row.anomalies == ["会话跨 2 个同族源 IP（疑似会话劫持）"]
    assert row.risk_at is not None


def test_profile_dict_exposes_risk_at(profiles: ModuleType) -> None:
    row = _profile(profiles, risk_score=0.8, anomalies=["x"], risk_at=None)
    assert profiles._profile_dict(row)["risk_at"] is None
    stamp = datetime.now(UTC)
    row.risk_at = stamp
    assert profiles._profile_dict(row)["risk_at"] == stamp.isoformat()


def _where_of(statement: str) -> str:
    """取 SQL 的 WHERE 段（`risk_at` 本来就在 SELECT 列表里，不能拿全文当依据）。"""
    return statement.split("WHERE")[-1]


def test_top_anomalies_only_lists_current_risk(
    profiles: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """「画像风险 TOP」是**当前**风险：必须按 risk_at 过滤掉过期判定。

    回归背景：归零只在「实体又被观测到」时发生，会话结束后该行永远留着旧风险，
    实机就有 4 条 2~4 小时前的风险一直挂在 TOP 上。
    """
    session = _FakeSession(row=None, rows=[])
    monkeypatch.setattr(profiles, "SessionLocal", lambda: session)
    out = profiles.top_anomalies(5)
    assert out["ttl_minutes"] == 60
    where = _where_of(session.statements[0])
    assert "risk_score" in where
    assert "risk_at" in where, session.statements[0]


def test_top_anomalies_can_be_unfiltered(
    profiles: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TTL=0 = 不过滤（当历史榜单看），此时 WHERE 里不该出现 risk_at。"""
    from types import SimpleNamespace

    session = _FakeSession(row=None, rows=[])
    monkeypatch.setattr(profiles, "SessionLocal", lambda: session)
    monkeypatch.setattr(
        profiles,
        "settings",
        SimpleNamespace(profile_risk_threshold=0.6, profile_risk_ttl_minutes=0),
    )
    out = profiles.top_anomalies(5)
    assert out["ttl_minutes"] == 0
    assert "risk_at" not in _where_of(session.statements[0]), session.statements[0]


def test_cleanup_prunes_old_static_paths(
    profiles: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """清理做两件事：删过期画像 + 剔除不合口径的旧路径。

    为什么路径自愈放在这里：口径是后加上的，老库里积了一堆静态资源路径（实测某环境 3934 条），
    只靠「该画像又被观测到」的话，不再活跃的画像永远不会清。
    """
    statements: list[str] = []
    row = _profile(profiles)
    row.paths = {"/seeyon/rest/keep": 1, "/seeyon/x/a.css": 2, "/img/b.png": 3}
    untouched = _profile(profiles)
    untouched.paths = {"/seeyon/rest/other": 5}

    class _Session:
        def execute(self, stmt: Any) -> Any:
            from types import SimpleNamespace

            statements.append(str(stmt))
            return SimpleNamespace(rowcount=4)

        def scalars(self, _stmt: Any) -> Any:
            from types import SimpleNamespace

            return SimpleNamespace(all=lambda: [row, untouched])

        def commit(self) -> None:
            return None

        def __enter__(self) -> Self:
            return self

        def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
            return False

    monkeypatch.setattr(profiles, "SessionLocal", _Session)
    out = profiles.cleanup()
    assert out == {"deleted": 4, "pruned": 2}
    assert row.paths == {"/seeyon/rest/keep": 1}
    assert untouched.paths == {"/seeyon/rest/other": 5}  # 合口径的不动
    assert statements and "DELETE FROM entity_profiles" in statements[0]
