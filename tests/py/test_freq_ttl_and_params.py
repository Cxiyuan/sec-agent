"""批 1 缺陷修复的守卫（2026-10 行为分析误报治理，生产实测驱动）。

三条都是"生产上真的在漏"的东西，不是风格偏好：

1. **freq `dst` 键 TTL 泄漏**：pipeline 里 `expire` 建键前执行 → 首次插入的键永久无 TTL
   （实测 62,695 个 dst 键里 94.5% `TTL=-1`）。Redis 是 `noeviction`，只增不减 → 迟早卡死。
2. **判重登记桶打顶**：单桶 5 万在 ~210 条/秒下 4 分钟填满，之后全部丢弃 → 去重实质失效
   （实测 25 分钟丢 24 万+）。
3. **默认参数对"多弱信号叠加"太松**：单强信号(0.45)+一个弱信号就到 0.6 过线，
   而 36% 的过线会话其实是 OA 正常使用（换手机/装 App / 新接口路径）。
"""

from __future__ import annotations

import importlib
import pathlib
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
FREQ = ROOT / "ndr" / "backend" / "app" / "detector" / "frequency.py"
CONFIG = ROOT / "ndr" / "backend" / "app" / "config.py"


# ===== ① freq dst 键 TTL：zadd 必须排在 expire 之前且同在一个 pipeline =====


def test_dst_zadd_precedes_expire_in_same_pipeline() -> None:
    """先 zadd 建键、再 expire 设过期 —— 顺序反了就会出现永久无 TTL 的键。"""
    src = FREQ.read_text(encoding="utf-8")
    # 只看发放 dst 的那段（避免 cnt 键的相似代码干扰）
    seg_start = src.index("if dst_key:")
    seg = src[seg_start : seg_start + 400]
    zadd_at = seg.index("pipe.zadd(dst_key")
    expire_at = seg.index("pipe.expire(dst_key")
    assert zadd_at < expire_at, "dst 键必须先 zadd 建键再 expire，否则空键 expire 无效"


def test_no_zadd_outside_pipeline_for_dst() -> None:
    """dst 的 zadd 不能在 `pipe.execute()` 之后（老写法就是这样漏 TTL 的）。"""
    src = FREQ.read_text(encoding="utf-8")
    execute_at = src.index("pipe.execute()")
    after = src[execute_at:]
    assert "zadd(dst_key" not in after, "execute 之后再 zadd 会让新建的键拿不到 TTL"


def test_dst_value_computed_before_pipeline() -> None:
    """distinct 值要在进 pipeline 前算好（不能一边建键一边取值）。"""
    src = FREQ.read_text(encoding="utf-8")
    assert src.index("dst_value = ") < src.index("pipe = self.r.pipeline()")


# ===== ② 判重登记桶容量 =====


def test_handled_bucket_default_is_raised() -> None:
    """50k 会被 210 条/秒打顶；默认必须抬到 200k（并允许环境变量覆盖）。"""
    src = CONFIG.read_text(encoding="utf-8")
    assert "detector_handled_max_members: int = 200000" in src


# ===== ③ 默认参数：多弱信号叠加不该过线 =====


def test_default_params_are_tuned_for_production() -> None:
    """画像/基线的默认值必须与 2026-10 生产实测口径一致。"""
    src = CONFIG.read_text(encoding="utf-8")
    assert "profile_risk_threshold: float = 0.75" in src, "阈值 0.6 会让单强+弱信号过线"
    assert "profile_min_windows: int = 10" in src, "冷启动 5 窗口对短命会话等于没学完就打分"
    assert "baseline_std_floor_min: float = 2.0" in src, (
        "distinct_* 均值 1.1，floor=1.0 时 4 个目的 IP 就判偏离"
    )


# ===== ④ 孤儿 dst 键清理工具（默认 dry-run）=====


class FakeRedis:
    """够用的假 Redis：只有 SCAN / TTL / ZRANGE / UNLINK。"""

    def __init__(self, keys: dict[str, tuple[int, list[tuple[str, float]]]]) -> None:
        # key -> (ttl, [(member, score), ...])
        self.keys = dict(keys)
        self.unlinked: list[str] = []

    def scan_iter(self, match: str = "*", count: int = 500) -> Any:
        # 按 glob 语义拆成「前缀 … 后缀」两段匹配（`*` 只出现在中间）
        prefix, _, suffix = match.partition("*")
        for key in list(self.keys):
            if not key.startswith(prefix):
                continue
            if suffix and not key.endswith(suffix):
                continue
            yield key

    def ttl(self, key: str) -> int:
        if key not in self.keys:
            return -2
        return self.keys[key][0]

    def zrange(self, key: str, start: int, end: int, withscores: bool = False) -> Any:
        members = sorted(self.keys.get(key, (0, []))[1], key=lambda m: m[1])
        if not members:
            return []
        pick = members[start : (None if end == -1 else end + 1)]
        return [(m, s) for m, s in pick] if withscores else [m for m, _ in pick]

    def unlink(self, key: str) -> int:
        self.unlinked.append(key)
        return 1


def _cleanup_mod() -> Any:
    """取清理工具模块；agent 栈没有检测器（`app.detector` 不存在）→ 跳过。

    本文件其余用例读的是**仓库内绝对路径**（ndr/backend/...），两栈都能跑；
    只有清理工具的运行时用例依赖 NDR 侧的 `app.detector` 包。
    """
    try:
        return importlib.import_module("app.detector.freq_cleanup")
    except ModuleNotFoundError:  # pragma: no cover - agent 栈
        pytest.skip("agent 栈没有检测器模块（freq_cleanup 属 NDR 侧）")


def test_cleanup_dry_run_deletes_nothing() -> None:
    mod = _cleanup_mod()
    now = 1_000_000.0
    fake = FakeRedis(
        {
            "shentong:freq:ruleA:1.2.3.4:dst": (-1, [("a", now - 9000)]),  # 无 TTL + 老 → 孤儿
            "shentong:freq:ruleA:1.2.3.5:dst": (600, [("b", now - 9000)]),  # 有 TTL → 不动
            "shentong:freq:ruleB:1.2.3.6:dst": (-1, [("c", now - 30)]),  # 无 TTL 但活跃 → 不动
            "shentong:freq:ruleB:1.2.3.7:cnt": (-1, [("d", now - 9000)]),  # 不是 dst 键 → 不扫
        }
    )
    stats = mod.cleanup_orphan_dst_keys(fake, execute=False, older_than_seconds=7200, now=now)
    assert stats["scanned"] == 3
    assert stats["with_ttl"] == 1
    assert stats["active"] == 1
    assert stats["orphans"] == 1
    assert stats["deleted"] == 0
    assert fake.unlinked == []


def test_cleanup_execute_deletes_only_orphans() -> None:
    mod = _cleanup_mod()
    now = 1_000_000.0
    fake = FakeRedis(
        {
            "shentong:freq:r:1:dst": (-1, [("a", now - 9000)]),
            "shentong:freq:r:2:dst": (-1, [("b", now - 9000)]),
            "shentong:freq:r:3:dst": (300, [("c", now - 9000)]),
        }
    )
    stats = mod.cleanup_orphan_dst_keys(fake, execute=True, older_than_seconds=7200, now=now)
    assert stats["orphans"] == 2
    assert stats["deleted"] == 2
    assert sorted(fake.unlinked) == ["shentong:freq:r:1:dst", "shentong:freq:r:2:dst"]


def test_cleanup_empty_zset_counts_as_orphan() -> None:
    """空 ZSET 没有成员也没有 TTL —— 留着没价值，算孤儿。"""
    mod = _cleanup_mod()
    fake = FakeRedis({"shentong:freq:r:1:dst": (-1, [])})
    stats = mod.cleanup_orphan_dst_keys(fake, execute=False, now=1_000_000.0)
    assert stats["orphans"] == 1


def test_cleanup_respects_limit() -> None:
    mod = _cleanup_mod()
    now = 1_000_000.0
    fake = FakeRedis({f"shentong:freq:r:{i}:dst": (-1, [("a", now - 9000)]) for i in range(10)})
    stats = mod.cleanup_orphan_dst_keys(fake, execute=False, now=now, limit=3)
    assert stats["orphans"] == 3


def test_cleanup_requires_evidence_of_age() -> None:
    """没有成员分数的键（异常数据）不能当孤儿删掉 —— 宁可留着。"""
    mod = _cleanup_mod()

    class Weird(FakeRedis):
        def zrange(self, key: str, start: int, end: int, withscores: bool = False) -> Any:
            return [("x", "not-a-number")]

    fake = Weird({"shentong:freq:r:1:dst": (-1, [])})
    assert mod.is_orphan(fake, "shentong:freq:r:1:dst", 1_000_000.0, 7200) is False


@pytest.mark.parametrize("older_than", [60, 7200, 86400])
def test_orphan_age_threshold_is_honoured(older_than: int) -> None:
    mod = _cleanup_mod()
    now = 1_000_000.0
    fake = FakeRedis({"shentong:freq:r:1:dst": (-1, [("a", now - 3600)])})
    expect = 3600 >= older_than
    assert mod.is_orphan(fake, "shentong:freq:r:1:dst", now, older_than) is expect
