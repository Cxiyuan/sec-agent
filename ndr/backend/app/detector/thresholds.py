"""运行阈值告警：把"看得见但不会响"的指标变成可读告警（2026-10）。

## 为什么单独一个模块

生产上这几类问题都是**静默积累**型的：Redis 键只增不减、判重登记被丢弃、内存碎片飙升、
采样通道停了。它们不会让任何接口报错，只会在某天突然"全链路卡死"（本项目踩过同源事故）。
指标本来就在 Redis 里，缺的只是"到线了就说一声"。

这里只做**判定**，不做投递：结果由一个接口统一暴露给「运营中心 → 资源/组件状态」，
以后要接告警通道（邮件/webhook）也只改这一处。

阈值都可通过环境变量调（保守取值，宁可晚报也不误报）。
"""

from __future__ import annotations

from typing import Any

from app.workers.log import get_logger

log = get_logger(__name__)

#: 判定级别（和健康检查同一套词）
OK = "ok"
WARN = "warn"
CRIT = "crit"

#: 阈值（可用环境变量覆盖：见 config.py 的 run_threshold_*）
DEFAULTS: dict[str, float] = {
    "redis_fragmentation": 1.8,  # 碎片率：>1.8 说明内存回收跟不上
    "freq_keys": 200000,  # 频率规则的键总数（含 dst）
    "handled_dropped": 0,  # 判重登记被丢弃条数：只要 >0 就说明去重已经失效
}


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _redis_memory(client: Any) -> dict[str, float]:
    """取 Redis 内存概览（info 解析，取不到的项省略）。"""
    try:
        info = client.info("memory")
    except Exception as exc:  # noqa: BLE001
        log.debug("读取 Redis 内存信息失败: %s", exc)
        return {}
    return {
        "fragmentation": _num(info.get("mem_fragmentation_ratio")),
        "peak": _num(info.get("used_memory_peak")),
    }


def _count_keys(client: Any, pattern: str, cap: int = 200000) -> int:
    """按 SCAN 抽样计数（不阻塞 Redis）；到 `cap` 就停，说明"已经很多了"。"""
    total = 0
    try:
        for _ in client.scan_iter(match=pattern, count=1000):
            total += 1
            if total >= cap:
                break
    except Exception as exc:  # noqa: BLE001
        log.debug("SCAN 计数失败（%s）: %s", pattern, exc)
    return total


def evaluate(client: Any, *, stats: dict[str, Any] | None = None) -> dict[str, Any]:
    """评估运行阈值，返回 `{level, items: [{key, level, value, threshold, detail}]}`。

    `stats` 是检测器心跳（`shentong:baseline:stats` / detector 统计），可选；
    没有它也能判——能判的项少一点而已。
    """
    stats = stats or {}
    items: list[dict[str, Any]] = []

    mem = _redis_memory(client)
    frag = mem.get("fragmentation", 0.0)
    if frag:
        limit = DEFAULTS["redis_fragmentation"]
        items.append(
            {
                "key": "redis_fragmentation",
                "level": CRIT if frag >= limit * 1.5 else (WARN if frag >= limit else OK),
                "value": round(frag, 2),
                "threshold": limit,
                "detail": "Redis 内存碎片率（越高说明释放的内存回不去，容易 OOM）",
            }
        )

    freq_keys = _count_keys(client, "shentong:freq:*")
    limit = DEFAULTS["freq_keys"]
    items.append(
        {
            "key": "freq_keys",
            "level": WARN if freq_keys >= limit else OK,
            "value": freq_keys,
            "threshold": limit,
            "detail": "频率规则键总数（只应随规则数收敛；只增不减说明 TTL 又漏了）",
        }
    )

    dropped = _num(stats.get("handled_dropped", stats.get("dropped_handled", 0)))
    items.append(
        {
            "key": "handled_dropped",
            "level": CRIT if dropped > 0 else OK,
            "value": int(dropped),
            "threshold": DEFAULTS["handled_dropped"],
            "detail": "判重登记被丢弃条数（>0 = 去重已失效，重复文档会被重复分析）",
        }
    )

    # 基线采样通道活性：窗口采样停了，数值基线就退回"只学命中规则的流量"
    sampled = _num(stats.get("baseline_sampled", 0))
    if stats:
        items.append(
            {
                "key": "baseline_sampled",
                "level": OK if sampled > 0 else WARN,
                "value": int(sampled),
                "threshold": 1,
                "detail": "数值基线窗口采样条数（0 = 采样通道没在跑，基线会空转）",
            }
        )

    level = OK
    for item in items:
        if item["level"] == CRIT:
            level = CRIT
            break
        if item["level"] == WARN:
            level = WARN
    return {"level": level, "items": items}
