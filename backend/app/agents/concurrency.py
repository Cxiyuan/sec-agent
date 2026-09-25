"""批内并发工具：线程池 + 动态并发度（边缘 / 云端分开治理）。

为什么单独一个模块：``nodes.py`` 与 ``deep_analysis.py`` 都要用；跨模块 import 私有函数
（下划线开头）是坏味道，所以抽成公开模块。

两类并发度的分工：
- **边缘**（本地 llama.cpp）：并发就是吞吐本身（多请求共享权重读取），所以尽量给满，
  上限对齐服务器槽位数。
- **云端**（MiniMax）：并发受 RPM/TPM 限流约束，只是"减少串行等待"，给大了会吃 429。
  所以线程池大小与 ``llm.py`` 的云端闸门取同一个配置（闸门控真实峰值，池子只控线程数）。
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app import runtime_config
from app.config import settings
from app.workers.log import get_logger

log = get_logger(__name__)

# 上限对齐边缘服务器槽位数（--parallel 16），再多只会排队
MAX_WORKERS = 16


def _as_int(value: Any, default: int) -> int:
    """安全转 int（后台配置可能是字符串或脏值）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def edge_concurrency() -> int:
    """边缘模型批内并发度（后台可调，默认 8）。

    服务器实测（2026-09-25 预热后）：并发 1 → ~5 次/分，4 → 17，8 → 23，16 → 26.5。
    CPU 上合批是唯一的吞吐杠杆（多请求共享同一次权重读取），所以并发度直接决定吞吐。
    """
    workers = _as_int(
        runtime_config.get("edge_review_concurrency", settings.edge_review_concurrency),
        settings.edge_review_concurrency,
    )
    return max(1, min(workers, MAX_WORKERS))


def cloud_concurrency() -> int:
    """云端模型批内并发度（后台可调，默认 4）。"""
    workers = _as_int(
        runtime_config.get("cloud_max_concurrency", settings.cloud_max_concurrency),
        settings.cloud_max_concurrency,
    )
    return max(1, min(workers, MAX_WORKERS))


def parallel_map(
    fn: Callable[[Any], Any], items: list[Any], prefix: str, *, workers: int | None = None
) -> list[Any]:
    """批内并发（线程池）；**返回顺序与输入严格一致**。

    调用方是同步阻塞的 HTTP 请求（边缘模型 / 云端模型），用线程池即可。
    workers=1 或只有 1 条时退化为串行（省线程开销）。
    """
    if not items:
        return []
    default = edge_concurrency() if workers is None else workers
    pool_size = min(max(1, default), len(items))
    if pool_size <= 1:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix=prefix) as pool:
        return list(pool.map(fn, items))
