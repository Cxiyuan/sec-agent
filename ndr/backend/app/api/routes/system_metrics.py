"""服务器状态（总览页的 CPU / 内存 / 磁盘三个圆环）：容器内读 `/proc` + 根分区用量。

**为什么在容器里读就够**：backend 容器**没有设 CPU/内存限额**（compose 里没写
`mem_limit`/`cpus`），未设限额的容器里 `/proc/meminfo`、`/proc/stat` 读到的就是宿主的值；
`shutil.disk_usage("/")` 也是宿主根分区（docker 的 overlay 与 ES 数据卷都在上面）。
因此不需要挂载宿主 `/proc`、也不需要引入 `psutil`。
**前提**：若以后给 backend 加了 `mem_limit`/`cpus`，`/proc` 视图仍是宿主的（cgroup 不改它），
但要改成读 cgroup 限额时只改本文件即可。

**失败语义**：任一项读不到 → 该字段 `null` + `notes` 说明，**端点不 500** ——
总览页不能因为少了一个数字就整页空白。
"""

from __future__ import annotations

import os
import shutil
import time
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User

#: 等价于 3.11 的 `datetime.UTC`（本仓库 requires-python >=3.11）；用别名写法
#: 免得按旧语法解析的静态检查工具报「unknown import symbol」。
UTC = timezone.utc

router = APIRouter(prefix="/api/system", tags=["system"])

_PROC_STAT = "/proc/stat"
_PROC_MEMINFO = "/proc/meminfo"
_PROC_LOADAVG = "/proc/loadavg"
_DISK_PATH = "/"
_KIB = 1024


def _read_text(path: str) -> str | None:
    """读一个小文本文件；读不到返回 None（调用方转成 null + note）。"""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def parse_cpu_totals(text: str) -> tuple[float, float] | None:
    """`/proc/stat` 的 `cpu` 汇总行 → `(idle 秒, total 秒)`。

    单位是 USER_HZ 的 jiffy，但占比只用到比值，所以不做换算。
    idle 取 `idle + iowait`：不然磁盘等待会被算成「忙」，负载看起来假高。
    """
    for line in text.splitlines():
        if not line.startswith("cpu "):
            continue
        try:
            values = [float(p) for p in line.split()[1:]]
        except ValueError:
            return None
        if len(values) < 5:
            return None
        return values[3] + values[4], sum(values)
    return None


def cpu_percent(
    first: tuple[float, float] | None, second: tuple[float, float] | None
) -> float | None:
    """两次采样的差值 → 忙碌占比（%）。差值<=0（计数器回绕/采样太近）返回 None。"""
    if not first or not second:
        return None
    d_idle = second[0] - first[0]
    d_total = second[1] - first[1]
    if d_total <= 0 or d_idle < 0:
        return None
    pct = (1.0 - d_idle / d_total) * 100.0
    return round(max(0.0, min(pct, 100.0)), 1)


def parse_meminfo(text: str) -> tuple[int, int] | None:
    """`/proc/meminfo` → `(used_bytes, total_bytes)`。

    用 `MemAvailable` 而不是 `MemFree` 算已用：`MemFree` 不含可回收的 page cache，
    会和 `top`/`free` 差出一大截（那是「看起来内存要满」的经典误报）。
    """
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        parts = rest.split()
        if not parts:
            continue
        try:
            values[key.strip()] = int(parts[0]) * _KIB  # kB → B
        except ValueError:
            continue
    total = values.get("MemTotal")
    if not total:
        return None
    available = values.get("MemAvailable", values.get("MemFree", 0))
    return max(0, total - available), total


def parse_loadavg(text: str) -> float | None:
    """`/proc/loadavg` 首字段 = 1 分钟平均负载。"""
    parts = text.split()
    if not parts:
        return None
    try:
        return round(float(parts[0]), 2)
    except ValueError:
        return None


def _percent(used: int | None, total: int | None) -> float | None:
    if not used or not total or total <= 0:
        return None
    return round(min(100.0, max(0.0, used * 100.0 / total)), 1)


@router.get("/metrics")
def system_metrics(_: Annotated[User, Depends(get_current_user)]):
    """CPU / 内存 / 磁盘占用（总览页三个圆环）。

    CPU 要两次采样才能算占比：间隔 `ST_SYSTEM_METRICS_CPU_SAMPLE_SECONDS`（默认 0.15s）。
    本端点是同步 `def`，FastAPI 会把它跑在线程池里，所以这点 sleep 不会卡住事件循环。
    """
    notes: list[str] = []

    stat_text = _read_text(_PROC_STAT)
    first = parse_cpu_totals(stat_text) if stat_text else None
    second = first
    if first is not None:
        time.sleep(max(0.0, float(settings.system_metrics_cpu_sample_seconds)))
        again = _read_text(_PROC_STAT)
        second = parse_cpu_totals(again) if again else None
    cpu = cpu_percent(first, second)
    if cpu is None:
        notes.append("读不到 /proc/stat（无法计算 CPU 占用）")

    mem_text = _read_text(_PROC_MEMINFO)
    mem = parse_meminfo(mem_text) if mem_text else None
    if mem is None:
        notes.append("读不到 /proc/meminfo（无法计算内存占用）")

    disk_used = disk_total = disk_percent = None
    try:
        usage = shutil.disk_usage(_DISK_PATH)
        disk_used, disk_total = int(usage.used), int(usage.total)
        disk_percent = _percent(disk_used, disk_total)
    except OSError as exc:
        notes.append(f"读不到磁盘用量：{exc}")

    load_text = _read_text(_PROC_LOADAVG)
    load_1m = parse_loadavg(load_text) if load_text else None

    return {
        "cpu_percent": cpu,
        "mem_percent": _percent(*(mem or (None, None))),
        "disk_percent": disk_percent,
        "mem_used_bytes": mem[0] if mem else None,
        "mem_total_bytes": mem[1] if mem else None,
        "disk_used_bytes": disk_used,
        "disk_total_bytes": disk_total,
        "load_1m": load_1m,
        "cpu_count": os.cpu_count(),
        "disk_path": _DISK_PATH,
        "sampled_at": datetime.now(UTC).isoformat(),
        "notes": notes,
    }
