"""IP → 地域（可视化流量页的「访问地域 TOP5」）。

**为什么是可选能力**：地域要靠一份离线地理库（`.mmdb`）。产品不随包带库（几十 MB，
且分发有许可约束），部署时把库文件挂进容器、用 `ST_GEOIP_DB` 指向它即可。没配库时
`available=False`，地域一栏统一显示「未知」，界面上明说原因 —— 不假装有数据。

**绝不联网**：只查本地库，不把访问地址发给任何外部服务（客户流量的源 IP 属敏感数据）。

库类型兼容：`City` 库能给出「国家 省 市」，`Country` 库只到国家 —— 代码先用 `city()`，
拿到 `AddressNotFoundError` / `ValueError`（Country 库不支持 city）时退回 `country()`，
两种库都能用。
"""

from __future__ import annotations

import threading
from functools import lru_cache
from typing import Any

from app.config import settings
from app.workers.log import get_logger

log = get_logger(__name__)

#: 地域标签的分隔符（界面直接当文本显示）
SEP = " "
#: 查不到 / 没配库时的占位
UNKNOWN = "未知"

_lock = threading.Lock()
_reader: Any = None
_reader_path = ""
_reader_error = ""


def _db_path() -> str:
    return str(getattr(settings, "geoip_db", "") or "").strip()


def _open() -> Any:
    """打开地理库（进程内单例；路径变了才重新打开）。失败只记一次，不反复重试。"""
    global _reader, _reader_path, _reader_error
    path = _db_path()
    if not path:
        return None
    with _lock:
        if _reader is not None and _reader_path == path:
            return _reader
        if _reader_path == path and _reader_error:
            return None
        _reader_path = path
        try:
            from geoip2.database import Reader

            _reader = Reader(path)
            _reader_error = ""
            log.info("地理库已加载：%s", path)
        except Exception as exc:  # noqa: BLE001 — 库缺失/损坏都不能挡住流量页
            _reader = None
            _reader_error = f"地理库打开失败：{exc}"[:200]
            log.warning("地理库不可用（%s）：%s", path, exc)
        return _reader


def _name(names: Any) -> str:
    """多语言名字字典 → 取中文名，回落英文名。"""
    if not isinstance(names, dict):
        return ""
    for key in ("zh-CN", "zh", "en"):
        value = str(names.get(key) or "").strip()
        if value:
            return value
    return ""


def _label(record: Any) -> str:
    """geoip2 记录 → 「国家 省 市」（缺哪级就省哪级）。"""
    parts: list[str] = []
    country = _name(getattr(getattr(record, "country", None), "names", None))
    if country:
        parts.append(country)
    subdivisions = list(getattr(record, "subdivisions", None) or [])
    if subdivisions:
        province = _name(getattr(subdivisions[0], "names", None))
        if province and province not in parts:
            parts.append(province)
    city = _name(getattr(getattr(record, "city", None), "names", None))
    if city and city not in parts:
        parts.append(city)
    return SEP.join(parts)


@lru_cache(maxsize=16384)
def _lookup(ip: str) -> str:
    reader = _open()
    if reader is None:
        return ""
    try:
        return _label(reader.city(ip))
    except Exception as exc:  # noqa: BLE001 — 地址不在库里 / Country 库不支持 city
        log.debug("city() 查询失败，退回 country()：%s", exc)
    try:
        return _label(reader.country(ip))
    except Exception:  # noqa: BLE001
        return ""


def resolve(ip: str) -> str:
    """单个地址 → 地域标签；查不到返回空串（调用方决定怎么显示）。"""
    value = str(ip or "").strip()
    if not value:
        return ""
    # 内网地址不查库（库里必然没有，还会白占缓存）
    try:
        from app.iputil import is_public_ip

        if not is_public_ip(value):
            return "内网"
    except Exception as exc:  # noqa: BLE001
        log.debug("按地址判内外网失败，按公网处理：%s", exc)
    return _lookup(value)


def region_counts(counts: dict[str, int], *, top: int = 5) -> list[dict[str, Any]]:
    """`{IP: 次数}` → 地域 TOP N（`[{"region", "count"}]`，按次数降序）。

    纯函数（`resolve` 作为函数参数注入）便于单测：地域统计不该依赖有没有库。
    """
    merged: dict[str, int] = {}
    for ip, count in (counts or {}).items():
        try:
            n = int(count)
        except (TypeError, ValueError):
            continue
        if n <= 0:
            continue
        label = resolve(ip) or UNKNOWN
        merged[label] = merged.get(label, 0) + n
    items = [{"region": k, "count": v} for k, v in merged.items()]
    items.sort(key=lambda row: (-row["count"], row["region"]))
    return items[: max(1, int(top))]


def status() -> dict[str, Any]:
    """地理库现状（前端据此决定显示地域列还是「未配置」提示）。"""
    path = _db_path()
    if not path:
        return {
            "available": False,
            "db": "",
            "note": "未配置离线地理库（ST_GEOIP_DB），地域一栏显示「未知」",
        }
    ok = _open() is not None
    return {
        "available": ok,
        "db": path,
        "note": "" if ok else (_reader_error or "地理库不可用，地域一栏显示「未知」"),
    }
