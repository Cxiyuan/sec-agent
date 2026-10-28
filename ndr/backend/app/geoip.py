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


#: DB-IP 的省/州名是英文 → 中文（国外只显示国家，不需要省）。
#: 键同时接受英文名与 ISO 3166-2 后缀（`CN-SD` 里的 `SD`）。
_CN_PROVINCE: dict[str, str] = {
    "beijing": "北京",
    "tianjin": "天津",
    "hebei": "河北",
    "shanxi": "山西",
    "inner mongolia": "内蒙古",
    "liaoning": "辽宁",
    "jilin": "吉林",
    "heilongjiang": "黑龙江",
    "shanghai": "上海",
    "jiangsu": "江苏",
    "zhejiang": "浙江",
    "anhui": "安徽",
    "fujian": "福建",
    "jiangxi": "江西",
    "shandong": "山东",
    "henan": "河南",
    "hubei": "湖北",
    "hunan": "湖南",
    "guangdong": "广东",
    "guangxi": "广西",
    "hainan": "海南",
    "chongqing": "重庆",
    "sichuan": "四川",
    "guizhou": "贵州",
    "yunnan": "云南",
    "tibet": "西藏",
    "xizang": "西藏",
    "shaanxi": "陕西",
    "gansu": "甘肃",
    "qinghai": "青海",
    "ningxia": "宁夏",
    "xinjiang": "新疆",
    "taiwan": "台湾",
    "hong kong": "香港",
    "macau": "澳门",
    "macao": "澳门",
}


def _province_zh(subdivision: Any) -> str:
    """省/州 → 中文省名（认不出来就返回空串，让调用方回落）。"""
    names = getattr(subdivision, "names", None) or {}
    for key in ("zh-CN", "zh"):
        value = str(names.get(key) or "").strip()
        if value:
            return value
    english = str(names.get("en") or "").strip().lower()
    if english in _CN_PROVINCE:
        return _CN_PROVINCE[english]
    iso = str(getattr(subdivision, "iso_code", "") or "").strip().upper()
    if "-" in iso:
        suffix = iso.split("-", 1)[1].lower()
        for name, label in _CN_PROVINCE.items():
            if name.replace(" ", "") in (suffix, english.replace(" ", "")) or name[:2] == suffix:
                return label
    return ""


def _label(record: Any) -> str:
    """geoip2 记录 → 中文地域标签。

    口径（2026-10 用户要求）：
    - **国内**（country=CN）只显示**省份**，不再显示"中国"（例：广东、北京、香港）；
    - **国外**只显示**国家**的中文名（例：美国、日本、新加坡）；
    - **全部中文**：DB-IP 的省名是英文，靠 `_CN_PROVINCE` 映射；国家名取库里的 zh-CN 字段。
    """
    country_names = getattr(getattr(record, "country", None), "names", None) or {}
    country_zh = str(country_names.get("zh-CN") or country_names.get("zh") or "").strip()
    iso = str(getattr(getattr(record, "country", None), "iso_code", "") or "").strip().upper()
    subdivisions = list(getattr(record, "subdivisions", None) or [])

    if iso == "CN":
        for sub in subdivisions:
            province = _province_zh(sub)
            if province:
                return province
        return country_zh or "中国"

    if country_zh:
        return country_zh
    # 库里没有中文国家名（少见）：用英文名兜底，总比空着强；再不行由调用方显示「未知」
    return _name(country_names)


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


@lru_cache(maxsize=16384)
def locate(ip: str) -> dict[str, Any]:
    """结构化地域：`{country, province, city, label, lan}`。

    为什么不能只用 `resolve()` 的展示字符串做比较：那个串是给人看的（国内只到省、
    国外只到国家），拿它做"地点变没变"的判据会把「四川→广东」和「美国→日本」当成
    两种维度的比较，口径不一致。这里把国家与省分开返回，账号基线按 **国家 + 省** 比。
    """
    value = str(ip or "").strip()
    out: dict[str, Any] = {"country": "", "province": "", "city": "", "label": "", "lan": False}
    if value == "":
        return out
    try:
        from app.iputil import is_public_ip

        if not is_public_ip(value):
            out.update({"label": "局域网", "lan": True})
            return out
    except Exception as exc:  # noqa: BLE001
        log.debug("内外网判断失败，按公网查询：%s", exc)
    reader = _open()
    if reader is None:
        return out
    try:
        record = reader.city(value)
    except Exception:  # noqa: BLE001 — Country 库/地址不在库里
        try:
            record = reader.country(value)
        except Exception:  # noqa: BLE001
            return out
    country = getattr(record, "country", None)
    iso = str(getattr(country, "iso_code", "") or "").strip().upper()
    names = getattr(country, "names", None) or {}
    country_zh = str(names.get("zh-CN") or names.get("zh") or "").strip()
    province = ""
    city = ""
    for sub in list(getattr(record, "subdivisions", None) or [])[:1]:
        province = _province_zh(sub)
        if province == "":
            sub_names = getattr(sub, "names", None) or {}
            province = str(sub_names.get("zh-CN") or sub_names.get("en") or "").strip()
    city_obj = getattr(record, "city", None)
    if city_obj is not None:
        city_names = getattr(city_obj, "names", None) or {}
        city = str(city_names.get("zh-CN") or city_names.get("zh") or "").strip()
    return {
        "country": iso or country_zh,
        "country_label": country_zh,
        "province": province,
        "city": city,
        "label": _label(record),
        "lan": False,
    }


def same_place(prev: dict[str, Any] | None, cur: dict[str, Any] | None) -> bool:
    """两个地点是否算"同一个地方"（口径：**国家 + 省**）。

    局域网登录不参与比较（`lan=True` 由调用方先排除）；任一地点缺国家/省就无法比较，
    按"相同"处理（宁可不报，也不凭空造一条异地事实）。
    """
    if not prev or not cur:
        return True
    if prev.get("lan") or cur.get("lan"):
        return True
    pc, cc = str(prev.get("country") or ""), str(cur.get("country") or "")
    pp, cp = str(prev.get("province") or ""), str(cur.get("province") or "")
    if pc == "" or cc == "":
        return True
    if pp == "" or cp == "":
        return pc == cc
    return pc == cc and pp == cp
