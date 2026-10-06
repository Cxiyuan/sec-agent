"""会话 cookie 的识别与取值（**唯一事实来源**）。

为什么要单独一份（2026-10 实机数据）：内置「会话跨IP复用」（critical 级）原来把**整条
Cookie 头**当会话标识，于是任何「跨用户恒定」的 cookie 都会撞车 —— 实测近 12 小时里：
`Path=/`（应用用 `document.cookie = "Path=/"` 造出的常量 cookie）跨 2 个源 IP、
`EPORTAL_COOKIE_PASSWORD=` 空值模板跨 **164** 个源 IP ⇒ 该规则产出的 337 条 critical 摘要里
**没有一条**是真会话劫持。所以会话标识必须**按名字**从 Cookie 头里精确取（名单可配），
并且要求值**非空**。

同一份逻辑也给基线画像的「会话实体」用（`app/baseline/profile.py` 转发到这里），
避免「会话劫持判据」与「会话实体」两份实现慢慢漂移。
"""

from __future__ import annotations

from typing import Any


def session_cookie_names(csv_value: Any) -> frozenset[str]:
    """把 `ST_SESSION_COOKIE_NAMES`（逗号分隔）解析成小写名字集合。"""
    return frozenset(
        part.strip().lower() for part in str(csv_value or "").split(",") if part.strip()
    )


def session_id_from_cookie(cookie: str, names_csv: Any = "") -> str:
    """从 Cookie 串里取会话 id：按名字**精确**匹配、取第一个**非空**值（带引号时去引号）。

    两道闸门缺一不可：

    - **名字精确匹配**（不做子串）：`Path` / `EPORTAL_COOKIE_PASSWORD` 这类不在名单里 ⇒
      常量 cookie 与「存密码的 cookie」都不会被当成会话标识；
    - **值必须非空**：`EPORTAL_COOKIE_PASSWORD=` 这种空值模板即使名字进了名单也会被跳过。
    """
    text = str(cookie or "")
    if not text:
        return ""
    names = session_cookie_names(names_csv)
    if not names:
        return ""
    for part in text.split(";"):
        name, sep, value = part.partition("=")
        if not sep:
            continue
        if name.strip().lower() in names:
            cleaned = value.strip().strip('"')
            if cleaned:
                return cleaned
    return ""
