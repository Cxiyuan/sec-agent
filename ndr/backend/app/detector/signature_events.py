"""签名告警的**事件类型**（替代原来的「签名命中(高/中/低危)」包装规则）。

## 为什么要这个模块

签名引擎的告警本身没有"事件类型"这个概念 —— Suricata 只告诉你"某条签名命中了一条流"，
签名归类在 `alert.category`（classtype，例如 `Web Application Attack` /
`Detection of a Network Scan` / `Attempted Administrator Privilege Gain`）。

旧实现用三条**包装规则**（「签名命中(高危)」「签名命中(中危)」「签名命中(低危)」）把签名告警
转成事件，于是：
- 规则管理里出现三条"不是检测逻辑、只是分流"的假规则；
- 事件类型只能看到 `signature_hit`，看不出这次到底是什么事。

现在改成：**告警直接按 classtype 归类成事件类型**（Web 应用攻击 / 网络扫描 / 账号口令攻击…），
规则表里不再有"签名命中"，事件类型也不再是内部码。

## 口径

- 事件类型 = classtype 的中文归类（映射表在 `detector/hits.py`，与事件标题共用一份，
  避免两处漂移）；
- 严重度 = Suricata 的 `alert.severity`（1=high、2=medium、其它=low）；
- 认不出归类时退到「其它可疑活动」，绝不退回"签名命中"这种笼统说法。
"""

from __future__ import annotations

from typing import Any

from app.detector.hits import signature_category_label, signature_hint
from app.workers.log import get_logger

log = get_logger(__name__)

#: 合成规则用的来源标记（事件详情里能看出这条是签名引擎产出的）
SOURCE = "signature"
#: 认不出归类时的兜底事件类型
FALLBACK_LABEL = "其它可疑活动"

_SEVERITY_BY_LEVEL = {1: "high", 2: "medium"}


def is_signature_alert(entry: Any) -> bool:
    """这条归一化事件是不是签名引擎告警。"""
    return str(getattr(entry, "event_type", "") or "") == "signature_hit"


def _category_of(entry: Any) -> str:
    """取签名归类（classtype）。归一化层把签名相关字段平铺在文档顶层与 `alert` 里。"""
    raw = getattr(entry, "raw", None)
    digest = raw if isinstance(raw, dict) else {}
    category, _signature, _sid = signature_hint(
        {
            "signature_category": getattr(entry, "signature_category", ""),
            "signature": getattr(entry, "signature", ""),
            "signature_id": getattr(entry, "signature_id", ""),
            "alert": digest.get("alert") if isinstance(digest, dict) else None,
        }
    )
    return category


def type_label_of(entry: Any) -> str:
    """事件类型（中文）：Web 应用攻击 / 网络扫描 / 账号口令攻击 …"""
    return signature_category_label(_category_of(entry)) or FALLBACK_LABEL


def severity_of(entry: Any) -> str:
    """事件严重度：沿用 Suricata 的 alert.severity（1/2/其它）。"""
    raw = getattr(entry, "raw", None)
    digest = raw if isinstance(raw, dict) else {}
    alert = digest.get("alert") if isinstance(digest, dict) else None
    level = alert.get("severity") if isinstance(alert, dict) else None
    if level is None:
        level = getattr(entry, "signature_severity", None)
    try:
        return _SEVERITY_BY_LEVEL.get(int(level), "low")  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "low"


def rule_of(entry: Any) -> dict[str, Any]:
    """给签名告警合成一条"规则"，让下游（聚合/落库）照常工作。

    名字就是**事件类型**（Web 应用攻击…），不是"签名命中(高危)"。
    """
    return {
        "name": type_label_of(entry),
        "description": f"签名引擎告警归类：{type_label_of(entry)}",
        "source": SOURCE,
        "severity": severity_of(entry),
        # 合成规则没有判据：匹配与否由 `is_signature_alert()` 决定，不走规则引擎
        "conditions": {},
    }
