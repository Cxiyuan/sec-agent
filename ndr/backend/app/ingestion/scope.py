"""监控网段：一份多行清单（一行一条 CIDR/IP），驱动抓包范围与分析范围。

清单是**唯一来源**，存在 SystemConfig 的 `zeek.monitored_nets` 键里（换行分隔）。
由此生成两个值，保证「抓什么就分析什么」：

- `bpf_filter`：Zeek 只抓这些网段（`net X` 在 BPF 里本身即「源或目的落在 X」）；
- `local_nets`：Zeek 的 `Site::local_nets`，规则里的 src_internal / dst_internal 依赖它。

检测器的网段过滤（`app.detector.runner._load_scopes`）读同一份清单。

原「分析网段」（AnalysisScope 多套网段组）已并入本清单 —— 一套概念，不再分组。
"""

from __future__ import annotations

import ipaddress

from app.db.base import SessionLocal
from app.db.models import SystemConfig
from app.workers.log import get_logger

log = get_logger(__name__)

#: 清单在 SystemConfig 里的键
MONITORED_NETS_KEY = "zeek.monitored_nets"
#: 条数上限（BPF 表达式会随条数线性变长，太长的表达式交给内核也会被拒）
MAX_NETS = 200


def is_valid_ip_or_cidr(value: str) -> bool:
    """合法单机 IP，或标准 CIDR 网段（主机位必须为 0，排除 /32、/128）。"""
    v = (value or "").strip()
    if not v:
        return False
    try:
        if "/" in v:
            net = ipaddress.ip_network(v, strict=True)
            return net.prefixlen < net.max_prefixlen
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def parse_nets(text: str) -> list[str]:
    """多行 / 逗号分隔的输入 → 去重保序的清单（忽略空行、`#` 注释与重复项）。"""
    out: list[str] = []
    seen: set[str] = set()
    for chunk in (text or "").replace(",", "\n").splitlines():
        value = chunk.strip()
        if not value or value.startswith("#") or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def nets_text(nets: list[str]) -> str:
    """清单 → 存库与回显用的换行文本。"""
    return "\n".join(nets)


def validate_nets(nets: list[str]) -> list[dict[str, str]]:
    """校验清单，返回字段级错误列表（空列表 = 通过）。"""
    errors: list[dict[str, str]] = []
    if not nets:
        errors.append({"field": "networks", "msg": "必须至少填写一个网段或 IP"})
    if len(nets) > MAX_NETS:
        errors.append({"field": "networks", "msg": f"最多 {MAX_NETS} 条"})
    for value in nets:
        if not is_valid_ip_or_cidr(value):
            errors.append({"field": "networks", "msg": f"非法 IP/CIDR：{value}"})
    return errors


def bpf_term(value: str) -> str:
    """单个网段 / IP → BPF 项：`net 10.0.0.0/8` 或 `host 10.0.0.1`。

    非法输入抛 ValueError —— 调用方先跑 `validate_nets()`。
    """
    if "/" in value:
        return f"net {ipaddress.ip_network(value, strict=True).with_prefixlen}"
    return f"host {ipaddress.ip_address(value)}"


def build_bpf(nets: list[str], extra: str = "") -> str:
    """清单 → BPF 表达式。

    多项之间是「或」：任一网段被命中就抓（`net X` 已含源与目的两个方向）。
    `extra` 是用户追加的附加条件（如 `not port 22`），与网段条件取「与」。
    """
    terms = [bpf_term(n) for n in nets]
    expr = " or ".join(terms)
    if len(terms) > 1:
        expr = f"({expr})"
    extra = (extra or "").strip()
    if expr and extra:
        return f"{expr} and ({extra})"
    return expr or extra


def monitored_nets() -> list[str]:
    """当前监控网段清单（去重保序）。读库出错时返回空（等价于不分析任何日志）。"""
    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, MONITORED_NETS_KEY)
    except Exception as exc:  # noqa: BLE001
        log.warning("读取监控网段失败: %s", exc)
        return []
    if row is None or not isinstance(row.value, dict):
        return []
    return parse_nets(str(row.value.get("value") or ""))


def networks_status() -> dict[str, int | bool]:
    """供前端首次向导判断：是否已配置监控网段。"""
    nets = monitored_nets()
    return {"configured": bool(nets), "count": len(nets)}
