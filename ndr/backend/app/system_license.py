"""设备授权ID：由硬件机器码派生的 **8 位**身份串（大写字母 + 数字）。

为什么需要：智能体按**项目组织**隔离数据，而"一个项目"对应的就是一台 NDR。
两边需要一个稳定、不用人工编造的标识来对上号 —— 用硬件机器码派生：

- 同一台机器（重建容器、重装系统）不变；
- 换一台机器就变（这正是"绑定要跟着硬件走"的语义）；
- 不需要部署时填任何东西，也不会因为忘填而写到归属不明的库。

**它是身份，不是密钥**：可以展示、可以抄写、泄露不导致越权；
鉴权仍靠每项目的 MCP 令牌与门铃推送令牌。

派生口径：`/sys/class/dmi/id/product_uuid`（硬件 UUID，容器内可直接读宿主）→
`/etc/machine-id`（系统安装标识）→ 主机名。取 SHA-256 后 5 字节（40 bit）按
RFC 4648 Base32 编码 8 位 —— 40 bit 对几千个部署的碰撞概率可以忽略。
"""

from __future__ import annotations

import hashlib
import socket
from pathlib import Path
from typing import Any

#: RFC 4648 Base32：大写字母 + 数字 2~7（不含容易看错的 0/1）
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

#: 硬件 UUID（容器里读到的就是宿主机的；虚拟机上就是这台 VM 的）
_DMI_UUID = Path("/sys/class/dmi/id/product_uuid")
#: 系统安装标识（重装系统会变）
_MACHINE_ID = Path("/etc/machine-id")

#: 派生时加的固定域分隔，避免与其他系统的哈希撞口径
_DOMAIN = "shentong-ndr:project:"

SOURCE_LABELS: dict[str, str] = {
    "hardware": "硬件 UUID（换机才会变）",
    "machine-id": "系统安装标识（重装系统会变）",
    "hostname": "主机名兜底（不稳定，建议检查 /sys/class/dmi/id/product_uuid 是否可读）",
}

_cache: dict[str, Any] | None = None


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return ""


def machine_code() -> tuple[str, str]:
    """返回 (机器码, 来源)。来源只用于界面提示，不外泄机器码本身。"""
    for path, source in ((_DMI_UUID, "hardware"), (_MACHINE_ID, "machine-id")):
        value = _read(path)
        if value:
            return value, source
    return socket.gethostname().strip() or "unknown-host", "hostname"


def encode_auth_id(seed: str) -> str:
    """把任意种子稳定地映射成 8 位大写字母+数字（纯函数，便于测）。"""
    digest = hashlib.sha256((_DOMAIN + str(seed or "")).encode("utf-8")).digest()
    value = int.from_bytes(digest[:5], "big")  # 40 bit
    return "".join(_ALPHABET[(value >> shift) & 0x1F] for shift in range(35, -1, -5))


def license_info(*, refresh: bool = False) -> dict[str, Any]:
    """本机授权信息：`{auth_id, source, source_label, stable}`。

    进程内缓存：机器码在进程生命周期里不会变（换机必须重启容器）。
    """
    global _cache
    if _cache is not None and not refresh:
        return dict(_cache)
    code, source = machine_code()
    info = {
        "auth_id": encode_auth_id(code),
        "source": source,
        "source_label": SOURCE_LABELS.get(source, source),
        # 主机名兜底时换主机名就会换 ID —— 界面要能提示"这不稳"
        "stable": source != "hostname",
    }
    _cache = info
    return dict(info)


def auth_id() -> str:
    """只要 8 位授权ID（门铃、MCP 响应头、绑定校验都用它）。"""
    return str(license_info()["auth_id"])


def reset_cache() -> None:
    """测试用：丢掉缓存，让下一次重新读机器码。"""
    global _cache
    _cache = None
