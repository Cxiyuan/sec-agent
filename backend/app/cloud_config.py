"""云端模型连接（MiniMax 国内版）。

- 模型名固化在 app/models/registry.py（界面只暴露角色名 flash/deep/embo-*）
- base_url 固化在 settings.cloud_model_base_url（MiniMax 国内版）
- api_key 由后台界面录入、保存到数据库（SystemConfig），30 秒 TTL 内生效
"""

from __future__ import annotations

from app.config import settings
from app.runtime_config import get as runtime_get

# SystemConfig 键名（后台「云端模型」面板读写）
CLOUD_API_KEY_CONFIG = "cloud.api_key"


def cloud_api_key() -> str:
    """当前生效的 API key（后台配置优先，未配置返回空串）。"""
    return str(runtime_get(CLOUD_API_KEY_CONFIG, "") or "")


def cloud_base_url() -> str:
    """云端模型 base_url（固化 MiniMax 国内版）。"""
    return settings.cloud_model_base_url.rstrip("/")


def mask_key(key: str) -> str:
    """脱敏展示：只露首尾各 4 位。"""
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * 6}{key[-4:]}"
