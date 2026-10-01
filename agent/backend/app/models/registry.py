"""模型解析：角色 → 固化模型名（MiniMax 国内版）。

界面不暴露 MiniMax 模型名，只保留角色名（flash / deep / embo-db / embo-query）：
- flash      → MiniMax-M2.7（日常分析：异常确认/定级/处置/报告正文）
- deep       → MiniMax-M3（深度分析：攻击链还原/攻击者画像）
- embo_db    → embo-01（向量入库，type=db）
- embo_query → embo-01（向量查询，type=query）
"""

from __future__ import annotations

MODEL_NAMES: dict[str, str] = {
    "flash": "MiniMax-M2.7",
    "deep": "MiniMax-M3",
    "embo_db": "embo-01",
    "embo_query": "embo-01",
}


def resolve_model(role: str) -> str:
    """按角色取固化模型名；未知角色原样返回。"""
    return MODEL_NAMES.get(role, role)


def invalidate_model_cache() -> None:
    """保留接口兼容：模型名已固化，无需失效缓存。"""


def current_models() -> dict[str, str]:
    """当前生效的模型名（用于 /api/health 运维排障）。"""
    return dict(MODEL_NAMES)
