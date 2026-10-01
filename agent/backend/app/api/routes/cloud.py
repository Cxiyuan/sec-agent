"""云端模型 API key 管理：后台界面录入，保存到数据库（不落环境变量）。"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.cloud_config import CLOUD_API_KEY_CONFIG, cloud_api_key, mask_key
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.runtime_config import invalidate as invalidate_runtime_config

router = APIRouter(prefix="/api/cloud", tags=["cloud"])


class CloudKeyIn(BaseModel):
    api_key: str


@router.get("")
def get_cloud(_: Annotated[User, Depends(get_current_user)]):
    """返回 key 是否已配置 + 脱敏展示（不回传明文）。"""
    key = cloud_api_key()
    return {"api_key_set": bool(key), "api_key_masked": mask_key(key)}


@router.put("/key")
def set_cloud_key(
    body: CloudKeyIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    key = (body.api_key or "").strip()
    row = db.get(SystemConfig, CLOUD_API_KEY_CONFIG)
    if row is None:
        row = SystemConfig(key=CLOUD_API_KEY_CONFIG, value={})
        db.add(row)
    row.value = {"value": key}
    db.commit()
    invalidate_runtime_config()
    return {"api_key_set": bool(key), "api_key_masked": mask_key(key)}
