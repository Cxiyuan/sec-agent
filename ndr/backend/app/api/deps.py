"""认证依赖：JWT 签发/校验 + 密码哈希。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import FACTORY_ADMIN_PASSWORD, settings
from app.db.base import get_db
from app.db.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def is_factory_password_hash(password_hash: str) -> bool:
    """库里这份哈希是不是「出厂默认口令」admin123。

    比的是**常量** `FACTORY_ADMIN_PASSWORD` 而不是 `settings.default_admin_password`：
    运维若用 `ST_DEFAULT_ADMIN_PASSWORD` 换过建号口令，那条口令就不是出厂默认值，
    这里必须如实返回 False，否则界面会一直提示「默认口令在用」。
    """
    return verify_password(FACTORY_ADMIN_PASSWORD, password_hash)


def default_password_in_use(db: Session) -> bool:
    """默认管理员账号当前是否仍在用出厂默认口令（启动告警 + 界面提示用）。"""
    user = db.execute(
        select(User).where(User.username == settings.default_admin_username)
    ).scalar_one_or_none()
    return user is not None and is_factory_password_hash(user.password_hash)


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(UTC) + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        username = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效凭证")
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户不存在")
    return user
