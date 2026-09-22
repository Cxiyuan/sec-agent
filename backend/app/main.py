"""FastAPI 应用入口。"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api.deps import hash_password
from app.api.router import api_router
from app.api.routes.ws import start_listener
from app.config import settings
from app.db.base import Base, SessionLocal, engine
from app.db.models import Rule, User
from app.rules.builtin import BUILTIN_RULES

# 幂等补列/补索引：保证已有库平滑升级（新列均有默认值，不破坏旧数据）
_MIGRATIONS = (
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS is_external BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS allow_ip_share BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64) NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS ix_documents_content_hash ON documents (content_hash)",
)


def _migrate() -> None:
    with engine.begin() as conn:
        for stmt in _MIGRATIONS:
            conn.exec_driver_sql(stmt)


def _seed() -> None:
    """幂等初始化：建 pgvector 扩展、建表、补列、默认管理员、内置规则与拓扑节点类型。"""
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE EXTENSION IF NOT EXISTS vector")
    Base.metadata.create_all(engine)
    _migrate()
    with SessionLocal() as db:
        if (
            db.execute(
                select(User).where(User.username == settings.default_admin_username)
            ).scalar_one_or_none()
            is None
        ):
            db.add(
                User(
                    username=settings.default_admin_username,
                    password_hash=hash_password(settings.default_admin_password),
                    role="admin",
                )
            )
        for r in BUILTIN_RULES:
            exists = db.execute(select(Rule).where(Rule.name == r["name"])).scalar_one_or_none()
            if exists is None:
                db.add(Rule(**r))
        db.commit()

    from app.topology.service import seed_node_types

    seed_node_types()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _seed()
    start_listener()
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.app_name}
