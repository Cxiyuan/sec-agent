"""FastAPI 应用入口（NDR 侧）。"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api.deps import hash_password
from app.api.router import api_router
from app.config import settings
from app.db.base import Base, SessionLocal, engine
from app.db.models import Rule, User
from app.rules.builtin import BUILTIN_RULES

# NDR 侧无历史迁移（原 _MIGRATIONS 全是 agent 表）
_MIGRATIONS: tuple[str, ...] = ()

# 依赖系统配置的规则：启用状态跟随配置（不保留用户手动开关）
_CONFIG_DRIVEN_RULES = {"内置-JA3指纹命中"}


def _dynamic_rule_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """把依赖系统配置的内置规则按当前配置实例化，避免出现「空实现」规则。

    - JA3 指纹规则：conditions.value 取自 ST_JA3_BLOCKLIST；清单为空时禁用
      （否则会对所有带 JA3 的 TLS 会话误报）
    """
    if spec.get("name") not in _CONFIG_DRIVEN_RULES:
        return spec
    ja3_list = [x.strip() for x in (settings.ja3_blocklist or "").split(",") if x.strip()]
    out = dict(spec)
    out["conditions"] = {
        "logic": "and",
        "rules": [{"field": "ja3", "op": "in", "value": ja3_list}],
    }
    out["enabled"] = bool(ja3_list)
    return out


def _migrate() -> None:
    with engine.begin() as conn:
        for stmt in _MIGRATIONS:
            conn.exec_driver_sql(stmt)


def _seed() -> None:
    """幂等初始化：建表、默认管理员、内置规则。"""
    Base.metadata.create_all(engine)
    _migrate()

    # 自检：内置规则正则（这类问题会「静默失败」）
    from app.selfcheck import run_startup_selfcheck

    run_startup_selfcheck()
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
        for spec in BUILTIN_RULES:
            rule_spec = _dynamic_rule_spec(spec)
            exists = db.execute(
                select(Rule).where(Rule.name == rule_spec["name"])
            ).scalar_one_or_none()
            if exists is None:
                db.add(Rule(**rule_spec))
            elif exists.source == "builtin":
                # 内置规则随版本同步更新（不覆盖用户自建规则）
                exists.description = rule_spec.get("description", "")
                exists.conditions = rule_spec.get("conditions", {})
                exists.severity = rule_spec.get("severity", exists.severity)
                exists.priority = rule_spec.get("priority", exists.priority)
                if rule_spec["name"] in _CONFIG_DRIVEN_RULES:
                    # 依赖配置的规则，启用状态跟随配置
                    exists.enabled = rule_spec.get("enabled", exists.enabled)
        db.commit()

    # 采集侧：首次部署播种默认 Logstash 管道（共享卷内无文件才写）
    from app.api.routes.logstash import seed_if_missing

    seed_if_missing()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _seed()
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
    """健康检查。"""
    return {"status": "ok", "app": settings.app_name}
