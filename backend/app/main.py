"""FastAPI 应用入口。"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api.deps import hash_password
from app.api.router import api_router
from app.api.routes.ws import start_listener
from app.config import settings
from app.db.base import Base, SessionLocal, engine
from app.db.models import Rule, Skill, User
from app.rules.builtin import BUILTIN_RULES
from app.skills import BUILTIN_SKILLS

# 幂等补列/补索引：保证已有库平滑升级（新列均有默认值，不破坏旧数据）
_MIGRATIONS = (
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS is_external BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS allow_ip_share BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE documents ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64) NOT NULL DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS ix_documents_content_hash ON documents (content_hash)",
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS lookback JSONB",
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS memory_hits JSONB",
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS profile_hits JSONB",
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS skill_hits JSONB",
    "ALTER TABLE baseline_stats ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ",
)

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
    """幂等初始化：建 pgvector 扩展、建表、补列、默认管理员、内置规则与拓扑节点类型。"""
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE EXTENSION IF NOT EXISTS vector")
    Base.metadata.create_all(engine)
    _migrate()

    # 自检：提示词模板与内置规则正则（这两类问题会「静默失败」）
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
        # 内置技能（分析 SOP + 工具）幂等 upsert：不覆盖用户自建技能
        for spec in BUILTIN_SKILLS:
            exists = db.execute(
                select(Skill).where(Skill.name == spec["name"])
            ).scalar_one_or_none()
            if exists is None:
                db.add(Skill(**{**spec, "source": "builtin"}))
            elif exists.source == "builtin":
                exists.description = spec.get("description", "")
                exists.sop = spec.get("sop", "")
                exists.event_types = spec.get("event_types", [])
                exists.tools = spec.get("tools", [])
                exists.priority = spec.get("priority", exists.priority)
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
    """健康检查 + 当前生效的模型配置（运维可见性）。"""
    from app.models.registry import current_models

    return {"status": "ok", "app": settings.app_name, "models": current_models()}
