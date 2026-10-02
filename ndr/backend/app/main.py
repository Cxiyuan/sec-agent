"""FastAPI 应用入口（NDR 侧）。"""

from __future__ import annotations

import logging
import threading
import time
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

logger = logging.getLogger(__name__)

# NDR 侧无历史迁移（原 _MIGRATIONS 全是 agent 表）
_MIGRATIONS: tuple[str, ...] = ()

# 依赖系统配置的规则：启用状态跟随配置（不保留用户手动开关）
_CONFIG_DRIVEN_RULES = {"内置-JA3指纹命中"}

#: 启动时下发 ILM/索引模板的最大尝试次数与间隔。compose 同时拉起十个服务时 ES 常比
#: 后端起得晚（实测 ES 就绪要 30~40 秒），一次性下发会静默失败 —— 模板缺失，Logstash
#: 自动建的索引拿到默认 `number_of_replicas: 1`，单节点集群恒 yellow（2026-10 从零
#: 重建时实测）。12 × 5 秒 ≈ 1 分钟，够覆盖 ES 冷启动。
_ES_SETUP_ATTEMPTS = 12
_ES_SETUP_INTERVAL_SECONDS = 5.0


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


def _push_es_retention() -> None:
    """幂等下发 ILM 策略与事件索引模板，ES 未就绪就重试（约 1 分钟）。

    在后台线程里跑：ES 没起来不能拖住 API 就绪，也不能让采集链路等它。
    全部尝试都失败才记 warning（并提示界面上那个手工入口）。
    """
    from app.api.routes.es_admin import ensure_retention

    for attempt in range(1, _ES_SETUP_ATTEMPTS + 1):
        try:
            ensure_retention()
        except Exception as exc:  # noqa: BLE001
            if attempt < _ES_SETUP_ATTEMPTS:
                time.sleep(_ES_SETUP_INTERVAL_SECONDS)
                continue
            logger.warning(
                "下发 ES 保留期策略/索引模板失败（重试 %d 次未成功，"
                "可稍后在界面点「下发保留期」）：%s",
                _ES_SETUP_ATTEMPTS,
                exc,
            )
            return
        if attempt > 1:
            logger.info("ES 保留期策略/索引模板已在第 %d 次尝试下发成功", attempt)
        return


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

    # 存储侧：幂等下发 ILM 策略与事件索引模板（含副本数 0，否则单节点集群恒 yellow）。
    # ES 可能比后端起得晚（compose 同时拉起），所以丢给后台线程重试，不阻断启动。
    threading.Thread(target=_push_es_retention, name="es-retention", daemon=True).start()


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
