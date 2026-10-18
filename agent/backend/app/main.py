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
from app.rules.builtin import BUILTIN_RULES, DELETED_RULES, RETIRED_RULES
from app.skills import BUILTIN_SKILLS
from app.workers.log import get_logger

log = get_logger(__name__)

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
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS aggregate JSONB",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS excluded BOOLEAN NOT NULL DEFAULT FALSE",
    "CREATE INDEX IF NOT EXISTS ix_events_excluded ON events (excluded)",
    # 误报治理：方向与「为什么跳过/被降级」都要可查
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS direction VARCHAR(16) NOT NULL DEFAULT ''",
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS exclude_reason TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS severity_cap_reason TEXT NOT NULL DEFAULT ''",
    # 回写改造：组上只留案件指针 + 案件视角副本（不再被案件叙事覆盖）
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS case_id VARCHAR(64) NOT NULL DEFAULT ''",
    "ALTER TABLE event_groups ADD COLUMN IF NOT EXISTS case_context JSONB",
    # 归并治理：归并依据 / 自动拆分原因 / 被哪个批次取代
    "ALTER TABLE attacker_cases ADD COLUMN IF NOT EXISTS merge_basis JSONB",
    "ALTER TABLE attacker_cases ADD COLUMN IF NOT EXISTS split_reason TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE attacker_cases ADD COLUMN IF NOT EXISTS superseded_by VARCHAR(64) NOT NULL DEFAULT ''",
)

# 依赖系统配置的规则：启用状态跟随配置（不保留用户手动开关）
_CONFIG_DRIVEN_RULES = {"JA3指纹命中"}

#: 内置规则改名映射（旧名 → 新名）。
#: 规则名是 upsert 的键：改名不迁移就会留下「旧行 + 新行」两份，而旧行还带着用户设过的
#: 主机监控」，旧库靠这张表就地改名。
_RENAMED_BUILTINS: dict[str, str] = {}


#: 规则名的历史前缀（拆开拼，别写成连续字面量 —— 2026-10 那次"全局去前缀"的批量替换
#: 把迁移 SQL 里的这个字面量一起改掉了，SQL 变成 `replace(name,'','') WHERE name LIKE '%'`，
#: psycopg 又把裸 `%` 当占位符 → 后端启动直接崩。用 Python 改名 + 拼字面量，两头都躲开。）
_LEGACY_RULE_PREFIX = "内置" + "-"


def _migrate_rule_names() -> None:
    """把库里规则名的历史前缀去掉（幂等，纯 ORM，不拼 SQL）。

    为什么需要：`DELETED_RULES` / `RETIRED_RULES` 是按名字匹配库里已有行的 ——
    代码里的规则名去掉前缀后，老库里的行还带着旧前缀，就变成"两套规则"。
    新名字已存在（历史上手工建过同名）时，以新名字那行为准，删掉旧前缀那条。
    """
    try:
        with SessionLocal() as db:
            rows = db.scalars(
                select(Rule).where(Rule.name.startswith(_LEGACY_RULE_PREFIX))
            ).all()
            if not rows:
                return
            renamed = 0
            for row in rows:
                new_name = row.name.replace(_LEGACY_RULE_PREFIX, "", 1).strip()
                if not new_name:
                    continue
                existing = db.scalars(select(Rule).where(Rule.name == new_name)).first()
                if existing is not None:
                    db.delete(row)  # 新名字那行更权威（可能被人工改过条件/开关）
                    continue
                row.name = new_name
                renamed += 1
            db.commit()
            log.info("规则名迁移：改名 %d 行，清理重复 %d 行", renamed, len(rows) - renamed)
    except Exception as exc:  # noqa: BLE001 — 迁移失败不能挡住启动
        log.warning("规则名迁移失败（不影响启动）：%s", exc)


def _delete_builtin_rules(db: Any) -> None:
    """删除已废弃的内置规则行（幂等，每次启动都跑）。

    与 `_retire_builtin_rules`（保留行、只置停用）的区别：这类规则**完全没有有效命中路径**
    （例：`端口扫描` 依赖 notice，而采集面已关掉 notice）。删之前打一条 warning，
    把“删了什么、为什么”写进日志（可审计）。
    """
    for name, reason in DELETED_RULES.items():
        row = db.execute(select(Rule).where(Rule.name == name)).scalar_one_or_none()
        if row is None:
            continue
        log.warning("删除废弃的内置规则：%s（%s）", name, reason)
        db.delete(row)
    db.flush()


def _retire_builtin_rules(db: Any) -> None:
    """把已**退役**的内置规则置为停用（幂等，每次启动都跑）。

    为什么要专门走一步（2026-10）：内置规则是**按名 upsert** 的，名字从 `BUILTIN_RULES`
    里拿掉只会“不再更新它”，库里那行还在、还是启用的 → 会继续出摘要。而启用状态又故意
    不跟随种子（否则用户手动的启用/停用会被盖掉）—— 所以退役只能显式置停用。

    **不删行**：① 运维在规则页看得到「它为什么没了」；② 随时能手动启用回去（回滚一条开关）。
    已经停用的不动（避免把用户后来又打开的开关按回去）。
    """
    for name, reason in RETIRED_RULES.items():
        row = db.execute(select(Rule).where(Rule.name == name)).scalar_one_or_none()
        if row is None or not row.enabled:
            continue
        row.enabled = False
        row.description = f"{reason}（原描述：{row.description}）"[:500]
        log.info("内置规则已退役并停用：%s", name)
    db.flush()


def _rename_builtin_rules(db: Any) -> None:
    """把旧名的内置规则**就地改名**（幂等，每次启动都跑）。

    就地改（而不是删旧建新）是为了保留用户在这条规则上做过的启用/停用与改动。
    新名已经存在时（例如重复播种过）旧行就是残留，删掉。
    """
    for old, new in _RENAMED_BUILTINS.items():
        row = db.execute(select(Rule).where(Rule.name == old)).scalar_one_or_none()
        if row is None:
            continue
        taken = db.execute(select(Rule).where(Rule.name == new)).scalar_one_or_none()
        if taken is not None and taken is not row:
            db.delete(row)
        else:
            row.name = new
        db.flush()


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
        _rename_builtin_rules(db)
        _retire_builtin_rules(db)
        _delete_builtin_rules(db)
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
