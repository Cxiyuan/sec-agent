"""FastAPI 应用入口（NDR 侧）。"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import delete, select

from app.api.deps import default_password_in_use, hash_password
from app.api.router import api_router
from app.config import settings
from app.db.base import Base, SessionLocal, engine
from app.db.models import AssetStat, Rule, SystemConfig, User
from app.rules.builtin import BUILTIN_RULES, DELETED_RULES, RETIRED_RULES

logger = logging.getLogger(__name__)

#: 建表补丁语句，**按顺序**执行，每条都必须可重复执行。
#: 只用于 `Base.metadata.create_all()` 覆盖不到的「给已存在的表加列/改类型」——
#: create_all 只建缺失的表，不会改已有表结构，所以新增列必须同时写在这里。
#: 新装部署两处都会跑（create_all 先建好列，ALTER 变成 no-op），所以语句必须幂等。
_MIGRATIONS: tuple[str, ...] = (
    # MCP 令牌过期（到期判定在 mcp/auth.py）：可空 = 永不过期
    "ALTER TABLE mcp_tokens ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ",
    # 画像风险分的判定时间（2026-10 实机 QA）：只有它有「当前风险」的时间语义，
    # updated_at 每轮观测都刷新，不能当风险时间用
    "ALTER TABLE entity_profiles ADD COLUMN IF NOT EXISTS risk_at TIMESTAMPTZ",
    # 服务端 IP（被访问的监控资产）：界面展示「账号 + 关联服务端 IP」靠它
    "ALTER TABLE entity_profiles ADD COLUMN IF NOT EXISTS dst_ips JSONB NOT NULL DEFAULT '{}'::jsonb",
    # 数值基线的两个过滤列索引（快照的预热计数、保留期清理）——以前都是全表扫描
    "CREATE INDEX IF NOT EXISTS ix_baseline_stats_first_seen ON baseline_stats (first_seen)",
    "CREATE INDEX IF NOT EXISTS ix_baseline_stats_updated_at ON baseline_stats (updated_at)",
)

#: 被访问方基线的**口径版本**：
#: - v2：`visits` 的含义从「每条事件」改成「每条连接（uid）」；
#: - v3：`distinct_clients` 从「每条连接只记一个客户端」改成「收一组」（WAF/反代的一条长连接
#:   会复用/承载很多个真实客户端 —— 实测 206 个请求只走 11 条连接、XFF 里 112 个客户端）。
#: 两种语义的样本混在同一个 Welford 里会把均值/标准差拉偏（那边是无法区分的），所以版本落后
#: 就把 `asset_stats` 清空重学 —— 它只是统计缓存（判据用的均值/方差），不含原始事件，
#: 清了不丢数据，只是重新攒观测期。
_ASSET_SEMANTICS_KEY = "asset.semantics_version"
_ASSET_SEMANTICS_VERSION = 3

# 依赖系统配置的规则：启用状态跟随配置（不保留用户手动开关）
_CONFIG_DRIVEN_RULES = {"内置-JA3指纹命中"}

#: 内置规则改名映射（旧名 → 新名）。
#: 规则名是 upsert 的键：改名不迁移就会留下「旧行 + 新行」两份，而旧行还带着用户设过的
#: 启用状态 / 阈值改动。2026-10：界面不再出现 Zeek/Wazuh 字样，规则名同步改用「网络采集器 /
#: 主机监控」，旧库靠这张表就地改名。
_RENAMED_BUILTINS: dict[str, str] = {
    "内置-Wazuh恶意软件告警": "内置-主机恶意软件告警",
    "内置-Web攻击（Wazuh规则组）": "内置-Web攻击（主机监控）",
    "内置-Wazuh登录失败": "内置-主机登录失败",
    "内置-Wazuh账号锁定": "内置-主机账号锁定",
    "内置-Wazuh提权告警": "内置-主机提权告警",
    "内置-Wazuh高危告警": "内置-主机高危告警",
    "内置-Wazuh文件完整性变更": "内置-主机文件完整性变更",
    "内置-Wazuh漏洞告警": "内置-主机漏洞告警",
    "内置-Wazuh网络告警": "内置-主机网络告警",
    "内置-Wazuh MITRE映射命中": "内置-主机MITRE映射命中",
    "内置-Wazuh策略违规": "内置-主机策略违规",
}


def _delete_builtin_rules(db: Any) -> None:
    """删除已废弃的内置规则行（幂等，每次启动都跑）。

    与 `_retire_builtin_rules`（保留行、只置停用）的区别：这类规则**完全没有有效命中路径**
    （例：`内置-端口扫描` 依赖 notice，而采集面已关掉 notice），保留只会让规则页看起来
    像在防这类事。删之前打一条 warning，把“删了什么、为什么”写进日志（可审计）。
    """
    for name, reason in DELETED_RULES.items():
        row = db.execute(select(Rule).where(Rule.name == name)).scalar_one_or_none()
        if row is None:
            continue
        logger.warning("删除废弃的内置规则：%s（%s）", name, reason)
        db.delete(row)
    db.flush()


def _retire_builtin_rules(db: Any) -> None:
    """把已**退役**的内置规则置为停用（幂等，每次启动都跑）。

    为什么要专门走一步（2026-10）：内置规则是**按名 upsert** 的，名字从 `BUILTIN_RULES`
    里拿掉只会“不再更新它”，库里那行还在、还是启用的 → 会继续出摘要。而启用状态又故意
    不跟随种子（否则用户手动的启用/停用会被盖掉，见 `_seed` 里对 `_CONFIG_DRIVEN_RULES`
    的例外）—— 所以退役只能显式置停用。

    **不删行**：① 运维在规则页看得到「它为什么没了」；② 随时能手动启用回去（回滚一条开关）。
    已经停用的不动（避免把用户后来又打开的开关按回去）；用户改过条件的也照样停 —— 名字退役
    是产品层面的语义变更，写在说明里（`RETIRED_RULES`）供人核对。
    """
    for name, reason in RETIRED_RULES.items():
        row = db.execute(select(Rule).where(Rule.name == name)).scalar_one_or_none()
        if row is None or not row.enabled:
            continue
        row.enabled = False
        row.description = f"{reason}（原描述：{row.description}）"[:500]
        logger.info("内置规则已退役并停用：%s", name)
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


#: 启动时下发 ILM/索引模板的节奏。compose 同时拉起十个服务时 ES 常比后端起得晚
#: （实测 ES 就绪要 30~40 秒，`stop` 后再 `start` 更慢），一次性下发会静默失败 ——
#: 模板缺失时 Logstash 自动建的索引拿到默认 `number_of_replicas: 1`，单节点集群恒
#: yellow（2026-10 实机实测：12 × 5 秒 ≈ 1 分钟那次没等到 ES 回来就放弃了）。
#: 所以前 24 次每 5 秒试（≈2 分钟），之后每 5 分钟复查一次；成功以后也继续复查，
#: 这样模板被人删掉、或 ES 卷被换掉都能自己长回来（两次幂等 HTTP 调用，开销可忽略）。
_ES_SETUP_ATTEMPTS = 24
_ES_SETUP_INTERVAL_SECONDS = 5.0
_ES_SETUP_RECHECK_SECONDS = 300.0


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


def _migrate_asset_semantics() -> None:
    """把被访问方基线的口径版本升到当前值；版本落后就清空 `asset_stats` 重学（幂等）。

    幂等：版本已经到位就直接返回；并发/重复启动最多多跑一次 `DELETE`（删空表不损失什么）。
    """
    with SessionLocal() as db:
        row = db.get(SystemConfig, _ASSET_SEMANTICS_KEY)
        payload = dict(row.value or {}) if row is not None else {}
        try:
            version = int(payload.get("value") or 0)
        except (TypeError, ValueError):
            version = 0
        if version >= _ASSET_SEMANTICS_VERSION:
            return
        removed = int(getattr(db.execute(delete(AssetStat)), "rowcount", 0) or 0)
        if row is None:
            db.add(
                SystemConfig(
                    key=_ASSET_SEMANTICS_KEY,
                    value={"value": _ASSET_SEMANTICS_VERSION},
                )
            )
        else:
            row.value = {"value": _ASSET_SEMANTICS_VERSION}
        db.commit()
        logger.info(
            "被访问方基线口径升级到 v%d：清掉旧口径的 %d 行统计，重新学习（口径变了不混样本）",
            _ASSET_SEMANTICS_VERSION,
            removed,
        )


def _push_es_retention() -> None:
    """幂等下发 ILM 策略与事件索引模板；ES 没就绪就一直等，之后定期复查。

    在后台线程里跑：ES 没起来不能拖住 API 就绪，也不能让采集链路等它。
    前 `_ES_SETUP_ATTEMPTS` 次每 5 秒试一次（覆盖 ES 冷启动），之后每 5 分钟
    复查一次；第一次放弃高速重试时记一条 warning（并提示界面上那个手工入口），
    之后不再刷日志。成功后也继续复查 —— 模板被删、ES 卷被换都能自动长回来。

    日志口径：**失败后重试成功**才记一条 info（带实际重试次数），稳态下每 5 分钟的
    幂等复查只记 debug —— 否则一条「第 N 次尝试下发成功」会每 5 分钟刷一次，
    N 一直涨（实机实测），看着像一直在重试。
    """
    from app.api.routes.es_admin import ensure_retention

    attempt = 0
    while True:
        attempt += 1
        try:
            ensure_retention()
        except Exception as exc:  # noqa: BLE001
            if attempt == _ES_SETUP_ATTEMPTS:
                logger.warning(
                    "下发 ES 保留期策略/索引模板失败（重试 %d 次未成功，"
                    "之后每 %.0f 秒自动重试，也可在界面点「下发保留期」）：%s",
                    _ES_SETUP_ATTEMPTS,
                    _ES_SETUP_RECHECK_SECONDS,
                    exc,
                )
            slow = attempt >= _ES_SETUP_ATTEMPTS
            time.sleep(_ES_SETUP_RECHECK_SECONDS if slow else _ES_SETUP_INTERVAL_SECONDS)
            continue
        if attempt > 1:
            logger.info(
                "ES 保留期策略/索引模板第 %d 次尝试下发成功（前 %d 次失败）",
                attempt,
                attempt - 1,
            )
        else:
            logger.debug("ES 保留期策略/索引模板复查成功（幂等，不计失败）")
        attempt = 0
        time.sleep(_ES_SETUP_RECHECK_SECONDS)


def _seed() -> None:
    """幂等初始化：建表、默认管理员、内置规则。"""
    Base.metadata.create_all(engine)
    _migrate()
    # 口径变了就清空重学（幂等；必须在检测器写新数据之前跑）
    _migrate_asset_semantics()

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
        db.commit()
        # 出厂默认口令仍在用就每次启动都提醒（实机验证过 admin/admin123 确实能登进来）。
        # 不强制改密、不随机生成：那会把现网锁在门外。提示面还有 GET /api/auth/me 的
        # default_password_in_use，供界面挂常驻横幅。
        if default_password_in_use(db):
            logger.warning(
                "默认管理员 %s 仍在使用出厂口令（未用 ST_DEFAULT_ADMIN_PASSWORD 覆盖，"
                "也还没在界面改密）：请尽快修改（POST /api/auth/change-password）。",
                settings.default_admin_username,
            )

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
