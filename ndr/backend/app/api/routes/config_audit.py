"""配置体检：把「当前生效值」与「**它从哪来**」一次说清。

为什么需要（2026-10 实机教训）：配置分散在三个地方 —— ①**引导项**（连 PG/Redis 之前就要有 ✓，
只能来自环境或部署脚本 ✗）、②**运行期配置**（入库 ✓、界面可改 ✓）、③**编排/引擎项**
（容器还不存在时就要确定 ✗，由部署侧决定 ✓）。实际排查时最耗时的一句是
「库里有、环境里也有，到底哪个生效？」—— 这个接口逐项给出：**生效值 + 来源 + 风险提示**。

安全：口令/令牌/密钥一律**脱敏**（只报「已配置（长度 N）」），接口永远不回显明文。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import SessionLocal
from app.db.models import SystemConfig, User
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/config", tags=["config"])

#: 推送目标的**内置默认主机**：智能体侧地址是产品常量（换哪部署 NDR 都连它），
#: 因此不作为"环境相关地址"。真正的推送 URL/令牌在库里的 `agent_push.params`（界面可改）。
DEFAULT_AGENT_HOST = "10.44.77.249"

#: JWT 默认占位值：上线必须换，体检里要报警
_PLACEHOLDER_SECRETS = {"change-me-in-production", ""}
#: 密码类：脱敏显示
_SECRET_HINTS = ("password", "token", "secret", "password", "passwd", "key")


def _mask(value: Any) -> str:
    """口令/令牌/密钥脱敏：只说"已配置（长度 N）"，不回显内容。"""
    text = str(value or "")
    if not text:
        return "未配置"
    return f"已配置（长度 {len(text)}）"


def _brief(value: Any, limit: int = 120) -> str:
    text = str(value or "")
    if not text:
        return "未配置"
    return text if len(text) <= limit else text[:limit] + "…"


def _env_source(name: str) -> str:
    """这项是从环境变量读的，还是走的默认值？

    注意要同时看 `NAME` 与 `ST_NAME`：容器里 settings 绑定的是 `ST_` 前缀
    （编排里 `ST_CORS_ORIGINS: ${CORS_ORIGINS:-}` 这种写法），只查原名会误报"代码默认值"
    （实测踩到：CORS 明明由编排给了值，体检却显示"代码默认值"）。
    """
    import os

    for candidate in (name, f"ST_{name}"):
        if str(os.environ.get(candidate) or "").strip():
            return f"环境变量 {candidate}"
    return "代码默认值"


def _db_value(key: str) -> Any:
    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, key)
    except Exception as exc:  # noqa: BLE001
        log.debug("配置体检读 %s 失败: %s", key, exc)
        return None
    if row is None or not isinstance(row.value, dict):
        return None
    return row.value.get("value")


def _db_params(key: str) -> dict[str, Any]:
    try:
        with SessionLocal() as db:
            row = db.get(SystemConfig, key)
    except Exception:  # noqa: BLE001
        return {}
    return dict(row.value or {}) if row is not None and isinstance(row.value, dict) else {}


def _item(
    key: str,
    name: str,
    source: str,
    value: str,
    *,
    secret: bool = False,
    warn: str = "",
    note: str = "",
) -> dict[str, Any]:
    return {
        "key": key,
        "name": name,
        "source": source,
        "value": _mask(value) if secret else _brief(value),
        "secret": secret,
        "warn": warn,
        "note": note,
    }


def _networks_configured() -> str:
    try:
        from app.ingestion.scope import monitored_nets

        nets = monitored_nets()
        return (
            f"{len(nets)} 条：{', '.join(nets[:3])}" + ("…" if len(nets) > 3 else "")
            if nets
            else "未配置"
        )
    except Exception:  # noqa: BLE001
        return "读取失败"


def _zeek_interface() -> str:
    try:
        from app.api.routes.zeek import _read_conf

        conf = _read_conf() or {}
        iface = str(conf.get("interface") or "").strip()
        nets = str(conf.get("monitored_nets") or "").strip()
        return f"网卡 {iface or '未配置'}；网段 {nets or '未配置'}（界面「监控网段」页维护）"
    except Exception:  # noqa: BLE001
        return "读取失败"


def _relay_configured() -> str:
    try:
        from app.ingestion import relay_nodes

        count = len(relay_nodes.networks())
        return f"{count} 个地址" if count else "未配置（= 认定网络里没有中继）"
    except Exception:  # noqa: BLE001
        return "读取失败"


@router.get("/audit")
def config_audit(_: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    """逐项列出配置的**生效值与来源**，并对危险状态给出提示。"""
    warnings: list[str] = []
    items: list[dict[str, Any]] = []

    # ---------- ① 引导项：连上系统之前就要有（只能来自环境/部署脚本） ----------
    pg = str(settings.pg_url or "")
    pg_secret = pg.split("//", 1)[-1] if "//" in pg else pg
    items.append(
        _item(
            "pg",
            "数据库连接（引导项）",
            _env_source("ST_PG_URL"),
            pg_secret,
            secret=True,
            note="要读库就得先连库 —— 这一项**不可能**放进库里",
        )
    )
    items.append(
        _item(
            "redis",
            "Redis 连接（引导项）",
            _env_source("ST_REDIS_URL"),
            settings.redis_url,
            note="归一化/检测器在读写库之前就要连它取队列；Filebeat 更是完全没有数据库客户端",
        )
    )
    items.append(
        _item(
            "redis_publish",
            "Redis 对外发布地址（编排项）",
            "编排文件 / 部署脚本（容器内不可见）",
            "（部署侧：默认 127.0.0.1，跨机互联时才改成互通地址）",
            note="改它的同时必须同步采集侧的投送地址，两者成对",
        )
    )
    items.append(
        _item(
            "filebeat_redis",
            "采集投送（Filebeat → Redis，编排项）",
            "编排文件 / 部署脚本（容器内不可见）",
            "（部署侧：默认 localhost:6379 / shentong:events:collect）",
            note="Filebeat 是 YAML 配置、没有数据库客户端，只能由部署侧给",
        )
    )

    # ---------- ② 库/界面：运行期配置 ----------
    es_db = _db_params("es.params") or {}
    es_db_url = es_db.get("url") or _db_value("es.url") or ""
    items.append(
        _item(
            "es",
            "Elasticsearch 连接",
            f"{_env_source('ES_URL')}（库里的 es.* 仅用于界面展示）",
            f"{settings.es_url}（库记录：{es_db_url or '无'}）",
            note="当前以环境为准；界面的 ES 面板是只读回显",
        )
    )
    items.append(
        _item(
            "es_password",
            "Elasticsearch 口令",
            "环境变量 ES_PASSWORD",
            settings.es_password,
            secret=True,
            warn=""
            if str(settings.es_password or "").strip()
            else "未配置口令（ES 无鉴权时才会是空，注意不要对外暴露端口）",
        )
    )

    push = _db_params("agent_push.params")
    push_url = str(push.get("url") or "")
    push_token = str(push.get("token") or "")
    items.append(
        _item(
            "agent_push",
            "摘要推送（NDR → 智能体）",
            "数据库 agent_push.params（界面「智能体对接」页可改）",
            push_url or f"未配置（内置默认主机 {DEFAULT_AGENT_HOST}，请在界面补全 URL）",
            note=f"智能体侧地址是产品常量：{DEFAULT_AGENT_HOST}（换哪部署 NDR 都连它）",
        )
    )
    items.append(
        _item(
            "agent_push_token",
            "推送令牌",
            "数据库 agent_push.params",
            push_token,
            secret=True,
            warn="" if push_url and push_token else "未配置推送地址或令牌 → 摘要会一直「未投递」",
        )
    )

    suri = _db_params("suricata.rules")
    rules_url = str(suri.get("url") or _db_value("suricata.rules_url") or "")
    items.append(
        _item(
            "suricata_rules",
            "签名规则源（在线更新）",
            "数据库 suricata.rules_*（界面「检测规则 → 签名规则」页可改）",
            rules_url or "未配置（用镜像内置的默认规则集）",
            note="规则文件由开发人员维护；检查≠生效，需人工确认",
        )
    )
    items.append(
        _item("nets", "监控网段", "数据库 zeek.monitored_nets（界面可改）", _networks_configured())
    )
    items.append(
        _item("iface", "抓包网卡与网段", "共享配置卷（界面「监控网段」页维护）", _zeek_interface())
    )
    items.append(
        _item("relay", "中继节点清单", "数据库 zeek.relay_nodes（界面可改）", _relay_configured())
    )

    # ---------- ③ 编排/引擎项：容器还不存在时就要定 ----------
    items.append(
        _item(
            "images",
            "镜像版本（编排项）",
            "编排文件 / 部署脚本",
            "（部署侧：SURICATA_IMAGE / ZEEK_IMAGE，默认 latest）",
        )
    )
    items.append(
        _item(
            "tls_sans",
            "证书覆盖地址（编排项）",
            "编排文件 / 部署脚本（TLS_SANS）+ 入口自动识别宿主",
            "（部署侧：证书要覆盖你实际访问用的 IP/域名，否则浏览器报「证书不匹配」）",
            note="入口会在地址变化时自动重签证书",
        )
    )

    # ---------- 危险状态提示 ----------
    jwt = str(settings.jwt_secret or "")
    if jwt in _PLACEHOLDER_SECRETS:
        warnings.append("登录密钥仍是默认占位值（`change-me-in-production`），上线前必须换成随机值")
    if ":3000" in str(settings.cors_origins or ""):
        warnings.append(
            "允许来源里还带着 http 的 3000 端口写法；现在站点是 HTTPS(443)，"
            "建议同步成 https://<访问地址>（前端同源代理一般不受影响，但直接调后端/跨源场景会被挡）"
        )
    if not push_url:
        warnings.append(
            f"摘要推送未配置 → 摘要会一直「未投递」；智能体地址常量是 {DEFAULT_AGENT_HOST}"
        )
    items.append(
        _item(
            "jwt",
            "登录密钥（引导项）",
            _env_source("JWT_SECRET"),
            jwt,
            secret=True,
            warn="" if jwt not in _PLACEHOLDER_SECRETS else "仍是默认占位值，必须更换",
        )
    )
    items.append(
        _item(
            "cors",
            "允许的页面来源（引导项）",
            _env_source("CORS_ORIGINS"),
            settings.cors_origins,
        )
    )

    return {
        "items": items,
        "warnings": warnings,
        "default_agent_host": DEFAULT_AGENT_HOST,
        "checked_at": datetime.now(UTC).isoformat(),
        "note": "口令/令牌/密钥一律脱敏（只报已配置与长度）；本页只读，不修改任何配置",
    }
