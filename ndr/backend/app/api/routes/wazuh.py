"""Wazuh 4.14 接入管理（第 6 期）：连接凭据、接入状态、Agent 清单、规则文件下发与生效校验。

设计要点：

- **凭据**（地址 / 用户名 / 密码 / 是否校验 TLS）存 `SystemConfig` 的 `wazuh.params`，
  环境变量只作默认值；界面回显一律打码，密码传 `None` = 不改动、传 `""` = 清空。
- **Wazuh API 用 Basic 换 JWT**：`POST /security/user/authenticate` 拿 token，
  token 有过期（默认 900s），故进程内按 `(url, user)` 缓存并在过期前重新登录；
  登录失败不抛 500，而是回结构化错误（界面能显示原因）。
- **「接入状态」不只看 API 通不通**，还看**归一化后的入库量**（ES 里
  `source_system=wazuh` 的告警与原始日志条数）：API 通了但日志没进来是最常见的假绿。
- 规则下发用 Wazuh 官方接口「上传自定义规则文件」+ 回读校验（下载原文比对 + 该文件的
  生效规则条数），避免「上传成功但其实没生效」。
"""

from __future__ import annotations

import re
import time
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.config import settings
from app.db.base import get_db
from app.db.models import SystemConfig, User
from app.ingestion import es_config
from app.ingestion.es_client import get_es
from app.investigation import catalog
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/wazuh", tags=["wazuh"])

CONFIG_KEY = "wazuh.params"
DEFAULT_PORT = 55000
#: token 提前这么久重新登录（Wazuh 默认有效期 900s）
TOKEN_SAFETY_SECONDS = 60.0
#: 自定义规则文件名：只允许一层、必须以 .xml 结尾（防目录穿越）
RULE_FILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}\.xml$")
RULE_ID_RE = re.compile(r"<rule\s[^>]*id\s*=\s*\"(\d+)\"")

HINT = (
    "先填 Wazuh manager 的 API 地址（https://<manager>:55000）与凭据，点「测试连接」；"
    "「接入状态」会分别显示 API 是否可达、以及最近 24 小时 Wazuh 告警/原始日志各入库多少条。"
    "注意：Wazuh 采的是主机日志，与「监控网段」无关 —— 那份清单只约束 Zeek 抓包。"
)

#: (url|user) -> (写入时刻, 过期时刻, token)
_token_cache: dict[str, tuple[float, float, str]] = {}


class WazuhConfigIn(BaseModel):
    url: str = ""
    user: str | None = None
    password: str | None = None  # None = 不改动；"" = 清空
    verify_tls: bool = False


class WazuhRuleIn(BaseModel):
    filename: str = "local_rules.xml"
    text: str
    verify: bool = True


# ---------- 配置存取与脱敏 ----------


def _stored(db: Session) -> dict[str, Any]:
    row = db.get(SystemConfig, CONFIG_KEY)
    value = row.value if row is not None else None
    return dict(value) if isinstance(value, dict) else {}


def _env_defaults() -> dict[str, Any]:
    return {
        "url": settings.wazuh_api_url,
        "user": settings.wazuh_api_user,
        "password": settings.wazuh_api_password,
        "verify_tls": settings.wazuh_api_verify_tls,
    }


def _merge(stored: dict[str, Any]) -> dict[str, Any]:
    cfg = _env_defaults()
    for key in ("url", "user", "password", "verify_tls"):
        if key in stored and stored[key] not in (None, ""):
            cfg[key] = stored[key]
    cfg["url"] = _normalize_url(str(cfg.get("url") or ""))
    return cfg


def _normalize_url(url: str) -> str:
    """补全 scheme/端口并去掉尾部斜杠；空值原样返回。"""
    raw = (url or "").strip().rstrip("/")
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"https://{raw}"
    return raw


def mask(value: str) -> str:
    """脱敏：只留头 2 尾 2，中间固定 6 个星号。"""
    raw = str(value or "")
    if not raw:
        return ""
    if len(raw) <= 4:
        return "*" * 6
    return f"{raw[:2]}{'*' * 6}{raw[-2:]}"


def _public(cfg: dict[str, Any]) -> dict[str, Any]:
    password = str(cfg.get("password") or "")
    return {
        "url": str(cfg.get("url") or ""),
        "user": str(cfg.get("user") or ""),
        "password_set": bool(password),
        "password_masked": mask(password),
        "verify_tls": bool(cfg.get("verify_tls")),
        # 地址 + 凭据齐全才算「已配置」
        "configured": bool(cfg.get("url") and cfg.get("user") and password),
    }


# ---------- Wazuh API 调用 ----------


def _timeout() -> float:
    try:
        return max(1.0, float(settings.wazuh_api_timeout_seconds))
    except (TypeError, ValueError):
        return 10.0


def _verify(cfg: dict[str, Any]) -> bool:
    return bool(cfg.get("verify_tls"))


def _login(cfg: dict[str, Any]) -> tuple[str | None, str]:
    """Basic → JWT；返回 (token, 错误说明)。"""
    url = str(cfg.get("url") or "")
    user = str(cfg.get("user") or "")
    password = str(cfg.get("password") or "")
    if not (url and user and password):
        return None, "还没填全 Wazuh API 地址 / 用户名 / 密码"
    cache_key = f"{url}|{user}"
    now = time.monotonic()
    cached = _token_cache.get(cache_key)
    if cached and cached[1] > now:
        return cached[2], ""

    try:
        with httpx.Client(timeout=_timeout(), verify=_verify(cfg)) as client:
            resp = client.post(f"{url}/security/user/authenticate", auth=(user, password))
    except Exception as exc:  # noqa: BLE001
        return None, f"连接 Wazuh API 失败：{exc}"
    if resp.status_code == 401:
        return None, "Wazuh API 认证失败（用户名或密码不正确）"
    if resp.status_code >= 400:
        return None, f"Wazuh API 登录失败：HTTP {resp.status_code} {resp.text[:200]}"
    try:
        token = str(resp.json().get("data", {}).get("token") or "")
    except ValueError:
        return None, "Wazuh API 登录响应不是 JSON"
    if not token:
        return None, "Wazuh API 没有返回 token"
    # 有效期取响应里的 expires_at（秒级字符串），缺省按 900s 兜底
    ttl = 900.0
    try:
        expires_at = float(resp.json().get("data", {}).get("expires_at") or 0)
        if expires_at > 0:
            ttl = max(60.0, expires_at - time.time())
    except (TypeError, ValueError):
        pass
    _token_cache[cache_key] = (now, now + max(60.0, ttl - TOKEN_SAFETY_SECONDS), token)
    return token, ""


def _api(
    cfg: dict[str, Any],
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    content: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[Any | None, str]:
    """带鉴权的 Wazuh API 请求；返回 (响应 JSON, 错误说明)。"""
    token, err = _login(cfg)
    if not token:
        return None, err
    url = str(cfg.get("url") or "")
    merged_headers = {"Authorization": f"Bearer {token}"}
    merged_headers.update(headers or {})
    try:
        with httpx.Client(timeout=_timeout(), verify=_verify(cfg)) as client:
            resp = client.request(
                method, f"{url}{path}", params=params, content=content, headers=merged_headers
            )
    except Exception as exc:  # noqa: BLE001
        return None, f"请求 Wazuh API 失败：{exc}"
    if resp.status_code == 401:
        # token 可能刚好过期：清缓存后重试一次
        _token_cache.pop(f"{url}|{cfg.get('user')}", None)
        token, err = _login(cfg)
        if not token:
            return None, err
        merged_headers["Authorization"] = f"Bearer {token}"
        try:
            with httpx.Client(timeout=_timeout(), verify=_verify(cfg)) as client:
                resp = client.request(
                    method,
                    f"{url}{path}",
                    params=params,
                    content=content,
                    headers=merged_headers,
                )
        except Exception as exc:  # noqa: BLE001
            return None, f"请求 Wazuh API 失败：{exc}"
    if resp.status_code >= 400:
        return None, f"Wazuh API 返回 HTTP {resp.status_code}：{resp.text[:200]}"
    try:
        return resp.json(), ""
    except ValueError:
        return None, "Wazuh API 响应不是 JSON"


def _probe(cfg: dict[str, Any]) -> dict[str, Any]:
    """连通性 + 基本信息（测试连接 / 状态都用它）。"""
    out: dict[str, Any] = {
        "reachable": False,
        "url": str(cfg.get("url") or ""),
        "version": "",
        "cluster_enabled": False,
        "detail": "",
    }
    if not cfg.get("url"):
        out["detail"] = "还没填 Wazuh API 地址"
        return out
    data, err = _api(cfg, "GET", "/manager/info")
    if err:
        out["detail"] = err
        return out
    item = _first_item(data)
    out["reachable"] = True
    out["version"] = str(item.get("version") or "")
    out["cluster_enabled"] = bool(_as_dict(item.get("cluster")).get("enabled"))
    out["detail"] = "连通"
    return out


def _first_item(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        items = data.get("data", {}).get("affected_items")
        if isinstance(items, list) and items and isinstance(items[0], dict):
            return items[0]
    return {}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


# ---------- 入库量（ES）：API 通了不代表日志进来了 ----------


def _ingest_stats() -> dict[str, Any]:
    """最近 24 小时 `source_system=wazuh` 的告警 / 原始日志条数。"""
    out: dict[str, Any] = {
        "alerts": 0,
        "archives": 0,
        "total": 0,
        "last_at": None,
        "error": "",
    }
    # 索引名走运行时配置（后台「系统配置 → Elasticsearch」能改），不能用静态
    # settings.es_events_index —— 否则改了索引名这里还在查旧索引，界面显示「没有入库」
    # 而实际数据在别的索引里（同类读路径见 app/ingestion/es_config.py）。
    cfg = es_config.current()
    index = str(cfg.get("es.events_index") or settings.es_events_index)
    # 精确匹配与聚合都必须走 keyword 路径：`log_type`/`source_system` 实机是 text
    # （动态映射另给一个 `.keyword` 副本），对 text 主路径做 terms 聚合会被 ES 直接拒
    # （`Fielddata is disabled on [log_type]`）—— 后果是「接入状态」永远显示「读 ES 失败」，
    # 这正是 `ndr/wazuh/README.md` 里「界面近 24h 入库条数」那条待验项。
    log_type_path = catalog.agg_path(index, "log_type")
    source_path = catalog.agg_path(index, "source_system")
    query = {
        "bool": {
            "filter": [
                {"term": {source_path: "wazuh"}},
                {"range": {"@timestamp": {"gte": "now-24h"}}},
            ]
        }
    }
    try:
        es = get_es()
        resp = es.search(
            index=index,
            query=query,
            size=0,
            # 默认 hits.total 超过 1 万就只给下界（"gte"），界面会把它当精确值显示
            track_total_hits=True,
            aggs={
                "by_type": {"terms": {"field": log_type_path, "size": 10}},
                "last": {"max": {"field": "@timestamp"}},
            },
        )
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"读 ES 失败：{exc}"
        return out
    aggs = _as_dict(resp.get("aggregations"))
    total = _as_dict(resp.get("hits")).get("total")
    out["total"] = (
        int(_as_dict(total).get("value") or 0) if isinstance(total, dict) else int(total or 0)
    )
    for bucket in _as_dict(aggs.get("by_type")).get("buckets") or []:
        key = str(_as_dict(bucket).get("key") or "")
        count = int(_as_dict(bucket).get("doc_count") or 0)
        if key == "wazuh":
            out["alerts"] = count
        elif key == "wazuh_archive":
            out["archives"] = count
    out["last_at"] = _as_dict(aggs.get("last")).get("value_as_string") or None
    return out


# ---------- 载荷 ----------


def _agents_summary(agents: list[dict[str, Any]]) -> dict[str, int]:
    """按状态分桶计数：每个 agent 只落一个桶，`total` = 各桶之和。

    原来的实现把 `pending` / `never_connected` 也算进 `disconnected`，而
    `never_connected` 又另计一次 → 三个桶加起来大于 `total`（界面上的分项与总数对不上）。
    """
    summary = {
        "total": len(agents),
        "active": 0,
        "disconnected": 0,
        "never_connected": 0,
        "pending": 0,
    }
    for item in agents:
        status = str(item.get("status") or "").lower()
        if status in summary and status != "total":
            summary[status] += 1
    return summary


def _payload(db: Session) -> dict[str, Any]:
    cfg = _merge(_stored(db))
    public = _public(cfg)
    status = (
        _probe(cfg)
        if public["configured"]
        else {
            "reachable": False,
            "url": public["url"],
            "version": "",
            "cluster_enabled": False,
            "detail": "还没填全 Wazuh API 地址 / 用户名 / 密码",
        }
    )
    agents: list[dict[str, Any]] = []
    if status["reachable"]:
        data, err = _api(
            cfg,
            "GET",
            "/agents",
            params={
                "limit": 500,
                "select": "id,name,ip,status,version,lastKeepAlive,os.name",
                "sort": "+id",
            },
        )
        if err:
            status["detail"] = f"连通，但读 Agent 清单失败：{err}"
        else:
            agents = [
                i
                for i in _as_dict(_as_dict(data).get("data")).get("affected_items") or []
                if isinstance(i, dict)
            ]
    return {
        "config": public,
        "status": {**status, "agents": _agents_summary(agents)},
        "agents": agents,
        "ingest": _ingest_stats(),
        "env": {
            "url": settings.wazuh_api_url,
            "user": settings.wazuh_api_user,
            "password_set": bool(settings.wazuh_api_password),
        },
        "hint": HINT,
    }


# ---------- 路由 ----------


@router.get("")
def get_wazuh(
    db: Annotated[Session, Depends(get_db)], _: Annotated[User, Depends(get_current_user)]
):
    return _payload(db)


@router.put("")
def save_wazuh(
    body: WazuhConfigIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    stored = _stored(db)
    stored["url"] = _normalize_url(body.url)
    if body.user is not None:
        stored["user"] = body.user
    if body.password is not None:
        stored["password"] = body.password  # "" = 显式清空
    stored["verify_tls"] = body.verify_tls

    row = db.get(SystemConfig, CONFIG_KEY)
    if row is None:
        row = SystemConfig(key=CONFIG_KEY, value={})
        db.add(row)
    row.value = stored
    db.commit()
    log.info(
        "Wazuh API 配置已更新（地址=%s，密码=%s）",
        stored.get("url"),
        "已设置" if stored.get("password") else "未设置",
    )
    return _payload(db)


@router.post("/test")
def test_wazuh(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    body: WazuhConfigIn | None = None,
):
    """测试连接：可以带一份临时配置（界面还没保存时先试）。"""
    cfg = _merge(_stored(db))
    if body is not None:
        if body.url:
            cfg["url"] = _normalize_url(body.url)
        if body.user is not None:
            cfg["user"] = body.user
        if body.password is not None:
            cfg["password"] = body.password
        cfg["verify_tls"] = body.verify_tls
    # 测试用的一定是「刚填的」凭据，不能复用旧 token 缓存
    _token_cache.pop(f"{cfg.get('url')}|{cfg.get('user')}", None)
    probe = _probe(cfg)
    return {
        "ok": bool(probe["reachable"]),
        "url": probe["url"],
        "version": probe["version"],
        "cluster_enabled": probe["cluster_enabled"],
        "detail": probe["detail"],
    }


@router.get("/status")
def get_status(
    db: Annotated[Session, Depends(get_db)], _: Annotated[User, Depends(get_current_user)]
):
    """Wazuh 探活 + 近 24h 入库量。

    与 `GET /api/wazuh`（`_payload`）内容重叠、界面没调它；保留为对外只读能力
    （复刻 Wazuh API 的 status 资源，脚本/智能体可直接取）。
    """
    cfg = _merge(_stored(db))
    probe = _probe(cfg)
    return {**probe, "ingest": _ingest_stats()}


@router.get("/agents")
def list_agents(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    status: str = "",
    limit: int = 500,
):
    """Wazuh Agent 清单（可按状态过滤）+ 分桶统计。

    同上：界面通过 `GET /api/wazuh` 拿同样的清单，这个独立入口保留给外部只读使用。
    """
    cfg = _merge(_stored(db))
    params: dict[str, Any] = {
        "limit": max(1, min(int(limit or 500), 1000)),
        "select": "id,name,ip,status,version,lastKeepAlive,os.name",
        "sort": "+id",
    }
    if status:
        params["status"] = status
    data, err = _api(cfg, "GET", "/agents", params=params)
    if err:
        return JSONResponse(status_code=400, content={"conflict": "wazuh_api", "detail": err})
    items = [
        i
        for i in _as_dict(_as_dict(data).get("data")).get("affected_items") or []
        if isinstance(i, dict)
    ]
    return {"agents": items, "summary": _agents_summary(items)}


@router.get("/rules")
def list_rule_files(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    limit: int = 200,
):
    cfg = _merge(_stored(db))
    data, err = _api(
        cfg,
        "GET",
        "/rules/files",
        params={"limit": max(1, min(int(limit or 200), 1000)), "sort": "+filename"},
    )
    if err:
        return JSONResponse(status_code=400, content={"conflict": "wazuh_api", "detail": err})
    items = [
        i
        for i in _as_dict(_as_dict(data).get("data")).get("affected_items") or []
        if isinstance(i, dict)
    ]
    local = [i for i in items if str(i.get("relative_dirname") or "").startswith("etc/rules")]
    return {"files": items, "local": local, "total": len(items)}


@router.post("/rules")
def upload_rule_file(
    body: WazuhRuleIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """下发一个自定义规则文件并（默认）回读校验是否真的生效。"""
    filename = (body.filename or "").strip()
    if not RULE_FILE_RE.match(filename):
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": "规则文件名只能是一层文件名、以 .xml 结尾（如 local_rules.xml）",
            },
        )
    text = body.text or ""
    if not text.strip():
        return JSONResponse(
            status_code=400, content={"conflict": "field_error", "detail": "规则文件内容不能为空"}
        )
    if "<rule" not in text or "<group" not in text:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": "内容看起来不是 Wazuh 规则文件（需要 <group> 与 <rule>）",
            },
        )
    cfg = _merge(_stored(db))
    _sent, err = _api(
        cfg,
        "PUT",
        f"/rules/files/{filename}",
        content=text.encode("utf-8"),
        headers={"Content-Type": "application/octet-stream"},
    )
    if err:
        return JSONResponse(status_code=400, content={"conflict": "wazuh_api", "detail": err})

    rule_ids = RULE_ID_RE.findall(text)
    result: dict[str, Any] = {
        "ok": True,
        "filename": filename,
        "sent_rules": len(rule_ids),
        "rule_ids": rule_ids[:50],
        "verified": False,
        "applied_rules": 0,
        "detail": "已上传",
    }
    if body.verify:
        # ① 该文件在 manager 上生效的规则条数（最能说明「真的生效了」）
        data, err = _api(
            cfg,
            "GET",
            "/rules",
            params={"filename": filename, "limit": 1},
        )
        if err:
            result["detail"] = f"已上传，但回读校验失败：{err}"
            return JSONResponse(
                status_code=400, content={**result, "ok": False, "conflict": "verify_failed"}
            )
        total = _as_dict(_as_dict(data).get("data")).get("total_affected_items")
        result["applied_rules"] = int(total or 0)
        # ② 回读原文，确认落地内容与我们发出的内容一致（忽略行尾空白）
        raw, raw_err = _api(cfg, "GET", f"/rules/files/{filename}", params={"raw": "true"})
        if raw_err:
            result["detail"] = (
                f"已上传（生效 {result['applied_rules']} 条），但回读原文失败：{raw_err}"
            )
            return result
        landed = raw if isinstance(raw, str) else str(raw)
        same = _strip_lines(landed) == _strip_lines(text)
        result["verified"] = same and result["applied_rules"] >= len(rule_ids)
        result["detail"] = (
            f"已下发并校验通过：生效 {result['applied_rules']} 条规则"
            if result["verified"]
            else (
                f"已上传，但校验不一致（生效 {result['applied_rules']} 条 / 发出 {len(rule_ids)} 条，"
                f"内容{'一致' if same else '不一致'}）—— 请到 manager 上核对"
            )
        )
    return result


def _strip_lines(text: str) -> str:
    return "\n".join(line.rstrip() for line in (text or "").strip().splitlines())
