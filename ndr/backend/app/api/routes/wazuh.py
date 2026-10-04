"""Wazuh 4.14 接入管理（第 6 期）：接入状态、Agent 清单、规则文件下发与生效校验。

设计要点：

- **连接信息不可由用户配置**：Wazuh 是随本项目一起部署的内置服务（见
  `docker-compose.wazuh.yml`），地址 / 用户名 / 密码 / 是否校验 TLS 全部由部署环境
  给定（`ST_WAZUH_API_URL` / `ST_WAZUH_API_USER` / `ST_WAZUH_API_PASSWORD` /
  `ST_WAZUH_API_VERIFY_TLS`），本模块只**读**环境变量，不写库、也没有保存接口 ——
  界面上不再出现「填地址 + 填密码 + 保存」这一步。第 6 期把凭据存进
  `SystemConfig.wazuh.params` 的写法已废弃，遗留的该行**不再被读取**。
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

from app.api.deps import get_current_user
from app.config import settings
from app.db.models import User
from app.ingestion import es_config
from app.ingestion.es_client import get_es
from app.investigation import catalog
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/wazuh", tags=["wazuh"])

DEFAULT_PORT = 55000
#: token 提前这么久重新登录（Wazuh 默认有效期 900s）
TOKEN_SAFETY_SECONDS = 60.0
#: 自定义规则文件名：只允许一层、必须以 .xml 结尾（防目录穿越）
RULE_FILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}\.xml$")
RULE_ID_RE = re.compile(r"<rule\s[^>]*id\s*=\s*\"(\d+)\"")

HINT = (
    "主机监控随本项目一起部署，连接信息由部署环境固定（`.env` 的 `WAZUH_API_*` → 后台的 "
    "`ST_WAZUH_API_*`），不需要在这里配置；本页只显示接入状态。"
    "「接入状态」会分别显示 API 是否可达、以及最近 24 小时告警/原始日志各入库多少条。"
    "注意：主机监控采的是主机日志，与「监控网段」无关 —— 那份清单只约束网络采集器抓包。"
)

#: (url|user) -> (写入时刻, 过期时刻, token)
_token_cache: dict[str, tuple[float, float, str]] = {}


class WazuhRuleIn(BaseModel):
    filename: str = "local_rules.xml"
    text: str
    verify: bool = True


# ---------- 连接配置（只来自部署环境） ----------


def _cfg() -> dict[str, Any]:
    """当前生效的连接信息：**只有环境变量这一个来源**。

    以前这里会先读 `SystemConfig.wazuh.params` 再让界面保存的值覆盖环境默认值；
    现在 Wazuh 是内置服务，连接信息在部署时就固定了，所以库里的那份配置
    （如果之前存过）被彻底忽略 —— 留着一个能改地址/密码的入口只会造成
    「界面写了一个地址、实际连的是另一个」这类问题。
    """
    return {
        "url": _normalize_url(settings.wazuh_api_url),
        "user": settings.wazuh_api_user,
        "password": settings.wazuh_api_password,
        "verify_tls": settings.wazuh_api_verify_tls,
    }


def _normalize_url(url: str) -> str:
    """补全 scheme/端口并去掉尾部斜杠；空值原样返回。"""
    raw = (url or "").strip().rstrip("/")
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"https://{raw}"
    return raw


def _public(cfg: dict[str, Any]) -> dict[str, Any]:
    password = str(cfg.get("password") or "")
    return {
        "url": str(cfg.get("url") or ""),
        "user": str(cfg.get("user") or ""),
        "password_set": bool(password),
        "verify_tls": bool(cfg.get("verify_tls")),
        # 地址 + 凭据齐全才算「已配置」（缺什么由部署环境补，界面改不了）
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
        return None, "部署环境没有配全主机监控 API 地址 / 用户名 / 密码（ST_WAZUH_API_*）"
    cache_key = f"{url}|{user}"
    now = time.monotonic()
    cached = _token_cache.get(cache_key)
    if cached and cached[1] > now:
        return cached[2], ""

    try:
        with httpx.Client(timeout=_timeout(), verify=_verify(cfg)) as client:
            resp = client.post(f"{url}/security/user/authenticate", auth=(user, password))
    except Exception as exc:  # noqa: BLE001
        return None, f"连接主机监控 API 失败：{exc}"
    if resp.status_code == 401:
        return None, "主机监控 API 认证失败（用户名或密码不正确）"
    if resp.status_code >= 400:
        return None, f"主机监控 API 登录失败：HTTP {resp.status_code} {resp.text[:200]}"
    try:
        token = str(resp.json().get("data", {}).get("token") or "")
    except ValueError:
        return None, "主机监控 API 登录响应不是 JSON"
    if not token:
        return None, "主机监控 API 没有返回 token"
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
    raw: bool = False,
    strict: bool = False,
) -> tuple[Any | None, str]:
    """带鉴权的 Wazuh API 请求；返回 (响应内容, 错误说明)。

    `raw=True` 表示这个端点回的是**原文而不是 JSON**（如
    `GET /rules/files/<name>?raw=true` 回 `application/xml`）。不区分就会在
    `resp.json()` 上炸掉、判成「Wazuh API 响应不是 JSON」——实机踩到：后果是
    「下发规则文件」的回读原文那一步永远失败、`verified` 永远 false。

    `strict=True` 表示**连 body 里的失败也算失败**（见 `_body_error`）。Wazuh 有些
    写操作失败时回的是 HTTP 200 + body 里 `error=1`/`total_failed_items>0`，只看状态码
    会把「没写进去」当成功——实机踩到：后果是下发规则悄悄没生效却报「已上传」。
    """
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
        return None, f"请求主机监控 API 失败：{exc}"
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
            return None, f"请求主机监控 API 失败：{exc}"
    if resp.status_code >= 400:
        return None, f"主机监控 API 返回 HTTP {resp.status_code}：{resp.text[:200]}"
    if raw:
        return resp.text, ""
    try:
        data = resp.json()
    except ValueError:
        return None, "主机监控 API 响应不是 JSON"
    if strict:
        body_err = _body_error(data)
        if body_err:
            return None, body_err
    return data, ""


def _body_error(data: Any) -> str:
    """把 Wazuh 回在 **HTTP 200 body 里**的失败翻译成人话（没有失败就回空串）。

    实机踩到：`PUT /rules/files/<name>` 覆盖一个已存在的文件时回的是 HTTP 200
    + body `{"error": 1, "message": "Could not upload rule", "data":
    {"total_failed_items": 1, "failed_items": [{"error": {"code": 1905,
    "message": "File could not be updated, it already exists", "remediation":
    "... set overwrite=True to overwrite actual file"}}]}}`。只看 HTTP 状态码就会
    判成「上传成功」，再拿旧文件的回读结果去比对，得到「已上传但内容不一致」这种
    查不出原因的告警（规则其实一条都没更新）。
    """
    body = _as_dict(data)
    if not body:
        return ""
    inner = _as_dict(body.get("data"))
    failed = int(inner.get("total_failed_items") or 0)
    code = body.get("error")
    if not failed and not (isinstance(code, int) and code != 0):
        return ""
    parts = [str(body.get("message") or "主机监控 API 报错")]
    items = inner.get("failed_items")
    for item in items[:3] if isinstance(items, list) else []:
        info = _as_dict(_as_dict(item).get("error"))
        detail = str(info.get("message") or "")
        fix = str(info.get("remediation") or "")
        if detail:
            parts.append(f"{detail}（{fix}）" if fix else detail)
    return "；".join(parts)


def _count_rules(
    cfg: dict[str, Any], filename: str, want: int, timeout: float = 8.0
) -> tuple[int, str]:
    """回读某个规则文件在 manager 上**生效的规则条数**（带轮询）。

    为什么轮询而不是读一次：实机踩到「下发后立刻回读拿到 0」——manager 侧的规则集
    是有扫描滞后的（实测几秒后才看得见；同样的操作第二次又可能立刻可见）。读一次就
    把结果当结论，会把「已经生效」误判成「没生效」，而这个数字正是「下发是否真的
    生效」的唯一证据。轮询到期仍未到 `want` 也按当前条数返回，交给调用方判定。

    返回 (条数, 错误说明)：只有一次都没读成功才带错误说明。
    """
    deadline = time.monotonic() + max(0.0, timeout)
    total = 0
    last_err = ""
    while True:
        data, err = _api(cfg, "GET", "/rules", params={"filename": filename, "limit": 1})
        if err:
            last_err = err
        else:
            last_err = ""
            total = int(_as_dict(_as_dict(data).get("data")).get("total_affected_items") or 0)
            if total >= want:
                return total, ""
        if time.monotonic() >= deadline:
            return total, last_err
        time.sleep(0.5)


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
        out["detail"] = "还没填主机监控 API 地址"
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


def probe_status() -> dict[str, Any]:
    """连通性 + 基本信息（总览页的组件灯也用它，避免两处各写一遍探测）。"""
    return _probe(_cfg())


def ingest_stats() -> dict[str, Any]:
    """近 24 小时 source_system=wazuh 的告警/原始日志条数（组件灯判「接了但没数据」）。"""
    return _ingest_stats()


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


def _payload() -> dict[str, Any]:
    cfg = _cfg()
    public = _public(cfg)
    status = (
        _probe(cfg)
        if public["configured"]
        else {
            "reachable": False,
            "url": public["url"],
            "version": "",
            "cluster_enabled": False,
            "detail": "部署环境没有配全主机监控 API 地址 / 用户名 / 密码（ST_WAZUH_API_*）",
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
        "hint": HINT,
    }


# ---------- 路由 ----------


@router.get("")
def get_wazuh(_: Annotated[User, Depends(get_current_user)]):
    """接入状态（只读）。

    Wazuh 随项目一起部署，连接信息由部署环境固定，所以这里**没有** `PUT` 保存配置、
    也没有「测试连接」入口 —— 页面只显示状态与入库量。
    """
    return _payload()


@router.get("/status")
def get_status(_: Annotated[User, Depends(get_current_user)]):
    """Wazuh 探活 + 近 24h 入库量。

    与 `GET /api/wazuh`（`_payload`）内容重叠、界面没调它；保留为对外只读能力
    （复刻 Wazuh API 的 status 资源，脚本/智能体可直接取）。
    """
    return {**_probe(_cfg()), "ingest": _ingest_stats()}


@router.get("/agents")
def list_agents(
    _: Annotated[User, Depends(get_current_user)],
    status: str = "",
    limit: int = 500,
):
    """Wazuh Agent 清单（可按状态过滤）+ 分桶统计。

    同上：界面通过 `GET /api/wazuh` 拿同样的清单，这个独立入口保留给外部只读使用。
    """
    cfg = _cfg()
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
def list_rule_files(_: Annotated[User, Depends(get_current_user)], limit: int = 200):
    cfg = _cfg()
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
                "detail": "内容看起来不是主机监控规则文件（需要 <group> 与 <rule>）",
            },
        )
    cfg = _cfg()
    _sent, err = _api(
        cfg,
        "PUT",
        f"/rules/files/{filename}",
        # `overwrite=true` 不能省：Wazuh 4.14 的 PUT 默认**不覆盖**已存在的文件，
        # 同名文件会回 HTTP 200 + body `error=1`/code 1905「File could not be
        # updated, it already exists」。实机踩到：不带它时规则一条都没更新，却因为
        # 只看状态码而报「已上传」，再拿旧文件的回读去比对就变成「内容不一致」。
        params={"overwrite": "true"},
        content=text.encode("utf-8"),
        headers={"Content-Type": "application/octet-stream"},
        strict=True,
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
        #    轮询到几秒：manager 侧规则集扫描有滞后（见 `_count_rules`）
        total, err = _count_rules(cfg, filename, want=len(rule_ids))
        if err:
            result["detail"] = f"已上传，但回读校验失败：{err}"
            return JSONResponse(
                status_code=400, content={**result, "ok": False, "conflict": "verify_failed"}
            )
        result["applied_rules"] = total
        # ② 回读原文，确认落地内容与我们发出的内容一致（忽略行尾空白）
        #    `raw=true` 回的是 XML 原文，必须让 `_api` 别按 JSON 解析
        raw, raw_err = _api(
            cfg, "GET", f"/rules/files/{filename}", params={"raw": "true"}, raw=True
        )
        if raw_err:
            result["detail"] = (
                f"已上传（生效 {result['applied_rules']} 条），但回读原文失败：{raw_err}"
            )
            return result
        landed = raw if isinstance(raw, str) else str(raw)
        same = _strip_lines(landed) == _strip_lines(text)
        result["verified"] = same and result["applied_rules"] >= len(rule_ids)
        head = (
            f"生效 {result['applied_rules']} 条 / 发出 {len(rule_ids)} 条，内容"
            f"{'一致' if same else '不一致'}"
        )
        if result["verified"]:
            result["detail"] = f"已下发并校验通过：生效 {result['applied_rules']} 条规则"
        elif same:
            # 条数够了但内容一致 ⇒ 通常是 manager 侧还没把新文件扫进规则集
            result["detail"] = f"已上传，但校验不一致（{head}）—— 请到 manager 上核对"
        else:
            # 只报「内容不一致」时运维看不出差在哪（实测就是「规则压根没写进去」），
            # 所以顺带指出首个不同的行
            result["detail"] = f"已上传，但校验不一致（{head}）：{_first_diff(text, landed)}"
    return result


def _strip_lines(text: str) -> str:
    return "\n".join(line.rstrip() for line in (text or "").strip().splitlines())


def _first_diff(sent: str, landed: str) -> str:
    """给「回读内容与发出内容不一致」一句能直接定位的说明。

    实测这条告警只说了「内容不一致」，看不出是差在行尾还是**根本没写进去**
    （后者才是真因：Wazuh 的 PUT 默认不覆盖同名文件）。这里指出首个不同的行号与
    两侧原文（截断），让运维一眼能判断。
    """
    want = _strip_lines(sent).splitlines()
    got = _strip_lines(landed).splitlines()
    for i in range(max(len(want), len(got))):
        left = want[i] if i < len(want) else "（没有这一行）"
        right = got[i] if i < len(got) else "（没有这一行）"
        if left != right:
            return (
                f"首个不同的行是第 {i + 1} 行"
                f"（manager「{right.strip()[:60]}」/ 发出「{left.strip()[:60]}」）"
            )
    return "内容相同（差异只在行尾空白）"
