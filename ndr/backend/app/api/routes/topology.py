"""拓扑发现页（/admin/topology）的两个接口：图数据 + 节点别名。

- `GET /api/topology`：两种视图（`mode=forward` 转发链路 / `mode=full` 全量通信）。
  转发链路的口径与「攻击链还原」页完全一致（只画进了检测的那些事件 + 中继上下级边），
  这样两页看到的链路永远对得上。
- `GET/PUT /api/topology/aliases`：节点别名（IP → 显示名），全局生效。

别名是**展示层**数据，改完立即生效、不影响任何检测语义（见 `app/topology/aliases.py`）。
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.base import get_db
from app.db.models import User
from app.topology import aliases, graph as topo_graph
from app.workers.log import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/topology", tags=["topology"])

#: 两种视图
MODES = ("forward", "full")


@router.get("")
def get_topology(
    _: Annotated[User, Depends(get_current_user)],
    mode: str = "forward",
    minutes: int = 60,
    hours: int = 24,
    from_ts: str = "",
    to_ts: str = "",
):
    """拓扑图数据。

    - `mode=forward`（默认）：按**流量转发的逻辑**画（客户端 →（中继…）→ 源站），
      中继与多级串联一定体现出来；时间窗用 `minutes` / `from_ts` / `to_ts`。
    - `mode=full`：ES 按 `src_ip → dst_ip` 聚合 TopN（`hours` 小时窗），节点多、无中继语义。
    """
    if str(mode) not in MODES:
        return JSONResponse(
            status_code=400,
            content={"detail": f"mode 只能是 forward / full，收到 {mode!r}"},
        )
    if str(mode) == "full":
        return topo_graph.full_graph(hours=hours)
    return topo_graph.forward_graph(minutes=minutes, from_ts=from_ts, to_ts=to_ts)


@router.get("/aliases")
def get_aliases(_: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    """全部节点别名（IP → 显示名）；前端用来把图上/列表里的 IP 显示成别名。"""
    return aliases.describe()


class AliasIn(BaseModel):
    ip: str = ""
    #: 空串 = 删除该别名（还原成 IP）
    name: str = ""


@router.put("/aliases")
def set_alias(
    body: AliasIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
):
    """给一个 IP 起名 / 改名 / 删名。校验不过 400 + `field_errors`。"""
    errors: list[dict[str, str]] = []
    ip_error = aliases.validate_ip(body.ip)
    if ip_error:
        errors.append({"field": "ip", "msg": ip_error})
    name_error = aliases.validate_name(body.name)
    if name_error:
        errors.append({"field": "name", "msg": name_error})
    if errors:
        return JSONResponse(
            status_code=400,
            content={
                "conflict": "field_error",
                "detail": errors[0]["msg"],
                "field_errors": errors,
            },
        )
    snapshot = aliases.set_alias(db, body.ip, body.name)
    log.info("拓扑节点别名已更新：%s → %r", body.ip.strip(), body.name.strip())
    return {"aliases": snapshot, "count": len(snapshot)}
