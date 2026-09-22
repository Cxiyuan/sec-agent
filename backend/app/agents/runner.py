"""图运行器：持有编译后的图（Postgres checkpointer），支持 HITL 恢复。"""

from __future__ import annotations

from typing import Any, cast

from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.types import Command
from psycopg import Connection
from psycopg.rows import DictRow, dict_row
from psycopg_pool import ConnectionPool

from app.agents.graph import build_graph
from app.config import settings

_pool: ConnectionPool[Connection[DictRow]] | None = None
_graph: Any = None


def _conn_string() -> str:
    # SQLAlchemy URL -> libpq DSN
    return settings.pg_url.replace("postgresql+psycopg://", "postgresql://")


def get_graph() -> Any:
    global _pool, _graph
    if _graph is None:
        _pool = cast(
            ConnectionPool[Connection[DictRow]],
            ConnectionPool(
                _conn_string(), open=False, kwargs={"autocommit": True, "row_factory": dict_row}
            ),
        )
        _pool.open()
        checkpointer = PostgresSaver(_pool)
        checkpointer.setup()
        _graph = build_graph(checkpointer=checkpointer)
    return _graph


def resume_graph(thread_id: str, decision: dict[str, Any]) -> dict[str, Any]:
    """HITL 恢复：以人工确认结果续跑被 interrupt 暂停的图。"""
    graph = get_graph()
    config = {"configurable": {"thread_id": thread_id}}
    return graph.invoke(Command(resume=decision), config)
