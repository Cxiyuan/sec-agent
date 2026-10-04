"""智能体侧的 MCP 客户端（同步 API）。

为什么需要这一层：调查链路整体是**同步**的（Celery 任务 → LangGraph `invoke` → planner 的
文本 ReAct 循环），而官方 MCP SDK 是 async-first。这里用一个常驻的后台事件循环线程持有
一条 streamable HTTP 会话，对外只暴露同步的 `call()` / `list_tools()`。

失败语义：**不让网络错误冒到调用方**。工具层原本的行为就是「查不到也回一段能读的文本」，
模型看到 `{"error": ...}` 会换一种查法或记一条信息缺口，比整轮调查崩掉好得多。
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

from app.config import settings

log = logging.getLogger(__name__)

_loop: asyncio.AbstractEventLoop | None = None
_thread: threading.Thread | None = None
_boot_lock = threading.Lock()
#: 会话重建的**单飞**锁（跑在后台循环里）。没它的话，两个线程同时发现会话为空就会
#: 各自建一条连接、`_stack` 被后建的覆盖，先建的那条泄漏（2026-10 MCP QA）。
_session_lock: asyncio.Lock | None = None
# 会话与它的 AsyncExitStack 只在后台循环里使用，别的线程不碰（Any 是为了不把 SDK 类型
# 拖进类型检查——它在 1.x/2.x 之间改过名，标注具体类型只会让升级时到处报错）
_session: Any = None
_stack: Any = None
# 建立会话时用的 (地址, 令牌)：两者一变就重建会话，避免换了配置还在用旧连接
_conn: tuple[str, str] | None = None


def enabled() -> bool:
    """没配地址就当没启用（本地跑单测、或智能体还没接 NDR 时）。"""
    return bool(settings.mcp_url)


def _ensure_loop() -> asyncio.AbstractEventLoop:
    global _loop, _thread, _session_lock
    with _boot_lock:
        if _loop is None or _thread is None or not _thread.is_alive():
            loop = asyncio.new_event_loop()
            thread = threading.Thread(target=loop.run_forever, name="mcp-client", daemon=True)
            thread.start()
            _loop, _thread = loop, thread
            # 3.10+ 的 asyncio.Lock 不在构造时绑定事件循环，可以在这里建
            _session_lock = asyncio.Lock()
            log.debug("MCP 客户端后台事件循环已启动")
        return _loop


async def _connect() -> None:
    """建立会话：自己带 Authorization 头（SDK 的 streamable_http_client 只管传输）。"""
    from contextlib import AsyncExitStack

    import httpx2
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    headers = {"Authorization": f"Bearer {settings.mcp_token}"} if settings.mcp_token else {}
    stack = AsyncExitStack()
    client = await stack.enter_async_context(
        httpx2.AsyncClient(headers=headers, timeout=settings.mcp_timeout_seconds)
    )
    read, write = await stack.enter_async_context(
        streamable_http_client(settings.mcp_url, http_client=client)
    )
    session = await stack.enter_async_context(ClientSession(read, write))
    await session.initialize()
    global _stack, _session, _conn
    _stack, _session = stack, session
    _conn = (settings.mcp_url, settings.mcp_token)
    log.info("MCP 会话已建立：%s", settings.mcp_url)


async def _reset() -> None:
    global _stack, _session, _conn
    stack, _session = _stack, None
    _stack = None
    _conn = None
    if stack is not None:
        try:
            await stack.aclose()
        except Exception as exc:  # noqa: BLE001
            log.debug("关闭 MCP 会话时出错（忽略）：%s", exc)


async def _fresh_session() -> Any:
    """按当前配置拿到可用会话（地址或令牌变了就重建）。

    **单飞**：并发调用只会建一条连接，建成后才轮到后来者取用。
    """
    if _session is not None and _conn == (settings.mcp_url, settings.mcp_token):
        return _session
    lock = _session_lock or asyncio.Lock()
    async with lock:
        if _session is None or _conn != (settings.mcp_url, settings.mcp_token):
            await _reset()
            await _connect()
        return _session


def _decode(result: Any) -> dict[str, Any]:
    """把 MCP 的 CallToolResult 摊成普通 dict（服务端回的是 JSON 文本）。"""
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(str(text))
    raw = "\n".join(parts).strip()
    data: Any = {}
    if raw:
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            data = {"text": raw}
    if not isinstance(data, dict):
        data = {"result": data}
    if getattr(result, "isError", False):
        data.setdefault("error", data.get("text") or "工具执行失败")
    return data


async def _call_async(name: str, args: dict[str, Any], timeout: float) -> dict[str, Any]:
    session = await _fresh_session()
    return _decode(await asyncio.wait_for(session.call_tool(name, args), timeout))


def call(name: str, args: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:
    """同步调用一个 MCP 工具；**任何失败都返回 `{"error": ...}`，不抛异常**。

    传输层出错（会话掉了、NDR 重启）会重建一次会话再试一遍；工具自己返回的
    `{"error": ...}` 不算传输失败，直接给模型看。
    """
    if not enabled():
        return {"error": "未配置 NDR MCP 地址（ST_MCP_URL），无法取数"}
    limit = float(timeout or settings.mcp_timeout_seconds)
    loop = _ensure_loop()
    detail = ""
    for attempt in (1, 2):
        try:
            future = asyncio.run_coroutine_threadsafe(_call_async(name, args, limit), loop)
            return future.result(timeout=limit + 10)
        except Exception as exc:  # noqa: BLE001
            detail = str(exc) or exc.__class__.__name__
            log.warning("MCP 调用 %s 失败（第 %d 次）：%s", name, attempt, detail)
            try:
                asyncio.run_coroutine_threadsafe(_reset(), loop).result(timeout=10)
            except Exception as reset_exc:  # noqa: BLE001
                log.debug("重置 MCP 会话失败（忽略）：%s", reset_exc)
    return {"error": f"{name} 调用失败：{detail}"}


async def _list_async() -> list[dict[str, Any]]:
    session = await _fresh_session()
    result = await session.list_tools()
    out: list[dict[str, Any]] = []
    for tool in getattr(result, "tools", None) or []:
        out.append(
            {
                "name": getattr(tool, "name", ""),
                "description": getattr(tool, "description", "") or "",
                "input_schema": getattr(tool, "input_schema", None) or {},
            }
        )
    return out


def list_tools(*, timeout: float | None = None) -> list[dict[str, Any]]:
    """拉取 NDR 暴露的工具清单（自检 / 排查用；失败回空表）。"""
    if not enabled():
        return []
    try:
        future = asyncio.run_coroutine_threadsafe(_list_async(), _ensure_loop())
        return future.result(timeout=float(timeout or settings.mcp_timeout_seconds))
    except Exception as exc:  # noqa: BLE001
        log.warning("MCP 工具清单拉取失败：%s", exc)
        return []
