"""WebSocket 实时推送：驾驶舱订阅分析结果。"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

import redis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import settings

router = APIRouter()

CHANNEL = "shentong:events"


class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


def _redis_listener() -> None:
    r = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    pubsub = r.pubsub()
    pubsub.subscribe(CHANNEL)
    for msg in pubsub.listen():
        if msg.get("type") != "message":
            continue
        try:
            data = json.loads(msg.get("data") or "{}")
        except json.JSONDecodeError:
            continue
        if manager.loop:
            asyncio.run_coroutine_threadsafe(manager.broadcast(data), manager.loop)


def start_listener() -> None:
    t = threading.Thread(target=_redis_listener, daemon=True, name="ws-redis-listener")
    t.start()


@router.websocket("/api/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    manager.loop = asyncio.get_running_loop()
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # 保持连接
    except WebSocketDisconnect:
        manager.disconnect(ws)
