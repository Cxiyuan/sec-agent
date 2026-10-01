"""API 路由聚合（Agent 侧）。"""

from fastapi import APIRouter

from app.api.routes import (
    assets,
    auth,
    cloud,
    config,
    documents,
    edge,
    events,
    investigation,
    memories,
    profiles,
    push,
    reports,
    skills,
    topologies,
    ws,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(assets.router)
api_router.include_router(documents.router)
api_router.include_router(cloud.router)
api_router.include_router(edge.router)
api_router.include_router(topologies.router)
api_router.include_router(memories.router)
api_router.include_router(profiles.router)
api_router.include_router(events.router)
api_router.include_router(investigation.router)
api_router.include_router(investigation.tools_router)
api_router.include_router(skills.router)
api_router.include_router(reports.router)
api_router.include_router(config.router)
api_router.include_router(ws.router)
api_router.include_router(push.router)
