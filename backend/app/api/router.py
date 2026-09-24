"""API 路由聚合。"""

from fastapi import APIRouter

from app.api.routes import (
    analysis_scopes,
    assets,
    auth,
    cloud,
    config,
    detector,
    documents,
    edge,
    es_admin,
    events,
    logstash,
    memories,
    profiles,
    reports,
    rules,
    skills,
    topologies,
    ws,
    zeek,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(analysis_scopes.router)
api_router.include_router(assets.router)
api_router.include_router(documents.router)
api_router.include_router(cloud.router)
api_router.include_router(edge.router)
api_router.include_router(topologies.router)
api_router.include_router(memories.router)
api_router.include_router(profiles.router)
api_router.include_router(events.router)
api_router.include_router(rules.router)
api_router.include_router(skills.router)
api_router.include_router(reports.router)
api_router.include_router(config.router)
api_router.include_router(es_admin.router)
api_router.include_router(logstash.router)
api_router.include_router(detector.router)
api_router.include_router(zeek.router)
api_router.include_router(ws.router)
