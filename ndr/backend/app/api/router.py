"""API 路由聚合（NDR 侧）。"""

from fastapi import APIRouter

from app.api.routes import (
    agent_push,
    auth,
    baseline,
    detector,
    es_admin,
    exclusions,
    files,
    ingest_filters,
    logstash,
    mcp,
    rules,
    wazuh,
    zeek,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(exclusions.router)
api_router.include_router(ingest_filters.router)
api_router.include_router(rules.router)
api_router.include_router(es_admin.router)
api_router.include_router(logstash.router)
api_router.include_router(detector.router)
api_router.include_router(baseline.router)
api_router.include_router(zeek.router)
api_router.include_router(files.router)
api_router.include_router(mcp.router)
api_router.include_router(agent_push.router)
api_router.include_router(wazuh.router)
