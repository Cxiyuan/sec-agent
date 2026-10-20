"""API 路由聚合（NDR 侧）。"""

from fastapi import APIRouter

from app.api.routes import (
    agent_push,
    assets_center,
    auth,
    baseline,
    detector,
    es_admin,
    exclusions,
    files,
    ingest_filters,
    logs,
    logstash,
    mcp,
    rules,
    traffic_views,
    zeek,
)

# 总览页的三个新只读端点：直接用「子模块」形式导入（与上面同义的另一种写法，
# 这里刻意保持模块名可读、便于按名字定位文件）。
from app.api.routes.chain import router as chain_router
from app.api.routes.config_audit import router as config_audit_router
from app.api.routes.health_components import router as health_components_router
from app.api.routes.stats_overview import router as stats_overview_router
from app.api.routes.system_metrics import router as system_metrics_router
from app.api.routes.topology import router as topology_router

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(exclusions.router)
api_router.include_router(ingest_filters.router)
api_router.include_router(rules.router)
api_router.include_router(es_admin.router)
api_router.include_router(logstash.router)
api_router.include_router(detector.router)
api_router.include_router(stats_overview_router)
api_router.include_router(system_metrics_router)
api_router.include_router(health_components_router)
api_router.include_router(baseline.router)
api_router.include_router(zeek.router)
api_router.include_router(files.router)
api_router.include_router(mcp.router)
api_router.include_router(agent_push.router)
api_router.include_router(chain_router)
api_router.include_router(topology_router)
api_router.include_router(config_audit_router)
api_router.include_router(logs.router)
api_router.include_router(traffic_views.router)
api_router.include_router(assets_center.router)
