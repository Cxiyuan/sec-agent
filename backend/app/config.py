"""应用配置：全部走环境变量，pydantic-settings 读取。"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ST_", extra="ignore")

    # 通用
    app_name: str = "深瞳 · 安全分析智能体"
    debug: bool = False
    timezone: str = "Asia/Shanghai"

    # Elasticsearch
    es_url: str = "http://localhost:9200"
    es_user: str = ""
    es_password: str = ""
    es_zeek_index: str = "zeek-*"
    es_wazuh_index: str = "wazuh-alerts-*"
    es_verify_certs: bool = False

    # PostgreSQL
    pg_url: str = "postgresql+psycopg://shentong:shentong@localhost:5432/shentong"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # 分析窗口
    analysis_interval_minutes: int = 5
    analysis_window_minutes: int = 5
    baseline_observe_days: int = 7

    # 拉取护栏 / 检索上限
    max_logs_per_window: int = 20000  # 单窗口拉取上限（护栏）
    rag_max_ips: int = 0  # RAG 检索 IP 上限，0 = 不限制

    # 回溯（LLM 决定时长，后端封顶）
    lookback_max_days: int = 7
    lookback_max_logs: int = 5000
    lookback_max_events: int = 200

    # 分析记忆
    memory_recall_limit: int = 5
    memory_persistence_days: int = 7
    memory_persistence_threshold: int = 3
    memory_retention_run_days: int = 7
    memory_retention_object_days: int = 180

    # ES IP 字段（可用逗号分隔多个；以 mapping 自检结果为准）
    es_zeek_src_fields: str = "id.orig_h"
    es_zeek_dst_fields: str = "id.resp_h"
    es_wazuh_src_fields: str = "data.srcip"
    es_wazuh_dst_fields: str = "data.dstip"

    # 模型（统一 OpenAI 兼容接口）
    # 三层：本地 edge（初筛降噪）→ 云端 flash（日常分析）→ 云端 deep（深度安全分析）
    edge_model_name: str = "qwen3.8-2b-distill"
    edge_model_base_url: str = "http://localhost:8080/v1"
    edge_model_api_key: str = "not-needed"
    edge_model_timeout: int = 300

    # 云端 one-api 端点（四个云端模型共用；模型名可在后台系统配置里运行时修改）
    cloud_model_base_url: str = "http://localhost:3000/v1"
    cloud_model_api_key: str = ""
    cloud_model_timeout: int = 600

    # 云端模型名（角色分工）
    flash_model_name: str = "flash"  # 日常分析：异常确认/定级/处置/报告正文
    deep_model_name: str = "deep"  # 深度分析：攻击链还原/攻击者画像
    embo_db_model_name: str = "embo-db"  # 向量入库
    embo_query_model_name: str = "embo-query"  # 向量查询

    # 嵌入（RAG 向量化，走 one-api 的 /v1/embeddings）
    embedding_base_url: str = ""  # 留空则回退 cloud_model_base_url
    embedding_api_key: str = ""  # 留空则回退 cloud_model_api_key
    embedding_dim: int = 1536
    embedding_timeout: int = 60

    # 局域网判定（逗号分隔 CIDR）
    lan_cidrs: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    # RAG 参数
    rag_enabled: bool = True
    rag_top_k: int = 5
    rag_min_score: float = 0.0
    rag_chunk_size: int = 500
    rag_chunk_overlap: int = 100
    rag_upload_dir: str = "/data/uploads"

    # 录入校验收紧
    asset_csv_max_mb: int = 20
    asset_csv_max_rows: int = 10000
    doc_min_chars: int = 10
    text_encodings: str = "utf-8,gb18030"

    # 网络拓扑
    topology_hops: int = 2  # 结构化检索上下游跳数
    topology_max_nodes: int = 10  # 单次渲染节点上限
    topology_max_nodes_per_graph: int = 500  # 单张拓扑节点上限（保存校验）

    # 升级与报告阈值（可被系统配置覆盖）
    escalate_score_threshold: float = 0.6
    report_min_severity: str = "medium"  # critical/high/medium/low/info
    hitl_enabled: bool = False
    hitl_min_severity: str = "high"  # 达到该级别才触发人工确认

    # 威胁情报
    intel_enabled: bool = True
    intel_api_url: str = ""
    intel_api_key: str = ""
    intel_timeout: int = 10

    # 认证
    jwt_secret: str = "change-me-in-production"
    jwt_expire_minutes: int = 720
    default_admin_username: str = "admin"
    default_admin_password: str = "admin123"

    # 报告
    report_storage_dir: str = "/data/reports"

    # 局域网部署（CORS 允许的前端源，逗号分隔）
    cors_origins: str = "http://localhost:3000,http://localhost:8080"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
