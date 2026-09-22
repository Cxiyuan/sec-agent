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

    # 模型（统一 OpenAI 兼容接口）
    edge_model_name: str = "qwen3.8-2b-distill"
    edge_model_base_url: str = "http://localhost:8080/v1"
    edge_model_api_key: str = "not-needed"
    edge_model_timeout: int = 300

    cloud_model_name: str = "minimax-text"
    cloud_model_base_url: str = "http://localhost:3000/v1"  # 局域网 one-api
    cloud_model_api_key: str = ""
    cloud_model_timeout: int = 600

    # 嵌入模型（RAG 向量化，走 one-api 的 /v1/embeddings）
    embedding_base_url: str = ""  # 留空则回退 cloud_model_base_url
    embedding_model_name: str = "text-embedding-3-small"
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
