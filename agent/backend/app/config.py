"""应用配置（Agent 侧）：全部走环境变量，pydantic-settings 读取。

契约字段（与 ndr 侧保持一致）单独成块；Agent 独有字段在后。
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ST_", extra="ignore")

    # ---------- 契约（两侧一致，值必须相同） ----------
    # 通用
    app_name: str = "深瞳 · 安全分析智能体"
    debug: bool = False
    timezone: str = "Asia/Shanghai"

    # Elasticsearch：智能体侧已无直连（取数全部走 NDR 的 MCP），故这里不再有 es.* 配置。
    # ES 地址/索引/保留期由 NDR 侧自己维护（见 ndr/backend/app/config.py）。

    # PostgreSQL
    pg_url: str = "postgresql+psycopg://shentong:shentong@localhost:5432/shentong"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # 队列 / 计数键名（契约）
    detector_raw_queue: str = "shentong:events:raw"
    detector_digest_queue: str = "shentong:events:digest"
    detector_processing_queue: str = "shentong:events:processing"
    detector_delivery_queue: str = "shentong:events:dispatch"  # ndr 审后投递队列（agent 消费）
    detector_handled_key: str = "shentong:handled:docs"
    detector_drop_key: str = "shentong:detector:dropped"
    detector_dedup_key: str = "shentong:detector:dedup"
    detector_task_failed_key: str = "shentong:detector:task_failed"
    detector_digest_max_age_seconds: int = 1800  # 摘要最长安存秒数，超龄丢弃（契约：与 ndr 一致）

    # 事件组时间桶（分钟）：与 ndr 摘要指纹同一桶宽
    group_bucket_minutes: int = 30

    # ---------- 第 5 期：NDR 经 HTTP 推送摘要 ----------
    # 接收令牌（契约：与 NDR 侧「智能体推送」配置里填的令牌一致）。空 = 拒绝所有推送。
    push_token: str = ""
    # 判重标记（Redis）：同一事件组指纹在桶宽内只跑一次图，重复推送只加计数
    push_dedup_key: str = "shentong:agent:push"
    # 单次推送最多接受的摘要条数（防止一个请求打爆图）
    push_max_items: int = 500

    # 误报治理（判据集中在 triage_policy，两侧一致）
    policy_internal_routine_skip: bool = True
    policy_skip_rules: list[str] = ["内置-扫描尝试连接", "内置-文件传输可观测"]
    policy_internal_routine_min_severity: str = "medium"
    policy_internal_routine_max_dst: int = 1
    policy_internal_routine_require_failed: bool = True
    severity_cap_internal: str = "medium"
    severity_require_evidence_above: str = "high"
    severity_critical_requires_external: bool = True
    escalate_require_rule_severity: str = "low"
    escalate_allow_external: bool = True
    prefilter_penalty_established: float = 0.3
    prefilter_penalty_known_asset: float = 0.2
    prefilter_penalty_common_port: float = 0.2
    evidence_bytes_out_strong: int = 10485760
    escalate_score_threshold: float = 0.4
    # 可疑 JA3 指纹（逗号分隔）；为空时「内置-JA3指纹命中」规则自动禁用（两侧种子同一套规则）
    ja3_blocklist: str = ""

    # ingestion 解析共享（两侧各持一份解析代码，字段名/截断必须一致）
    account_form_fields: str = "username,user,email,login,account,uname,userid"
    http_body_fields: str = (
        "request_body,body,post_body,payload,http.request.body,http.request_body"
    )
    http_body_max_chars: int = 2000
    http_cookie_max_chars: int = 200
    web_login_path_regex: str = (
        "(?i)/(login|signin|sign-in|auth|authorize|session|sso|oauth|token|passwd|password)($|[/?])"
    )
    max_logs_per_window: int = 20000
    exclusion_cache_seconds: int = 30

    # 认证
    jwt_secret: str = "change-me-in-production"
    jwt_expire_minutes: int = 720
    default_admin_username: str = "admin"
    default_admin_password: str = "admin123"

    # CORS
    cors_origins: str = "http://localhost:3000,http://localhost:8080"

    # ---------- Agent 独有 ----------
    # 分析窗口 / 兜底
    analysis_interval_minutes: int = 15
    analysis_window_minutes: int = 5
    baseline_observe_days: int = 7  # 基线观测期：不足 N 天只学习不判异常
    analysis_stuck_minutes: int = 30  # 事件组停在 analyzing 超过该分钟数视为"分析未收敛"
    analysis_task_budget_seconds: int = 900  # 单任务时间预算（接近就正常收尾）
    analysis_max_redeliveries: int = 2  # 同一批摘要最多重投次数
    run_window_lock_ttl_seconds: int = 1800  # 兜底任务分布式锁 TTL
    investigation_dispatch_batch_max: int = 8  # 清理后自动派发并发上限

    # 拉取护栏 / 检索上限
    rag_max_ips: int = 0  # RAG 检索 IP 上限，0 = 不限制

    # ---------- NDR MCP（智能体取数的唯一入口） ----------
    # 查询 / 调查 / 写回结论全部走 MCP，智能体不再直连 ES。
    # 令牌在 NDR 界面「系统配置 → MCP 接入」里生成（明文只显示一次）。
    mcp_url: str = "http://ndr-mcp:8090/mcp"
    mcp_token: str = ""
    # 单次工具调用的等待上限；要大于 NDR 侧单次 ES 查询的 45 秒，否则永远等不到结果
    mcp_timeout_seconds: float = 90.0

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

    # 模型（统一 OpenAI 兼容接口）：本地 edge → 云端 flash → 云端 deep
    edge_model_timeout: int = 300
    edge_review_concurrency: int = 8
    edge_max_tokens: int = 512
    edge_max_tokens_thinking: int = 4096
    cloud_model_base_url: str = "https://api.minimaxi.com/v1"
    cloud_model_timeout: int = 600
    cloud_max_tokens_flash: int = 4096
    cloud_max_tokens_deep: int = 8192
    cloud_max_concurrency: int = 4
    cloud_max_retries: int = 3
    cloud_retry_base_seconds: float = 2.0

    # 嵌入（RAG 向量化）
    embedding_dim: int = 1536
    embedding_timeout: int = 60

    # 局域网判定（逗号分隔 CIDR）
    lan_cidrs: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

    # RAG 参数
    rag_enabled: bool = True
    rag_top_k: int = 5
    rag_min_score: float = 0.4
    rag_chunk_size: int = 500
    rag_chunk_overlap: int = 100

    # 录入校验收紧
    asset_csv_max_mb: int = 20
    asset_csv_max_rows: int = 10000
    doc_min_chars: int = 10
    text_encodings: str = "utf-8,gb18030"

    # 兜底预筛（防漏报）：规则未命中的日志经启发式打分后交边缘模型复筛
    prefilter_enabled: bool = True
    prefilter_min_score: float = 0.3
    prefilter_max_candidates: int = 300
    prefilter_bytes_out_warn: int = 10 * 1024 * 1024
    prefilter_bytes_out_alert: int = 100 * 1024 * 1024
    prefilter_query_len_warn: int = 100

    # 账号 / 会话跨窗口长期画像（UEBA）
    profile_enabled: bool = True
    profile_min_obs: int = 5
    profile_risk_threshold: float = 0.6
    profile_retention_days: int = 180
    session_cookie_names: str = (
        "JSESSIONID,PHPSESSID,SESSION,ASP.NET_SessionId,connect.sid,token,sid"
    )

    # 网络拓扑
    topology_hops: int = 2
    topology_max_nodes: int = 10
    topology_max_nodes_per_graph: int = 500

    # 升级与报告阈值
    report_min_severity: str = "low"
    report_min_interval_minutes: int = 30
    hitl_enabled: bool = False
    hitl_min_severity: str = "high"

    # 自主取证调查（深度分析路径上的「有界自主」）
    investigation_enabled: bool = True
    investigation_min_severity: str = "medium"
    investigation_max_steps: int = 24
    investigation_max_queries: int = 40
    investigation_max_llm_calls: int = 16
    investigation_timeout_seconds: int = 600
    investigation_invalid_json_limit: int = 4
    investigation_no_progress_steps: int = 4
    investigation_repeat_action_limit: int = 3
    investigation_max_steps_hard: int = 60
    investigation_max_llm_calls_hard: int = 24
    investigation_salvage_enabled: bool = True
    investigation_salvage_model: str = "flash"
    investigation_max_extensions: int = 6
    investigation_query_timeout_seconds: float = 45.0
    investigation_timeline_max_hours: int = 72
    investigation_max_docs_per_query: int = 2000
    investigation_raw_evidence_max: int = 20
    investigation_observation_chars: int = 1500
    investigation_keep_observations: int = 3
    investigation_max_prompt_chars: int = 24000
    investigation_tool_timeout_seconds: float = 20.0
    investigation_cooldown_minutes: int = 60
    investigation_max_rounds_per_day: int = 6
    investigation_link_window_hours: int = 24
    investigation_link_max_calls: int = 3
    investigation_max_lookback_days: int = 30
    investigation_keep_fixed_deep: bool = True
    case_stale_close_days: int = 7
    # 归并与定级治理
    case_max_groups: int = 40
    case_split_by_actor: bool = True
    consistency_guard: bool = True
    contradiction_confidence_cap: float = 0.3
    degraded_tool_error_limit: int = 3
    key_require_domain_field: bool = True

    # 威胁情报（免费在线服务）
    intel_enabled: bool = True
    intel_api_url: str = ""
    intel_api_key: str = ""
    intel_timeout: int = 3
    intel_cache_ttl: int = 600
    intel_max_queries_per_group: int = 20

    # 技能库
    skill_enabled: bool = True
    skill_max_per_group: int = 3
    skill_sop_max_chars: int = 3000
    active_scan_enabled: bool = False
    active_scan_timeout: float = 1.0
    active_scan_max_ports: int = 100
    active_scan_ports: str = (
        "21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,"
        "5432,5900,6379,8080,8443,9200"
    )

    # 报告
    report_storage_dir: str = "/data/reports"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
