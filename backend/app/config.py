"""应用配置：全部走环境变量，pydantic-settings 读取。"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ST_", extra="ignore")

    # 通用
    app_name: str = "深瞳 · 安全分析智能体"
    debug: bool = False  # True 时日志为 DEBUG 级别（见 workers/log.py）
    timezone: str = "Asia/Shanghai"

    # Elasticsearch
    es_url: str = "http://localhost:9200"
    es_user: str = ""
    es_password: str = ""
    es_zeek_index: str = "zeek-*"
    es_wazuh_index: str = "wazuh-alerts-*"
    es_verify_certs: bool = False
    es_retention_days: int = 30  # ES 日志保留天数（后台可改，下限 = 回溯封顶 7 天）
    es_ilm_policy: str = "shentong-retention"

    # Zeek 采集（镜像侧轮转 24h / 本地保留 3 天为硬编码）
    zeek_conf_dir: str = "/config"
    zeek_iface_conf: str = "/config/interface.conf"
    zeek_interfaces_json: str = "/config/interfaces.json"
    zeek_interface: str = "eth0"
    zeek_bpf_filter: str = ""
    zeek_local_nets: str = ""  # 留空则从「分析网段」自动生成

    # PostgreSQL
    pg_url: str = "postgresql+psycopg://shentong:shentong@localhost:5432/shentong"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # 分析窗口
    analysis_interval_minutes: int = (
        15  # 兜底定时任务间隔（仅环境变量生效；实时链路为主，这是全量兜底）
    )
    analysis_window_minutes: int = 5
    baseline_observe_days: int = 7  # 基线观测期：不足 N 天只学习不判异常（防上线首日误报）

    # 数据接入：检测器（旁路队列实时检测）
    detector_enabled: bool = True
    detector_raw_queue: str = "shentong:events:raw"
    detector_digest_queue: str = "shentong:events:digest"
    detector_processing_queue: str = "shentong:events:processing"
    detector_handled_key: str = "shentong:handled:docs"
    detector_handled_ttl: int = 90000  # 已处理登记保留秒数（需 > 兜底最大回补时长）
    detector_agg_seconds: int = 60  # 短窗聚合时长（源IP+规则）
    detector_agg_max_keys: int = 5000  # 并发聚合态上限（护栏）
    detector_batch_seconds: int = 20  # 攒批：最长等待
    detector_batch_max: int = 5  # 攒批：凑够多少条就触发
    detector_max_per_batch: int = 50  # 单次投递摘要数上限（护栏）
    detector_max_digests_per_minute: int = 60  # 投递速率上限（护栏，防打爆分析管线）
    detector_digest_max_age_seconds: int = 1800  # 摘要最长安存秒数（超龄丢弃，保证分析的是新事件）
    detector_poll_timeout: int = 5  # 队列阻塞读取秒数
    detector_scope_refresh_seconds: int = 60  # 分析网段刷新间隔
    detector_stats_log_seconds: int = 300  # 运行统计日志间隔
    # 频率规则滑动窗口（实时链路用 Redis 滑窗替代“窗口内计数”）
    freq_window_seconds: int = 300
    freq_cooldown_seconds: int = 300  # 同一分组触发后的冷却，防重复告警
    # 兜底任务水位（存 PostgreSQL，跨重启可靠）
    fallback_watermark_key: str = "fallback.last_run"
    fallback_max_backfill_hours: int = 24  # 单次最大回补时长（超限截断并告警）

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
    # Filebeat 把 Zeek 字段放在 zeek.* 命名空间下（避免与其元数据 host/agent/ecs 撞名）
    es_zeek_src_fields: str = "zeek.id.orig_h"
    es_zeek_dst_fields: str = "zeek.id.resp_h"
    es_wazuh_src_fields: str = "data.srcip"
    es_wazuh_dst_fields: str = "data.dstip"

    # 模型（统一 OpenAI 兼容接口）
    # 三层：本地 edge（初筛降噪）→ 云端 flash（日常分析）→ 云端 deep（深度安全分析）
    # 注意：edge 的连接信息（api_key/模型名/端口/路径）已固化在 app/edge_config.py，
    # 环境变量不可覆盖；此处只保留超时等行为参数。
    edge_model_timeout: int = 300

    # 云端模型（MiniMax 国内版；模型名固化见 registry）
    # api_key 由后台界面录入、存数据库（不落环境变量），见 app/cloud_config.py
    cloud_model_base_url: str = "https://api.minimaxi.com/v1"
    cloud_model_timeout: int = 600

    # 嵌入（RAG 向量化，走 MiniMax embo-01）
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

    # 录入校验收紧
    asset_csv_max_mb: int = 20
    asset_csv_max_rows: int = 10000
    doc_min_chars: int = 10
    text_encodings: str = "utf-8,gb18030"

    # 兜底预筛（防漏报）：规则未命中的日志经启发式打分后交边缘模型复筛
    prefilter_enabled: bool = True
    prefilter_min_score: float = 0.3
    prefilter_max_candidates: int = 300
    prefilter_bytes_out_warn: int = 10 * 1024 * 1024  # 10MB
    prefilter_bytes_out_alert: int = 100 * 1024 * 1024  # 100MB
    prefilter_query_len_warn: int = 100

    # Web 深检
    http_body_fields: str = (
        "request_body,body,post_body,payload,http.request.body,http.request_body"
    )
    http_body_max_chars: int = 2000
    http_cookie_max_chars: int = 200
    web_login_path_regex: str = (
        "(?i)/(login|signin|sign-in|auth|authorize|session|sso|oauth|token|passwd|password)($|[/?])"
    )
    ja3_blocklist: str = ""  # 可疑 JA3 指纹（逗号分隔）；为空时「内置-JA3指纹命中」规则自动禁用

    # 账号 / 会话跨窗口长期画像（UEBA）
    profile_enabled: bool = True
    profile_min_obs: int = 5  # 冷启动：低于此观测数只学习不告警
    profile_risk_threshold: float = 0.6
    profile_retention_days: int = 180
    session_cookie_names: str = (
        "JSESSIONID,PHPSESSID,SESSION,ASP.NET_SessionId,connect.sid,token,sid"
    )
    account_form_fields: str = "username,user,email,login,account,uname,userid"

    # 网络拓扑
    topology_hops: int = 2  # 结构化检索上下游跳数
    topology_max_nodes: int = 10  # 单次渲染节点上限
    topology_max_nodes_per_graph: int = 500  # 单张拓扑节点上限（保存校验）

    # 升级与报告阈值（可被系统配置覆盖）
    escalate_score_threshold: float = 0.6
    report_min_severity: str = "medium"  # critical/high/medium/low/info
    hitl_enabled: bool = False
    hitl_min_severity: str = "high"  # 达到该级别才触发人工确认

    # 威胁情报（免费在线服务，无需 API key：ip-api/ipwho.is、rdap.org、abuse.ch 家族）
    intel_enabled: bool = True
    intel_api_url: str = ""  # 可选：自定义情报端点（留空则用内置免费服务）
    intel_api_key: str = ""
    intel_timeout: int = 3  # 免费服务单次超时（秒）
    intel_cache_ttl: int = 600  # 情报结果缓存秒数
    intel_max_queries_per_group: int = 20  # 单事件组查询条数上限（防打爆免费额度）

    # 技能库（安全事件分析 SOP + 脚本工具）
    skill_enabled: bool = True
    skill_max_per_group: int = 3  # 单事件组最多加载几个技能
    skill_sop_max_chars: int = 3000  # 单技能 SOP 注入提示词前的截断长度
    active_scan_enabled: bool = False  # 主动探测默认关（仅授权网段 + 结果只作参考）
    active_scan_timeout: float = 1.0  # 单端口探测超时（秒）
    active_scan_max_ports: int = 100
    active_scan_ports: str = (
        "21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,"
        "5432,5900,6379,8080,8443,9200"
    )

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
