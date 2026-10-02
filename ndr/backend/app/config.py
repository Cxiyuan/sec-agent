"""应用配置（NDR 侧）：全部走环境变量，pydantic-settings 读取。

契约字段（与 agent 侧保持一致）单独成块；NDR 独有字段在后。
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ST_", extra="ignore")

    # ---------- 契约（两侧一致，值必须相同） ----------
    # 通用
    app_name: str = "深瞳 · 安全分析智能体"
    debug: bool = False  # True 时日志为 DEBUG 级别（见 workers/log.py）
    timezone: str = "Asia/Shanghai"

    # Elasticsearch
    # 归一化前置之后只有**一族**索引：Zeek 与 Wazuh 落同一套结构、按日期滚动。
    es_events_index: str = "shentong-events-*"
    es_url: str = "http://localhost:9200"
    es_user: str = ""
    es_password: str = ""
    es_verify_certs: bool = False
    es_retention_days: int = 30  # ES 日志保留天数（后台可改，下限 = 回溯封顶 7 天）
    lookback_max_days: int = 7  # 回溯最大天数（契约：ES 保留期下限 + agent 回溯时长封顶）
    es_ilm_policy: str = "shentong-retention"
    # 归一化文档里的源/目的地址字段（可用逗号分隔多个；以 mapping 自检结果为准）
    es_events_src_fields: str = "src_ip"
    es_events_dst_fields: str = "dst_ip"

    # PostgreSQL
    pg_url: str = "postgresql+psycopg://shentong:shentong@localhost:5432/shentong"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # 队列 / 计数键名（契约：ndr 生产摘要、agent 消费；agent 回传 done、ndr 消费）
    detector_raw_queue: str = "shentong:events:raw"
    detector_digest_queue: str = "shentong:events:digest"
    detector_processing_queue: str = "shentong:events:processing"
    detector_delivery_queue: str = "shentong:events:dispatch"  # 旧投递队列（第 5 期回退通道；新 agent 不消费）
    detector_handled_key: str = "shentong:handled:docs"
    detector_drop_key: str = "shentong:detector:dropped"  # 丢弃计数（跨重启可查）
    detector_dedup_key: str = "shentong:detector:dedup"  # 去重拦下计数（第 5 期起只读历史值）
    detector_task_failed_key: str = "shentong:detector:task_failed"  # 分析任务失败计数

    # 第 5 期：检测器命中后经 HTTP 推给智能体（不再走 Redis 队列交接）
    # 地址形如 http://agent:8000/api/push/digests；留空 = 不推送，仍走旧队列（兼容升级）
    agent_push_url: str = ""
    agent_push_token: str = ""  # 必须与智能体侧 ST_PUSH_TOKEN 一致
    agent_push_enabled: bool = True
    agent_push_timeout_seconds: float = 10.0
    agent_push_max_per_push: int = 200  # 单次 POST 最多带多少条摘要（智能体侧上限 push_max_items）
    detector_push_retry_queue: str = "shentong:events:pushretry"  # 推送失败落这里，后台重发
    detector_push_processing_queue: str = "shentong:events:pushretry:processing"
    detector_push_retry_max_per_round: int = 50
    detector_push_stats_key: str = "shentong:push:stats"  # 推送状态计数（界面读）

    # 事件组时间桶（分钟）：ndr 摘要指纹与 agent 事件组共用同一桶宽
    group_bucket_minutes: int = 30

    # 误报治理（策略级）：判据集中在 triage_policy，全部环境无关、可后台调；两侧一致
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
    # 默认与 Zeek 侧一致（site/shentong-limits.zeek 的 16384/65536）；Web 后台
    # 「采集 → 网段与上限」改这两个值时同时写 Zeek 侧 interface.conf 与 system_config 的
    # http.body_max_chars / http.resp_body_max_chars，运行时经 runtime_config 生效（见 normalizer）
    http_body_max_chars: int = 16384
    # 响应体（Zeek 侧由 site/shentong-httpbody.zeek 采到 HTTP::Info$resp_body）
    http_resp_body_fields: str = "resp_body,response_body,http.response.body,http.response_body"
    http_resp_body_max_chars: int = 65536
    http_cookie_max_chars: int = 200
    # Zeek 日志流分类（契约，两侧一致）：event=入库且进检测/画像；ops=只入库（当证据）。
    # 名单外的新流保留原名并标 log_type_known=False（先观察，不静默丢）。判定见 ingestion/log_types.py
    zeek_event_log_types: str = "conn,dns,http,ssl,files,dhcp,x509,weird,notice,smtp,ssh"
    zeek_ops_log_types: str = "ntp,packet_filter,reporter,stats,ja4ssh,ja4d"
    web_login_path_regex: str = (
        "(?i)/(login|signin|sign-in|auth|authorize|session|sso|oauth|token|passwd|password)($|[/?])"
    )
    max_logs_per_window: int = 20000  # 单窗口拉取上限（护栏）
    exclusion_cache_seconds: int = 30  # 过滤器配置缓存秒数（跨进程最迟这么久生效）
    ingest_filter_cache_seconds: int = 30  # 降噪过滤（入库前）配置缓存秒数
    ingest_filter_dry_run_hours: int = 24  # 试运行默认回看时长（小时）
    ingest_filter_dry_run_max: int = 500  # 试运行最多扫多少条历史事件

    # 认证
    jwt_secret: str = "change-me-in-production"
    jwt_expire_minutes: int = 720
    default_admin_username: str = "admin"
    default_admin_password: str = "admin123"

    # 局域网部署（CORS 允许的前端源，逗号分隔）
    cors_origins: str = "http://localhost:3000,http://localhost:8080"

    # ---------- NDR 独有 ----------
    # Zeek 采集（镜像侧轮转 24h / 本地保留 3 天为硬编码）
    zeek_conf_dir: str = "/config"
    zeek_iface_conf: str = "/config/interface.conf"
    zeek_interfaces_json: str = "/config/interfaces.json"
    zeek_interface: str = "eth0"
    # 监控网段清单（一行一条 CIDR/IP，也可逗号分隔）：由它生成 bpf_filter 与 local_nets
    zeek_monitored_nets: str = ""
    # 追加到 BPF 末尾的附加条件（可选，如 not port 22）
    zeek_bpf_extra: str = ""

    # Wazuh 采集（第 6 期）：manager 容器 + Filebeat 把 alerts.json / archives.json 写进采集队列
    # archives.json 是 logall_json 的全量原始日志，量级远大于告警：默认只入库、不喂检测器
    # （检测器跑的是告警规则，把原始日志也灌进去既无收益又会把队列与模型容量吃掉）。
    wazuh_archive_to_detector: bool = False

    # Wazuh API(55000) 管理面：凭据界面可配（存 SystemConfig），环境变量只作默认值
    wazuh_api_url: str = ""  # 形如 https://wazuh-manager:55000；空 = 面板显示未配置
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_api_verify_tls: bool = False  # Wazuh 自签证书是常态，默认不校验
    wazuh_api_timeout_seconds: float = 10.0

    # 数据接入：检测器（旁路队列实时检测）
    detector_enabled: bool = True
    # 已处理登记保留秒数（2h 窗口，防 Redis 撑爆）
    detector_handled_ttl: int = 7200
    detector_handled_bucket_seconds: int = 600
    detector_handled_max_members: int = 50000
    redis_memory_warn_perc: int = 85
    detector_agg_seconds: int = 300
    detector_agg_max_keys: int = 5000
    detector_batch_seconds: int = 20
    detector_batch_max: int = 5
    detector_max_per_batch: int = 50
    detector_max_digests_per_minute: int = 24
    detector_queue_max: int = 20000
    detector_raw_queue_max: int = 30000
    detector_coverage_warn_ratio: float = 0.6
    detector_consume_batch: int = 1000
    # ---- 摘要压缩 ----
    digest_suppress_hours: int = 0
    digest_merge_family: bool = False
    detector_digest_max_age_seconds: int = 1800
    detector_poll_timeout: int = 5
    detector_scope_refresh_seconds: int = 60
    detector_stats_log_seconds: int = 300
    # 选主（Redis 租约）
    detector_leader_key: str = "shentong:detector:leader"
    detector_leader_ttl_seconds: int = 30
    detector_leader_renew_seconds: int = 10
    # 频率规则滑动窗口
    freq_window_seconds: int = 300
    freq_cooldown_seconds: int = 300

    # 基线（数值 2σ + 账号/会话画像）：第 8 期从智能体侧迁来 —— 基线是纯统计、不需要模型，
    # 而检测器本来就逐条看到归一化事件，所以算在数据产生侧，算完随摘要打标给智能体定性。
    baseline_enabled: bool = True
    baseline_observe_days: int = 7  # 观测期：不足这么多天只学习、不判异常
    baseline_zscore: float = 2.0  # 数值基线判偏离的标准差倍数
    baseline_flush_seconds: int = 60  # 画像观测落库 + 判异常的节奏（秒）
    baseline_cleanup_seconds: int = 3600  # 过期画像清理的检查节奏（秒）
    baseline_max_observations: int = 50000  # 单窗口最多攒多少条画像观测，超了提前落库
    baseline_cache_max: int = 20000  # 进程内数值基线缓存条目上限（超出丢最旧的）
    baseline_stats_key: str = "shentong:baseline:stats"  # 检测器侧基线计数（界面看活性）
    profile_enabled: bool = True
    profile_min_obs: int = 5  # 观测次数不足时只学习、不判异常（冷启动）
    profile_risk_threshold: float = 0.6  # 画像异常风险分阈值（达到才报）
    profile_retention_days: int = 180  # 画像保留期（到期清理）
    session_cookie_names: str = "JSESSIONID,PHPSESSID,SESSION,ASP.NET_SessionId,connect.sid,token,sid"

    # 采集侧归一化服务（Filebeat → Redis → 归一化 → Logstash → ES）
    collector_collect_queue: str = "shentong:events:collect"  # Filebeat 写入的原始日志
    collector_processing_queue: str = "shentong:events:collect:processing"
    collector_queue_max: int = 30000  # 队列封顶（超出裁掉最旧的，防 Redis 打满）
    collector_consume_batch: int = 500
    collector_poll_timeout: int = 5
    collector_post_timeout_seconds: int = 20
    collector_post_retries: int = 3
    collector_retry_backoff_seconds: float = 1.0
    collector_stats_log_seconds: int = 300

    # MCP 服务（智能体在分析事件时用它查询、调查、写回结论；独立容器）
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8090
    mcp_path: str = "/mcp"
    # 智能体连的地址（服务名，不是 0.0.0.0）：界面展示 + 探活都用它
    mcp_public_url: str = "http://ndr-mcp:8090"
    mcp_token_prefix: str = "stmcp_"  # 便于人一眼认出这是深瞳的 MCP 令牌
    mcp_call_key: str = "shentong:mcp:calls"  # 最近调用记录（Redis 列表，供界面看）
    mcp_call_keep: int = 200  # 只留最近这么多条，防止无限增长
    mcp_call_detail_chars: int = 300  # 调用参数摘录长度（只留开头，够定位问题）
    mcp_conclusion_retention_days: int = 7  # 结论镜像保留期（与判重窗口对齐）
    mcp_max_rows: int = 500  # 单次查询返回条数上限（防止模型一口气拉空 ES）

    # 采集侧 Logstash 管道（由后台界面维护：写共享卷 → Logstash 自动重载）
    logstash_pipeline_conf: str = "/logstash/logstash.conf"
    logstash_pipeline_backup: str = "/logstash-backup/logstash.conf.bak"
    logstash_api_url: str = "http://logstash:9600"
    # 归一化服务 POST 归一化文档进来的 http 输入端口（不再是 beats）
    logstash_http_port: int = 8080
    logstash_seed_on_startup: bool = True
    logstash_pipeline_max_chars: int = 50000


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
