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
    # 已处理登记保留秒数。**不要为了“覆盖 24h 回补”把它调成一天以上**：登记量随流量线性增长，
    # 线上实测 25h 窗口涨到 1677 万成员 / 1.4GB，直接把 Redis 撑爆（noeviction → 全线写失败）。
    # 现在按 2h 窗口登记：常规运行完全够用；长时间停机后的回补会重复分析，
    # 由“投递前去重 + 摘要超龄”两道闸门兜住。
    detector_handled_ttl: int = 7200
    detector_handled_bucket_seconds: int = 600  # 分桶粒度：桶自带 TTL，到期整桶消失（内存有界）
    detector_handled_max_members: int = 50000  # 单桶成员硬上限（超限丢弃登记并告警，不静默）
    redis_memory_warn_perc: int = 85  # Redis 内存占用告警线（占 maxmemory 的百分比）
    analysis_stuck_minutes: int = 30  # 事件组停在 analyzing 超过该分钟数视为“分析未收敛”
    detector_agg_seconds: int = 60  # 短窗聚合时长（源IP+规则）
    detector_agg_max_keys: int = 5000  # 并发聚合态上限（护栏）
    detector_batch_seconds: int = 20  # 攒批：最长等待
    detector_batch_max: int = 5  # 攒批：凑够多少条就触发
    detector_max_per_batch: int = 50  # 单次投递摘要数上限（护栏）
    detector_max_digests_per_minute: int = (
        20  # 投递速率上限（护栏）= 边缘模型实测容量（8~16 并发 23~26 条/分钟）留余量
    )
    detector_queue_max: int = 20000  # 摘要队列上限（超过则裁掉最老的，保证有界）
    # raw 队列上限。采集速率实测可达 ~3800 条/秒，检测器永远追不上；不封顶就会把 Redis
    # 撑满 → noeviction 拒写 → 检测器/ Celery 全线卡死（真实事故）。
    # raw 队列只是“快车道”，ES 才是事实源（水位兜底会补齐），所以丢掉最老的可以接受；
    # 但丢弃必须计数可查（dropped.raw_trimmed）。
    detector_raw_queue_max: int = 20000
    detector_drop_key: str = "shentong:detector:dropped"  # 丢弃计数（跨重启可查）
    detector_dedup_key: str = "shentong:detector:dedup"  # 去重拦下计数（跨重启可查）
    detector_task_failed_key: str = "shentong:detector:task_failed"  # 分析任务失败计数
    detector_digest_max_age_seconds: int = 1800  # 摘要最长安存秒数（超龄丢弃，保证分析的是新事件）
    detector_poll_timeout: int = 5  # 队列阻塞读取秒数
    detector_scope_refresh_seconds: int = 60  # 分析网段刷新间隔
    detector_stats_log_seconds: int = 300  # 运行统计日志间隔
    # 选主（Redis 租约）：只有持锁实例才消费，多实例时其余待命做热备
    detector_leader_key: str = "shentong:detector:leader"
    detector_leader_ttl_seconds: int = 30  # 租约 TTL，须 ≥ 续约间隔×2，否则会在两次续约间被抢主
    detector_leader_renew_seconds: int = 10  # 续约间隔（也决定待命实例的轮询节奏）
    # 投递前去重闸门：按「规则|源IP|时间桶」指纹查库，已分析过的不再重复投（省完整 LLM 链）
    dedup_enabled: bool = True
    dedup_inflight_ttl_seconds: int = (
        2400  # 在途标记有效期：须 > 任务硬超时（1800s），否则任务还在跑就被当失败重投
    )
    analyzed_retention_days: int = 7  # 已完结指纹保留天数（供查询排查）
    # 用户自定义排除过滤（命中则仍记事件，但跳过全部模型调用与报告）
    exclusion_cache_seconds: int = 30  # 过滤器配置缓存秒数（跨进程最迟这么久生效）
    # 频率规则滑动窗口（实时链路用 Redis 滑窗替代“窗口内计数”）
    freq_window_seconds: int = 300
    freq_cooldown_seconds: int = 300  # 同一分组触发后的冷却，防重复告警
    # 兜底任务水位（存 PostgreSQL，跨重启可靠）
    fallback_watermark_key: str = "fallback.last_run"
    fallback_max_backfill_hours: int = 24  # 单次最大回补时长（超限截断并告警）
    fallback_lag_seconds: int = (
        60  # 兜底窗口右边界后退量：留时间给检测器先处理，避开重叠竞态（0=关）
    )

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
    # 边缘模型调用参数（2026-09-25 实测：并发 8 → 23 次/分，串行仅 ~5；故批内并发是最大红利）
    edge_review_concurrency: int = 8  # 批内并发度（1=串行）
    edge_max_tokens: int = 512  # 非思考输出上限（实测纯 JSON 约 60~120 token，512 足够且不截断）
    edge_max_tokens_thinking: int = 4096  # 思考模式输出上限（实测 ≤579，余量充足）

    # 云端模型（MiniMax 国内版；模型名固化见 registry）
    # api_key 由后台界面录入、存数据库（不落环境变量），见 app/cloud_config.py
    cloud_model_base_url: str = "https://api.minimaxi.com/v1"
    cloud_model_timeout: int = 600
    # 云端并发与重试（节点里"逐个事件组"的循环改成并发后，必须自己控峰值，
    # 否则很容易吃 429；max_retries 设 3 次、指数退避）
    cloud_max_concurrency: int = 4  # 同时最多几个云端请求（后台可改，即时生效）
    cloud_max_retries: int = 3  # 仅对 429/5xx/超时退避重试；401 等配置错误不重试
    cloud_retry_base_seconds: float = 2.0  # 退避基数（2s → 4s → 8s）

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
    # 事件组时间桶（分钟）：同一对象在桶内复用同一个组，避免持续攻击每分钟新建组/报告
    group_bucket_minutes: int = 30
    # 同一组在多少分钟内只留一份报告（0 = 不抑制，每轮都新建）
    report_min_interval_minutes: int = 30
    hitl_enabled: bool = False
    hitl_min_severity: str = "high"  # 达到该级别才触发人工确认

    # 误报治理（策略级）：判据集中在 app/agents/triage_policy.py，全部环境无关、可后台调
    # ① 分级放行：内网常规流量（内→内 + 低危逐条规则 + 单目标 + 无成功连接）只落库不跑模型。
    #    不做"内→内一律不分析"：横向移动就藏在内→内，一刀切会致盲。
    policy_internal_routine_skip: bool = True
    policy_internal_routine_min_severity: str = "medium"  # 规则严重度 ≥ 此值的内→内照旧全量分析
    policy_internal_routine_max_dst: int = 1  # 目标数 ≤ 此值才算"单目标"（扇出即扫描特征）
    policy_internal_routine_require_failed: bool = True  # 有成功连接则不跳
    # ② 定级约束（每条降级都写原因，不静默）
    severity_cap_internal: str = "medium"  # 内→内 封顶
    severity_require_evidence_above: str = "high"  # 无证据链不得 ≥ 此级别
    severity_critical_requires_external: bool = True  # critical 仅限 外→内
    # ③ 升级闸门（进深度分析）：除分数外还要满足规则严重度或方向
    escalate_require_rule_severity: str = "medium"
    escalate_allow_external: bool = True  # 外→内 不受规则严重度限制
    # ④ 兜底预筛的正常特征扣分（与加分叠加后与门槛比较，下限钳到 0）
    prefilter_penalty_established: float = 0.3  # 双向有字节的已建立连接
    prefilter_penalty_known_asset: float = 0.2  # 目标在已录资产内
    prefilter_penalty_common_port: float = 0.2  # 常用端口

    # 自主取证调查（深度分析路径上的「有界自主」：按需查询 → 还原完整攻击路径）
    # 设计取舍：预算全部写死，超限即停并产出部分结论；失败回落固定深度分析
    investigation_enabled: bool = True
    investigation_min_severity: str = "high"  # 只对 ≥ 该级别的案件开调查
    investigation_max_steps: int = 10  # 循环步数上限
    investigation_max_queries: int = 12  # 查询类工具调用上限
    # 为什么抬到 10：实测上限 6 时调查**全部**撞限就停（模型把预算花在查询上，
    # 没机会输出结论）→ path/gaps/IOC 全空、事件组上的取证结果也是空的。
    investigation_max_llm_calls: int = 10  # 模型调用次数上限
    investigation_timeout_seconds: int = 240  # 单轮墙钟上限（秒）
    investigation_max_docs_per_query: int = 2000  # 单次查询文档上限（硬顶 5000）
    investigation_raw_evidence_max: int = 20  # 单轮原始证据条数上限
    investigation_observation_chars: int = 1500  # 单步观察压缩上限（防 token 爆炸）
    investigation_keep_observations: int = 3  # 保留完整观察的最近步数
    investigation_max_prompt_chars: int = 24000  # 单轮提示词上限
    investigation_tool_timeout_seconds: float = 20.0  # 单工具超时
    investigation_cooldown_minutes: int = 60  # 增量重跑冷却（冷却内只累积新证据）
    investigation_max_rounds_per_day: int = 6  # 单案每日调查轮次上限
    investigation_link_window_hours: int = 24  # 案件归集「相似」判定的时间窗
    investigation_link_max_calls: int = 3  # 每批模型裁定次数上限
    investigation_max_lookback_days: int = 30  # 调查自身取证跨度上限（默认=ES 保留期）
    investigation_keep_fixed_deep: bool = True  # 保留固定深度分析作为即时结果与兜底

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

    # 采集侧 Logstash 管道（由后台界面维护：写共享卷 → Logstash 自动重载）
    logstash_pipeline_conf: str = (
        "/logstash/logstash.conf"  # 必须叫 logstash.conf：它正好覆盖镜像自带的示例管道
    )
    # 备份**不能**放在管道目录里：Logstash 会把目录里所有文件当配置读（不看扩展名），
    # 备份一放进去就会变成第二个管道（两个 beats 抢 5044）。所以单独一个卷。
    logstash_pipeline_backup: str = "/logstash-backup/logstash.conf.bak"
    logstash_api_url: str = "http://logstash:9600"
    logstash_beats_port: int = 5044
    logstash_seed_on_startup: bool = True
    logstash_pipeline_max_chars: int = 50000

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
