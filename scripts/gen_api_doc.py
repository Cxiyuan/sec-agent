#!/usr/bin/env python3
"""从 OpenAPI 生成 `docs/api/README.md`（给前端 team 用的 REST 接口文档）。

为什么要脚本：接口是活的，手工维护的文档必然过期（2026-10 就发生过"文档写了接口没实现/实现了没写"）。
这里直接读 `app.main:app` 的 OpenAPI，再叠加人工整理的**模块说明**与**页面级对接要点**，
`python3 scripts/gen_api_doc.py` 一条命令刷新。

用法（仓库根执行，需要本地 venv 装好依赖）：
    .venv/bin/python scripts/gen_api_doc.py
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

MODULES: list[tuple[str, str, str]] = [
    (
        "认证",
        "/api/auth",
        "登录、当前用户、改口令。**登录用表单编码**（`application/x-www-form-urlencoded`）",
    ),
    (
        "运营中心",
        "/api/stats",
        "总览仪表：24h 流量与协议 `/overview`、近端流量 `/traffic`（20 秒打点 / 30 分钟窗口 / 30 秒缓存）",
    ),
    ("运营中心", "/api/system", "服务器资源指标（CPU / 内存 / 磁盘 / 负载）"),
    ("运营中心", "/api/health", "组件连通性探测（呼吸灯）"),
    (
        "事件中心",
        "/api/detector",
        "检测器状态、**命中事件列表/详情/忽略/白名单**、聚合统计 `/hits/stats`、覆盖率、速率、历史",
    ),
    (
        "分析中心",
        "/api/logs",
        "日志检索：字段 `/fields`、下拉 `/facets`、检索 `/search`、单条 `/doc/{id}`",
    ),
    ("分析中心", "/api/traffic", "可视化流量三视角 `/ips`、某 IP 对端拓扑 `/peers`"),
    ("分析中心", "/api/topology", "拓扑发现与节点别名"),
    ("分析中心", "/api/chain", "攻击链还原"),
    ("资产中心", "/api/assets", "资产分组与台账 CRUD、被动发现 `/discover`、被动扫描 `/scan`"),
    ("资产中心", "/api/baseline", "被访问方资产基线、账号会话画像、数值基线、可调参数"),
    (
        "分析机制",
        "/api/analysis",
        "派工队列（客观线索）、智能体结论、覆盖率与对象清单（数据地图）、队列参数读写、人工派工",
    ),
    ("配置管理", "/api/rules", "检测规则 CRUD（每条带 `source_kind`/`source_label` 三类来源）"),
    (
        "配置管理",
        "/api/suppressions",
        (
            "精准抑制：智能体判过的误报四元组合（源IP + 目的IP:端口 + 协议 + payload），"
            "命中即不再派工、不再推送；含清单/统计/参数读写/影响面积试算/撤销恢复"
        ),
    ),
    (
        "配置管理",
        "/api/suricata",
        "签名引擎运行状态（规则集管理端点已移除，签名规则改由 /api/rules 只读列出）",
    ),
    ("配置管理", "/api/zeek", "采集：网卡、监控网段状态、中继清单与角色"),
    ("配置管理", "/api/exclusions", "排除过滤器"),
    ("配置管理", "/api/ingest", "入库过滤"),
    ("配置管理", "/api/logstash", "日志管道状态"),
    ("配置管理", "/api/es", "Elasticsearch 集群 / 索引 / 模板 / 保留期"),
    ("配置管理", "/api/config", "配置体检"),
    ("配置管理", "/api/agent-push", "摘要推送配置与积压"),
    ("配置管理", "/api/mcp", "MCP 令牌与工具清单"),
    ("运维", "/api/files", "采集产物文件下载与列表"),
]

HEADER = """# 深瞳 NDR · REST API 文档（供前端团队对接）

> 本文件由 `python3 scripts/gen_api_doc.py` **从 OpenAPI 自动生成**，与代码一致（当前共 **{TOTAL} 个接口**）。
> 后端只提供 REST 接口；页面结构与样式由前端团队负责。
> 智能体控制台（xdr-ui）自己的接口另见 [`agent-console.md`](./agent-console.md)（项目组织 / 分析过程 / 脚本 / 参数）。

## 一、通用约定

| 项 | 说明 |
| --- | --- |
| Base URL | `https://<服务器地址>`（强制 HTTPS，80 会 308 → 443） |
| 认证 | 除 `/api/auth/login` 外全部需要 `Authorization: Bearer <access_token>` |
| 登录 | `POST /api/auth/login`，**表单编码** `username=…&password=…`（发 JSON 会 422） |
| 错误 | 4xx/5xx + `{"detail": "中文原因"}`；列表接口失败会额外给 `error` 字段 |
| 分页 | `limit` / `offset`（服务端有上限，超了自动截断） |
| 时间 | 接口一律 **UTC ISO8601**；界面展示一律**北京时间** |
| 缓存 | 总览类接口有 30 秒~5 分钟缓存，响应里带 `cached` / `computed_at` |
| 限流 | 登录 60 秒内失败 5 次 → 429 |

### 1.1 事件来源三类（界面按这三类展示，**不要出现 zeek/suricata 字样**）

| `source_kind` | `source_label` | 含义 |
| --- | --- | --- |
| `feature_match` | 特征匹配 | 签名引擎按报文特征命中（Web 攻击 / 扫描器指纹 / C2…） |
| `behavior_analysis` | 行为分析 | 流量日志上的规模与时序判据（横向移动 / 慢速枚举 / TLS 异常…） |
| `baseline_deviation` | 基线偏离 | 与自身历史基线的偏离（新来源地址 / 认证失败激增 / 连接数 2σ…） |

命中事件（`hit_events`）关键字段：`id`（系统唯一事件 ID）、`rule`（**具体安全事件归类**，
如「Web 应用攻击」「会话可能被劫持」）、`rule_severity`、`source_kind`/`source_label`、
`src_ip`/`client`/`via`、`dst_pairs`（成对的 `IP:端口`）、`count`、`first_seen`/`last_seen`、
`evidence`（结构化证据，键名中文）、`ignored`/`whitelist_id`。

## 二、接口清单（按模块）
"""

FOOTER = """
## 三、前端对接要点

### 事件中心 / 运营中心

- 列表：`GET /api/detector/hits`，筛选参数 ——
  `minutes`（时间范围）、`source_kind`（三类来源）、`severity`、`rule`（事件归类子串）、
  `ip`（请求方/客户端/中继/目的）、`q`（跨字段关键字）、`include_ignored`、`sort=recent|oldest|count`、
  `limit`/`offset`。
- 首页 KPI / 趋势：`GET /api/detector/hits/stats?minutes=1440`
  → `total`、`ignored`、`by_source_kind[]`、`by_severity[]`、`top_rules[]`、`trend[]`
  （`trend` 的桶大小见 `bucket_seconds`：≤6h 按 10 分钟，否则按小时）。
- 详情 / 处置：`GET /hits/{id}`、`POST /hits/{id}/ignore`、`POST /hits/{id}/whitelist`。

### 其它页面

- **运营中心**：`/api/stats/overview?hours=24`、`/api/stats/traffic?minutes=30`、`/api/system/metrics`、`/api/health`
- **日志检索**：`/api/logs/fields` → `/api/logs/facets` → `/api/logs/search` → `/api/logs/doc/{id}`
- **可视化流量**：`/api/traffic/ips?view=outbound|lateral|egress` → `/api/traffic/peers?ip=…`
- **资产中心**：`/api/assets/discover|scan|groups|records`
- **行为画像**：`/api/baseline`、`/api/baseline/profiles`、`/api/baseline/numeric`、`/api/baseline/config`
- **配置管理**：`/api/rules`、`/api/suppressions/*`、`/api/zeek/*`、`/api/es/*`、`/api/config/audit`
  （`/api/suricata/*` 那组「签名规则集」管理端点已随功能删除 —— 签名规则现在直接出现在 `/api/rules` 里，只读）

### 分析机制（`/api/analysis`，派工队列）

- 队列浏览：`GET /api/analysis/tasks?state=&kind=&subject=&q=&limit=&offset=`（按客观强度降序）；
  详情 `GET /api/analysis/tasks/{id}` 含 `hint` 全量与该任务的历史结论
- 结论：`GET /api/analysis/results?task_id=&subject=&verdict=`
- 验收指标：`GET /api/analysis/stats`（各状态条数、按类型/结论分布、平均成本，以及
  `counters` 里的 `merged / superseded / dropped_overflow / stuck / expired / doorbell_*`）、
  `GET /api/analysis/coverage`（覆盖率与盲区）、`GET /api/analysis/inventory`（对象清单）
- 人工派工：`POST /api/analysis/tasks`，body `{subject, subject_kind, kind, note, strength}`；
  与自动线索同一套去重/容量规则，**不插队**
- 队列参数：`GET/PUT /api/analysis/config`、`POST /api/analysis/config/reset`
  （全部 `analysis.*` 参数都以 `GET /api/analysis/config` 返回的 `items` 为准，形状与 `/api/baseline/config` 一致，可复用同一套表单渲染）
- **界面不提供「领取任务」入口**：领取是智能体通道（MCP `claim_tasks`）；NDR 不设领取额度

### 智能体侧 MCP 新工具（不是 REST，但契约要一起看）

`claim_tasks` / `complete_task` / `defer_task` / `task_stats` / `asset_map` / `coverage_report`。

- NDR 不再推摘要，改为只发一次「门铃」（载荷只有队列状况）；智能体自行决定何时 `claim_tasks` 领取；
- 领到的任务只含客观事实（偏离倍数 / 是否首见 / 涉及对象数），**不含严重度与结论**；
- `complete_task` 可内联 `next_tasks` 追问（受深度上限）与 `suppression` 提交精准抑制：
  后者只在 `verdict=false_positive` 时允许，且 `evidence_refs` 必须是**本次会话真取回过**的引用。

### 精准抑制（`/api/suppressions`）

匹配口径是**结构化条件树**（与规则引擎同一套语法）：
`{"logic": "and", "rules": [{"field": "signature_id", "op": "eq", "value": "9110004"}, ...]}`。
可用字段见 `GET /api/suppressions/config` 的 `allowed_fields`（**不含正文类字段**——
正文能被投毒，不能当判据）。

- 清单：`GET /api/suppressions?q=&enabled_only=&include_expired=&limit=&offset=`（按命中数降序）
- 新建前试算：`POST /api/suppressions/preview`，body `{"match": {...}}`
  → `{trial:{events,srcs,segments}, mode, thresholds}`；
  `mode=record_only` 表示影响面过大，会降级成「事件仍生成、只不派工」
- 提交：`POST /api/suppressions`，body `{name, match, reason_code, evidence_refs, confidence, ttl_days}`
  （**至少 2 个独立维度**、证据 ≥3 条且来自 ≥2 种取数工具、置信度达标，否则 400 + `field_errors`）
- 修改：`PUT /api/suppressions/{id}`（改了 `match` 会重新试算并按结果调整 mode）
- 撤销/恢复：`POST /api/suppressions/{id}/revoke`（带 `reason`）、`POST /api/suppressions/{id}/restore`
- 总览：`GET /api/suppressions/stats`（活跃/过期/已撤销、累计抑制量、两种 mode 分布、全部门槛与允许字段）
- 参数：`GET/PUT /api/suppressions/config`、`POST /api/suppressions/config/reset`
  （`suppression.*` 参数，形状与 `/api/baseline/config` 一致，可复用同一套表单渲染）

**两种 mode 的语义**（界面必须显示清楚）：`suppress`＝该类现象不再生成事件、不再派工；
`record_only`＝事件仍生成、只是不派工不推送（影响面过大或自动生效关闭时的降级档）。

## 三·补、近期字段变化（端点没变，字段有增）

| 接口 | 新增字段 | 说明 |
| --- | --- | --- |
| `GET /api/baseline/observations`、`/observations/stats` | **新端点**（2026-10 行为基线事实） | 行为基线只产出**客观事实**（`egress_new` 外连新目标 / `egress_rare` / `geo_jump` 账号异地登录 / `login_bruteforce` / `path_probe` 大量 404 / `conn_shift` 连接数偏离）。**没有 severity、没有 verdict**，判断权在智能体。响应 `{available,total,items[{id,kind,kind_label,subject_kind,subject,facts,strength,count,first_seen,last_seen}]}` |
| `GET /api/baseline/egress` | **新端点** | 某台资产已学到的主动外连目的地（`src_ip` / `kind=dst_ip / domain / port` / `count` / 首末时间） |
| `GET/POST /api/baseline/egress-allow`、`DELETE /{id}`、`POST /{id}/restore` | **新端点** | 外连白名单：自学习条目（稳定 N 天 + N 次自动入表）可手工新增/编辑/删除；**删除留墓碑**（`tombstone=true`，以后不再自动学回来），`restore` 撤销墓碑 |
| `GET /api/baseline/config` | 新增参数键 | `egress.enabled` / `egress.rare_min` / `egress.learn_days` / `egress.learn_occurrences`；`profile.geo_enabled`（国家+省，基准=上次成功登录）/ `profile.brute_account_ips` / `profile.brute_account_fails` / `profile.path_probe_min_requests` / `profile.path_probe_404_ratio` / `profile.session_retention_days` |
| **行为基线口径变化**（2026-10） | 规则与派工 | 停用「协议异常」「会话跨IP复用」（实测 0 真阳/全假阳）；连接数偏离降级为事实（不再派工）；规则命中不再默认生成任务（`analysis.candidate_kinds` 默认 `novelty,coverage,observation`，`hit`/`shift` 需显式打开）；Zeek 新增 `ftp.log` 采集，FTP 登录映射为 `ftp_login`（reply_code 230→成功、5xx→失败）进账号画像 |
| MCP `/mcp` | 新工具 `list_observations`（analyst 档） | 查行为基线事实（按 kind/subject/时间窗），与界面同一份数据；智能体据此判断，不需要自己算"正常长什么样" |
| `GET /api/traffic/ips` | **口径修正**（2026-10）+ 响应新增 `truncated` | `view=outbound`（对外业务）改为**公网来源全量 → 按被访问资产聚合**：旧实现按流量取 TOP-N 主语 + composite 只读第一页，会把"被公网扫一枪的小流量资产"和"第 5000 条之后的资产"丢掉（实测 1 小时 13 台只显示 8 台、24 小时 40 台只剩 1 台）。横向/外连仍是抽样（内网主语太多），但会翻页并在 `truncated=true` 时明确提示"不是全部"。响应字段：`items[]`（ip/hostname/bytes_out/bytes_in/bytes_total/conns/peers/ports/peers_top/last_seen/regions）、`scanned_pairs/kept_pairs/filtered_out/truncated/monitored_nets` |
| `GET /api/system/license` | **新端点**（2026-10，项目组织身份） | 本机**授权ID**（8 位大写字母+数字，由硬件 UUID 派生）。响应：`{auth_id, source, source_label, stable, note}`；`source ∈ hardware / machine-id / hostname`，`stable=false` 表示只能靠主机名兜底（换名就变，界面要提示）。**是身份不是密钥**：可展示、可抄写，鉴权仍靠 MCP 令牌与推送令牌；换机后 ID 会变，需到智能体控制台改绑定。同一身份也出现在 MCP 响应的 `x-ndr-auth-id` 头与 `server_info` 工具里 |
| MCP `/mcp` | `x-ndr-auth-id` 响应头 + `server_info` 工具 + 门铃 `project` 字段 | 多项目 agent 靠这三处核对绑定：每个 MCP 响应都带本 NDR 授权ID；`server_info` 返回 `{auth_id, source, stable}`（analyst 档共 23 个工具）；门铃载荷 `{project, queue_len, top_kind, max_strength, watermark, ts}`，`project` 即本机授权ID（**不含任何事件数据**）。绑定不一致时 agent 停掉该项目并报警 |
| `GET /api/detector/hits`、`/hits/{id}` | `agent_status / agent_severity / agent_summary / agent_updated_at`（详情另有 `agent_detail / agent_thread_id`） | **智能体分析结论（判定权威来源）**：status 值域 true_positive/false_positive/benign/suspicious/inconclusive/pending/done；severity 为 info/low/medium/high/critical。无记录时字段为 null（表示智能体尚未返回结论，此时界面回退显示 NDR 初判）。结论由 `complete_task` 自动镜像到 `conclusion_records`（命中线索用 hint 里的 `事件ID` 关联），也兼容 MCP `record_conclusion` 显式写回；同一事件只留一份、重复覆盖 |
| `GET /api/detector/hits` | **新参数** `agent_status`、`agent_task_state` | `agent_status`：结论态（true_positive/false_positive/benign/suspicious/inconclusive/pending/done）+ 特殊值 `unanalyzed`（结论表无记录 = 智能体尚未返回）。`agent_task_state`：`none`（未派工）/ `queued`（排队中）/ `claimed`（分析中）/ `done` / `failed`（stuck/expired）。留空 = 不筛；未识别的值不筛（与 `source_kind` 同策略）。任务态靠 `analysis_tasks.hint→事件ID` 关联，一次 EXISTS 子查询 |
| `GET /api/detector/hits`、`/hits/{id}` | `agent_task_state` / `agent_task_id`（详情另有 `agent_task`） | 派工任务态与任务 ID；详情 `agent_task = {task_id, state, bucket, claimed_by, verdict, claimed_at}`。用于把「未派工」与「分析中」分开，积压可视化 |
| `GET /api/detector/hits/stats` | **两套口径并存**：`by_agent_status[]`、`agent_pending_total` | `by_agent_status[]` 按结论态分组（含 `unanalyzed` 桶，各桶之和 = `total`）；`agent_pending_total` = 智能体尚未返回结论的事件数。原有 `by_severity` / `by_source_kind` / `top_rules` / `trend` **保持不变**（检测器口径），字段名区分、不做覆盖 |
| `GET /api/detector/hits/clusters` | `agent_status / agent_status_label / agent_severity / agent_analyzed / agent_pending / agent_true_positive` | 簇内聚合：任一成员 `true_positive` 优先，其次 suspicious > inconclusive > false_positive/benign；`agent_severity` 取成员里最高档；`agent_analyzed/agent_pending` 是簇内已分析/未分析事件数。与列表视图同一套 `agent_*` 命名 |
| `GET /api/detector/hits`、`/hits/{id}` | `event_types` / `event_type_labels` | **事件类型（具体归类，中文）**：`网络扫描`／`Web 应用攻击`／`账号口令攻击`／`权限提升尝试`／`连接数异常偏离`／`大流量外传`…（2026-10 改口径：不再返回 `signature_hit`、`baseline_deviation` 这类内部码）。两个字段同源，前端直接显示即可 |
| `GET /api/detector/hits`、`/hits/{id}` | （已有）`source_kind` / `source_label` | 三类来源：特征匹配 / 行为分析 / 基线偏离 |
| `GET /api/baseline/profiles` | `posterior` | 似然比**后验概率**（0~1）。打分方式=llr 时列表按它排序；`risk_score` 仍返回（加和分，回滚口径） |
| `GET /api/baseline/config` | 9 个新参数键 | `baseline.scheme` / `alpha` / `learn_source` / `pool_k` / `deviation_cap_per_entity_hour` / `deviation_cap_per_hour`、`profile.scoring` / `prior_odds` / `posterior_threshold`（都可在界面改、30 秒生效） |
| `POST /api/baseline/alerts/{profile_id}/disposition` | **新端点** | 告警处置（`false_positive` / `confirm`）；`profile_id` 可填画像 UUID 或实体键。判成误报后该实体（或 `signal` 指定的那一路证据）在 `profile.false_positive_suppress_days` 天内不再参与打分 |
| `GET /api/baseline/alerts/dispositions` | **新端点** | 最近处置记录（核对降权是否生效） |
| `GET /api/detector/hits`、`/hits/{id}` | `cluster_id` | 告警簇 ID：同一事件归类 + 同一 /24（v6 /64）+ 同一小时归为一簇，界面可把同簇收成一行 |
| `GET /api/baseline/numeric` | **新参数** `scope` | `entity`（默认，只看 `源IP:维度`）／`group`（只看 `grp:{网段}:维度` 组先验）／`all`。组先验是等组池化的内部统计（稀疏实体向 /24 先验收缩），不是"某个 IP 的基线"，默认不返回，免得列表里混进 `grp:10.0.0.0/24` 这种像网段的键 |
| `GET /api/rules` | **规则数变化** | 三条「签名命中(高/中/低危)」分流包装规则已删除（见 `DELETED_RULES`）。规则条数三档口径：**源码定义 19 条** → 其中 **7 条已收敛到特征匹配**（登记删除、播种跳过） → **实际生效 12 条**行为分析规则。签名告警**不走规则表**，事件类型直接取签名归类（classtype） |
| `GET /api/rules` | `readonly` | 特征匹配（签名）规则是**只读**条目：随镜像发布，界面不给编辑/删除入口 |
| 新表 `analysis_suppressions` | 字段见下 | `match`（结构化条件树）+ `mode`（suppress 不生成事件 / record_only 只不派工）+ `trial`（申请时爆炸半径试算）+ `reason_code`/`evidence_refs`/`evidence_tools`/`confidence`/`source_task_id`（**审计四件套**）+ `hits`/`last_hit_at`（命中数）+ `expires_at`/`revoked_at` |
| `hit_events.evidence`（事件证据） | `p` / `alpha` / `var` / `pooled_with` | 泊松判据下的偏离证据：上尾概率、校正后阈值、方差、是否用了组池化；回滚到 zscore 时仍是 `z` / `std` / `std_raw` |

## 四、前端必读的坑
1. 登录是**表单编码**，不是 JSON。
2. 接口给 UTC，**界面一律北京时间**。
3. 空态要区分「真的没有」与「读取失败」（失败会有 `error` 或非 2xx）。
4. 流量字段：`bytes_*` 是字节；`*_per_sec` 已是每秒（不要再除 20）。
5. 命中事件默认不含已忽略；按 `source_kind` 分三类展示。
6. 写操作错误码：400 参数错 / 404 不存在 / 409 重名。
"""


def main() -> int:
    # 延迟导入：先把后端加入 sys.path，再导入应用（模块顶层做这件事会踩 I001/E402）
    sys.path.insert(0, str(ROOT / "ndr" / "backend"))
    from app.main import app  # 延迟到 sys.path 就绪之后

    spec = app.openapi()
    rows: list[tuple[str, str, str, str, str]] = []
    for path, item in spec.get("paths", {}).items():
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            query = [p["name"] for p in op.get("parameters", []) if p.get("in") == "query"]
            pathp = [p["name"] for p in op.get("parameters", []) if p.get("in") == "path"]
            rows.append(
                (
                    method.upper(),
                    path,
                    ",".join(query),
                    ",".join(pathp),
                    "body" if op.get("requestBody") else "",
                )
            )
    rows.sort(key=lambda r: r[1])

    out = [HEADER.replace("{TOTAL}", str(len(rows)))]
    used: set[str] = set()
    for label, prefix, desc in MODULES:
        items = [r for r in rows if r[1].startswith(prefix)]
        if not items:
            continue
        used.add(prefix)
        out.append(
            f"\n### {label} — `{prefix}`\n\n{desc}\n\n| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |\n| --- | --- | --- | --- | --- |\n"
        )
        for method, path, query, pathp, body in items:
            out.append(
                f"| `{method}` | `{path}` | {('`' + query + '`') if query else '—'} | "
                f"{('`' + pathp + '`') if pathp else '—'} | {body or '—'} |\n"
            )
    rest = [r for r in rows if not any(r[1].startswith(p) for (p,) in [(u,) for u in used])]
    if rest:
        out.append("\n### 其它\n\n| 方法 | 路径 | 查询参数 |\n| --- | --- | --- |\n")
        for method, path, query, _pathp, _body in rest:
            out.append(f"| `{method}` | `{path}` | {query or '—'} |\n")
    out.append(FOOTER)

    target = ROOT / "docs" / "api" / "README.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(out), encoding="utf-8")
    print(f"✔ 已生成 {target}（{len(rows)} 个接口，{len(''.join(out).splitlines())} 行）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
