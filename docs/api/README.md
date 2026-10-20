# 深瞳 NDR · REST API 文档（供前端团队对接）

> 本文件由 `python3 scripts/gen_api_doc.py` **从 OpenAPI 自动生成**，与代码一致（当前共 **107 个接口**）。
> 后端只提供 REST 接口；页面结构与样式由前端团队负责。

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

### 认证 — `/api/auth`

登录、当前用户、改口令。**登录用表单编码**（`application/x-www-form-urlencoded`）

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `POST` | `/api/auth/change-password` | — | — | body |
| `POST` | `/api/auth/login` | — | — | body |
| `POST` | `/api/auth/logout` | — | — | — |
| `GET` | `/api/auth/me` | — | — | — |

### 运营中心 — `/api/stats`

总览仪表：24h 流量与协议 `/overview`、近端流量 `/traffic`（20 秒打点 / 30 分钟窗口 / 30 秒缓存）

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/stats/overview` | `hours` | — | — |
| `GET` | `/api/stats/traffic` | `minutes` | — | — |

### 运营中心 — `/api/system`

服务器资源指标（CPU / 内存 / 磁盘 / 负载）

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/system/metrics` | — | — | — |

### 运营中心 — `/api/health`

组件连通性探测（呼吸灯）

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/health` | — | — | — |
| `GET` | `/api/health/components` | — | — | — |

### 事件中心 — `/api/detector`

检测器状态、**命中事件列表/详情/忽略/白名单**、聚合统计 `/hits/stats`、覆盖率、速率、历史

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/detector/coverage` | `minutes` | — | — |
| `GET` | `/api/detector/history` | `limit` | — | — |
| `GET` | `/api/detector/hits` | `limit,offset,include_ignored,source_kind,minutes,severity,rule,ip,q,cluster_id,sort` | — | — |
| `GET` | `/api/detector/hits/clusters` | `minutes,limit,include_ignored,source_kind` | — | — |
| `GET` | `/api/detector/hits/stats` | `minutes` | — | — |
| `GET` | `/api/detector/hits/{hit_id}` | — | `hit_id` | — |
| `POST` | `/api/detector/hits/{hit_id}/ignore` | — | `hit_id` | body |
| `POST` | `/api/detector/hits/{hit_id}/whitelist` | — | `hit_id` | body |
| `GET` | `/api/detector/rate` | `minutes` | — | — |
| `GET` | `/api/detector/stats` | — | — | — |

### 分析中心 — `/api/logs`

日志检索：字段 `/fields`、下拉 `/facets`、检索 `/search`、单条 `/doc/{id}`

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/logs/doc/{doc_id}` | `index` | `doc_id` | — |
| `GET` | `/api/logs/facets` | `minutes` | — | — |
| `GET` | `/api/logs/fields` | — | — | — |
| `GET` | `/api/logs/search` | `q,log_type,src_ip,dst_ip,account,hostname,event_type,method,uri_path,src_port,dst_port,status_code,minutes,size,offset,order` | — | — |
| `GET` | `/api/logstash` | — | — | — |
| `PUT` | `/api/logstash/params` | — | — | body |
| `PUT` | `/api/logstash/pipeline` | — | — | body |
| `POST` | `/api/logstash/preview` | — | — | body |
| `POST` | `/api/logstash/rollback` | — | — | — |

### 分析中心 — `/api/traffic`

可视化流量三视角 `/ips`、某 IP 对端拓扑 `/peers`

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/traffic/ips` | `view,minutes,limit` | — | — |
| `GET` | `/api/traffic/peers` | `ip,view,minutes,limit` | — | — |

### 分析中心 — `/api/topology`

拓扑发现与节点别名

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/topology` | `mode,minutes,hours,from_ts,to_ts` | — | — |
| `GET` | `/api/topology/aliases` | — | — | — |
| `PUT` | `/api/topology/aliases` | — | — | body |

### 分析中心 — `/api/chain`

攻击链还原

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/chains` | `minutes,from_ts,to_ts,ip,host,suspicious_only` | — | — |
| `GET` | `/api/chains/detail` | `client,origin,minutes,from_ts,to_ts` | — | — |
| `POST` | `/api/chains/dispatch` | — | — | body |

### 资产中心 — `/api/assets`

资产分组与台账 CRUD、被动发现 `/discover`、被动扫描 `/scan`

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/assets/discover` | `minutes,limit` | — | — |
| `GET` | `/api/assets/groups` | — | — | — |
| `POST` | `/api/assets/groups` | — | — | body |
| `PATCH` | `/api/assets/groups/{group_id}` | — | `group_id` | body |
| `DELETE` | `/api/assets/groups/{group_id}` | — | `group_id` | — |
| `GET` | `/api/assets/records` | `q,group_id,criticality,limit,offset` | — | — |
| `POST` | `/api/assets/records` | — | — | body |
| `PATCH` | `/api/assets/records/{record_id}` | — | `record_id` | body |
| `DELETE` | `/api/assets/records/{record_id}` | — | `record_id` | — |
| `GET` | `/api/assets/scan` | `minutes,limit` | — | — |

### 资产中心 — `/api/baseline`

被访问方资产基线、账号会话画像、数值基线、可调参数

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/baseline` | `limit` | — | — |
| `GET` | `/api/baseline/alerts/dispositions` | `limit,kind` | — | — |
| `POST` | `/api/baseline/alerts/{profile_id}/disposition` | — | `profile_id` | body |
| `GET` | `/api/baseline/assets` | `q,sort,limit,offset,scope` | — | — |
| `GET` | `/api/baseline/assets/stats` | `asset` | — | — |
| `GET` | `/api/baseline/config` | — | — | — |
| `PUT` | `/api/baseline/config` | — | — | body |
| `POST` | `/api/baseline/config/reset` | — | — | body |
| `GET` | `/api/baseline/numeric` | `q,feature,sort,limit,offset,group,scope` | — | — |
| `GET` | `/api/baseline/profiles` | `kind,q,min_risk,limit,offset` | — | — |
| `GET` | `/api/baseline/stats` | `ip,key,limit` | — | — |

### 配置管理 — `/api/rules`

检测规则 CRUD（每条带 `source_kind`/`source_label` 三类来源）

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/rules` | — | — | — |
| `POST` | `/api/rules` | — | — | body |
| `PUT` | `/api/rules/{rule_id}` | — | `rule_id` | body |
| `DELETE` | `/api/rules/{rule_id}` | — | `rule_id` | — |

### 配置管理 — `/api/suricata`

签名引擎：内置规则集查看/校验/生效/重置/在线源

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/suricata/rules` | — | — | — |
| `POST` | `/api/suricata/rules/apply` | — | — | — |
| `POST` | `/api/suricata/rules/check` | — | — | — |
| `POST` | `/api/suricata/rules/reset` | — | — | — |
| `PUT` | `/api/suricata/rules/source` | — | — | body |

### 配置管理 — `/api/zeek`

采集：网卡、监控网段状态、中继清单与角色

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `PUT` | `/api/zeek/interface` | — | — | body |
| `GET` | `/api/zeek/networks/status` | — | — | — |
| `GET` | `/api/zeek/relay-nodes` | — | — | — |
| `PUT` | `/api/zeek/relay-nodes` | — | — | body |
| `PUT` | `/api/zeek/relay-nodes/roles` | — | — | body |
| `PUT` | `/api/zeek/relay-nodes/sides` | — | — | body |
| `GET` | `/api/zeek/status` | — | — | — |

### 配置管理 — `/api/exclusions`

排除过滤器

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/exclusions` | — | — | — |
| `POST` | `/api/exclusions` | — | — | body |
| `GET` | `/api/exclusions/fields` | — | — | — |
| `GET` | `/api/exclusions/stats` | — | — | — |
| `PUT` | `/api/exclusions/{filter_id}` | — | `filter_id` | body |
| `DELETE` | `/api/exclusions/{filter_id}` | — | `filter_id` | — |

### 配置管理 — `/api/ingest`

入库过滤

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/ingest-filters` | — | — | — |
| `POST` | `/api/ingest-filters` | — | — | body |
| `POST` | `/api/ingest-filters/dry-run` | — | — | body |
| `GET` | `/api/ingest-filters/fields` | — | — | — |
| `GET` | `/api/ingest-filters/stats` | — | — | — |
| `PUT` | `/api/ingest-filters/{filter_id}` | — | `filter_id` | body |
| `DELETE` | `/api/ingest-filters/{filter_id}` | — | `filter_id` | — |

### 配置管理 — `/api/logstash`

日志管道状态

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/logstash` | — | — | — |
| `PUT` | `/api/logstash/params` | — | — | body |
| `PUT` | `/api/logstash/pipeline` | — | — | body |
| `POST` | `/api/logstash/preview` | — | — | body |
| `POST` | `/api/logstash/rollback` | — | — | — |

### 配置管理 — `/api/es`

Elasticsearch 集群 / 索引 / 模板 / 保留期

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `POST` | `/api/es/apply-retention` | — | — | body |
| `GET` | `/api/es/config` | — | — | — |
| `PUT` | `/api/es/config` | — | — | body |
| `GET` | `/api/es/status` | — | — | — |

### 配置管理 — `/api/config`

配置体检

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/config/audit` | — | — | — |

### 配置管理 — `/api/agent-push`

摘要推送配置与积压

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/agent-push` | — | — | — |
| `PUT` | `/api/agent-push` | — | — | body |
| `POST` | `/api/agent-push/retry` | — | — | — |
| `POST` | `/api/agent-push/test` | — | — | body |

### 配置管理 — `/api/mcp`

MCP 令牌与工具清单

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/mcp/calls` | `limit` | — | — |
| `DELETE` | `/api/mcp/calls` | — | — | — |
| `GET` | `/api/mcp/conclusions` | `limit` | — | — |
| `GET` | `/api/mcp/status` | — | — | — |
| `GET` | `/api/mcp/tokens` | — | — | — |
| `POST` | `/api/mcp/tokens` | — | — | body |
| `DELETE` | `/api/mcp/tokens/{token_id}` | — | `token_id` | — |
| `POST` | `/api/mcp/tokens/{token_id}/expiry` | — | `token_id` | body |
| `POST` | `/api/mcp/tokens/{token_id}/rotate` | — | `token_id` | — |
| `POST` | `/api/mcp/tokens/{token_id}/state` | — | `token_id` | body |
| `GET` | `/api/mcp/tools` | — | — | — |

### 运维 — `/api/files`

采集产物文件下载与列表

| 方法 | 路径 | 查询参数 | 路径参数 | 请求体 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/files/{fuid}` | — | `fuid` | — |

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
- **配置管理**：`/api/rules`、`/api/suricata/rules`、`/api/zeek/*`、`/api/es/*`、`/api/config/audit`

## 三·补、近期字段变化（端点没变，字段有增）

| 接口 | 新增字段 | 说明 |
| --- | --- | --- |
| `GET /api/detector/hits`、`/hits/{id}` | `event_types` / `event_type_labels` | **事件类型（具体归类，中文）**：`网络扫描`／`Web 应用攻击`／`账号口令攻击`／`权限提升尝试`／`连接数异常偏离`／`大流量外传`…（2026-10 改口径：不再返回 `signature_hit`、`baseline_deviation` 这类内部码）。两个字段同源，前端直接显示即可 |
| `GET /api/detector/hits`、`/hits/{id}` | （已有）`source_kind` / `source_label` | 三类来源：特征匹配 / 行为分析 / 基线偏离 |
| `GET /api/baseline/profiles` | `posterior` | 似然比**后验概率**（0~1）。打分方式=llr 时列表按它排序；`risk_score` 仍返回（加和分，回滚口径） |
| `GET /api/baseline/config` | 9 个新参数键 | `baseline.scheme` / `alpha` / `learn_source` / `pool_k` / `deviation_cap_per_entity_hour` / `deviation_cap_per_hour`、`profile.scoring` / `prior_odds` / `posterior_threshold`（都可在界面改、30 秒生效） |
| `POST /api/baseline/alerts/{profile_id}/disposition` | **新端点** | 告警处置（`false_positive` / `confirm`）；`profile_id` 可填画像 UUID 或实体键。判成误报后该实体（或 `signal` 指定的那一路证据）在 `profile.false_positive_suppress_days` 天内不再参与打分 |
| `GET /api/baseline/alerts/dispositions` | **新端点** | 最近处置记录（核对降权是否生效） |
| `GET /api/detector/hits`、`/hits/{id}` | `cluster_id` | 告警簇 ID：同一事件归类 + 同一 /24（v6 /64）+ 同一小时归为一簇，界面可把同簇收成一行 |
| `GET /api/baseline/numeric` | **新参数** `scope` | `entity`（默认，只看 `源IP:维度`）／`group`（只看 `grp:{网段}:维度` 组先验）／`all`。组先验是等组池化的内部统计（稀疏实体向 /24 先验收缩），不是"某个 IP 的基线"，默认不返回，免得列表里混进 `grp:10.0.0.0/24` 这种像网段的键 |
| `GET /api/rules` | **规则数变化** | 三条「签名命中(高/中/低危)」分流包装规则已删除（见 `DELETED_RULES`）。规则条数三档口径：**源码定义 19 条** → 其中 **7 条已收敛到特征匹配**（登记删除、播种跳过） → **实际生效 12 条**行为分析规则。签名告警**不走规则表**，事件类型直接取签名归类（classtype） |
| `hit_events.evidence`（事件证据） | `p` / `alpha` / `var` / `pooled_with` | 泊松判据下的偏离证据：上尾概率、校正后阈值、方差、是否用了组池化；回滚到 zscore 时仍是 `z` / `std` / `std_raw` |

## 四、前端必读的坑
1. 登录是**表单编码**，不是 JSON。
2. 接口给 UTC，**界面一律北京时间**。
3. 空态要区分「真的没有」与「读取失败」（失败会有 `error` 或非 2xx）。
4. 流量字段：`bytes_*` 是字节；`*_per_sec` 已是每秒（不要再除 20）。
5. 命中事件默认不含已忽略；按 `source_kind` 分三类展示。
6. 写操作错误码：400 参数错 / 404 不存在 / 409 重名。
