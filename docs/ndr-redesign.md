# NDR 改造方案：采集 → 归一化 → 过滤 → 检测 → 推送智能体

状态：**第 1~12 期已实施完成**（监控网段 / 归一化前置 / MCP 服务 + 智能体切到 MCP / 过滤规则 / HTTP 推送智能体 / Wazuh 4.14 集成与容量 / 界面整理 / 基线分析迁到 NDR / 采集面改造批 1~4：类型识别与流分类 / 指纹与文件元数据 / 请求头全量值 + 正文上限可设置 / 文件提取 + 下载通道），代码、门禁与 CI 均绿；**2026-10 已在实机服务器 `172.16.196.77` 部署上线**（含按用户要求删掉全部 10 个卷后从零重建），十个容器全 Up、`Filebeat → Redis → 归一化 → Logstash → ES` 与 `检测器 → 队列 → 智能体` 两条链路端到端跑通、Zeek 专项检查已做、监控网段 `172.16.196.0/24` 已下发并复验（`-f net 172.16.196.0/24` + `packet_filter.log` success），见下方「实机部署记录」。XFF 原始客户端 IP 已支持（`http.log` 的 `proxied` → 归一化 `real_client_ip`，无代理头为 NULL），请求体与响应体都已采集。**仍未做的是后续轮的事**：智能体侧对等适配（含文件下载入口）、智能体线路部署、以及第 8 节列出的几个调查项。全新服务器环境部署，无历史数据迁移。
范围：`ndr/`（主改）+ `agent/`（接收端与 ES 文档形态同步改）

---

## 1. 目标（用户需求原文要点）

- NDR 的功能边界：**采集 Zeek/Wazuh 原始数据 → 推入 Logstash 处理并落库 Elasticsearch 存储**。
- Logstash 对数据进行处理过滤，并**完成字段归一化**；过滤规则在**用户界面**定义。
- 过滤后的数据推送给**规则检测器**做安全分析；匹配事件触发后推送给智能体（**网络推送**）。
- Elasticsearch **直接落库未过滤的全量数据**。
- 集成 **Wazuh 4.14**（不要 wazuh-dashboard）；为 Zeek / Wazuh / Logstash / Elasticsearch 提供管理界面。

## 2. 已定决策（用户拍板）

### 采集与归一化

| # | 问题 | 结论 |
|---|---|---|
| 1 | 过滤语义 | **两种规则分开**：① **监控网段**——Zeek 抓包层（BPF），一行一条网段/IP，只抓这些，其余丢弃；② **过滤规则**——已知某些固定 IP/端口/内容无分析价值时编写，手动精准降噪、减轻分析压力 |
| 2 | 原「分析网段」（AnalysisScope） | 并入监控网段，同一套概念 |
| 3 | 监控网段的作用面 | 同一份列表**同时喂** `bpf_filter`（只抓这些）与 `local_nets`（Zeek 内部/外部判定），因为规则里的 `src_internal` / `dst_internal` 依赖后者 |
| 4 | 归一化位置 | `normalizer.py` 提到 Logstash **之前**，由它完成字段归一化 |
| 5 | normalizer 接口 | **B**：Filebeat `redis` 输出 → normalizer 消费并 ack → Logstash `http` 输入 |
| 6 | Wazuh | 仓库内起 `wazuh-manager` 4.14，**不含** indexer / dashboard |
| 7 | Wazuh 采集范围 | **告警 `alerts.json` + 全量日志 `archives.json`**（manager 需开 `logall` / `logall_json`，Filebeat 侧开 archives 输入）。数据量显著上升，容量单列评估 |
| 8 | Wazuh 管理深度 | **通过 Wazuh API(55000) 管 agent 注册与规则下发**（不只是只读状态）：后端经 Basic 换 JWT、token 过期需刷新，界面可列 agent / 下发规则文件并校验生效；连接信息**固化在部署环境**（`ST_WAZUH_API_*`，界面只读、无保存入口）—— 第 6 期原本设计成「凭据存 `SystemConfig` 表、界面可配」，实机部署后取消（同一事实两份来源，见第 6 期的说明） |

### 存储与字段

| # | 问题 | 结论 |
|---|---|---|
| 9 | ES 文档形态 | **只存归一化后的文档**，智能体侧同步改。另有两条落地约定：只输出**非空字段**（避免大量 null 撑爆 mapping），原始文档整份进 `raw` |
| 10 | ES 索引名 | 不再沿用 `zeek-*` / `wazuh-alerts-*` 两族，改用**统一索引族 `shentong-events-*`**（按日期滚动），智能体只面对一个索引模式 |
| 11 | 过滤条件字段 | 源/目的 **地址 + 端口**，**再加协议内容字段**（`uri_path` / `host` / `user_agent` / `body` / `command` / `query` 等），操作符含「包含」与「正则」 |
| 12 | URL 解码语义 | 现在规则引擎（Python）对 `contains`/`regex` 自动做 URL 解码，Logstash 不会。**由 normalizer 归一化时解码干净**，保证检测器与过滤器行为一致 |

### 投递与回执

| # | 问题 | 结论 |
|---|---|---|
| 13 | 投递智能体 | **换掉 Redis 改 HTTP**；推送地址在 Web 界面配置（要能推给远程/异构的接收方） |
| 14 | 可靠性 | **要持久化重试**（失败落盘/队列，后台重发） |
| 15 | 回执形式 | **用 HTTP 响应当回执**：NDR POST → agent 返回 200 + 「已收到」。不需要反向通道，agent 也不必知道 NDR 地址 |
| 16 | 判重责任 | **移到智能体侧**。NDR 生成**事件ID + 指纹**放进载荷；智能体收到先查表，近期已分析过就只累加计数、不进分析流程 |
| 17 | 事件ID / 指纹 | **事件ID = 每次投递生成 UUID**（追踪与回执对应）；**指纹 = 确定性哈希**（沿用现在 NDR `digest_fingerprint` 的算法，作判重键） |
| 18 | 判重窗口 | ~~默认 7 天~~ → **实施结果**：判重键 = 事件组指纹（IP 集合 + `group_bucket_minutes` 时间桶，默认 30 分钟）+ Redis 占位 TTL 两个桶；与保留期无关（见 §8.1） |
| 19 | Logstash → 检测器 | **继续走 Redis**（`shentong:events:raw`），本次只改「检测器 → 智能体」那一跳 |

### 智能体接口（MCP）

| # | 问题 | 结论 |
|---|---|---|
| 20 | NDR 对外接口 | **提供完整 MCP server** 供智能体调用：分析事件时的查询、调查、分析端点（详见第 6 节） |
| 21 | 能力范围 | **只读 + 写回结论**：查询/调查工具只读；另开一组把调查结论写回 NDR（标记已分析 / 定级 / 结论摘要），NDR 界面可见。**不给管理动作**——智能体不能改监控网段、过滤规则，也不能启停规则 |
| 22 | 托管方式 | **独立 MCP 服务**（独立进程/容器），不挂在 NDR 后端进程上 |
| 23 | 认证 | **令牌校验**；令牌由 **NDR Web 界面**生成与吊销（只完整显示一次，库里存哈希） |
| 24 | 智能体数据访问 | **完全走 MCP，不再直连 ES**：`agent/backend/app/investigation/es_query.py` 的 ES 查询整体退役，改由 MCP 工具承担 |

### 基线与画像（第 8 期）

用户的判断（原话）：「**应该把基线分析迁移到NDR，agent智能体本身是消费数据进行LLM推理分析的。基线应该放在数据产生的NDR侧。**」数据在哪产生、就在哪沉淀长期行为；智能体只拿标签做定性。

| # | 问题 | 结论 |
|---|---|---|
| 25 | 搬什么 | **数值 2σ 基线 + UEBA 账号/会话画像都搬到 NDR**（两者都是纯统计，不需要模型） |
| 26 | 交付形态 | **既写进推送摘要（`digest.baseline` 标签），也开 MCP 查询工具**（`baseline_lookup` / `entity_profile`）——智能体分析时能顺着标签追问细节 |
| 27 | 2σ 还要不要模型确认 | **要**：NDR 只按 `当前值 > mean + zσ` 打标，**定性仍由智能体用云端模型做**（沿用原「异常确认」提示词） |
| 28 | 界面 | **并入现有「运行状态」页**（`ndr/frontend/components/status-panel.tsx` 的「基线观测」块），不新增导航项 |
| 29 | 会话 cookie 落库 | **必须在 NDR 侧哈希后才落 `entity_profiles`**（sha256，展示只用前 8 位）；事件里只留截断值 |

### 部署前提：全新服务器环境

现网已下线，改造后将在**全新服务器环境**部署，ES 里没有需要兼容的历史数据。因此**不存在新旧格式并存的问题**，也不需要任何数据迁移、双查兜底或过渡期代码 —— 智能体一律按新字段路径查新索引即可。

### 实机部署记录（2026-10，`172.16.196.77`）

一次性部署记录，供后续复现与排查用。

**服务器与环境**：`nss@172.16.196.77`，Ubuntu 24.04.1 LTS（kernel 6.8），6 核 / 11 GiB 内存；Docker **29.1.3** + Compose **2.40.3**，`nss` 在 docker 组（免 sudo 用 docker）与 sudo 组；`ufw` inactive、iptables INPUT policy ACCEPT（不用额外开端口）；网卡 `ens160` = 172.16.196.77/24。

**部署目录与文件**：`/opt/shentong-ndr`，三个文件 —— `docker-compose.deploy.yml`（从仓库拷）、`logstash/config/logstash.yml`（从仓库拷）、`.env`（600，含 `JWT_SECRET` / `CORS_ORIGINS=http://172.16.196.77:3000,http://localhost:3000` / `ZEEK_IFACE=ens160` / `REDIS_HOST=localhost` / `REDIS_PORT=6379` / `REDIS_KEY=shentong:events:collect`）。**Wazuh 叠加件已于 2026-10-03 一起部署**（`4655bd2`/`12eab73`/`646b779`/`f3f91ef`/`ca35c42`/`e598764` 之后的镜像）：`docker-compose.deploy.yml` 顶部加 `include: [docker-compose.wazuh.yml]`（compose ≥2.20.4 支持 `include`，本机与服务器都是 2.40.3），于是多出 `wazuh-manager` 与 `wazuh-filebeat`；`.env` 另加 `WAZUH_API_URL=https://wazuh-manager:55000` / `WAZUH_API_USER=wazuh-wui` / `WAZUH_API_PASSWORD=…` 与 `WAZUH_ARCHIVES_ENABLED=false`。用 `include` 而**不是**把服务复制进 deploy 文件的理由：单一定义、结构上不可能与开发版漂移（本地开发仍是 `-f docker-compose.wazuh.yml` 显式 opt-in）。实机验证结论见 `ndr/wazuh/README.md` 第五节。

**镜像**：仓库是私有库 → 三个 GHCR 包匿名拉取 403，先在服务器 `docker login ghcr.io`（需要带 `read:packages` 的 PAT）才能拉。实际用到 7 个镜像：`ghcr.io/cxiyuan/sec-agent/shentong-ndr`（backend / detector / normalizer / ndr-mcp **四服务共用**，靠 compose 的 `command` 覆盖成 `python -m app.detector` 等）、`shentong-ndr-frontend`（Next）、`shentong-zeek`（Zeek + Filebeat）、`elasticsearch:8.15.3`、`logstash:8.15.3`、`postgres:16`、`redis:7`。

**十个服务**：backend / detector / elasticsearch / frontend / logstash / ndr-mcp / normalizer / postgres / redis / zeek，全部 `RestartCount=0`。（2026-10-03 加 Wazuh 叠加件后为 **12 个**：再加 `wazuh-manager` 与 `wazuh-filebeat`。）

**验收结果（实测）**：ES `_cluster/health` = green（**首次带索引时是 yellow** —— 单节点集群默认 1 副本分配不出去，见下方第 5 条）；`GET /api/health` = `{"status":"ok","app":"深瞳 · 安全分析智能体"}`（注意路径带 `/api`）；`ndr-mcp /health` = ok；frontend `:3000` 返回 307（重定向，正常）；Logstash `:8080` = 200；归一化服务每 10s `POST http://logstash:8080/ "HTTP/1.1 200 OK"`；ES 索引 `shentong-events-YYYY.MM.DD` 持续增长（实测某 10 分钟窗口入库 9079 条、其中退化成 `message` 的 0 条）；Redis 四个队列（`collect` / `collect:processing` / `raw` / `dispatch`）为空＝实时消化；检测器正常投递摘要（`扫描 17335 / 命中 60 / 频率触发 1 / 重复跳过 3126 / 摘要 7 / 投递 9`）；`conn.log` 持续增长。默认管理员 `admin` / `admin123`（`ndr/backend/app/config.py:105-106`）。

**上线过程中修掉的六个缺陷**（都已提交、CI 通过、服务器复验）：

1. **检测器/归一化崩溃重启循环**（commit `4e9508b`）——`redis-py 8.x` 默认 `socket_timeout=5s`，`ndr/backend/app/detector/queue.py` 的 `brpoplpush(timeout)` 阻塞超过 5s 就被读超时打崩。修法：新增 `make_blocking_client()`（socket 超时 = 阻塞超时 + `_BLOCK_SOCKET_MARGIN_SECONDS = 10`）并捕获 `redis.TimeoutError`，`runner.py:119` 与 `collector/normalizer_service.py:174` 改用它。
2. **Logstash 管道没被播种**（commit `5a4d7fe`）——compose 把命名卷同时挂到 backend 的 `/logstash` 与 logstash 的 `/usr/share/logstash/pipeline`，**首次挂载时 Docker 会把镜像自带的示例管道（92 字节 `beats→stdout`）拷进卷**；`ndr/backend/app/api/routes/logstash.py` 的 `seed_if_missing()` 原来只看「文件非空」→ 认定用户配过 → 不播种，于是 8080 没有 http 输入、归一化报 `[Errno 111] Connection refused`。修法：新增 `_looks_managed()`（首行标记或含 `elasticsearch` 才算本系统管道），非托管就覆盖播种。
3. **ECS 撞字段毁掉全部事件**（同一个 commit）——`logstash-input-http` 3.8.1 在 ECS 开启时会 `event.set("[user_agent][original]", <User-Agent>)`，而我们的归一化文档里 `user_agent` 是**字符串**（常为空串）→ 路径冲突抛 `InvalidFieldSetException`，异常发生在输送给编解码器的 block 里，被 `json_lines` 捕获 → **整条事件退化成一条 `message`**（实测 3 分钟 1258 条）。修法：管道模板的 http 输入加 `ecs_compatibility => "disabled"`，`logstash.yml` 再加 `pipeline.ecs_compatibility: disabled` 兜底。**次生坑**：坏文档已把 `user_agent` 动态映射成 object，改好后的扁平文档反而被 ES 400 拒收（`document_parsing_exception` 3243 次）→ 删掉中毒索引让它按新映射重建。
4. **Zeek 把中文请求体整块丢掉**（commit `5499fb3`）——`ndr/zeek/site/shentong-httpbody.zeek` 的守卫 `/[^\x09\x0a\x0d\x20-\x7e]/` 只放行可打印 ASCII，UTF-8 多字节全被当二进制丢（同一 POST 路径：英文有 `body`、中文没有）。修法：改成只拦 NUL / C0 控制字符 / DEL（`/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/`），实机复验中英文 `body` 都进 `http.log`。
5. **ES 集群健康恒为 yellow**（commit `26052e1`）——Logstash 输出是 `manage_template => false`，索引由 ES 自动创建，单节点集群拿到默认 `number_of_replicas: 1`，副本永远分配不出去（`_cluster/allocation/explain` 说得很直白：这份分片已经在本节点上了）。修法：`ndr/backend/app/api/routes/es_admin.py` 抽出 `ensure_retention()`，模板设置改成 `number_of_replicas: 0` + `auto_expand_replicas: "0-1"`（单节点 0 副本 = green，真多节点时 ES 自动补 1 副本），并让 `ndr/backend/app/main.py` 启动时幂等下发（原来只有界面点「下发保留期」才下发，且下发的内容不含副本设置，ES 起得晚还会静默跳过）；**已存在的索引**模板管不到，要用 `PUT <index>/_settings {"index":{"auto_expand_replicas":"0-1"}}` 单独改一次。

6. **配了监控网段后 Zeek 起不来**（commit `0b538d6`）——`ndr/zeek/entrypoint.sh` 的 `start_zeek()` 把 BPF 过滤器当**位置参数**传给 Zeek（`zeek -C -i "$iface" "$bpf" …`），而 Zeek 的位置参数是脚本/输入文件名 → `fatal error: can't find net 172.16.196.0/24`，看门狗 2 秒后拉起、再失败，无限循环。修法：改用 `-f "$bpf"`（`zeek -h` 确认 `-f|--filter` 存在）。未配网段时走 else 分支不带过滤器，所以这条路径**上线后第一次配网段才第一次被跑到**；当天先用卷内配置临时清空 `bpf_filter` 恢复抓包，镜像更新后再下发网段并复验 `-f`。

**收尾加固（2026-10-02）**：按用户要求收紧存储端口暴露面（commit `b41bb12`）——ES `127.0.0.1:9200`、Postgres `127.0.0.1:5432`、Redis `${REDIS_BIND:-127.0.0.1}:6379`（本机 `.env` 设 `REDIS_BIND=10.255.12.4`，zeek 容器的 `REDIS_HOST` 同步改成同一地址，否则 host 网络的 Filebeat 投不进采集队列）；`docker compose up -d` 重建后实测 `127.0.0.1:9200` / `127.0.0.1:5432` 通、`172.16.196.77:9200` / `:5432` / `:6379` 全不通、`10.255.12.4:6379` = PONG（`redis-cli` 容器实测）；重建期间 Redis 载入 AOF 让归一化/检测器各崩一次（`BusyLoadingError`）并自动重启恢复，之后 `RestartCount` 不再增长；链路复验：四队列为空、当日索引 15 秒 +143 条、归一化每 10s `200 OK`、检测器正常投递摘要。

**HTTP 正文与代理头（2026-10-02）**：按用户要求把**响应体**也采进 `http.log`（`ndr/zeek/site/shentong-httpbody.zeek` 新增 `resp_body`，上限 `max_resp_body_len = 4096` 字节，`redef` 可放大；请求体上限仍是 `max_body_len = 4096`），并把 Zeek 的 `proxied` 解析成归一化字段 `real_client_ip`（无代理头 = NULL）。归一化新增 `resp_body`（截 2000 字符，配置项 `http_resp_body_max_chars`）、`resp_body_len`（= `response_body_len`，整条响应体字节数）、`real_client_ip`；`real_client_ip` 参与**规则、画像、检索**（`ndr/backend/app/baseline/profile.py` 的 `_accumulate` 优先用 `entry.real_client_ip` 填 `src_ips`，两侧 `investigation/catalog.py` 的字段表/摘要/聚合字段都加了它），但**检测器的聚合摘要与推送仍按 TCP `src_ip`**（`ndr/backend/app/detector/aggregate.py` 的 `_agg_key`、`ndr/backend/app/detector/engine.py` 的数值基线未改）——即「谁在扫」按代理看待，「这个客户端的历史行为」按真实客户端看待。NDR 与智能体两侧的 `normalizer.py` / `schemas.py` / `config.py` / `rules/engine.py` / `investigation/catalog.py` 同步改，字段名与截断保持一致。**已知限制**：响应体采集的二进制守卫为保住中文只能拦 NUL/C0，压缩响应（gzip/br）可能以乱码进 `resp_body`（字段在、内容不可读），要精确跳过需再接 `http_header` 记录 `Content-Encoding`。

**遗留事项**：① ~~监控网段未配~~ **已配（2026-10-02）**：界面下发 `172.16.196.0/24`，`/config/interface.conf` 里 `monitored_nets` / `bpf_filter` / `local_nets` 三处一致，启动命令变为 `zeek -C -i ens160 -f net 172.16.196.0/24 …`，`packet_filter.log` 记 `{"filter":"net 172.16.196.0/24","init":true,"success":true}`；首次下发顺带暴露并修掉入口脚本 BPF bug（见第 6 条）；② **暴露面已收紧（2026-10）**：compose 原先把 `9200`（ES，无鉴权）、`5432`（postgres）、`6379`（redis，无密码）都发布在 `0.0.0.0`（同网段可直连）。现改为 ES / Postgres 只绑 `127.0.0.1`、Redis 绑到隧道地址 `10.255.12.4`（`.env` 里 `REDIS_BIND=10.255.12.4`，同时把 zeek 容器的 `REDIS_HOST` 改成同一地址 —— 该容器是 host 网络，它的 Filebeat 必须连到 Redis 实际监听的地址，否则采集队列投不进去）；③ ~~24h 轮转的日期目录与 3 天清理当天未见（时间未到）~~ **已核实并修正（2026-10 QA）**：轮转**不进日期子目录**（一直如此，旧文档把 `conn.2026-10-01.log` 误读成目录），2026-10 起轮转名带时分秒；3 天清理按 `mtime` 分钟级判定、且 Filebeat 不在运行时跳过删除；④ **XFF 原始客户端 IP 已支持（2026-10-02）**：Zeek 的 `HTTP::Info$proxied` 采代理头，normalizer 解析最左合法 IP 落成归一化字段 `real_client_ip`（无代理头 = NULL，`src_ip` 仍是 TCP 对端）；⑤ **响应体也采集并落库**：`resp_body`（截断）+ `resp_body_len`（= Zeek `response_body_len`，整条响应体字节数）。

**卷级重建（2026-10-02，用户要求「数据卷也删除」→ 从零重建）**：执行 `docker compose -f docker-compose.deploy.yml down -v --remove-orphans`，删掉 **10 个容器 + 网络 `shentong-ndr_default` + compose 声明的全部 10 个卷**（`es-data` / `pg-data` / `redis-data` / `zeek-logs` / `zeek-config` / `zeek-filebeat` / `zeek-extract` / `logstash-pipeline` / `logstash-backup` / `logstash-queue`；宿主上只有这 10 个卷，未波及其他项目，镜像未动），随后 `pull` + `up -d` 重建。**能自动回来的**：ES 集群 green、PG 建表 9 张（`baseline_stats` / `conclusion_records` / `entity_profiles` / `exclusion_filters` / `ingest_filters` / `mcp_tokens` / `rules` / `system_config` / `users`）、默认管理员 `admin`、内置规则 **82** 条、ES 模板与 ILM 策略（后端启动幂等下发）、Logstash 管道（后端 `seed_if_missing()` 播种 `/logstash/logstash.conf`，2386 B）、全部容器 Up、以及「Zeek 提取 → Filebeat → 归一化 → ES」整条链路（重建后第一次上传即入库）。**必须人工补的只有采集配置**——监控网段 / 附加 BPF / 两个正文上限存在 PG `system_config` 与 Zeek 卷内 `interface.conf`，不在播种范围：清空 `zeek-config` 后 Zeek 回落默认（`interface=ens160`、网段空、`body_max_bytes=16384`、`resp_body_max_bytes=65536`、启动命令**无** `-f`，`packet_filter.log` 记 `"filter":"ip or not ip"`）；用 `PUT /api/zeek/interface` 重新下发后复验：`interface.conf` 七键齐全、启动命令 `zeek -C -i ens160 -f net 172.16.196.0/24 /usr/local/zeek/share/zeek/site/local.zeek`、`packet_filter.log` `"filter":"net 172.16.196.0/24" … "success":true`、容器内 `shentong-limits.zeek` 渲染回 `16384` / `65536`。**顺序坑**：登录是 OAuth2 **表单编码**（`-d 'username=admin&password=admin123'`），拿 JSON 发 `{"username":…}` 会 422 返回空 token，`PUT` 随后报 `{"detail":"无效凭证"}`，看起来像「默认口令不对」。重建后带令牌复验：2400 B `text/plain` 与 2208 B `application/json` 上传 → 落盘 sha256 与本机逐字一致（另有两条 404 响应体 2318 B `text/html`）、`GET /api/files/<fuid>` 全 200（`content-type` 取自 `mime_type`、`content-disposition: attachment; filename="<fuid>"`、`content-length` 与落盘一致）、无令牌 401；清理助手 `--dry-run` 保留 6 / 删除 0（`text/json` 那条白名单修复在重建后的最新镜像里生效）。**重建后的一个时序问题（已在代码里修掉，2026-10-02 实机复验）**：后端在启动时下发 ILM 策略与索引模板；当时的实现是**一次性**调用、失败只记一条 warning（本次后端日志里正是 `elastic_transport` 连续失败后放弃）。于是模板 `shentong-events` 缺失，Logstash 自动创建的索引拿到默认 `number_of_replicas: 1`，单节点集群恒为 **yellow**（`_cat/shards` 一条 `r UNASSIGNED`）。**当时的应急修法**：调界面同款接口 `POST /api/es/apply-retention`（**无请求体** = 用系统配置的默认 30 天；发 `{}` 会 422，因为 `RetentionIn.retention_days` 是必填）→ 模板出现且设置正确（`lifecycle.name=shentong-retention`、`number_of_replicas=0`、`auto_expand_replicas=0-1`、pattern `shentong-events-*`、priority 500）；再对已存在的索引 `PUT shentong-events-*/_settings {"index":{"auto_expand_replicas":"0-1"}}` → 索引副本变 0、集群回到 **green**（`unassigned_shards: 0`）。**代码改造（`bc58c62` + `075e33b`，用户选的「加启动重试」）**：`ndr/backend/app/main.py` 的 `_seed()` 把下发丢给守护线程 `_push_es_retention()`（不阻断 API 就绪）——前 `_ES_SETUP_ATTEMPTS = 24` 次每 `_ES_SETUP_INTERVAL_SECONDS = 5.0` 秒重试（≈2 分钟），之后每 `_ES_SETUP_RECHECK_SECONDS = 300.0` 秒复查一次，**成功之后也不停**（模板被删、ES 卷被换都能自己长回来）；打完第一轮高速重试才记一条 warning，之后不再刷日志。`ndr/backend/app/api/routes/es_admin.py` 的 `ensure_retention()` 除了下发模板，还会对**已存在**的同类索引 `put_settings(number_of_replicas=0, auto_expand_replicas="0-1")`（幂等；没有匹配索引时 ES 报 `index_not_found`，忽略），所以界面「下发保留期」现在一步就能把 yellow 修回 green，不再需要手工 `PUT`。**第一版（12 × 5 秒 ≈ 1 分钟）实机没通过**：`stop elasticsearch` 后重建后端，1 分钟窗口内 ES 还没回来，重试就放弃并记了 warning（模板仍是 404）→ 才改成 24 次 + 长期复查。**复验（2026-10-02，镜像 `sha256:d05515624331434897fb0449ce659c7b3e904ab0cb871e2995713eef03f89221`，四服务同镜像一起重建）**：删模板 + `stop elasticsearch` + 重建 backend → 日志里只有 `elastic_transport` 的重试、**没有**「失败」warning；`start elasticsearch` 后 **30 秒**（第 10 次尝试）自动补上，后端日志 `ES 保留期策略/索引模板已在第 10 次尝试下发成功`、`GET _index_template/shentong-events` → 200；同一轮里故意新建一个带 `number_of_replicas: 1` 的索引 `shentong-events-2026.10.99`，收尾核对它已被回正为 `number_of_replicas: 0` + `auto_expand_replicas: 0-1`、集群 `green` / `unassigned_shards: 0`（测完删掉该索引）。**探针口径提醒**：归一化把 `fuid` / `extracted` 等放在 `_common`，**每条日志都带这两个键**（非 files 类型是空串），所以 `exists extracted` 的计数 ≈ 全量文档数（重建后实测 3770 / 总 3933），不能当作「有提取件」的判据 —— 判据要用 `log_type.keyword=files` 再取 `extracted` 非空。

### 两条已确认的既有事实

- **智能体没有自己的 Redis / ES**：`agent/backend/app/config.py:38-40` 的 `ST_REDIS_URL` / `ST_CELERY_BROKER_URL` / `ST_CELERY_RESULT_BACKEND` 全部指向 `NDR_REDIS_URL`（`/0`、`/1`、`/2`）。**ES 这一侧的直连由第 6 节的 MCP 彻底切断**（智能体从此不需要 ES 地址）；剩下的只有 Celery broker/backend 仍在用 NDR 的 Redis ——「推送改 HTTP」解不掉它，真要解耦得连 broker 一起换，本次不做。
- **现状链路里没有归一化**（第 2 期已改掉）：改造前是 `Filebeat → Logstash → ES`，`ndr/backend/app/collector/template.py` 的 filter 段只补一个 `source_system`，文档原样落库（Zeek 在 `zeek.*`、Wazuh 在 `data.*`）——`agent/backend/app/investigation/catalog.py:7-12` 的注释正是照此写的。现在归一化提前到 normalizer 服务，ES 只存统一字段。

## 3. 目标数据流

```
Zeek(只抓监控网段 / BPF) ─ Filebeat ┐
                                    ├→ Redis 队列 shentong:events:collect（Filebeat 用 RPUSH 写右端；设长度上限）
Wazuh 4.14(alerts + archives) ──────┘             │
                          normalizer 服务（BRPOPLPUSH 取出 → 归一化 → 成功后确认）
                                                  │
                     ┌────────────────────────────┴───────────────────────────┐
                     │ ① LPUSH 归一化文档（先做：检测不被 ES/Logstash 拖住）      │ ② POST NDJSON
                     ▼                                                        ▼
        Redis shentong:events:raw                                Logstash http :8080
                     │                                                        │
             规则检测器（规则匹配 / 聚合）                        output : ES（无条件，全量）
                     │ 命中                                        索引 shentong-events-<日期>
        HTTP POST（持久化重试）→ 智能体
        ← 200 + 已收到（这就是回执）
                     │
   智能体 ──MCP over HTTP（令牌）──→ NDR MCP 服务
                                       ├─→ ES（查询 / 聚合 / 原始证据）
                                       ├─→ 规则 / 检测器状态 / 网段与过滤配置
                                       └←─ record_conclusion（写回结论，只给界面看）
```

> 第 4 期的「过滤规则（降噪）」落在**归一化服务**里判定（决定要不要把这条投进检测器队列），不再写成 Logstash 的 `drop` —— 因为原始日志已经不经过 Logstash，而第 2 期之后 ES 只有 Logstash 一个写入方。

### 三条红线

1. **过滤绝不用 `drop{}`**。Logstash 的 `drop` 会**终止整个事件**，连 ES 那条输出一起没了，直接违反「ES 落全量」。**最终落法**：过滤压根不写在 Logstash 里，而是归一化服务里的一次判断（`ndr/backend/app/ingestion/ingest_filter.py`）—— 命中就跳过「投检测器队列」那一步，ES 那条 POST 照旧发全量。
2. **ES 输出永远无条件**。
3. **ES 输出的分流判断已被消灭**（第 2 期落地）。原方案要求把 `if [log_type]` 改成按 `source_system` 分流；实际上归一化前置后**只剩一族索引** `shentong-events-*`，`render()` 里已没有任何分流：原始文档根本不经过 Logstash。归一化后 Wazuh 也带 `log_type="wazuh"`（`ndr/backend/app/ingestion/normalizer.py:373`）这个坑随之不存在。

## 4. 关键契约变更：ES 文档形态

现在 ES 存**原始**文档，智能体按来源走不同字段路径：

| 概念 | 现在（zeek） | 现在（wazuh） | 改后（统一） |
|---|---|---|---|
| 源地址 | `zeek.id.orig_h` | `data.srcip` | `src_ip` |
| 目的地址 | `zeek.id.resp_h` | `data.dstip` | `dst_ip` |
| 源端口 | `zeek.id.orig_p` | `data.srcport` | `src_port` |
| 目的端口 | `zeek.id.resp_p` | `data.dstport` | `dst_port` |

改后的统一字段 = `ndr/backend/app/schemas.py:14` 的 `class UnifiedLog`：
`source_system / ts / event_type / log_type / src_ip / dst_ip / src_port / dst_port / protocol / conn_state / hostname / user / process / command / query / uri_path / query_string / method / body / resp_body / resp_body_len / referer / cookie / auth_scheme / content_type / user_agent / status_code / resp_mime / bytes_out / bytes_in / ja3 / ja3s / tls_version / cert_issuer / qtype / filename / mime_type / real_client_ip / account / rule_id / rule_groups / mitre / severity / summary / raw`。

**原始数据不会丢**：`UnifiedLog.raw: dict[str, Any]` 把原始文档整份带进 ES。

### 智能体侧必须同步改的点（已定位）

| 文件:行 | 现在 | 改后 |
|---|---|---|
| `agent/backend/app/investigation/catalog.py` | 26 个字段条目、51 处 `"zeek": ...` 双列映射（`{"zeek": "zeek.id.orig_h", "wazuh": "data.srcip", ...}`） | 单列：概念 → 统一字段名。**净简化** |
| `agent/backend/app/investigation/es_query.py:284` | 硬编码 `for extra in ("zeek.body", "data.command", "rule.description")` | 用统一字段名 |
| `agent/backend/app/ingestion/es_schema.py:20-21` | `es_source_fields()` 返回原始路径（与 `ndr/backend/app/ingestion/es_schema.py` 逐字相同） | 返回 `src_ip` / `dst_ip` |
| `agent/backend/app/config.py:29-32` | `es_zeek_src_fields="zeek.id.orig_h"` 等 4 项（`ndr/backend/app/config.py:31-34` 同） | 新索引名 + 统一字段名 |
| `agent/backend/app/consumer.py` | Redis 消费端 | 退役，改 HTTP 接收端点 |

> 其中 `catalog.py` 与 `es_query.py` **随第 3 期整体搬到 NDR**（改由 MCP 的 `describe_data` 等工具提供），所以这两处不在智能体侧改，而是在 NDR 侧按统一字段重写一次 —— 避免同一份改动做两遍。`es_schema.py` / `config.py` 的 ES 相关项在智能体侧**直接删除**。

## 5. 判重与回执（已实施，第 5 期）

```
NDR 检测器                               智能体 POST /api/push/digests
  命中 → 聚合摘要（一批 = 一次图运行）
  每条配 event_id(UUID) + fingerprint     逐条：算事件组指纹
  POST {"items":[...]} ─────────────────→   ① 库里有同指纹 EventGroup → event_count += count、
  Authorization: Bearer <令牌>                 window_end 前移，**不跑图**
                                            ② 库里没有、Redis 桶内占位已存在（同桶在跑）→ 跳过
  ←────────── 200 + PushResult ──────────   ③ 都没有 → Redis 占位(nx) + 投 Celery 跑图
  失败 → 落 shentong:events:pushretry
         检测循环后台重发（2xx 才算送达）
```

- **判重落在智能体侧**（`agent/backend/app/api/routes/push.py`）：只有它知道某个事件组分析过没有。指纹算法下沉到 `agent/backend/app/digest.py` 的 `group_fingerprint(ips, start)`，与图里落库用的完全同源（`agent/backend/app/agents/nodes.py:_group_fingerprint` 现在转发调用它），桶宽 = `group_bucket_minutes`；**必须用「现在」的桶**，与 `agent/backend/app/workers/tasks.py` 里 `window_start = now` 对齐。
- **不预建 EventGroup 行**：`agent/backend/app/agents/persistence.py:save_groups` 会用 `row.event_count = len(existing)`（现有 Event 行数）覆盖计数，预建行会污染它；「同桶第一批还在跑」用 Redis 占位（`set(nx, ex=bucket*2)`）拦，Redis 不可用时放行（fail-open，宁可多跑不漏报）。
- **回执 = HTTP 2xx**：`ndr/backend/app/detector/push.py:push_batch()` 收到 2xx 即算送达；非 2xx/超时 → 整批落 `shentong:events:pushretry`（`ReliableQueue`，processing 队列兜住进程崩），由检测循环每轮的 `push.retry_pending()` 重发，并区分两类失败：网络错/超时/5xx/408/429（整体不可达）→ 整批放回队尾并**结束本轮**（空转没意义）；持续 4xx 的坏批 → 尝试次数 +1 并挪到队列最新端让健康批先走，满 `_RETRY_MAX_ATTEMPTS=5` 判 `lost` 丢弃并计数（不再永久堵队首）。重试队列有上限 `_RETRY_QUEUE_MAX=2000`（lpush 后立即 ltrim，保最新、丢最老，丢失批数记 `retry_dropped`）；`retry_pending()` 全程持 Redis 锁（SET NX EX）与 `POST /api/agent-push/retry` 串行，抢不到返回 `locked=true`；`recover_pending()` 只在主循环选主时显式调一次。
- **NDR 侧不再有闸门**：`analyzed_fingerprints` 表、`ndr/backend/app/detector/analyzed.py`、`_drain_done`、`analyzed:done` 队列、agent 侧 `consumer.py` 与 `_notify_done` 已全部删除；`ndr/backend/app/detector/fingerprint.py` 保留 `digest_age`（超龄丢弃）与 `digest_fingerprint`（推送载荷用）。
- **升级注意**：老部署里 `analyzed_fingerprints` 表会留下（`Base.metadata.create_all` 不删表），不再写入、可手工 drop；`shentong:detector:dedup` 只剩历史计数，界面标注为「退役前」。
- **验收对照**（单进程实测，`/tmp/test_push_api.py` 30 项、`/tmp/test_agent_push.py` 51 项、`/tmp/test_runner_push.py` 15 项全过）：重复推送同一指纹 → 只加计数、不投任务 ✅；未配/配错令牌 → 503/401，界面报错可见 ✅；推送失败 → 落重试队列并在下一轮重发 ✅；智能体不可达且重试队列写不进 → 摘要放回检测队列，不静默丢 ✅。**未在真实 Zeek/Wazuh 流量与双机部署下端到端跑过**（与第 1~4 期同批实机验收）。

## 6. 智能体接口：MCP（新）

NDR 对外提供 **MCP server**，智能体在分析事件时通过它查询、调查、分析。

**现状**：全仓没有任何 MCP 代码（`grep -i 'mcp|modelcontextprotocol|fastmcp'` 零命中）；NDR 侧也**没有事件查询 API**——`ndr/backend/app/api/router.py` 只挂 `auth` / `exclusions` / `rules` / `es_admin` / `logstash` / `detector` / `zeek` 七组管理类路由（原 `analysis_scopes` 已随第 1 期并入 `zeek`）。所以智能体现在是**直接连 NDR 的 ES 查**（`agent/backend/app/investigation/es_query.py`）。

### 工具面

| 分组 | 工具 | 来源 |
|---|---|---|
| 查询 | `describe_data`（数据源 / 真实时间范围 / 字段清单）、`search_events`、`aggregate_events`、`raw_evidence` | `agent/backend/app/investigation/tools.py:636-718`，走 `es_query.py` |
| 调查 | `timeline`、`net_flows`、`dns_queries`、`tls_fingerprints`、`web_requests`、`file_hashes` | 同上，整体搬到 NDR |
| NDR 上下文 | `get_event`（按事件ID/指纹取摘要）、`get_rule`（触发规则定义）、`detector_status`（检测器 / 队列 / 速率）、`list_networks`、`list_filters` | **NDR 独有，新增**——现在智能体只能从推送载荷里猜 |
| 写回 | `record_conclusion`（按事件ID/指纹写：状态、定级、结论摘要、thread_id） | **新增**，就是「只读 + 写回结论」里的那一半写 |

**留在智能体本地、不进 MCP 的 8 个工具**：`asset_lookup`、`topology_neighbors`、`entity_profile`、`memory_recall`、`group_history`、`threat_intel`、`record_finding`、`note_gap` —— 它们查的是智能体自己的 Postgres 与外部情报，与 NDR 无关。

### 为什么智能体侧改动小

`agent/backend/app/investigation/planner.py` 是**文本 ReAct，不是原生 function-calling**：`:286` 把 `tools.tool_catalog_text()` 拼进提示词，`:448-451` 拿模型输出的 `action` + `params` 调 `tools.execute(action, params, ctx)` 派发（`FREE_TOOLS = {"record_finding", "note_gap"}` 在 `:29` 直接放行）。于是：

- 只需在 `tools.execute` 的**派发层**把 NDR 类工具转成 MCP 调用，**调查循环一行不用改**。
- 工具清单可以**从 MCP server 动态拉**（`list_tools`），NDR 以后加工具不需要智能体重启或重新部署。
- 字段目录 `agent/backend/app/investigation/catalog.py`（26 个字段条目、51 处 `"zeek":` 双列映射）连同 `es_query.py`（511 行）一起搬到 NDR，改由 `describe_data` 提供 —— 这正好和第 4 节的字段契约变更**合并成同一次改动**，不重复做两遍。

### 两组令牌不要混

| 令牌 | 方向 | 谁生成 | 谁校验 | 存哪 |
|---|---|---|---|---|
| **推送令牌** | NDR → 智能体 | 智能体侧定，填进 NDR 的「智能体推送」配置 | 智能体的 HTTP 入口 | NDR 的 `SystemConfig` |
| **MCP 令牌** | 智能体 → NDR | **NDR 界面生成 / 吊销** | NDR 的 MCP 服务 | NDR 新表（只存哈希，明文只显示一次） |

两者方向相反，是两份不同的密钥，互不替代。

### 结论回写与判重的关系

- **判重的权威仍在智能体**（第 16 / 17 条）：收到推送先按指纹查 `agent/backend/app/db/models.py:59` 的 `EventGroup`，命中只累加 `event_count`。
- NDR 侧由 `record_conclusion` 写下的记录**只是给界面看和审计的镜像**，不参与判重 —— 避免两边各判一次、结论对不上。
- 镜像的保留期（`ST_MCP_CONCLUSION_RETENTION_DAYS`，默认 7 天）只影响这些镜像记录能查多久，**不参与判重**（判重看事件组时间桶，见 §8.1）。

### 部署与配置

- compose 新增 `mcp` 服务（同 NDR 镜像，`command: python -m app.mcp_server`），单独暴露一个端口。
- 传输用 MCP **streamable HTTP**（要跨机部署，不走 stdio）。
- 依赖新增官方 `mcp` Python SDK（写进 `ndr/backend/pyproject.toml`）。
- 智能体侧配置：MCP 地址 + MCP 令牌；`es_query.py` 退役后，智能体的 ES 相关配置项一并删除。

## 7. 分期实施

### 第 1 期 · 监控网段（Zeek 抓包层）

> ✅ **已完成**。一份多行清单成为唯一来源，Zeek 的 `bpf_filter` 与 `Site::local_nets` 都由它生成。

**落地形态**：

- 清单存在 SystemConfig 的 `zeek.monitored_nets`（换行分隔）；同时以**逗号**形式写进 `/config/interface.conf` —— 该文件是 `key=value` 行格式，多行值必须压成逗号，Zeek 入口（`ndr/zeek/entrypoint.sh: render_nets`）按逗号切开渲染 `Site::local_nets`。
- `/config/interface.conf` 现在写 5 个键：`interface` / `monitored_nets` / `bpf_filter` / `local_nets` / `bpf_extra`。其中 **`bpf_filter` 与 `local_nets` 是生成物**，输入只有 `interface` / `monitored_nets` / `bpf_extra`。
- BPF 生成规则（`ndr/backend/app/ingestion/scope.py: build_bpf`）：CIDR → `net 10.0.0.0/8`，单 IP → `host 1.2.3.4`，多项取「或」并加括号（BPF 里 `net X` 本身即「源或目的落在 X」，无需写 src/dst）；`bpf_extra` 非空时以 ` and (...)` 追加。
- 校验（`validate_nets`）：至少 1 条、最多 200 条、逐条 `is_valid_ip_or_cidr`（CIDR 主机位必须为 0，排除 /32、/128）。
- 接口：`GET /api/zeek/status`（回 `networks` / `bpf_extra` / 生成的 `bpf_filter` 与 `local_nets`）、`GET /api/zeek/networks/status`（供前端首次向导拦截）、`PUT /api/zeek/interface`（`interface` 留空 = 保持当前网卡，首次向导只提交网段即可）。
- 落库镜像键：`zeek.interface` / `zeek.monitored_nets` / `zeek.bpf_filter` / `zeek.local_nets` / `zeek.bpf_extra`。**检测器读库**（`ndr/backend/app/detector/runner.py: _load_scopes` → `monitored_nets()`），因为它不挂 `/config` 卷；配置文件里 `monitored_nets` 为空时 Zeek 侧回落读库，避免共享卷被清后抓包范围丢失。
- 概念合并已完成：删除 `AnalysisScope` 表与模型、`ndr/backend/app/api/routes/analysis_scopes.py`、`ndr/backend/app/api/validation.py`、`ndr/frontend/components/scope-manager.tsx`；`ndr/frontend/components/nav.tsx` 的首次向导拦截改打 `/api/zeek/networks/status`，不再有「多套网段组 + 启用/停用」的概念。

**验收**：界面改网段 → 生效可见 → Zeek 只抓到该网段；非法输入被拒。

### 第 2 期 · normalizer 前置

> ✅ **已完成**。⚠️ 但**必须和第 3 期同批上线**：第 2 期一改 ES 文档格式，智能体现有直连 ES 的查询（按 `zeek.id.orig_h` / `data.srcip`）就查不到了，两期之间不能留窗口。

**落地形态**：

- 新服务 `ndr/backend/app/collector/normalizer_service.py`（入口 `python -m app.collector.normalizer_service`）：复用 `ndr/backend/app/detector/queue.py:18 class ReliableQueue` 的 raw→processing→ack 模式消费 `shentong:events:collect`，逐条 `normalize(source_of(doc), doc)` 得 `UnifiedLog`，`_payload()` 只留非空字段（`raw` 永远保留），再走两条路：
  - **① 先** `LPUSH` 到 `shentong:events:raw`（检测是实时车道，不该被 ES/Logstash 的抖动拖住）；
  - **② 再** 以 NDJSON 批量 POST `http://logstash:8080/`，**2xx 才 ack**；失败则把本批**放回队尾**重试（`recover()` 只兜底进程崩溃留下的残留 —— 只在启动时跑一次，靠它重试会让 Logstash 一挂就永久躺平）。重放造成的重复由检测器 `handled` 注册表按文档哈希挡住。
- `source_of(doc)` 是新增的**归一化前来源判定**（`ndr/backend/app/ingestion/normalizer.py`）：`source_system` 优先，缺失则看顶层 `log_type` 或 `zeek` 是否为 dict → `zeek`，否则 `wazuh`。
- 坏消息（JSON 坏 / 非 dict / 归一化返回 None）**直接确认掉并记数**，否则一条坏消息会把队列卡死。
- 队列封顶 `_trim_queue()`（`ltrim` 裁掉最旧，上限 `collector_queue_max=30000`）；周期日志汇报「入库 / 待重试 / 坏消息 / 积压」。
- `ndr/backend/app/config.py` 新增采集段 9 项：`collector_collect_queue` / `collector_processing_queue` / `collector_queue_max` / `collector_consume_batch=500` / `collector_poll_timeout=5` / `collector_post_timeout_seconds=20` / `collector_post_retries=3` / `collector_retry_backoff_seconds=1.0` / `collector_stats_log_seconds=300`；`logstash_beats_port=5044` → `logstash_http_port=8080`。
- ES 索引名全链路收敛为一族：`es_events_index="shentong-events-*"`（模板渲染成 `shentong-events-%{+yyyy.MM.dd}`），删掉 `es_zeek_index` / `es_wazuh_index` 与 `es_zeek_src_fields` / `es_zeek_dst_fields` / `es_wazuh_src_fields` / `es_wazuh_dst_fields`，改为 `es_events_src_fields="src_ip"` / `es_events_dst_fields="dst_ip"`（**2026-10 QA 又删掉了这两项**：唯一读它们的 `ndr/backend/app/ingestion/es_schema.py` 整条链是死代码，网段过滤实际走 `detector/runner.py` 与 `mcp/ndr_tools.py` 的运行时逻辑）。
- `ndr/backend/app/collector/template.py` 整体重写：input 段 `beats{port 5044}` → `http{port 8080}`，**必须用 `codec => "json_lines"` + `additional_codecs => { "application/json" => "json_lines" }`**（http 输入默认「一个请求 = 一个事件」，否则一批 NDJSON 会被当成一条、json 解析失败）；`remote_host_target_field` / `request_headers_target_field` 挪进 `[@metadata]`（默认会写成 `host`、`headers` 并入库）；filter 段只把 `ts` 搬进 `@timestamp`；output 段只剩一条无条件 ES 输出。
- Logstash 开持久化队列（`ndr/logstash/config/logstash.yml` 的 `queue.type: persisted` + `path.queue` + `queue.max_bytes: 2gb`），让「Logstash 返回 200 = 已持久化」成立，normalizer 的 ack 才有意义。
- compose 两份都加了 `normalizer` 服务与 `logstash-queue` 卷、logstash 端口 `5044` → `8080`；zeek 容器 env 从 `LOGSTASH_HOST`/`LOGSTASH_PORT` 改为 `REDIS_HOST`/`REDIS_PORT`/`REDIS_DB`/`REDIS_KEY`。
- `ndr/zeek/filebeat.yml`：`output.logstash` → `output.redis`（`key: shentong:events:collect`、`data_type: list`）。
- 顺手清掉的死代码：`ndr/backend/app/ingestion/es_client.py` 的 `fetch_window_logs` / `_scroll` / `scope_clause` / `FetchResult`（水位全量重放移除后已无调用者）。
- 前端同步：`es-panel` 两个索引输入框合并成一个「索引模式」；`logstash-panel` 去掉 Redis 参数一栏、`beats` → `http`、「旁路队列」→「待归一化积压」。

**两条方案外的发现（实现时才暴露，已按此落地）**：

1. **检测器必须改吃「已归一化」文档**。原方案没说这条：既然归一化提前了，`shentong:events:raw` 里放的就是归一化文档，检测器不该再归一化一遍（白费 CPU）。`ndr/backend/app/detector/runner.py` 加了 `_to_entry()`：文档带 `source_system` + `event_type` + `raw` 三个标记 → 直接 `UnifiedLog.model_validate()`，否则回退老路 `normalize()`。**兼容改造前格式，新旧混跑不炸。**
2. **投给智能体的摘要样本里必须仍是「原始文档」**。`agent/backend/app/agents/nodes.py:197-203` 会拿样本里的 `doc` 再归一化一次（`entry = normalize(log_source, raw_doc)`），所以检测器聚合时要传 `entry.raw`（原始文档、已脱敏），**不能**传消费到的归一化文档。`_aggregate()` 的形参已从 `doc` 改名 `raw_doc` 并写明这条。

**验收**：三个容器起来后，Zeek 与 Wazuh 事件都进 `shentong-events-*` 且字段统一；停掉 Logstash 不丢数据（消息放回队列尾等下轮重试，检测器侧不重复灌）。

### 第 3 期 · MCP 服务 + 智能体切到 MCP

> ✅ **已完成（2026-02）**。原方案的「急」在于第 2 期一落地、ES 里只剩 `shentong-events-*` 一族扁平字段，而 agent 侧还在按 `zeek.id.orig_h` / `data.srcip` 旧路径查（`es_zeek_index="zeek-*"` / `es_wazuh_index="wazuh-alerts-*"`）。第 3 期已把这条缝补上：agent 侧不再有任何 ES 直连代码与配置，取数全部经 `ndr-mcp`。

- NDR 侧新增 MCP 服务（独立进程 / 容器 `ndr-mcp`）：用官方 `mcp` SDK 起 streamable HTTP 服务，Bearer 令牌校验，工具实现复用 NDR 现有的 ES 客户端与配置。
- 把 `agent/backend/app/investigation/es_query.py`(511 行) 与 `catalog.py`(450 行) 整体搬到 NDR，**按新统一字段重写路径** —— 一次改完，不留旧路径。
- 智能体侧：`agent/backend/app/investigation/tools.py` 的 `execute()` 派发层里，NDR 类工具改走 MCP 客户端；`es_query.py` 删除；ES 相关配置项删除。
- NDR 新表存 **MCP 令牌哈希**（明文只在生成时显示一次）与 **`record_conclusion` 回写记录**（按事件ID / 指纹）。
- NDR 界面新增「MCP」面板：令牌生成 / 吊销、服务状态、最近调用与错误。

**验收**：智能体不配 ES 地址也能跑完一次完整调查；NDR 界面能看到调用记录；令牌吊销后智能体立刻调不通；`record_conclusion` 写回的内容在 NDR 界面可见。

#### 服务端：✅ 已完成（2026-02，实施记录）

落地形态：

1. **`ndr/backend/app/mcp/server.py`**（入口 `python -m app.mcp.server`）：

   ```python
   MCPServer(name="shentong-ndr", title="深瞳 NDR", instructions=..., version="0.1.0")
   server.streamable_http_app(streamable_http_path=settings.mcp_path, host=settings.mcp_host)
   ```

   **共 17 个工具**（10 个 ES 查询/调查 + 7 个 NDR 自身；**第 8 期新增 `baseline_lookup` / `entity_profile` 后为 19 个 = 10 + 9**；**2026-10 MCP QA 又新增 `file_content` 后为 20 个 = 10 + 10**，见「2026-10 MCP 质量收口」小节），全部写成**显式形参的普通函数**注册 —— MCP 的 `inputSchema` 由函数签名推导，用 `**kwargs` 会被当成一个必填参数（实测报 `1 validation error for search_eventsArguments kwargs Field required`），这个坑踩过一次。工具名与参数名**逐字沿用**智能体原来的 10 个工具，提示词与调用样例不用改。

2. **ES 查询层搬进 NDR 并重写**：新增 `ndr/backend/app/investigation/{__init__,catalog,es_query,tools}.py`（1595 行）；字段目录从 50 条收敛到 **42 条**（删掉只在 `raw` 里的 `duration`/`rcode`/`answers`/`fuid`/`md5`/`sha1`、合并掉 `service`/`host`/`server_name`/`uri`/`note`/`msg`/`rule_level`/`agent_name`/`wazuh_url` 等，新增 12 条顶层统一字段）。索引选择塌成单族：

   ```python
   def index_pattern() -> str:
       return settings.es_events_index          # 原「按来源选 zeek-*/wazuh-alerts-*」整段删除
   ```

   `source_clause()` 改 `build_clause("source_system", source)`；`ts` 路径是 ES 元字段 `@timestamp`；`sha256` 路径落 `raw.sha256`。上限值原为 agent 侧配置项、NDR 没有对应物，写成模块常量（`QUERY_TIMEOUT_SECONDS=45` / `TIMELINE_MAX_HOURS=72` / `DEFAULT_LOOKBACK_DAYS=30` / `max_docs()=2000` / `RAW_EVIDENCE_MAX=20`）。

3. **NDR 自身 7 个工具**（`ndr/backend/app/mcp/ndr_tools.py`，形状与 ES 侧一致、无 `ctx`、纯函数；**第 8 期起为 9 个**，新增 `baseline_lookup` / `entity_profile`）：`get_event`（按事件ID/指纹查结论历史；NDR 侧已不记录投递指纹，只回一句指向智能体的说明）、`get_rule`、`detector_status`（队列积压 / 五段速率 / 丢弃 / 去重 / 任务失败 / 选主 / Redis 内存，口径与 `ndr/backend/app/api/routes/detector.py` 对齐）、`list_networks`、`list_filters`、`record_conclusion`（按 `dedup_key = event_id or fingerprint` upsert）、`fetch_window`（按时间窗 + 网段/IP 拉原始条目，给回溯用；返回每条 log 带 `ref = es:<索引>/<文档id>` 与**完整 `raw` 原文**）。

   八个查询工具（`search_events` / `aggregate_events` / `timeline` / `net_flows` / `dns_queries` / `tls_fingerprints` / `web_requests` / `file_hashes`）都收 `source`（`zeek|wazuh|both`，空 = 两个来源）—— 下层 `ndr/backend/app/investigation/tools.py:114 _resolve_sources()` 本来就有这个参数，补的是 MCP 包装层缺的形参（缺了会被**静默丢弃**）。包装层类型必须与下层取值函数对齐：`web_requests.status_code` 下层用 `_str_param()`（支持 `4xx` 这类关键字匹配），包装层原写 `int = 0` 会让非数字状态码在 MCP 校验层就被拒，已改 `str = ""`。

   > `raw_evidence` 的 ref 白名单校验与 `describe_data` 的「案件已知事实」**留在智能体侧**（NDR 不知道本轮调查查到过什么），所以 NDR 侧工具必须是无状态纯函数：参数进、JSON 文本出。

4. **令牌**（`ndr/backend/app/mcp/auth.py` + 新表 `mcp_tokens`）：只存 sha256 哈希 + 明文前 8 位 `prefix`；明文只在 `POST /api/mcp/tokens` 返回一次；**每次调用都查库、不缓存**，所以界面一吊销就立刻调不通（单次调查的工具调用量才几十次，多一次主键查询不值得引入缓存失效的坑）。

5. **令牌校验不用 SDK 自带那套**：`mcp.server.auth` 的 `TokenVerifier` / `AuthSettings` 是 OAuth 风格（要求 `issuer_url`），改为一个纯 ASGI `BearerAuth` 中间件包住 `streamable_http_app()` 的返回值；`/health` 与 `/healthz` 免令牌（容器健康检查要用）。

6. **调用记录**（`ndr/backend/app/mcp/calls.py`）：Redis 有界列表 `LPUSH` + `LTRIM`，**记录失败整体吞异常**（旁路不该让智能体的调查挂掉）。

7. **管理接口** `ndr/backend/app/api/routes/mcp.py`（NDR 后端第 8 组路由）：`GET /status`、`GET /tools`、`GET|POST /tokens`、`POST /tokens/{id}/state`（启用/吊销）、`DELETE /tokens/{id}`、`GET|DELETE /calls`、`GET /conclusions`（顺手清过期结论）。界面面板 `ndr/frontend/components/mcp-panel.tsx`（第 7 期拆页后挂在 `/admin/agent`「智能体对接」页）。

8. **编排**：两份 compose 都加 `ndr-mcp` 服务（`command: python -m app.mcp.server`、端口 8090、healthcheck 打 `/health` —— 镜像里没有 curl，用 `python -c` 打）。`ndr/backend/pyproject.toml` 依赖加 `mcp>=2.2,<3`。

   > **MCP SDK 2.x 与 1.x 差别很大**，写代码前先确认版本：`FastMCP` 已改名 `MCPServer`（`from mcp.server.mcpserver import MCPServer`，1.x 的 `mcp.server.fastmcp` 直接 `ModuleNotFoundError`）；客户端也换了（`from mcp.client.streamable_http import streamable_http_client`，只 yield `(read, write)` 二元组，带 Authorization 要自己建 `httpx2.AsyncClient(headers=...)` 传进去）。

9. **实测**（真起 uvicorn + 真 SDK 客户端，桩掉 ES）：无令牌 / 错令牌 → 401；`/health` 免令牌 → 200；`tools/list` → 17 个工具；工具调用回正确 JSON；`search_events` 在 ES 不可用时回**结构化降级结果**（`{"returned": 0, "by_source": {}, "notes": [...]}`）且 `isError: False` —— 模型能据此自我纠正，不会整轮失败。17 个工具的 `required` 全空、无一个含 `kwargs`；八个查询工具的 `input_schema` 都带 `source`。

#### 智能体侧：✅ 已完成（2026-02，实施记录）

1. **新增 `agent/backend/app/investigation/mcp_client.py`**：`call(name, args, *, timeout=None) -> dict`，**永不抛异常**、失败回 `{"error": ...}`（调查流程不该因取数失败整轮挂掉）；`enabled()` 看 `settings.mcp_url` 是否为空；`list_tools()` 失败回 `[]`。

   > 为什么客户端是**同步**的：调查规划器 `agent/backend/app/investigation/planner.py` 是文本 ReAct 循环（把动作名与参数写在提示词里、解析后交给 `tools.execute()` 派发），全文件没有一个 `async def` / `await`。所以实现成「常驻后台事件循环线程 + `run_in_threadpool` 式提交」：`_ensure_loop()` 开一个 daemon 线程跑 `asyncio.new_event_loop().run_forever()`，调用方 `run_coroutine_threadsafe` 取结果。连接键是 `(mcp_url, mcp_token)`，配置一变就重连。

2. **10 个 NDR 类工具改走 MCP**（`agent/backend/app/investigation/tools.py`，702 行；`MAX_ROWS = 2000`）：每次调用 `mcp_client.call("<工具名>", {...})`。`raw_evidence` 的 **ref 白名单校验留在本地**（先用自己的 `ToolCtx` 校验再调用），`describe_data` 的「案件已知事实」块也留在本地 —— NDR 侧那个工具用的是一个新建的空 `ToolCtx`，看不到案件。

3. **字段目录改为动态拉取**：`agent/backend/app/investigation/catalog.py` 重写为**纯展示目录**（42 个字段的名字/类型/说明，与 NDR 侧逐字对齐，AST 对比全等），并新增 `catalog_text(index, fields=None, *, sources=("zeek","wazuh"), max_chars=2600)`；`planner.py` 的 `_field_catalog_text()` 调 MCP `describe_data` 拿索引名与字段清单后渲染，**进程内缓存 10 分钟**（`_case_context` 每轮循环都算，而 `describe_data` 在 NDR 侧要做时间边界聚合）。索引名不再在 agent 侧硬编码。

4. **回溯改为拉 MCP 窗口**：`agent/backend/app/agents/nodes.py` 的 `lookback_node` 用 `mcp_client.call("fetch_window", {"start","end","nets","limit"})` 取代 `es_client.fetch_window_logs()`；新增 `_doc_list()` / `_to_log()` 把返回条目还原成 `UnifiedLog`（条目里已带统一字段就直接 `model_validate`，否则按 `raw` 原文再走一次 `normalize()`）。

5. **删除的 ES 直连面**（`git rm`）：`agent/backend/app/investigation/es_query.py`(511 行)、`agent/backend/app/ingestion/es_client.py`、`es_config.py`、`es_schema.py`；`agent/backend/app/config.py` 的 12 个 `es_*` 配置项整段删除；`agent/backend/pyproject.toml` 去掉 `elasticsearch` 依赖。

6. **配置**：`agent/backend/app/config.py` 加 `mcp_url`（默认 `http://ndr-mcp:8090/mcp`）/ `mcp_token` / `mcp_timeout_seconds`；两份 compose 把 `ST_ES_URL` 换成 `ST_MCP_URL` + `ST_MCP_TOKEN`（外部变量 `NDR_MCP_URL` / `NDR_MCP_TOKEN`）。

7. **方案外发现（顺手修掉）**：agent 侧还留着一份**重复的网段配置** —— `agent/backend/app/ingestion/scope.py` 的 `enabled_cidrs()` 读自己的 `AnalysisScope` 表（`agent/backend/app/db/models.py` 原 282 行，`main.py` 播种 `10.0.0.0/8` 等三段私网兜底），而这份配置**没有任何界面**，且 NDR 第 1 期已把网段唯一来源改成 `zeek.monitored_nets` —— 两份会不一致，回溯就会按错误网段筛日志。现改为 `enabled_cidrs()` 调 MCP `list_networks`（进程内缓存 60 秒；拿不到时回空列表 = **不限制**，因为 NDR 的语义是「清单为空 = 抓全部」），`AnalysisScope` 模型与播种函数一并删除。

**验收对照**：智能体不配 ES 地址也能跑完一次完整调查 ✅（配置项已不存在）；NDR 界面能看到调用记录 ✅；令牌吊销后智能体立刻调不通 ✅（每次调用查库不缓存）；`record_conclusion` 写回的内容在 NDR 界面可见 ✅。四项均以「真起服务 + 真 SDK 客户端」实测过，**未在真实 Zeek/Wazuh 流量下端到端跑过**（与第 2 期同批上线，实机验收一并做）。

### 第 4 期 · 过滤规则

> ✅ **已完成（2026-02）**。原方案的「渲染器：条件树 → Logstash 条件表达式」这一条**已作废** —— 第 2 期把归一化提到 Logstash 之前，原始日志不再经过 Logstash，于是「要不要投检测器」这个判断只能落在**归一化服务**里（`ndr/backend/app/collector/normalizer_service.py`）。红线仍是红线：**绝不用 Logstash `drop{}`**（`drop` 会终止整条事件、把 ES 那条输出一起丢，`shentong-events-*` 就不是全量了），**ES 输出永远无条件**。

- 新表 `IngestFilter`（名字 / 启用 / 优先级 / 条件树），照抄 `ndr/backend/app/ingestion/exclusion.py`(237 行) 的范式：条件树 `{"rules": [{"field","op","value"} | {"logic":"and"|"or","rules":[...]} | {"not":{...}}]}`、`validate_conditions()`（拒绝空 rules / 未知字段 / 正则错），求值复用 `app.rules.engine.evaluate_conditions`。
- 字段白名单 = 源/目的 **地址 + 端口** + **协议内容字段**（`uri_path` / `host` / `user_agent` / `body` / `command` / `query` 等），操作符含「包含」与「正则」。
- 渲染器：条件树 → Logstash 条件表达式（只作用于送检测器那条输出）。→ **作废**，改为归一化服务里的 `ingest_filter.match()`。
- UI：过滤规则页，复用 `ndr/frontend/components/condition-editor.tsx`；**带「试运行 / 干跑」**（先看会命中哪些历史事件，再启用）。
- `template.py` 三段化：① 统一字段兜底 ② 过滤条件 ③ 输出。→ **作废**（同上；`template.py` 里已无任何索引分流与过滤条件）。

#### 实施记录（2026-02）

1. **新表** `ndr/backend/app/db/models.py`：`class IngestFilter(Base)` → 表 `ingest_filters`（`id` / `name`(unique,index,128) / `description`(Text) / `conditions`(JSON) / `enabled`(默认 True) / `priority`(默认 100) / `created_at` / `updated_at`）。docstring 写明与 `ExclusionFilter` 的**作用点差异**：这张在归一化之后、规则之前，决定「要不要进检测器」；那张在规则命中之后，决定「要不要跑模型」。NDR 侧 `_MIGRATIONS = ()`，新表靠 `Base.metadata.create_all` 建。

2. **判定引擎** `ndr/backend/app/ingestion/ingest_filter.py`：

   - `ADDRESS_FIELDS = ("src_ip","dst_ip","src_port","dst_port")`；`CONTENT_FIELDS` 35 个协议/日志内容字段；`allowed_fields()` = 地址 ∪ 内容 ∪ `VIRTUAL_FIELDS`（复用 `src_internal` / `dst_internal` 这类方向虚拟字段）。**刻意不含 `raw`**，也不含 `hit_rule` / `rule_source` / `rule_severity` —— 这三个是「规则命中之后」才有的东西，在归一化时点根本不存在。
   - `load_filters(force=False)` 按 `settings.ingest_filter_cache_seconds`（默认 30s）缓存，**DB 异常沿用上次缓存**（配置读不到就按旧的判）；`invalidate_cache()` 由写接口调用。
   - `match(entry: UnifiedLog) -> str | None` 按 priority 顺序逐条求值，**任何异常都按「未命中」处理（fail-open）**：宁可多跑检测器，不能因为一条写错的正则把真实攻击静默挡下。
   - `record_hit(name, entry)` 写 Redis（`shentong:ingestfilter:stats` 计数 + `shentong:ingestfilter:samples` 每条例最多 3 条样例，TTL 30 天），供界面回答「到底挡掉了什么」。

3. **试运行（干跑）** `ingest_filter.dry_run(conditions, *, hours=0, limit=0)`：回看 `hours`（默认 `ST_INGEST_FILTER_DRY_RUN_HOURS=24`）、最多取样 `limit`（默认 `ST_INGEST_FILTER_DRY_RUN_MAX=500`，硬上限 5000）条，返回 `{source, hours, scanned, matched, ratio, samples, exclude_name, hint}`。取数顺序 **ES（`shentong-events-*`，按 `@timestamp` 范围、倒序、ref=`es:<索引>/<文档id>`）→ 检测器待处理队列 → 采集队列**，ES 不可用时只 log 后降级到队列（`source` 字段告诉界面数据来自哪层）。原始文档（只有 `source_system`/`event_type`/`raw`）会现场再跑一次 `normalize()`，所以「刚采集还没落库」的事件也能试。

4. **接线** `ndr/backend/app/collector/normalizer_service.py`：`_split()` 改为返回 `UnifiedLog`（每条只 `model_dump` 一次）；主循环建成「全量 `payloads`」与「未命中 `kept`」两份，**只把 `kept` LPUSH 进检测器队列**，而 `_post()` 依旧发**全量**（含被降噪的）→ 成功才 ack 全部。所以被降噪的事件照样进 ES、照样 ack，只是检测器看不到。`_maybe_log` 加了「降噪挡下 N 条」。

5. **接口** 新增 `ndr/backend/app/api/routes/ingest_filters.py`（NDR 后端第 9 组路由，`prefix="/api/ingest-filters"`）：`GET ""`（list，每条带 `hit_count` 与 `samples`）、`GET "/fields"`（字段分组 + 运算符 + **三条现成示例**：内网互扫 / 监控探活 UA / 心跳域名）、`GET "/stats"`、`POST "/dry-run"`、`POST ""`、`PUT "/{id}"`、`DELETE "/{id}"`；三道校验（400 空条件/未知字段/正则错、404 不存在、409 同名），写操作后 `invalidate_cache()`。挂在 `ndr/backend/app/api/router.py` 的 exclusions 之后。

6. **界面** 新增 `ndr/frontend/components/ingest-filters-panel.tsx`，与排除过滤面板同挂在 `/admin/filters`「过滤规则」页（第 7 期拆页前是 `ndr/frontend/app/admin/settings/page.tsx` 里 MCP 面板与排除过滤面板之间），复用 `condition-editor.tsx`；面板带**「试运行（不保存）」**按钮 + 回看小时/取样条数输入，结果区显示取数来源、扫描/命中条数与比例、命中样例（含事件 ref），以及三条示例的一键套用；列表显示每条例「已挡下」计数与最近命中的样例。`ndr/frontend/lib/api.ts` 补 `IngestFilterItem` / `IngestFilterSample` / `IngestFilterFields` / `IngestFilterDryRunResult` 等类型。

7. **顺手扩了 MCP `list_filters`**：原来只回排除过滤，现在回 `{"filters": 排除, "ingest_filters": 降噪, "hint": ...}`，hint 明确「两道闸门都会导致没有告警，别把被过滤当成没有异常」。智能体侧从未调用过该工具，改形状安全。

8. **实测**（`/tmp/test_ingest_filter.py`，24 项全过）：校验四类拒绝逐条覆盖；`match()` 命中/不命中/**求值抛异常时回 None（fail-open）**；`dry_run()` 含原始文档的混合取样、非法条件回 error、无数据回提示；`normalizer_service.run()` 用 FakeRedis + FakeQueue + FakeHttp 整轮跑，断言「**检测器队列只剩未命中的那条**」「**ES 收到 2 行、含被挡下的那条**」「两条都 ack」「命中计数 1 / 样例 1」「重试列表为空」。

**验收对照**：加「忽略 10.0.0.5:445」→ 试运行先看到命中量与样例 ✅（`POST /api/ingest-filters/dry-run`）；该流量不再进检测器 ✅（主循环只 LPUSH `kept`）；**ES 里仍有** ✅（`_post` 发全量，测试断言 2 行含被挡下的）。均为单进程内实测，**未在真实 Zeek/Wazuh 流量下端到端跑过**（与第 2、3 期同批实机验收）。

### 第 5 期 · HTTP 推送智能体 ✅ 已完成（2026-02，实施记录）

- **agent 侧接收端点**：`agent/backend/app/api/routes/push.py` —— `GET /api/push/ping`（连通性自检）、`POST /api/push/digests`；Bearer 令牌常数时间比较（未配 `ST_PUSH_TOKEN` → 503，令牌不符 → 401，超 `push_max_items` → 413）；逐条按「查库 → Redis 占位」判重（见第 5 节），新摘要用 `celery_app.send_task("analysis.analyze_digests", args=[accepted])` 投递（API 进程不必 import 整个任务模块）。指纹下沉：`agent/backend/app/digest.py` 新增 `group_fingerprint` / `time_bucket` / `bucket_minutes` / `digest_ips`，`agents/nodes.py:_group_fingerprint` 改为转发。
- **NDR 侧推送与重发**：`ndr/backend/app/detector/push.py`（配置读写 / 分片 / 2xx 判定 / 统计 / `deliver` 四态 off·pushed·queued·lost / 重试队列与尝试上限 `_RETRY_QUEUE_MAX=2000`·`_RETRY_MAX_ATTEMPTS=5` / `retry_pending`）、`ndr/backend/app/detector/fingerprint.py`（`digest_age` + `digest_fingerprint` 从原闸门搬出）；`runner._flush()` 交接是「优先 HTTP 推 → 没配地址/被关掉时不再写已退役的 `shentong:events:dispatch`（全仓无消费者），改为记 `undelivered` 计数（`dropped.undelivered` + `/api/agent-push` 的 `undelivered`）后 ack，绝不静默丢也绝不计成 delivered」，推送失败但重试队列也写不进去（Redis 挂了）时摘要放回检测队列；主循环每轮调 `push.retry_pending()`。
- **配置接口与界面**：`ndr/backend/app/api/routes/agent_push.py`（`GET`/`PUT /api/agent-push`、`POST /test`、`POST /retry`；令牌只回显打码，`token=None` 表示不改动）；`ndr/frontend/components/agent-push-panel.tsx`（第 7 期拆页后挂在 `/admin/agent`「智能体对接」页）（地址 / 令牌 / 超时 / 单次条数 / 开关 + 已送达·失败待重发·重发成功·重发失败·待重发批数 + 测试连接 / 立即重发）。配置存 `ndr/backend/app/db/models.py:SystemConfig`（键 `agent_push.params`），环境变量只作默认值。
- **退役**：删 `agent/backend/app/consumer.py`、`agent/backend/app/workers/tasks.py:_notify_done()`、NDR `detector/analyzed.py`、`AnalyzedFingerprint` 模型、两侧 `analyzed_done_queue` 配置、agent 两份 compose 的 `consumer` 服务；`/api/detector/stats` 与 MCP `detector_status` 的 `dedup` 字段改为「判重已下放到智能体」+ 退役前历史计数，前端同步。
- **配置项**：NDR `ST_AGENT_PUSH_URL` / `ST_AGENT_PUSH_TOKEN` / `ST_AGENT_PUSH_ENABLED` / `ST_AGENT_PUSH_TIMEOUT_SECONDS` / `ST_AGENT_PUSH_MAX_PER_PUSH` / `ST_DETECTOR_PUSH_RETRY_QUEUE` / `ST_DETECTOR_PUSH_PROCESSING_QUEUE` / `ST_DETECTOR_PUSH_RETRY_MAX_PER_ROUND` / `ST_DETECTOR_PUSH_STATS_KEY`；agent `ST_PUSH_TOKEN` / `ST_PUSH_DEDUP_KEY` / `ST_PUSH_MAX_ITEMS`。**两侧令牌必须一致**，compose 分别从 `NDR_AGENT_PUSH_TOKEN` / `PUSH_TOKEN` 取。
- **实测**：`/tmp/test_push_api.py` 30 项（鉴权 / 首次 / 重复 / 占位冲突 / 无 IP / 413 / 422 / 指纹与图一致）；`/tmp/test_agent_push.py` 51 项（`deliver` 四态与分片 / 重发队列回灌与失败停止 / 配置合并与 `_to_bool`（"no"/"false"/"0"/"off" 认成假）/ 路由 GET·PUT·test·retry）；`/tmp/test_runner_push.py` 15 项（`_flush` 四态交接、超龄丢弃先于推送、旧队列写不进则回队）。写库测试用 FakeSession / FakeRedis / `dependency_overrides`，**未连真 PG / 真 Redis**。

**验收对照**：agent 挂掉 → 摘要落 `shentong:events:pushretry`、恢复后由检测循环补齐 ✅（测试覆盖 queued → retry_pending 全成功，见 `tests/py/test_detector_push.py:235`）；地址配错 → 界面「失败待重发 / 最近失败」有计数与原因 ✅（「失败待重发」= `retry_backlog_batches`；另有 `retry_lost`/`retry_dropped`/`undelivered` 三个「再也不会重发」的可见计数）；**没配地址（`deliver` 返回 `off`）→ 摘要记 `undelivered` 后 ack，不再伪装成已投递** ✅（`tests/py/test_detector_runner.py:56`）；重复推送同一指纹 → 只累加 `event_count`、不投任务、不出第二份报告 ✅。

### 第 6 期 · Wazuh 4.14 集成与容量 ✅ 已完成（2026-02，实施记录）

- **告警与原始日志分流**（`ndr/backend/app/ingestion/normalizer.py` 与 agent 侧同名文件**同步**改）：`normalize_wazuh` 用 `is_archive = not rule` 区分 —— `alerts.json` 每条都带 `rule`，`archives.json`（`logall_json` 的全量原始日志）没有。告警 → `log_type="wazuh"` + 事件类型（`_wazuh_event_type`）；原始日志 → `log_type="wazuh_archive"` + `event_type="wazuh_log"`（不套告警事件类型，规则不会误命中；`ndr/backend/app/rules/builtin.py:1045` 那条 `log_type == "wazuh"` 的规则天然不会跑），`summary` 取 `full_log` 单行化后 200 字。理由：archives 量级远大于告警，混在一起会让告警规则被全量日志触发。
- **原始日志默认只入库、不喂检测器**：`ST_WAZUH_ARCHIVE_TO_DETECTOR`（默认 false）；`ndr/backend/app/collector/normalizer_service.py` 分流处 `elif entry.log_type == "wazuh_archive" and not settings.wazuh_archive_to_detector: stats["archive_es_only"] += 1`，统计行加「原始日志只入库 %d」。红线「ES 落全量」不受影响（Logstash 那条线照旧）。
- **容器侧（opt-in 叠加编排）**：`ndr/docker-compose.wazuh.yml` 加 `wazuh-manager`（官方 `wazuh/wazuh-manager:4.14.8`，不含 indexer/dashboard，暴露 55000 与可选 1514/1515，8 个命名卷）与**独立的** `wazuh-filebeat`（官方 beats 8.15.3，`user: root` + `-strict.perms=false`，只读挂载 `wazuh-logs`，命令指向 `ndr/wazuh/filebeat.yml`）。**为什么另起一个 Filebeat**：manager 自带那个是为「发往 Wazuh indexer」预设的，其 `output.redis` 支持在 4.14 未经实机验证（开放问题 6）——另起一个用我们自己的配置，与 Zeek 线行为一致；Filebeat 只支持单一 output，这也顺带绕开了「Zeek 与 Wazuh 各发各的」这个纠结点。`docker compose -f docker-compose.yml -f docker-compose.wazuh.yml config -q` 与 deploy 版组合**均校验通过**。
- **`ndr/wazuh/filebeat.yml`**：两个 filestream（`alerts.json` 常开 / `archives.json` 由 `WAZUH_ARCHIVES_ENABLED` 控制），都 `ndjson: {overwrite_keys: true, add_error_key: true}` 且**不设 target**（`normalize_wazuh` 从根读 `rule`/`data`/`agent`/`full_log`；`overwrite_keys` 防 Filebeat 的 ECS 顶层 `agent` 盖掉 Wazuh 的 `agent.name`，否则主机名丢失），`fields: {source_system: wazuh}` + `fields_under_root`，`output.redis` 指向 `${REDIS_KEY:shentong:events:collect}`。
- **`ndr/wazuh/enable-logall.sh`**：幂等开 `archives.json` —— `cp -a` 备份后**就地改值**（`sed` 把 `<logall>no</logall>` / `<logall_json>no</logall_json>` 改 `yes`），只有这两个键在目标小版本里缺失时才 awk 在**第一个** `<global>` 之后插入；**不整体替换 `ossec.conf`**（4.14.x 小版本默认配置有差异，写错 manager 起不来）。写完自检「每个键恰好 1 处 `yes`、0 处 `no`」，不通过就 `cp -a` 回滚原文件并报错退出。（原实现是无条件追加，实测会在同一文件里留下 `yes`/`no` 两组矛盾键，见 `ndr/wazuh/README.md` 第五节「踩到的坑」4。）
- **Wazuh API 管理面**：`ndr/backend/app/api/routes/wazuh.py` + 路由注册 + `ndr/frontend/components/wazuh-panel.tsx`（第 7 期拆页后挂在 `/admin/collect`「采集接入」页）。**连接信息只有一个来源**：部署环境变量 `ST_WAZUH_API_URL` / `ST_WAZUH_API_USER` / `ST_WAZUH_API_PASSWORD` / `ST_WAZUH_API_VERIFY_TLS`（部署时由 `.env` 的 `WAZUH_API_*` 传入，与 manager 自己用的是同一组值），`_cfg()` 只读环境变量；第 6 期原本让凭据存 `SystemConfig` 键 `wazuh.params`、界面保存的值优先，实机部署后**取消**（遗留的该行不再被读取，`PUT ""` 与 `POST /test` 一并删除、密码不再打码回显）——理由：Wazuh 随项目部署，同一事实留两份来源就会出现「界面写了一个地址、实际连的是另一个」而看不出来，且部署完还要人工再填一遍。Basic → JWT（`POST /security/user/authenticate`，token 按 `(url, user)` 进程内缓存，按 `expires_at` 提前 60 秒失效）；端点 `GET ""`（状态 + Agent 清单 + 入库量，只读）、`GET /status`、`GET /agents`（汇总 + 列表）、`GET /rules`（标出 `etc/rules` 下的本地自定义文件）、`POST /rules`（**`PUT /rules/files/<name>?overwrite=true`** 下发 → `GET /rules?filename=…` **轮询**取生效条数 + `GET /rules/files/…?raw=true` 回读**原文**比对，两者都对才算 `verified`；文件名白名单 `^[A-Za-z0-9_.-]{1,64}\.xml$` 挡目录穿越）。接入状态**同时**看 API 与 ES 入库量：面板的「近 24h 入库 告警 N / 原始日志 N」查 `source_system=wazuh` 并按 `log_type` 分桶（走 `catalog.agg_path()` 拿到 `.keyword`，否则 text 主字段聚合会 400）—— 这是链路真通了的证据，不只是「API 通」。
- **容量评估（本机实测 + 纸面推算，2026-02）**：本机跑 `normalize("wazuh", doc)` + `_payload` 实测（CPython 3.11，单核）：**告警 94 µs/条（≈1.06 万条/秒）、原始日志 63 µs/条（≈1.6 万条/秒）**；单条线上载荷 **1.36 KB / 1.17 KB**（含 `raw` 整份原始文档）。据此：
  - **ES 日增量** ≈ 单条载荷 × 日条数（单副本）：10 万条告警/天 ≈ **0.13 GB/天（3.9 GB/月）**；100 万条原始日志/天 ≈ **1.11 GB/天（33 GB/月）**。原始日志是容量主项 —— **先按现场日志量估算，再决定是否开 `logall_json`**。
  - **normalizer 吞吐**：单进程 1 万条/秒以上，高于同机 ES/Logstash 的写入能力 —— 瓶颈在 ES，不在归一化。
  - **Redis**：collect 队列上限 `collector_queue_max=30000`，满载约 **40 MB（告警）/ 34 MB（原始日志）**；历史上出过 noeviction 卡死事故，故内存仍要留余量并按 `maxmemory` 观察。
  - **磁盘**：manager 侧的 `archives.json` 由 Wazuh 自己滚动、**不设保留期**，长期开 `logall_json` 要配合宿主/卷的清理策略。
  - **检测器与推送不受原始日志影响**（默认不喂检测器），仍按告警量计。

**验收**：Wazuh 告警与（可选的）全量日志都进 ES、可查、状态页可见；容量数字落在可接受区间。实施取证：`/tmp/test_wazuh.py` **65/65**（凭据脱敏与 `None`/`""` 语义、JWT 缓存与 401 提示、agents 汇总、规则下发回读校验与文件名穿越拦截、ES 按 `log_type` 分桶与读失败回显）、两侧 ruff/pyright 0 error、`ndr/frontend` `npx tsc --noEmit` 通过、两份 compose 组合 `config -q` 通过、`normalize` 分流与载荷大小本机实测如上。

**实机复验（2026-10-03，`172.16.196.77`，manager 4.14.8）**：六条待验项全部通过，逐条结论与证据见 `ndr/wazuh/README.md` 第五节。过程中修掉 5 个真 bug，其中 3 个会让「接入成功」站不住：**ES 索引模板没有 mappings** ⇒ `raw.id` 被动态映射定成 object 后，Wazuh 告警与 Zeek `ocsp` 的字符串形态文档被 ES **静默 400 丢弃**（`log_type.keyword=wazuh` 恒 0，而 Filebeat/Redis/归一化三段都正常；修法 `{"properties":{"raw":{"type":"object","enabled":false}}}`，两个老索引按「拷贝→删旧→重建→回灌」迁移，`failures: 0`）；面板 `_ingest_stats()` 用 text 主字段聚合 ⇒ 恒报「读 ES 失败」；规则下发 `PUT /rules/files/<name>` **默认不覆盖**同名文件、失败态回在 HTTP 200 的 body 里 ⇒ 规则一条都没更新却报「已上传」。另外两处：`?raw=true` 回读被按 JSON 解析、生效条数会瞬时读到 0（轮询修）；Wazuh `syscollector`/FIM 原始日志的 `process` 是对象 ⇒ 被 pydantic 打成 373 条死信（`_text_or_none()` 修，**两侧 normalizer 同步**，373 条原文回灌全部成功）。提交：`4655bd2`/`12eab73`（映射与面板）、`646b779`（规则下发校验）、`f3f91ef`（死信）、`ca35c42`（`enable-logall.sh`）、`e598764`（`overwrite` + body 级失败判定）。现场容量实测：3 台 agent 约 2000 条告警/1.5 h ≈ **3.2 万条/天**、原文 3.7 MB/1.5 h ≈ **59 MB/天**；archives 侧只在 12 分钟验证窗口里量到 824 KB，**开口前必须按现场真实原始日志量复核**。

### 第 7 期 · 界面整理 ✅ 已完成（2026-02，实施记录）

原来八个面板全挤在 `ndr/frontend/app/admin/settings/page.tsx` 一页里（Zeek / Wazuh / ES / Logstash / MCP / 智能体推送 / 降噪 / 排除），随 Wazuh 与推送接入后页面已经过长。现按「配置的是哪一段链路」拆成六个子页，`/admin/settings` 保留为**配置总览索引**（旧链接不失效）：

1. **`ndr/frontend/components/page-shell.tsx`（新增）**：统一页面骨架 `PageShell({title, desc, children})` = 左侧 `Nav` + `ml-56` 主区 + 标题/说明 + `space-y-4` 内容栈，新页不再各写一遍布局。
2. **六个新页面**（均在 `ndr/frontend/app/admin/` 下，套 `PageShell`）：
   - `collect/page.tsx`「采集接入」= `<ZeekPanel section="iface"/>`（监听网卡）+ `<WazuhPanel/>`（API 凭据、下发规则、入库量）
   - `networks/page.tsx`「监控网段」= `<ZeekPanel section="networks"/>`（抓包范围 + 附加 BPF）
   - `storage/page.tsx`「数据存储」= `<EsPanel/>` + `<LogstashPanel/>`
   - `filters/page.tsx`「过滤规则」= `<IngestFiltersPanel/>` + `<ExclusionsPanel/>`
   - `agent/page.tsx`「智能体对接」= `<McpPanel/>` + `<AgentPushPanel/>`
   - `status/page.tsx`「运行状态」= `<StatusPanel/>`（新增，见下）
3. **`ndr/frontend/components/zeek-panel.tsx` 按 section 复用**：签名改为 `ZeekPanel({ section = "all" }: { section?: "all" | "iface" | "networks" })`，标题/说明/可见块随 section 切；`save()` 仍一次性 PUT `{interface, networks, bpf_extra}`，**没显示的那部分原样回传**，因此「采集接入」与「监控网段」两页互不覆盖。旧的 `section="all"` 形态保留。
4. **`ndr/frontend/components/status-panel.tsx`（新增，运行状态页主体）**：只读既有接口、不新增后端 —— `/api/detector/stats`（队列深度 / 投递速率 / 丢弃 / 选主 / Redis 体检）、`/api/agent-push`（送达与重发）、`/api/wazuh`（API 可达性 + 近 24h 入库量）。四个块 + **每 15 秒自刷新**（可关）；Redis 用量超过告警线时显式标红「内存接近上限，整链路会卡死」—— 历史上出过 noeviction 卡死事故，这是最该被看见的前兆。
5. **`ndr/frontend/components/nav.tsx` 七项导航**：检测规则 / 采集接入 / 监控网段 / 数据存储 / 过滤规则 / 智能体对接 / 运行状态；~~**配置总览（`/admin/settings`）挂在全局页头的 logo 上**（可点，带齿轮图标），不占导航行~~ → **该页与入口已取消，见「2026-10 界面口径」小节的后续说明**。
6. **顺手修掉两处死跳转**：`ndr/frontend/app/setup/page.tsx`（首次向导保存后）与 `ndr/frontend/app/login/page.tsx`（登录后）原本都 `router.replace("/dashboard")`，而本前端没有 `/dashboard`（首页 `app/page.tsx` 即 `/`，它再 redirect 到 `/admin/rules`）→ 都改为 `"/"`。原先这两处会跳到 404。
7. **第 6 期那条说明在拆页后保留**：`networks/page.tsx` 的页面说明里写明「这份清单只约束 Zeek 抓包，不影响 Wazuh 采到的主机日志」，`wazuh.py` 的 `HINT` 里也有一句同样的话。

**验收**：六个子页可直达、旧 `/admin/settings` 仍是有效入口、导航七项高亮正确、首次向导与登录不再跳 404。实施取证：`ndr/frontend` `npx tsc --noEmit` 通过（`agent/frontend` 未改动，另行复跑）；后端本轮无改动，收尾仍复跑 ruff/pyright。**未取证**：浏览器里的实际渲染与交互（未起前端 dev server，按 AGENTS.md 也不本地 build）。

### 第 8 期 · 基线分析迁到 NDR ✅ 已完成（2026-02，实施记录）

用户判断「基线应该放在数据产生的 NDR 侧」——数值 2σ 与 UEBA 账号/会话画像都是纯统计，智能体本来只是拿它喂提示词。本期把两者整体搬到检测器里（同进程、无新服务），智能体侧只保留「提取标签 → 合并到事件组 → 渲染进提示词 → 交给模型定性」。

1. **两张新表**（`ndr/backend/app/db/models.py`）：`baseline_stats`（`key` 主键 / `count` / `mean` / `m2` / `first_seen` / `updated_at`）与 `entity_profiles`（`id` / `kind` / `entity_key` / `entity_display` / `obs_count` / `first_seen` / `last_seen` / `src_ips` / `user_agents` / `paths` / `hour_hist` / `success_count` / `fail_count` / `risk_score` / `anomalies` / `updated_at`，带 `(kind, entity_key)` 唯一索引与 `risk_score` / `last_seen` 索引）。字段与智能体侧两表逐字段同构；NDR 靠 `create_all` 建表（`_MIGRATIONS` 为空），**不需要迁移**。
2. **新包 `ndr/backend/app/baseline/`**（4 文件）：
   - `stats.py`：Welford 在线均值/方差。`_std`（`m2/(count-1)` 开方，与智能体侧一致）、`_warmed`（`first_seen` 满 `baseline_observe_days` 才算过了观测期）、`load_stats`（批量读，`_BATCH=500` 分批）、`apply_stats`（批量增量落库，单写者不需锁）、`lookup(ip, key, limit)`（按 IP 查该 IP 全部维度或按完整 key）、`snapshot()`（运行状态页用的规模/观测期进度）。
   - `profile.py`：从 `agent/backend/app/agents/profile.py` 逐函数移植。`session_entity` 把会话 cookie 取值后 **sha256 哈希**（落库键是哈希，展示用前 8 位），`account_entity` 取 `account` 再退 `user`；`observe_entry(buckets, entry)` 是新增的**无 I/O 逐条并入**（账号 + 会话各一个桶），`_trim` 在窗口内就把超限分布裁到 top N（落库列名 `hour_hist` 对应桶字段 `hours`，用 `_BUCKET_FIELDS` 映射）；`detect` 的加权与原实现一致（新源 IP +0.35 / 新 UA +0.2 / 非常用时段 +0.15 / 会话跨 ≥2 IP +0.45 / 失败≥5 且多于成功 +0.25，封顶 1.0，冷启动不判）；`recall_from_observations` 返回 `{entities, anomalies}`（后者才是过 `profile_risk_threshold` 的）；另有 `update_profiles` / `cleanup` / `list_profiles` / `top_anomalies`。**没有移植 `profile_text`** —— 渲染在智能体侧（`baseline_labels.text_of`）。
   - `engine.py`：`BaselineEngine(client)`，检测器进程内单实例（只有持锁实例消费队列，累加天然一致）。逐条 `observe(entry)` 并桶观测；摘要产出时 `annotate(digest)` 算三个数值特征（`conn_count` = 摘要 `count`、`distinct_dst_ports` = `len(dst_ports)`、`distinct_dst_ips` = `len(dst_ips)`，key = `f"{src_ip}:{feature}"`，与智能体侧 `_stat_features` 语义一致）→ 超过 `mean + baseline_zscore*std` 才算偏离，同时把值排进待落库队列；画像异常按 **IP 交集**归属到摘要（`src_ip ∪ dst_ips`，与智能体侧原来的归属方式一致），最多挂 6 条。周期 `maybe_flush()` → `flush()` = 数值落库 + 画像观测落库并判异常 + 按 `baseline_cleanup_seconds` 清理过期画像 + `_publish()` 把计数写进 `shentong:baseline:stats`（24h 过期，运行状态页据此判断基线在不在跑）。标签形状：`{"checked": 3, "warmed": N, "numeric": [...], "profiles": [...]}`，**`warmed` 为 0 表示基线还在观测期，「没报偏离 ≠ 正常」**。
3. **接线 `ndr/backend/app/detector/runner.py`**：`engine = BaselineEngine(client)`；`_handle(...)` 在「网段过滤 + 排除过滤」之后、规则之前调 `engine.observe(entry)`（④，放在规则之前是因为画像是长期行为基线，不该只学命中规则的那部分日志）；主循环 `agg.pop_due()` 后 **被排除的摘要不打标**，其余的 `digest["baseline"] = engine.annotate(digest)` 再进投递队列；循环末尾 `engine.maybe_flush()`。
4. **配置 13 项**（`ndr/backend/app/config.py`）：`baseline_enabled` / `baseline_observe_days=7` / `baseline_zscore=2.0` / `baseline_flush_seconds=60` / `baseline_cleanup_seconds=3600` / `baseline_max_observations=50000` / `baseline_cache_max=20000` / `baseline_stats_key` / `profile_enabled` / `profile_min_obs=5` / `profile_risk_threshold=0.6` / `profile_retention_days=180` / `session_cookie_names`。
5. **MCP 两个新工具**（`ndr/backend/app/mcp/ndr_tools.py` + `server.py`，`TOOLS` 由 7 条增至 **9** 条）：`baseline_lookup(ip, key, limit)` 查某 IP / 某维度的长期均值与标准差（附「观测期内不参与判定、没报偏离不等于正常」的说明）、`entity_profile(kind, keys, min_risk, anomalies_only, limit)` 查账号/会话画像与过阈值异常（附阈值与加权说明）。`server.py` 用显式形参包装（MCP 的 inputSchema 由签名推导，`**kwargs` 会被当成一个必填参数）。
6. **API**（新增 `ndr/backend/app/api/routes/baseline.py`，已注册进 `ndr/backend/app/api/router.py`）：`GET /api/baseline`（总览：开关 / 观测期 / zσ / 阈值 / 规模 / 过阈值 TOP / Redis 心跳，`_detector_counters()` 读不到心跳则 `{"alive": False}`）、`GET /api/baseline/profiles`、`GET /api/baseline/stats`。
7. **界面**（并入第 7 期的「运行状态」页，不新增导航项）：`ndr/frontend/components/status-panel.tsx` 新增「基线观测」块 —— 基线开关、还在观测期的维度数、检测器心跳时间、四格（已学维度 / 过了观测期 / 在册画像 / 过阈值异常）与过阈值 TOP5；`ndr/frontend/lib/api.ts` 补 7 个 `Baseline*` 类型。
8. **智能体侧下线与改接**（净删 912 行 / 增 432 行）：
   - 新增 `agent/backend/app/agents/baseline_labels.py`：`labels_of`（取摘要标签）、`merge_labels`（按维度/实体去重、`checked`/`warmed` 取最大、按 `|z|` 与 `risk` 降序，整批为空则返回 `{}` 以便不塞空字段）、`candidates_of`（数值偏离 → 「异常确认」候选，键名与旧 `_stat_features` 一致、提示词无需改）、`entities_of`、`text_of`（渲染成提示词文本块，原来 `profile_text` 的位置）。
   - `agent/backend/app/agents/metrics.py`：`merge_aggregates` 原来把结果**固定成 6 个键**，未知键会被丢掉 —— 现在显式合并 `baseline`（否则标签到不了组级）。
   - `nodes.py`：`_digest_aggregate` 带上 `labels_of(digest)`；`_profile_text_for_group` 改读所在组的标签；`profile_recall_node` 重写为「收集 NDR 标签 → 按组归档 + `update_group_profile_hits`」；**删掉 `profile_update_node`（节点 9）**，`graph.py` 的边改成 `memory_write → END`。
   - `deep_analysis.py`：删 `_stat_features` / `_detect_candidates` / Welford 读写，`anomaly_node` 改读标签里的候选（**模型确认仍保留**，NDR 只打标）；`persistence.py` 删 `update_baseline` / `get_baseline`；`db/models.py` 删两张表；`main.py` 删 `baseline_stats` 的 ALTER；`config.py` 删 6 项。
   - 删文件：`agent/backend/app/agents/profile.py`、`agent/backend/app/api/routes/profiles.py`、`agent/frontend/app/admin/profiles/page.tsx`；导航项 / 设置项 / `dashboard` 的画像卡片（改为一句「基线已在 NDR 侧计算，排行见 NDR 运行状态页」）一并下线。
   - `investigation/tools.py` 的 `entity_profile` 工具**改为转发 NDR 的 MCP 工具**（智能体仍能按需追问画像），`pg_query.entity_profiles` 删除。
   - **一条重要事实**：智能体侧原来的 UEBA 观测在实时链路里**本来就是死路径** —— `profile_recall_node` / `profile_update_node` 读的 `raw_logs` 全仓没有任何地方赋值（旧 ingest 节点已随兜底入口下线），所以 `profile_text` 恒返回「无画像异常」。这次下架不改变现网行为，是把已经停摆的代码搬走。
9. **验收**：NDR 摘要带上基线标签、检测器不再依赖模型就能沉淀长期基线、智能体提示词里仍有画像与数值偏离文本、运行状态页能看到基线与异常 TOP、智能体「追问画像」走 MCP。
   **实施取证**：`/tmp/test_baseline.py` **112/112**（Welford 增量与观测期、分布裁剪、画像冷启动与各项加权、标签合并去重与渲染、engine 打标 / IP 归属 / 异常去重过期 / flush 发布 Redis）；回归脚本全过（`/tmp/test_wazuh.py` 65/65、`/tmp/test_wazuh_normalize.py` 22/22、`/tmp/test_agent_push.py` 51/51、`/tmp/test_runner_push.py` 15/15、`/tmp/test_push_api.py` 30/30、`/tmp/test_ingest_filter.py` 24/24）；`.venv/bin/ruff check ndr/backend/app agent/backend/app` 全过、`.venv/bin/pyright ndr/backend/app agent/backend/app` 0 error、`python -m compileall -q` 通过、`ndr/frontend` 与 `agent/frontend` 各 `npx tsc --noEmit` 通过。测试还抓出一个移植 bug：`_trim` 按 `_LIMITS` 的落库列名去取观测桶字段（`hour_hist` vs `hours`）会 KeyError，已用 `_BUCKET_FIELDS` 映射修掉。
   **未取证**：真实流量下基线的收敛速度与画像误报率（默认 7 天观测期，需现场跑够时间）；检测器主备切换时进程内缓存会重建（数值基线从库里重捞、画像异常有一段标签稀疏 —— 不丢数据，但切换瞬间的摘要可能少标签）。

### 第 9 期 · 采集面改造批 1：类型识别 / 流分类 / Filebeat 加固 ✅ 已完成（2026-10-02，实施记录）

**起因**：归一化层拿不到 Zeek 流的真实类型时会**兜底成 `conn`**（`_ZEEK_TYPE_HINTS` 猜不出就 `return "conn"`），于是 `x509`/`ntp`/`weird`/`packet_filter`/`reporter` 这些运维流以「conn + generic」混进事件索引，还可能进检测；同时 Filebeat 的输出队列只有内存（`queue.mem` 默认 3200 条），Redis 一停就丢事件。批 1 只改「类型与去向」，不碰采集内容。逐条决定与后续批次见 `docs/ndr-collect-plan.md`。

1. **新增 `ndr/backend/app/ingestion/log_types.py`，逐字节复制到 `agent/backend/app/ingestion/log_types.py`**（`diff` 确认一致）：三类去向 `EVENT` / `OPS` / `UNKNOWN`；`canonical_log_type(name)` 去掉目录前缀、`.log` 后缀与 `.<YYYY-MM-DD>` / `.<YY-MM-DD>` 日期后缀；`event_log_types()` / `ops_log_types()` / `known_log_types()` / `is_known()` / `classify()`；`classify_entry(entry)` **非 zeek 来源一律 EVENT**（闸门不能误伤 Wazuh 线）；`is_detectable(entry)`。类型判定全仓只有这一个入口。
2. **两侧 `config.py`** 新增两个键：`zeek_event_log_types = "conn,dns,http,ssl,files,dhcp,x509,weird,notice,smtp,ssh"`、`zeek_ops_log_types = "ntp,packet_filter,reporter,stats,ja4ssh,ja4d"`（加减类型只改配置）。
3. **两侧 `schemas.py`**：`UnifiedLog` 新增 `log_type_known: bool = True` 与 `source_file: str = ""`；`cookie` / `auth_scheme` 的注释改为与现实一致（请求头值按既定口径原样保留；`auth_scheme` 只留方案名）。
4. **两侧 `normalizer.py`**：类型判定改为 `_zeek_log_type(doc, outer) -> (log_type, known)` —— **信封 `log_type` 优先** → 猜（`_ZEEK_TYPE_HINTS` 扩到 17 条，专用流排在共用字段流之前，`any()` 撞一个字段即定案）→ 都不中记 `unknown` 并**保留原名**（不再兜底 `conn`）；新增 `_source_file(outer)`（取 Filebeat 的 `log.file.path` 末段）与 `_raw_with_type(...)`，持久化的 `raw` 里带上 `log_type` / `source_file`，让原文自解释、ES 能按流统计（此前 `raw.log_type` 恒不存在）。两侧改完只差 NDR 独有的 `_SOURCES` / `source_of()` 与 docstring。
5. **两道类型闸门**：归一化服务（`ndr/backend/app/collector/normalizer_service.py`）在 Wazuh 归档分支之后加 `elif not log_types.is_detectable(entry)` → 只入库并计 `ops_es_only` / `unknown_es_only`；检测器（`ndr/backend/app/detector/runner.py`）在 `_to_entry` 之后、网段过滤之前再兜一道（队列里可能还压着升级前的旧文档或人工重放数据），计 `ops_skipped` / `unknown_skipped`。两侧周期统计日志都加出这两个计数，否则实机看不见闸门在工作。
6. **`ndr/zeek/filebeat.yml` 加固**：① 纠正「轮转后进日期子目录」的错误注释（实机是**同目录平铺改名**；轮转名后来定为带时分秒的 `conn.2026-10-01-08-00-00.log`，见下文「同日轮转覆盖」修复）；② 非事件文件排除名单（stderr/stdout/loaded_scripts/debug/prof/telemetry/threading/capture_loss）；③ 文件名 → 类型从 JS 的 `split(".")[0]` 变成显式剥 `.log` 与日期后缀（**先剥完整时间戳、再剥只到天**，否则带时分秒的轮转件会被认出第二个类型），并**删掉 `drop_event`**（认不出的文件名也照发，由归一化层标 `log_type_known=false` 保留原名 —— 否则新流会静默消失）；④ `queue.disk` 落盘缓冲（1GB、段 128MiB、`write_ahead` 2048），spool 与注册表同在命名卷 `zeek-filebeat` 上，Redis 不可用或容器重建都不丢。**实测坑**：本镜像的 Filebeat 8.15.3 是 OSS 构建，`queue.spool` 直接报 `unrecognized queue type 'spool'`，只有 `queue.disk` 可用 —— 见 `docs/ndr-collect-plan.md` 决定表。
7. **`tests/` 落地并进 CI**（此前「没有 `tests/` 目录」，验证全靠 `/tmp/*.py`）：`tests/py/`（`conftest.py` 带 `--stack=ndr|agent`、`samples.py` 23 个流样本、`test_log_types.py` 判定矩阵、`test_normalizer_fields.py`、`test_xff_respbody.py`（由 `/tmp/test_xff_respbody.py` 搬入）、`test_stack_consistency.py` 子进程逐字段比对两侧、`test_filebeat_yml.py`）+ `tests/zeek/hb_test.zeek` 与 `run.sh`（容器内 Zeek 单测）+ `tests/README.md`。`.github/workflows/ci.yml` 由 1 个作业变 3 个：`build`（原样）、`test`（ruff + pyright + 两侧 pytest + Zeek 容器单测，依赖**从两侧 `pyproject.toml` 现读**）、`web`（两侧 `tsc --noEmit`）。

**验收（四步，全部实机取证）**

- **① 容器内 Zeek 单测**：`sh tests/zeek/run.sh` → 9 条 PASS、`FAILS=0`（请求/响应截断、GET 无请求体但有响应体、NUL 双向拦、UTF-8 双向放行）。
- **② 本地两侧一致性与质量门**：`pytest tests/py --stack=ndr` **139 passed**、`--stack=agent` **138 passed, 1 skipped**（NDR 专属画像用例）；`ruff` / `pyright`（0 error）全过；两侧 `tsc --noEmit` 退出码 0。CI 首跑（run `36971997483`）在 pyright 步失败，**根因是 CI 的 venv 只装了 7 个包、pyright 进入降级模式**（导入解析不了、类型退化成 `Any`/`None`，本地装全依赖是 0 error）—— 本地绿、CI 红不是代码问题；改成从两侧 `pyproject.toml` 读依赖清单安装后，run `36972649548` 三作业全绿。
- **③ 部署**：10 容器全 Up；镜像 `shentong-ndr` `14cf8c79da24` → `b4ed5a34450d`、`shentong-zeek` `bfcc7cea7e98` → `f19ce18abebc`；Zeek 命令仍是 `zeek -C -i ens160 -f net 172.16.196.0/24 /usr/local/zeek/share/zeek/site/local.zeek`；Filebeat 落盘队列已建（`/usr/local/bin/data/spool/filebeat/{0.seg,state.dat}`）；新字段 `source_file` / `log_type_known` 已动态建好（部署后 30 分钟：`log_type_known=true` 557 条，`source_file` = conn.log 553 / dns.log 4）。
- **④ 实机探针**：
  - **未知流不丢、保留原名**：新建 `/logs/zzprobe.log` 投 `{"probe":"batch1-marker-1",…}` → ES 命中 `log_type:"zzprobe"`、`log_type_known:false`、`source_file:"zzprobe.log"`、`event_type:"generic"`。
  - **停 Redis 不丢事件**：`stop redis` 期间投两个标记 → ES **0 条**（没丢也没提前投），磁盘队列段涨到 954694 字节；`start redis` 后 40 秒两条各 **1 条**，四个队列回 0。代价是 Redis 不可用时归一化/检测器进程会退出由重启策略拉起（重启计数 normalizer 8 / detector 1）—— 没丢数据，但这是既有行为，**注：不是本次引入**。
  - **运维流只入库**：合成 `/logs/stats.log` 两行 → ES 得 `log_type:"stats"`、`log_type_known:true`、`source_file:"stats.log"`（照样入库当证据）；归一化周期日志「**类型闸门只入库 2 条**」→ 下一条「3 条」。
  - **检测器兜底闸门**：直接 `LPUSH shentong:events:raw` 一条 `log_type:"stats"` 的合成文档 → 检测器统计出现「**类型跳过(运维 1 / 未知 0)**」且不产生摘要（这条只走检测器、不入 ES）。
  - **上线后 24h `source_file`×`log_type`**：conn.log 10350 / dns.log 43 / ssl.log 25 / zzprobe.log 3 / stderr.log 1；`packet_filter`/`ntp`/`weird`/`x509` **部署后十余分钟内没有新行**（本身极低频，基线里运维类 24h 约 62 条），运维闸门以合成探针为准。10 分钟窗口里 3 条「缺 `raw.conn_state` 的 conn」是旧镜像切换前入库的遗留文档（`ts` 06:19:09Z / 06:21:15Z，无 `source_file` / `raw.log_type` 字段），**不是回归**。
- **验收抓出的缺陷（已修，随本期提交）**：排除名单最初写在 filestream 输入的**顶层 `exclude_files`**，实机探针证明完全无效 —— `/logs/stderr.log` 照样入库（ES 命中探针 1 条、Filebeat 注册表里 `stderr.log` 3 处）。按官方 8.15 文档，filestream 的排除是 Scanner 选项 **`prospector.scanner.exclude_files`**，顶层那个是旧 `log` 输入才有的键；`filebeat test config` 对两种写法都回 `Config OK`（不报未知键），`filebeat --once` 也在第一次扫描前就退出（约 40ms、harvester 0）—— **只有端到端探针能判定**。已移到 `prospector.scanner.exclude_files` 并在注释里记下这次实测，`tests/py/test_filebeat_yml.py` 加断言（顶层不得再出现该键）。

**部署修复后的复验（2026-10-02，`shentong-zeek` 镜像 `f19ce18abebc` → `244ec0300d17`）**

- **排除名单生效**：投探针 `{"probe":"exclude-stderr-2"}` 到 `/logs/stderr.log` → 75 秒后 ES 命中 **0 条**，Filebeat 注册表里 `stderr.log` 的条数 **4 → 4 不变**（修复前是能被采集并入库的）。
- **运维类仍入库**：同批投 `/logs/stats.log` → ES 命中 1 条，`log_type:"stats"`、`log_type_known:true`、`source_file:"stats.log"`、`event_type:"generic"`；归一化周期日志「类型闸门只入库 2 条」、检测器「类型跳过(运维 1 / 未知 0)」照旧。
- **保留策略实测**：往 `/logs` 放两个轮转命名的探针（`zzoldprobe.2026-09-20.log` mtime 改成 10 天前、`zznewprobe.2026-10-01.log` mtime 改成 1 天前）→ 重建容器后**启动清理循环在没有任何人工干预的情况下**删掉了旧的那个、留下新的那个。2026-10 的 QA 修复把口径钉死：保留 `ZEEK_RETENTION_DAYS=3` 天按 `mtime` 以**分钟**判定（`-mmin +$((days*1440))`，原来的 `-mtime +3` 实际留 4 天多），只匹配轮转命名（`*.????-??-??-??-??-??.log` 与 `*.????-??-??.log`）、活动日志 `*.log` 永不删，且 **Filebeat 没在运行时跳过本轮删除**（先确保发运再清归档）；两条 `find` 同时覆盖平铺与子目录，原先那个只在日期子目录布局下才命中的 `-mindepth 2` 分支已删。
- 复验后探针文件与 ES 探针文档（5 条）已清理，10 容器全 Up，`collect`/`raw` 队列为 0，Zeek 命令仍是 `zeek -C -i ens160 -f net 172.16.196.0/24 /usr/local/zeek/share/zeek/site/local.zeek`。

**已知取舍与遗留**：① 运维流（`packet_filter`/`ntp`/`weird`/`x509`/`reporter`）本身极低频，上线后十余分钟没有自然新行，闸门证据以合成探针为准；② Redis 不可用时归一化/检测器进程会退出并由重启策略拉起（重启计数上涨，**不丢数据**，是既有行为、非本批引入）；③ 本批只动类型与去向，正文上限不一致、请求头值、JA4/JA4S、文件哈希与提取分别留给批 2/3/4。

### 第 10 期 · 采集面改造批 2：指纹与文件元数据 ✅ 已完成（2026-10-02，实施记录）

**起因**：第 8 期的实机专项检查（见 `## 8. 开放问题` 第 8 条）抓出两条硬事实 —— ① Zeek 9.0 自带分析器**没有** `ja3`/`ja3s` 字段（`local i: SSL::Info; print i?$ja3;` 编译报 `no such field in record`），基于它的规则永不命中；② `files.log` 的 `analyzers` 是空数组，**没有任何哈希**、没有文件名。本期补上指纹与文件元数据。逐条决定见 `docs/ndr-collect-plan.md` 的批 2。

1. **许可证收窄（用户决策：本产品会对外售卖/托管给客户）→ 只收 BSD-3-Clause**：JA3/JA3S（`salesforce/ja3`，commit `502cc6395811c54743b0561419d61900a6df3ff7`）与 **JA4 本体**（`FoxIO-LLC/ja4-zeek-scripts`，commit `8bf9feca52790ae8c926c6a8d79a3547ac19541a`，其 `LICENSE-JA4` 就是 BSD-3）。**JA4S / JA4H / JA4L / JA4LS / JA4T / JA4TS / JA4D / JA4SSH / JA4X 一律不进仓库** —— 它们是 `FoxIO License 1.1`（版权许可仅限非商业；FAQ 明确「作为产品功能出售、托管给客户、用它给付费客户提供价值」都需 FoxIO OEM 授权），因此原计划里的 `ja4s`/`ja4h` 归一化**取消**。
2. **vendor 落在 `ndr/zeek/site/vendor/`**（`ndr/zeek/Dockerfile:28` 只把 `site/` 整棵复制进镜像；放 `ndr/zeek/vendor/` 会直接 `fatal error in /site/shentong-fingerprints.zeek … can't find ./vendor/ja3`）：
   - `vendor/ja3/{ja3.zeek,ja3s.zeek,LICENSE.txt,zkg.meta}` 逐字 + **自建** `vendor/ja3/__load__.zeek`（只加载 `ja3.zeek`/`ja3s.zeek`；上游那个还会加载 `intel_ja3.zeek`，它把 JA3 接进 Intel 框架并另开 `ja3sfp.log`，本项目不用）。
   - `vendor/ja4/LICENSE-JA4.txt` + 逐字 `ja4/{__load__,helpers,main}.zeek`、`utils/{common,ssl-consts}.zeek` + **自建** `vendor/ja4/__load__.zeek`（Zeek 9 的 base 里没有 `FINGERPRINT` 模块，`FINGERPRINT::Info` 与 `redef record connection += { fp: … }` 必须自己声明）与最小 `vendor/ja4/config.zeek`（只留 `delimiter`/`JA4_raw`，不含 JA4+ 的开关）。
   - `vendor/README.md`：来源 commit、逐字 vs 自建清单、**为什么 JA4+ 不进仓库**、`site/` 位置约束。
3. **两个新站点脚本**：`site/shentong-fingerprints.zeek`（`option ja3_enabled = T` / `option ja4_enabled = T`，在 `@if` 里 `@load ./vendor/ja3` 与 `./vendor/ja4`）；`site/shentong-policies.zeek`（`policy/protocols/ssl/ssl-log-ext.zeek`、`policy/frameworks/files/hash-all-files.zeek`、`policy/misc/stats.zeek` + `event zeek_init() &priority=-10 { Log::disable_stream(Notice::LOG); }`）。**不需要**再关 `tlsfp`/`ja3sfp`/`fingerprint_ja4` 流：三家的脚本都没有给这些流写入口（实测都不产生）。`site/local.zeek` 顺序变为 json → extra → policies → httpbody → fingerprints → nets → scripts-d。
4. **归一化（两侧逐字一致，只差 NDR 独有的 `source_of()`）**：`schemas.py` 加 `ja4`、`fuid`、`md5`、`sha1`、`sha256`、`file_source`、`file_is_orig`；`normalizer.py` 新增 `_to_bool()`（吃掉 Zeek 的 `"T"`/`"F"` 字符串）、`_ZEEK_TYPE_HINTS` 的 ssl 加 `ja4` / files 加 `sha256`、`_http_fields` 搬运上述字段（哈希与 `fuid` 截 64 字符、`file_source` 截 32）；`investigation/catalog.py` 注册新字段并进 SUMMARY/AGG —— 顺带修掉一处**一直取不到值**的路径：`sha256` 的 `path` 原写 `raw.sha256`，而 `rules/engine.py` 的 `_get_field` 只认 extra → `VIRTUAL_FIELDS` → `getattr(log, field)`，**根本不支持 `raw.` 前缀**，所以批 2 之前基于文件哈希的规则永远匹配不到，现在 path 改成 `sha256`（真有这个归一化字段了）；`rules/engine.py` 的 `_FIELD_TYPES` 把 `md5`/`sha1`/`sha256`/`file_source`/`file_is_orig` 挂 `files`、`ja4` 挂 `ssl`。
5. **测试**：`tests/py` 增 ssl `ja4` 与 files 哈希/方向/来源断言（含 `_to_bool` 的 `"T"/"F"` 两种写法）；新增 `tests/zeek/batch2_test.zeek`（断言 `SSL::Info$ja4` 字段在编译期存在、`FINGERPRINT::delimiter == "_"`、`JA4_raw` 默认关、两个开关默认开、`Stats::report_interval` 已加载、`Notice::LOG !in Log::active_streams`）；`tests/zeek/run.sh` 重写为**复制整棵 site 树**并逐个跑 `tests/zeek/*_test.zeek`（旧版只扁平 `cp *.zeek`，相对 `@load ./vendor/...` 必然加载失败）。

**验收（四步）**

- **① 容器内 Zeek 单测**：`sh tests/zeek/run.sh` → `batch2_test.zeek` 7 条 PASS + `hb_test.zeek` 9 条 PASS，两个 `FAILS=0`，`ZEEK TESTS: ALL PASS`。
- **① 附带：容器内真实样本实测**（`zeek/zeek:9.0`，`-i lo`，镜像里没有 `curl`，用 `openssl s_server`/`s_client` 造 TLS 握手、用 `python3 -m http.server` 造下载）：`ssl.log` 得 `ja3:"284deaeae14ea5ddc96c5d7e59855422"`、`ja3s:"15af977ce25de452b96affa2addb1036"`、`ja4:"t13d301200_1d37bd780c83_ecd0401ec68b"`、`client_version`/`server_version`=771（ssl-log-ext 生效）；`files.log` 的 `md5`/`sha1`/`sha256` 与 Python `hashlib` **逐字一致**、另有 `fuid`/`source:"HTTP"`/`is_orig:false`/`seen_bytes`/`total_bytes`=5000；`stats.log` 有行；**不产生** `notice.log`/`tlsfp.log`/`ja3sfp.log`/`fingerprint_ja4.log`。已知测试环境现象：回环上单个 200KB 响应会 `truncated_tcp_payload`，使 `http.log` 的 `resp_fuids` 为空（小文件正常），不是脚本缺陷。
- **② 本地两侧一致性 + 质量门**：`pytest tests/py --stack=ndr -q` **142 passed**、`--stack=agent -q` **141 passed, 1 skipped**（NDR 专属画像用例）；`ruff check ndr/backend/app agent/backend/app tests/py` All checks passed；`pyright` 同一组路径 0 errors / 0 warnings / 0 informations。
- **③ CI**：提交 `ad112c9` 推送后 GitHub Actions run `36976456458` **三作业全绿**（`build` 构建并推送 5 个镜像 / `test` ruff+pyright+两侧 pytest+Zeek 容器单测 / `web` 两侧 `tsc --noEmit`）。
- **④ 服务器部署与实机探针**（`/opt/shentong-ndr`，`docker compose -f docker-compose.deploy.yml pull zeek backend detector normalizer ndr-mcp && up -d`）：
  - 部署后 10 容器全 Up；镜像 `shentong-zeek` `244ec0300d17` → `213e76f6fc69`、`shentong-ndr` `b4ed5a34450d` → `0fa55ff4dbc6`；Zeek 启动命令仍是 `zeek -C -i ens160 -f net 172.16.196.0/24 /usr/local/zeek/share/zeek/site/local.zeek`；`reporter.log` 无异常。
  - **探针 A（TLS 指纹）**：从服务器发起真实 HTTPS（`curl -s https://www.baidu.com`，200/0.19s）→ ES 30 分钟内 `log_type:ssl` **187 条**，样例文档带 `ja3:"7704a11cf87dfcf33080b90ce11d5527"`、`ja3s:"f4febc55ea12b31ae17cfb7e614afda8"`、`ja4:"t13d1715h2_5b57614c22b0_a54fffd0eb61"`（`dst_ip` 为 yahoo CDN、`src_ip` 172.16.196.77）；`ja4` 值分布：`t13d1715h2_5b57614c22b0_a54fffd0eb61` ×20、`t13d3112h2_e8f1e7e78f70_b26ce05bbdd6` ×1，另有 83 条 ssl 文档 `ja4` 为空（部署前的旧会话与没有 client hello 的流）。**证明 vendor 的 JA3/JA3S/JA4 在实机产出并落库**。
  - **探针 B（文件哈希）**：明文 HTTP 下载 `http://mirrors.aliyun.com/ubuntu/dists/noble/Release`（254968 字节）→ `files.log` 该条带 `analyzers:["SHA256","SHA1","MD5"]`、`md5":"1696fa2694f099d735d609ea8bd8dee6"`、`sha1":"34b3a459ecbfdde0111263c39a7d1f762adf4185"`、`sha256":"26758a13cecfaff9ff274d31ea9a4633674a999bd130c09f6ecd66a4b8071184"`、`seen_bytes`/`total_bytes`=254968；ES 文档同样字段齐全，且 **`md5`/`sha256` 与服务器上 `md5sum`/`sha256sum` 的本地计算逐字一致**，另有 `fuid:"FXrH5G2MHUtFR4uPxh"`、`file_source:"HTTP"`、`file_is_orig:false`、`mime_type:"text/plain"`。
  - **探针 C（stats 运维流）**：`policy/misc/stats.zeek` 生效，`/logs/stats.log` 开始产出（默认 5 分钟一报）→ ES 30 分钟内 `log_type:stats` **2 条**，`log_type_known:true`、`source_file:"stats.log"`、`event_type:"generic"`；同期归一化周期日志「**类型闸门只入库 2 条**」、检测器「**类型跳过(运维 0 / 未知 0)**」—— 运维流只入库当证据、不进检测（它在归一化层就被挡住，所以检测器侧计数为 0 属预期）。
  - **30 分钟 `log_type` 分布**：conn 48988 / dns 215 / ssl 187 / weird 6 / x509 5 / files 3 / http 3 / stats 2，`log_type_known` 全为 true。
  - **探针方法学（下次照用）**：① `log_type` 等字段是动态映射出的 `text`，聚合要写 `log_type.keyword`，否则报 `Fielddata is disabled`；② normalizer 对缺失字段写**空字符串**，所以**裸 ES 的** `exists` 查询会把「字段存在但为空」也算上，核「有没有值」要用 `.keyword` 的 terms 分布或看具体文档，别用 `exists` 计数 —— **注意这条只针对手写 ES 探针**：NDR 查询层（MCP 工具 / `investigation/es_query.py`）2026-10 QA 已改成「字符串字段必须非空才算 exists」（`exists ja4` 从 529370 掉到 1252，与 `must_not term ja4.keyword:""` 一致），工具侧可以放心用 `{"exists": true}`；③ 造 TLS 流量只需从服务器 `curl` 一个外网 HTTPS（`src` 是 172.16.196.77，命中 BPF 且出 ens160），造明文下载用 `http://mirrors.aliyun.com/...`（勿用 HTTPS，否则看不到 files.log 明文体）。

**已知取舍与遗留**：① JA4S/JA4H 等 JA4+ 未收录（许可证），智能体侧/规则侧不依赖它们；② `file_source` 只记 Zeek 的 `source` 字段（HTTP/FTP/SMTP/SSL…），不代表真实落地路径；③ 请求头值、正文上限与文件内容提取仍留给批 3/批 4。

### 第 11 期 · 采集面改造批 3：请求头全量值 + 正文上限可设置 ✅ 已完成（2026-10-02，实施记录）

**起因**：第 8 期实机检查确认 `HTTP::Info` 只有少数几个头落成独立字段（`host`/`user_agent`/`referrer`/`origin`/`proxied`/认证信息），`policy/protocols/http/header-names.zeek` 也只记**头名**（且默认只记客户端侧）不记值 —— `Cookie`、`Authorization`、`Content-Type`、`Set-Cookie`、`X-Forwarded-*` 这些调查要用的值在日志里根本没有；同时请求正文与响应正文在 Zeek 侧是**硬编码 4096 字节**（`site/shentong-httpbody.zeek` 的 `max_body_len`/`max_resp_body_len`），用户改不了。本期补头值采集，并把两个正文上限做成后台可配、可热重载。逐条决定见 `docs/ndr-collect-plan.md` 的批 3。

1. **头值采集（自写 `site/shentong-httpheaders.zeek`）**：`module ShentongHTTPHeaders`；`redef record HTTP::Info += { req_headers, resp_headers }`（都是 `string &log &optional`，逐行 `"Name: value\n"`）；`const max_header_value_len = 256 &redef`、`const max_headers_len = 4096 &redef`（单方向各自累计）；`append_header(current, name, value)` 单头先截 256 字符、总量到 4096 后**停止追加**（最后一行允许被截断）；`clean_header_value(value)` 把含任意 C0 控制字符（字符类 `[\x00-\x1f\x7f]`，**含 `\r`/`\n`**）的值整体替换成 `<binary>` —— 头值里出现换行会在日志里伪造出假头行。**这是本期的实测修正**：初版沿用了正文脚本的字符类（`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`，故意放行 tab/CR/LF 以便正文保留换行），被 `tests/zeek/batch3_test.zeek` 的注入用例抓出来；两个函数在 `export` 块里声明为 `global`（定义在块外），否则模块外无法调用、单测也调不到。
2. **`site/shentong-policies.zeek` 扩到 5 个 `@load`**：新增 `policy/protocols/http/header-names.zeek`（提供**有序**的 `client_header_names`/`server_header_names`，与本脚本的头值互为补充）与 `policy/protocols/http/var-extraction-cookies.zeek`（请求 `Cookie` 的变量名进 `cookie_vars`）。
3. **上限可配 + 热重载**：`site/shentong-limits.zeek` 是镜像内默认值（请求 16 KB / 响应 64 KB）；`entrypoint.sh` 新增 `render_limits()`（`conf_get body_max_bytes` / `resp_body_max_bytes`，**只接受纯数字**，缺失或非法回落 16384/65536，写出 `## 由 entrypoint.sh 自动生成（render_limits）…` + 两行 `redef`），并在 `main` 与看门狗（10 秒轮询 `interface.conf` 的 sha256）检测到变化时都调用 —— 后台改上限 → 写 `interface.conf` → 看门狗重载 Zeek 时重建 `shentong-limits.zeek`。`local.zeek` 顺序变为 json → extra → policies → httpbody → **limits** → **httpheaders** → fingerprints → nets → scripts-d（`limits` 必须排在 `httpbody` 之后：它 `redef` 的是后者声明的 const）。
4. **后端**：`api/routes/zeek.py` 的 `CONF_KEYS`/`DEFAULT_CONF` 加 `body_max_bytes`/`resp_body_max_bytes`（**不加进 `CONF_KEYS` 则 `_read_conf` 读不到**）；`ZeekIfaceIn` 加 `body_max_kb`/`resp_body_max_kb`（`None` = 沿用当前值），KB 范围 1~1024，越界回 400 `field_error`；`PUT /interface` 同时写 `interface.conf` 与 `system_config` 的 `http.body_max_chars`/`http.resp_body_max_chars`，并 `runtime_config.invalidate()`；`GET /status` 回这两个值。两侧 `config.py` 的 `http_body_max_chars`/`http_resp_body_max_chars` 默认 2000 → **16384/65536**；两侧 `normalizer.py` 新增 `http_body_limit()`/`http_resp_body_limit()`（经 `runtime_config.get` 读 `system_config`，30 秒 TTL，读不到就回落 settings，单位是字符）替换原来直接读 settings 的两处截断；`schemas.py` 加 `req_headers`/`resp_headers`（后端再截 8192 字符兜底）；`investigation/catalog.py` 注册两个字段、`rules/engine.py` 的 `_FIELD_TYPES` 把它们挂到 `http`。
5. **前端**：监控网段页的 Zeek 面板新增「请求正文上限（KB，1~1024）」「响应正文上限（KB，1~1024）」两个输入框（留空或非法就不提交，后端沿用当前值），「当前生效」多显示一行当前上限；`lib/api.ts` 的 `ZeekStatus` 加两个字段。
6. **测试**：`tests/py` 新增 `test_http_headers_captured`（头值逐字搬运 + 非 HTTP 流不串味）、`test_http_limits_follow_settings`（无 `system_config` 行时回落 settings）与 `test_zeek_limits.py`（镜像内默认值与 `settings` 一致、`local.zeek` 里 `limits` 在 `httpbody` 之后、把 `render_limits` 抽出来用 bash 真跑三种 conf：正常值原样写出、缺键与非法值回落默认）；新增 `tests/zeek/batch3_test.zeek`（字段/常量存在性、单头截断 256、总量封顶 4096、`\r\n` 注入中和）；原有两处「上限 2000」的断言改为按 `settings` 造必然超限的输入。

**验收（四步）**

- **① 容器内 Zeek 单测**：`sh tests/zeek/run.sh` → `batch3_test.zeek` 9 条 PASS + `batch2_test.zeek` 7 条 PASS + `hb_test.zeek` 9 条 PASS，三个 `FAILS=0`，`ZEEK TESTS: ALL PASS`。
- **① 附带：容器内真实流量实测**（`zeek/zeek:9.0`，`-i lo` + python 探针，默认上限）：GET 带 30 个 190 字符自定义头 + `X-Long: A×400` → `req_headers` 总长 **4096**（22 行）、`X-Long` 值 **256** 字符，`client_header_names` 有序出现（HOST/X-LONG/X-H00…）；POST 4000 字节 → `body` 长 4000、`request_body_len` 4000、`cookie_vars:["a","b"]`；响应 8000 字节 + `X-Resp-Long: D×400` → `resp_headers` 334 字符且 `X-RESP-LONG` 值 256、`resp_body` 长 8000、`response_body_len` 8000。把 `shentong-limits.zeek` 换成 `max_body_len = 1024` / `max_resp_body_len = 1500` 再跑一遍 → `body` 长 **1024**、`resp_body` 长 **1500**，而 `response_body_len` 仍是 **8000** —— 证明「截断只影响落库文本，完整字节数不受影响」。已知测试环境现象：回环上单个大 payload（≳8 KB 单包）会 `truncated_tcp_payload` 并把整条请求的头/方法丢掉（容器内没有 `ip` 命令，改不了 lo MTU），所以探针请求总字节要压在 ~8 KB 内，要验证 16 KB 这类上限就用挂载覆盖的 limits 文件把上限调小。
- **② 本地两侧一致性 + 质量门**：`pytest tests/py --stack=ndr -q` **149 passed**、`--stack=agent -q` **148 passed, 1 skipped**；`ruff check ndr/backend/app agent/backend/app tests/py` All checks passed；`pyright` 同一组路径 0 errors / 0 warnings / 0 informations。
- **③ CI**：提交推送后 GitHub Actions 三作业全绿（`build` 构建并推送镜像 / `test` ruff+pyright+两侧 pytest+Zeek 容器单测 / `web` 两侧 `tsc --noEmit`）。
- **④ 服务器部署与实机探针（2026-10-02，172.16.196.77，镜像 `shentong-zeek` `213e76f6fc69` → `716005bbe598`）**：按用户要求先 `docker compose down --remove-orphans` 清掉本项目全部容器与所有 `ghcr.io/cxiyuan/sec-agent/*` 镜像（回收 1.2GB；数据卷与第三方基础镜像保留），再 `pull` + `up -d`（10 容器全 Up，ES green）。清理后先核**回落路径**：`interface.conf` 里还没写两个新键 → 容器内 `shentong-limits.zeek` 被 `render_limits()` 渲染成默认 `16384`/`65536`，`local.zeek` 的 `@load` 顺序为 json → extra → policies → httpbody → **limits** → **httpheaders** → fingerprints → nets → scripts-d。实机探针（服务器本机 `curl`，走 ens160 命中 BPF）：
  - **头值全量入库**：`POST http://mirrors.aliyun.com/ubuntu/dists/noble/Release` 带 `X-Probe-Long: B×400`、`X-Probe: b3-ev-post`、`Cookie: probe=abc123; sid=xyz` 与 3908 字节体 → ES 文档 `@timestamp 2026-10-02T07:49:13.426Z`（与 Zeek 事件 `ts` 同在毫秒级，链路近似实时）：顶层 `req_headers` **450** 字符、`resp_headers` **496** 字符、`body=1024`（当时上限 1 KB）、`resp_body_len=591`；`raw.request_body_len=3908`（**完整字节数不受截断影响**）；`raw.client_header_names` 8 项、`raw.cookie_vars=['probe','sid']`、`X-PROBE-LONG` 的值被截到 **256** 字符、`COOKIE: probe=abc123; sid=xyz` **明文落库**。
  - **上限热改双向都通**：`PUT /api/zeek/interface` 带 `body_max_kb:1` / `resp_body_max_kb:4` → 写入 `interface.conf`（`body_max_bytes=1024` / `resp_body_max_bytes=4096`）→ 看门狗 ~10 秒内重写容器内 `shentong-limits.zeek` 并重载（`last_reload` 前进；约 1~2 秒抓包中断）；同一 POST 的 `body` 落成 **1024**、GET 一条 254968 字节响应的 `resp_body` 落成 **4096** 而 `resp_body_len` 仍是 **254968**；随后改回 16 KB / 64 KB 并核 `interface.conf` 与容器内脚本均为 `16384`/`65536`。
  - **字段归属**：`req_headers` / `resp_headers` / `resp_body_len` 有顶层归一化字段；`client_header_names` / `server_header_names` / `cookie_vars` 只在 `raw.*` 下（归一化 schema 不带这三个）。
  - **已知限制（实测，非本期引入）**：Filebeat 偶发 `ndjson` 解析失败会让事件变成**空壳文档**（有 `@timestamp` / `log_type`，其余字段空串，`raw.error.type=json`）或直接丢。90 分钟内实测 **9 条**，跨 `conn`/`http`/`files`/`x509`/`stats`/`weird` 多种日志、时间跨本期部署前后，**多落在 Zeek 重启/日志轮转前后约半分钟内**（看门狗 07:44:47 重载后 9s 与 33s 各一次），疑为轮转窗口读到非行首片段；`filebeat.yml` 的 `add_error_key: true` 留下了 `raw.error`。本期两条探针恰好落进这个窗口没进 ES，改在静默窗口重发即正常入库（上面的证据即重发所得）。**未改 Filebeat 配置**（避免动已工作的采集链路），列为后续调查项，同时写进 `ndr/zeek/README.md` 的「已知限制」。

### 第 12 期 · 采集面改造批 4：文件提取 + 下载通道 ✅ 已完成（2026-10-02，实施记录）

**起因**：批 2 起 `files.log` 已经有文件元数据（fuid / mime / filename / 大小 / 哈希），但**文件内容本身没有落盘** —— 现场想知道"这个 HTTP 上传/下载到底是什么"，只能拿着 sha256 去别处找样本。本期把 HTTP/FTP 明文传输的文件按白名单提取到磁盘，并给后端一个按 fuid 取文件的下载接口。逐条决定见 `docs/ndr-collect-plan.md` 的批 4。

1. **Zeek 侧提取（新增 `site/shentong-file-extract.zeek`）**：`@load base/frameworks/files` + `@load base/files/extract`；`redef FileExtract::prefix = "/extract/"`、`redef FileExtract::default_limit = 16777216`（16 MiB）；`const sources: set[string] = { "HTTP", "FTP" } &redef`；`event file_new(f)` 里 `if ( ! f?$source || f$source !in sources ) return;` 然后 `Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=f$id])`。**为什么要把文件名显式指定成 fuid**：FileExtract 默认取名 `extract-<时间>-<来源>-<fuid>`，而它写进 files.log 的 `f$info$extracted` 是**裸文件名**（`prefix` 只影响磁盘路径，不进日志）—— 指定成 `f$id` 之后，日志里的 `extracted` 就等于 fuid，磁盘路径恒为 `/extract/<fuid>`，下载接口不需要解析任何命名规则。超过 16 MiB 时 FileExtract 会截断并置 `extracted_cutoff` / `extracted_size`。
2. **删除为什么不在 Zeek 里做**：Zeek 没有 unlink / system 这类 BIF（`zeek -NN` 里也没有），脚本根本删不了文件，因此"在 Zeek 脚本里判完 MIME 直接删"这条路走不通。改由容器入口的清理助手 `ndr/zeek/extract_cleanup.py` 承担：每 5 分钟读 `/logs/files.log` + `files.*.log`（**先轮转件、后活动日志**，后者覆盖前者；半行与非 JSON 行跳过，容忍 Zeek 正在写的最后一行）建出 `fuid → mime_type` 表，再扫 `/extract`：**白名单外**删、**没有记录**（来源不是 HTTP/FTP，或分析器没落元数据）删，但只动 `mtime` 早于 `--min-age`（默认 120 秒）的文件（避免删掉还在写的提取件）；最后按 mtime 从最老淘汰，直到目录不超过 `--max-bytes`（默认 10 GiB）。白名单 `DEFAULT_MIME_ALLOW`（文本 / XML / JSON / PDF / 邮件 / Office（含 `…officedocument.*`、`…opendocument.*` 前缀）/ 常见压缩包，**不含** `application/octet-stream` 与可执行体）**只在助手这一处定义**，下载接口不重复判定。比较前先做 MIME 归一化（剥掉 `; charset=…` 参数、去空白、转小写）—— files.log 的 `mime_type` 直接来自 HTTP 的 `Content-Type`，实测带参数，不归一化会把正常网页判成"白名单外"删掉（这条是自查时补的）。files.log 记录本身保留（删的是提取件，不是日志）。
3. **卷与权限**：compose 两个文件都加 `zeek-extract`（zeek `rw` / backend `ro`）。后端只读挂载，写权限只留在采集容器里。
4. **下载接口（新增 `api/routes/files.py`）**：`GET /api/files/{fuid}`，鉴权沿用 `get_current_user`；`fuid` 先过 `^[A-Za-z0-9_-]{8,64}$`（不合法 400）；再用 fuid 去 ES 查**最新一条带 `extracted` 的文件事件**，文件名取自服务端的 `extracted` 字段；`resolve_extract_path()` 只接受裸文件名（空 / `.` / `..` / 含 `/` 或 `\` 一律拒绝），并要求 `resolve()` 后的 `parent` 正好是提取目录 —— **目录穿越与符号链接逃逸同时挡住**；`FileResponse` 的下载名再清洗一次（控制字符 / 引号 / 分隔符换成 `_`、128 字符截断），避免响应头注入。文件已被清理时回 404 并说明原因（"非白名单类型或超出容量上限"）；`extracted_cutoff` 为真时加 `X-Extract-Cutoff: 1` 与 `X-Extract-Size` 响应头，让下载方一眼看出拿到的是截断文件。**接口绝不接受客户端提供的路径**。
5. **字段（两侧同改）**：UnifiedLog 加 `extracted`（落盘文件名，等于 fuid）/ `extracted_size`（实际落盘字节数，截断时是上限）/ `extracted_cutoff`（布尔）。`tests/py/test_stack_consistency.py` 要求两侧字段集完全一致，故两侧同时改 `schemas.py`、`ingestion/normalizer.py`（`extracted` 截 128 字符）、`rules/engine.py` 的 `_FIELD_TYPES` 与 `investigation/catalog.py`。
6. **测试**：`tests/py/test_extract_cleanup.py`（白名单、日志读取顺序、半行容忍、在写保护、容量淘汰、dry-run、CLI 端到端、entrypoint/Dockerfile/local.zeek 接线）与 `tests/py/test_files_api.py`（目录穿越 / 符号链接 / 下载名头注入 / fuid 正则、Zeek `prefix` 与后端 `extract_dir` 一致；仅 NDR 侧，`--stack=agent` 下跳过）；`tests/zeek/batch4_test.zeek`（prefix / limit / 来源集合 / 三个新字段）。**顺手修掉两个自己的坑**：助手最初"先 `files.log` 后轮转件"，会让旧记录覆盖新记录；端到端用例一开始拿固定的"未来"时间当 mtime，被在写保护直接跳过（改成真实时钟）。

**验收（四步）**

- **① 容器内 Zeek 单测**：`sh tests/zeek/run.sh` → `batch4_test.zeek` 6 条 PASS + `batch3_test.zeek` 9 条 + `batch2_test.zeek` 7 条 + `hb_test.zeek` 9 条，四个 `FAILS=0`，`ZEEK TESTS: ALL PASS`（exit 0）。
- **② 本地质量门**：`pytest tests/py --stack=ndr -q` **179 passed**；`--stack=agent -q` **160 passed, 19 skipped**（下载接口与提取目录一致性的用例只在 NDR 侧跑）；`ruff check ndr/backend/app agent/backend/app ndr/zeek/extract_cleanup.py tests/py` All checks passed；`pyright` 同组路径 0 errors / 0 warnings；两个 compose `docker compose config -q` 通过。
- **③ CI**：两次推送都三作业（build / test / web）全绿 —— `2ee6155`（批 4 主体，18 files，+201/-10）→ run **36981997754**；`5309d11`（补 `text/json` 与 MIME 参数归一化）→ run **36982193977**。build 作业同时把 `ghcr.io/cxiyuan/sec-agent/shentong-zeek:latest`（context `./ndr/zeek`）推新。
- **④ 服务器部署与实机探针（172.16.196.77，`/opt/shentong-ndr`）**：服务器**不是 git 仓库**（只有 compose、`.env`、`logstash/`）→ compose 只能覆盖：先备份 `docker-compose.deploy.yml.bak-b4`，`diff` 确认与仓库只差批 4 三处（backend `zeek-extract:/extract:ro`、zeek `zeek-extract:/extract`、顶层卷 `zeek-extract:`），覆盖后 `docker compose config -q` 通过，再 `pull` + `up -d zeek backend`。**踩到的坑**：`shentong-ndr` 镜像被 backend / normalizer / detector / ndr-mcp **四个服务共用**，只重建 zeek+backend 会让 normalizer 继续跑旧镜像 —— 表现为 `/extract` 里明明有文件、ES 里 `exists extracted` 却恒为 0（新字段永远不进库）；补 `up -d normalizer detector ndr-mcp` 后四个服务镜像统一为 `sha256:9adedfe6053d`，字段立刻落库。容器侧核对：`/usr/local/bin/extract_cleanup.py` 含 `def normalize_mime`、`/extract` 在 zeek 内 rw 在 backend 内 ro、`app/api/routes/files.py` 在镜像里、十容器 Up、Zeek 启动命令带 `-f net 172.16.196.0/24`。
  **探针证据**（目标 `http://mirrors.aliyun.com/ubuntu/`，POST 请求体走镜像可见方向）：2400B `text/plain` → `/extract/FKQO9x4uHwL5zeCR6` 2400B（sha256 与本机原文一致），`GET /api/files/FKQO9x4uHwL5zeCR6` 200（`content-type: text/plain; charset=utf-8`、`content-length: 2400`）；3000B `application/octet-stream` → 落盘 3000B 但 files.log 的 `mime_type` 为空 → 清理助手判白名单外删除，删除后下载 404；无令牌 401，`short` / `has space` 400，编码斜杠与库中不存在的 fuid 404；清理助手 `--dry-run` 与真跑口径一致（白名单外 1 件、保留 9 件），`--max-bytes 2000` 按 mtime 淘汰 8 件、释放 5.1 MiB、只剩最新的 599B 件；ES 侧 `exists fuid` 91637、`exists extracted` 2119、`exists extracted_size` 0（与"仅截断时写"一致）。
  **截断链路**：真实 18.7MB 上传被远端 413 拒且镜像丢包严重（`total_bytes=18700000` / `seen_bytes=184432` / 落盘 5.3MB / `extracted_cutoff=false`），无法用真实大文件复现 16MiB 截断，因此改为容器内临时把 `FileExtract::default_limit` 改成 1000 验证全链路：上传 2400B → 两个 1000 字节截断件，files.log `extracted_size=1000` + `extracted_cutoff=true`，ES 同步（`exists extracted_size`=2、`extracted_cutoff=true`=2），下载响应带 `x-extract-cutoff: 1` + `x-extract-size: 1000` + `content-length: 1000`；测完按容器内备份覆盖回 `16777216`，sha256 校验一致、Zeek 重启后命令仍带 BPF（16 MiB 这个具体数值由 `tests/zeek/batch4_test.zeek` 断言）。

### 2026-10 深度 QA 修复批（A–G 七组，2026-10-02）

用户先要求「深度 QA NDR 代码：功能实现完整度、业务逻辑性，是否还存在空实现 / 死代码 / 代码逻辑造成现实数据采集流转问题」，只读审计报告出来后下达修复指令：**必修 = 会真丢数据或静默失效；应修 = 业务逻辑 / 口径不一致（会造成排查困难或局部失效）；并清理死代码、死配置、注释与实现不符**。七个互斥文件白名单的并行子代理（A 采集/归一化、B 检测器/投递、C 规则/基线/分诊、D 调查工具/MCP、E API/鉴权/config/DB、F Zeek/部署、G 前端）分工，`README.md` / `docs/**` 只由主控改；C 组子代理未产出，其条目由主控实现。`tests/py/test_stack_consistency.py` 逐字段比对两侧 `UnifiedLog`，所以 normalizer / schemas 的每处改动两侧同步。

**必修（丢数据 / 静默失效）**

- **坏消息不再静默丢**：`ndr/backend/app/collector/normalizer_service.py` 归一化异常的原始消息进死信 `shentong:events:dead`（LPUSH + LTRIM 保最新 1 万）、`shentong:collector:stats` HINCRBY 持久计数、按积压量告警；仍 ack 不卡链路。
- **队列裁剪方向纠错**：原 `ltrim(key, 0, limit-1)` 丢的其实是**最新**（Filebeat 用 `RPUSH` 写右端），改为 `ltrim(key, -limit, -1)` 保最新、丢最旧。
- **`conn_state` 语义纠错**：只有 `S0`（只发 SYN、无任何回应）算 `scan_attempt`，`S1/S2/S3/SF/RSTO/RSTR` 归 `conn_established`。原实现把已建立的连接也判成扫描 → 「内置-横向移动管理端口」「内置-异常外联端口」里的 `event_type ne scan_attempt` 永不命中，而「内置-扫描尝试连接」被灌误报。（2026-10-03 进一步把这套语义收进唯一事实来源，见下节「连接状态语义收口」。）
- **检测器投递不再谎报成功**：`ndr/backend/app/detector/runner.py` 在 `push.deliver()` 返回 `off`（未配推送地址）时改记 `undelivered` + ack，不再把摘要写进无人消费的退役队列 `shentong:events:dispatch` 并计 `delivered`。
- **异常消息不再无条件丢弃**：`runner.py` 处理失败的消息进隔离队列 `shentong:detector:failed`（1 千上限 + 7 天 TTL）并计数，取代 `log.exception` + `finally ack`。
- **推送重试队列有界**：`ndr/backend/app/detector/push.py` 给 `shentong:events:pushretry` 加 `_RETRY_QUEUE_MAX = 2000`（LTRIM 保最新，丢弃计 `retry_dropped`）；区分可重试（网络/超时/5xx/408/429 → 放回队尾、结束本轮，与 `docs` 第 5 期"停止本轮"的设计意图一致）与永久失败（持续 4xx → 记 5 次后判 `retry_lost`）；`recover_pending()` 加 SET NX 锁并与 `/api/agent-push/retry` 收敛，避免两个写者互抢 processing 批造成重复推送。
- **`exists` 算子语义纠错**：`ndr/backend/app/investigation/es_query.py` 对字符串字段的 `{"exists": true}` 改译为「有该字段且非空串」（`must_not term <keyword路径>:""`）。归一化给所有字符串字段默认 `""` 且全量落库，原语义下 `exists ja4` 命中全部 529370 条（正确口径 1252 条）、`exists account` 命中全量（实际 0）；规则引擎 `rules/engine.py` 一直就是非空判定。
- **多来源检索不再吞 Wazuh**：`ndr/backend/app/investigation/tools.py` 原来 `hits[:limit]` 只截第一个来源（zeek）段，Wazuh 命中整体丢失而 `by_source` 仍报 `returned=N`；改为各来源全取回 → 全局按时间排序 → 统一截断，`by_source.returned` 按最终返回重算并附 `fetched` 与说明。
- **`request_timeout` 传字符串让每次查询都失败（2026-10-03 部署后实机发现）**：`ndr/backend/app/investigation/es_query.py::query_timeout()` 返回 `"45s"`，而 elasticsearch-py 把它原样交给 urllib3 的 `Timeout(connect=…)` → 每次查询在建连接前就抛 `ValueError: Timeout value connect was 45s, but it must be an int, float or None.`；更糟的是 `_is_timeout` 按子串匹配 "timeout" 把这条 ValueError 判成超时，于是「查询根本没发出去」被报成「ES 查询超时…请缩小时间窗」——MCP 的 `search_events`/`aggregate_events`/`get_event`/`describe_data` 全部返回空结果 + 误导 note（本批之前就存在，`3af81c4` 引入）。修法：`query_timeout()` 改返回 `float`（4 个调用点同时修好），`_is_timeout` 对 `ValueError`/`TypeError`/`KeyError`/`AttributeError` 直接返回 False。实机复验：修前 `search_events(source=both, limit=5, filters={log_type: ssl})` → `hits: 0` + 两条超时 note；修后返回真实命中。
- **回溯上限走运行时保留期**：`es_query.py` 原读静态 `settings.es_retention_days`，后台把保留期 30 天改 90 天后超期查询静默返回空；改读 `ingestion/es_config.py` 的运行时 `retention_days()`（ES 索引名同理走 `current()`）。
- **出厂口令与登录面**：默认 `admin`/`admin123` 且原无改密入口 → 新增 `GET /api/auth/me`（含 `default_password_in_use`）、`POST /api/auth/change-password`（校验旧口令、8~128 位、不得与出厂口令相同）、`POST /api/auth/logout`，首启 warning，前端新增「账户」页 + 导航红字提醒；登录加同 IP+用户名限速（60 秒 5 次失败 → 429 + `Retry-After`），不做账号锁定。
- **规则改名撞唯一约束**：`ndr/backend/app/api/routes/rules.py` 改名/新建统一重名 409、内置规则禁止改名（400）、兜 `IntegrityError`。原来改名撞名直接 500，且内置规则被改名后启动时按 `Rule.name` 幂等 upsert 失败 → 重复插入内置规则。
- **基线落库阈值与样本保护**：`ndr/backend/app/baseline/engine.py` 原用累计 `stats["observed"]` 判阈值 → 累计越过 `baseline_max_observations` 后**每条事件**都触发一次整批落库（PG + 画像 + 清理判断全跑，吞吐打穿）；改为新增 `_obs_since_flush` 窗口计数、`flush()` 归零，累计值只用于界面展示。`baseline/stats.py` 写库失败时原来样本已被换走（那批观测永久丢失）→ 失败回并 `_pending` 下轮重试，超上限有界丢弃并记 `stats_write_dropped` / `stats_write_failed`。
- **Zeek 轮转名丢时分秒**：`ndr/zeek/site/shentong-json.zeek` 轮转名原只到天，同一天多次轮转会**同名覆盖**（丢日志）；改回带时分秒，`ndr/zeek/filebeat.yml` 相应「先剥完整时间戳、再剥只到天」；保留策略改按 mtime 分钟级、只匹配轮转命名、Filebeat 不在运行时不删、活动日志不删。
- **采集面可观测**：新增 `ndr/zeek/healthcheck.sh` + `ndr/zeek/Dockerfile` 的 HEALTHCHECK（只上报不重启）、`entrypoint.sh` 守护 Filebeat（30 秒探活）并在 Zeek 退出时写 unhealthy 哨兵；两份 compose 补 `TZ: Asia/Shanghai`；Wazuh 线 `ndr/wazuh/filebeat.yml` 补 `queue.disk`（1GB 落盘缓冲）+ `ndr/docker-compose.wazuh.yml` 加 Filebeat 注册表卷。

**应修（口径 / 局部失效）**

- **规则字段归属补 `wazuh` 桶**：`rules/engine.py::_FIELD_TYPES` 原来 Web 字段只挂 `("http",)`，而 Wazuh 分支同样填 `uri_path`/`query_string`/`method`/`body`/`status_code`/`user_agent` → 14 条 Web/URL 内置规则在 Wazuh 告警上永不求值；`query` 补 `("dns","http","wazuh")`（dns 里是域名，http/Wazuh 里是完整 URL）。删掉两条死映射 `host`/`referrer`（真名 `hostname`/`referer`）—— 它们会让只引用这些字段的规则「只挂 http 且永不匹配」。**审计报告的一处误判也已更正**：`rules/builtin.py:566` 的 `event_type eq wazuh_web_attack` 本身是对的（`normalizer.py::_wazuh_event_type` 确实产出该值）；真正缺口是另一分支产出的 `web_attack` 无人匹配，故该规则改为 `in ["wazuh_web_attack","web_attack"]`。
- **`auth_scheme` 取自请求头**：Zeek http.log 没有顶层 `authorization`（头在 `req_headers`，由 `ndr/zeek/site/shentong-httpheaders.zeek` 拼好），原实现恒空 → `normalizer.py` 回落用 `_AUTH_HEADER_RE` 从头文本解析，内置「Token/JWT 异常使用」的 bearer/jwt 分支才真正生效。
- **qtype 口径统一为 Zeek 数字码**：内置 DNS 隧道规则 `["16","TXT"]` → `["16"]`；前端 `ndr/frontend/lib/qtype.ts` 给出数字码 → 名字的提示。
- **检测器口径**：`/api/detector/coverage` 分子改用「窗口内投递量」（原来拿单调累计的 `delivered` 比窗口内文档数，比值只增不减 → `warn` 永不触发，且快照过期时报 `stale`）；`detector_enabled=false` 现在真的停消费/停投递/释放租约并在 `/stats` 暴露 `paused`；聚合 key 到上限不再静默丢弃（计 `agg_full`）；leader 续约改独立线程 + 墙上时钟（原来绑主循环，单轮超时就丢租约）。
- **其余口径修正**：`ingest_filter.py` / `wazuh.py` / `mcp/ndr_tools.py` 改读运行时 ES 索引名；`_with_degrade` 传真时间窗并区分「超时」与「ES 不可用」（原来一切异常都写成「已把时间窗对半重试仍失败」）；`fetch_window` 的网段条件下推 ES（不能下推的本地过滤并说明）；`record_conclusion` 的 status/severity 加枚举校验；`es_admin` 改 ES 地址会同步重渲染 Logstash 管道、ES 密码支持显式清空（`""` / `clear_password`）回落环境变量（**2026-10-03 作废**：连接信息整体不再可配，见「连接信息收口」一节）；`files.py` 的 `exists extracted` 过滤改本地判非空串；`wazuh.py` 的 pending 统计与 total 对齐；`triage_policy.py` 的开关文案不再谎称「无成功连接」；配了 `Site::local_nets` 时关掉 `private_address_space_is_local`（原来私网地址被判成"外部"）；前端八个面板不再把接口报错吞成空态、令牌/密码可清空、积压显示改真实队列深度、规则页补删除入口（仅非内置规则）。

**清理（死代码 / 死配置 / 注释）**

- 删：`ingestion/dedup.py`（两侧）、`ingestion/es_schema.py` 整条链、`rules/engine.py::match_count_rule`、`baseline/profile.py::window_observations`、`triage_policy.py` 的 `evidence_tier`/`cap_severity`/`should_escalate`（真源在智能体侧 `agent/backend/app/agents/triage_policy.py`）、`detector/handled.py::filter_unhandled`、`investigation/es_query.py::count`、六个「目录生成」函数、`ndr/frontend/lib/api.ts` 的三个零引用类型。
- 死配置：`es_events_src_fields` / `es_events_dst_fields`、`max_logs_per_window`、`digest_suppress_hours`、`digest_merge_family`、`CONFIG_KEYS`、compose 里两组 `ZEEK_*` 旋钮；`policy_skip_rules` 里的规则名不存在 → 改成真实名字（`内置-扫描尝试连接`、`内置-恶意文件传输`）。
- 注释与实现对齐：`ingestion/es_config.py`、`mcp/__init__.py` 的模块名、`agent-push-panel` 的 `queued` 语义、`push.py` 的 `recover()` docstring、`runner.py` 的「睡到分钟桶边界」、Zeek 保留策略与 `ZEEK_LOG_DIR` 等。
- ~~**只报告未改**（口径未定，等用户拍板）：`triage_policy.py::SUCCESS_CONN_STATES` 含 `RSTO`/`RSTR`（连接被重置，实际未成功），而 `_zeek_event_type` 把它们映射成 `generic`，两处对"成功连接"的定义不一致~~ → **已于 2026-10-03 彻底解决**：`RSTO`/`RSTR` 是「握手已建立、随后一方 RST 断开」，算握手完成；`SH`/`SHR` 从未完成握手，不算。语义收进 `conn_states.py` 一张表，三处调用点共用，见下节。
- **已知未动**：`investigation/tools.py` 的 `_timeline` / `_net_flows` 有与已修多来源截断同型的 `hits[:limit]`（风险更低）；`shentong:events:dispatch` 退役队列里积压的约 400 条（推送线路未部署，部署后 `DEL`）。

**门禁与验收**（2026-10-02，仓库根）

`.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py` All checks passed；`.venv/bin/pyright ndr/backend/app agent/backend/app tests/py` 0 errors / 0 warnings；`pytest tests/py --stack=ndr -q` **281 passed**；`--stack=agent -q` **195 passed, 86 skipped**；`ndr/frontend` 与 `agent/frontend` 的 `npx tsc --noEmit` 均 exit 0；`sh tests/zeek/run.sh` **ALL PASS**；`docker compose config -q` 对 `docker-compose.yml`、`docker-compose.deploy.yml` 及两份 +`docker-compose.wazuh.yml` 组合均通过。新增测试：`tests/py/test_detector_runner.py`、`test_detector_push.py`、`test_detector_coverage.py`、`test_investigation_query.py`、`test_mcp_tokens.py`、`test_rules_routing.py`。

**实机验收（2026-10-03，172.16.196.77，镜像 `d873953`）**：备份并覆盖 `docker-compose.deploy.yml` → `pull` + `up -d`，十个容器全 Up（`ndr-mcp` 与 `zeek` healthy）；镜像内新代码标记逐项命中；`/api/auth/me` 报 `default_password_in_use: true`、`/api/detector/coverage` 已是窗口口径（`delivered_interval`/`stale`/`delivered_window_est`）、`/api/agent-push` 有 `undelivered`/`retry_lost`/`retry_dropped` 与真实 `queue_depth`、`/api/detector/stats` 有 `paused`/`queue_failed`；ES 集群 green/unassigned 0、模板 200；Logstash 管道卷内 `ecs_compatibility => "disabled"`、近 5 分钟 0 条 WARN/ERROR、入库 4555 条/5 分钟；`exists ja4` 走查询层 = 2265（与 `must_not term ja4.keyword:""` 一致），原生 `exists` 仍 101 万；`account` 存在判定 = 0。`shentong:events:dispatch` 已无写入方（旧代码遗留约 400 条）。

### 2026-10-03 连接状态语义收口（`conn_state` 唯一事实来源）

起因是深度 QA 报告里留的一条「待拍板」：`triage_policy.SUCCESS_CONN_STATES` 含 `RSTO`/`RSTR`，而 `normalizer._zeek_event_type` 把它们标成 `generic`，两处对"成功连接"的定义不一致。用户追问「如何彻底解决这个问题」，复查后确认根因**不是那两个状态**，而是同一份 `conn_state` 语义被**手写三遍**（三份只要错一处，结果就静默翻转）：

1. `ndr/backend/app/ingestion/normalizer.py::_zeek_event_type` —— 翻事件类型标签；
2. `ndr/backend/app/triage_policy.py` —— `SUCCESS_EVENT_TYPES` / `SUCCESS_CONN_STATES` 判「有没有成功连接」（`has_success()`）；
3. `agent/backend/app/agents/prefilter.py::_looks_established` —— 兜底预筛分，第三次手写同一份白名单。

复查同时抓到**第二个更实的静默失效**（比 RSTO/RSTR 严重）：Zeek 的 `SH` = 「发了 SYN 又发 FIN、从没收到 SYN-ACK」= **没建立**，代码却因标签是 `connection_shutdown` 而把它算进"成功连接"（`has_success` 判 True、`evidence_tier` 判 T2、`_looks_established` 走成功分支）—— 方向是**该分析的被降噪**。

修法：新增 `ndr/backend/app/ingestion/conn_states.py` 与 `agent/backend/app/ingestion/conn_states.py`（**两侧逐字一致**，由 `tests/py/test_stack_consistency.py` 的字节比对守住），作为唯一事实来源：

- `CONN_STATES: dict[str, ConnStateInfo]`（`ConnStateInfo = (event_type, established)`）覆盖 Zeek 官方 13 个状态：`S0→scan_attempt/否`、`S1/SF/S2/S3/RSTO/RSTR→conn_established/是`、`REJ→rejected_connection/否`、`SH/SHR→connection_shutdown/否`、`RSTOS0/RSTRH→rejected_connection/否`、`OTH→generic/否`；
- `ESTABLISHED_CONN_STATES` 由表推导；`event_type_of()` / `is_established()` / `is_known()` / `produced_event_types()` 是唯一入口；**表外状态不静默**（每个未知状态进程内喊一次 warning，提示补表）；
- `normalizer` 只查表，不再写 if 链；`triage_policy.SUCCESS_CONN_STATES = ESTABLISHED_CONN_STATES`、`SUCCESS_EVENT_TYPES = {"conn_established", "conn_http"}`（**删掉 `connection_shutdown`** —— 这一刀修的就是 SH 坑）；`prefilter._looks_established` 改用 `is_established()`。

**行为变化（会影响告警口径，须记住）**：`SH`/`SHR` 不再算"成功连接"（`has_success` 判 False、`evidence_tier` 从 T2 降到 T1、内网常规流量预筛不再把它们当正常会话跳过）；`RSTOS0`/`RSTRH` 的标签由 `generic` 变成 `rejected_connection`（当前无规则引用该标签）；`RSTO`/`RSTR` 的标签由 `generic` 变成 `conn_established`（与分诊口径对齐，将来写 `event_type = conn_established` 的规则不会再漏掉它们）；`SH`/`SHR` 标签仍是 `connection_shutdown`。

**新增守卫**：`tests/py/test_conn_states.py`（49 条，两栈各跑一遍）——官方状态全集覆盖（Zeek 新增状态时 CI 先炸，而不是线上静默按 `generic` 处理）、逐状态 `(标签, 是否已建立)` 与文档口径一致、`normalizer` 产出标签 == 表、`has_success` 跟随表、SH 回归、未知状态限流告警一次、内置规则与智能体技能引用的 event_type 都有生产者（词表守卫，防引用一个永不产出的标签）；`tests/py/test_stack_consistency.py` 另加两侧 `conn_states.py` 逐字一致的字节比对。

**门禁（2026-10-03，仓库根）**：`.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py` All checks passed；`.venv/bin/pyright ndr/backend/app agent/backend/app tests/py` 0 errors / 0 warnings；`pytest tests/py --stack=ndr -q` **330 passed, 1 skipped**；`--stack=agent -q` **245 passed, 86 skipped**。

### 2026-10-03 连接信息收口：Wazuh 与 Elasticsearch 都不再由界面配置

Wazuh 与 Elasticsearch 都是**随本项目一起部署**的内置服务（`up -d` 一起起），所以「连哪台、用什么凭据」在部署时就已经确定，属于部署事实、不是用户偏好。但第 6 期把两者都做成了「存 `SystemConfig` + 界面填写 + 测试连接」：同一个事实有**两份来源**（`.env` 一份、库里一份），界面写一个地址、实际连另一个也不会报错，换人接手时还要重新问一遍口令。用户先后两次要求去掉，现已全部收口：

- **Wazuh**：`_cfg()` 只读环境变量（`ST_WAZUH_API_*`）—— `PUT /api/wazuh` 与 `POST /api/wazuh/test` 删除、密码不再打码回显、`SystemConfig.wazuh.params` 的历史行不再被读；「采集接入 → Wazuh」只剩状态 + Agent 清单 + 近 24h 入库量 + 规则下发（下发要真生效，见 :416 的 `overwrite=true` + 轮询校验）。**依据**：`ndr/backend/app/api/routes/wazuh.py` 的模块 docstring 与 `tests/py/test_wazuh_config.py`（钉住「旧入口不许回来」）。
- **Elasticsearch**：`es_config.RUNTIME_KEYS` 只剩**策略项** `es.events_index` / `es.retention_days`；连接三项（`es.url` / `es.username` / `es.password`）永远取 `settings.es_*`（部署时由 `.env` 的 `ES_*` → `ST_ES_*`，默认 `http://elasticsearch:9200`），库里的历史行不再被读；`PUT /api/es/config` 只收两个策略字段、`POST /api/es/test` 删除、`_mask()` 改名 `_public()` 且密码永不下发明文（只回 `password_set`）。前端「数据存储」去掉地址/用户名/密码/测试连接，「Logstash 管道」的 ES 地址改成只读展示。
- **写侧一并对齐**：Logstash 管道的 `elasticsearch { hosts => [...] }` 也是部署事实。原先 `PUT /api/logstash/params` 收 `es_host` 并落库（`logstash.params` 的第三份来源），现在 `ParamsIn` 只剩 `es_enabled` / `events_index`，`_effective_params()` 一律把 `es_host` 覆盖成 `settings.es_url`、`_save_params()` 落库前剥掉它；新增 `_resync_es_host()` 在后端启动播种时把**已生成**管道里的旧地址对齐到当前 `ST_ES_URL`（管道被人手工改过就只告警、不覆盖，返回 `manual-edit`）。**依据**：`tests/py/test_es_config.py` 九条（含三条 `_resync_es_host` 行为用例）。

**为什么策略项留在界面上**：`events_index`（日志落哪族索引）与 `retention_days`（留多久）改的是**数据策略**、不是「连到哪台机器」，且 30 秒 TTL 缓存内即生效、写侧 `invalidate()` 立即失效，属于管理员在运行期就该能调的东西 —— 与「连接信息」是两类，故意不一起收。Logstash 的**管道全文编辑器**同样保留（高级出口：临时加 filter 用），但它不再能改 ES 地址。

**丢卷重建的后果变了**：这两组连接信息不在库里，`docker compose down -v` 不会丢，也不需要重新填（改过 `.env` 才要 `up -d backend` 重建容器）。

**门禁（2026-10-03，仓库根）**：`.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py` All checks passed；`.venv/bin/pyright ndr/backend/app agent/backend/app tests/py` 0 errors / 0 warnings；`pytest tests/py --stack=ndr -q` **369 passed, 1 skipped**；`--stack=agent -q` **251 passed, 119 skipped**；`ndr/frontend` 与 `agent/frontend` 的 `npx tsc --noEmit` 均无输出。

### 2026-10-04 NDR 侧真待办收口：可信代理白名单 / Filebeat 解析失败 / MCP 独立门面 / 清理与退役队列

用户要求（`m13675`）：「完成 Zeek 的 3 天归档清理、NDR 侧真待办推进完成、给 MCP 切一层独立接口」。四件事一次收口，另加退役队列清空。

- **可信代理白名单（两侧 normalizer 同构）**：新增配置 `zeek_trusted_proxies`（`.env` → 容器 `ST_ZEEK_TRUSTED_PROXIES`，落在 `ndr/backend/app/config.py` 与 `agent/backend/app/config.py` 的同一契约块）。逗号或换行分隔、接受单 IP 与 CIDR、`#` 注释与 `/32` 均可，非法项丢弃并限量告警（`_MAX_TRUSTED_PROXY_WARNINGS=5`）。`_real_client_ip(doc, peer_ip)` 只在**直连对端落在白名单内**时才解析代理头，否则 `real_client_ip` 一律 NULL（`src_ip` 仍是 TCP 对端）；**清单留空 = 谁都不信**（fail-closed）。`_XFF_HEADERS` 增 `X-REAL-IP`、`_RAW_PROXY_HEADERS` 兜住大小写变体，`_http_fields(doc, log_type, peer_ip)` 增加第三个参数、调用点传 `src_ip`。**为什么放 normalizer 而不是 `ingestion/scope.py`**：agent 侧的 `scope.py` 是完全不同的东西（只有 MCP 取网段），放进去会破坏两栈同构；且**必须两侧同改** —— `tests/py/test_stack_consistency.py` 经 `tests/py/_dump_entries.py` 逐条比对两栈归一化结果，只改 NDR 会让测试样本的 `real_client_ip` 从 `198.51.100.77` 变 NULL 而失败。**为什么必须做**：转发头是客户端自报、可伪造，而 `real_client_ip` 已被规则引擎、字段目录、ES 查询、画像与 MCP 工具消费 —— 不设信任锚就等于让任何人在头里自报身份。测试：`tests/py/test_xff_respbody.py` 新增 `test_untrusted_peer_drops_proxy_headers`（非可信对端 / 空清单 ⇒ NULL）与 `test_trusted_proxies_accepts_host_cidr_and_list`（单 IP、`/32`、`/24`、逗号多项、`#` 注释、网段外、非法项），`test_real_client_ip` 改传可信对端（autouse fixture 把 `zeek_trusted_proxies` 设成探针同网段），`test_normalizer_fields.py` 的 HTTP 用例同法放行。
- **Zeek 侧补 `X-Real-IP`**：`ndr/zeek/site/shentong-httpheaders.zeek` 在 `@load base/protocols/http` 之后加 `redef HTTP::proxy_headers += { "X-REAL-IP" };`，`tests/zeek/batch3_test.zeek` 加断言。**坑**：成员必须**全大写** —— HTTP 分析器先把请求头名统一转大写，再拿去和 `proxy_headers` 比对，小写写法单测直接 `FAIL`。
- **Filebeat `ndjson` 解析失败不再落空壳文档**：用探针在真实容器上取到了失败事件的准确形态（停 normalizer → 写一行半行 `h{"ts":…}` 与一行裸数字 `17` → 直接读采集队列）：失败事件**解析出来的字段一个都没有**，错误挂在 `zeek.error`（`{"type":"json","message":"Error decoding JSON: invalid character 'h' looking for beginning of value"}`，裸数字那条是 `json: cannot unmarshal number into Go value of type map[string]interface {}`），而**原始那一行原样留在顶层 `message`**。据此 `_filebeat_parse_error()` 认这个标记（根级 `error` 也认），`_unwrap_filebeat_parse_error()` 用 `message` 再 `json.loads` 抢救：解得成对象就照常入库，解不出**返回 None 进死信**（`normalize_failed` 桶、限量告警 `_MAX_FILEBEAT_PARSE_WARNINGS=5`）；`normalize_zeek` 返回类型放宽为 `UnifiedLog | None`，`normalize()` 入口同样过闸（Zeek 与 Wazuh 一视同仁）。**没有改 Filebeat 配置** —— 不动已工作的采集链路。探针取证时 6 秒内采集队列从 0 涨到 **757**（≈126 事件/秒，链路本身健康），探针条目随后用 Lua 精确摘除。测试：新增 `tests/py/test_filebeat_decode.py`（6 例，两侧都跑）。
- **MCP 切独立接口**：见 §8 第 5 条的结案（新增 `ndr/backend/app/mcpapi.py` 门面 + `tests/py/test_mcp_boundary.py` AST 边界守卫）。
- **Zeek 3 天归档清理实机复验**：机制早已在（`cleanup_once()` 的两条 `find`），缺的一直是端到端证据。在跑的生产容器上放一个 mtime 4 天前、轮转命名、位于两层子目录的探针 → 到点的清理轮把它删掉（观察任务 `18:57Z` 命中），同一时刻活动 `conn.log` 仍在增长、Filebeat 存活、顶层归档 62 个 ⇒ 「保留 3 天」成立。**判定轮次的口径**：`cleanup_once` 每 `CLEAN_INTERVAL=3600` 秒一轮、从容器启动时刻起算（实测容器 `StartedAt=2026-10-03T02:54:31Z` ⇒ 轮次落在每小时 `:54:31`）；`cleanup_once` 成功路径**不打日志**，所以「日志没动静」不等于没跑。巡检表第 2 行已同步。
- **`shentong:events:dispatch` 退役通道清空**：`DEL` 掉 400 条（2026-10-03T02:48Z 的 `excluded` 低危摘要）。全仓确认该键**既无写入方也无消费者**（HTTP 推送早已取代 Redis 交接，`detector/push.py` 明确不再写、`runner.py` 改记 `undelivered`），留着只会让监控显示假积压。

**门禁（2026-10-04，仓库根）**：`.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py` `All checks passed!`；`.venv/bin/pyright ndr/backend/app agent/backend/app tests/py` `0 errors, 0 warnings`；`pytest tests/py --stack=ndr -q` **385 passed, 1 skipped**；`--stack=agent -q` **262 passed, 124 skipped**；`sh tests/zeek/run.sh` 四个测试文件全 `PASS`（`FAILS=0`）；`ndr/frontend` 与 `agent/frontend` 的 `npx tsc --noEmit` 均无输出。

### 2026-10-04 实机巡检收口：Logstash 暴露面 / 检测器告警刷屏 / 启动日志噪音

用户要求（`m13679`）：「回收 logstash 8080 的对外暴露；检测器日志被刷屏问题处理；小噪音处理」。三件事一次收口，来源是 `172.16.196.77` 的实机巡检（11 容器全 Up、ES green、7k~10k 事件/分钟、ja4/请求头/提取件等新字段全在）。

- **Logstash 端口收回回环**：`ndr/docker-compose.deploy.yml` 的 `logstash` 服务 `8080/9600` 由发布到 `0.0.0.0` 改为 `127.0.0.1` —— `8080` 是 `json_lines` 输入且**无鉴权**，发布到 `0.0.0.0` 等于同网段谁都能往 ES 灌数据；这两个口本来也只给**容器网络**用（归一化服务 POST `logstash:8080`、后端读 `logstash:9600`），宿主机排查走 `127.0.0.1` 就够。新增 `tests/py/test_deploy_exposure.py` 用编排文件钉住红线（ES / Postgres / Logstash 必须写死 `127.0.0.1`、Redis 默认必须是 `${REDIS_BIND:-127.0.0.1}`）。README §四第 14 条同步把 Logstash 列入「不许对外暴露」的必查清单。
- **检测器「已处理登记单桶达上限」告警限频**：`ndr/backend/app/detector/handled.py` 原来每丢弃一条登记就打一条 WARNING；实机流量下每个桶（10 分钟 / 5 万成员）都会被顶满，最近 2000 行日志**全被这一条占满**，真告警被淹没。改为模块级限频 `_CAP_LOG_INTERVAL_SECONDS = 60`：同类最多 60 秒一条，且下一条带出「本进程累计丢弃 N 条 / 近 60 秒 M 条」—— **计数不丢**（`handled.skipped` 仍进周期统计日志与 Redis `shentong:handled:docs:skipped`）。测试 `tests/py/test_handled_registry.py`（分桶上限、计数、限频、限频窗口过后重新告警）。
- **启动日志噪音**：`ndr/backend/app/main.py::_push_es_retention` 原来只要 `attempt > 1` 就打一条 info，而它每 5 分钟幂等复查一次、`attempt` 一直累加 —— 实机每 5 分钟刷一条「第 N 次尝试下发成功」（N 已涨到 15+），看着像一直在重试。改为：成功后**重置 attempt**，稳态复查只记 debug，只有「失败后重试成功」才记一条 info —— `第 N 次尝试下发成功（前 N-1 次失败）`；连续失败的告警口径不变（仍只在第 `_ES_SETUP_ATTEMPTS` 次一条，不回归）。测试 `tests/py/test_main_retention.py`（稳态不记 info、失败后成功记一条带次数、连续失败只一条 warning）。

**门禁（2026-10-04，仓库根）**：`.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py` `All checks passed!`；`.venv/bin/pyright ndr/backend/app agent/backend/app tests/py` `0 errors, 0 warnings`；`pytest tests/py --stack=ndr -q` **399 passed, 1 skipped**；`--stack=agent -q` **270 passed, 130 skipped**。


### 2026-10-04 内置规则质量评审与修复（7 条车道全量评审 + 落地）

来源：用户要求「派子 agent 从网络安全专家视角评审 NDR 内置规则质量」。7 条只读评审车道（注入 / Web-WebShell / 探测 / 凭证 / 网络威胁 / Wazuh+杂项 / 引擎语义）逐条评审 82 条规则，产出 [`docs/ndr-rules-quality-report.md`](ndr-rules-quality-report.md)（原始 7 份在 `docs/review/ndr-rules/`）。**评审后已全部落地修复**（规则 82 → 84 条）。

**引擎与链路（`rules/engine.py` / `rules/service.py` / `detector/*`）**

- `rules_for_log_type` 合并 `types + wild` 后**按 (priority, name) 重排**：原来两张表直接拼接、调用方「首个命中即停」，通配的 p5/p10（Wazuh 恶意软件告警、暴力破解）会被专有的 p25（参数 fuzzing）遮蔽。
- `build_rule_index`：**显式 `log_type eq X` 现在是权威的** —— 原来先判通配再看 explicit，导致「log_type eq wazuh + 通用字段」的规则反被归入通配集合（每条日志都跑）。
- `_FIELD_TYPES`：删 12 个僵尸键（`uri`/`request_body_len`/`response_body_len`/`rcode`/`answers`/`duration`/`orig_bytes`/`resp_bytes`/`proto`/`service`/`seen_bytes`/`issuer`/`server_name`），补 `content_type`/`tls_version`/`cert_issuer`/`cert_self_signed`，并给 `dst_ip` 登记 conn owner —— 否则 SSRF/云元数据规则的 `dst_ip eq 169.254.169.254` 分支在 conn 日志上**永不求值**（真实取证路径漏报）。
- `_match` 收口：条件必须给字段名（`whitelist: [{}]` 不再静默全命中）、`eq` 缺值不算相等、**`ne` 在空值上不再恒真**（`auth_scheme ne basic` 曾把「没带认证头」当成「不是 Basic 认证」放行）、`exists` 把布尔 `False` 当存在（`file_is_orig` 的 False 是有效取值）。
- `service.get_enabled_rules` 改 `order_by(priority, id)`：同优先级无二级键时命中归属随 DB 行序漂移。
- `_flush`：额度不足时**按严重度降序**投递（不再 FIFO）；新增**单规则每分钟上限**（`ST_DETECTOR_MAX_DIGESTS_PER_RULE_MINUTE=8`），超限计入 `dropped.rule_capped`；`aggregate._MAX_SET` 50 → 200（baseline 拿 `len(dst_ips)` 当 `distinct_dst_ips` 特征，50 会截断导致 2σ 失真），样本改为「最早 2 条 + 最新 1 条」。
- `frequency.FreqWindow`：长窗规则（6h）缺省冷却改为 `max(全局冷却, 本规则窗口)`，并支持规则自带 `cooldown` —— 原来 300s 全局冷却让 6h 规则每 5 分钟重复触发（单主机 6h 最多 72 条）。

**上游字段生产（`ingestion/normalizer.py`，两侧同改）**

- **从头文本解析 `Cookie` 与 `Content-Type`**（`_header_value`）：Zeek 的 http.log 没有这两列 → `cookie` 恒空，「会话跨IP复用」（critical 级会话劫持）与「反序列化 rememberMe」分支永不触发；`content_type` 恒空让「WebShell 上传」「上传类型不匹配」无从判定。
- **`weird.log` → `protocol_anomaly` / `tls_anomaly`**：采集面已关掉 Zeek 自带 notice，原来这两个标签只由 notice 产出 → 「协议异常」「TLS异常」两规则在**本部署永不触发**（零覆盖却看不出）。
- **x509 自签判定**：`cert_issuer` 原来只取顶层 `issuer`，而 Zeek 把签发者嵌套在 `certificate.issuer`（恒空）→「自签或异常证书」死规则。现解析嵌套并新增 `cert_self_signed`（subject == issuer，引擎无法比字段，只能在归一化层算）。
- **`_wazuh_event_type` 去掉 `sshd` 判据**：Wazuh 的 sshd 组同时覆盖**成功**登录，原来会把正常运维登录判成 `brute_force`，连带「暴力破解 / 高频认证失败 / 撞库」在无攻击时就报。
- `schemas` 两侧新增 `cert_self_signed`；`triage_policy.SUCCESS_EVENT_TYPES` 里的 `conn_http` **全仓无生产者**（HTTP 侧永远判「无成功连接」），换成真实存在的 `http_login`/`http_upload`/`http_request`。
- `config.web_login_path_regex` 补常见登录形态（`/wp-login.php`、`/admin/login.do`、`/api/v2/authenticate`、`/user/sign_in`）并加词首边界：原正则漏掉它们，让「登录接口爆破 / 密码喷洒 / 明文凭证传输」整链漏报。
- `policy_skip_rules` 移除「内置-恶意文件传输」：它 `severity=high ≥ min_severity=medium`，**永远不生效**（死配置）；顺带把该规则改为只报上传方向（`file_is_orig`），不再把软件更新/内部 JAR 下载全报 high。

**内置规则内容（代码里 82 条内置、启用 81 条：`ndr/` 与 `agent/` 两份逐字一致；库里另有 1 条已退役保留行，见文末「扫描规则改扇出」）**

- **P0**：`WebShell上传` 判据从「请求路径以 .php 结尾」改为「multipart + body 里真有 `filename="x.php"`」（原来 `POST /login.php→302` 报 critical、真上传却漏报）；`Log4Shell` 的 `ognl|spel` 加词边界（`/spellcheck` 曾报 critical）并补 `req_headers`/`resp_headers`（CVE-2021-44228 头向量漏报）；`命令注入` 允许分隔符后直接跟命令（`;id`/`|id`/`&&id` 曾全漏）；`大面积目标探测` 去掉恒真条件 `src_ip exists`（实为无条件按源计数）；`cookie`/`weird` 类死规则经上游修复复活。
- **P1**：新增方向/连接状态限定（横向移动、异常外联、外传、弱 TLS、敏感端口）；账号类 count 规则 key 加 `dst_ip`、抬高阈值（密码喷洒 5→8/5 分钟、登录爆破 15→30/10 分钟、撞库 3→5/30 分钟）并修 normalizer 的 `sshd` 误判；`DNS-TXT隧道` 改为「同源多个不同 TXT 名字」（原 key 含 query，语义相反）；`横向移动管理端口`/`内网慢速横向`/`服务枚举` 补方向与失败连接限定、阈值收敛；`多路径探测`/`暴力路径枚举`/`服务端错误突变` 补状态码过滤与白名单。
- **P2**：Wazuh 五条规则与等级脱钩（高危告警改按 `severity in [high,critical]`，FIM/策略违规/MITRE 加「非高危」闸门并降级）；`邮件滥用` 从「命中任意 SMTP」改为同源群发频率规则；`CSRF可疑来源` 描述改为与实现一致（已知测试域名黑名单，不是通用 CSRF 检测）；`危险HTTP方法` 去掉 OPTIONS/PUT/DELETE（常规业务）并白名单放行 CORS 预检；`Host头攻击` 限定 `source_system=zeek + log_type=http`（Wazuh 的 hostname 是 agent 名）。
- **新增两条补漏规则**：「内置-Bearer令牌高频使用」（把原 `auth_scheme in [bearer,jwt]` 的逐条误报改成 ≥60 次/10 分钟的频率规则）、「内置-单目标多端口深扫」（补「单目标多端口」漏报）。

**测试（新增 `tests/py/test_rules_quality.py`，两侧都跑）**：`_FIELD_TYPES` 无僵尸键、**规则引用的字段必须存在**（防写错字段名静默失效）、正则全可编译、路由全局 priority 有序、`_match` 收口语义、cookie/content-type 头解析、weird→异常事件类型、x509 自签、sshd 不再等于爆破、登录路径正则、Log4Shell 词边界+头向量、命令注入分隔符、WebShell 上传正反例、**最普通的正常 conn/http 流量不得命中任何逐条规则**（恒真/过宽条件护栏）、Wazuh 规则必须路由到 wazuh、单规则限速 + 严重度优先。

**门禁（2026-10-04，仓库根）**：`.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py` `All checks passed!`；`.venv/bin/pyright ...` `0 errors, 0 warnings`；`pytest tests/py --stack=ndr -q` **417 passed, 1 skipped**；`--stack=agent -q` **287 passed, 131 skipped**；`sh tests/zeek/run.sh` 全 `PASS`（`FAILS=0`）；两侧 `npx tsc --noEmit` 无输出。


### 2026-10 MCP 质量收口：失效的校验 / 死输出 / 覆盖缺口 / 文件内容工具

背景：对 MCP 做了专项 QA（工具面覆盖 + 空实现 + 死代码 + 逻辑）。19 个工具**没有一个是空壳函数**（两层都用 `TOOLS[name]["run"]` 分派表，逐个实现；签名与参数说明表 19/19 一致），但查出四类问题，已全部收口（工具 19 → 20）。

- **“空校验”修复：ToolCtx 按令牌会话复用**（`mcp/server.py`）。原实现每次工具调用都 `es_tools.ToolCtx()` 新建上下文，于是三件事**静默失效**：① `raw_evidence` 的「不能凭空引用」白名单（`if ctx.valid_refs and ...` 永远空集）；② `RAW_EVIDENCE_MAX=20` 的条数上限（计数永远从 0 开始）；③ `describe_data` 的 `case` 块永远为 null（agent 侧已就在注释里说明"NDR 侧的 ToolCtx 是新建的空上下文"）。现改为按**令牌 id** 缓存（TTL 6h、最多 64 个会话、单会话最多 2 万条 ref 超出即清空），并在 `_run` 这个**唯一入口**统一登记本次结果里的 ref —— 这样 `fetch_window` 这类 native 工具带的 ref 也能被后续 `raw_evidence` 认。
- **索引白名单**（`investigation/tools.py::_raw_evidence`）：ref 里的索引是调用方给的，叠加上述失效等于“MCP 令牌持有者可以读 ES 里任意索引的任意文档”。现只允许运行时 `es.events_index` 的索引族（`shentong-events-*`），其余直接报错。
- **死输出清理**：`describe_data` 的 `case` 块与 NDR 侧 `ToolCtx.case` 字段删除（MCP 工具不收参数，永远拿不到案件；agent 侧本来就在自己拼 `case`）；`get_event` 的 `dispatch` 空壳块改成一句 `delivery_note`（NDR 从第 5 期起就不记投递指纹，返回一个只有 note 的"伪结构"只会误导模型），工具描述同步改成「取已有结论」。
- **新工具 `file_content`**（提取件内容）：采集面批 4 的文件提取与下载入口只在 NDR Web API 上（要管理员 JWT），**智能体拿不到** —— 模型知道"有个文件"却看不到内容，采集做了、分析用不上。新工具按 fuid 取回**有界**内容（默认 64 KiB、硬上限 1 MiB，`encoding=text|base64`）与元数据，取数校验与前缀路径校验与下载路由**完全同源**（`is_valid_fuid` / `lookup_extract` / `resolve_extract_path` 经 `mcpapi` 转发）；完整文件仍走 `/api/files/{fuid}`（响应里回 `download` 路径）。
- **智能体侧补上三个可调工具**（`agent/.../investigation/tools.py`）：`get_rule`（取规则原文——摘要只带规则名与严重度，模型无法回答"这条为什么被判可疑"）、`list_filters`（兑现「让智能体看到两道闸门、别把被过滤读成没异常」的文档承诺）、`file_content`。原 `get_event` / `record_conclusion` / `detector_status` / `baseline_lookup` 仍无模型可调入口（`fetch_window` / `list_networks` 由 agent 内部调用）。
- **结论回写真正落地**（新增 `agent/.../investigation/ndr_writeback.py`）：NDR 后台「智能体对接 → 写回结论」面板与 `get_event` 读的是 NDR 结论表，而那张表**只有** MCP 的 `record_conclusion` 会写，智能体从不调它 ⇒ 面板永远为空、`ConclusionRecord` 全仓唯一写入方形同虚设。现改为在调查收尾（`service.investigate` 落库之后）**用确定性代码**按案件的事件组指纹逐条回写（每次最多 20 组，判定映射：failed→pending / 非 succeeded 或无攻击链或 contradiction→inconclusive / 有链且 confidence≥0.6→true_positive / 否则 suspicious），旁路失败不影响本轮结果。
- **一致性小项**：字段目录补 `cert_self_signed`（bool）与 `log_type_known`（bool，模型可筛白名单外的流）；`describe_data` 的 `lookback_limit_days` 在 agent 侧改为**透传 NDR 的值**（原来被本地静态配置覆盖，而 NDR 那个是跟着运行时保留期走的）；技能 `tools` 字段的校验从「只认脚本工具注册表」改成「脚本工具 ∪ 调查工具」（原来声明 `search_events` 会被判"工具不存在"）；`mcp_client._fresh_session` 加**单飞锁**（并发首调会建两条会话并泄漏一条）；`ndr_tools.execute` 改名 `dispatch`、取数调度收归门面 `mcpapi.execute_es_tool` —— 前者是名字里带 execute 会被静态扫描当成动态执行端点（实际参数是工具名），后者让 MCP 侧只有一个取数调度点。

**测试**：新增 `tests/py/test_mcp_coverage.py`（27 例，按栈分配）：注册表与调度表一一对应、签名与参数表不漂移、上下文按令牌复用且 ref 跨调用累积/有上限、`raw_evidence` 拒绝非事件索引、证据条数上限生效、`file_content` 的正/反例（含截断与 base64 回环）、智能体三个新工具的转发参数与必填校验、结论回写的判定矩阵/逐指纹写入/无指纹或无 MCP 时跳过/被拒时不抛、字段目录覆盖 `UnifiedLog`（防漂移）、技能工具名校验认两套注册表。

**门禁（2026-10-04，仓库根）**：`.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py` `All checks passed!`；`.venv/bin/pyright ...` `0 errors`；`pytest tests/py --stack=ndr -q` **431 passed, 14 skipped**；`--stack=agent -q` **300 passed, 145 skipped**；`sh tests/zeek/run.sh` 全 `PASS`。


### 2026-10 界面口径：网卡下拉只留物理网卡 + 界面不再出现 Zeek/Wazuh 字样

用户要求：「① 监听网卡下拉只显示物理网卡，过滤掉虚拟网卡与环回接口；② 界面不体现 Zeek/Wazuh 文字，一律叫网络采集器 / 主机监控」。

- **网卡下拉只留物理网卡**：采集器容器的 `write_interfaces()`（`ndr/zeek/entrypoint.sh`）逐张网卡写 `physical` 字段，判定依据是 sysfs 的 `/sys/class/net/<n>/device` 链接是否存在 —— **只有它是 host 网络**，能看到宿主全部网卡的 sysfs（后端容器只能看到自己的 eth0，所以判定不能放后端）。后端 `_read_interfaces()`（`api/routes/zeek.py`）只返回 `physical=true` 的项，并用名字模式（`lo|docker*|br-*|veth*|virbr*|vmnet*|vboxnet*|tun*|tap*|wg*|tailscale*|zt*|dummy*|ifb*|nflog|kube*|cni*|cali*|…`，忽略大小写）兜底——旧镜像的 `interfaces.json` 没有 `physical` 字段时也不会把 docker0/veth 塞进下拉。实机核对：16 张网卡里只剩 `ens160`/`ens192` 两张（`/sys/class/net/*/device` 与名字过滤结果一致）。
- **界面文案去掉厂商字样**（用户可读处一律「网络采集器 / 主机监控」）：
  - NDR 前端：采集/网段/总览/首次向导/运行状态/ES 与 Logstash 面板/错误条标签，共 8 个文件；
  - 后端**返回给界面**的消息：`/api/zeek/interface` 的 `note`、`/api/wazuh` 的 HINT 与全部 API 报错文案；
  - **内置规则名与描述**：11 条规则改名（`内置-Wazuh高危告警` → `内置-主机高危告警` …、`内置-Web攻击（Wazuh规则组）` → `内置-Web攻击（主机监控）`），描述里的「Wazuh/Zeek …」改成「主机监控：… / 网络采集器：…」。规则名是 upsert 的键，所以 `main._seed` 新增 `_RENAMED_BUILTINS` **就地改名迁移**（每次启动幂等；新名已存在才删旧行）——不迁移会新旧两行并存，而旧行还带着用户设过的启用状态。
- **明确不动的边界**（改了要付数据迁移代价，且不是界面散文）：API 路径（`/api/zeek/*`、`/api/wazuh/*`）、配置键与环境变量（`ST_ZEEK_*`、`ST_WAZUH_*`、`zeek.*`）、`source_system`/`log_type`/`event_type` 的**内部枚举值**（`wazuh`、`wazuh_high_alert`、`wazuh_web_attack`…，已落在 1200 万+ 存量文档里）、代码注释与文档。这些只出现在技术下拉/条件编辑器与运维文档中。

**顺手修的既存 lint**（都在本次改动的同一行附近，oxlint 直接拦）：ES 面板的嵌套三元提成 `healthVariant()`；ES/Logstash/首次向导里 5 个 `<label>` 补 `htmlFor`+`id`，3 个只是小标题的 `<label>`（下面不是表单控件）改成 `<p>`。

**测试**：新增 `tests/py/test_zeek_interfaces.py`（6 例：physical 过滤、旧格式名字兜底、文件缺失/坏 JSON 回空、入口脚本必须按 sysfs 标记）；`test_rules_quality.py` 新增「规则名与描述不得出现 Zeek/Wazuh」与「改名映射必须旧名已不在、新名确实在」两条护栏；原引用旧规则名的两处测试同步更新。

**后续（同日）**：用户要求「采集接入」页不要再显示主机监控面板的标题/说明/连接信息，已按列表逐项删掉：
卡片标题「主机监控接入」、整段说明文字（包括 `.env` 的 `WAZUH_API_*`、“日志走另外一跳”那段），
以及连接信息行（`API 已连通 / https://wazuh-manager:55000 / 用户 wazuh-wui / 密码 已设置 / 连通`）。
保留：刷新按钮、`API 版本 / 集群模式 / Agent 在线 / 近 24h 入库量` 汇总行、Agent 列表、自定义规则下发。
连接是否可达与入库量在「运行状态」页仍有（那里是运维看板，不在采集配置页）。

**后续（同日）**：用户要求把侧边栏顶部的 logo 搬到**全局页头**，并补上告警铃铛 / 当前用户 / 退出。已新增 `components/topbar.tsx`：`fixed inset-x-0 top-0 h-14 z-40`，宽度铺满、滚动不动；左侧是 logo（`深瞳 · NDR` + 齿轮，仍链到 `/admin/settings`），右侧依次是告警铃铛（带计数徽标 + 下拉面板）、当前用户名、退出登录（文字版）。为此：侧边栏改为 `top-14` + `h-[calc(100vh-3.5rem)]`，正文改 `ml-56 px-6 pb-6 pt-20`（页头 `h-14` 对就的是 `top-14` / `pt-20`，改高度时三处一起改）；侧边栏不再放 logo 与退出按钮，只留导航与「仍在用出厂口令」提醒。
铃铛的语义（本页自己聚合，**不新增后端接口**）：把需要动作的运行事实折成一个数，点开每条可跳到对应页 —— 检测器暂停、隔离队列非空、Redis 内存告警、归一化队列 >80% 上限、摘要推送未启用、推送待重发 N 批；数据源是既有的 `/api/detector/stats`、`/api/agent-push`、`/api/auth/me`，取不到就当没有（不报错、不挡页），30 秒一轮。登录页与首次向导页没有页头（那两页不属于后台外壳）。

**再后续（同日）**：用户要求删掉 logo 右边的齿轮图标、**取消「系统配置总览」这个页面与入口**、logo 改为不可点。已：① `topbar.tsx` 去掉 `Settings` 图标，logo 从 `<Link>` 改成纯 `<div>`（不可点、无 hover）；② 删除 `ndr/frontend/app/admin/settings/page.tsx`（目录一并消失），`/admin/settings` 不再存在（书签会 404）；③ 全前端确认再无 `/admin/settings` 引用。配置项本来都在左侧各页里（采集接入 / 监控网段 / 数据存储 / 过滤规则 / 智能体对接 / 账户），不需要一层索引页。

**门禁（2026-10，仓库根）**：ruff `All checks passed!`；pyright `0 errors`；`pytest tests/py --stack=ndr -q` **438 passed, 14 skipped**；`--stack=agent -q` **303 passed, 149 skipped**；`sh tests/zeek/run.sh` 全 `PASS`；两侧 `npx tsc --noEmit` 无输出。


### 2026-10 「总览」页：默认落地页 + 服务器/组件/威胁/流量与协议 + 全页图表化

用户要求：「将侧边栏运行状态上移到首页作为页面进入的默认页面，同时改造运行状态页面以图表方式显示各个数值」，随后补充要展示：**服务器状态（CPU/内存/磁盘圆环）**、**组件状态呼吸灯（zeek/wazuh/redis/logstash/elasticsearch/归一化/分析智能体）**、**威胁事件统计**、**24h 流量捕捉曲线**、**24h 协议分析占比圆图**。计划阶段定了三件事：趋势数据**后端加采样**、呈现方式**数字块 + 图表混合**、入口**置顶 + 默认跳转 + 改名「总览」**。

**入口（路由不变）**：`components/nav.tsx` 把「总览」（原「运行状态」）放到第一项、icon 换 `LayoutDashboard`，**href 仍 `/admin/status`**；`/` 的重定向写进 `next.config.mjs` 的 `redirects()`（`/` → `/admin/status`，307）；`app/admin/status/page.tsx` 标题改「总览」，原 `app/page.tsx`（内含 `redirect()`）**已删**——原因见下面「上线复验」。

**后端（4 个新端点 + 1 个采样）**：

- **检测器历史采样**（新增 `detector/history.py`，接线在 `runner.py` 统计块）：以前 `shentong:detector:rates` 每次 `HSET` **覆盖**，界面根本拿不到历史。现每 `ST_DETECTOR_STATS_LOG_SECONDS`（默认 300s）把快照 LPUSH 进 `shentong:detector:history` 并 `LTRIM` 到 288 条（24h）+ 7 天 TTL；采样里除既有 `d_*` 与累计计数器外，新增**本区间按严重度增量**（`d_digest_sev_*`，走既有 `rate_prev` 增量机制）与**本区间按规则计数**（`by_rule`，用 `digest_rule_*` 前缀计数器、**读完即清**，否则会变成进程启动以来的累计）。`GET /api/detector/history?limit=288` 时间正序返回。
- **`GET /api/system/metrics`**（新增 `api/routes/system_metrics.py`）：CPU 取两次 `/proc/stat` 差值（间隔 `ST_SYSTEM_METRICS_CPU_SAMPLE_SECONDS`，idle 含 iowait）、内存用 `MemAvailable`（比 `MemFree` 贴近 `top`）、磁盘 `shutil.disk_usage("/")`，另回 `load_1m` 与原始字节数。**在容器内读就够**：backend 未设 `mem_limit`/`cpus`，`/proc` 与根分区就是宿主的；任一项读不到 → 字段 `null` + `notes`，**端点不 500**。
- **`GET /api/health/components`**（新增）：七盏灯一次算完，判据全在 `judge_*` 纯函数里（`ok/degraded/down/unknown`）：ES=cluster health、Redis=PING+内存告警线、Logstash=9600 探活+重载失败数、网络采集器=近 5/30 分钟有无 zeek 文档、主机监控=管理 API 可达+近 24h 入库量、归一化=近 2/15 分钟有无文档入库（它是唯一写 ES 的角色）、分析智能体=`agent-push` 的 `active`/`last_success_at`（**未配置 → unknown，是「不知道」而不是「坏了」**）。**一个 ES 往返**（近 30 分钟按 `source_system` 的 `max(@timestamp)`）喂三盏灯；结果**进程内缓存 30s**（页面 15s 轮询）。每个探测都过 `_guard()`：**任何一个探测失败只影响它自己那盏灯**（总览页不能白屏）。
- **`GET /api/stats/overview?hours=24`**（新增）：一次 ES `_search` 同时出**流量**（`date_histogram` 1h + `sum(bytes_out/bytes_in)`，**必须过滤 `log_type=conn`** —— HTTP 文档的 `bytes_in` 取自 `response_body_len`，不过滤就把同一份响应字节重复计一遍）与**协议占比**（`log_type` terms top15 + other；顺带按 `log_type_known` 分桶，好在图上注明「白名单外 X% 只入库不进检测」）。**进程内缓存 300s**（失败**不写缓存**，下一轮能立刻重试），命中回 `cached=true`。
- **配置新增**：`ST_DETECTOR_HISTORY_KEY`/`_MAX`（288）、`ST_STATUS_PROBE_CACHE_SECONDS`（30）、`ST_STATUS_AGG_CACHE_SECONDS`（300）、`ST_SYSTEM_METRICS_CPU_SAMPLE_SECONDS`（0.15）。

**前端**：新增 `components/status-charts.ts`（11+ 个**纯函数** option 构造：圆环 / 五段速率漏斗 / 速率与队列趋势 / 严重度环 / 规则 TOP / 流量曲线 / 协议圆图 / 丢弃原因 / 投递重发 / ES 按天双轴 / Logstash 吞吐 / 基线维度 / 画像风险 / 覆盖率）；`components/status-panel.tsx` 重写为五个带锚点的分区（服务器 / 组件 / 威胁事件 / 流量与协议 / 链路细节），12 个接口 `Promise.all` + `loadInto` 并行取（单接口失败只影响对应卡片），保留 15 秒自刷新与开关；`globals.css` 加呼吸动画 keyframes（ok 3s 慢呼吸、degraded 1s 快闪、down/unknown 静止，**尊重 `prefers-reduced-motion`**）；`lib/api.ts` 补 12 个类型。

**顺手修掉的既存缺陷（图表化必需）**：`packages/ui` 的 `Chart` 原来在 `useEffect([option])` 里 `dispose()` + `init()` —— 轮询页面每 15 秒就会把每张图重建一次（闪 + 白付成本）。现改为**实例只建一次、option 变化走 `setOption(option, true)` 原地更新**（`height` 变化单独 `resize()`）。这条对智能体侧的 `/dashboard` 同样生效。

**测试**：新增 `tests/py/test_detector_history.py`（写入有界/TTL、读取时间正序与容错、区间计数用后即清、严重度增量不为负、**静态断言 runner 统计块确实调了采样**）、`test_system_metrics.py`（`/proc/stat` 与 `/proc/meminfo` 解析、计数器回退不算负载、端点缺指标不 500）、`test_health_components.py`（判据边界、七盏灯齐全、**单个探测抛异常只影响它自己**、30s 缓存与 TTL=0 关闭缓存）、`test_stats_overview.py`（查询结构必须只在流量侧过滤 conn、字节/秒与百分比换算、缓存命中、失败不缓存、ES 异常降级）。共 80 例。

**门禁（2026-10，仓库根）**：`.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py` `All checks passed!`；`.venv/bin/pyright ...` `0 errors`；`pytest tests/py --stack=ndr -q` **518 passed, 14 skipped**；`--stack=agent -q` **304 passed, 228 skipped**；两侧 `npx tsc --noEmit` 无输出。

**上线复验补修（同日，两处本地门禁全绿也没抓到的）**：

1. **ES 响应不是 dict，也不是 Mapping** —— `/api/stats/overview` 实机回「ES 返回了非预期结构」、流量曲线与协议圆图全空。原因：`elastic_transport.ObjectApiResponse` 的 MRO 是 `[ObjectApiResponse, ApiResponse, Generic, object]`，**既不是 `dict` 也不是 `Mapping`**，只是鸭子类型实现了 `.get`/`__getitem__`；而 `_fetch` 拿 `isinstance(resp, dict)` 当有效性判定（第一版修成 `isinstance(resp, Mapping)` **仍然错**）。本地测试全用 dict 桩，所以完全没抓到。**改为不做类型判定、直接按鸭子类型用，把 shape 解析包进 try**（解析真失败才落 `error`）；测试桩 `_EsObjectResponse` 改成**不继承 Mapping** 的鸭子类型对象，以后再有 `isinstance(resp, dict/Mapping)` 直接红。
2. **`/` 的 307 不带 `Location`** —— 实机 `curl localhost:3000/` 只看到 `307 Temporary Redirect` 且无 `Location`，`curl -L` 原地不动；返回的 HTML 是 `<html id="__next_error__">` 错误外壳，靠 `NEXT_REDIRECT` 摘要让客户端 JS 跳，还被 `s-maxage=31536000` **缓存一年**。原因：在 App Router 里对**静态页**调 `redirect()`，Next 把重定向烘进错误外壳而不是回重定向响应。**改为 `next.config.mjs` 的服务端级 `redirects()`**（真回 `Location`、不依赖 JS、不进页面缓存），并删掉 `app/page.tsx`（留着它只能产生坏 307）。

**修订（同日，用户口径）：协议占比只算「协议识别类」日志**。原实现是 `log_type` 全量 `terms`（实机 24h 里 `conn` 一家 1.86M 条占 56%、`syslog` 570K、`weird` 201K —— 那张饼图实际上是「我们的日志构成」，不是协议占比）。现改为**白名单 `ST_STATS_PROTOCOL_LOG_TYPES`**（`dns,http,ssl,ssh,ftp,smtp,smb,kerberos,ntp,dhcp,snmp,rdp,mysql,pgsql,radius,ldap,modbus,quic,websocket,mqtt…`），查询用 `terms.include` 限住；百分比分母 = **协议类文档总数**（top N 之和 + `sum_other_doc_count`）；被排除的量单独一个 `filter` agg 回 `excluded_docs` / `excluded_percent`，卡片上写「另有 X% 为 conn 流记录/异常/主机日志等非协议日志，未计入」——**不静默消失**。

- 选白名单而不是黑名单的理由：实机确实混进了 `analyzer`（4.5K）、`wazuh`（2K）这类名单外的新类型，黑名单得不停地追着加；白名单则默认不上图，要加改配置一行。
- **口径区别必须写清**（已写进 config 注释、README 配置表、`log_types.py` 的 docstring）：这张图看的是「协议」，与 `ST_ZEEK_EVENT_LOG_TYPES`/`_OPS_`（决定谁进检测）**不是一回事**。所以 `ntp`/`dhcp` 属 ops（不进检测）但会出现在图上；`conn`/`weird`/`files` 属 event（进检测）但不该出现在图上。
- 旧的 `unclassified_docs`/`unclassified_percent`（“白名单外只入库不进检测”）已随本次改写删掉：它与新口径分母不同、摆在一张卡片上只会让人算不清；那个信息在「数据存储/类型分布」与 `log_type_known` 字段里本来就能看。
- 测试（`test_stats_overview.py`）：断言白名单里**不得**出现 conn/weird/files/notice/x509/syslog/stats/reporter、必须含 http/dns/ssl/ssh/mysql/pgsql/smtp/ftp；断言 `excluded` 的 `must_not` 就是同一份白名单；新增加只排除非协议日志时的除零边界用例（协议图为空、未计入 100%）。

**修订（同日，用户口径）：严重度分布与协议占比改成实心饼图**。原来两张图都是圆环（`radius: ["45%", "68%"]` / `["42%", "66%"]`），用户要求**实心圆形**显示比例。`components/status-charts.ts` 的 `severityOption` 与 `protocolPieOption` 改成单值半径（`"68%"` / `"66%"`），中心点与图例不动；圆环只留给真正该是环的图（CPU/内存/磁盘、队列/投递容量、投递覆盖率），它们表达的是「占了多少额度」，有中心数字的需求。

**再修订（同日，用户口径）：两张饼图加指针（指引线）+ 旁边文字**。两张图不能只靠 tooltip/图例，要用指针把每块的内容标在圆外：

- `severityOption`：`label.formatter = "{b} {c} 条 ({d}%)"`（5 个严重度，连带条数一起标）；
- `protocolPieOption`：`label.formatter = "{b} {d}%"`，另设 `minShowLabelAngle: 6`——协议是长尾，`quic 0.02%` 这类小块的标签会把图糊满，所以**角度小于 6° 的块不标**（块本身仍在图上，看 tooltip/图例）；
- 两者都开 `labelLine`（`length: 8, length2: 10, smooth: true`）+ `labelLayout.hideOverlap`，并 `avoidLabelOverlap`；
- **半径从无标签时的 68%/66% 收到 52%/50%、中心点上移到 46%**：不收小就没有位置放指针与文字。
- 卡片加高（饼图 260 → 300；严重度那一行三张同高 220 → 280），否则标签会被挤在图里。
- 四个新用到的键（`minShowLabelAngle`/`labelLayout`/`labelLine`/`avoidLabelOverlap`）已在本仓 `node_modules/echarts/types` 里逐个核对存在，不靠猜。

### 2026-10-04 基线与画像实机 QA：六处修复（含三处假阳性来源）

用户要求「QA 一下服务器上基线/画像的实际运行状况，有什么 BUG 需要修」。先拿实机数据，再定性，再修 —— 全部结论都有库/接口/日志证据。

**先看运行状况（这部分是好的）**：检测器心跳有值；`entity_profiles` 567 条（会话 441 / 账号 126）、`baseline_stats` 1458 行（486 个 IP × 3 维度），都在实时更新；`GET /api/baseline`、`/profiles?min_risk=`、`/stats?ip=`（真实 IP 回 3 个维度，读写 key 格式一致）全部 200；无一条落库失败。观测期 7 天内 `warmed=0` 属预期。

**但查出 6 个问题，其中 3 个是假阳性来源**：

1. **「非常用时段」把每个整点当异常**（假阳性最大来源）。判据分母只算历史出现过的时段，新时段恒为 0% < 1% ⇒ 每个整点、每个活跃实体各报一次。实机：risk>0 的 54 条里 **40 条**是这个原因，10/11/12/13/14/15 时各 3~9 个（明显整点批量）。**修**：新增 `ST_PROFILE_HOUR_MIN_COVERAGE`（≥8 个不同时段）与 `ST_PROFILE_HOUR_MIN_AGE_HOURS`（画像 ≥24h）两个门槛，三条件同时满足才判。
2. **「会话跨源 IP」不分 v4/v6**（假阳性第二来源）。实机被判的 5 条**全部**是双栈（v4+v6）或纯 v6 换地址，没有一条是真的多 IPv4；最像真问题的那个是 iPhone+微信 UA，`110.185.129.127`(v4,108 次) 与 `240e:398:...`(v6,8 次)。**修**：只在**同族内** ≥2 个才算（v4∩v4 或 v6∩v6），跨族不算。
3. **新源 IP 对 v6 一律算新**。IPv6 隐私地址（RFC 4941）在同一 /64 内轮换是常态。**修**：v6 只在 **/64 前缀**也新时才算。
4. **风险分只升不降、没有风险时间**。只在有理由时写 `risk_score`，实体不再异常后旧值永久保留 —— 实机 4 条 risk≥0.6 的画像 `last_seen` 是 11:56~13:58（已 2~4 小时没再出现），却一直挂在总览「画像风险 TOP」；而 `updated_at` 每轮观测都刷新，**无法判断风险新旧**。**修（用户选 A）**：本轮无理由就归零 + 清空理由 + `risk_at` 置空（新列 + 启动迁移 ALTER）；有理由则写 `risk_at`，总览 TOP 的 tooltip 显示判定时间。
5. **`baseline_stats` 没有保留期**。全仓零清理逻辑（`profile.cleanup()` 只删画像）；key 是 `{src_ip}:{feature}`，被扫过一次的 IP（尤其外网/攻击者）永久留 3 行；且 `first_seen` 无索引，而 `snapshot()` 每次轮询都 `COUNT(*) ... WHERE first_seen <=`（实机 seq_scan 已 1660）。**修**：新增 `ST_BASELINE_RETENTION_DAYS`（90，按 `updated_at` 清理，挂在 `flush()` 的清理段、不依赖画像开关）+ `first_seen`/`updated_at` 两个索引（模型 + 启动迁移 `CREATE INDEX IF NOT EXISTS`）。
6. **心跳计数语义混乱**。`anomalies`/`numeric_keys` 是**上一轮的值**（覆盖写），`observed`/`numeric_samples`/`flushes`/`profiles_*` 是累计，混在一个 dict 返回 —— 实机 `anomalies=0` 而库里有 54 条 risk>0，读的人会当成「没有异常」。**修**：改名 `anomalies_last_round`/`numeric_keys_last_round`，另给累计 `anomalies_total`/`anomaly_rounds`；前端类型同步并标明两类语义。
7. **顺便修掉 `/api/baseline` 没缓存**：总览页 15 秒轮询 → 每次 2 条 `COUNT(*)` + 一次 Redis 连接，而项目其它轮询端点都做了 30s/300s 缓存。**修**：`snapshot()` 改成**一条聚合 SQL**（`count() FILTER (WHERE ...)` 一次出 total 与 warmed）+ 端点复用 `ST_STATUS_PROBE_CACHE_SECONDS`（30s），响应带 `cached`。

**顺带发现的缺口**：基线是第 8 期迁移过来的核心逻辑，但 `tests/py` 下**没有任何专门测试**（只有零散提及）。本次补三个文件：`test_baseline_profile.py`（17 例）、`test_baseline_stats.py`（10 例）、`test_baseline_engine.py`（4 例）。

**未改的两处（记下口径）**：`paths` 采集了但判据里没用（detect 只看新 IP/新 UA/时段/跨 IP/失败激增），属死数据、还被静态资源挤占 30 条上限；会话画像的展示名是 cookie 哈希前 8 位，运维看不懂 —— 两者都是隐私/展示取舍，要动得先定口径。

### 2026-10 画像展示与路径判据 + 硬编码审计（通用产品化）

用户定了两个口径，并加一项全局要求：

**一、界面只展示账号画像 + 关联服务端 IP**（会话展示名是哈希，看不懂。早就该改）。

- **新增服务端 IP 字段**：`EntityProfile.dst_ips`（JSONB，`{被访问的资产 IP: 次数}`）+ 启动迁移 ALTER；
  `_accumulate` 记 `entry.dst_ip`。为什么要新字段：原来只记客户端源 IP，界面无法回答「这个账号在哪几台服务器上活动」。
- **展示层只取账号**：`top_anomalies(..., kind=ACCOUNT)`，接口 `/api/baseline` 传账号过滤；
  前端标签变成 `账号名 · 服务端IP`（tooltip 给服务端 IP 全量 + 来源 IP + 理由 + 判定时间）。
- **会话画像仍在算**：摘要标签（`baseline.profiles`）与 MCP `entity_profile` 都还看得到会话异常 ——
  只改「展示」，不动检测能力，包括 MCP 的 `anomalies_only`。

**二、增加拿路径判异常，只留接口、过滤静态资源**。

- 实机证据：会话画像的 `paths` 里全是前端 js/css/图片/字体（次数最多，把 30 条上限占满了），有价值的接口路径反而进不来。
- 采集侧就过滤：`api_path()` 按 `ST_PROFILE_PATH_INCLUDE_REGEX` + `ST_PROFILE_PATH_EXCLUDE_REGEX`
  决定要不要记；任一为空 = 那一步不过滤。
- **默认只用排除名单（include 留空）—— 与用户字面口径的差异，有实机证据**：部署后一查库，该环境的真实接口是
  `/seeyon/rest/…`、`/pty/mad/user/…`，**不含 `/api/`**；若默认要求 `/api/`，会把真实接口全滤光、一个异常也报不出来，
  而该滤的 `.css/.png` 反倒留着。所以默认排掉静态资源与页面后缀（`.js/.css/图片/字体/.html/.jsp/.php/.do…`），
  要再窄化就填 include。（库里当时已积了 5237 条不合口径的旧路径值。）
- **老数据自愈**：`update_profiles` 合并前先按当前口径过一遍已有的 `paths`（`_kept_paths`），
  静态路径在该画像再次被观测时被剔掉，不需要额外的数据迁移。
- 新增判据「新接口路径」+0.25，且要求画像已认识 ≥`ST_PROFILE_PATH_MIN_KNOWN`（默认 3）条，
  否则刚建的画像「第一条路径就是新的」等于白报。MCP 的权重说明同步。

**三、硬编码审计（通用产品发布）**：把「服务器网络环境产生的内容」从产品代码里清出去 ——
用户的说法很准：这些属于**部署配置/用户数据**，不是代码。审计结果与整改：

| 位置 | 原值（客户环境） | 整改 |
| --- | --- | --- |
| `agent/edge_config.py` | `EDGE_API_KEY="qaz@7410"`、`EDGE_MODEL_NAME="/opt/models/Qwen3.8-2B-Q8_0.gguf"` | 改为 `ST_EDGE_API_KEY` / `ST_EDGE_MODEL_NAME` / `ST_EDGE_PORT` / `ST_EDGE_BASE_PATH`（默认空 / 空 / 8080 / `/v1`，与环境无关）|
| `ndr/config.py` + `compose`×2 + `entrypoint.sh` | 网卡默认值 `ens224`（三处写死） | 默认留空；`entrypoint.sh` 新增 `auto_iface()` 按 sysfs 自动取第一块**物理**网卡（优先 `operstate=up`），挑不到就显式报「没有可用监听网卡」+ 哨兵 unhealthy + sleep，不拿空名字去启动 Zeek（避免又一个重启循环）|
| 前端网卡输入框 | placeholder `ens224` | 改 `eth0`（中性示例）|
| `entrypoint.sh` / `compose` 注释 | `172.16.196.0/24`、`ZEEK_IFACE=ens160`、`10.255.12.4` | 改成通用描述（或在 .env 里给）|
| `config.py` / `profile.py` 注释 | 客户应用路径 `/Phone/js/*.js` | 换成通用示例 `/static/app.js` |
| `tests/py/*`（7 个文件） | 实机 IP `172.16.196.77/80/1/10/90` | 换成 RFC 5737 文档保留段 `192.0.2.x` |
| `docs/**` 的部署记录 | 172.16.196.77 等 | **保留**：那是「实际发生过的验收记录」，属于文档历史；产品代码里不留 |

- 加了守卫测试：`test_zeek_interfaces.py::test_no_hardcoded_nic_name_in_product_code` ——
  产品代码里不得出现 `${ZEEK_IFACE:-<非空>}`（否则红），且必须存在 `auto_iface()` 与空默认值。
- **部署侧对应动作**：服务器 `.env` 需补 `ZEEK_IFACE`（保持显式指定）与 `ST_EDGE_API_KEY` / `ST_EDGE_MODEL_NAME`
  （原来靠代码里的字面量，现在必须由部署环境给）。

**测试**：`test_baseline_profile.py` 19 → 27 例（路径判据 5 例、服务端 IP 2 例、kind 过滤与摘要标签 2 例）；
`test_zeek_interfaces.py` 加硬编码守卫；`test_zeek_limits.py` 的网卡断言改为「留空」。

**补充（同日，用户指出「单条永远到不了阈值」）**：拆库时看到一条 `认证失败突增（20 次，成功 0 次）` 只拿 0.25 分、而阈值是 0.6 —— 说明真爆破只要没同时伴随新 IP/新 UA（同一台机器、同一个 UA 一直试），就会**漏报**。用户选了**分档加权**（而非硬判）：

- `fail_burst_score()`：≥5 且多于成功 → **0.25**；≥10 → **0.35**；**≥20 且零成功 → 0.6（单条即达阈值）**，理由文本标「疑似爆破/撞库（一次都没成功）」。
- 门槛与原来一致（失败 ≥5 且多于成功），所以「用户输错几次」仍然只 0.25，不会因此变吵；最高档额外要求零成功。
- 四个新用例钉住分档边界（5/4→.25、12/3→.35、20/5→.35 不进最高档、20/0→.6）与「最高档单条达阈值」这条。

**顺带做的数据清理（用户要求「立刻清理干净」）**：库里 50 条改代码前留下的陈旧风险（`risk_at` 为空或已过 60 分钟有效期，却还挂着 risk/旧格式理由）被一次性归零（`SET risk_score=0, anomalies='[]', risk_at=NULL`），清后残留 0、不一致行 0、旧格式理由 0；当前带风险分的只剩 5 条新鲜判定（≤0.5 分，未过阈值）。


### 2026-10 「行为分析」页：基线与画像的明细 + 判据参数编辑区

用户要求：「在用户 web 界面创建行为分析的功能页面，将基线和画像的分析内容动态展示，并提供可配置参数的编辑区域」。

**为什么先改后端再加页面**：明细本来就有（`baseline_stats` + `entity_profiles` 两张表），但**参数改不了** ——
`observe_days` / `zscore` / `risk_threshold` / 时段与路径门槛 / 路径正则 / 保留期 这些原来直接读 `settings`，
改一次要动 `.env` 再重启。所以先做一层**运行时可配参数**（`baseline/params.py`），再让页面长在它上面。

**后端**：
- `app/baseline/params.py`（新增）：**单一定义源** —— `KNOBS` 里一行一个参数（键、标签、类型、默认值、
  范围、单位、说明），同时驱动「校验」「`GET/PUT /api/baseline/config`」「前端表单」三处，加参数只改这一处。
  共 18 项：数值基线 8（开关/观测期/σ/落库节奏/清理节奏/保留期/单窗口上限/缓存上限）+ 画像 10（开关/冷启动/
  阈值/时效/时段两个门槛/路径 include、exclude、已知门槛/保留期）。读侧每个存取器都**夹紧到范围内**
  （库里被手改成越界或非数字也不会把运行时带坏）；写侧**只认白名单**，正则先编译通过。
- `stats.py` / `profile.py` / `engine.py` 的 `settings.*` 读取全部切到 `params.*`（`session_cookie_names`、
  Redis 键名、`detector_agg_seconds` 保持 env 专用，不暴露给界面）。
- 路径正则的缓存从 `lru_cache` 改成**按正则文本做键**的字典：改完参数下次调用就是新键，不需要显式失效。
- 新端点：`GET/PUT /api/baseline/config`（读清单/保存，400 带 `field_errors`）、`POST /api/baseline/config/reset`
  （恢复默认，可单键）、`GET /api/baseline/numeric`（数值基线**浏览**：key 子串/维度过滤 + 排序 + 分页 ——
  原来的 `/stats` 必须指名 IP 或完整 key，没法翻着看）；`/api/baseline/profiles` 加 `q` 搜索；
  `snapshot()` 多回 `oldest_first_seen` / `next_warm_at`（**观测期倒计时**，与总数/预热数同一条聚合 SQL）。
- 保存后会清掉总览的 30 秒进程内缓存，避免界面继续显示旧标量。

**前端**：新增导航项「行为分析」（放在「总览」之后 —— 两个都是「看数据」的页）+ `app/admin/behavior/page.tsx`
+ `components/behavior-panel.tsx`。**主页面只做展示，三块**：①学习进度与检测器心跳（含**观测期倒计时**与
当前风险 TOP）；②数值基线 **IP 列表**；③**画像列表**。后两块都带**状态列：`生效中` / `观测中`** ——
运维第一眼要知道的就是「这个维度/实体现在能不能出判定」：
- 数值基线：过了观测期（`warmed`）= **生效中**（参与 2σ 判定）；否则 **观测中**（只学习，悬停能看到
  「只观测过 1 次，标准差不可靠」这类原因）；
- 画像：观测次数 ≥ 冷启动门槛（`profile.min_obs`，取自参数清单，不写死）= **生效中**（已参与打分）；
  否则 **观测中**（悬停显示 `观测 3/5 次`）。

**列表显示口径（同日几次用户要求）**：
- **按 IP 合成一行 + 维度标签 + 悬停提示**：数值基线表原来一行一个 `源IP:维度`（一个 IP 占 3 行），
  现在**一行一个 IP**：三个维度用中文标签排在「维度」列，**均值 / 标准差 / 观测次数 / 状态 / 首见**
  全部挪进标签的悬停提示（`title`）—— 列表行数直接降到 1/3。
  - 分组**必须在后端做**（`GET /api/baseline/numeric?group=ip`，默认仍是 `group=key`）：前端分组会把同一 IP
    的维度切到相邻两页去，分页就假了。后端用 `regexp_replace(key, ':[^:]*$', '')` 取 IP（**不能**用
    `split_part` 按第一个冒号切 —— IPv6 地址里全是冒号），按 IP 分页 + 排序后再批量取回这批 IP 的全部维度；
    分组逻辑抽成纯函数 `group_rows_by_ip()`，单测直接揿 IPv6 / 维度排序 / 空组边界。
- **key / 维度映射成中文**：界面显示 IP + 中文维度（连接数 / 目的端口数 / 目的 IP 数），原始 key 仍可悬停查看、
  搜索也仍按原始 key/IP 走（服务端过滤没变）。筛选下拉复用同一份映射表，避免两处漂移。
- **配色：`生效中`=绿色、`观测中`=黄色**：给共享 `Badge` 加了 `success` 变体（绿）。
  中途试过「两态统一绿色」，用户看过后要求观测中仍用黄色 —— 黄色表达「还在学习、没到门槛」，
  与「已生效」区分开更直观。

参数编辑挪到**右侧抽屉**（用户 2026-10 的要求）：页面上只留一个 **「分析配置」** 按钮，点开从右侧滑出，
里面按 `baseline.` / `profile.` 分两组，每项显示类型/范围/默认值/「已改」标记，越界与坏正则在字段下方报错，
底部固定「保存改动 / 全部恢复默认 / 重新读取」；有未保存改动时按钮上直接显示条数。抽屉用项目自制
`Drawer` 组件（原生 div + Button，不引第三方包）。画像表支持类型/名称/风险下限筛选与分页，展开看
理由·来源 IP·服务端 IP·UA·接口路径·时段分布直方图；数值基线表支持按 IP/key 搜、按维度与排序筛选。
30 秒自刷新（可关），单接口失败只影响自己那块。

**测试**：新增 `tests/py/test_baseline_config.py`（18 例：白名单、越界/非数字/坏正则/跨字段约束、
读侧夹紧脏值、save/reset 只动白名单且让缓存失效、端点接线与 400）。改造后同步修了 4 个引用旧 `settings`
打桩的旧用例（补丁改打到 `params`），并给快照的倒计时字段补了断言。

### 2026-10 中继链路还原 + 被访问方基线（5 个增量，均门禁全绿后提交）

**用户要解决的问题**（原话口径）：经过 WAF/反向代理/内网 DNS 转发的访问，「只看 conn 会把 dst_ip 变成代理」；
计数与检测都**只应认「公网客户端 → 内网源站」一条数据链路**，把中继自己的「接受 + 转发」去重掉；
可信代理清单要能在界面维护、存 PG，并自动推算它是反代还是 DNS 转发器。

**实机取证（先看清再动手）**：
- `uid` 在全量索引里 **0 条** —— 归一化把它丢了，所以「按 uid 关联 http↔conn」当时根本做不到；
- 代理链路两跳都在抓：`src=172.16.199.203(代理) dst=172.16.196.112:80 real=47.100.132.81`
  （后跳，带 XFF）与「客户端 → 代理」（前跳）；
- `direction` 只算在摘要上（事件文档里没有该字段），且用 `src_ip` 判 ——
  实测 `direction_of("172.16.199.203", ["172.16.196.112"])` = `in→in`（**外网经代理访问被误判**），
  而 `direction_of("202.120.8.186", ["172.16.196.112"])` = `out→in`；
- 智能体侧的方向是**从事件重算**的（`_group_direction` 取 `src_ips[0]`，排序后代理常常在前），
  所以「改摘要 src_ip」并不能修好那一侧 —— 这直接推翻了最初设想的「把 real_client_ip 加进聚合键」方案。

**1/5 中继清单改为 PG 专属**：新增 `ingestion/relay_nodes.py`（两侧栈一致，只读 `SystemConfig.zeek.relay_nodes`，
30 秒 TTL 缓存、IP/CIDR + 逗号/换行 + `#` 注释、非法项限量告警）。**删掉** `ST_ZEEK_TRUSTED_PROXIES`
设置项（两侧 config）、compose 透传与 README 那行；**PG 没配 = 认定网络里没有中继**（不认任何代理头、
hop 全 direct、不配对）—— 用户确认「不迁移，升级后等人录」，所以界面与发布说明必须写明这个行为断崖。
`uid`（Zeek 连接 UID，**只能关联同一跳**）与 `hop`（direct/front/back/relay_internal，stateless，
**不看 XFF**）两个新字段进 `UnifiedLog` + MCP 字段目录（守卫测试要求覆盖）。新端点
`GET/PUT /api/zeek/relay-nodes` **独立于网段接口**：改清单不该触发 Zeek 重载、不打断抓包。

**2/5 角色自动推算**：新增 `detector/relay_roles.py` —— 检测器逐条累计证据（http/ssl → proxy，dns → dns；
conn 覆盖所有流量、判不出角色），清单文本变化即清零，每 `ST_RELAY_ROLE_DETECT_SECONDS`（300s）用
`save_roles()` 回写同一个 PG 键（**不覆盖清单文本**），界面只读展示角色与证据计数。

**3/5 方向判定「真实客户端优先」（A′）**：摘要新增 `real_client_ips`（上限 5）与 `proxied`；两侧
`triage_policy.direction_of(src, dst, real_clients)` 有真实客户端就按它判（多个时「任一为公网即外向」，
与既有「任一目的为公网即外向」同一哲学），没有则回落 `src_ip`（直连场景行为不变）；
智能体 `_group_direction` 同样优先用组内事件的 `real_client_ip`。修好后：外网经代理的攻击不再被
压级/不许升级/当内网常规跳过；内网直连与内网经代理仍判 `in→in`，伪造 XFF 翻不动（对端不在清单就不认）。

**4/5 中继去重（一次业务访问只算一次）**：新增 `detector/relay_pairing.py`。
**保留前跳**（客户端→中继：src 就是真实客户端，请求头/payload/JA3 都在它上面）、**丢掉后跳**
（中继→真实目的：否则同一请求算两次，而且它的 src 是内网中继 → 「内网主机查询可疑域名」这类告警会归因到
DNS 服务器头上）。**为什么不做时间窗配对/合并**：两跳是两条独立 TCP 连接（uid 不同），配对要挂起前跳、
等后跳、再补源站，热路径改动面与失败模式都大；改用**可见性守卫**（与顺序无关）：最近
`ST_RELAY_VISIBILITY_SECONDS`（默认 300，下限 30）内见过该中继的前跳 → 后跳判重复丢掉；
从未见过（抓包点只在源站侧）→ 后跳照常处理（计数 `relay_back_kept`），**宁可多算也不丢数据**。
四个计数（前跳 / 后跳去重 / 后跳保留 / 中继内部）写进基线心跳并在「行为分析」页展示。
已知取舍：一条摘要的 `dst_ips` 是中继而非源站 IP（源站 IP 见同一次访问的后跳 ES 文档）。

**5/5 被访问方（内网源站 / 内网 DNS）基线**：新增表 `asset_stats`（与 `baseline_stats` 同结构，
**单表避开现有列表按 key 推 IP 的分组逻辑**；`apply_stats/load_stats/cleanup` 已参数化为可传模型）+ 
`baseline/asset.py`。资产标识 **hostname 优先**（HTTP Host / SSL SNI —— 中继场景下前跳也带它，
所以经代理的访问同样归到站点上），无则回落 `IP:端口`（内网 DNS = `IP:53`）。四个特征：
`visits` / `distinct_clients`（取 `real_client_ip or src_ip`，否则经代理时永远是 1）/
`distinct_client_ports` / `distinct_targets`（HTTP=URI、DNS=域名）。一个聚合窗口 = 一个观测点，
复用 Welford + 观测期 + zσ；**v1 只展示与标记，不写进摘要标签**（判据先在真实流量上校准）。
端点 `GET /api/baseline/assets`（分页/搜索）与 `/assets/stats?asset=`（特征明细），概览进 `/api/baseline`。

**前端**：「监控网段」页新增「中继节点清单」卡片（textarea 编辑 + 保存 + 未配置时的醒目提示
「当前不信任任何代理头、不做去重」+ 角色只读表含证据计数）；「行为分析」页新增「被访问方
（内网源站 / 内网 DNS）」卡片（资产 / 类型 / 状态（生效中·绿、观测中·黄）/ 平均每区间被访问 /
不同客户端 / 不同目标 / 首见）与中继去重四项计数徽标。

**测试**：新增 `tests/py/test_relay_chain.py`（15 例）与 `tests/py/test_asset_baseline.py`（18 例）；
`conftest.py` 新增 `set_relays` fixture（清单只读 PG，测试改为 patch `relay_nodes.networks`）。

### 2026-10 被访问方基线改口径 B2（按连接算，实机巡检驱动）

**为什么改**：中继清单生效后的实机巡检发现，被访问方列表第一名是 `172.16.199.203:8000`
（**中继自身的端口**，平均 1817/区间），而真正要看的 `www.nczy.edu.cn` 只有 114/区间 ——
1215 个资产里 18 个是「中继自身」却占了 **30.6%** 的被访问量（DNS 2.6% + 非 DNS 28%）。

**根因**：资产基线原本按**每条事件**累计，而同一次业务访问在抓包点会产生多条事件：
`conn`（**无** Host/SNI → 只能落 `IP:端口`）与 `http`/`ssl`（**有** Host/SNI → 落 hostname）——
于是同一次访问在两个键上**各记一次**；前跳的 dst 是中继，那些 `IP:端口` 行就全落在中继身上。

**改法（B2，用户选定）**：
- 桶键从「资产标识」改成 **Zeek `uid`**：一个连接 = 一次「访问」；一条连接的身份**逐步补全**
  （`conn` 先到就先记 `IP:端口`，`http/ssl` 到了再补 hostname），窗口结束在 `finalize()` 里定稿 ——
  **与事件到达顺序无关**；
- 新增 `requests` 特征（每条 http/dns +1）：连接数暴增（扫描/探测）与请求数暴增（负载/CC）分开看；
- **中继自身不作为资产**（端口 53 除外）：按**端口**判而不是按「推算出来的角色」判，
  免得依赖角色回写的时序；
- 只统计**有 `uid` 的 Zeek 事件**：主机监控（Wazuh，它的 dst 是主机自己）与
  files/x509/dhcp/notice 这类没有连接语义的日志不进基线；丢了多少条写进心跳
  `asset_uids_dropped`（**不静默**）；
- 内存保护 `ST_ASSET_MAX_UIDS`（默认 20000 条连接/窗口；实机 60s 窗口只有几千条）；
- **清空重学**：口径变了（事件→连接），两种语义的样本混在同一个 Welford 里会把均值/标准差
  拉偏，所以 `main.py` 加 `_migrate_asset_semantics()`：`SystemConfig["asset.semantics_version"] < 2`
  就清空 `asset_stats` 并置 2（幂等、自动；它只是统计缓存、不含原始事件，清掉不丢数据，
  只是重新攒观测期）。

**实机预期**：中继那些端口行消失（`199.211:53` / `199.186:53` 保留），`www.nczy.edu.cn` 的
`visits_mean` 变成**连接数**（比原来的 http 事件数小），且不再同时出现「hostname」与「`IP:端口`」
两份；`199.211:53` 的 `requests_mean` ≈ 该内网 DNS 的查询数。

**前端**：「行为分析」页被访问方卡片加「平均每区间请求」列 + 口径说明（连接数/请求数/身份优先/
中继除外），心跳徽标加「被访问连接 本轮·累计」与「未进基线」。

### 每期收尾门禁

**本地（仓库根，都不需要 Docker、不产生构建产物）**：`.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py`、`.venv/bin/pyright ndr/backend/app agent/backend/app tests/py`、`pytest tests/py --stack=ndr` 与 `--stack=agent`；前端在 `ndr/frontend` / `agent/frontend` 下 `npx tsc --noEmit`。

**只在 CI 跑**：`sh tests/zeek/run.sh`（它用 `docker run zeek/zeek:9.0`，本地没镜像会**自动拉**，还会在容器里编译脚本）—— 已列入 CI 的 `test` 作业。构建/编译一律走 GitHub Actions；本地不 `docker pull` / `docker build` / `docker run` / `npm run build` / 装依赖（详见 AGENTS.md「构建规则」）。

## 8. 开放问题

1. ~~判重窗口的默认值~~（**已定**，第 5 期）：不用「7 天保留期」做判重窗口，而是**事件组时间桶**（`group_bucket_minutes`，默认 30 分钟）+ Redis 占位 TTL 两个桶；库里 `EventGroup` 命中即累加计数，等价于「同一事件组只出一份报告」，与保留期无关。
2. **跨机部署时智能体仍依赖 NDR 的 Redis**：ES 直连已由第 6 节的 MCP 切断，推送那跳也改成 HTTP 了；但 `agent/backend/app/config.py:38-40` 的 Celery broker/backend 仍指 `NDR_REDIS_URL`。本次是否接受这个残留耦合，还是要一并把 broker 也换掉？
3. **监控网段只对 Zeek 生效** —— Wazuh 是主机日志，与网段无关。**已在界面上写明**（第 6 期）：Wazuh 面板的提示语里带一句「Wazuh 采的是主机日志，与『监控网段』无关 —— 那份清单只约束 Zeek 抓包」；第 7 期拆页时保留这条说明。
4. ~~推送载荷除了摘要还带什么~~（**已定**，第 5 期）：载荷 = `{items: [{event_id, fingerprint, digest}]}`，只加 NDR 生成的事件ID与摘要级指纹（供排查与回执对账），触发规则/原始事件数/时间窗仍在摘要里（`rule` / `count` / `first_seen` / `last_seen`），不额外冗余。
5. ~~MCP 服务与 NDR 后端的代码共享边界~~（**已定，2026-10-04**）：切了一层独立接口 `ndr/backend/app/mcpapi.py` —— `app/mcp/` 只准 import `app.config` / `app.mcp.*` / `app.mcpapi`，内部子系统（`app.db` / `app.ingestion` / `app.detector` / `app.investigation` / `app.baseline` / `app.workers` / …）一律经门面转发；边界由 `tests/py/test_mcp_boundary.py` 用 AST 静态守住（白名单比黑名单更强，以后新加的内部包也会被拦）。门面**只转发、不含业务逻辑**，且一律转发「模块属性」而不是导入期绑定的函数对象 —— 保住原懒导入的可 monkeypatch 性（否则 `monkeypatch.setattr(es_client, "get_es", …)` 会静默失效，`tests/py/test_investigation_query.py` 会挂 2 个）。`app/mcp/calls.py` 只依赖 `app.config`，留在原地不动。
6. **待实机验证（第 2 期遗留 + 第 5 期 + 第 6 期）**：~~Wazuh 4.14 自带的 Filebeat 是否支持 `output.redis`~~（**已绕开**，第 6 期）：不再指望 manager 自带的 Filebeat，`ndr/docker-compose.wazuh.yml` 另起一个官方 Filebeat 容器用 `ndr/wazuh/filebeat.yml` 投 Redis；manager 自带那个只留着报「找不到 indexer」的错。~~仍待实机：两个 Filebeat（Zeek 与 Wazuh）同时 `RPUSH` 同一 list 的实际吞吐~~ **已实机验证（2026-10-03）**：两个 Filebeat 确实同时在往同一 list `RPUSH`（Zeek 侧是 host 网络容器、Wazuh 侧在 compose 网络里；Redis `CLIENT LIST` 能按连接看到 `cmd=rpush`，20 秒 MONITOR 聚合到 Zeek 侧 422 次 RPUSH），消费端 `BRPOPLPUSH`（左旧右新、取最新优先）跟得上 —— 连续多个 5 分钟窗口入库 3.9–4.9 万条、死信 0、待重试 0、队列实时清空；`INFO commandstats` 里 `rpush` 与 `brpoplpush` 大体同量级。容器侧清单（`ndr/wazuh/README.md` 第五节）也已在 2026-10-03 逐条跑过，六条全绿。
7. **基线与画像的真实效果（第 8 期遗留）**：默认 7 天观测期内不判异常，收敛速度与误报率只能在现场跑够时间后才知道；另外检测器主备切换时进程内缓存会重建 —— 数值基线从库里重捞、画像异常有一小段标签稀疏（不丢数据，但切换瞬间的摘要可能少标签）。
8. **Zeek 日志生成与协议解析的专项检查（上线后必做，用户 2026-02 提出）**：本次所有 Zeek 侧改动都只在纸面与本机归一化侧验证过，真实网卡上线后要专门核一遍：① 实际产出了哪些 `log_type`（`/logs` 顶层 + 日期目录，24h 轮转与 3 天清理是否如期）；② 各协议分析器字段是否齐全（`site/shentong-extra.zeek` 加载的 conn/dns/http/ssl/files/smtp/ssh/dhcp/notice，以及自研 `shentong-httpbody.zeek` 的请求体是否落进 `http.log`）；③ 归一化后的 `log_type` / `event_type` 分桶与内置规则的字段命中（82 条内置规则里 47 处用到 body/uri/query/user_agent/ja3 等）；④ ~~反向代理场景拿不到原始客户端 IP~~ **已支持（2026-10-02）** —— 不需要自己接 `http_header`：Zeek 自带的 HTTP 分析器已把默认代理头清单（`X-Forwarded-For`/`X-Forwarded-From`/`Forwarded`/`Client-IP`/`Via`/`Xroxy-Connection`/`Proxy-Connection`）收进 `HTTP::Info$proxied`，normalizer 解析其中最左的合法 IP 落成 `real_client_ip`（无代理头 = NULL，`src_ip` 仍是 TCP 对端）。实测探针 `X-Forwarded-For: 198.51.100.77, 203.0.113.9` → `proxied: ["X-FORWARDED-FOR -> 198.51.100.77, 203.0.113.9"]` → `real_client_ip=198.51.100.77`。**2026-10-04 收口**：可信代理白名单已做（`ST_ZEEK_TRUSTED_PROXIES`，只有直连对端落在清单里才认代理头，清单留空 = 一律不认，fail-closed）、`X-Real-IP` 已补进 Zeek 采集清单（`site/shentong-httpheaders.zeek` 的 `redef HTTP::proxy_headers += { "X-REAL-IP" };`，成员必须全大写）；**四层代理的 PROXY protocol 明确不做** —— Zeek 9.0 没有该分析器（镜像内 `zeek -NN` 无该条目），要支持只能在外层终结或回查 NAT/防火墙日志。同一批改动把响应体也采集了（`resp_body` / `resp_body_len`）。逐条清单见 `ndr/zeek/README.md` 的「上线后专项检查」与「已知限制」。
   **实机结果（2026-10，172.16.196.77，Zeek 9.0.0，`iface=ens160`）**：已按 9 项清单核过一遍，逐项证据表见 `ndr/zeek/README.md` 的「实机结果」。三条要记住的结论：① **HTTP 请求体把中文整块丢了**（检查项 4 抓出来的真 bug）—— 自研 `shentong-httpbody.zeek` 的二进制守卫 `/[^\x09\x0a\x0d\x20-\x7e]/` 只放行可打印 ASCII，UTF-8 多字节全被当二进制丢弃；同一 POST 路径对照实测：`{"probe":"ascii","n":1}` 有 `body`、`{"text":"中文请求体"}` 无 `body`。已改为只拦 NUL/C0 控制字符（`/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/`），并在容器内用 Zeek 单测四种样本验证；② **`ja3`/`ja3s` 在 Zeek 9.0 里根本不存在** —— `local i: SSL::Info; print i?$ja3;` 编译报 `no such field in record`，`ssl.log` 127 条 0 处 ja3。检查项 3 与 `shentong-extra.zeek` 注释里的原期望是错的，基于 `ja3` 字段的规则（`rules/builtin.py` 那条空值模板）永不命中；要用得另装/自写 JA3 脚本，已写进 README「已知限制」；③ **监控网段仍未配**（`/config/interface.conf` 里 `monitored_nets=` / `local_nets=` 为空 → Zeek 启动命令无 BPF、全量抓包），这是上线收尾里唯一需要用户拍板的一项。其余：日志产出 conn/dhcp/dns/ssl/http/files/weird/x509 齐全、无 notice.log（符合预期）、`log_type`/`event_type` 分桶正确、内置规则已命中（扫描 17335 / 命中 60 / 投递 9）、24h 轮转当天未见日期目录。XFF（④）**已支持**（2026-10-02，`proxied` → `real_client_ip`）；HTTP 请求体与响应体都采集（`body` / `resp_body`，完整响应字节数 `response_body_len` → `resp_body_len`）。**类型分桶（③）与轮转形态**已由第 9 期改造与核对：`log_type` 改由 `log_types.py` 单一入口判定（信封 `log_type` 优先 → 17 条字段提示猜 → 都不中记 `unknown` 并保留原名，**不再兜底成 `conn`**），运维流（ntp/packet_filter/reporter/stats/ja4ssh/ja4d）只入库、不进检测；轮转实测是**同目录平铺改名**（`conn.log` → `conn.2026-10-01.log`），不是日期子目录。

### 2026-10 中继去重判据修正：按「哪一侧有明文内容」判 + 链续跳去重 + 端口可配

**缘起**：用户在中继清单里补了 `172.16.199.214` / `172.16.199.215`（泛域名转发设备，nginx 类，
按 SNI/端口把 `*.nczy.edu.cn` 转到 WAF 的对应端口）后要求复核。实测数据把**判据本身的错误**暴露出来。

**实测（服务器原始日志 / ES / Redis，全部可复核）**：

| 事实 | 数字 |
|---|---|
| 客户端侧那一跳（199.214/215 → 199.203） | conn 45,183 / ssl 44,623（**SNI 0 条**）/ http **9** / weird 62,505；src 99.9% 是 199.214（另一台代理，不是客户端） |
| 源站侧那一跳（199.203 → 196.112/125） | **http 28,557 行 / 2,431 连接**、files 20,825、Host `www.nczy.edu.cn` 16,774；XFF 真实客户端 **438 个/15 分钟** |
| 两侧内容比 | **9 : 28,557（1 : 3172）** |
| 现有判据的后果 | `relay_back_dropped 29,403 / back_kept 24`（99.9% 被误丢）；84 条内置规则里 **21 条**依赖 `uri_path/method/status_code/user_agent/referer/content_type` → 对 WAF 后面的站点**永不命中** |
| 被访问方基线 | `www.nczy.edu.cn` 的「不同客户端」恒为 **1.0**（真值 438）；`njwc.nczy.edu.cn` 查不到 |
| 假协议异常 | `bad_HTTP_request` 25,317 + `line_terminated_with_single_CR` 26,790（根因：8000/8008 在 Zeek 默认 HTTP 端口表里，实际是 TLS）；`src=199.214` 的 weird 4,167 条/5 分钟 |
| 客户端 IP 取法 | 后跳文档里 XFF 最左值与 X-Real-IP **298/298 完全一致** → 现有取法无需加固 |

**改法（三条判据，全部单条事件可判、不做两跳配对）**：

1. **按内容判侧向**：`detector/relay_roles.py` 在**去重之前**累计每台中继两侧的明文内容条数
   （`http`/`http2`/`smtp`/`dns`；**不含 ssl**），`detector/relay_pairing.py` 据此决定保留哪一侧：
   默认客户端侧，另一侧 `≥ ST_RELAY_SIDE_MIN(50)` 且 `≥ ST_RELAY_SIDE_RATIO(10)` 倍才翻转。
   统计在去重之前 → **丢了哪一侧都不会让判据自己锁死**；判定与角色一起回写 PG，重启无过渡期。
   运维可在界面**手动覆盖**（auto / 保留客户端侧 / 保留源站侧，存 `SystemConfig.zeek.relay_nodes.sides`）。
2. **链的下游续跳丢掉**：本跳 `src` 不是中继，但代理头里**发送方自己观测到的对端**
   （`X-Real-IP` 或 `X-Forwarded-For` 末尾）是清单内中继 → 丢掉（计数 `relay_chain_continuation_dropped`）。
   **必须限定「src 不是中继」**：证据跳的代理头里同样带着中继（它是上游，实测 XFF 末尾 1,669 条是
   199.214），不限定就会把要保留的那条也丢掉 —— 这是纯静态分析看不出来、只有读了代理头原始值才会发现的一条。
   用 `UnifiedLog.raw` 里已有的原始代理头，不加字段、不改 ES 结构。
3. **`relay_internal` 不再无条件丢**：只有「发送方的内容侧就是源站侧」且本跳确实带明文内容时才留
   （本环境的 199.214 → 199.203 是 TLS 无内容 → 照旧丢）。

**端口可配**：新增采集配置项「按 TLS 解析的端口」（`interface.conf` 的 `tls_ports`，界面「采集」页维护，
空 = 沿用采集器默认端口表），入口脚本 `render_ports` 渲染成 `redef HTTP::ports -= { ... }` 并触发重载。
端口是环境相关的（本环境 8013 就是**真明文 HTTP**，不能一刀切），所以做成部署配置而**不写死在产品代码里**。

**接口与界面**：`GET /api/zeek/relay-nodes` 回带 `nodes` / `sides` 与每台的两侧内容计数、
生效侧向与来源（auto/manual）；新增 `PUT /api/zeek/relay-nodes/sides`；
`GET /api/zeek/status` 与 `PUT /api/zeek/interface` 增加 `tls_ports`。
「监控网段」页中继表格加「客户端侧内容 / 源站侧内容 / 当前保留 / 保留哪一侧（三选下拉）」；
「采集」页加「按 TLS 解析的端口」输入；「行为分析」页徽标改为
「客户端侧跳 保留/丢弃、源站侧跳 保留/去重、中继内部 保留/丢弃、链续跳去重」。

**验收修正（实测推翻了原计划里的一条预期，如实记录）**：原以为 `内置-协议异常` 的 75-78 条/5 分钟
摘要全部来自 WAF 前跳的假 weird；实测那批（`src=199.214` → `dst=199.203`）在用户把 199.214/215 加入清单后
已经是 `hop=relay_internal` **被丢弃**，当前 75-78 条摘要来自**约 88 个不同内网主机**的真实/抓包类 weird
（WAF 只占其中 1 个分组）。所以端口配置的收益是**数据卫生**（约 4,167 条/5 分钟 ≈ 120 万条/天的垃圾文档）
与不再污染分析输入，而不是「摘要数归零」。

**验收又抳出一个缺陷（已修）**：部署后被访问方基线的 `distinct_clients` 仍是 1.19，而 ES 里同一个
站点近 5 分钟有 **112 个不同真实客户端**。根因是口径漏了一种形态：**WAF/反代的一条长连接会复用/承载
很多个客户端** —— 实测 `www.nczy.edu.cn` 近 5 分钟 **206 个请求只走了 11 条连接**，XFF 在每个请求上
都不同；而实现里「一条连接只记一个客户端」，于是「不同客户端数」恒被压成 1。
改为：每条连接记录保留**一组**真实客户端（优先 XFF；一个都没有才回落连接的 src），口径版本升到
**v3** 并清空 `asset_stats` 重学（同 v2 的道理：口径变了不混样本）。
同一份数据也说明：对经中继的资产，**`requests`（请求数）才是真实访问量**，`visits`（连接数）会被
长连接压小、`distinct_client_ports` 反映的是中继自己的端口 —— 界面两列都展示，口子在文档里写清楚。

**测试**：`tests/py/test_relay_chain.py` 扩到 30 例（两侧内容统计、侧向判定与阈值边界、手动覆盖优先、
判据异常回退、清单变更清零、链续跳只认发送方侧的头、src 是中继时不算续跳、relay_internal 按内容判）；
`tests/py/test_zeek_limits.py` 新增 `render_ports` 的 5 组渲染用例与 `local.zeek` 加载守卫。

### 2026-10 weird 分类：采集类异常降级为健康指标（不再占摘要额度）

**缘起**：用户问「weird 日志有什么意义」。逐名统计本环境 30,063 条 weird，发现 **~87% 是采集类**：
`possible_split_routing` 13,795 / `data_before_established` 5,604 / `truncated_tcp_payload` 2,053 /
`SYN_inside_connection` 1,447 / `window_recision` 1,416 / `data_after_reset` 935 /
`inappropriate_FIN` 879 —— 它们的含义是**采集在丢东西（丢包 = 漏检）**，不是攻击信号。
但归一化把它们和真正的协议异常一起标成 `protocol_anomaly`，被「内置-协议异常」一刀切命中 →
一个 5 分钟窗口产出 **75~84 条摘要**（约占全部摘要的一半），把真该看的挤到限流丢弃。

**网卡侧实测（先量再定，这一项决定「治标还是治本」）**：抓包口 `ens192` 是 vmxnet3 / 10G，
`rx_dropped` 仅 **216,104 / 75.2 亿包 ≈ 0.003%**，`rx_errors` 与 `rx_missed_errors` 均为 0，
`rx-gro-hw` off [fixed] → **不是网卡丢包**；这批异常是镜像口/非对称路由的固有形态。
所以**不动网卡 offload 设置**（收益不确定、又要碰生产采集口），改为把它们当**采集质量指标**看。

**改法**：
1. 新增 `UnifiedLog.weird_name`（两侧契约 + 字段目录 + `_FIELD_TYPES` + SUMMARY/AGG 字段）：
   异常名从此可查可聚合 —— 此前只埋在 `raw.name` 里，实测**不可聚合**（terms 聚合恒空）；
2. `ingestion/normalizer.py` 新增 `_capture_weird()`：名单内（`ST_ZEEK_CAPTURE_WEIRD_NAMES`，
   默认就是上面 7 个 Zeek 稳定异常名）的 weird 标成 `event_type=capture_anomaly` ——
   **数据一条不丢**，只是不再当告警；
3. 总览页新增第 8 盏灯「**采集质量（采集类协议异常）**」：近 15 分钟条数 + 最常见异常名，
   阈值 `ST_CAPTURE_ANOMALY_WARN_15M` / `_CRIT_15M`（默认 5000 / 20000）；
   读不到统计只影响它自己这盏灯（其余灯不受牵连）；
4. 「内置-协议异常」**加同源频次门槛**（`mode=count` / `key=[src_ip]` / `min_count=5`）：
   第一次只做了分类，实测摘要数没怎么降（52~68 条/5 分钟）—— 因为摘要按「源 IP × 规则」分组，
   残留的 ~52 个源每个只出 1~几条也各占一条额度。改成频次规则后单发怪象留在 ES（供回溯/MCP 查），
   只有同源 ≥5 次才告警。

**验收（部署后实测，15 分钟窗口）**：weird 总数 9,776，其中 `capture_anomaly` **9,197（94%）**、
`protocol_anomaly` 578（6%）；`内置-协议异常` 的每 5 分钟摘要从 52~68 **降到 11**（单规则降 ~80%），
总摘要 119 → **87**；总览页第 8 盏灯「采集质量」常态为绿（近 15 分钟约 615 条，最常见
`possible_split_routing`）；`capture_anomaly` 文档在 ES 里照旧可查（数据不丢）。

**已处置（见文末「扫描规则改扇出」一节）**：`内置-扫描尝试连接` 曾是摘要第一大户 —— **66~71 条/5 分钟**
（约占全部摘要的 79%）。它与协议异常是同一个形态：`event_type=scan_attempt`（conn_state S0，只发
SYN 没回应）逐条命中，导致「每个有过一次 S0 连接的源各占一条摘要」。同样按「扫描要有规模」加频次
门槛（例如同源 ≥N 次 / ≥N 个不同目的端口）即可收敛，但这属于**改检测灵敏度**，需用户拍板。

**测试**：`test_rules_quality.py`（采集类名字→capture_anomaly、大小写不敏感、异常名仅 weird 日志有）、
`test_rules_routing.py`（`weird_name` 只路由到 weird；`capture_anomaly` 不命中「协议异常」）、
`test_health_components.py`（八盏灯 + 采集阈值判据 5000/20000 + 单灯降级）。

### 2026-10 扫描规则改「扇出判据」：误报从 66~71 条/5 分钟降到 0

**缘起**：用户问「内置-扫描尝试连接现在有什么问题，误报率」。实测把结论钉死了：

| 事实 | 数字 |
|---|---|
| `conn_state=S0`（只发 SYN 无回应） | **9,165 条 / 15 分钟、92 个源、143 个目的、仅 38 个不同目的端口** |
| 其中「不同目的端口最多」的源 | **3 个**（正常重试的形态，不是扫描） |
| 规则判据 | 只有 `event_type=scan_attempt`，**没有任何规模要求** → 一次失败 SYN 就告警 |
| 典型误报 | 14789/8000/8200/1514 等**固定业务端口反复失败**（服务没起/防火墙静默丢）；443→172.217.x.x（Google）**44 个目的 0 回应**（出站被丢或镜像单向） |
| 占额度 | 66~71 条摘要/5 分钟 = 全部摘要的 **55~79%** |
| 漏报 | 经典 connect 扫描打「活主机的关闭端口」会收到 RST → Zeek 记 `REJ`/`RSTOS0`/`RSTRH`（`event_type=rejected_connection`），**旧规则完全不看** |

**判据设计（精准与检出同时成立）**：真实扫描的定义是「一个源在短时间内摸很多端口/很多主机」——
扇出。实测正常失败尝试的端口扇出 **≤3**，与扫描（≥8 个端口）天然可分。

**改动**：
1. **退役 `内置-扫描尝试连接`**（单个失败尝试不再告警）：名字从 `BUILTIN_RULES` 拿掉（当时代码 84 条内置；本页后续又删了「内置-端口扫描」「内置-明文凭证传输(HTTP登录)」，当前代码 82 条内置、启用 81 条），
   `builtin.RETIRED_RULES` 备案说明；播种流程新增 `_retire_builtin_rules()`（**幂等**）把库里那行
   置 `enabled=False` 并追加说明 —— **不删行**（规则页看得到「它为什么没了」，可一键启用回滚）。
   两侧（`ndr/` 与 `agent/`）都加：agent 若自建库播种，旧行同样会被停用。
2. **新增 `内置-快速端口扫描`**：`mode=count, key=[src_ip], window=300, min_count=10,`
   `distinct=dst_port, min_distinct=8`，事件 = `conn` + `event_type in [scan_attempt, rejected_connection]`
   （优先级 25 / medium）。补齐「窄端口扫描（8~29 个端口）」这个口子 —— 既有 `内置-高频扫描连接`
   要求 30 分钟内 ≥30 次，扫 20 个端口打不中它；`内置-内网慢速服务枚举` 要求同目的 ≥25 个端口，
   也打不中。
3. **判据只用「未建立」的失败**：`RSTO`/`RSTR` 是握手建立后的 RST（正常业务断连，见 `conn_states` 表），
   **不计入**，否则立刻引入新一批误报。
4. **配置**：`policy_skip_rules` 默认值清空（原放的旧规则名已退役，属死配置）；新规则**不进**跳过名单
   （否则内网真扫描会被「内网常规」整条跳过）。

**分工（覆盖矩阵）**：
| 形态 | 规则 |
|---|---|
| 快速窄端口扫描（8~29 个端口 / 5 分钟） | `内置-快速端口扫描`（新增） |
| 中尺度端口扫描（≥8 个端口且 ≥30 次 / 30 分钟） | `内置-高频扫描连接`（既有） |
| 慢速端口枚举（同源同目的 ≥25 个端口 / 6 小时） | `内置-内网慢速服务枚举`（既有） |
| 主机扫描/横向（≥10 个内网目的 / 6 小时） | `内置-内网慢速横向`（既有） |

**验收**：`pytest` 里用内存假 Redis 驱动 `FreqWindow`：同源 12 个不同端口 → 触发；固定 3 个端口
× 300 次 → **不触发**；`REJ` 计入而 `RSTO/RSTR` 不计入；退役步骤幂等（两次跑结果一致）。
实机部署后按当前流量预期：扫描类摘要 66~71 → **0**，总摘要 87~119 → 约 20~50；ES 里 S0/REJ 文档不变。

**遗留（未做，已量化）**：`内置-端口扫描`（按 notice 的 `event_type=port_scan`，优先级 28）在本部署
**是死规则** —— 采集面关掉了 Zeek 自带 notice（`shentong-policies.zeek`），该事件类型不会出现。
保留它不影响摘要（永不触发）；是否清理与 `2026-10 规则评审`第 16 条（合并三条扫描规则）一起评估。

### 2026-10 实机数据体检后的一轮修复：会话判据改 session_id + 删除明文凭证规则

**缘起**：用户要求「全面对所有内置规则进行分析、结合服务器实际产出的数据，找出还存在问题的部分」。
方法：① 当天索引近 6h 的 log_type/event_type/**字段非空**画像；② 检测器 288 个 5 分钟采样（24h）的
按规则摘要计数；③ 逐规则的字段/事件类型与实机产出交叉比对。查出四条问题，本轮先修两条。

**1) 「内置-会话跨IP复用」（critical / priority 8）实测 100% 误报**（24h 337 条，**零真命中**）：

| cookie 值（12 小时窗口） | 次数 | 不同 src_ip | 判定 |
|---|---|---|---|
| `Path=/` | 14,139 | 2 | ✗ 应用用 `document.cookie` 造出的**常量 cookie**（原文核实：请求头里确实是 `COOKIE: Path=/`，不是解析串味） |
| `Path=/; Path=/` | 6,095 | 2 | ✗ 同上 |
| `EPORTAL_COOKIE_PASSWORD=; …` | 3,631 | **164** | ✗ 空值模板 cookie |
| `HRSSESID=…` / `ASP.NET_SessionId=…`（真会话） | 3,600~4,600 | **1** | ✓ 每条只出现在一个 IP（不触发，正确） |

根因：规则用**整条 Cookie 头**当键，而 Cookie 头里含跨用户恒定的值。
**改法**：新增共享模块 `ingestion/session_cookie.py`（按名单**精确**匹配会话 cookie 名、取第一个
**非空**值；两侧逐字一致），新增 `UnifiedLog.session_id`（两侧契约 + 字段目录 + `_FIELD_TYPES=http`，
从**未截断**的 Cookie 头里取，避免长头把会话 cookie 截掉），`baseline/profile.py` 的会话实体改用同一份
实现（防漂移），规则 key 由 `cookie` 改为 `session_id`，默认名单补 `HRSSESID`（**不**加存密码的
`EPORTAL_COOKIE_PASSWORD`）。
**验收**：部署后逐窗口 `会话跨IP复用` = **0**（实测近 10 分钟无任何会话跨多个源 IP）；
单测覆盖「真会话跨 2 个 IP → 命中」「`Path=/` / 空值模板跨 100 个 IP → 不命中」。

**2) 「内置-明文凭证传输(HTTP登录)」按用户口径删除**：实测 2,848 条/12h 全是校园 App 的正常登录
（`/PhoneApi/api/Account/Login` 1,797 条/579 个真实客户端、`/njwhd/login` 917/644，status=200），
属「站点该上 HTTPS」的**配置事实**而非攻击事件。名字进 `builtin.DELETED_RULES`，播种幂等删行
（与「内置-端口扫描」同机制）。部署后逐窗口 = **0**。

**同轮一并处置的还有**：删除 notice 型死规则「内置-端口扫描」（并收紧 `_wazuh_event_type` 的
`"scan"` 词匹配 —— 原来 Wazuh 的 CIS 合规标题（"Ensure 'Turn on e-mail scanning'…"）被误标成 `port_scan`）。

**本轮未修（待定，已量化）**：
- **主机监控（Wazuh）整条检测线被范围闸门丢掉**：近 6h 1,981 条 Wazuh 告警里**带 `src_ip` 的 0 条**，
  而 `_entry_in_scope()` 只认 `src_ip`/`dst_ip` 落在监控网段 ⇒ 全部在规则之前被丢
  （5 条主机规则 + 依赖 Wazuh 的认证类规则 24h 零摘要）。日志类型闸门**已经**给 Wazuh 开了例外，
  范围闸门没开 —— 两处口径不一致。
- **Wazuh 事件类型标签不准**：`rule_groups=windows,system_error`（1,573 条，占 79%）被归成
  `wazuh_system_change` ⇒ 修好上一条后「内置-主机文件完整性变更」会把 Windows 错误事件报成文件完整性变更。
- ~~**`cert_issuer` 字段恒空**（近 6h 0 条非空）⇒「内置-自签或异常证书」的 issuer 分支是死路径~~
  **已处置**：先删掉 issuer 死分支（判据只剩 `cert_self_signed`），随后按用户口径**整条删除**
  （自签证书不需要检测；本环境 `cert_self_signed == true` 文档数 = 0，属配置事实非攻击事件）。
  两条 TLS 相关规则的分工因此收敛为：`内置-弱TLS版本`（协议版本维度，只算内网→外网，实测
  `TLSv10` 242 条 / `TLSv11` 23 条）+ `内置-TLS异常`（Zeek TLS 解析异常名维度，实测只有
  `SSL_excessive_alerts_in_record`）。
- ~~**同一现象多份摘要**：Web 扫描类 24h 合计约 970 条（多路径探测 339 + 框架漏洞探测 299 +
  目录/路径爆破 211 + 未授权访问 99 + 暴力路径枚举 22）~~ **已按方案 A 处置（见下）**。

**已处置（方案 A，2026-10）**：`内置-多路径探测(漏洞挖掘)` 的状态码由 `200/401/403/404` 收成
**`401/403/404`**（只算「不同路径且失败」），并**删除 `内置-目录/路径爆破`**（进 `DELETED_RULES`）。
依据（近 6h 实机数据，按源 IP 的路径扇出）：
- 现口径（含 200）里「≥30 条且 ≥30 个不同路径」的源 **92** 个、「≥50 条且 ≥50 路径」**43** 个；
  把状态码收成 401/403/404 后分别只剩 **1** 个 ⇒ 200 是「正常浏览/爬虫」的形态，
  这也与规则自己那句注释「这里只看大量不同路径且失败」一致（注释写了、条件没写，属实现与口径不符）；
- 目录/路径爆破与多路径探测在数据上**完全重叠**（6h 里命中的唯一源两条都中），且它的门槛只有
  「次数」（30 次 403/404、不限不同路径）⇒ 正常用户连点 30 个 404（坏链/缺图）就会中 ——
  这两点 2026-10 规则评审已经点过（`docs/review/ndr-rules/recon.md:38`、
  `engine-semantics.md:189`），本次实现按方案 A 收口。
预期：这一族摘要 550 → 个位数~50；保留的检出能力 = ≥50 个失败路径的宽扫描 + 同路径高频
（暴力路径枚举）+ 特定框架特征 + 敏感文件泄露 + 未授权访问成功。代价：丢掉「30~49 次失败」那一档。


### 2026-10 「检测规则」页重构：内置按网络/主机分组 + 自定义规则抽屉

**界面**（用户口径）：
- 导航「规则配置」改名 **「检测规则」**；
- 页面分两个标签页：**内置规则** / **自定义规则**；
- 内置规则按**网络（网络采集器）**与**主机（主机监控）**两组组织，点规则名**展开详情**
  （描述 / 条件 JSON / 规则 ID / 类型阈值），每条前面有**勾选框**启停（内置规则只有启用状态会保留）；
- 自定义规则：右上「添加规则」打开右侧抽屉，填 规则名称 / 描述 / **规则内容（网络规则 or 主机规则）**
  / 级别 / 优先级 / 启用 / 触发条件（含频率规则）；**规则 ID 自动生成、只读不可编辑**（新增时显示
  「保存后自动生成」）；已有自定义规则可编辑/删除。

**后端（这个划分不是界面猜的，是一等公民）**：
- `Rule` 新增 `scope VARCHAR(16) NOT NULL DEFAULT 'network'`（`main.py::_MIGRATIONS` 幂等补列，两侧栈都有）；
- 适用范围由**规则条件**自动判定：`rules/builtin.py::rule_scope()` —— 条件引用
  `log_type == "wazuh"` / `source_system == "wazuh"` / `wazuh_*` 事件类型 ⇒ **主机**，其余 ⇒ **网络**；
  少数条件里看不出侧向的认证/账号类（暴力破解/主机登录失败/高频认证失败/撞库）在
  `_SCOPE_HOST_OVERRIDES` 里手工归主机（本部署由主机监控驱动），实测分布 **网络 65 / 主机 15**；
- 播种时把判定结果写进 `Rule.scope`（内置规则随版本同步更新该字段）；自定义规则的 scope 由界面选择，
  更新时**不会**覆盖内置规则的自动归类；
- 接口：`RuleIn.scope`（校验只允许 network/host）、`_rule_dict` 返回 scope；
- **检测器按侧过滤**：`runner._entry_side()` + `_same_side()` —— 主机规则只在 `source_system=wazuh`
  的事件上求值，网络规则反之（缺 scope 按 network），逐条规则与频率规则两条路径都过滤。

### 2026-10 引入签名引擎（Suricata）：48 条重叠规则移交 + Community ID 关联

**为什么（一手依据）**：把 80 条内置规则的判据逐个对照 Suricata 官方规则关键字表
（`http.host/uri/method/user_agent/cookie/request_body/response_body`、`file.name/fileext/
file.magic/filemd5/filesha1/filesha256`、`tls.sni/tls.version`、`dns.query`、`|00|` 字节匹配、
`flowbits/xbits`、`dataset`）后分成三桶：

| 桶 | 条数 | 去向 |
| --- | --- | --- |
| 判据全落在 Suricata 有关键字的字段上 | 48 | **删除，交给签名引擎（ET Open，MIT）** |
| 主机监控侧 | 15 | 保留（Suricata 是纯网络引擎，看不到主机事件） |
| 「按实体数不同值」+ 部分重叠 | 17 | 保留（`dataset` 是二值集合，数不出“几个不同账号/端口/目的”） |

**做到的改动**：

- 新增 `ndr/suricata/`（Dockerfile + 入口看门狗 + 配置模板 + 裁剪清单）：CI 构建镜像时用
  `suricata-update` 固话 ET Open（运行期不需要外网），只输出命中规则的事件（EVE `alert`）；
- 采集侧 Filebeat 加第二个输入（`/logs/suricata/*.json`，静态 `source_system/log_type`），
  与 Zeek 共用同一个 Redis 采集队列 → 同一条归一化/入库/检测/摘要链路；
- 归一化新增 `normalize_suricata`（两侧栈逐字一致）：`event_type=signature_hit`、
  `log_type=suricata`，签名名/SID/类别/severity 进独立字段，`raw` 丢掉整包十六进制与载荷 base64；
- 新增 **`内置-签名命中(高危/中危/低危)`**（按 EVE `alert.severity` 1/2/3 分档），
  摘要样本带 `signature/signature_id/signature_category/community_id`；
- **签名命中的两处例外**（都有实机理由）：不做中继去重 —— 本环境客户端侧是 TLS（无 SNI）、
  有内容的恰是源站侧那跳，套「哪一侧有内容」的去重会把该保留的告警丢掉；
  不进行为基线/画像/资产统计 —— 告警是派生产物，学进去等于把告警当正常行为；
- **Community ID**：`UnifiedLog.community_id` + Zeek 侧 `@load policy/protocols/conn/
  community-id-logging`（conn.log）+ Suricata 侧 `community-id: yes`；
  两个采集器对同一条流可用同一个键对上（不受 NAT/端口复用影响，加密流量也能对）；
- 界面：「监控网段」页加一行说明（同一份网卡/网段配置同时用于采集器与签名引擎）
  并显示签名引擎状态（`/logs/suricata/status.json`，后端只读挂同一日志卷转出来）。

**验收顺序（先保覆盖再删规则）**：部署后先确认 EVE 有 alert 写出、`log_type=suricata` 文档
落 ES 且 `community_id` 非空、三条签名规则产出摘要 → 再确认 48 条已从规则库消失 →
观察真实告警量并按实测裁剪（**上线当天就裁了两类**：`SURICATA STREAM *` 引擎流异常占全部告警
93.5%（镜像口非对称流造成的引擎抱怨，与 Zeek 侧「采集类异常」同源）、以及 ET INFO 的
「服务端 banner 版本」类（每条 SSH 连接报一次，属配置事实）；理由与实测数字写在
`ndr/suricata/disable.conf` 里）。不裁的后果是真实的：摘要通道全局 24 条/分钟，
被噪音占满后真正的签名命中就挤不进来。

### 2026-10 签名引擎规则集改为「开发人员提供的 rules 文件 + manifest 在线更新」

**为什么改**（用户口径）：内置的 ET Open 五万多条规则既不由我们维护、量级也不受控 ——
上线当天实测 345~660 条告警/分钟，其中 93.5% 是引擎自身的流异常噪音（`SURICATA STREAM *`），
而且它是「别人的规则、别人的命名」。规则来源应当单一、由项目自己维护。

**改成什么**：

- 镜像**不再带任何规则集**、也不再联网自动更新：去掉 `suricata-update`、ET Open 下载、
  `disable.conf` / `modify.conf`；自带一个**空占位规则文件** ⇒ 开箱 0 条规则、**不产生任何告警**；
  引擎自带事件（`SURICATA *`、`*-events.rules`）按口径一律**不加载**。
- 规则集放共享卷 `/rules`：**后端**写 `staging/` 与三个请求标记（validate / activate / reset），
  **容器**跑 `suricata -T` 校验、切 `active/`、`suricatasc -c reload-rules` 热重载，两边各写自己的
  状态文件（`source.json` / `runtime.json` / `validation.json`）——沿用「后端写共享文件、容器执行」
  的既有架构，后端不碰 docker socket。
- 在线更新走 **manifest（文件列表 + sha256）**：界面「检测规则 → 签名规则」配置地址与令牌；
  手动「立即检查更新」或**每 12 小时自动检查**（只拉取 + 下载差异文件 + 校验）；
  **校验通过也不自动生效** —— 弹确认框、人工点「立即更新」才切换（规则属检测口径变更）。
- 界面显示当前版本/文件/条数、待确认版本与校验结果、最近检查与最近 10 次历史；
  空规则时明确提示「不会产生任何告警」。

**踩过的坑与定下的口径**（都写进 `ndr/suricata/README.md`）：

- 基础镜像把 `/var/lib/suricata` 与 `/etc/suricata` 声明成 `VOLUME`，**匿名卷在容器重建时被保留**
  ⇒ 升级镜像后容器里可能还是上一版文件（ET 时代踩过：镜像内 69028 行、容器里仍 69096 行）。
  现在规则与配置都在我们自己的 `/rules` 卷 + 每次启动重新渲染的 `/etc/suricata/suricata.yaml`，
  结构上不受影响。
- 该镜像**没有 `cmp`**（实测 `MISSING cmp`），比较文件用 `sha256sum`。
- 规则约定：SID 段 `1000000-1999999`（不撞上游 2xxxxxx）、必填 `msg`/`sid`/`rev`、
  `classtype` 或 `priority: 1|2|3` 决定 EVE `alert.severity`（⇒ 我们摘要的高/中/低三档）；
  可用 `$HOME_NET` / `$EXTERNAL_NET` / `$HTTP_PORTS`。
- 引擎事件在「事件类型」这一层与 Zeek 的 `weird.log` 重复，而后者已经覆盖（且我们按「采集类异常」
  降级为健康指标）；这也是关掉引擎事件的一个理由。

### 2026-10 TLS 判据重做：删掉裸单条匹配，换成两条有攻击含义、阈值按实测定的规则

**问题**：`内置-TLS异常` 是**裸单条匹配**（`event_type=tls_anomaly`，来一条报一条）。实测（7 天）：
59 条 ≈ 8 条/天，**全部**来自 `weird.log`，目标固定在同一个对外 TLS 服务（7 天 2,400+ 次成功会话里
约 7% 异常收尾），异常名是 `SSL_excessive_alerts_in_record` / `ssl_early_application_data`
—— 它们说的是「客户端/中间盒与该服务握手不顺」，属运维/健康信号，不是攻击事件。

**改成什么**（用户口径：只实现 TLS 层面高价值的攻击判断，放弃低价值的）：

| 规则 | 判据 | 阈值依据（线上实测，6 小时窗口采样） |
| --- | --- | --- |
| `内置-TLS弱版本协商` | 同源同目标协商出 SSLv3/TLSv1.0/TLSv1.1 ≥5 次/6 小时 | 弱版本共 20 条、集中在 1 对（领先 18 次 vs 其余 ≤1 次）→ 5 落在空白区 |
| `内置-TLS握手失败风暴` | 同源同目标 `tls_established=false` ≥30 次/6 小时 | 168 条 / 31 对，领先的一对 105 次、其余 ≤10 次 → 30 落在空白区 |

- 新增归一化字段 `tls_established`（Zeek `ssl.log` 的 `established`）—— 规则靠它判「握手没建立」；
- **不做**「版本回退（客户端 offer 版本高于协商结果）」：实测该判据 **0 条命中**（本环境没有降级特征），
  做了就是一条永不触发的死规则（同一类缺陷这轮已清理过）。将来环境变了再用同一套方法重新量；
- 两条阈值的第一版曾写成「10 次/1 小时」「30 次/1 小时」，对照数据会发现**永不触发**（实测单对峰值
  才 3 次/小时与 17.5 次/小时）⇒ 窗口改成 6 小时、门槛落在实测数据的空白区。这就是「先量再定」：
  阈值不是拍的，是在「领先那一对」和「其余所有对」之间那段空白里取的值。
