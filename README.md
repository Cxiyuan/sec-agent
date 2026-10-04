# 深瞳 · 安全分析智能体

基于 LangGraph 的**事件驱动**安全分析系统：规则检测器实时消费日志，命中后按短窗聚合，
把摘要投递给智能体做深度分析（攻击链 / 画像 / 定级 / 处置建议 / 报告）。

含 Web 管理后台 + 驾驶舱大屏。后端 FastAPI + Celery + PostgreSQL(pgvector)；前端 Next.js。

仓库分**两条可独立部署的线路**：

| 线路 | 目录 | 职责 | 自带的数据面 |
| --- | --- | --- | --- |
| **NDR 线路** | `ndr/` | Zeek 抓包 → 归一化 → 入库(ES) → 规则检测 → 投递摘要；并对外提供 **MCP 服务**（智能体取数的唯一入口） | Elasticsearch、Redis、PostgreSQL |
| **智能体线路** | `agent/` | 消费摘要跑 LangGraph 深度分析、自主取证调查、报告；带自己的 Web 后台 | PostgreSQL(pgvector) + Celery（复用 NDR 的 Redis） |

---

## 一、数据接入链路

```text
Zeek(Filebeat) ─┐
                ├→ Redis List  shentong:events:collect（采集队列）
Wazuh(Filebeat) ┘                    ↓
                        归一化服务 normalizer（python -m app.collector.normalizer_service）
                        UnifiedLog 统一字段（源系统/事件类型/IP/端口/协议/原文 raw…）
                                    ├─ ① LPUSH shentong:events:raw ──→ 检测器（实时车道）
                                    └─ ② POST Logstash:8080 ──→ ES  shentong-events-*（历史归档）

检测器 detector（常驻）
网段过滤 → 排除过滤 → 基线观测（数值 2σ + 账号/会话画像）
→ 幂等去重 → 逐条规则 + Redis 滑窗频率规则
→ 短窗聚合（源IP+规则）→ 给摘要打上基线标签 → 投递「聚合摘要」（攒批 20s / 5 条）
                                    ↓
智能体 HTTP 入口：POST /api/push/digests（Bearer 令牌）→ LangGraph
边缘降噪 → 归组 → 资产富化 → 画像标签（NDR 打好的）→ 技能路由 → 回溯 → 深度分析 → 定级 → HITL
→ 处置建议 → 报告 → 记忆写入；**收到就回 200**（同一事件组只累加计数、不重复出报告）
推送失败 → 落 shentong:events:pushretry，检测循环后台重发（2xx 才算送达）
                                    ↑
智能体取数（查询 / 回溯 / 基线画像 / 写回结论）走 NDR 的 MCP 服务 :8090/mcp（Bearer 令牌）
```

要点：
- **智能体不主动捞数据**，也不直连 ES：检测器实时投递聚合摘要，取数一律经 NDR 的 MCP 工具
  （索引名、字段白名单、条数上限、令牌吊销都由 NDR 侧掌握）
- **归一化前置**：入库的只有统一字段的文档，界面与智能体看到的是同一套字段名
- **基线在 NDR 侧算**（第 8 期）：长期均值/方差与账号/会话画像由检测器逐条沉淀，
  **模型只做定性**——摘要里带的是已算好的偏离与异常标签（详见 §四之二末）
- **短窗聚合**是关键：同源同规则上千次命中 → 1 条摘要，避免逐条送模型导致容量爆炸

---

## 二、部署（服务器）

前置：Linux 宿主、Docker + Compose；NDR 宿主还需 `vm.max_map_count=262144`（ES 硬要求）。
两条线路各自一个 compose 文件，可同机（端口已错开）或分机部署。
镜像在**私有 GHCR** 里，服务器上要先 `docker login ghcr.io`（PAT 需带 `read:packages`）才拉得动。
实机部署过程、验收结果与上线时踩到的六个坑见 [docs/ndr-redesign.md](docs/ndr-redesign.md) 的「实机部署记录（2026-10，172.16.196.77）」。

**NDR 线路**（`ndr/docker-compose.deploy.yml`）：

```bash
mkdir -p /opt/shentong-ndr && cd /opt/shentong-ndr
# 三个编排文件要放同一目录：docker-compose.deploy.yml、docker-compose.wazuh.yml、wazuh/filebeat.yml
cat > .env <<'EOF'
JWT_SECRET=<随机 64 位>
CORS_ORIGINS=http://<NDR服务器IP>:3000
ZEEK_IFACE=ens224          # 镜像/SPAN 抓包口
# 内置 Wazuh 4.14：这组变量同时喂给 wazuh-manager 和后台（ST_WAZUH_API_*），两边不会各写一份。
# 口令必须满足 Wazuh 复杂度要求（≥8 位且含大小写/数字/符号），否则 manager 的 API 起不来。
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=<强口令>
EOF
docker compose -f docker-compose.deploy.yml pull
docker compose -f docker-compose.deploy.yml up -d
```

部署编排默认 `include` 了 `docker-compose.wazuh.yml`（Wazuh 是本项目的**内置服务**，随项目一起发布），
所以这一条 `up -d` 会把 `wazuh-manager` + `wazuh-filebeat` 一起带起来。想临时不接 Wazuh 就按服务名起：
`docker compose -f docker-compose.deploy.yml up -d backend normalizer detector ndr-mcp`。

存储端口默认只绑宿主机回环（ES 9200 / Postgres 5432 / Redis 6379 都不对外，ES 与 Postgres
本身无额外鉴权）。**智能体线路要连这台机器的 Redis 时**（`NDR_REDIS_URL`），在 `.env` 里加：

```bash
REDIS_BIND=10.255.12.4   # Redis 监听的宿主地址（换成两边互通的地址）
REDIS_HOST=10.255.12.4   # zeek 容器是 host 网络，它的 Filebeat 用这个地址投采集队列
```

两行必须指向同一个可访问地址：`REDIS_BIND` 决定 Redis 发布在哪，`REDIS_HOST` 决定采集侧往哪投；
默认值（`127.0.0.1` / `localhost`）是同一台机器自洽的一套。隧道/该地址断开时采集会在 Filebeat
侧积压（不丢数据），恢复后继续投。

**智能体线路**（`agent/docker-compose.deploy.yml`）：

```bash
mkdir -p /opt/shentong-agent && cd /opt/shentong-agent
cat > .env <<'EOF'
JWT_SECRET=<随机 64 位>
CORS_ORIGINS=http://<智能体服务器IP>:3000
NDR_MCP_URL=http://<NDR服务器IP>:8090/mcp
NDR_MCP_TOKEN=<在 NDR 后台「智能体对接 → MCP 服务」生成的令牌>
NDR_REDIS_URL=redis://10.255.12.4:6379/0   # 必须是 NDR 侧 REDIS_BIND 放开的那个地址
EOF
docker compose -f docker-compose.deploy.yml pull
docker compose -f docker-compose.deploy.yml up -d
```

镜像全部从 GHCR 拉取（不在服务器本地构建）。服务清单：

| 线路 | 服务 | 作用 |
| --- | --- | --- |
| NDR | `elasticsearch` / `postgres` / `redis` | 存储与消息 |
| NDR | `backend` / `frontend` | API + 管理后台（全局页头：logo 深瞳·NDR / 告警铃铛 / 当前用户 / 退出；左侧八页：**总览** / 规则配置 / 采集接入 / 监控网段 / 数据存储 / 过滤规则 / 智能体对接 / 账户；**`/` 默认落到「总览」**） |
| NDR | `normalizer` | **归一化服务**（消费采集队列 → 检测器队列 + 写 ES） |
| NDR | `detector` | 实时检测器（消费归一化队列） |
| NDR | `ndr-mcp` | MCP 服务（`python -m app.mcp.server`，宿主 `:8090`） |
| NDR | `logstash` | 归一化文档入 ES（只有 ES 一个去处） |
| NDR | `zeek` | 抓包（host 网络 + NET_RAW/NET_ADMIN） |
| NDR | `wazuh-manager` / `wazuh-filebeat` | **内置**（部署编排默认 `include`，见 §三）：官方 Wazuh 4.14 manager（不含 indexer/dashboard）+ 独立 Filebeat 采集 |
| 智能体 | `postgres` | 智能体自己的库（pgvector 支持向量检索） |
| 智能体 | `backend` / `frontend` | API + 管理后台/驾驶舱 |
| 智能体 | `celery-worker` / `celery-investigation` / `celery-beat` | 分析任务 / 调查 worker / 定时任务（**摘要由 NDR 直接 HTTP 推给 `backend`**，不再有队列消费者进程） |

首次登录：两条线路各自 `admin` / `admin123`（**登录后请立即改密**）。

---

## 三、Wazuh 接入

Wazuh 的日志走**和 Zeek 一样的路**：Filebeat → NDR 的 Redis 采集队列 `shentong:events:collect`
（不直连 Logstash，也不直连 ES）。

### 3.1 用本仓库自带的 manager（内置服务，部署默认带上）

`ndr/docker-compose.wazuh.yml` 是内置服务的编排：部署编排 `docker-compose.deploy.yml` 用
`include` 引入它，所以部署就是一条命令（`up -d` 里已经含 Wazuh）：

```bash
cd ndr
docker compose -f docker-compose.deploy.yml up -d          # 含 wazuh-manager + wazuh-filebeat

# 本地开发默认编排不含 Wazuh，要接就显式叠加
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d
```

它加两个官方镜像服务：

| 服务 | 镜像 | 作用 |
| --- | --- | --- |
| `wazuh-manager` | `wazuh/wazuh-manager:4.14.8` | Wazuh 本体（**不含** indexer / dashboard），暴露 `55000`（API）与可选 `1514`/`1515` |
| `wazuh-filebeat` | `docker.elastic.co/beats/filebeat:8.15.3` | 只读挂载 manager 日志卷，按 `ndr/wazuh/filebeat.yml` 投 Redis |

> **为什么另起一个 Filebeat**：manager 自带的那个是为「发往 Wazuh indexer」预设的，
> 而「4.14 自带的 Filebeat 能否配 `output.redis`」没有实机验证过；Filebeat 又只支持单一
> output。另起一个用我们自己的配置，行为与 Zeek 线一致、可控。

细节与**实机验证记录**见 [`ndr/wazuh/README.md`](ndr/wazuh/README.md)（2026-10-03 已在
真实 Wazuh 4.14.8 环境上逐条跑过，六条清单全绿，过程中修掉 5 个真 bug —— 包括「告警被 ES
静默丢弃」「面板恒报读 ES 失败」「规则下发其实没生效」这三个会让「接入成功」站不住的问题）：

- 想要**全量原始日志**：先在 manager 上幂等开 `logall_json`（`ndr/wazuh/enable-logall.sh`），
  再把 `WAZUH_ARCHIVES_ENABLED=true` 传给 `wazuh-filebeat`。原始日志默认**只入库、不喂检测器**
  （`ST_WAZUH_ARCHIVE_TO_DETECTOR=false`）—— 量级比告警大得多，容量估算见
  [`docs/ndr-redesign.md`](docs/ndr-redesign.md) 第 6 期。
- 管理面「采集接入 → 主机监控」**只显示状态、不需要配置**：主机监控随项目一起部署，
  地址与凭据由部署环境固定（`.env` 的 `WAZUH_API_*` → 后台 `ST_WAZUH_API_*`）；
  面板显示 API 版本 / Agent 在线情况 / **近 24h 入库的告警与原始日志条数**（后者是链路真通了的证据），
  并可下发本地规则文件（下发后回读校验）。

### 3.2 接外部已有的 Wazuh

不要起本仓库的 `wazuh-manager`，把 `ndr/wazuh/filebeat.yml` 拷到能读到 `alerts.json` 的机器上，
改 `WAZUH_LOG_DIR` 与 `REDIS_HOST`/`REDIS_PORT`/`REDIS_KEY`，起 Filebeat 即可；再把那台 manager 的
API 地址与凭据写进后台的 `ST_WAZUH_API_*`（`GET /api/wazuh` 只读，界面没有填写入口）。

两个字段改配置时别丢：`overwrite_keys: true`（否则 Filebeat 自己的 ECS 顶层 `agent` 会盖掉 Wazuh
的 `agent.name`，主机名就丢了）与 **不设 ndjson `target`**（归一化服务直接从根读
`rule`/`data`/`agent`/`full_log`）。

### 3.3 Elasticsearch 也是内置的，连接信息同样不在界面上配

`up -d` 会一起起 `elasticsearch`。**地址与凭据只有部署环境一个来源**（`.env` 的
`ES_URL`/`ES_USER`/`ES_PASSWORD` → 后台 `ST_ES_*`，默认就是 `http://elasticsearch:9200`）：
「数据存储」页只把「现在连的是哪台」显示出来，没有地址输入框、密码框，也没有「测试连接」
（读路径的连通性看同页的集群状态与索引列表）；`GET /api/es/config` 只读，
`PUT /api/es/config` 只收**索引族与保留期**这两项策略，`POST /api/es/test` 已删除。

要换一台 ES：改 `.env` 再 `docker compose -f docker-compose.deploy.yml up -d backend` 重建容器。
Logstash 那一侧的 `elasticsearch { hosts => [...] }` 也由后端按 `ST_ES_URL` 生成 —— 容器重启时
会自动把已生成管道里的旧地址对齐（管道若被人手工改过就只告警、不覆盖，见「数据存储 → Logstash 管道」）。

---

## 四、部署后必做

1. **登录后立刻改密**：首次登录是 `admin` / `admin123`。改密在左侧「系统配置 → 账户」（或调
   `POST /api/auth/change-password`，新口令 8~128 位、不得与出厂口令相同）。只要还在用出厂口令，
   后端启动日志会警告一次、`GET /api/auth/me` 的 `default_password_in_use` 也是 `true`。
   首次部署想换掉建号口令就设环境变量 `ST_DEFAULT_ADMIN_PASSWORD`（只在**建号那一次**生效，
   库已建好后再改这个变量不会覆盖既有口令——要用「账户」页的改密）

2. **配置监控网段**（左侧「监控网段」页）——填要监控的网段/IP（每行一条，1~200 条）。
   保存后约 10 秒 Zeek 自动重载，`bpf_filter` / `local_nets` 由网段清单自动生成。
   复核一下真的吃到了：`docker exec <zeek> ps -o args= -C zeek` 里要出现 `-f net <你的网段>`
   （少了 `-f` 会被 Zeek 当成脚本名、启动即 fatal 重启循环——上线时踩过，见 docs 部署记录第 6 条）。
   网段在 **Zeek 抓包层**生效：没抓到的流量后面谁也看不到，这一步必须先做对
3. （智能体线路）**填云端模型 API Key**（系统配置 → 云端模型）
4. （智能体线路）边缘模型 IP（系统配置 → 边缘模型；默认已指向内网推理服务器）
5. （智能体线路）建议点「边缘模型 → 测试连接」确认可达
6. （NDR 线路）到「数据存储」确认集群状态与索引族：ES 是内置部署的，**地址与凭据由部署环境
   固定、界面上没有填写入口**（要换 ES 就改 `.env` 再重建 backend，见 §3.3）；
   页面上能改的是索引族与保留期。需要时在「数据存储 → Logstash 管道」调整入库管道
   （参数表单或管道全文；保存后 Logstash 约 10 秒自动重载，无需重启容器；
   每次保存自动备份上一版，界面可一键回滚）
7. （NDR 线路）需要时在「过滤规则 → 降噪过滤」把日常噪声挡在检测器外（**先用试运行看命中样例**）、
   在「过滤规则 → 排除过滤」把某些规则的分析关掉（可选；详见下节）
8. （NDR 线路）**生成 MCP 令牌**（智能体对接 → MCP 服务）：明文只显示一次，复制进智能体线路的 `NDR_MCP_TOKEN`；
   该面板还能看令牌用量、最近调用、智能体写回的结论与全部工具清单。令牌可以设有效天数
   （`POST /api/mcp/tokens` 的 `expires_in_days`，不设 = 永不过期）、随时**轮换**（原地换新明文，
   新的只显示一次）、单独**设到期**（`expires_at`）；过期令牌一律拒绝，列表里会标红
9. （两条线路）**配好摘要推送**：先给智能体线路设 `PUSH_TOKEN`（或 `ST_PUSH_TOKEN`），
   再到 NDR「智能体对接 → 摘要推送」填地址（`http://<agent>:8000/api/push/digests`）与同一令牌，
   点「测试连接」应为连通；之后检测器命中就会直接推过去（面板可看送达与失败计数）
10. （NDR 线路）**Wazuh 已内置，部署即已接入**：`up -d` 会一起起 `wazuh-manager` 与
   `wazuh-filebeat`；只需确认 `.env` 里的 `WAZUH_API_USER`/`WAZUH_API_PASSWORD` 是强口令
   （与 manager 共用同一组变量，后台直接取它，没有第二处要填），
   到「采集接入 → 主机监控」应直接看到「API 已连通」与 Agent 在线情况（这一页只显示状态，
   地址固定是 `https://wazuh-manager:55000`，没有保存/测试连接的入口）；
   要全量原始日志就先跑 `ndr/wazuh/enable-logall.sh` 再开 `WAZUH_ARCHIVES_ENABLED=true`。
   只有接**外部已有**的 Wazuh 时才需要看 §3.2
11. **日常盯「总览」页**（左侧导航第一项，也是 `/` 的默认落地页，每 15 秒自刷新）：
    **服务器状态**（CPU/内存/磁盘三个圆环，容器内读 `/proc`）、**组件呼吸灯**（网络采集器/
    主机监控/Redis/Logstash/Elasticsearch/归一化服务/分析智能体，绿=正常、黄闪=注意、红=不可用、
    灰=未知）、**威胁事件**（24h 命中与摘要趋势、严重度分布、规则 TOP15、投递覆盖率）、
    **24h 流量与协议**（按小时字节/秒曲线 + 协议占比圆图）、**链路细节**（五段速率、队列深度趋势、
    丢弃原因、投递重发、ES 按天索引、Logstash 吞吐、基线画像）。历史上 Redis 写满（noeviction）会使
    整条链路静默卡死 —— 队列/内存那两块一旦标红就是这个前兆。
    失败**不再静默**，各有明确去处：投递失败看「智能体对接 → 摘要推送」的 `undelivered` / `retry_lost` /
    `retry_dropped`（重发队列有 2000 条上限、单批最多试 5 次），处理异常看 `/api/detector/stats`
    的 `queue_failed`（隔离队列 `shentong:detector:failed`），归一化坏消息在 Redis
    `shentong:events:dead`（上限 1 万条）与 `shentong:collector:stats` 的累计计数里，
    采集队列被裁剪时也记计数。**Filebeat 的 `ndjson` 解析失败不再产生空壳文档**：能在顶层
    `message` 里拼回完整 JSON 的照常入库，拼不回的一律进死信（以前会落成只有时间戳与
    `log_type`、其余全空的文档，看着像"采集正常"）
12. **专门核对 Zeek 的日志生成与协议解析**（真实网卡上线后必做一遍）：实际产出了哪些
    `log_type`、各协议分析器字段是否齐全、HTTP 请求体有没有落进 http.log、归一化后的
    `log_type`/`event_type` 与内置规则的命中情况；反向代理场景的原始客户端 IP 走 `http.log` 的
    `proxied` → 归一化字段 `real_client_ip`（无代理头时为 NULL，`src_ip` 仍是 TCP 对端），
    **只有直连对端落在 `ST_ZEEK_TRUSTED_PROXIES` 里才认这些头**（留空 = 一律不认，防伪造；
    `X-Real-IP` 已并入 Zeek 的采集清单，四层代理的 PROXY protocol 见 `ndr/zeek/README.md`），
    响应体也采集（`resp_body` + `resp_body_len`，后者是整条响应体的字节数）。逐条清单见
    [`ndr/zeek/README.md`](ndr/zeek/README.md) 的「上线后专项检查」。
    **轮转与清理口径**：轮转文件名带时分秒（`conn.2026-10-01-08-00-00.log`），同一天多次重启
    不再互相覆盖；清理按 `mtime` 保留 **3 天**（分钟级判定），且 **Filebeat 没在运行时跳过删除**
    （先确保发运，再清归档；实测探针见 `ndr/zeek/README.md` 第 2 行）。zeek 容器现在有
    `HEALTHCHECK`（只上报不重启，不和入口脚本的自愈循环打架），底部状态：
    `docker inspect --format '{{.State.Health.Status}}' <zeek 容器>`
13. （NDR 线路）**确认 ES 集群健康是 green**：事件索引模板在后端启动时自动下发，副本按
    `auto_expand_replicas: "0-1"`（单节点 = 0 副本，所以不会出现「副本分配不出去」的常驻 yellow）。
    后端比 ES 先起来也不会漏：后台线程前 2 分钟每 5 秒重试、之后每 5 分钟复查一次（幂等），
    ES 一回来就补上，日志里会有一条「已在第 N 次尝试下发成功」。想立刻触发就到「数据存储 →
    保留期」点一次「下发保留期」——它同时会把**已经建好**的同类索引副本口径拉回
    `0 副本 + 0-1`（旧版本遗留的 1 副本索引也靠这一步回 green）
14. （NDR 线路）**确认存储与采集管道端口没有对外暴露**：`docker compose ps` 里
    ES/Postgres/Redis/**Logstash** 的 PORTS 应显示 `127.0.0.1:...`（或 `.env` 里
    `REDIS_BIND` 指定的那一个地址），**不应是 `0.0.0.0:...`** —— ES 与 Postgres 无额外鉴权、
    Redis 默认无密码；**Logstash 的 `8080` 是 `json_lines` 输入且无鉴权，谁都能往 ES 灌数据**
    （`9600` 是监控 API）。它们只给容器网络用（归一化服务 POST `logstash:8080`、后端读
    `logstash:9600`），发布到 `0.0.0.0` 等于同网段任何机器都能直接读写库、队列与归档。
    只有智能体线路确实要连 Redis 时才按 §二放开一个受控地址（`REDIS_BIND` + `REDIS_HOST` 成对改）`
15. （NDR 线路）**删卷重建后要重新做的事**：`docker compose down -v`（或换服务器）会清掉 ES 事件、
    Postgres（规则/用户/系统配置）、Redis 队列、Zeek 配置与日志、提取件；重新 `up -d` 后**建表、
    默认管理员 `admin`/`admin123`、内置规则、ES 模板与 ILM、Logstash 管道都会自动回来**，但
    **监控网段与两个正文上限必须重新下发**（左侧「监控网段」页，或 `PUT /api/zeek/interface`），
    MCP 令牌、摘要推送地址与令牌、云端模型 Key 也都要重填
    （**ES 与 Wazuh 的连接信息不用管**：它们在 `.env` 里，不在库里，删卷不影响）。脚本里调登录接口注意
    它是 **OAuth2 表单编码**（`-d 'username=admin&password=admin123'`），发 JSON 会 422 返回空 token

---

## 四之二、摘要推送与判重、降噪过滤与排除过滤

**HTTP 推送（第 5 期起，检测器 → 智能体）**：检测器把聚合摘要 POST 到智能体的
`/api/push/digests`（Bearer 令牌，两侧必须一致），**收到 2xx 就是送达**（响应当回执）。

- 没配地址或关了开关 → 回落旧的 `shentong:events:dispatch` 队列通道（仅对未升级的智能体有意义）
- 推送失败 → 整批落 `shentong:events:pushretry`（带 processing 队列防进程崩），检测循环每轮自动重发；
  失败原因与待重发批数在「智能体对接 → 摘要推送」面板里看（已送达 / 失败待重发 / 重发成功 / 重发失败）
- **判重在智能体侧**（只有它知道某个事件组分析过没有）：收到逐条算「事件组指纹」（源+目的 IP 集合 +
  `ST_GROUP_BUCKET_MINUTES` 时间桶，与落库用的同一套算法），
  ① 库里已有该组 → 只 `event_count += 摘要条数`、窗口前移，**不重复出报告**；
  ② 库里没有但 Redis 桶内占位已存在（同桶第一批还在跑）→ 跳过；③ 都没有 → 占位 + 投 Celery 跑图
- 代价：NDR 侧不再有闸门，同一事件在**不同时间桶**里会再推一次（这正是「同一事件持续发生时还能再报」的来源）；
  Redis 不可用时判重放行（宁可多跑、不漏报）
- 配置项见下表 `ST_AGENT_PUSH_*`（NDR 侧）与 `ST_PUSH_TOKEN`（智能体侧）

**降噪过滤（可选，检查点在归一化之后、规则之前）**：命中的事件**照样完整落进 ES**
（事件列表里查得到、可回溯，也就是“全量入库”没被破坏），只是**不投检测器**，因此不产生告警、
不花模型成本。适合挡掉扫描器日常噪声、监控探活、心跳域名这类“看着像攻击、其实每天都有”的流量。

- 条件只能引用**地址/端口 + 协议内容字段**（不允许拿 `raw` 全字段匹配），自带「内网互扫 / 监控探活 UA /
  心跳域名」三个现成示例
- 保存前必须能**试运行**：拿最近 N 小时的历史事件（ES → 检测器队列 → 采集队列依次取）跑一遍，
  告你这条条件会挡下多少条（含命中比例与最多 10 条样例）——先看清楚再启用
- 保存时三道校验：拒绝空条件、拒绝未知字段、校验正则；运行时求值失败按“不命中”处理（宁可多跑检测器，不漏报）
- 生效最多 30 秒（`ST_INGEST_FILTER_CACHE_SECONDS`）；「降噪过滤」面板能看到每条例挡下多少、最近挡下了什么
- **绝不用 Logstash `drop` 实现**：`drop` 会终止整条事件、连 ES 那份一起丢；这里是归一化服务里的一次判断，
  ES 输出永远无条件

**排除过滤（可选，检查点在规则命中之后）**：命中排除条件的事件**仍进事件列表**（状态为“已排除”、默认折叠）且可回溯，
但跳过边缘研判、深度分析、定级、处置、报告生成与记忆写入，因此不花模型成本。

- 条件可引用日志字段 + 命中规则元数据（`hit_rule` / `rule_source` / `rule_severity`），
  检查点在「规则命中之后」，所以能“把某条规则的全部噪声关掉”
- 保存时三道校验：拒绝空条件、拒绝未知字段、校验正则；运行时读配置失败按“不排除”处理（宁可多分析，不漏报）
- 生效最多 30 秒（`ST_EXCLUSION_CACHE_SECONDS`）；「排除过滤」面板能看到每个过滤器排掉了多少、最近排掉了什么

两者都导致「没有告警」：**降噪**是连检测器都没进，**排除**是进了检测器但不分析。智能体可用 MCP
`list_filters` 同时看到两道闸门，避免把“被过滤”误读成“没有异常”。

**基线与画像（第 8 期起，全部在 NDR 侧算）**：长期行为基线和账号/会话画像都是纯统计，不需要模型，
因此放在数据产生的 NDR 侧（检测器进程内），智能体只消费标签。

- **检查点**：网段过滤 + 排除过滤**之后**、规则**之前** —— 画像是长期行为基线，不该只学命中规则的那部分日志
- **数值 2σ 基线**：按源 IP 记三个维度（连接数 / 目的端口数 / 目的 IP 数），Welford 在线均值方差；
  当前值 > 均值 + `ST_BASELINE_ZSCORE` 个标准差就算偏离。**观测期内（默认 7 天）不打标**，
  标签里的 `warmed` 为 0 就代表「没报偏离 ≠ 正常」
- **账号/会话画像**：按账号（`account` 再退 `user`）与会话 cookie 累计源 IP / UA / 路径 / 时段分布，
  加权打分（新源 IP、新 UA、非常用时段、会话跨多 IP、失败多于成功），过 `ST_PROFILE_RISK_THRESHOLD` 才进异常
- **会话 cookie 先哈希再落库**（sha256，展示只用前 8 位），事件正文里只留截断值
- **交付**：① 摘要字段 `baseline`（`{checked, warmed, numeric[], profiles[]}`）——
  数值偏离会被智能体当作「异常确认」的候选，**定性仍由云端模型做**（NDR 只打标）；
  账号/会话异常渲染成提示词里的一段长期基线文本；② MCP 两个新工具
  `baseline_lookup`（查某 IP / 某维度的均值与标准差）与 `entity_profile`（查账号/会话画像与过阈值异常，
  智能体的 `entity_profile` 调查工具就是转发它）
- **界面**：并入「运行状态」页的「基线观测」块，不新增导航项；不跑检测器时该块会显示「未在跑」
- **调参**：见下表 `ST_BASELINE_*` / `ST_PROFILE_*`；`ST_BASELINE_ENABLED` 关掉后摘要不带标签，
  智能体侧自动退化为「无基线信息」（不会报错）

---

## 五、关键配置项（环境变量，`ST_` 前缀）

NDR 线路（采集与检测）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ST_ES_URL` / `ST_ES_USER` / `ST_ES_PASSWORD` | `http://elasticsearch:9200` / 空 / 空 | ES 连接信息，**唯一来源**（面板只读、没有填写入口）；部署时由 `.env` 的 `ES_*` 传入 |
| `ST_ES_EVENTS_INDEX` | shentong-events-* | 统一事件索引（确认模板写入 `shentong-events-%{+yyyy.MM.dd}`） |
| `ST_ES_RETENTION_DAYS` | 30 | ES 保留期（ILM 策略） |
| `ST_LOOKBACK_MAX_DAYS` | 7 | 回溯最大跨度的**兜底**值；实际跟着运行时保留期走（后台改「保留期」不用重启，见 `investigation/es_query.py:154`） |
| `ST_ZEEK_INTERFACE` | ens224 | 抓包网卡的兜底名（界面「监控网段」页保存的值优先；下拉里只列**物理网卡**） |
| `ST_ZEEK_MONITORED_NETS` | 空 | 监控网段/IP（界面「监控网段」页写入的值优先） |
| `ST_ZEEK_BPF_EXTRA` | 空 | 附加 BPF 片段，追加在网段表达式之后 |
| `ST_ZEEK_TRUSTED_PROXIES` | 空 | **可信代理白名单**（逗号分隔的 IP/CIDR）：只有直连对端在清单里，才承认 `X-Forwarded-For` / `X-Real-IP` 里的客户端地址（`real_client_ip`）；**留空 = 不认任何代理头**（fail-closed）。安全锚点，只从部署环境给（`.env` 的 `ZEEK_TRUSTED_PROXIES`），界面无入口 |
| `ST_WAZUH_ARCHIVE_TO_DETECTOR` | false | Wazuh 原始日志（`logall_json`）是否也投检测器；默认**只入库** |
| `ST_WAZUH_API_URL` / `ST_WAZUH_API_USER` / `ST_WAZUH_API_PASSWORD` | 空 | Wazuh API 连接信息，**唯一来源**（面板只读、没有填写入口）；部署时由 `.env` 的 `WAZUH_API_*` 传入 |
| `ST_WAZUH_API_VERIFY_TLS` / `ST_WAZUH_API_TIMEOUT_SECONDS` | false / 10 | Wazuh 自签证书是常态，默认不校验 TLS |
| `ST_COLLECTOR_COLLECT_QUEUE` | shentong:events:collect | Filebeat 写入的**采集队列** |
| `ST_COLLECTOR_CONSUME_BATCH` / `ST_COLLECTOR_POLL_TIMEOUT` | 500 / 5 | 归一化服务每轮取批与轮询超时 |
| `ST_COLLECTOR_POST_RETRIES` / `ST_COLLECTOR_RETRY_BACKOFF_SECONDS` | 3 / 1.0 | 写 Logstash 失败的重试次数与退避 |
| `ST_COLLECTOR_QUEUE_MAX` | 30000 | 采集队列封顶（保最新、丢最旧；Filebeat 用 RPUSH 写右端） |
| `ST_DETECTOR_ENABLED` | true | 关掉则只归一化入库、不做检测 |
| `ST_DETECTOR_AGG_SECONDS` | 300 | 短窗聚合时长（源IP+规则） |
| `ST_DETECTOR_BATCH_SECONDS` / `ST_DETECTOR_BATCH_MAX` | 20 / 5 | 攒批投递触发条件 |
| `ST_DETECTOR_MAX_DIGESTS_PER_MINUTE` | 24 | 投递速率上限（对齐模型容量） |
| `ST_DETECTOR_MAX_DIGESTS_PER_RULE_MINUTE` | 8 | **单规则名**每分钟摘要上限（0=不限）。per-event 规则没有别的抑制手段，一条噪声规则（如横向移动管理端口）能几分钟吃满总额度把高价值摘要挤到超龄丢弃；超限计入 `dropped.rule_capped`。额度不足时**按严重度降序**投递，不再 FIFO |
| `ST_DETECTOR_HISTORY_KEY` / `ST_DETECTOR_HISTORY_MAX` | shentong:detector:history / 288 | **检测器历史采样**（总览页 24h 趋势/威胁图的数据源）：每 `ST_DETECTOR_STATS_LOG_SECONDS` 追加一条，LPUSH+LTRIM 固定条数（288 = 24h @ 5min）+ 7 天 TTL。以前 `shentong:detector:rates` 每次都被覆盖，没有历史可画 |
| `ST_STATUS_PROBE_CACHE_SECONDS` | 30 | 总览页「组件呼吸灯」的进程内探测缓存（组件健康 + ES 新鲜度）：页面 15 秒轮询，两次里大约一次命中缓存，不每轮都打 ES/外部 API |
| `ST_STATUS_AGG_CACHE_SECONDS` | 300 | 总览页 24h 流量/协议聚合（ES）的进程内缓存；命中直接回 `cached=true`，页面轮询不得穿透 |
| `ST_SYSTEM_METRICS_CPU_SAMPLE_SECONDS` | 0.15 | 读两次 `/proc/stat` 的间隔（算 CPU 占用%；端点是同步 `def`，跑在线程池，不阻塞事件循环） |
| `ST_AGENT_PUSH_URL` | 空 | 智能体推送地址（形如 `http://<agent>:8000/api/push/digests`）；**空 = 不投递**（不再进退役队列，会明确计 `undelivered`） |
| `ST_AGENT_PUSH_TOKEN` | 空 | 推送令牌（与智能体 `ST_PUSH_TOKEN` 一致） |
| `ST_AGENT_PUSH_ENABLED` | true | 推送开关（关掉 = 不投递，同样计 `undelivered`） |
| `ST_AGENT_PUSH_TIMEOUT_SECONDS` / `ST_AGENT_PUSH_MAX_PER_PUSH` | 10 / 200 | 单次请求超时与每批条数（超出分片） |
| `ST_DETECTOR_PUSH_RETRY_QUEUE` / `..._PROCESSING_QUEUE` | shentong:events:pushretry / ...:processing | 推送失败的重发队列（ReliableQueue；**上限 2000 批**，超出丢最旧并计 `retry_dropped`） |
| `ST_DETECTOR_PUSH_RETRY_MAX_PER_ROUND` | 50 | 每轮最多重发多少批（单批最多试 5 次，超限丢并计 `retry_lost`） |
| `ST_BASELINE_ENABLED` | true | 基线观测总开关（关掉则摘要不带 `baseline` 标签） |
| `ST_BASELINE_OBSERVE_DAYS` | 7 | 观测期：不足这么多天只学习、不打标 |
| `ST_BASELINE_ZSCORE` | 2.0 | 数值偏离阈值（当前值 > 均值 + N 个标准差） |
| `ST_BASELINE_FLUSH_SECONDS` | 60 | 画像观测落库 + 判异常的节奏（秒） |
| `ST_BASELINE_CLEANUP_SECONDS` | 3600 | 过期画像清理的检查节奏（秒） |
| `ST_BASELINE_MAX_OBSERVATIONS` | 50000 | 单窗口最多攒多少条画像观测，超了提前落库 |
| `ST_BASELINE_CACHE_MAX` | 20000 | 进程内数值基线缓存条目上限（超出丢最旧的） |
| `ST_BASELINE_STATS_KEY` | shentong:baseline:stats | 检测器侧基线计数键（「运行状态」页看活性） |
| `ST_PROFILE_ENABLED` | true | 账号/会话画像开关（关掉则只算数值 2σ） |
| `ST_PROFILE_MIN_OBS` | 5 | 观测次数不足时只学习、不打分（冷启动） |
| `ST_PROFILE_RISK_THRESHOLD` | 0.6 | 画像异常风险分阈值（达到才报） |
| `ST_PROFILE_RETENTION_DAYS` | 180 | 画像保留期（到期清理） |
| `ST_SESSION_COOKIE_NAMES` | JSESSIONID,PHPSESSID,… | 会话 cookie 名单（命中才按会话建画像；**先哈希再落库**） |
| `ST_EXCLUSION_CACHE_SECONDS` | 30 | 排除过滤配置缓存（跨进程生效延迟上限） |
| `ST_INGEST_FILTER_CACHE_SECONDS` | 30 | 降噪过滤配置缓存（同上） |
| `ST_INGEST_FILTER_DRY_RUN_HOURS` | 24 | 试运行默认回看时长（界面可改） |
| `ST_INGEST_FILTER_DRY_RUN_MAX` | 500 | 试运行默认取样条数上限（硬上限 5000） |
| `ST_LOGSTASH_API_URL` | http://logstash:9600 | Logstash 监控 API（后端读状态用） |
| `ST_LOGSTASH_HTTP_PORT` | 8080 | 归一化服务写 Logstash 的 http 输入 |
| `ST_LOGSTASH_PIPELINE_CONF` | /logstash/logstash.conf | 管道配置路径（共享卷内；文件名必须叫 logstash.conf，否则会与镜像自带示例管道同时被加载） |
| `ST_LOGSTASH_PIPELINE_BACKUP` | /logstash-backup/logstash.conf.bak | 管道备份路径（**必须与管道目录分开**：Logstash 会把管道目录里所有文件当配置读，备份放进去就变成第二个管道） |
| `ST_MCP_HOST` / `ST_MCP_PORT` / `ST_MCP_PATH` | 0.0.0.0 / 8090 / /mcp | MCP 服务监听与路径 |
| `ST_MCP_PUBLIC_URL` | http://ndr-mcp:8090 | MCP 对外地址（面板显示与自检用） |
| `ST_MCP_MAX_ROWS` | 500 | 单次查询返回条数上限 |
| `ST_MCP_CONCLUSION_RETENTION_DAYS` | 7 | 智能体写回结论的保留期（与判重窗口对齐） |
| `ST_DEFAULT_ADMIN_PASSWORD` | admin123 | **首次部署建号**用的管理员口令（只在建号那一次生效；已建库后改用「账户」页改密） |

智能体线路（取数与分析）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ST_MCP_URL` | http://ndr-mcp:8090/mcp | **取数唯一入口**（NDR 的 MCP 服务） |
| `ST_MCP_TOKEN` | 空 | 在 NDR 后台「智能体对接 → MCP 服务」生成的令牌；空 = 取数不可用 |
| `ST_MCP_TIMEOUT_SECONDS` | 90 | 单次工具调用超时（要大于 NDR 侧单次 ES 查询的 45s） |
| `ST_PUSH_TOKEN` | 空 | **接收 NDR 推送的令牌**（与 NDR「智能体推送」里填的一致）；空 = 拒绝所有推送（503） |
| `ST_PUSH_DEDUP_KEY` | shentong:agent:push | 判重占位键前缀（Redis，TTL = 两个时间桶） |
| `ST_PUSH_MAX_ITEMS` | 500 | 单次最多接收多少条摘要（超出 413） |
| `ST_GROUP_BUCKET_MINUTES` | 30 | 事件组时间桶（判重与落库共用，两侧必须一致） |
| `ST_LOOKBACK_MAX_LOGS` / `ST_LOOKBACK_MAX_EVENTS` | 5000 / 200 | 回溯取原始日志与落地窗口事件的条数上限 |

模型与凭据：
- 边缘模型：连接信息固化在 `agent/backend/app/edge_config.py`（仅 IP 可在界面改）
- 云端模型：模型名固化（`agent/backend/app/models/registry.py`），API Key 在界面录入、存数据库

---

## 六、开发约定

- **只用 GitHub Actions 构建镜像**，禁止本地构建（`docker build` / `npm run build`）
- 本地质量门（仓库根执行；**都不需要 Docker、也不产生构建产物**）：
  - `.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py`
  - `.venv/bin/pyright ndr/backend/app agent/backend/app tests/py`
  - `.venv/bin/python -m pytest tests/py --stack=ndr -q` 与 `--stack=agent -q`
    （两个后端包的 import 名都是 `app`，只能分开跑；一致性用例会比对两侧归一化输出）
  - 前端在 `ndr/frontend` / `agent/frontend` 下 `npx tsc --noEmit`
  - **`sh tests/zeek/run.sh` 不在本地跑**：它会拉 `zeek/zeek:9.0` 并在容器里编译脚本，
    已列入 CI 的 `test` 作业（与 AGENTS.md 的「禁止本地拉镜像/起容器」一致）
  测试怎么加、覆盖什么见 `tests/README.md`
- 推送 `main` 触发 CI 构建五个镜像到 GHCR：`shentong-ndr`、`shentong-ndr-frontend`、`shentong-zeek`
  （NDR 线路）与 `shentong-agent`、`shentong-agent-frontend`（智能体线路）


## 数据路径（两层）

1. **实时车道**：Filebeat → Redis 采集队列 → 归一化服务 → 检测器（规则命中才进智能体，额度对齐模型容量）。
   归一化服务同时把同一份文档写进 ES；检测器队列裁剪最老的日志以封顶 Redis 内存。
2. **ES 全量事实源**：归一化后的全量文档长期保留（统一索引族 `shentong-events-*`），
   随时可按需查询/回溯——智能体经 **NDR 的 MCP 工具**查（不直连 ES），界面在 NDR 后台查。

**「水位兜底（全量重放）」已彻底移除**：实测单轮过完整图必被硬超时、水位永不推进，反而占死 worker。
因此不承诺自动补齐历史——被裁剪或停机期间的日志只留在 ES，按需查询。
