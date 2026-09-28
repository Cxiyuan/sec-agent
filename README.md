# 深瞳 · 安全分析智能体

基于 LangGraph 的**事件驱动**安全分析系统：规则检测器实时消费日志，命中后按短窗聚合，
把摘要投递给智能体做深度分析（攻击链 / 画像 / 定级 / 处置建议 / 报告）。

含 Web 管理后台 + 驾驶舱大屏。后端 FastAPI + Celery + PostgreSQL(pgvector)；前端 Next.js。

---

## 一、数据接入链路

```text
Zeek(Filebeat) ─┐
                ├→ Logstash(:5044) ─┬→ Elasticsearch   历史归档 + 界面/回溯查询
Wazuh(外部) ────┘                    └→ Redis List      旁路队列 shentong:events:raw
                                                              ↓
                                    检测器 detector（常驻）
                                    归一化 → 网段过滤 → 幂等去重
                                    → 逐条规则 + Redis 滑窗频率规则
                                    → 短窗聚合（源IP+规则，默认 60s）
                                    → 投递「聚合摘要」（攒批 20s / 5 条）
                                                              ↓
                                    智能体分析：边缘降噪 → 归组 → 资产富化 → 记忆/画像
                                    → 技能路由 → 回溯 → 深度分析 → 定级 → HITL
                                    → 处置建议 → 报告 → 记忆/画像更新

兜底（水位驱动，默认每 15 分钟）：窗口 = [上次水位, now] → 拉 ES → 跳过检测器已处理的 → 只补漏
```

要点：
- **智能体不主动捞数据**；检测器实时检测并把聚合摘要投递给它
- **短窗聚合**是关键：同源同规则 1234 次命中 → 1 条摘要，避免逐条送模型导致容量爆炸
- **兜底任务补齐故障期漏报**：窗口由水位（存 PostgreSQL）决定，而非写死 15 分钟；
  服务整体停机数小时后恢复，能一次性补上停机期间的漏报

---

## 二、部署（服务器）

前置：Linux 宿主、Docker + Compose；`vm.max_map_count=262144`（ES 硬要求）。

```bash
mkdir -p /opt/shentong && cd /opt/shentong
# 放置 docker-compose.yml（仓库的 docker-compose.deploy.yml）与 .env
cat > .env <<'EOF'
JWT_SECRET=<随机 64 位>
CORS_ORIGINS=http://<服务器IP>:3000
ZEEK_IFACE=ens224          # 镜像/SPAN 抓包口
EOF

docker compose pull
docker compose up -d
docker compose ps
```

镜像全部从 GHCR 拉取（不在服务器本地构建）。服务清单：

| 服务 | 作用 |
| --- | --- |
| `elasticsearch` / `postgres` / `redis` | 存储与消息 |
| `backend` / `celery-worker` / `celery-beat` | API 与分析任务 |
| `detector` | **实时检测器**（消费旁路队列） |
| `logstash` | 采集侧双写（ES + 队列） |
| `frontend` | 管理后台 + 驾驶舱 |
| `zeek` | 抓包（host 网络 + NET_RAW/NET_ADMIN） |

首次登录：`admin` / `admin123`（**登录后请立即改密**）。

---

## 三、Wazuh 接入（外部采集）

Wazuh 的采集输出需指向本项目的 Logstash（`<服务器IP>:5044`，beats 协议）：

在 Wazuh 侧的 Filebeat 配置（通常在 `/etc/filebeat/filebeat.yml`）：

```yaml
output.logstash:
  hosts: ["<深瞳服务器IP>:5044"]
  # 若原来是 output.elasticsearch，请替换为上面两行
```

未接入前，Wazuh 事件只能靠**兜底任务**（15 分钟）覆盖；Zeek 走旁路队列为秒级实时。

---

## 四、部署后必做

1. **登录改密**（admin/admin123）
2. **配置分析网段**（系统配置 → 分析网段）——不配则不会分析任何日志
3. **填云端模型 API Key**（系统配置 → 云端模型）
4. 边缘模型 IP（系统配置 → 边缘模型；默认已指向内网推理服务器）
5. 建议点「边缘模型 → 测试连接」确认可达
6. 需要时在「系统配置 → 采集侧 · Logstash 管道」调整采集链路
   （参数表单或管道全文；保存后 Logstash 约 10 秒自动重载，无需重启容器；
   每次保存自动备份上一版，界面可一键回滚）
7. 需要时在「系统配置 → 排除过滤」加降噪规则（可选；详见下节）

---

## 四之二、投递前去重与排除过滤

**投递前去重（默认开）**：检测器投递前会按「规则 + 源 IP + 30 分钟时间桶」指纹查库，
同一事件组在桶内只投一次，避免同一事件反复跑完整 LLM 链（最多可省 ~30 次/桶）。

- 两态标记：`inflight`（已投递、图在跑，检测器写）→ `done`（图正常跑完，worker 写）
- 失败不会永久吞事件：任务异常保持 `inflight`，超过在途 TTL（40 分钟）后允许重投
- 代价：被拦下的摘要，其命中次数不会补进事件组（事件在、桶内规模可能低估）
- 关掉：`ST_DEDUP_ENABLED=false`；状态看「采集侧」面板的「去重闸门」一行

**排除过滤（可选）**：命中排除条件的事件**仍进事件列表**（状态为“已排除”、默认折叠）且可回溯，
但跳过边缘研判、深度分析、定级、处置、报告生成与记忆写入，因此不花模型成本。

- 条件可引用日志字段 + 命中规则元数据（`hit_rule` / `rule_source` / `rule_severity`），
  检查点在「规则命中之后」，所以能“把某条规则的全部噪声关掉”
- 保存时三道校验：拒绝空条件、拒绝未知字段、校验正则；运行时读配置失败按“不排除”处理（宁可多分析，不漏报）
- 生效最多 30 秒（`ST_EXCLUSION_CACHE_SECONDS`）；「排除过滤」面板能看到每个过滤器排掉了多少、最近排掉了什么

---

## 五、关键配置项（环境变量，`ST_` 前缀）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ST_ANALYSIS_INTERVAL_MINUTES` | 15 | 兜底任务间隔（实时链路为主） |
| `ST_FALLBACK_MAX_BACKFILL_HOURS` | 24 | 单次最大回补时长（防长期停机后拉爆） |
| `ST_DETECTOR_ENABLED` | true | 关掉则退化为「纯定时拉取」 |
| `ST_DETECTOR_AGG_SECONDS` | 60 | 短窗聚合时长（源IP+规则） |
| `ST_DETECTOR_BATCH_SECONDS` / `ST_DETECTOR_BATCH_MAX` | 20 / 5 | 攒批投递触发条件 |
| `ST_DETECTOR_MAX_DIGESTS_PER_MINUTE` | 8 | 投递速率上限（对齐边缘模型实测容量 3~4 条/分钟） |
| `ST_DEDUP_ENABLED` | true | 投递前去重闸门（按指纹查库，已分析过的不再重复投） |
| `ST_DEDUP_INFLIGHT_TTL_SECONDS` | 2400 | 在途标记有效期（需 > 任务硬超时 1800s） |
| `ST_ANALYZED_RETENTION_DAYS` | 7 | 已完结指纹保留天数 |
| `ST_EXCLUSION_CACHE_SECONDS` | 30 | 排除过滤配置缓存（跨进程生效延迟上限） |
| `ST_FREQ_WINDOW_SECONDS` / `ST_FREQ_COOLDOWN_SECONDS` | 300 / 300 | 频率规则滑动窗口与冷却 |
| `ST_MAX_LOGS_PER_WINDOW` | 20000 | 单次拉取上限 |
| `ST_LOGSTASH_API_URL` | http://logstash:9600 | Logstash 监控 API（后端读状态用） |
| `ST_LOGSTASH_PIPELINE_CONF` | /logstash/logstash.conf | 管道配置路径（共享卷内；文件名必须叫 logstash.conf，否则会与镜像自带示例管道同时被加载） |
| `ST_LOGSTASH_PIPELINE_BACKUP` | /logstash-backup/logstash.conf.bak | 管道备份路径（**必须与管道目录分开**：Logstash 会把管道目录里所有文件当配置读，备份放进去就变成第二个管道） |

模型与凭据：
- 边缘模型：连接信息固化在 `backend/app/edge_config.py`（仅 IP 可在界面改）
- 云端模型：模型名固化（`backend/app/models/registry.py`），API Key 在界面录入、存数据库

---

## 六、开发约定

- **只用 GitHub Actions 构建镜像**，禁止本地构建（`docker build` / `npm run build`）
- 本地质量门：`cd backend && .venv/bin/ruff check app/ && .venv/bin/pyright app/`；前端 `npx tsc --noEmit`
- 推送 `main` 触发 CI 构建三个镜像（backend / frontend / zeek）到 GHCR


## 三层数据路径与补齐 SLA

1. **实时车道**：Logstash 双写 → Redis → 旁路检测器（规则命中才进智能体）。
   实测能力约 130 条/秒（平稳），突发峰值（~1850 条/秒）会进入排队，极端时按上限裁剪最老的日志。
2. **水位兜底（已停用）**：原设计是每 15 分钟按水位重放 ES，但实测「单轮过完整图」必被 1800s 硬超时、水位永不推进，反而占死 worker。
   现已从 beat 调度中摘除（`fallback_enabled=false`，置 true 可恢复）。因此**不再承诺自动补齐历史**：
   被裁剪/停机期间的日志只留在 ES，通过自主调查工具按需查询。
3. **ES 全量事实源**：所有原始日志长期保留，可随时回溯/按需查询（自主调查工具直接查 ES）。

对账工具：`GET /api/detector/backfill-check?minutes=90` 抽样核对「ES 文档是否进入了分析」。
资源账：raw 队列上限 20 万条（约 650MB Redis，maxmemory 1.5GB，超 85% 触发内存告警）。
