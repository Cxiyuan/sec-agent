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

---

## 五、关键配置项（环境变量，`ST_` 前缀）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ST_ANALYSIS_INTERVAL_MINUTES` | 15 | 兜底任务间隔（实时链路为主） |
| `ST_FALLBACK_MAX_BACKFILL_HOURS` | 24 | 单次最大回补时长（防长期停机后拉爆） |
| `ST_DETECTOR_ENABLED` | true | 关掉则退化为「纯定时拉取」 |
| `ST_DETECTOR_AGG_SECONDS` | 60 | 短窗聚合时长（源IP+规则） |
| `ST_DETECTOR_BATCH_SECONDS` / `ST_DETECTOR_BATCH_MAX` | 20 / 5 | 攒批投递触发条件 |
| `ST_FREQ_WINDOW_SECONDS` / `ST_FREQ_COOLDOWN_SECONDS` | 300 / 300 | 频率规则滑动窗口与冷却 |
| `ST_MAX_LOGS_PER_WINDOW` | 20000 | 单次拉取上限 |

模型与凭据：
- 边缘模型：连接信息固化在 `backend/app/edge_config.py`（仅 IP 可在界面改）
- 云端模型：模型名固化（`backend/app/models/registry.py`），API Key 在界面录入、存数据库

---

## 六、开发约定

- **只用 GitHub Actions 构建镜像**，禁止本地构建（`docker build` / `npm run build`）
- 本地质量门：`cd backend && .venv/bin/ruff check app/ && .venv/bin/pyright app/`；前端 `npx tsc --noEmit`
- 推送 `main` 触发 CI 构建三个镜像（backend / frontend / zeek）到 GHCR
