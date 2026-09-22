# 深瞳 · 安全分析智能体

基于 **LangGraph** 的定时批量安全分析智能体：每 5 分钟从 Elasticsearch 拉取窗口日志，走多节点分析管线（降噪→关联→深度分析→定级→处置→报告），结果落 PostgreSQL，通过 **Web 管理后台 + 驾驶舱大屏** 展示。

## 技术栈

- **语言**：Python 3.11（后端）/ TypeScript（前端）
- **分析框架**：LangGraph（混合结构：主流水线 + 条件分支 + 深度分析子图）
- **后端**：FastAPI + Celery（Beat 调度 + Worker 执行）
- **前端**：Next.js 14 + React + shadcn/ui 风格 + ECharts（暗黑主题）
- **存储**：Elasticsearch（原始日志）、PostgreSQL（分析结果/规则/报告/配置）、Redis（Celery broker + 推送）
- **模型**：本项目**只负责对接调用**，不负责模型运行环境。通过统一 OpenAI 兼容接口连接边缘模型（本地部署）与云端模型（局域网 one-api 代理）

> **范围边界**：LLM 模型本身的运行环境（llama.cpp / Ollama / vLLM、one-api 代理、模型权重等）由外部部署，不属于本项目。本项目只通过 `ST_EDGE_MODEL_BASE_URL` / `ST_CLOUD_MODEL_BASE_URL` 对接调用。

## 数据流

```
Zeek(网络) ─┐
            ├─→ Elasticsearch ──(每5分钟 Celery Beat)──→ LangGraph 分析管线 ──→ PostgreSQL
Wazuh(主机)─┘                                                   │
外部威胁情报(IP信誉/地理/已知恶意) ────────────────────────────→ 画像富化 │
                                                                  ▼
外部 LLM 接口(边缘模型 / one-api) ──(对接调用，非本项目部署)───→ 分析节点
                                                                  ▼
                                    FastAPI ←── Web管理后台 + 驾驶舱大屏（Next.js）
```

## LangGraph 分析管线

| 节点 | 职责 |
|---|---|
| 0 调度 | Celery Beat 每 5 分钟触发 |
| 1 拉取+规范化+去重 | 从 ES 拉全量窗口日志，统一 schema，窗口指纹去重 |
| 2 研判降噪 | 四层漏斗：用户规则 → 内置规则 → 边缘模型审查 → 打分 |
| 3 多源关联 | IP+时间窗口归组，规则+语义混合，输出事件+归属组 |
| 4 云端深度分析 | 子图三节点：异常检测（统计+LLM）、攻击链还原（4阶段+证据）、攻击者画像 |
| 5 定级 | 5 级（紧急/高/中/低/提示），规则+LLM |
| 5.5 HITL | 可配置，高危定级后 interrupt 暂停，人工确认后 resume |
| 6 处置建议 | 阻断+修复+应急流程，只建议不自动执行 |
| 7 报告输出 | 模板+LLM 填充，Jinja2 渲染 PDF（WeasyPrint） |

## 目录结构

```
├── backend/               # FastAPI + LangGraph + Celery
│   └── app/
│       ├── agents/        # LangGraph 节点、子图、图定义、运行器
│       ├── rules/         # 规则引擎 + 内置规则
│       ├── models/        # 统一模型封装（边缘/云端）+ 提示词
│       ├── ingestion/     # ES 拉取、规范化、去重
│       ├── intel/         # 外部威胁情报
│       ├── reports/       # PDF 报告渲染 + 模板
│       ├── api/           # FastAPI 路由 + WebSocket
│       ├── db/            # SQLAlchemy 模型
│       └── workers/       # Celery + Redis 发布
├── frontend/              # Next.js + shadcn/ui 风格 + ECharts
├── docker-compose.yml
└── .github/workflows/     # CI：构建 Docker 镜像
```

## 快速启动

```bash
docker compose up -d
```

> 启动前请确保外部依赖可达（可用 `.env` 覆盖）：Elasticsearch、PostgreSQL、Redis，以及
> **外部部署的 LLM 接口**（边缘模型与 one-api 代理）。模型运行环境不在本 compose 内。

前端 http://localhost:3000（默认账号 `admin` / `admin123`），后端 http://localhost:8000。

## 环境变量（后端，前缀 `ST_`）

| 变量 | 说明 | 默认 |
|---|---|---|
| `ST_ES_URL` | Elasticsearch 地址 | `http://localhost:9200` |
| `ST_PG_URL` | PostgreSQL 连接串 | `postgresql+psycopg://shentong:shentong@localhost:5432/shentong` |
| `ST_EDGE_MODEL_BASE_URL` | 边缘模型 OpenAI 接口（外部部署） | `http://localhost:8080/v1` |
| `ST_CLOUD_MODEL_BASE_URL` | one-api 代理地址（外部部署） | `http://localhost:3000/v1` |
| `ST_CLOUD_MODEL_API_KEY` | 云端模型密钥 | 空 |
| `ST_JWT_SECRET` | JWT 密钥 | `change-me-in-production` |

完整配置见 `backend/app/config.py`。

> 模型运行环境（推理服务、one-api、模型权重）**不在本项目范围**，本项目只需其服务地址与密钥。

完整配置见 `backend/app/config.py`。

## 构建与部署

- **只用 GitHub Actions 构建** Docker 镜像（`.github/workflows/ci.yml`），推送到 GHCR。
- **禁止本地构建**：不在本地执行 `docker build`、`npm run build`、`go build` 等。
- 本地只写代码、提交推送，构建结果以流水线为准。

## 本地开发与类型检查

项目规则禁止本地构建，但**类型检查不是构建**，可在本地装依赖验证：

```bash
# 后端
cd backend
python3.12 -m venv .venv
.venv/bin/pip install -e . --no-deps        # 先装依赖（见 pyproject.toml）
.venv/bin/pyright app/                       # 应为 0 errors

# 前端
cd frontend
npm install
npx tsc --noEmit                             # 应为 0 errors
```

> 注：编辑器内 pyright LSP 若显示 "Import could not be resolved"，是 LSP 未加载本地 venv 所致；以上命令为准。
