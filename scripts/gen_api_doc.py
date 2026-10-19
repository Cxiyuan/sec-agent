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
    ("配置管理", "/api/rules", "检测规则 CRUD（每条带 `source_kind`/`source_label` 三类来源）"),
    ("配置管理", "/api/suricata", "签名引擎：内置规则集查看/校验/生效/重置/在线源"),
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
- **配置管理**：`/api/rules`、`/api/suricata/rules`、`/api/zeek/*`、`/api/es/*`、`/api/config/audit`

## 三·补、近期字段变化（端点没变，字段有增）

| 接口 | 新增字段 | 说明 |
| --- | --- | --- |
| `GET /api/detector/hits`、`/hits/{id}` | `event_type_labels` | 事件类型的**中文名**（`signature_hit` → 签名命中、`protocol_anomaly` → 协议异常、`baseline_deviation` → 基线偏离）。与 `event_types`（英文码）并列返回，前端不用自建映射表 |
| `GET /api/detector/hits`、`/hits/{id}` | （已有）`source_kind` / `source_label` | 三类来源：特征匹配 / 行为分析 / 基线偏离 |
| `GET /api/baseline/profiles` | `posterior` | 似然比**后验概率**（0~1）。打分方式=llr 时列表按它排序；`risk_score` 仍返回（加和分，回滚口径） |
| `GET /api/baseline/config` | 9 个新参数键 | `baseline.scheme` / `alpha` / `learn_source` / `pool_k` / `deviation_cap_per_entity_hour` / `deviation_cap_per_hour`、`profile.scoring` / `prior_odds` / `posterior_threshold`（都可在界面改、30 秒生效） |
| `POST /api/baseline/alerts/{profile_id}/disposition` | **新端点** | 告警处置（`false_positive` / `confirm`）；`profile_id` 可填画像 UUID 或实体键。判成误报后该实体（或 `signal` 指定的那一路证据）在 `profile.false_positive_suppress_days` 天内不再参与打分 |
| `GET /api/baseline/alerts/dispositions` | **新端点** | 最近处置记录（核对降权是否生效） |
| `GET /api/detector/hits`、`/hits/{id}` | `cluster_id` | 告警簇 ID：同一事件归类 + 同一 /24（v6 /64）+ 同一小时归为一簇，界面可把同簇收成一行 |
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
