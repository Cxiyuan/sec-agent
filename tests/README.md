# tests/ —— 回归测试（进 CI，不靠手工）

这一层是为了解决一个老问题：**能过 CI 却上线才炸**的错（脚本把 BPF 过滤器当文件名、
Filebeat 配置键名不对、类型判定兜底成 conn……）。现在分成三块：

## 1. Python 回归（`tests/py`）

两个栈的包都叫 `app`（`ndr/backend/app`、`agent/backend/app`），同一个进程里没法同时 import，
所以用 `--stack` 选一个栈来跑，**两个栈各跑一遍**：

```sh
.venv/bin/python -m pytest tests/py --stack=ndr -q
.venv/bin/python -m pytest tests/py --stack=agent -q
```

| 文件 | 覆盖 |
| --- | --- |
| `test_log_types.py` | 类型规范化/分类/`is_detectable` 判定矩阵（含 Wazuh 不受闸门约束） |
| `test_normalizer_fields.py` | 类型判定、`raw.log_type`/`raw.source_file` 自解释字段、XFF→`real_client_ip`、响应体截断 |
| `test_xff_respbody.py` | 代理头各种形态（proxied/RFC7239/裸头/IPv6+端口/非法值）、规则命中、画像取真实客户端 |
| `test_stack_consistency.py` | **两侧一致性**：子进程分别加载两侧，逐字段比对（只改一侧会在这里炸） |
| `test_filebeat_yml.py` | 采集配置形状：filestream 路径、排除名单、文件名→类型 JS、`queue.disk`、Redis 输出 |
| `test_rules_quality.py` | **2026-10 规则评审回归**：`_FIELD_TYPES` 无僵尸键、规则字段名必须存在、正则可编译、路由全局 priority 有序、`_match` 收口语义（空条件/缺值/`ne` 空值/`exists` 布尔）、cookie 与 content-type 头解析、weird→protocol/tls_anomaly、x509 自签、sshd≠爆破、登录路径正则、Log4Shell 词边界+头向量、命令注入分隔符、WebShell 上传正反例、**正常流量不得命中任何逐条规则**、Wazuh 规则路由、单规则限速+严重度优先 |
| `test_deploy_exposure.py` | 部署编排暴露面：ES/Postgres/Logstash 必须回环、Redis 默认回环、不得发布到 `0.0.0.0` |
| `test_handled_registry.py` | 已处理登记单桶上限与**告警限频**（计数不丢、窗口过后重新告警） |
| `test_main_retention.py` | 启动下发 ES 模板的日志口径（稳态不记 info、失败后成功记一条、连续失败只一条 warning） |
| `test_mcp_coverage.py` | **MCP 覆盖与失效逻辑**：注册表↔调度表一致、签名↔参数表不漂移、ToolCtx 按令牌会话复用（ref 白名单与证据上限真正生效）、`raw_evidence` 索引白名单、`file_content` 正反例、智能体 `get_rule`/`list_filters`/`file_content` 转发、结论回写判定矩阵与逐指纹写入、字段目录覆盖 `UnifiedLog`、技能工具名认两套注册表 |
| `test_zeek_interfaces.py` | 监听网卡下拉只留**物理网卡**：`physical` 标志过滤、旧格式名字模式兜底、文件缺失/坏 JSON 回空、入口脚本必须按 sysfs 标记 |
| `test_detector_history.py` | 总览页 24h 趋势的采样底座：写入有界（LPUSH+LTRIM+TTL）、读取时间正序与坏行容错、「按规则」计数用后即清、严重度区间增量不为负、统计块确实调了采样 |
| `test_system_metrics.py` | 服务器圆环：`/proc/stat`（含 idle+iowait、计数器回退不算负载）与 `/proc/meminfo`（用 MemAvailable）解析、缺指标不 500 而是 null+notes |
| `test_health_components.py` | 组件呼吸灯：判据边界（5/30 分钟、2/15 分钟、green/yellow/red、未配置≠坏了）、七盏灯齐全、**单个探测抛异常只影响它自己**、30 秒缓存 |
| `test_stats_overview.py` | 24h 流量与协议：查询结构必须**只在流量侧过滤 `log_type=conn`**、逐小时字节/秒与百分比（top N + 其他为分母）换算、缓存命中、失败不缓存、ES 异常降级为空 |

样本在 `samples.py`（字段名取自实机 `/logs/*.log`），含"没有 `log_type` 的旧文档"
这条只能靠猜的路径。

## 2. Zeek 脚本单测（`tests/zeek`）

```sh
sh tests/zeek/run.sh          # 默认 zeek/zeek:9.0，与 ndr/zeek/Dockerfile 的 ZEEK_BASE 一致
```

在官方 Zeek 容器里把 `ndr/zeek/site/*.zeek` 拷进去跑 `hb_test.zeek`：
请求/响应体分块累加与截断、GET 无请求体但有响应体、NUL 二进制拦截、UTF-8 放行。
Zeek 脚本是编译期加载的，语法/字段错误只有真跑一次才会暴露。
脚本输出以 `FAILS=0` 为通过标记（Zeek 的 `print` 会把中文打成 `\xNN` 转义，故标签用 ASCII）。

## 3. 质量门（CI 与本地同一套）

```sh
.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py
.venv/bin/pyright ndr/backend/app agent/backend/app tests/py
cd ndr/frontend   && npx tsc --noEmit
cd agent/frontend && npx tsc --noEmit
```

`.venv` 需要 `pytest`、`pyyaml`、`ruff`、`pyright`、`pydantic`、`pydantic-settings`、`sqlalchemy`
（后端依赖的完整清单在各 `backend/pyproject.toml`；CI 里按清单装）。
