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
| `test_normalizer_fields.py` | 类型判定、`raw.log_type`/`raw.source_file` 自解释字段、XFF→`real_client_ip`、响应体截断 |；**会话 id 提取**（按名单精确匹配、大小写不敏感、去引号；`Path=/` 与空值模板被排除；长 Cookie 头从**未截断**值里取 ⇒ 不因截断漏报）
| `test_xff_respbody.py` | 代理头各种形态（proxied/RFC7239/裸头/IPv6+端口/非法值）、规则命中、画像取真实客户端 |
| `test_stack_consistency.py` | **两侧一致性**：子进程分别加载两侧，逐字段比对（只改一侧会在这里炸） |
| `test_filebeat_yml.py` | 采集配置形状：filestream 路径、排除名单、文件名→类型 JS、`queue.disk`、Redis 输出 |
| `test_deploy_exposure.py` | 部署编排暴露面：ES/Postgres/Logstash 必须回环、Redis 默认回环、不得发布到 `0.0.0.0` |
| `test_handled_registry.py` | 已处理登记单桶上限与**告警限频**（计数不丢、窗口过后重新告警） |
| `test_main_retention.py` | 启动下发 ES 模板的日志口径（稳态不记 info、失败后成功记一条、连续失败只一条 warning） |
| `test_mcp_coverage.py` | **MCP 覆盖与失效逻辑**：注册表↔调度表一致、签名↔参数表不漂移、ToolCtx 按令牌会话复用（ref 白名单与证据上限真正生效）、`raw_evidence` 索引白名单、`file_content` 正反例、智能体 `get_rule`/`list_filters`/`file_content` 转发、结论回写判定矩阵与逐指纹写入、字段目录覆盖 `UnifiedLog`、技能工具名认两套注册表 |
| `test_zeek_interfaces.py` | 监听网卡下拉只留**物理网卡**：`physical` 标志过滤、旧格式名字模式兜底、文件缺失/坏 JSON 回空、入口脚本必须按 sysfs 标记；另加**硬编码审计**守卫：产品代码里不得给网卡名写死默认值（`${ZEEK_IFACE:-<非空>}` 一律红），必须留空 + `auto_iface` 自动探测物理网卡 |
| `test_detector_history.py` | 总览页 24h 趋势的采样底座：写入有界（LPUSH+LTRIM+TTL）、读取时间正序与坏行容错、「按规则」计数用后即清、严重度区间增量不为负、统计块确实调了采样 |
| `test_system_metrics.py` | 服务器圆环：`/proc/stat`（含 idle+iowait、计数器回退不算负载）与 `/proc/meminfo`（用 MemAvailable）解析、缺指标不 500 而是 null+notes |
| `test_health_components.py` | 组件呼吸灯：判据边界（5/30 分钟、2/15 分钟、green/yellow/red、未配置≠坏了）、**八盏灯齐全**（含「采集质量」）、采集类异常阈值判据（5000/20000、读不到=unknown）与单个探测抛异常只影响它自己、30 秒缓存 |
| `test_stats_overview.py` | 24h 流量与协议：查询结构必须**只在流量侧过滤 `log_type=conn`**、**协议侧只算协议识别类日志**（白名单 `include` + 非协议日志单列 `excluded` 计数，conn/weird/files/syslog 不得入白名单）、逐小时字节/秒与百分比（协议类 top N + 其他为分母，**不含非协议日志**）换算、缓存命中、失败不缓存、ES 异常降级为空 |
| `test_relay_chain.py` | 中继链路四件套：清单（只读 PG、IP/CIDR/注释解析、缓存与失效、保存不抹掉角色与侧向）、角色推算 + **两侧内容统计**、**按内容判侧向**（9:28557 → 源站侧；阈值边界 49/50 与 10 倍；运维手动覆盖优先；判据异常回退客户端侧；清单变更清零）、**链的下游续跳去重**（只认 X-Real-IP / XFF 末尾、src 是中继时不算续跳、链里无中继不算）、去重（direct / relay_internal 按内容判 / 侧向=客户端侧时沿用「前跳可见则丢后跳」/ 未见前跳则保留 / 可见期过期 / 窗口下限） |
| `test_asset_baseline.py` | 被访问方（内网源站 / 内网 DNS）基线**口径 B2（按连接算）**：`conn`+`http` 同一 `uid` = 一次访问（**两种到达顺序**都不重复、身份归 hostname）、keep-alive 多请求 = 1 次访问 + N 次请求、纯 TCP 回落 `IP:端口`（请求数 0）、中继链路上客户端取 `real_client_ip`、多连接按资产聚合、**中继自身丢弃**（有 Host/SNI 则保留、端口 53 的 DNS 保留）、**无 `uid` 不入基线**（主机监控/files）、`ST_ASSET_MAX_UIDS` 上限、请求数口径可配、`window_values` 形状（5 特征）、落库到 `asset_stats`（换模型复用 Welford）、**口径版本迁移清空且幂等**、列表（含 `requests_mean`）/明细/概览与端点接线 |
| `test_baseline_config.py` | 基线/画像的**可调参数**（后台「行为分析」页）：白名单（未知键一律不写库）、校验（越界/非数字/坏正则/「保留期必须大于观测期」跳字段约束）、空正则合法、读侧夹紧脏值（越界/非数字不能带坏运行时）、save/reset 只动白名单且让缓存失效、端点接线（400 + `field_errors`、筛选参数透传） |
| `test_baseline_profile.py` | 画像判据与风险写回（2026-10 实机 QA 的产物）：非常用时段的三个门槛（覆盖时段数 / 画像年龄 / 占比）、**双栈 v4+v6 不算会话劫持**而同族 ≥2 个算、新源 IP 对 v6 只看 /64 前缀、**接口路径判据**（静态资源与 `.html`/`.jsp` 等页面不记、默认不要求含 `/api/`、新路径需已认识 ≥N 条、老库静态路径自愈剔除）、服务端 IP 落库与合并（界面展示「账号 · 服务端IP」）、冷启动不打分、**本轮无理由则风险归零 + 理由清空 + risk_at 置空**、TOP 只取当前风险且只取账号、**认证失败突增分档**（≥5 +0.25 / ≥10 +0.35 / ≥20 且零成功 +0.6，最高档单条即达阈值）|
| `test_baseline_stats.py` | 数值基线存取：`snapshot()` **只能一条 SQL**（回归：以前两条 `COUNT(*)` 被 15s 轮询）、warmed>total 不为负、PG 异常降级；保留期 `cleanup()` 只删过期键、0 = 不清理、失败不抛；Welford 增量（10/20 → mean 15、样本标准差 √50） |
| `test_baseline_engine.py` | 基线心跳与清理接线：`*_last_round` 与累计量**分名**（回归：`anomalies` 被当累计读，而实机 0 vs 库里 54 条风险>0）、`anomalies_total`/`anomaly_rounds` 累加、心跳有 TTL、`flush()` 的清理段**确实调了数值基线清理**且不依赖画像开关 |

样本在 `samples.py`（字段名取自实机 `/logs/*.log`），含"没有 `log_type` 的旧文档"
这条只能靠猜的路径。

## 2. Zeek 脚本单测（`tests/zeek`）—— **只在 CI 跑，本地不跑**

```sh
sh tests/zeek/run.sh          # 默认 zeek/zeek:9.0，与 ndr/zeek/Dockerfile 的 ZEEK_BASE 一致
```

> ⚠️ **本地不要执行这条命令**：它用 `docker run zeek/zeek:9.0` 跑，本地没镜像时会**自动拉**
> （实测拉进来 751MB，还会在容器里编译脚本）。按 AGENTS.md「构建规则」，本地不拉镜像、
> 不起容器；这一步已列入 CI 的 `test` 作业，提交后用流水线结果为准。

在官方 Zeek 容器里把 `ndr/zeek/site/*.zeek` 拷进去跑 `hb_test.zeek`：
请求/响应体分块累加与截断、GET 无请求体但有响应体、NUL 二进制拦截、UTF-8 放行。
Zeek 脚本是编译期加载的，语法/字段错误只有真跑一次才会暴露。
脚本输出以 `FAILS=0` 为通过标记（Zeek 的 `print` 会把中文打成 `\xNN` 转义，故标签用 ASCII）。

## 3. 签名引擎（Suricata）自检（`tests/suricata`）—— **只在 CI 跑，本地不跑**

```sh
sh tests/suricata/run.sh       # 构建 ndr/suricata 镜像并跑配置/规则自检
```

> ⚠️ **本地不要执行**：它会 `docker build` 并 `docker run`（会拉基底镜像）。
> 按 AGENTS.md「构建规则」，镜像只在 GitHub Actions 构建；这一步已列入 CI 的 `test` 作业。

规则来源是「开发人员提供的 rules 文件 + manifest 在线更新」，镜像里**没有**内置规则集。所以验证的是
容易静默失效的五件事：① 空占位能启动（**0 条规则** ⇒ 不产生告警）② 开发人员写的样例规则能加载
（`tests/suricata/sample/`）③ 渲染出的配置只引用 `active/`、**不含任何 `*-events.rules`**（引擎事件确实不加载）
④ `staging` 校验与 `activate` 切换这套共享卷协议跑通 ⑤ 清空规则回到空占位。

## 4. 质量门（CI 与本地同一套）

```sh
# NDR 栈（唯一还有 Python 后端的栈：agent 已换成 dsh）
.venv/bin/ruff check ndr/backend/app tests/py
.venv/bin/pyright ndr/backend/app tests/py
.venv/bin/python -m pytest tests/py --stack=ndr -q
cd ndr/frontend && npx tsc --noEmit

# agent（dsh）侧的质量门在它自己目录里跑，由 CI 的 agent-web / agent-plugins 作业执行
cd agent && pnpm install --frozen-lockfile && pnpm run typecheck && pnpm run lint && pnpm run build
```

`.venv` 需要 `pytest`、`pyyaml`、`ruff`、`pyright`、`pydantic`、`pydantic-settings`、`sqlalchemy`
（后端依赖的完整清单在各 `backend/pyproject.toml`；CI 里按清单装）。
