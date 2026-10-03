# 深瞳 · Wazuh 4.14 接入（容器侧）

把 Wazuh 的告警（可选：全量原始日志）接进深瞳 NDR 的数据面。本目录只有**配置**，
不含自建镜像（项目规则禁止本地构建），跑的是两个官方镜像：

| 服务 | 镜像 | 作用 |
|---|---|---|
| `wazuh-manager` | `wazuh/wazuh-manager:4.14.8` | Wazuh 本体（**不含** indexer / dashboard） |
| `wazuh-filebeat` | `docker.elastic.co/beats/filebeat:8.15.3` | 读 manager 日志卷，投进 Redis 采集队列 |

链路与 Zeek 那条线一致（同一套投递形状，2026-10 QA 后对齐：共用 `queue.disk` 落盘队列 +
命名卷 `wazuh-filebeat:/usr/share/filebeat/data` 持久化读取注册表；`data_type=list` 下
Filebeat 用 RPUSH 追加到队尾，消费端从右端取 ⇒ 最新优先）：

```text
alerts.json / archives.json
      │  wazuh-filebeat（ndjson，字段放根，不设 target）
      ▼
Redis  shentong:events:collect
      │  normalizer（NDR 侧）
      ├─ 告警   log_type=wazuh          → Logstash → ES，并投检测器
      └─ 原始日志 log_type=wazuh_archive → Logstash → ES，默认**不**投检测器
      ▼
检测器 → 摘要 → HTTP 推送智能体（见 README §四之二）
```

## 目录

```text
wazuh/
├── filebeat.yml        # 采集配置（挂进 wazuh-filebeat）
├── enable-logall.sh    # 幂等开启 archives.json（改 manager 的 ossec.conf）
└── README.md
```

## 一、起服务

在 `ndr/` 目录下用叠加编排（**不写进默认 compose**，不接 Wazuh 的部署完全不受影响）：

```bash
# 开发/本地
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d

# 部署版
docker compose -f docker-compose.deploy.yml -f docker-compose.wazuh.yml up -d
```

可用环境变量覆盖（放在 `ndr/.env` 或命令行）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `WAZUH_IMAGE` | `wazuh/wazuh-manager:4.14.8` | manager 镜像（4.14.x） |
| `WAZUH_FILEBEAT_IMAGE` | `docker.elastic.co/beats/filebeat:8.15.3` | Filebeat 镜像（与 ES/Zeek 一致） |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | `wazuh-wui` / 占位 | manager 的 API 用户，**生产必须改** |
| `WAZUH_ARCHIVES_ENABLED` | `false` | 是否采集原始日志（**两处开关**：先 `enable-logall.sh` 开 manager 的 logall_json，再设这里为 `true`，见第二节） |

> 只暴露了 `55000`（API，深瞳后台要用）与可选的 `1514`/`1515`（agent 上报/注册）。
> 本编排**不带** Wazuh indexer / dashboard：manager 自带的 Filebeat 会因为找不到 indexer
> 一直报连接失败，这是预期现象，不影响 manager 与我们的采集线；已有 indexer 的环境可在
> `docker-compose.wazuh.yml` 里打开 `INDEXER_*` 三项。

## 二、打开原始日志（可选）

Wazuh 默认只写 `alerts.json`（告警）。要收全量原始日志得先让 manager 打开 `logall_json`：

```bash
cd ndr
./wazuh/enable-logall.sh                                    # 默认 compose 组合
COMPOSE_FILES="-f docker-compose.deploy.yml -f docker-compose.wazuh.yml" ./wazuh/enable-logall.sh
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml restart wazuh-manager
```

脚本的做法是**幂等补两行**（`<logall>` / `<logall_json>` 插在 `<global>` 之后，原文件先备份），
**不是**整体替换 `ossec.conf` —— 各 4.14.x 小版本的默认配置有差异，整体替换很可能让 manager 起不来。
再把 `WAZUH_ARCHIVES_ENABLED=true` 传给 `wazuh-filebeat` 才会真正采集：

```bash
WAZUH_ARCHIVES_ENABLED=true docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d wazuh-filebeat
```

原始日志量级比告警大得多，所以归一化侧默认**只入库、不喂检测器**
（`ST_WAZUH_ARCHIVE_TO_DETECTOR=false`）；确实要让检测规则也看原始日志再打开它。

## 三、在界面里看接入状态（不需要配置）

Wazuh 是**随本项目一起部署**的内置服务，连接信息在部署时就固定了，所以「采集接入 → Wazuh」
这一页**只显示状态**：API 版本、集群/单机、Agent 在线情况，以及**近 24 小时入库的
告警 / 原始日志条数** —— 后者就是这条链路真正通了的证据（它查的是 ES 里的
`source_system=wazuh`）。同一个面板还能下发本地规则文件并回读校验。

连接信息的唯一来源是环境变量 `ST_WAZUH_API_URL` / `ST_WAZUH_API_USER` /
`ST_WAZUH_API_PASSWORD`（部署时由 `.env` 的 `WAZUH_API_*` 传入，与 manager 自己用的是同一组值）。
界面上没有填写入口、也没有「测试连接」按钮：地址与密码多一处来源，就会出现「界面写了一个
地址、实际连的是另一个」而看不出来的情况。

## 四、接外部已有的 Wazuh

已经有自己的 Wazuh 环境时，**不要**再起本目录的 `wazuh-manager`，只要把 Filebeat 指过去：

1. 把 `wazuh/filebeat.yml` 拷到能读到 `alerts.json`（与可选的 `archives.json`）的机器上；
2. 改 `WAZUH_LOG_DIR`、`REDIS_HOST`/`REDIS_PORT`/`REDIS_KEY`（或直接改 `paths`/`output.redis`）；
3. 起 Filebeat 后，把**那台 manager 的** API 地址与凭据写进后台的 `ST_WAZUH_API_URL` /
   `ST_WAZUH_API_USER` / `ST_WAZUH_API_PASSWORD`（界面只读，没有填写入口）。

`filebeat.yml` 里两个字段是必须的，改配置时别丢：`overwrite_keys: true`
（否则 Filebeat 自己的 ECS 顶层 `agent` 会盖掉 Wazuh 的 `agent.name`，主机名就丢了）与
**不设 ndjson `target`**（归一化服务直接从根读 `rule`/`data`/`agent`/`full_log`）。

## 五、实机验证记录（2026-10-03，`172.16.196.77`）

本目录的文件当初是照着官方文档与既有 Zeek 线路写的，2026-10-03 在真实 Wazuh 4.14.8
环境上逐条跑过一遍。**六条全部通过**，过程中揪出并修掉了 5 个真 bug（其中 3 个会让
「接入成功」这句话站不住：告警被 ES 静默丢弃、面板恒报读 ES 失败、规则下发其实没生效）。

**环境**：服务器 `/opt/shentong-ndr`，Compose 2.40.3；`docker-compose.deploy.yml` 用
`include: [docker-compose.wazuh.yml]` 引入叠加件（compose ≥2.20.4 才支持 `include`；
**单一定义、结构上不会与开发版漂移**，本地开发仍是 `-f docker-compose.wazuh.yml` 显式 opt-in）。
`wazuh-manager` = 官方 `wazuh/wazuh-manager:4.14.8`（单机、不含 indexer/dashboard），
`wazuh-filebeat` = beats 8.15.3，3 台 Windows agent（含 manager 自身 `agent.id=000`）。

| # | 待验项 | 结果 |
|---|---|---|
| 1 | manager 在本编排下启动（`API_USERNAME`/`API_PASSWORD`、卷、ulimits） | ✅ 容器 running，`wazuh-control status` 10 个进程 running；`POST /security/user/authenticate` 用 `.env` 里的 `wazuh-wui` 口令拿到 JWT（200）。卷清单与官方 single-node 对齐（**当时我们比官方少 `agentless`/`wodles` 两卷、多了一个嵌在 `etc` 里会遮蔽父卷的 `wazuh-agent-config`，已按官方改齐**）；ulimits `memlock=-1` / `nofile=655360`。日志里只有 `wazuh-remoted` 的 `Invalid ID` 噪声（官方同款，与本编排无关）。 |
| 2 | `enable-logall.sh` 注入位置正确 | ✅ 但**脚本本身有 bug，已重写**（见下「踩到的坑」4）。实测开关一次后 `ossec.conf` 是 `11: <logall>yes</logall>` / `12: <logall_json>yes</logall_json>`，manager 重启后 10 进程 running、`/var/ossec/logs/archives/archives.json` 按预期产出。验完已回滚为默认 `no`（`.env` 的 `WAZUH_ARCHIVES_ENABLED` 也回 `false`）。 |
| 3 | `wazuh-filebeat` 读到日志卷并发进 `shentong:events:collect` | ✅ Redis `INFO commandstats` 有量、`CLIENT LIST` 里该连接 `cmd=rpush`；归一化服务连续多个 5 分钟窗口「入库 3.9–4.9 万条 / 坏消息 0 / 待重试 0」。 |
| 4 | 面板「近 24h 入库」随真实告警增长；开 archives 后 archives 数同步增长 | ✅ 但**面板这条链路原先根本不通，已修两个 bug**（见下「踩到的坑」1、2）。修后 `GET /api/wazuh/status` 回 `{"reachable":true,"version":"v4.14.8","ingest":{"alerts":4367,"archives":0,"total":4367,"error":""}}`；archives 窗口内该字段从 0 涨到 186（实测 `log_type.keyword=wazuh_archive` 同步增长），并确认**原始日志只入库、不喂检测器**（`shentong:events:raw` 里 `wazuh_archive` 计数 0，代码见 `collector/normalizer_service.py` 的 `archive_es_only` 分支）。测试产生的 archives 文档已删净（现网 `archives` 恒 0，与「默认关闭」一致）。 |
| 5 | 规则下发在真实 manager 上 `verified=true` | ✅ 最终回 `{"ok":true,"verified":true,"applied_rules":1,"sent_rules":1,"detail":"已下发并校验通过：生效 1 条规则"}`，manager 侧规则描述与下发内容一致。**这条原先恒 false，一共修了三个 bug**（见下「踩到的坑」3、5）。探针规则文件已从 manager 删除。 |
| 6 | 容量（按现场量估算 ES 日增量与 Redis 内存） | ✅ 实测 3 台 agent 约 **2000 条告警 / 1.5 小时 ≈ 3.2 万条/天**，原文（`alerts.json`）3.7 MB / 1.5 小时 ≈ **59 MB/天**。按第 6 期容量评估的单条载荷 1.36 KB 折算，告警侧 ES 日增量约 **44 MB/天**。archives 侧在 12 分钟验证窗口里产出 824 KB（含刚开启时的积压回放），粗算 **60–100 MB/天**量级，但窗口太短、**现场开口前必须按真实原始日志量复核**；Redis 队列上限仍是 `collector_queue_max=30000`。 |

### 踩到的坑（都已修，附提交）

1. **ES 索引模板没有 mappings → Wazuh 告警被静默丢弃**（`4655bd2` 修骨架、`12eab73` 定稿）。
   `raw.id` 在 Zeek `conn` 里是对象、在 Wazuh 告警与 Zeek `ocsp` 里是字符串，动态映射先把
   `raw.id` 定成 object，之后**字符串形态的文档被 ES 以 HTTP 400 静默拒收**（Logstash 日志里
   同一类 400 出现 2024 次）：症状是 `log_type.keyword=wazuh` 恒为 0，而 Filebeat、Redis、
   归一化三段全都正常。修法：索引模板下发 `{"properties": {"raw": {"type": "object",
   "enabled": false}}}`（`collector/es_mapping.py` 单一事实来源）；`raw` 不解析 ⇒ 结构上不可能
   再因字段冲突丢文档，代价是 `raw.*` 不可查（仓库里没有任何查询依赖它，MCP 的原文证据走
   `_source`）。**已存在的索引改不了字段类型**（`dynamic:false`/`enabled:false`/`ignore_malformed`
   三条路实测全部不通，`enabled:false` 还会报 `can't be updated`），两个老索引是
   「拷贝 → 删旧 → 按新映射重建 → 回灌」迁移的（各 84.9 万 / 97.9 万条，`failures: 0`）。
   顺便给 backend 加了启动告警：老索引的 `raw` 不是新映射就打 warning。
   注：`flattened` 方案实测**不行** —— 单值超过 32766 字节时整条文档照样被丢（现场就有一条
   32 KB 的 LLM 响应体），只是换了个丢数据的理由，与「根除静默丢数据」的目标相反。
2. **面板「Wazuh 接入状态 / 近 24h 入库」永远显示读 ES 失败**（`12eab73`）。
   `api/routes/wazuh.py:_ingest_stats()` 用 text 主字段做 term 聚合（`"field": "log_type"`）⇒
   ES 回 `Fielddata is disabled on [log_type] ... Please use a keyword field instead`（400）。
   修法：改走 `catalog.agg_path()`（text → `.keyword`）并加 `track_total_hits`（否则 >1 万条时
   `hits.total` 只是下界，界面会当精确值显示）。
3. **规则下发 `verified` 恒 false（两个 bug）**（`646b779`）。
   ① `GET /rules/files/<name>?raw=true` 回的是 `application/xml` 原文，`_api` 却无条件
   `resp.json()` ⇒ 判成「响应不是 JSON」；`_api` 加 `raw=True` 走文本。
   ② 下发后立刻 `GET /rules?filename=…` 可能读到 0 条（manager 侧规则集扫描有滞后，几秒后才可见）
   ⇒ `_count_rules()` 改成轮询到 `want` 或超时。
4. **`enable-logall.sh` 会写出自相矛盾的配置**（`ca35c42`）。
   4.14.8 的默认 `ossec.conf` 第 11-12 行**本来就有** `<logall>no</logall>` /
   `<logall_json>no</logall_json>`；老脚本用 awk 在 `<global>` 之后**追加** `yes`，实测生成
   `yes`(9-10 行) 与 `no`(13-14 行) 并存、第二个 `<global>`(194 行) 处又插一份 —— 解析器取哪个
   不可依赖，等于可能没生效而脚本报成功。新脚本改成就地改值（`sed`）、只在键缺失时才插入、
   并在写完后自检「每个键恰好 1 处 `yes`、0 处 `no`」，不通过就回滚原文件并报错退出。
5. **规则下发其实一条都没更新，却报「已上传」**（`e598764`）。
   Wazuh 4.14 的 `PUT /rules/files/<name>` **默认不覆盖**已存在的文件：同名文件回的是
   **HTTP 200 + body `error=1` / code 1905「File could not be updated, it already exists」**。
   `_api` 只看 HTTP 状态码 ⇒ 把「没写进去」当成功，再拿旧文件的回读结果去比对，就变成
   「已上传但内容不一致」这种查不出原因的告警（`applied_rules` 还会被旧规则凑够 1 条）。
   修法：下发时带 `overwrite=true`；`_api` 新增 `strict`，把 body 里的
   `error`/`total_failed_items`/`failed_items` 翻译成人话回给界面；「内容不一致」的说明里补上
   首个不同的行号与两侧原文，让运维一眼看出是差在行尾还是压根没写进去。
   另外顺手修了一个真 bug：Wazuh `syscollector`/FIM 原始日志的 `process` 是**对象**，
   直接喂给 `UnifiedLog.process: str | None` 会被 pydantic 打成死信（实测 373 条进
   `shentong:events:dead`）；`normalize_wazuh` 现在统一走 `_text_or_none()`（对象取
   `name`/`command`/`path`，取不到退化成一行的紧凑 JSON），修复后 373 条原文全部回灌成功
   （ES `wazuh_archive` +373、0 新死信）。**这份 normalizer 两侧必须同步**（`ndr/` 与 `agent/`）。

**仍未做**：`archives.json` 的保留策略（Wazuh 自己滚动、不设保留期，长期开 `logall_json`
要配合宿主/卷清理）；`wazuh-remoted` 的 `Invalid ID` 噪声是否与 agent 版本有关，未深究。
测试窗口留下的 `archives.json`/`archives.log`（约 800 KB）与 `shentong:collector:stats` 里
累计的 `dead_normalize_failed 373` 未清理（后者是**累计**计数，按设计不复位，可留作历史记录）。
