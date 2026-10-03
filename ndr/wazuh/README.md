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

## 三、在界面里接上 API

「系统配置 → Wazuh 接入」填地址（`https://<manager>:55000`）、用户名、密码，保存后点
**测试连接**；连通后会显示 API 版本、集群/单机、Agent 在线情况，以及**近 24 小时入库的
告警 / 原始日志条数** —— 后者就是这条链路真正通了的证据（它查的是 ES 里的
`source_system=wazuh`）。同一个面板还能下发本地规则文件并回读校验。

凭据默认来自环境变量 `ST_WAZUH_API_URL` / `ST_WAZUH_API_USER` / `ST_WAZUH_API_PASSWORD`，
界面上保存的值存在库里、优先级更高（密码只写不回显，留空表示不改）。

## 四、接外部已有的 Wazuh

已经有自己的 Wazuh 环境时，**不要**再起本目录的 `wazuh-manager`，只要把 Filebeat 指过去：

1. 把 `wazuh/filebeat.yml` 拷到能读到 `alerts.json`（与可选的 `archives.json`）的机器上；
2. 改 `WAZUH_LOG_DIR`、`REDIS_HOST`/`REDIS_PORT`/`REDIS_KEY`（或直接改 `paths`/`output.redis`）；
3. 起 Filebeat 后，到深瞳「系统配置 → Wazuh 接入」填那台 manager 的 API 地址与凭据。

`filebeat.yml` 里两个字段是必须的，改配置时别丢：`overwrite_keys: true`
（否则 Filebeat 自己的 ECS 顶层 `agent` 会盖掉 Wazuh 的 `agent.name`，主机名就丢了）与
**不设 ndjson `target`**（归一化服务直接从根读 `rule`/`data`/`agent`/`full_log`）。

## 五、待实机验证

本目录的文件是照着官方文档与既有 Zeek 线路写的，**没有真实 Wazuh 环境跑过**，以下逐条待验：

- [ ] `wazuh/wazuh-manager:4.14.8` 在本编排下的启动（`API_USERNAME`/`API_PASSWORD`、8 个卷、ulimits）
- [ ] `enable-logall.sh` 注入位置在目标小版本上正确（看 `docker compose logs wazuh-manager` 无配置报错）
- [ ] `wazuh-filebeat` 能读到日志卷并发进 `shentong:events:collect`（`redis-cli LLEN` 有增长）
- [ ] 界面「近 24h 入库」告警数随真实告警增长；原始日志开关打开后 archives 数同步增长
- [ ] 规则下发在真实 manager 上 `verified=true`（回读一致 + 生效条数对得上）
- [ ] 容量：按现场告警量估算 ES 日增量与 Redis 内存（见 `docs/ndr-redesign.md` 第 6 期容量评估）
