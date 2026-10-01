# 深瞳 · Zeek 9.0 适配镜像

面向本项目的 Zeek 容器：JSON 日志、**24 小时轮转 + 本地只保留 3 天**、Filebeat 发 Redis 采集队列
（归一化服务再入库，见 README §四）、自定义脚本（HTTP 请求体采集等）、以及**由 Web 后台配置监听网卡**（看门狗自动重载）。

## 基底与版本

- 基底：官方 `zeek/zeek`（Debian），默认 tag **`9.0`**（Zeek 9.0 LTS，2026-09 发布）
- 可用构建参数覆盖：`--build-arg ZEEK_BASE=zeek/zeek:lts`
- 已核实：Zeek 9.0 是 LTS，集群通信用 ZeroMQ、移除 Broker WebSocket（本项目不用集群，无影响）

## 目录

```text
zeek/
├── Dockerfile              # 基底 + Filebeat + 站点脚本 + 入口
├── entrypoint.sh           # 网卡枚举 / 脚本渲染 / 启动 / 看门狗 / 清理
├── filebeat.yml            # 发运到 Redis 采集队列（shentong:events:collect）
├── site/
│   ├── local.zeek              # 总入口
│   ├── shentong-json.zeek      # JSON 输出 + 24h 轮转 + /logs 输出目录
│   ├── shentong-extra.zeek     # 显式加载各协议分析器（保证字段齐全）
│   ├── shentong-httpbody.zeek  # HTTP 请求体采集（截断 + 跳过二进制）
│   ├── shentong-nets.zeek      # Site::local_nets（入口自动重写）
│   └── shentong-scripts-d.zeek # scripts.d 加载器（入口自动重写）
└── scripts.d/              # ★ 可扩展目录：放 *.zeek 自动加载
```

## 运行要求

- **Linux 宿主机**：抓宿主网卡需要 `network_mode: host` + `cap_add: [NET_RAW, NET_ADMIN]`
- macOS / Windows 无法抓宿主网卡 → 请用 Linux 宿主或用镜像流量（SPAN/TAP）
- Zeek 用 host 网络，访问 ES 请用宿主可达地址（不要用 compose 内部服务名）

## 日志与保留

| 项 | 值 | 实现 |
|---|---|---|
| 格式 | NDJSON（每行一个 JSON） | `policy/tuning/json-logs` |
| 输出目录 | `/logs`（活动日志在顶层） | `Log::default_logdir` |
| 轮转 | **每 24 小时** | `Log::default_rotation_interval = 24hrs` |
| 轮转归档位置 | `/logs/<YYYY-MM-DD>/` | `Log::default_rotation_date_format` |
| 本地保留 | **只保留 3 天** | 容器入口清理循环（Zeek 日志框架**不做过期删除**，见下） |

> **为什么清理要自己写**：Zeek 日志框架只做 rotation，**不做过期删除**；Zeek 生态里删除过期归档是
> `zeekctl` 的能力（`LogExpireInterval` + `bin/expire-logs`，由 `zeekctl cron` 跑）。本项目用单进程
> 方式运行（不用 zeekctl 集群），因此保留 3 天由 `entrypoint.sh` 的清理循环保证：
> 只删**日期子目录**（`mindepth 2`）里超过 3 天的文件，**不动正在写的活动日志**。

## 网卡配置（由 Web 后台管理）

- 后台写入共享文件 `/config/interface.conf`：

  ```ini
  interface=eth0
  monitored_nets=10.0.0.0/8,192.168.0.0/16
  bpf_filter=(net 10.0.0.0/8 or net 192.168.0.0/16) and (not port 22)
  local_nets=10.0.0.0/8,192.168.0.0/16
  bpf_extra=not port 22
  ```
- `monitored_nets` 是后台「监控网段」清单（逗号分隔；界面上一行一条）；
  **`bpf_filter` 与 `local_nets` 由它自动生成**，不是手填字段 —— Zeek 只抓这些网段
  （BPF 里 `net X` 本身即「源或目的落在 X」），规则里的内外网判定也用同一份清单，
  保证「抓什么就分析什么」
- `bpf_extra`（可选）会被 `and` 进 BPF，用于追加条件（如 `not port 22`）
- 容器入口把网卡清单写入 `/config/interfaces.json`（供后台下拉选择）
- **看门狗**每 10 秒比对配置哈希，变化则渲染网段脚本并在**容器内重载 Zeek**（不重启容器、
  不需要 docker socket；重载期间约 1~2 秒短暂中断抓包）

## 可扩展脚本

把 `*.zeek` 放进 `scripts.d/`，重启容器生效（加载器由入口自动生成）：

```bash
docker compose restart zeek
```

## 构建

只由 GitHub Actions 构建（项目规则禁止本地构建），镜像推送至
`ghcr.io/<owner>/sec-agent/shentong-zeek:latest`。

## 已知限制

- 不做 Zeek 集群（manager/proxy/worker）
- 不做脚本在线热更新（改脚本需重启容器）
- HTTP 体只采请求方向、单条上限 4096 字节、跳过二进制
- **不解析请求头**：Zeek 默认不把 HTTP 请求头写进 `http.log`（`HTTP::Info` 里没有头字段），
  因此**经过反向代理时 `src_ip` 是代理的 IP**，拿不到 `X-Forwarded-For` / `X-Real-IP` /
  `Forwarded` 里的原始客户端 IP；要用得自己接 `http_header` 事件加 `&log` 字段
  （与 `shentong-httpbody.zeek` 同一套路），并配可信代理白名单（转发头可被伪造）

## 上线后专项检查（日志与协议解析）

> 状态：**待实机做**。本仓库这些脚本只在纸面 + 单进程归一化侧验证过，真实网卡上线后
> 按下表逐条核一遍（对应用户提出的「部署上线后专门检查 Zeek 的日志生成情况和相关协议解析」）。

| # | 检查项 | 怎么核 | 期望 |
|---|---|---|---|
| 1 | 实际产出了哪些日志 | `docker exec <zeek> ls -la /logs` | 至少 `conn.log` / `http.log` / `dns.log` / `ssl.log`；有对应流量时出现 `files.log` / `smtp.log` / `ssh.log` / `dhcp.log` / `notice.log` |
| 2 | 轮转与保留 | `ls /logs` 顶层活动日志 + `/logs/<YYYY-MM-DD>/` 子目录 | 每 24h 轮转进日期目录；超过 3 天的归档被入口清理循环删掉（活动日志不动） |
| 3 | 字段是否齐全 | 看一条 `http.log` / `dns.log` / `ssl.log` | http 有 `method`/`host`/`uri`/`user_agent`/`status_code`；ssl 有 `server_name`/`ja3`/`ja3s`/`cipher`；`site/shentong-extra.zeek` 加载的分析器都生效 |
| 4 | 自研 HTTP 体采集 | 看 POST 请求的 `http.log` 是否有 `body` 字段 | 有 `body`（请求方向、≤4096B、二进制跳过）；GET/HEAD 无 body |
| 5 | 网段只放行该抓的 | `zeek` 启动命令的 BPF（`docker exec <zeek> ps aux \| grep zeek`） | 与界面「监控网段」一致（`bpf_filter` 由网段自动生成） |
| 6 | 是否重复告警 | 看 `notice.log` 有无内容 | 目前只加载 `policy/tuning/json-logs`，**没有**加载 `policy/protocols/*`，故 Zeek 自己不产检测类 notice；检测全由内置规则做 |
| 7 | 归一化后的类型 | `GET /api/events` 或看运行状态/事件页 | `log_type` 分桶正确（`conn`/`http`/`dns`/`ssl`/`files`/…），`event_type` 细分正确（`http_login`/`http_upload`/`http_error`/`http_request`） |
| 8 | 内置规则是否吃到字段 | 看规则命中与 `raw_evidence` | body/uri/query/user_agent/ja3 等字段真的进了检测（82 条内置规则里 47 处用到这些字段） |
| 9 | **反向代理的原始客户端 IP** | 经过 nginx/HAProxy/CDN 的请求，看 `http.log` 的 `src_ip` | **当前拿不到**（= 代理 IP）。要支持需新增 `scripts.d/` 脚本接 `http_header` 取 `X-Forwarded-For`/`X-Real-IP`/`Forwarded` + `UnifiedLog` 加字段 + 归一化映射 + 可信代理白名单（四层代理不写这些头，只能靠 PROXY protocol 或回查 NAT/防火墙日志，本项目均未支持） |
