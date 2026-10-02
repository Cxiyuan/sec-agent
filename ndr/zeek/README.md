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
| 轮转归档位置 | **同目录平铺改名**：`conn.log` → `conn.2026-10-01.log` | `Log::default_rotation_date_format`（实机核对：不是日期子目录） |
| 本地保留 | **只保留 3 天** | 容器入口清理循环（Zeek 日志框架**不做过期删除**，见下） |

> **为什么清理要自己写**：Zeek 日志框架只做 rotation，**不做过期删除**；Zeek 生态里删除过期归档是
> `zeekctl` 的能力（`LogExpireInterval` + `bin/expire-logs`，由 `zeekctl cron` 跑）。本项目用单进程
> 方式运行（不用 zeekctl 集群），因此保留 3 天由 `entrypoint.sh` 的清理循环保证：
> 两条 `find`（`entrypoint.sh:137-138`）分别处理**平铺改名的归档**与历史/其它部署可能出现的
> **日期子目录**布局，只删超过 3 天的**已轮转文件**，**不动正在写的活动日志**（`conn.log` 这类）。
> 另外每次 Zeek 重启也会把当前日志改名成当天（如今日 02:55 重建产生了 `*.2026-10-02.log`）。

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
- HTTP 体只采请求方向、单条上限 4096 字节、跳过二进制（**放行 UTF-8**：2026-10 上线发现
  原判据只放行可打印 ASCII，中文请求体整块被丢，已改成只拦 NUL/C0 控制字符）
- **不产 JA3 / JA3S 指纹**：Zeek 9.0 的 SSL 分析器里没有 `ja3`/`ja3s` 字段（容器内
  `local i: SSL::Info; print i?$ja3;` 编译报 `no such field in record`），实测
  `ssl.log` 127 条 0 处 ja3。所以基于 `ja3` 字段的规则（`rules/builtin.py` 里那条空值
  模板）永远匹配不到；要用得另装/自写 JA3 脚本（社区 `ja3.zeek`、zkg 包）再接归一化
- **响应体可能含二进制乱码**：`shentong-httpbody.zeek` 的判据为了保住中文（UTF-8
  高位字节）只能拦 NUL/C0 控制字符，因此**压缩响应（gzip/br）或恰好不含这些字节的
  二进制响应**会以乱码形式写进 `resp_body`（字段不丢、内容不可读）。要精确跳过需再接
  `http_header` 事件记录 `Content-Encoding` 并维护「本事务不采」表，本项目尚未做。
- **请求头只采「代理相关」那几个（2026-10 修正）**：Zeek 不会把任意请求头写进 `http.log`，
  但它自带的 HTTP 分析器会把**表明请求经过代理**的头收进 `HTTP::Info$proxied`
  （默认清单：`X-Forwarded-For` / `X-Forwarded-From` / `Forwarded` / `Client-IP` /
  `Via` / `Xroxy-Connection` / `Proxy-Connection`），值形如
  `"X-FORWARDED-FOR -> 198.51.100.77, 203.0.113.9"`；本项目 normalizer 已把它解析成归一化
  字段 `real_client_ip`（没有代理头时是 NULL，`src_ip` 仍是 TCP 对端）。**Cookie 与其它自定义头
  仍不落盘**，要采得自己接 `http_header` 事件加 `&log` 字段（与 `shentong-httpbody.zeek`
  同一套路）。注意转发头是客户端自报、**可伪造**，拿它做封禁/画像必须配可信代理白名单
  （本项目尚未做，`real_client_ip` 只代表「头里写了什么」）

## 上线后专项检查（日志与协议解析）

> 状态：**已在实机（172.16.196.77，Zeek 9.0.0，iface=ens160）做过一遍**，2026-10。
> 结论见下表后的「实机结果」；脚本改动只在纸面 + 单进程归一化侧验证过，首次上线必须逐条核。

| # | 检查项 | 怎么核 | 期望 |
|---|---|---|---|
| 1 | 实际产出了哪些日志 | `docker exec <zeek> ls -la /logs` | 至少 `conn.log` / `http.log` / `dns.log` / `ssl.log`；有对应流量时出现 `files.log` / `smtp.log` / `ssh.log` / `dhcp.log` / `notice.log` |
| 2 | 轮转与保留 | `ls /logs` 顶层活动日志与轮转归档 | 每 24h **同目录平铺改名**（`conn.log` → `conn.2026-10-01.log`，实机核对：**不是日期子目录**）；超过 3 天的归档被入口清理循环删掉（活动日志不动） |
| 3 | 字段是否齐全 | 看一条 `http.log` / `dns.log` / `ssl.log` | http 有 `method`/`host`/`uri`/`user_agent`/`status_code`；ssl 有 `server_name`/`cipher`（**`ja3`/`ja3s` 拿不到**，见「已知限制」）；`site/shentong-extra.zeek` 加载的分析器都生效；经过代理的请求 `http.log` 的 `proxied` 会有值 |
| 4 | 自研 HTTP 体采集 | 看 POST 请求的 `http.log` 是否有 `body`（请求体）与 `resp_body`（响应体） | 两者都有（各 ≤4096B，可用 `redef` 放大；二进制块跳过、UTF-8 放行）；GET/HEAD 无 `body` 但有 `resp_body`；**响应体完整字节数看 Zeek 自带的 `response_body_len`**（不受截断影响，落库为 `resp_body_len`） |
| 5 | 网段只放行该抓的 | `zeek` 启动命令的 BPF（`docker exec <zeek> ps -o args= -C zeek`） | 与界面「监控网段」一致（`bpf_filter` 由网段自动生成，命令里应出现 `-f net …`；`-f` 缺失会被 Zeek 当脚本名，启动即 fatal）；**未配网段时全量抓包** |
| 6 | 是否重复告警 | 看 `notice.log` 有无内容 | 目前只加载 `policy/tuning/json-logs`，**没有**加载 `policy/protocols/*`，故 Zeek 自己不产检测类 notice；检测全由内置规则做 |
| 7 | 归一化后的类型 | `GET /api/events` 或看运行状态/事件页 | `log_type` 分桶正确（`conn`/`http`/`dns`/`ssl`/`files`/…），`event_type` 细分正确（`http_login`/`http_upload`/`http_error`/`http_request`） |
| 8 | 内置规则是否吃到字段 | 看规则命中与 `raw_evidence` | body/uri/query/user_agent 等字段真的进了检测（82 条内置规则里 47 处用到这些字段） |
| 9 | **反向代理的原始客户端 IP** | 经过 nginx/HAProxy/CDN 的请求，看 `http.log` 的 `proxied` 与归一化后的 `real_client_ip` | **已支持（2026-10）**：Zeek 采代理头进 `proxied`，normalizer 解析最左合法 IP 落成 `real_client_ip`（无代理头 = NULL，`src_ip` 仍是代理 IP）。**未做**：可信代理白名单（头可伪造）、`X-Real-IP`（不在 Zeek 默认清单）、四层代理（只转发 TCP 不写头）只能靠 PROXY protocol 或回查 NAT/防火墙日志 |

### 实机结果（2026-10，172.16.196.77）

| # | 结果 | 证据 |
|---|---|---|
| 1 | ✅ | `/logs`：conn.log 7.9MB、dhcp.log 23KB、dns.log 39KB、files.log 1140B、http.log、ssl.log 35KB、weird.log、x509.log、packet_filter.log；无 notice.log |
| 2 | ✅ 轮转 / ⏳ 清理实效 | 轮转是**同目录平铺改名**：`conn.2026-10-01.log`（121MB）、`ssl.2026-10-02.log`、`packet_filter.2026-10-02.log`、`reporter.2026-10-02.log`、`dhcp.2026-10-02.log` 等都在 `/logs` 顶层，没有日期子目录；每次 Zeek 启动/重建也会把当前日志改名成当天（2026-10-02 02:55 与 06:21 两次重建各产生一批）。清理由 `entrypoint.sh` 的 `cleanup_once()` 两条 `find` 做（平铺归档 `*.????-??-??.log` 与日期子目录两种布局都覆盖，只删轮转件、不动活动日志），按 `ZEEK_RETENTION_DAYS=3` 每 `ZEEK_CLEAN_INTERVAL=3600` 秒跑一次；**整点清理循环的实效仍待用探针文件（改 mtime 的旧归档）复验** |
| 3 | ✅（除 ja3） | dns 有 query/qtype/qtype_name/rcode/rcode_name/opcode/rejected；ssl 有 server_name/version/cipher/curve/established/resumed/ssl_history；http 字段齐全；带 `X-Forwarded-For` 的请求另有 `proxied`（见第 9 行）。`ja3`/`ja3s` 在 Zeek 9.0 里不存在（见「已知限制」） |
| 4 | ✅ 已修 + 已扩到响应体 | 上线实测 POST 无 body：ASCII 体 `{"probe":"ascii","n":1}` 有 `body`、UTF-8 体 `{"text":"中文请求体"}` 无 → 判据 `[^\x09\x0a\x0d\x20-\x7e]` 把中文整块丢了；已改为只拦 NUL/C0（见 `site/shentong-httpbody.zeek`）。2026-10-02 又加响应体：`resp_body` + Zeek 自带 `response_body_len`，容器内 Zeek 单测 9 项全过（请求/响应分块截断、GET 只采响应体、NUL 双向拦、UTF-8 双向放行、PUT 采请求体） |
| 5 | ✅ | 界面配 `172.16.196.0/24` 后启动命令变为 `zeek -C -i ens160 -f net 172.16.196.0/24 /usr/local/zeek/share/zeek/site/local.zeek`，`/config/interface.conf` 里 `monitored_nets` / `bpf_filter` / `local_nets` 三处一致，`packet_filter.log` 记 `{"filter":"net 172.16.196.0/24","init":true,"success":true}`。**首次下发即暴露一个入口脚本 bug**：`entrypoint.sh` 原来把过滤器写成位置参数（`zeek -C -i "$iface" "$bpf" …`），Zeek 当脚本名去加载 → `fatal error: can't find net 172.16.196.0/24` 无限重启；已改为 `-f "$bpf"`（未配网段时走 else 分支，此前没跑到过） |
| 6 | ✅ | 无 notice.log（未加载 `policy/protocols/*`），符合预期 |
| 7 | ✅ | ES 聚合：log_type = conn 3168 / dhcp 18 / dns 8 / ssl 8 / http 2；event_type = rejected_connection 3140 / dhcp_activity 18 / conn_established 17 / scan_attempt 11 / dns_query 8 / tls_session 8 / http_request 2 |
| 8 | ✅ | detector 统计日志：扫描 17335 / 命中 60 / 频率触发 1 / 摘要 7 / 投递 9（`shentong:freq:*` 里已有内置-内网慢速横向、大面积目标探测、内网慢速服务枚举等键） |
| 9 | ✅ 已支持（2026-10-02） | 本机探针（uid `Cy2rDP36QlAdi9ru79`）发 `X-Forwarded-For: 198.51.100.77, 203.0.113.9` → `http.log` 得 `proxied: ["X-FORWARDED-FOR -> 198.51.100.77, 203.0.113.9"]`，`id.orig_h` 仍是 TCP 对端；归一化后 `real_client_ip=198.51.100.77`、`src_ip` 不变；同一条还有 `resp_body` 与 `resp_body_len=80` |
