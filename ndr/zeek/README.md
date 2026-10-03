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
├── entrypoint.sh           # 网卡枚举 / 脚本渲染 / 启动 / 看门狗 / 日志与提取件清理
├── filebeat.yml            # 发运到 Redis 采集队列（shentong:events:collect）
├── extract_cleanup.py      # 提取件清理：按 files.log 的 MIME 白名单删 + 容量淘汰（批 4）
├── site/
│   ├── local.zeek              # 总入口（顺序：json → extra → policies → httpbody → limits → httpheaders → file-extract → fingerprints → nets → scripts-d）
│   ├── shentong-json.zeek      # JSON 输出 + 24h 轮转 + /logs 输出目录
│   ├── shentong-extra.zeek     # 显式加载各协议分析器（保证字段齐全）
│   ├── shentong-policies.zeek  # Zeek 自带策略：ssl-log-ext / hash-all-files / stats / header-names / var-extraction-cookies + 关掉 notice 流
│   ├── shentong-httpbody.zeek  # HTTP 请求体/响应体采集（截断 + 跳过二进制）
│   ├── shentong-limits.zeek    # 正文上限（入口按 interface.conf 自动重写）
│   ├── shentong-httpheaders.zeek # HTTP 请求/响应头全量值（单头 256、同向总量 4KB 封顶）
│   ├── shentong-file-extract.zeek # HTTP/FTP 明文文件提取到 /extract（单文件上限 16MiB，批 4）
│   ├── shentong-fingerprints.zeek # 指纹开关：JA3/JA3S 与 JA4（BSD-3-Clause）
│   ├── shentong-nets.zeek      # Site::local_nets（入口自动重写）
│   ├── shentong-scripts-d.zeek # scripts.d 加载器（入口自动重写）
│   └── vendor/                 # 上游脚本（只收 BSD-3-Clause，见 vendor/README.md）
│       ├── README.md           # 来源 commit、逐字 vs 自建、为什么 JA4+ 不进仓库
│       ├── ja3/                # salesforce/ja3（+ 自建 __load__.zeek，不加载 intel_ja3）
│       └── ja4/                # FoxIO ja4-zeek-scripts 的 ja4/ 与 utils/（+ 自建 __load__.zeek / config.zeek）
└── scripts.d/              # ★ 可扩展目录：放 *.zeek 自动加载
```

> **`site/vendor/` 只能放在 `site/` 下面**：`Dockerfile:28` 只把 `site/` 整棵复制进镜像的
> `/usr/local/zeek/share/zeek/site/`，站点脚本用相对路径 `@load ./vendor/...`；放到 `zeek/vendor/`
> 会直接 `fatal error … can't find ./vendor/ja3`。
> **许可证**：只收录 BSD-3-Clause 的 JA3/JA3S（`salesforce/ja3`）与 **JA4 本体**（FoxIO 仓库里
> 唯一 BSD-3 的部分）。JA4S / JA4H / JA4L / JA4LS / JA4T / JA4TS / JA4D / JA4SSH / JA4X 是
> `FoxIO License 1.1`（仅非商业，出售/托管/给付费客户提供价值都需 OEM 授权），**本项目对外售卖
> 与托管，因此一律不收录**，理由与来源见 `site/vendor/README.md`。

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
| 轮转归档位置 | **同目录平铺改名**：`conn.log` → `conn.2026-10-02-09-30-15.log` | `Log::default_rotation_date_format = "%Y-%m-%d-%H-%M-%S"`（实机核对：不是日期子目录；**必须带时分秒**，见下） |
| 本地保留 | **只保留 N 天**（默认 3 天，按分钟精确判定） | 容器入口清理循环（Zeek 日志框架**不做过期删除**，见下） |

> **为什么清理要自己写**：Zeek 日志框架只做 rotation，**不做过期删除**；Zeek 生态里删除过期归档是
> `zeekctl` 的能力（`LogExpireInterval` + `bin/expire-logs`，由 `zeekctl cron` 跑）。本项目用单进程
> 方式运行（不用 zeekctl 集群），因此保留天数由 `entrypoint.sh` 的 `cleanup_once()` 保证：
> 两条 `find` 分别处理**顶层平铺归档**与子目录布局里**轮转命名**的文件（`*.????-??-??-??-??-??.log`
> 与历史格式 `*.????-??-??.log`），**不动正在写的活动日志**（`conn.log` 这类），也不无差别删子目录。
> 保留期用 `-mmin +$((天数*1440))`，即字面的「超过 N 天就删」（早先用 `-mtime +3`，实际会留到第 4 天以上）。
> **Filebeat 不在运行时本轮直接跳过删除** —— 删掉还没上报的归档就是永久丢数据。
>
> **⚠ 轮转名必须带时分秒（2026-10 QA 必修 1）**：日期格式只到「天」时，同一天内第二次启动 Zeek
> 会用同名文件**覆盖**当天已归档的数据（本机实测：同配置连跑两次，第二次的 `rot.2026-10-02.log`
> 覆盖第一次，sha256 变化、前一次内容消失）。界面改网段触发的重载、`docker compose restart`、
> 崩溃自愈都会重启 Zeek，所以这是常态风险。现在用 Zeek 上游默认的 `%Y-%m-%d-%H-%M-%S`，
> **别改回只到天的格式**；Filebeat 的 `log_type` 提取规则同步能剥这个后缀
> （`tests/py/test_filebeat_yml.py` 对规则内容与顺序都有断言）。
>
> **2026-10-02 实测**：往 `/logs` 放两个轮转命名的探针（`zzoldprobe.2026-09-20.log` 的 mtime 改成 10 天前、`zznewprobe.2026-10-01.log` 改成 1 天前）→ 容器重建时**启动清理循环在没有任何人工干预的情况下**就把旧的那个删掉、新的那个留下；同样两条 `find` 手工跑一遍也验证了模式匹配。

**Filebeat 发运的两个易错点**（都实测过，别再踩）：

1. **非事件文件的排除必须写在 `prospector.scanner.exclude_files`**（filestream 的 Scanner 选项）。写成输入顶层的 `exclude_files:`（那是旧 `log` 输入的键）在 Filebeat 8.15.3 上**完全无效**：探针 `/logs/stderr.log` 照样被采集并进了事件索引。而且 `filebeat test config` 对两种写法都回 `Config OK`（不报未知键）、`filebeat --once` 也在第一次扫描前就退出（约 40ms、harvester 0）—— **只有端到端探针能判定**。
2. **输出用 `queue.disk`，不要用 `queue.spool`**：本镜像的 Filebeat 是 OSS 构建，`spool` 直接报 `unrecognized queue type 'spool'`。磁盘队列目录与注册表同在命名卷 `zeek-filebeat` 上，所以 Redis 停掉期间事件留在磁盘、恢复后补齐（实测：停用期间两条标记在 ES 里 0 条，`start redis` 后各 1 条），容器重建也不丢。

## 可观测性（健康检查 / 守护 / 时区）

采集面最危险的失败模式是「容器 Up、其实啥都没采」。四处护栏（2026-10 QA 必修 2）：

| 机制 | 行为 | 相关变量（默认） |
|---|---|---|
| 容器健康检查 | 镜像内置 `HEALTHCHECK`，执行 `healthcheck.sh` 读入口写的哨兵 `/tmp/zeek-health`。**Zeek 进程不在**、**窗口内启动次数超限**（起不来或刚到就退）、**Filebeat 掉线**、**哨兵 >2 分钟没更新** → `unhealthy`（`docker ps` 的 STATUS 可见）。只上报，不触发重启（compose 的 restart 策略不看健康状态，故与「退出就重拉」不打架） | `ZEEK_HEALTH_INTERVAL`(30) `ZEEK_FLAP_WINDOW`(300) `ZEEK_FLAP_MAX`(5) |
| Zeek 存活 | 主循环在 Zeek 退出后 2 秒重拉（原有行为）；一退出就把哨兵改写为 `unhealthy`，不必等下一拍 | — |
| Filebeat 守护 | 每 30 秒确认 Filebeat 进程；掉线自动重拉，输出**追加**到 `/var/log/filebeat.out`（能看到上次退出前的原因） | `ZEEK_FILEBEAT_CHECK_INTERVAL`(30) `ZEEK_FILEBEAT_BIN`(/usr/local/bin/filebeat) |
| 时区 | 容器设 `TZ=Asia/Shanghai`（基础镜像自带 tzdata，实测 `date` 为 CST）：轮转文件的日期戳、清理窗口与日志时间都按北京时间，不再比北京时间晚 8 小时换日 | compose 的 `TZ` |

> 另：未配网段（`bpf_filter` 为空）时启动日志会**显式告警「全量抓包」**，`packet_filter.log` 记为
> `ip or not ip` —— 「新装/清卷后忘了下发网段」不再只靠人记得。

## 网卡配置（由 Web 后台管理）

- 后台写入共享文件 `/config/interface.conf`：

  ```ini
  interface=ens224
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
- `interface` 的缺省值三处统一为 **`ens224`**（compose 的 `ZEEK_IFACE` 默认、`entrypoint.sh` 的
  `IFACE_DEFAULT`、后端 `settings.zeek_interface`）——实机在 `.env` 里显式设 `ZEEK_IFACE=ens160`，
  不受默认值影响；**默认值只是兜底**，网卡名还是要按宿主实际网卡填（界面下拉可选）
- `local_nets` 渲染时会**同时**写 `redef Site::private_address_space_is_local = F;`：只 redef
  `local_nets` 收窄不掉 —— Zeek 的 `update_local_nets_table()` 会把内置的私有地址段（RFC1918 等
  42 条）并进来（2026-10 实测：配 1 条网段后 `|Site::local_nets|=43`），关掉它才与后台清单一致；
  `local_nets` 留空时不写这一行，沿用 Zeek 默认判定
- 容器入口把网卡清单写入 `/config/interfaces.json`（供后台下拉选择）
- **看门狗**每 10 秒比对配置哈希，变化则渲染网段脚本并在**容器内重载 Zeek**（不重启容器、
  不需要 docker socket；重载期间约 1~2 秒短暂中断抓包）

## 文件提取（批 4）

HTTP/FTP **明文**传输的文件会被落到 `/extract/<fuid>`（fuid 就是 files.log 的 `fuid`），
后端只读挂载同一个卷，用 `GET /api/files/{fuid}`（需登录）下载。

- **只提取 HTTP/FTP**：`site/shentong-file-extract.zeek` 里 `sources = { "HTTP", "FTP" } &redef`；
  SSL/TLS 里的文件（加密流量）不碰。
- **单文件上限 16 MiB**：`redef FileExtract::default_limit = 16777216`；**只有超限时** FileExtract 才写
  `extracted_size`（= 上限）并把 `extracted_cutoff` 置真，此时下载响应带 `X-Extract-Cutoff: 1` 与
  `X-Extract-Size`，别把截断件当完整样本。**完整落盘的件 `extracted_size` 是 NULL** ——
  要核对字节数请看 `files.log` 的 `total_bytes`（实机复验确认：FileExtract 只在
  `file_extraction_limit` 事件里写 `extracted_size`）。
- **白名单是唯一的"能下载"口径**：`extract_cleanup.py` 里的 `DEFAULT_MIME_ALLOW`
  （文本 / XML / JSON / PDF / 邮件 / Office / 常见压缩包；**不含** `application/octet-stream`
  与可执行体）。JSON 同时收 `application/json` 与 `text/json`（Zeek 对 JSON 请求体实测报后者，
  2026-10 实机复验补）。比较前会**剥掉 `; charset=…` 参数并统一小写**（files.log 的 `mime_type` 直接来自
  HTTP 的 `Content-Type`，实测带参数），否则正常网页会被当"白名单外"删掉。容器入口每 5 分钟跑一次清理：
  白名单外的删、files.log 里查不到记录的删（来源不是 HTTP/FTP 或分析器没落元数据）；
  只动 mtime 早于 120 秒的文件。
- **目录容量默认 10 GiB**：超过就按 mtime 从最老开始淘汰（先删老的，再保留新的）。
- 可调环境变量（`entrypoint.sh` 读取，重启容器生效）：

  | 变量 | 默认 | 作用 |
  |---|---|---|
  | `ZEEK_EXTRACT_DIR` | `/extract` | 提取目录（与后端 `extract_dir` 必须一致） |
  | `ZEEK_EXTRACT_CLEAN_INTERVAL` | `300` | 清理间隔（秒） |
  | `ZEEK_EXTRACT_MAX_BYTES` | `10737418240` | 目录容量上限（0 = 不按容量淘汰） |
  | `ZEEK_EXTRACT_MIN_AGE` | `120` | 只删 mtime 早于该秒数的文件（保护在写文件） |
  | `ZEEK_EXTRACT_MIME_ALLOW` | 空 | 逗号分隔的自定义白名单（覆盖内置表；`text/*` 这类通配要写 `text/` 前缀 —— 用 `.*` 结尾表示前缀匹配） |

- 手工核一遍：

  ```bash
  docker exec <zeek> python3 /usr/local/bin/extract_cleanup.py --dir /extract --logs /logs --dry-run -v
  ```

  输出形如 `[extract-cleanup] 目录=/extract 上限=10.0 GiB files.log 记录=N 保留=… 白名单外删除=… 无记录删除=… 超限淘汰=… 释放=…`。
  **`--dry-run` 只统计不删**，排查"文件怎么没了"时先用它看一眼判定结果。
- 提取件与日志一样属于现场数据：**下载接口只认 fuid**（不接受客户端路径），文件名取自 ES 里
  服务端自己写的 `extracted` 字段，并在解析后钉死在提取目录内（目录穿越与符号链接逃逸都会被拒）。

## 可扩展脚本

`site/scripts.d/` 里的 `*.zeek` 由入口的 `render_scripts_loader()` 在**容器启动时**生成 `@load` 列表
（脚本本身随镜像 COPY 进去，另有 `000-placeholder.zeek` 占位保证目录非空）：

- **开发线**（`docker-compose.yml`）：该目录 **bind mount** 进容器，放 `*.zeek` 后
  `docker compose restart zeek` 即生效，无需重建镜像。
- **部署线**（`docker-compose.deploy.yml`）：容器里没有源码目录，**必须把脚本提交进仓库、由
  GitHub Actions 出镜像**，服务器 `docker compose pull` + `up -d zeek` 后生效；直接往运行中的
  容器里写文件不会持久（也躲不过下一次重建）。

## 构建

只由 GitHub Actions 构建（项目规则禁止本地构建），镜像推送至
`ghcr.io/<owner>/sec-agent/shentong-zeek:latest`。

## 已知限制

- 不做 Zeek 集群（manager/proxy/worker）
- 不做脚本在线热更新（加载器只在容器启动时生成：开发线 bind mount + `restart zeek` 生效；
  部署线需重新出镜像 —— 见「可扩展脚本」）
- HTTP 体采请求与响应两个方向、单条上限 4096 字节、跳过二进制（**放行 UTF-8**：2026-10 上线发现
  原判据只放行可打印 ASCII，中文请求体整块被丢，已改成只拦 NUL/C0 控制字符）
- **JA3 / JA3S / JA4 已可产出（2026-10，批 2）**：Zeek 9.0 自带的分析器里**没有** `ja3`/`ja3s`
  字段（容器内 `local i: SSL::Info; print i?$ja3;` 编译报 `no such field in record`），所以本仓库
  vendor 了上游 BSD-3 脚本，由 `site/shentong-fingerprints.zeek` 加载：`ssl.log` 现有
  `ja3` / `ja3s`（`salesforce/ja3`）与 `ja4`（FoxIO JA4 本体）。**JA4S / JA4H / JA4L / JA4T /
  JA4SSH / JA4D / JA4X 一律不收录**（`FoxIO License 1.1` 仅非商业；见上面 vendor 那段与
  `site/vendor/README.md`），需要时买 OEM 授权再把脚本丢进 `site/vendor/ja4/` 并 `@load`。
  这三个上游脚本自带的独立日志流（`tlsfp.log`/`ja3sfp.log`/`fingerprint_ja4.log`）**都没有写入口**，
  实测不会产生，所以只需关掉 `notice`（`shentong-policies.zeek` 里 `Log::disable_stream(Notice::LOG)`）
- **文件哈希已可产出（2026-10，批 2）**：`policy/frameworks/files/hash-all-files.zeek` 让
  `files.log` 带上 `md5`/`sha1`/`sha256`（容器内与 Python `hashlib` 逐字比对一致），归一化后落成
  `md5`/`sha1`/`sha256` 字段；此前 `files.log` 的 `analyzers` 是空数组、没有任何哈希
- **响应体可能含二进制乱码**：`shentong-httpbody.zeek` 的判据为了保住中文（UTF-8
  高位字节）只能拦 NUL/C0 控制字符，因此**压缩响应（gzip/br）或恰好不含这些字节的
  二进制响应**会以乱码形式写进 `resp_body`（字段不丢、内容不可读）。要精确跳过需再接
  `http_header` 事件记录 `Content-Encoding` 并维护「本事务不采」表，本项目尚未做。
- **请求头值已全量采集（2026-10，批 3）**：Zeek 自带的 HTTP 分析器只把**表明请求经过代理**的头收进
  `HTTP::Info$proxied`（默认清单：`X-Forwarded-For` / `X-Forwarded-From` / `Forwarded` / `Client-IP` /
  `Via` / `Xroxy-Connection` / `Proxy-Connection`），值形如
  `"X-FORWARDED-FOR -> 198.51.100.77, 203.0.113.9"`；本项目 normalizer 已把它解析成归一化
  字段 `real_client_ip`（没有代理头时是 NULL，`src_ip` 仍是 TCP 对端）。注意转发头是客户端自报、
  **可伪造**，拿它做封禁/画像必须配可信代理白名单（本项目尚未做，`real_client_ip` 只代表「头里写了什么」）。
  其余头现在由自写的 `site/shentong-httpheaders.zeek` 落成 `req_headers` / `resp_headers` 两列
  （逐行 `Name: value`，**单头截 256 字符、同方向累计封顶 4KB**；值里含任意控制字符 —— 包括
  `\r`/`\n` 换行注入 —— 整体记成 `<binary>`），另有 `policy/protocols/http/header-names.zeek`
  提供的**有序头名** `client_header_names` / `server_header_names`（只有名字没有值）。
  **这两个字段是明文**：`Cookie` / `Authorization` / `Set-Cookie` 都会落库，是既定取舍
  （见 `docs/ndr-collect-plan.md`「已接受的风险与取舍」）。
- **正文上限可在后台改（2026-10，批 3）**：请求/响应正文的落库上限在
  `site/shentong-limits.zeek`（默认请求 16 KB / 响应 64 KB），该文件由 `entrypoint.sh` 的
  `render_limits()` 在启动时与看门狗检测到配置变化时，按 `/config/interface.conf` 的
  `body_max_bytes` / `resp_body_max_bytes` 重写；界面上在「监控网段」页的 Zeek 面板改 KB 值
  （后端同时写 `interface.conf` 与 `system_config` 的 `http.body_max_chars` /
  `http.resp_body_max_chars`，normalizer 30 秒 TTL 内跟随）。**Zeek 记的
  `request_body_len` / `response_body_len` 是完整字节数，不受截断影响**（落库为
  `request_body_len` / `resp_body_len`）。改上限会触发 Zeek 重载（约 1~2 秒抓包中断）。
- **明文文件会落盘（2026-10，批 4）**：HTTP/FTP 明文传输的文件按上面的白名单提到 `/extract/<fuid>`，
  **单文件 16 MiB 封顶**（超限只写前 16 MiB，`extracted_cutoff` 置真、`extracted_size` 记上限）；
  **加密流量（SSL/TLS）不提取** —— "文件内容拿不到"只解决了一半，TLS 里的文件仍只能靠哈希/元数据。
  提取件是**原始明文**（上传的凭据、内部文档都会落盘），护栏只有容量上限与 MIME 白名单；
  `/extract` 卷只挂给 zeek（rw）与 backend（ro），下载必须登录且只认 fuid。
- **落盘件可能因镜像丢包而不完整（2026-10 实机复验，未做护栏）**：提取只保证"Zeek 看到多少写多少"。
  实机把 18.7 MB 主体上传到外网镜像时，`files.log` 记 `total_bytes=18700000` 而 `seen_bytes=184432`，
  落盘件 5.3 MB —— 既不是上限截断（`extracted_cutoff=false`），也不是完整原文。
  下载接口目前**无法告知这种不完整**（归一化 schema 没搬 `total_bytes`/`seen_bytes`，只有上限截断会在
  元数据里留痕）。要处理得先把 `total_bytes` 纳入归一化并在响应头加 `X-Extract-Partial`（待办）。
  影响面：被监测主机的大文件上传/下发（高带宽流）比小文件更容易丢；小文件（KB 级）实测字节数与
  `total_bytes` 完全一致。

## 上线后专项检查（日志与协议解析）

> 状态：**已在实机（172.16.196.77，Zeek 9.0.0，iface=ens160）做过一遍**，2026-10。
> 结论见下表后的「实机结果」；脚本改动只在纸面 + 单进程归一化侧验证过，首次上线必须逐条核。

| # | 检查项 | 怎么核 | 期望 |
|---|---|---|---|
| 1 | 实际产出了哪些日志 | `docker exec <zeek> ls -la /logs` | 至少 `conn.log` / `http.log` / `dns.log` / `ssl.log`；有对应流量时出现 `files.log` / `smtp.log` / `ssh.log` / `dhcp.log` / `notice.log` |
| 2 | 轮转与保留 | `ls /logs` 顶层活动日志与轮转归档 | 每 24h **同目录平铺改名**（`conn.log` → `conn.2026-10-02-09-30-15.log`，实机核对：**不是日期子目录**；时间戳带时分秒，防同日重启覆盖）；超过 N 天（默认 3）的归档被入口清理循环删掉，**Filebeat 不在运行时这一轮不删**（活动日志不动） |
| 3 | 字段是否齐全 | 看一条 `http.log` / `dns.log` / `ssl.log` / `files.log` | http 有 `method`/`host`/`uri`/`user_agent`/`status_code`（**批 3 起还有 `req_headers`/`resp_headers` 全量头值与 `client_header_names`/`server_header_names`**）；ssl 有 `server_name`/`cipher`/`version`（**批 2 起还有 `ja3`/`ja3s`/`ja4`**，见「已知限制」）；files 有 `md5`/`sha1`/`sha256`（`source`/`is_orig` 表明方向）；**批 4 起 files 还会出现 `extracted`/`extracted_size`/`extracted_cutoff`（该文件已落盘到 `/extract/<fuid>`，`extracted` 的值就是 fuid）**；`site/shentong-extra.zeek` 加载的分析器都生效；经过代理的请求 `http.log` 的 `proxied` 会有值 |
| 4 | 自研 HTTP 体采集 | 看 POST 请求的 `http.log` 是否有 `body`（请求体）与 `resp_body`（响应体） | 两者都有（**批 3 起上限默认 16KB/64KB 且可在界面改**，见「已知限制」；二进制块跳过、UTF-8 放行）；GET/HEAD 无 `body` 但有 `resp_body`；**响应体完整字节数看 Zeek 自带的 `response_body_len`**（不受截断影响，落库为 `resp_body_len`） |
| 5 | 网段只放行该抓的 | `zeek` 启动命令的 BPF（`docker exec <zeek> ps -o args= -C zeek`） | 与界面「监控网段」一致（`bpf_filter` 由网段自动生成，命令里应出现 `-f net …`；`-f` 缺失会被 Zeek 当脚本名，启动即 fatal）；**未配网段时全量抓包** |
| 6 | 是否重复告警 | 看 `notice.log` 有无内容 | **不产检测类 notice**：不加载 `policy/protocols/*` 的检测脚本（只加载 json-logs 与 `shentong-policies.zeek` 里的 ssl-log-ext / hash-all-files / stats / header-names / var-extraction-cookies），且 `shentong-policies.zeek` 显式 `Log::disable_stream(Notice::LOG)` —— 检测全由内置规则做 |
| 7 | 归一化后的类型 | `GET /api/events` 或看运行状态/事件页 | `log_type` 分桶正确（`conn`/`http`/`dns`/`ssl`/`files`/…），`event_type` 细分正确（`http_login`/`http_upload`/`http_error`/`http_request`） |
| 8 | 内置规则是否吃到字段 | 看规则命中与 `raw_evidence` | body/uri/query/user_agent 等字段真的进了检测（82 条内置规则里 47 处用到这些字段） |
| 9 | **反向代理的原始客户端 IP** | 经过 nginx/HAProxy/CDN 的请求，看 `http.log` 的 `proxied` 与归一化后的 `real_client_ip` | **已支持（2026-10）**：Zeek 采代理头进 `proxied`，normalizer 解析最左合法 IP 落成 `real_client_ip`（无代理头 = NULL，`src_ip` 仍是代理 IP）。**未做**：可信代理白名单（头可伪造）、`X-Real-IP`（不在 Zeek 默认清单）、四层代理（只转发 TCP 不写头）只能靠 PROXY protocol 或回查 NAT/防火墙日志 |

| 10 | **文件提取（批 4）** | 经 HTTP 传一个白名单文件，看 `docker exec <zeek> ls -l /extract`、`files.log` 的 `extracted`/`extracted_size` 与 `GET /api/files/<fuid>` | `/extract/<fuid>` 存在且字节数与 `files.log` 的 `total_bytes` 一致（`extracted` 的值就是 fuid；**完整件的 `extracted_size` 是 NULL**）；传图片等白名单外类型 → 5 分钟内被清理助手删掉（files.log 记录仍在），下载返回 404；**只覆盖 HTTP/FTP 明文**，TLS 里的文件不会出现；超 16 MiB 的文件被截断（`extracted_cutoff=true`、`extracted_size`=上限）且响应带 `X-Extract-Cutoff: 1` |

### 实机结果（2026-10，172.16.196.77）

| # | 结果 | 证据 |
|---|---|---|
| 1 | ✅ | `/logs`：conn.log 7.9MB、dhcp.log 23KB、dns.log 39KB、files.log 1140B、http.log、ssl.log 35KB、weird.log、x509.log、packet_filter.log；无 notice.log |
| 2 | ⚠️ 已修（2026-10 QA） | 轮转是**同目录平铺改名**：`conn.2026-10-01.log`（121MB）、`ssl.2026-10-02.log`、`packet_filter.2026-10-02.log`、`reporter.2026-10-02.log`、`dhcp.2026-10-02.log` 等都在 `/logs` 顶层，没有日期子目录。**但当时格式只到「天」，同一天启动两次是拿同名文件互相覆盖**：2026-10-02 02:55 与 06:21 两次重建，后一次的 `*.2026-10-02.log` 覆盖了前一次（本机用 `zeek/zeek:9.0` 独立复现：`rot.2026-10-02.log` 第二次覆盖第一次，sha256 `0d87e368…`→`0e5c3186…`）→ 已把 `Log::default_rotation_date_format` 改成带时分秒的 `%Y-%m-%d-%H-%M-%S`，Filebeat 的 `log_type` 剥离规则同步（`tests/py/test_filebeat_yml.py` 断言规则内容与顺序）。清理由 `entrypoint.sh` 的 `cleanup_once()` 两条 `find` 做（顶层与子目录布局都只删轮转命名件、不动活动日志；保留期用 `-mmin` 精确到分钟；**Filebeat 不在时不删**），按 `ZEEK_RETENTION_DAYS=3` 每 `ZEEK_CLEAN_INTERVAL=3600` 秒跑一次。**2026-10-02 探针实测**：`zzoldprobe.2026-09-20.log`（mtime 10 天前）与 `zznewprobe.2026-10-01.log`（mtime 1 天前）放进 `/logs` 后重建容器 → 启动清理循环自动删掉旧的那个、留下新的那个 |
| 3 | ✅（批 2 起含指纹） | dns 有 query/qtype/qtype_name/rcode/rcode_name/opcode/rejected；ssl 有 server_name/version/cipher/curve/established/resumed/ssl_history；http 字段齐全；带 `X-Forwarded-For` 的请求另有 `proxied`（见第 9 行）。**`ja3`/`ja3s` 在 Zeek 9.0 自带分析器里不存在**（见「已知限制」），批 2 起由 `site/vendor/` 里 vendor 的上游 BSD-3 脚本产出 `ja3`/`ja3s`/`ja4`（容器内实测：`ja3:"284deaeae14ea5ddc96c5d7e59855422"`、`ja3s:"15af977ce25de452b96affa2addb1036"`、`ja4:"t13d301200_1d37bd780c83_ecd0401ec68b"`），`files.log` 另带 `md5`/`sha1`/`sha256` |
| 4 | ✅ 已修 + 已扩到响应体 | 上线实测 POST 无 body：ASCII 体 `{"probe":"ascii","n":1}` 有 `body`、UTF-8 体 `{"text":"中文请求体"}` 无 → 判据 `[^\x09\x0a\x0d\x20-\x7e]` 把中文整块丢了；已改为只拦 NUL/C0（见 `site/shentong-httpbody.zeek`）。2026-10-02 又加响应体：`resp_body` + Zeek 自带 `response_body_len`，容器内 Zeek 单测 9 项全过（请求/响应分块截断、GET 只采响应体、NUL 双向拦、UTF-8 双向放行、PUT 采请求体） |
| 5 | ✅ | 界面配 `172.16.196.0/24` 后启动命令变为 `zeek -C -i ens160 -f net 172.16.196.0/24 /usr/local/zeek/share/zeek/site/local.zeek`，`/config/interface.conf` 里 `monitored_nets` / `bpf_filter` / `local_nets` 三处一致，`packet_filter.log` 记 `{"filter":"net 172.16.196.0/24","init":true,"success":true}`。**首次下发即暴露一个入口脚本 bug**：`entrypoint.sh` 原来把过滤器写成位置参数（`zeek -C -i "$iface" "$bpf" …`），Zeek 当脚本名去加载 → `fatal error: can't find net 172.16.196.0/24` 无限重启；已改为 `-f "$bpf"`（未配网段时走 else 分支，此前没跑到过） |
| 6 | ✅ | 无 notice.log（未加载 `policy/protocols/*`），符合预期 |
| 7 | ✅ | ES 聚合：log_type = conn 3168 / dhcp 18 / dns 8 / ssl 8 / http 2；event_type = rejected_connection 3140 / dhcp_activity 18 / conn_established 17 / scan_attempt 11 / dns_query 8 / tls_session 8 / http_request 2 |
| 8 | ✅ | detector 统计日志：扫描 17335 / 命中 60 / 频率触发 1 / 摘要 7 / 投递 9（`shentong:freq:*` 里已有内置-内网慢速横向、大面积目标探测、内网慢速服务枚举等键） |
| 9 | ✅ 已支持（2026-10-02） | 本机探针（uid `Cy2rDP36QlAdi9ru79`）发 `X-Forwarded-For: 198.51.100.77, 203.0.113.9` → `http.log` 得 `proxied: ["X-FORWARDED-FOR -> 198.51.100.77, 203.0.113.9"]`，`id.orig_h` 仍是 TCP 对端；归一化后 `real_client_ip=198.51.100.77`、`src_ip` 不变；同一条还有 `resp_body` 与 `resp_body_len=80` |

**批 2 实机复验（2026-10-02，镜像 `shentong-zeek` `244ec0300d17` → `213e76f6fc69`）**

- **指纹**：从服务器发起外网 HTTPS → ES 30 分钟内 `log_type:ssl` 187 条，带真实值
  `ja3:"7704a11cf87dfcf33080b90ce11d5527"`、`ja3s:"f4febc55ea12b31ae17cfb7e614afda8"`、
  `ja4:"t13d1715h2_5b57614c22b0_a54fffd0eb61"`（`ja4` 值分布：该值 ×20、另一个 ×1；另有 83 条旧会话为空）。
- **文件哈希**：明文下载 254968 字节 → `files.log` 的 `analyzers:["SHA256","SHA1","MD5"]`，`md5`
  `1696fa2694f099d735d609ea8bd8dee6`、`sha256` `26758a13cecfaff9ff274d31ea9a4633674a999bd130c09f6ecd66a4b8071184`
  **与服务器上本地 `md5sum`/`sha256sum` 逐字一致**；ES 文档另有 `fuid`/`file_source:"HTTP"`/`file_is_orig:false`。
- **stats 流**：`stats.log` 开始产出（5 分钟一报）→ ES 2 条（`log_type:"stats"`、`log_type_known:true`、
  `source_file:"stats.log"`），归一化记「类型闸门只入库 2 条」，**不进检测**。
- 核 ES 时两个坑：`log_type` 是 `text`，聚合要用 `log_type.keyword`（否则 `Fielddata is disabled`）；
  normalizer 对缺失字段写空字符串，`exists` 会把空值也算上，别用它数「有值的文档」。

**批 3 实机复验（2026-10-02，镜像 `shentong-zeek` `213e76f6fc69` → `716005bbe598`）**

- **头值全量入库**：服务器本机 `curl -X POST http://mirrors.aliyun.com/ubuntu/dists/noble/Release
  -H 'X-Probe-Long: B×400' -H 'X-Probe: b3-ev-post' -H 'Cookie: probe=abc123; sid=xyz'
  --data-binary @/tmp/b3_body.txt`（体 3908 字节）→ ES 文档 `@timestamp 2026-10-02T07:49:13.426Z`
  （与 Zeek 事件的 `ts` 同在毫秒级）：顶层 `req_headers` **450** 字符、`resp_headers` **496** 字符，
  `X-PROBE-LONG` 的值被截到 **256** 字符，`COOKIE: probe=abc123; sid=xyz` **明文落库**；
  `raw.client_header_names` = `['HOST','USER-AGENT','ACCEPT','X-PROBE-LONG','X-PROBE','COOKIE','CONTENT-LENGTH','CONTENT-TYPE']`、
  `raw.cookie_vars` = `['probe','sid']`。
- **正文上限热改（双向都通）**：`PUT /api/zeek/interface` 带 `body_max_kb:1` / `resp_body_max_kb:4` →
  `interface.conf` 写入 `body_max_bytes=1024` / `resp_body_max_bytes=4096` → 看门狗 ~10 秒内重写容器内
  `shentong-limits.zeek` 并重载（`last_reload` 前进，约 1~2 秒抓包中断）。此时同一 POST 的 `body=1024`、
  GET 一条 254968 字节响应的 `resp_body=4096`，而 **`resp_body_len` 仍是 254968**（Zeek 的
  `raw.response_body_len`、请求侧 `raw.request_body_len=3908` 同样完整）。随后改回 16 KB / 64 KB，
  `interface.conf` 与容器内脚本均复验为 `16384`/`65536`。
- **字段归属**：`req_headers` / `resp_headers` / `resp_body_len` 有顶层归一化字段；
  `client_header_names` / `server_header_names` / `cookie_vars` **只在 `raw.*` 下**（归一化 schema 不带）。
- **已知限制（实测，非批 3 引入）**：Filebeat 偶发 `ndjson` 解析失败会让事件变成**空壳文档**
  （有 `@timestamp` / `log_type`，其余字段空串，`raw.error.type=json`）或直接丢失。90 分钟内实测 **9 条**，
  跨 `conn`/`http`/`files`/`x509`/`stats`/`weird` 多种日志、时间跨批 3 部署前后，**多落在 Zeek 重启/日志轮转
  前后约半分钟内**（看门狗 07:44:47 重载后 9s 与 33s 各一次），疑为轮转窗口读到非行首片段；
  `filebeat.yml` 的 `add_error_key: true` 留下了 `raw.error`。批 3 的两条探针恰好落进这个窗口没进 ES，
  改在静默窗口重发即正常入库（上面证据即重发所得）。**未改 Filebeat 配置**（避免动已工作的采集链路），
  列为后续调查项。

**批 4 实机复验（2026-10-02，镜像 `shentong-zeek` `716005bbe598` → `latest` 修复版；后端 `sha256:9adedfe6053d`）**

- **落盘与下载全通**：`POST http://mirrors.aliyun.com/ubuntu/`（明文出方向，镜像看得到）带 2400B
  `text/plain` 体 → `/extract/FKQO9x4uHwL5zeCR6` 落盘 2400B，**sha256 与服务器上原文件逐字一致**；
  `GET /api/files/FKQO9x4uHwL5zeCR6`（带登录令牌）200，`content-type: text/plain; charset=utf-8`、
  `content-length: 2400`、`content-disposition: attachment; filename="FKQO9x4uHwL5zeCR6"`。
  同时那条请求的 404 响应体（2318B `text/html`）也落成一件（`is_orig:false`）。
- **白名单真的在删**：3000B 随机字节（`application/octet-stream`）落盘后 files.log 的 `mime_type`
  **为空** → 清理助手判「白名单外」删除（`--dry-run` 与真跑口径一致），删除后下载回 **404**；
  `--max-bytes 2000` 一轮按 mtime 从最老淘汰 8 件、释放 5.1 MiB、只剩最新的 599B 件。
- **鉴权与错误分支**：无令牌 **401**；fuid 长度不足（`short`）或带空格 **400**；URL 编码斜杠
  （`..%2F..%2Fetc%2Fpasswd`）路由不匹配 **404**；库中不存在的 fuid **404**。
- **截断链路（用临时调小的上限验证，非 16 MiB 实值）**：真实 18.7 MB 上传被远端 **413** 拒且镜像丢包
  严重（`total_bytes=18700000` / `seen_bytes=184432` / 落盘 5.3 MB / `extracted_cutoff=false`，见「已知限制」），
  所以把容器内 `default_limit` 临时改成 **1000** 再上传 2400B：两个 1000 字节截断件、
  files.log `extracted_size=1000` + `extracted_cutoff=true`、ES 同步（`exists extracted_size`=2、
  `extracted_cutoff=true`=2）、下载响应带 `x-extract-cutoff: 1` + `x-extract-size: 1000` +
  `content-length: 1000`；测完按容器内备份覆盖回 `16777216`（sha256 校验一致），Zeek 重启后命令仍是
  `zeek -C -i ens160 -f net 172.16.196.0/24 …`。16 MiB 这个具体数值由 `tests/zeek/batch4_test.zeek` 断言。
- **ES 字段**：`exists fuid` 91637、`exists extracted` 2119、`exists extracted_size` 0（= 完整件不写）、
  `extracted_cutoff=true` 0 → 调小上限验证后两者各变成 2。
- **两个部署/环境坑**：① `shentong-ndr` 镜像被 backend / normalizer / detector / ndr-mcp 四个服务共用，
  只 `up -d zeek backend` 会让 normalizer 跑旧镜像、新字段永远进不了 ES（`exists extracted` 恒为 0），
  必须四个一起重建；② **镜像口看不到采集机自身对部分外网目标的流量**（实测 Cloudflare/`postman-echo.com`
  在 `conn.log`/`http.log`/`files.log` 里完全没有记录，`mirrors.aliyun.com` 正常）——实机验收要挑可见目标，
  且高带宽流的丢包会让落盘件不完整（见「已知限制」）。

**卷级重建复验（2026-10-02，删掉全部 10 个卷从零重建后）**

- `zeek-config` / `zeek-logs` / `zeek-extract` 清空后 Zeek 回落默认：`interface.conf` 只剩 `interface=ens160`
  与两个默认上限（`body_max_bytes=16384` / `resp_body_max_bytes=65536`），启动命令**不带** `-f`
  （`packet_filter.log` = `"filter":"ip or not ip"`）——**网段是人工配置，删卷后必须重新下发**。
- 经 `PUT /api/zeek/interface` 重下发 `172.16.196.0/24` + 16 KB / 64 KB 后：启动命令回到
  `zeek -C -i ens160 -f net 172.16.196.0/24 …`，`packet_filter.log` `"filter":"net 172.16.196.0/24" … "success":true`，
  容器内 `shentong-limits.zeek` 重新渲染成 16384 / 65536。
- 提取/下载链路在空白卷上照样自愈：2400 B `text/plain` 与 2208 B `application/json` 上传 → 落盘
  sha256 与原文件逐字一致、`GET /api/files/<fuid>` 200 且 `content-length` 与落盘一致、无令牌 401；
  清理助手 `--dry-run` 对 6 件全保留（`text/json` 已在白名单内）。
- **核数时的坑（复核）**：`fuid` / `extracted` 在 `_common` 里，**每种 `log_type` 都带这两个键（值为空串）**，
  `exists extracted` 数出来的是全量文档（重建后 3770 / 总 3933）——数「有提取件的文件」要
  `log_type.keyword=files` 加 `extracted` 非空。
