# 深瞳 · Zeek 9.0 适配镜像

面向本项目的 Zeek 容器：JSON 日志、**24 小时轮转 + 本地只保留 3 天**、Filebeat 直发 ES、
自定义脚本（HTTP 请求体采集等）、以及**由 Web 后台配置监听网卡**（看门狗自动重载）。

## 基底与版本

- 基底：官方 `zeek/zeek`（Debian），默认 tag **`9.0`**（Zeek 9.0 LTS，2026-09 发布）
- 可用构建参数覆盖：`--build-arg ZEEK_BASE=zeek/zeek:lts`
- 已核实：Zeek 9.0 是 LTS，集群通信用 ZeroMQ、移除 Broker WebSocket（本项目不用集群，无影响）

## 目录

```text
zeek/
├── Dockerfile              # 基底 + Filebeat + 站点脚本 + 入口
├── entrypoint.sh           # 网卡枚举 / 脚本渲染 / 启动 / 看门狗 / 清理
├── filebeat.yml            # 发运到 ES（索引 zeek-<logtype>-yyyy.MM.dd）
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
  bpf_filter=not port 22
  local_nets=10.0.0.0/8,192.168.0.0/16
  ```
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
