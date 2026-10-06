# 签名引擎（Suricata）适配镜像

与 Zeek 并列的第二个采集/检测组件：**只输出命中规则的事件**（EVE `alert`），
与网络采集器共用同一份网卡/网段配置，日志走同一条归一化 → 入库 → 检测 → 摘要链路。

```text
SPAN 网卡 ─┬─ Zeek ─ conn/http/ssl/… ────────────┐
           └─ Suricata ─ eve.json（仅 alert，带 community_id）─┤
                                Filebeat（两个输入）→ Redis 采集队列
                                → 归一化（normalize_suricata）→ ES + 检测器 → 摘要 → 智能体
```

## 为什么是「并行加装」而不是「替换检测器」

- **签名引擎更强的地方**：字节级匹配（`|00|` 十六进制、`byte_test/byte_extract`）、
  几万条现成签名（ET Open，MIT）、二进制协议与协议内部字段、已知 CVE 利用的覆盖面。
- **检测器更强的地方**（Suricata 结构上做不了）：7 天 Welford 基线、账号/会话画像、
  被访问方资产基线、中继链路还原与去重、内外网方向、**「按实体数不同值」**
  （Suricata 的 `dataset` 是二值集合，不会数“有几个不同的账号/端口/目的”）、主机监控侧。
- 因此 2026-10 起：**48 条「判据全在 Suricata 有关键字的字段上」的内置规则交给签名引擎**
  （见 `../backend/app/rules/builtin.py` 的 `DELETED_RULES` 说明），检测器保留 32 条 + 新增
  3 条「签名命中」分档规则。

## 配置：只认共享文件

`entrypoint.sh` 读的是 `/config/interface.conf`（与网络采集器**同一份**，界面「监控网段」页维护）：

| 共享配置项 | 本容器的用法 |
|---|---|
| `interface` | `af-packet` 抓包网卡（缺省自动取第一块物理网卡；可用 `SURICATA_IFACE` 覆盖） |
| `monitored_nets` | `HOME_NET`（`EXTERNAL_NET: !$HOME_NET`）；为空时回落通用私网段并告警 |
| `tls_ports` | 从明文 HTTP 端口集里**剔除**这些端口（口径与 Zeek 侧一致：引擎默认端口集 − 运维声明） |

配置变化由容器内看门狗检测（默认 10s）→ 重渲染 + 重启 Suricata。
后端不接触 docker socket：它只写这份共享文件。

## 输出

- `eve.json` 只开 `alert`（`types: [alert]`），关掉 flow/dns/http/tls/stats ——
  那些元数据 Zeek 已经在提供，两边都产只会让 ES 变胖、让智能体看到两份事实。
- `community-id: yes`：告警带 `community_id`，Zeek 的 `conn.log` 也带同值（站点脚本
  `local.zeek` 里 `@load policy/protocols/conn/community-id-logging`），
  两个采集器对**同一条流**的事实就能对上（比五元组稳：不受 NAT/端口复用影响）。
- 告警保留 `payload`/`payload_printable`（默认 4KB 截断），但不落整包十六进制；
  写 `raw` 前会去掉 `packet`/`payload` 两个大字段（见 `normalizer._EVE_RAW_DROP`）。
- 归一化后：`event_type=signature_hit`、`log_type=suricata`、`source_system=suricata`，
  签名名/SID/类别/severity 进独立字段；**映射字节数为空**（体积类规则只认 Zeek 的 conn）。
- 日志按天/按 64MB 轮转进 `/logs/suricata/archive/`（留 3 天），轮转后重启 Suricata 重开文件。
- 每 30s 写一次 `/logs/suricata/status.json`（存活/网卡/网段/规则行数/版本），
  后端只读挂同一个日志卷，界面「监控网段」页据此显示签名引擎状态。

## 规则更新

规则在**构建镜像时**由 `suricata-update` 拉取 ET Open 并固化进镜像（容器运行期不需要外网）。
要改规则：改 `disable.conf` / `modify.conf`（或升级基底 tag）→ 提交 → CI 重出镜像。

第一版两个清单**故意为空**：删掉 48 条重叠规则后覆盖面全靠签名引擎，凭感觉关签名等于把能力关掉。
正确姿势是上线后看一周真实告警，把与保留的 32 条内置规则「同源同窗口双报」的签名逐条关掉，
理由写在 `disable.conf` 里。

## 基底与验证

- 基底：`ARG SURICATA_BASE`（默认 `jasonish/suricata:7.0`，官方社区镜像，内含
  `suricata` 与 `suricata-update`）。升级只改这一行，由 CI 验证。
- **本地禁止构建/拉镜像**（见仓库 `AGENTS.md`）：镜像只在 GitHub Actions 构建；
  配置与规则的加载由 `tests/suricata/run.sh` 在 CI 里用真容器跑 `suricata -T` 验证
  （渲染出的 YAML 是否被这个版本接受、ET Open 是否真的拉下来、是否只开 alert、
  `community-id` 是否打开）。
- 排障：`docker run --rm -v <conf>:/config:ro <镜像> --render-only`
  就等于「渲染 + `suricata -T`」，退出码即结果。
