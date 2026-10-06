# 签名引擎（Suricata）适配镜像

与网络采集器（Zeek）并列的第二个采集/检测组件：**只输出命中规则的事件**（EVE `alert`），
与采集器共用同一份网卡/网段配置，日志走同一条归一化 → 入库 → 检测 → 摘要链路。

```
SPAN 网卡 ─┬─ Zeek ─ conn/http/ssl/… ────────────┐
           └─ Suricata ─ eve.json（仅 alert，带 community_id）─┤
                                Filebeat（两个输入）→ Redis 采集队列
                                → 归一化（normalize_suricata）→ ES + 检测器 → 摘要 → 智能体
```

## 规则从哪来（2026-10 口径）

- **镜像里没有任何内置规则集**：不用 `suricata-update`、不拉 ET Open、**不联网自动更新**；
  引擎自带事件规则（`SURICATA *`、`*-events.rules`）按口径**一律不加载**。
- 镜像只带一个**空占位规则文件** ⇒ 开箱 0 条规则、**不产生任何告警**。
- 真实规则由**项目开发人员维护**：通过界面「检测规则 → 签名规则」配置在线地址
  （manifest：文件列表 + sha256）下发，或直接把 `*.rules` 放进规则卷的 `active/`。
- 规则变更属**检测口径变更**：定时任务（默认每 12 小时）只做「拉 manifest + 下载差异 + 校验」，
  **不自动生效**；界面上校验通过后弹确认，人工点「立即更新」才切换。

## 目录约定（共享卷 `/rules`，后端与容器各写自己的文件）

| 路径 | 谁写 | 说明 |
|---|---|---|
| `active/` | 容器 | 生效中的 `*.rules`（任何时候至少一个文件：空占位或真实规则）+ `manifest.json`（版本） |
| `staging/` | 后端 | 已下载待确认的新版本（完整一套 `*.rules` + `manifest.json`） |
| `previous/` | 容器 | 上一版（回滚用） |
| `rejected/` | 容器 | 最近 5 次校验失败（`*.rules` + `error.txt`） |
| `source.json` | 后端 | 地址/开关/最近检查/待确认版本/最近 10 次历史 |
| `runtime.json` | 容器 | 已加载文件、规则条数、引擎版本、存活（界面「监控网段」页也读它） |
| `validation.json` | 容器 | 最近一次 staging 校验结果（`ok` + 错误摘要） |
| `validate.request` / `activate.request` / `reset.request` | 后端写、容器删 | 请求标记（后端不碰 docker socket） |

**令牌**不落这个卷：存 PG `SystemConfig`（与 MCP 令牌同口径，不回显、不写日志）。

## manifest 格式（界面填它的地址；不以 `.json` 结尾会补 `manifest.json`）

```json
{"version": "2026.10.07-1", "generated_at": "2026-10-07T02:00:00Z",
 "files": [{"name": "shentong-web.rules", "sha256": "<64位hex>", "size": 12345}]}
```

校验（任一不过整批拒绝，绝不半套生效）：`version` 必填；`name` 必须匹配
`^[A-Za-z0-9._-]+\.rules$`（防路径穿越）；文件 ≤ 64 个、单文件 ≤ 8 MiB、合计 ≤ 32 MiB；
`sha256` 必填且下载后逐个比对；文件默认与 manifest 同级，可用 `url` 覆盖但**必须同源**。
示例见 `manifest.example.json`。

## 规则编写约定（给开发人员）

- SID 段 **1000000-1999999**（上游 ET 用 2xxxxxx，不撞车）；每行一条规则；UTF-8。
- 必填 `msg` / `sid` / `rev`；必须给 `classtype:` 或 `priority: 1|2|3`
  —— 它决定 EVE `alert.severity`，也就是我们摘要「高危/中危/低危」三档的来源。
- 可用变量：`$HOME_NET` / `$EXTERNAL_NET` / `$HTTP_PORTS`（模板已定义，HTTP_PORTS 已按
  共享配置里的 `tls_ports` 剔除）。
- 不要写 `SURICATA *` 引擎事件名（本项目不加载引擎事件规则）。
- 文件头写用途/维护人/生成时间，便于排查。

## 配置：只认共享文件

`entrypoint.sh` 读 `/config/interface.conf`（与网络采集器**同一份**，界面「监控网段」页维护）：

| 共享配置项 | 本容器的用法 |
|---|---|
| `interface` | `af-packet` 抓包网卡（缺省自动取第一块物理网卡；可用 `SURICATA_IFACE` 覆盖） |
| `monitored_nets` | `HOME_NET`（`EXTERNAL_NET: !$HOME_NET`）；为空时回落通用私网段并告警 |
| `tls_ports` | 从明文 HTTP 端口集里**剔除**这些端口（口径与 Zeek 侧一致：引擎默认端口集 − 运维声明） |

配置或规则变化由容器内看门狗（默认 10s）检测 → 重渲染 + `suricatasc -c reload-rules`
（不可用则重启 Suricata，由守护循环重拉）。

## 输出

- `eve.json` 只开 `alert`，并带 `community_id`（Zeek 的 `conn.log` 也带同值 →
  两个采集器对**同一条流**的事实能对上）。
- 写 `raw` 前去掉 `packet`/`payload` 两个大字段；**不映射字节数**（体积类规则只认 Zeek 的 conn）。
- 归一化后：`event_type=signature_hit`、`log_type=suricata`、`source_system=suricata`，
  签名名/SID/类别/severity 进独立字段。
- eve.json 按天/按 64MB 轮转进 `archive/`（留 3 天）。

## 排障

```sh
# 渲染配置 + suricata -T 自检（退出码即结果）
docker run --rm -v <config>:/config:ro -v <rules>:/rules <镜像> --render-only
# 只渲染并打印（不做昂贵的 -T）
docker run --rm -v <config>:/config:ro -v <rules>:/rules --entrypoint sh <镜像> \
  -c '/usr/local/bin/shentong-suricata-entrypoint.sh --render-config'
# 手动跑一次 staging 校验 / 处理一次请求标记（CI 也这么用）
docker run --rm ... <镜像> --validate-staging <版本>
docker run --rm ... <镜像> --handle-requests
```

> ⚠️ 本镜像的 ENTRYPOINT 就是入口脚本 —— 进容器敲 shell 必须写 `--entrypoint sh`，
> 否则参数会被当成脚本参数、掉进抓包主循环不退出（CI 踩过一次）。

**一个必须知道的坑**：基础镜像把 `/var/lib/suricata` 与 `/etc/suricata` 声明成了 `VOLUME`，
Docker 的**匿名卷在容器重建时被保留** ⇒ 升级镜像后容器里可能还是上一版文件。
本适配的规则与配置都放在我们自己的 `/rules` 卷 + 每次启动重新渲染的 `/etc/suricata/suricata.yaml`，
不受该坑影响（历史的 ET 规则死在这一点上，见 `docs/ndr-redesign.md`）。

## 验证

- CI：`tests/suricata/run.sh` 在真容器里验证 ① 空占位 0 条规则可启动 ② 开发人员写的样例规则
  能加载 ③ 渲染只引用 `active/`、不含 `*-events.rules` ④ staging 校验与 activate 切换协议跑通
  ⑤ 清空规则回到空占位。
- 服务器：配置一个 manifest 地址 → 「立即检查更新」→ 校验通过 → 人工确认 → 规则条数与告警生效。
