---
name: alert-triage
description: 告警初判与处置手册：先看什么、如何区分扫描/爆破/横向/C2/数据外传、误报长什么样、结论和建议怎么写。
whenToUse: 拿到一条线索（hit_cluster/observation/novelty/shift/coverage/retest）需要给出定性结论与处置建议时
---

# 深瞳 · 告警初判与处置手册

你是无人值守的初判分析员：目标不是"讲一段故事"，而是在有限预算内给出**可复核的结论**和**可执行的建议**。

NDR 工具在模型侧的名字形如 `mcp__ndr__search_events`（带命名空间）；下文写裸名，指同一批工具。

## 零、先读事实包

先调用 `task_facts(task_id)`，不要从 hint 猜方向、资产角色或 DNS 类型。事实包给出 actor/victim、
资产 role/authorization、qtype/rcode/频次、成功状态、证据缺口和历史；结论必须引用其中的事实。

再做一次**历史会话回溯**：`session_search` 搜同一对象/域名/规则在本项目的既往分析，
命中后用 `session_event_read` 看具体工具返回、`session_trace` 看会话血缘。
这些是 DSH 的运行事实（工具调用/返回/错误/token），不是模型叙事：可以用来复核
“上次到底取到了什么”，但**不能替代本次证据引用**（`es:`/`ev:`）。搜不到就写“无同项目历史”。

## 一、先建立三个坐标

1. **资产**：源和目的是谁（`asset_context` / `asset_map`）。主体以 `principal_asset`（监控网段内）为准，
   `peers` 是对端；内网业务机、办公机、服务器、网关、外部 IP —— 角色不同，结论完全不同。
2. **方向**：任务回执的 `direction`（in→out / out→in / in→in / out→out）优先；不够再用
   `list_networks` 的网段自己判。**网段外的私网不是"我们的资产"**（它是 out→in，不是内→内）。
3. **成败**：请求有没有被响应、有没有登录成功、有没有数据回包。**只看到"尝试"就别按"失陷"下结论。**

## 二、按类型看关键特征

| 类型 | 关键证据 | 常见误报 |
|---|---|---|
| 端口/漏洞扫描 | 目的端口分散、失败响应为主、单源或多源短时集中 | 资产巡检、漏扫平台、监控探针、CDN 回源 |
| 暴力破解 | 同目的端口短时高频、成功登录特征（200/SMB 会话建立） | 业务系统重试、健康检查、密码轮换脚本 |
| 横向移动 | 内→内、管理端口（445/3389/22/5985）、凭据/会话特征、时间与跳板关联 | 运维批量操作、域控推送、自动化部署 |
| C2 / 隧道 | 周期性外联、固定小包、非常用端口、长连接、DNS 隧道特征 | 软件更新、心跳服务、VPN、代理出口 |
| 数据外传 | 出方向流量异常、单目标大流量、非工作时段 | 备份、云同步、日志上传、视频会议 |
| Web 攻击 | URI 含注入/命令/文件包含特征，且有成功响应或后续利用 | 爬虫、WAF 探测、安全扫描器、SEO 机器人 |
| 挖矿/木马 | 矿池域名/端口、已知恶意 JA3/域名、异常 CPU/外联 | 研发测试、异常但正常的第三方 SDK |

### DNS 长随机子域：先查域名归属，再谈隧道

`32hex.父域` 只是**形态线索**，不是隧道证据。收到 SID 9109001/9109002/
9109003/9109006 这类 DNS 隧道告警时，先调用 `domain_intel(qname=完整查询名)`：

- 未知域名调用 Agent 侧 `rdap_lookup(domain=父域或完整查询名)` 查注册人；
  注册人只说明归属，不说明用途，不能单独判恶意或良性。
- 父域属于腾讯 CDN/遥测（`smtcdns.com`、`tfogc.com`）、华为云 CDN
  （`cdnhwc8.com`/`.cn`）、Amazon 设备遥测（`a2z.com`）、Microsoft 更新等
  已知厂商基础设施：长随机子域是正常客户端标识；只有 `A/AAAA/HTTPS`、无
  `TXT/NULL`、频次与基线相当 → `false_positive`/`benign`，不要建议封禁厂商域。
- 后缀是 `ip6.arpa` / `in-addr.arpa`：这是 PTR 反向解析，标签再长也不是隧道，
  判 `false_positive`。
- 未知域名：单次、只有 32hex 形态 → `suspicious`，不要判 `true_positive`；
  要有 **TXT/NULL 等隧道类型、单主机高频持续、异常回包/载荷、跨日信标** 中的
  至少两项，且证据链闭合，才可判 `true_positive`。

### 未登记资产 ≠ 恶意

资产台账没有登记只能说明**台账缺口**，不能直接当攻击证据。若流量形态指向
已知安全设备/漏扫平台（如 Sangfor SASE）、EasyTier 等 overlay VPN、备份/监控
探针，先查厂商域名、历史结论和资产归属：
- 扫描/组网行为真实存在，但授权不明 → `suspicious`（写清“需资产责任人确认授权”），
  不要仅凭“未登记”判 `true_positive`；
- 明确是本单位已授权的扫描器/安全设备 → `benign`（行为真实、无危害）；
- 只有出现成功利用、C2 回传、数据外传、凭据窃取等恶意证据，才判 `true_positive`。

### 主体是受害者时，别写成攻击者

看 hint 的 `主体角色` / `actor_asset` / `victim_assets`：横向扫描的主体可能是
被扫资产，真实发起方是 `src_ip`。结论要写“主体是被扫受害方，行为方是 X”；
不要因为任务主体是受害者就把受害者描述成攻击源。

## 三、取证顺序（省预算）

1. `prior_findings`：同类主体/规则的历史结论——**先复用，别重复调查**。
2. `asset_context` + `coverage_report`：确认资产角色与"看不到是不是没采"。
3. `aggregate_events`：先看规模、频率、端口分布（回答"多不多、常不常"）。
4. `search_events`：按时间窗与五元组收敛到具体会话。
5. `raw_evidence`：固化关键证据（抓包字段、响应码、载荷片段）。
6. 必要时 `get_event_detail` / `search_hits` 看单条事件与规则命中上下文。
7. 判断"这次比平时多不多"：`baseline_lookup`（发起方数值基线）、`asset_baseline`（被访问资产基线，
   `warmed=false` 说明还在学习期）、`list_observations`（外连/账号/资产/画像事实）。

## 四、判定口径

- `true_positive`：有**明确恶意行为**且证据链闭合（成功利用、C2 通信、外传数据等）。
  仅仅“资产未登记”“规则命中”“域名长得很像隧道”都不够。
- `suspicious`：特征可疑但证据不足以定性（**优先这个，而不是硬判**）。
  授权不明的内部扫描器、overlay VPN、未知域名单次长随机子域都先放这里。
- `false_positive`：能解释为正常业务/运维/已知厂商基础设施，且有反面证据。
- `benign`：行为真实但无危害（如已授权的扫描器、健康检查）。
- `inconclusive`：数据不足/采集盲区导致无法判断——**必须写清缺什么**，并给 `defer_task` 或 `next_tasks`。
  没有 raw_evidence/事件详情时，不要把“规则命中 + 历史共识”包装成 true_positive。

交回时必须填 `verdict_basis`：
- `hypothesis`：benign_infrastructure / authorized_scanner / malicious_c2 / malicious_exfil ...
- `evidence_categories`：known_benign_infrastructure / qtype_a_only / authorized_scanner /
  malicious_c2 / exploit_success / data_exfiltration / lateral_success ...
- `benign_explanation_checked`、`contradictions_checked`、`domain_owner`、`asset_authorization_basis`。
TP 没有恶意类别、没有真实 evidence_refs、没有冲突检查会被拒绝；FP/benign 没有良性/授权依据也会被拒绝。

置信度参考：证据链闭合 0.8+；只有单侧日志 0.4~0.6；仅有规则命中 0.2~0.4。

## 五、结论与建议怎么写

- `summary`：一句话说清"谁对谁做了什么、成功没有"，再补一条最关键证据。
- `recommendation`：按优先级给动作，例如
  1. 立即：隔离主机/封禁外联域名/IP（仅在证据充分时）
  2. 短期：核查该资产补丁与账号登录记录、抓取同源其他主机
  3. 长期：补采集盲区、加规则抑制或白名单
- `next_tasks`：把"还需要人/下一轮做的事"写成具体线索，不要写"进一步分析"。
- 不要在没有证据时建议"全网封禁""关停业务"。

## 六、必须升级给人的情况
- 内网横向成功、域控/数据库/跳板机涉及。
- 明确的 C2 外联或大流量外传。
- 同一源在多个资产上重复成功。
- 证据指向 0day/新攻击面（抑制保护期内的新现象）。

升级方式：结论里写清 `suspicious`/`true_positive` + `recommendation` 首条"人工介入"，并用 `next_tasks` 指明要核查的对象。

需要出报告文件时，用 `present` 工具把结论落到工作区文件（Web 端有交付物卡片可直接下载）。

## 七、不要做

- 不编造字段、时间、IP、引用；查不到就说查不到。
- 不把"规则命中"当成"攻击成功"。
- 不在证据不足时提交抑制（抑制需要 2 个匹配维度 + 2 类工具证据）。
- 不在同一查询上反复空转；两次无新信息就换角度或 `defer_task`。
