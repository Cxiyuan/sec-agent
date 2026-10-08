# NDR 内置规则评审（A/E/F/G 组，13 条）

范围：`ndr/backend/app/rules/builtin.py` 第 35–78 行（3 条）、1094–1146 行（3 条）、1147–1226 行（4 条）、1227–1260 行（3 条）。文件内容按当前工作区读取（未做 diff/提交范围对比，未运行测试）。

先说三条贯穿全组的引擎事实（后面反复引用）：

- **抑制/容量**：`config.py:71-76` 内网常规跳过要求"规则名在 `policy_skip_rules`（默认只有「内置-扫描尝试连接」「内置-恶意文件传输」）+ 内→内 + 严重度 < medium + 目标 ≤1 + 无成功连接"——本组 13 条**没有一条**能被跳过。`config.py:170` 投递限流 24 摘要/分钟、`:177` 摘要 30 分钟超龄丢弃。

## 本组小结

| 规则（builtin.py:行号） | 结论 | 一句话 |
|---|---|---|
| 内置-勒索/僵尸网络域名 (35) | 需修 | 短词无边界子串（`conti`/`beacon`）在 critical 级放大误报，同时抓不到真实 C2 |
| 内置-挖矿域名/矿池 (52) | 需修 | `xmr` 三字符子串过宽；`stratum+tcp` 在 DNS 上物理不可能出现（该分支无效） |
| 内置-横向移动高频连接 (1096) | 需修 | 无方向限定；10 次/5 分钟对 SMB/RDP 正常会话过松；priority 对频率规则无意义 |
| 内置-横向移动多目标 (1116) | 需修 | 无方向；与「大面积目标探测」「内网慢速横向」同一行为产多份摘要；端口集与 (1134) 不一致 |
| 内置-横向移动管理端口 (1134) | 需修（最严重） | 无方向/无白名单的"全量 SMB·RDP·NFS 命中"，挤占投递预算并遮蔽 3389 的低危规则 |
| 内置-异常外联端口 (1149) | 需修 | 无方向 → 内网服务监听 5555/9001 时入向连接也报"疑似 C2"；缺 50050/1080 等常见 C2 默认口；p20 平级顺序不确定 |
| 内置-DNS隧道可疑长查询 (1180) | 需修 | 只看长度+字符集、不排除 PTR/ACME/NSEC3 长合法名 → high 级误报；<60 字符分块隧道漏 |
| 内置-DNS-TXT隧道 (1194) | 逻辑不成立（疑似死规则） | key 含 `query` 要求同一名字重复 10 次，与"TXT 隧道"语义相反，真隧道永不触发 |
| 内置-大流量外传 (1229) | 需修 | 无 `dst_external`；10MB 阈值过低；`bytes_out` 为空时静默不命中；无按源求和 → 慢速外传漏 |
| 内置-超大流量外传 (1240) | 需修 | 同上（方向/白名单）；100MB 阈值本身合理 |
| 内置-大规模数据下载 (1251) | 需修 | 无方向，`bytes_in=resp_bytes`，外→内连接时其实是出站外传却叫"下载"；正常更新/媒体/备份 FP |

**总体结论：OK with notes**——引擎语义、字段填充、路由口径没有发现代码缺陷；问题全部在**规则内容**（阈值、方向限定、字段选择、正则边界）。就"这套规则能不能直接上线"而言：**BLOCK**（3 条结构性漏报 + 1 条噪音炸弹）。另：这些规则在 `agent/backend/app/rules/builtin.py` 有一份逐字节相同的副本（已核对 1206/1222/1258 行），修一处必须同步另一处，否则两侧漂移。

---

### 内置-勒索/僵尸网络域名（builtin.py:35，priority=5，severity=critical）
- 逻辑问题：`logic: and` 单条件，等价于该条件，**OK**。但"关键字命中域名 = critical 勒索/C2"这个判据本身价值低：真实 C2 用 DGA/正常域名，关键字型规则主要命中"研究/测试/误撞"。
- 漏报：指标集不含常见家族/工具名（`sliver`、`havoc`、`mythic`、`asyncrat`、`remcos`、`cobalt`、`empire`、`metasploit`）；且**TLS SNI 完全没有覆盖**：`hostname`（`normalize_zeek` 里来自 `doc["host"] or doc["server_name"]`）上有域名，但本规则只查 `query`，路由后 ssl/conn 日志根本不评估。硬编码 IP + DoH 的无 DNS 场景直接漏。
- 置信度：高（正则无边界、字段与路由、http 下 `query` 是路径这三点都由代码直接可证；`continental`/`beacon.gif` 为示意性 FP 例子）。附带一条：`priority=5` 与「内置-挖矿域名/矿池」(line 55) 同为 5，而 `rules/service.py:15` 只有 `order_by(Rule.priority)` 无第二排序键，`runner.py:699` 又是 `next(...)` 取首个命中 → 同一事件两条都命中时"报哪条"取决于 DB 返回顺序（不确定）。

### 内置-挖矿域名/矿池（builtin.py:52，priority=5，severity=high）
- 误报：任何含 `xmr` 子串的域名/路径（示意：`xmradio.com`、`/xmr/report`、主机名 `xmr-node`）；`monero` 命中科普/交易所页面路径；`coin-hive`/`2miners` 类词出现在安全博客/搜索结果 URL → high。同样是 critical/high 级无白名单。
- 漏报：常见矿池/协议未覆盖（`pool.minexmr`已有、缺 `nanopool.org` 之外的 `ethermine`、`nicehash`、`hashvault`、`herominers`、`kryptex`、`unmineable`、`c3pool`；协议 `stratum+tcp/ssl`、`getwork`、`ethproxy` 等）。挖矿流量多为长连接 TLS，真正可分的是"到矿池 IP/域的会话"，本规则只查名字字段。
- 修复建议：`xmr` 改为带边界的标签匹配 `(?i)(^|[._-])(xmr|xmr-?[a-z]*pool|moneroocean|nanopool|minexmr|2miners|f2pool|nicehash|ethermine|c3pool|herominers|hashvault|unmineable)([._-]|$)`；协议特征移出 DNS 语义、放到 `query_string`/`body` 独立规则；补 `stratum\+(tcp|ssl)`、`getwork`、`ethproxy`；加"内部资产/自有域"白名单。severity high 保留合理。
- 置信度：高（`+` 在 DNS 名不可能出现、子串匹配语义由引擎代码决定）；矿池补充清单为中（按公开默认域名，未在本仓库验证）。


### 内置-横向移动高频连接（builtin.py:1096，priority=22，severity=high）
- 条件：`line 1102-1104` `mode=count`、`key=["src_ip","dst_ip"]`、`min_count=10`；`line 1110` 条件 `dst_port in [445,139,135,3389,5985,5986,512,513,514]`。窗口取默认 `config.py:186 freq_window_seconds=300`，冷却 `config.py:187 = 300`。
- 逻辑问题：**没有方向限定**（没有 `src_internal/dst_internal`，对比 `builtin.py:1468-1469` 的「内网慢速横向」是有的）→ 外网→内网对单台主机的重复连接（445/3389）会被命名成"横向移动"。另外 `priority` 对频率规则**完全无效**：`runner.py:709-712` 遍历全部 count 规则且不 break，`priority=22` 不产生任何优先级效果（该字段对 count 规则是装饰）。
- 误报：同一 (源,目标) 在 5 分钟内 445/3389 上 10 条 conn 记录是 Windows 常态（SMB 会话重建、多 TCP 连接、DFS/打印重连、RDP 多路复用、扫描探活）；`dst_port` 属通用字段 → 该规则对每种 log_type 都在评估。且它无白名单，`policy_skip_rules` 不含它、severity=high ≥ medium → `internal_routine_reason` 必然返回 None，**无法被抑制**。
- 漏报：阈值 10/5min 只抓"爆量"；攻击者每目标 3–5 次、跨 6 小时铺开就绕开（「内网慢速横向」窗口 6h/5 目标只覆盖多目标形态，不覆盖单目标慢速）。端口集含 512-514 而 (1116) 不含 → 同一战术两条规则口径不一致。
- 修复建议：加 `{"field":"src_internal","op":"eq","value":true}` + `dst_internal eq true`（或至少 `dst_internal`），并把 `min_count` 提到 20–30、端口集与 (1116) 统一；给"已知管理服务器/备份服务器"加白名单；把 512-514 这类 legacy 口单列。
- 置信度：高（方向缺失、count 规则不受 priority 影响、SMB 记录数特性均可由代码/协议常识支持；"10 条属正常"为经验判断，标中高）。

### 内置-横向移动多目标（builtin.py:1116，priority=18，severity=high）
- 条件：`line 1122-1126` `mode=count`、`key=["src_ip"]`、`min_count=8`、`distinct="dst_ip"`、`min_distinct=8`；`line 1129` 端口 `[445,139,135,3389,5985,5986]`。窗口默认 300s。
- 逻辑问题：**无方向限定**（外网扫描 8 台内网主机的 445 也被叫"横向扩散"）；`min_count=8` 在 `min_distinct=8` 下必然满足（8 个不同目标至少 8 条事件）→ `min_count` 冗余，实际判据只有"8 个目标/5 分钟"；端口集与 (1134) 的 `[445,139,135,3389,5985,5986,2049]`、与 (1096) 的 `[…,512,513,514]` **三套不一致**。
- 误报：管理/运维面天然是"一台源碰 8 台以上目标、走 445/135"——补丁分发/资产盘点（WSUS/SCCM/Ansible/PDQ）、AD 域控复制（135/445 跨多台 DC）、备份（Veeam/rsync/robocopy 多主机）、杀软/EDR 管理端下发、授权漏扫。5 分钟 8 目标是很容易达到的量级，且在 high 级别无人抑制（同前：名字不在 `policy_skip_rules`、severity ≥ medium）。
- 漏报：只统计 6 个端口 → 跨 SQL(1433)/NFS(2049)/VNC(5900)/SSH(22)/WinRM 其他口的横向不计；8 目标/5 分钟的硬窄窗，攻击者每 5 分钟只碰 7 台即绕开（「内网慢速横向」6h/5 目标可部分兜住，但那条也只看任意端口、无端口语义）。
- 重复/遮蔽：与「内置-内网慢速横向」(1454)、「内置-大面积目标探测」(781) 语义重叠；因为 count 规则全跑、互不遮蔽，**同一段行为会产出 2–3 份不同严重度的摘要**（去重只能靠上层）。
- 修复建议：加 `src_internal/dst_internal` 双内网；端口集与 (1134) 合并为一个常量集合；`min_distinct` 提到 15–20 并把窗口明确写成 `"window": 300`；与管理/备份服务器白名单联动；与「内网慢速横向」「大面积目标探测」明确分工（短窗高并发 vs 长窗低慢小），避免三份告警。
- 置信度：高（条件结构、字段、去重逻辑均代码可证；误报场景为运维常识，标高）。

### 内置-横向移动管理端口（builtin.py:1134，priority=30，severity=medium）
- 条件：`line 1142` `dst_port in [445,139,135,3389,5985,5986,2049]` + `line 1143` `event_type ne "scan_attempt"`；无白名单、无方向、无频次门槛。`scan_attempt` 由 `conn_states.py:42`（conn_state S0）产生，所以该条只排除"连不上的 SYN"，**握手成功的 SMB/RDP/NFS 一律命中**。
- 逻辑问题：这是本组最严重的结构问题——**逐条规则、只按端口命中**，等于"每次正常文件共享/RDP/NFS 访问都生成 medium 摘要"。端口集是通用字段 → 通配集合，所有 log_type 上评估；没有任何"是否内网、是否成功、是否多次"的限定。
- 误报（量级问题）：企业里 445/3389/2049 的合法会话是海量噪声源。按 `runner.py` 的聚合键（源 IP + 规则）虽能按源合并，但每个源仍会产出一条摘要，而投递受 `config.py:170` 24 条/分钟限流、超龄摘要 `config.py:177` 30 分钟后被丢 → **这条规则的噪声会把高价值摘要挤出投递窗口/挤到过期**（这是本次评审最该先修的点）。抑制也救不了：`policy_skip_rules`（`config.py:73`）不含它，`policy_internal_routine_min_severity=medium`（`config.py:74`）要求"严重度 < medium"才可能跳 → 恰好卡在门槛上，必不跳。
- 漏报/遮蔽（互相遮蔽的反向问题）：**端口 3389 同时出现在 (1134) 的 medium 列表和「内置-常见敏感端口访问」(1449, low, p40, 列表含 3389)**；两条都是通用字段 → 都在 wild 集合，候选顺序按 priority 升序（`service.py:15`），`runner.py:699` 首个命中即停 → dst_port=3389 永远命中 (1134)，**low 的「常见敏感端口访问」在 3389 上永不触发**（该规则实际只剩 22/23/3306/5432/6379/27017 生效）。这是"设计取舍"（高的覆盖低的），但代价是端口覆盖清单说谎，运维按规则名排查会漏。
- 误报（方向语义）：无方向 → 外网→内网成功连到 3389/445（暴露的 RDP/SMB 被访问）也被写成"横向移动"，而实际是"暴露面/外部访问"，方向结论是错的（应为 out→in）。
- 修复建议：① 加 `dst_internal eq true`（内网管理面确实存在才叫横向移动），外→内单独一条"公网访问管理端口"并给更高严重度；② 加频次限定（改成 count 规则：同源 ≤ 5 分钟命中 ≥ N 次或 ≥ N 个目标）或把 `event_type` 限定为 `conn_established` 之外的"非首次/重复"形态；③ 给已知文件服务器/备份/NFS/vCenter/管理网段加白名单；④ 把 2049/3389 的分工写清楚，避免与 (1449) 重叠；⑤ 至少把 severity 降到 low 或把它从"逐条告警"改为"摘要打标不投递"。
- 置信度：高（字段、路由、抑制条件、优先级遮蔽链都可从代码逐行验证；噪声量级判断基于端口语义，标高）。

### 内置-异常外联端口（builtin.py:1149，priority=20，severity=high）
- 条件：`line 1160-1174` `dst_port in [4444,4445,5555,6666,6667,7777,9001,9050,1337,31337,12345,54321]` + `line 1175` `event_type ne scan_attempt`；无白名单、无方向。
- 逻辑问题：**"外联"没有方向约束**。规则只看 `dst_port`，于是"内网服务监听 5555/9001，外部客户端连进来"同样命中，命名与语义相反（应为 inbound）。另外 `priority=20` 与「内置-端口扫描」(800, p20)、「内置-开放重定向探测」(397, p20) 等多条平级，`service.py:15` 无第二排序键 → 同一事件若同时命中平级规则，报哪条不确定（严重度会跳变）。
- 误报：5555（Android ADB over TCP、大量 Java/Node 调试与厂商设备），9001（Tor ORPort、部分面板/网关默认口），6667（IRC/IRC 网桥，若组织内自建 Mattermost/IRC 网关），12345/54321（若干运维/游戏/中间件默认口） → 内网入向连接被判"疑似 C2/后门" high。`event_type ne scan_attempt` 只排除 S0，握手成功的扫描流量仍全量命中 high。
- 漏报：常见 C2/后门默认口未覆盖——Cobalt Strike 团队服务器默认 **50050**、SOCKS/代理 **1080**、常见备用 8443/4443、Havoc 40056、部分远控 5552/5683 等（按公开默认端口，标中）。真正的 C2 走 80/443/8443 时本规则天然无感（设计限制，需 JA3/域名单补）。
- 修复建议：加 `dst_external eq true`（保留"外联"原义），外→内方向另立规则；对 5555/9001/54321 这类"双用途"端口要求"外网目标 + 非白名单服务"；补 50050/1080/4443/8443 到列表并把白名单（如内网代理、VPN 出口）配到位；`event_type` 条件建议扩成 `not in ["scan_attempt","port_scan"]` 以避免与扫描类规则互相抢标签。
- 置信度：高（方向缺失、路由、平级不确定性均可证；具体端口的"正常用途"标中）。

### 内置-DNS隧道可疑长查询（builtin.py:1180，priority=20，severity=high）
- 条件：`line 1188` `log_type eq "dns"`（显式 → 只挂 dns，路由**正确**）+ `line 1189` `query` regex `^[A-Za-z0-9_.-]{60,}$`。`re.search` + `^...$` ⇒ 等价全字符串匹配，且字符集覆盖大小写/`_`/`-`/`.`（Zeek 域名字符）→ 匹配机制本身是合理的。
- 逻辑问题：判据只有"长度 ≥ 60 + 字符集"，**没有任何 qtype/rcode/answers/频率判定** → 把所有"长而合法"的 DNS 名一并收进来；也不区分"外部权威解析"与"内网 PTR"。`query` 在 `_DECODE_FIELDS` 里（会额外匹配 unquote 变体，对本规则无害）。
- 误报（真实场景，长度可算）：① **ACME DNS-01 挑战**：`_acme-challenge`(15) + `.` + base64url token(43) + `.` + 区域名 ⇒ ≈ 70+ 字符、字符集完全在允许集内 → certbot/acme.sh/cert-manager/lego 的正常验证查询被判 high；② **IPv6 反向解析**：`<32 个 nibble 点分>.ip6.arpa` = 63+9=72 字符 → 内网做 IPv6 PTR 就报 high（qtype=PTR=12 未排除）；③ DNSSEC 场景下的 NSEC3 owner（32 字符 base32 hash + 区域）在多层区域下常超 60；④ 长 DKIM selector（`selector1-<长串>._domainkey.<多层区>`）、部分 CDN/遥测长 FQDN（长哈希子域）也在阈值之上。这些都在 high 级、无白名单、无法被 triage 跳过。
- 漏报：真正隧道只要把每段名字控制在 60 以下就完全绕过（iodine/dnscat2 可配 label 长度、可拆分）；只用长度无法识别"短标签高频 + 高熵"型隧道；DoH/DoT 隧道不经 dns.log（设计限制）。
- 修复建议：① 加 `{"field":"qtype","op":"ne","value":"12"}`（或 `qtype in ["1","28","16","5","255"]`）先干掉 PTR 大类噪声；② 加白名单：`query contains "_acme-challenge"`、`query contains "ip6.arpa"`、`query regex "(?i)_domainkey"`；③ 阈值改为"≥ 52 字符 **且** ≥ 3 个标签 **且** 最长标签 ≥ 30"这类组合（或对子域标签做熵/基数判定），把 DGA 与真隧道区分开；④ 新增"同源不同名字数"频率规则（补 (1194) 的缺陷，见下）：`key=["src_ip"], distinct="query", min_distinct>=50, window=300`（阈值需按环境标定）。本规则语义与字段选得对，**修的方向是收窄 FP + 组合条件，而不是换字段**。
- 置信度：高（正则语义、字段、路由代码可证，长度算式可复核）；FP 场景标本仓库无样本，标"高（代码层）/中（场景量）"。

### 内置-DNS-TXT隧道（builtin.py:1194，priority=20，severity=high）
- 条件：`line 1200-1202` `mode=count`、`key=["src_ip","query"]`、`min_count=10`（无 `window` → 默认 300s）；`line 1205` `log_type eq "dns"`；`line 1206` `qtype in ["16"]`。
- 逻辑问题（核心）：**key 里含 `query`，等于"同一个 TXT 名字 5 分钟内被查 ≥10 次"**。而 TXT 隧道的特征是"每个包一个不同名字"（数据编码在名字里），**名字几乎不会重复 10 次** → 这条规则按定义抓不到隧道，与描述"DNS TXT 记录高频查询（隧道特征）"不符。真正常见的"同一 TXT 名高频"是客户端不做缓存/轮询的场景，属误解而非隧道。另外对 count 规则而言 `log_type` 条件不参与路由（count 规则全跑，`runner.py:709`），它只作判定条件，写法无误但容易被误读为"只跑 dns"。
- 误报：同一主机对同一 TXT 名 10 次/5 分钟的现实来源——ACME DNS-01 传播轮询（cert-manager/lego 会连续多轮解析验证记录）、Consul/服务发现的 `*.service.consul` TXT 轮询、邮件网关的 DNSBL/SPF/DKIM TXT 重试、监控探针、容器重启循环导致的无缓存重复解析。冷却 `config.py:187=300s` 会把同一 (源,名) 的重复压成每 5 分钟一次，噪声量可接受，但一旦命中就是 high。
- 漏报：① 真隧道（名字每次不同）永不触发（见上）；② `qtype` 只接受字符串 `"16"`，而 `normalizer.py:548` 明确会在上游没给数字码时**回落到 `qtype_name`**（值会是 `"TXT"`）→ 那种管线上这条规则静默恒假（字段非空但值不匹配）；③ 无 `qtype=255`(ANY)/`qtype=16` 以外的 TXT 变体；④ DoT/DoH 不可见。
- 修复建议：① 改成以"源 + 目标解析器"为键、以"不同名字数"为判据：`{"mode":"count","key":["src_ip"],"distinct":"query","min_count":30,"min_distinct":30,"window":300, "rules":[{"field":"log_type","op":"eq","value":"dns"},{"field":"qtype","op":"in","value":["16","TXT","txt"]}]}`（阈值需按环境标定）；② `qtype` 列表补齐 `"TXT"` 兼容回落路径；③ 若保留"同名重复"语义，把规则名/描述改成"同一 TXT 名高频轮询"以免误导 SOC。
- 置信度：高（key 语义、qtype 存储口径、路由行为均可从 `frequency.py`/`normalizer.py`/`runner.py` 直接验证）。

### 内置-可疑域名（动态DNS/短域名）（builtin.py:1211，priority=25，severity=medium）
- 逻辑问题：
  1. **名不符实**：规则名/描述包含"短域名"，但正则里**没有任何长度判定**（无 `{1,4}` 之类）→ 运维以为短域名被覆盖，实际完全不覆盖（漏报源，且是文档级误导）。
  3. `dyn(dns)?\.`、`no-ip\.`、`pastebin\.`、`transfer\.sh` 全是**无边界子串**（`re.search`）：`dyn.` 命中静态资源路径 `/dyn.js`、`/cdn/dyn.css`；`transfer.sh` 命中 `transfer.shtml`/`transfer.shared`（`.shtml` 是常见的旧式后缀）；`pastebin.` 命中任何含该词的分享/代理路径。`\.onion` 基本只在测试/情报场景出现，价值低。
- 误报：内网自建区域里带 `dyn` 标签（`dyn.corp.local`）也命中；`.xyz/.top/.pw` 上有大量正常站点（TLD 滥用比例高但合法使用确实存在）→ medium 级噪声无白名单、且 `policy_skip_rules`/`policy_internal_routine_min_severity=medium` 组合使它在"内→内 + medium"时也**不会被跳过**（门槛要求 < medium）。
- 漏报：主流 DDNS 大面积缺失——`duckdns.org`、`ddns.net`、`noip.com`（只有 `no-ip.` 命中，`noip.com` 不中）、`hopto.org`、`sytes.net`、`zapto.org`、`myftp.org`、`3utilities.com`、`freedns.afraid.org`、`dynu.com`、`changeip.com`、`myonlineportal.net`；且 `.top/.xyz` 之外的高滥用 TLD（`.cc`、`.click`、`.gq`、`.cf`、`.ml`、`.work`、`.cam`）未覆盖。
- 置信度：高（锚点语义、`query` 在不同 log_type 的取值、子串匹配边界均由代码决定）；DDNS 清单为中。

### 内置-大流量外传（builtin.py:1229，priority=25，severity=medium）
- 条件：`line 1236` `bytes_out gt 10485760`（10MB）；路由 `bytes_out → conn`（只跑 conn，正确）；无白名单、无方向。`bytes_out = orig_bytes`（`normalizer.py:674`，"源→目的"）。
- 逻辑问题：字段名是方向相对的（`schemas.py:60` 注释也只说"源→目的"，不含内外网），规则名却写"外传"→ **缺少 `dst_external eq true`**。当发起方是外部主机（外→内的上传、外部备份对端）时 `orig_bytes` 是**入站**字节，被记成"外传"。阈值 10MB 对现代网络**过低**：单个 TCP 连接的 10MB 在内网备份、镜像分发、媒体、上传类业务里是日常量级；也没有按（源,目的）时间窗**求和**的判据（`frequency.py` 只做 ZSET 计数/基数，全仓无字节求和），所以调高阈值只能牺牲灵敏度。
- 误报（具体场景）：内网到文件服务器/备份（Veeam、robocopy、rsync、rclone）、WSUS/SCCM 补丁分发（源=内网服务器，`orig_bytes` 天然几十~几百 MB）、VM/容器镜像复制、监控视频上传（NVR→存储）、`docker push`、数据库复制、HTTP POST 上传 >10MB。medium 级、无白名单、名字不在 `policy_skip_rules`、severity ≥ medium → 无法被内网常规策略跳过，直接进入摘要投递（受 24/分钟限流）。
- 漏报：① Zeek 的 `orig_bytes` 常为 `-`（未知）→ `_to_int("-")` 得 `None` → `gt` 分支 `float(None)` 抛异常被吞，返回 **False**（`engine._match` 的数值分支），这类连接**静默不命中**；② **分片/慢速外传完全漏**：1GB 拆成 1000 个 5MB 连接，任何规则都不会看到总量（没有"按源字节求和"的规则类型）；③ 压缩/加密后总量达标但单连接不达标同样漏。
- 修复建议：① 加 `{"field":"dst_external","op":"eq","value":true}`（"外传"名副其实）；② 阈值提到 50–100MB 或改成"按 (src_ip,dst_ip) 5 分钟求和 > N MB"（需要给频率引擎加 sum 能力，或新写一条聚合规则）；③ 对"备份/更新/媒体"服务器和网段配白名单（`whitelist` 支持 `src_ip in [...]`，见引擎 `whitelisted`）；④ 若保留 10MB，就把 severity 降到 low 并只做打标不投递。
- 置信度：高（字段来源、路由、数值比较对 None 的失败路径均由代码直接可证；FP 场景属运维常识，标高）。

### 内置-超大流量外传（builtin.py:1240，priority=15，severity=high）
- 条件：`line 1247` `bytes_out gt 104857600`（100MB）；路由 conn；无方向、无白名单。
- 逻辑问题：与 (1229) 同一结构问题（缺 `dst_external`），只是阈值更高。100MB **单连接**阈值本身在本组里是最合理的一个（外传 100MB 确实异常），问题全部在方向与抑制缺位。优先级 15 < (1229) 的 25 → 同一连接两条都命中时由 p15 先命中（`runner.py:699` 首个命中即停，候选按 priority 升序），**遮蔽行为是符合预期的**（高严重度覆盖低严重度），不是 bug。
- 误报：内→内的大文件搬运（备份镜像、存储复制、p2p 内部分发、大数据 shuffle）在 high 级报警；外→内方向的"客户上传/对端回传"也被叫"外传"。这在高危级别意味着每条都可能触发深度分析（`escalate_require_rule_severity=low` 之上），成本高。
- 漏报：与 (1229) 相同——`orig_bytes` 缺失时静默不命中；慢速/分片外传无一规则覆盖；此外没有任何"外传到高风险国家/新目标"的辅助条件来降低 FP。
- 修复建议：`dst_external eq true` + 白名单（备份/存储网段）+ 视环境把阈值调到 200–500MB；配合 (1229) 的"按源求和时间窗"规则一起上，才能同时压 FP 与补 FN。
- 置信度：高（同 (1229)）。

### 内置-大规模数据下载（builtin.py:1251，priority=20，severity=high）
- 条件：`line 1258` `bytes_in gt 104857600`；路由 `bytes_in → conn`；无方向、无白名单。`bytes_in = resp_bytes or response_body_len`（`normalizer.py:561`，位于共用的 `_http_fields`，对 conn 日志即 `resp_bytes`），`schemas.py:61` 注释为"目的→源字节数（数据窃取）"。
- 逻辑问题：**方向语义倒置**。`resp_bytes` 是"响应方→发起方"字节数，与"谁在内网"无关：当发起方是**外部主机**、响应方是**内网服务器**时，`resp_bytes` 就是"内网→外网"的**出站外传**，却被命名为"下载"。名字说"下载"、字段说"窃取"，两者方向相反，只有描述句尾"疑似数据窃取"勉强对上服务器被窃取的场景 → 命名与告警结论会误导分析师（要么改名"单连接大流量（双向）"，要么加方向）。
- 误报：内网服务对外/对内提供 >100MB 单连接是常见业务——Windows Update 客户端拉大更新包/ESD、内网软件/镜像仓库分发、模型与工件下载（ML 权重、Jupyter、Harbor）、媒体/录播文件下载、大文件共享（SMB/NFS 读）、iSCSI/备份读取流。high 级、无白名单、不可被内网常规策略跳过。
- 漏报：① `resp_bytes` 为 `-`/缺失 → 数值比较失败返回 False，静默不命中；② 分段下载（浏览器/下载器的 Range 分片、CDN 分块）每连接 <100MB 就完全绕开；③ **完全不覆盖上传方向的大流量**（那是 (1240)/(1229) 的职责，但三条都缺方向 → 三者组合起来是"有阈值、无方向、无总量"，语义最乱）。
- 修复建议：① 明确方向：`{"field":"dst_internal","op":"eq","value":true}`（发起方外、目标是内才算"从外部下载"）或反向外传场景拆成独立规则；② 改名以匹配字段语义，避免"下载/窃取"混用；③ 与 (1229)/(1240) 合并为一条"按方向 + 阈值"的参数化规则族，减少三份重复维护；④ 白名单（更新源、镜像仓库、备份网段）+ 或改为按 (src,dst) 窗口求和。
- 置信度：高（字段来源与注释、路由、数值比较失败路径均可证；业务量级判断标高）。

---

## 本组 Top 3 问题

1. **P1｜内置-横向移动管理端口 (1134)：无方向、无白名单的端口全能命中，挤占 24 摘要/分钟的投递额度并把高价值摘要挤到 30 分钟超龄丢弃**（`config.py:170,177`；抑制条件 `config.py:73-75` 对 medium 恰好失效）。附带遮蔽：dst_port=3389 时永远命中它，low 的「常见敏感端口访问」(1449, p40) 永不触发（`runner.py:699` 首个命中即停 + `service.py:15` 按 priority 排序）。修：加 `dst_internal` + 频次门槛 + 白名单，或降为打标不投递。
2. **P1｜内置-DNS-TXT隧道 (1194)：判据（`key` 含 `query`、`min_count=10`）与"TXT 隧道"语义相反，真隧道永不触发；`qtype in ["16"]` 又与 `normalizer.py:548` 的 `qtype_name` 回落路径不兼容（静默恒假）**。修：改为按源统计 **不同** query 数（`distinct:"query"`）、`qtype in ["16","TXT"]`。
3. **P1｜数据外传三兄弟 (1229/1240/1251)：全部缺 `dst_external/dst_internal` 方向限定，且全仓没有任何"按源字节求和"的规则类型（`frequency.py` 只计数/基数）→ 内网备份·更新分发·媒体造成大量 high/medium FP，同时 1GB 分片慢速外传结构性漏报；`bytes_*` 为 `-` 时数值比较静默返回 False 再漏一层**（`engine._match` 数值分支 + `normalizer.py:561,674`）。修：加方向谓词 + 白名单，并新增按 (src,dst) 窗口的字节求和规则。


## 证据与复核说明

- 未做（限制）：没有运行测试（本环境不执行构建/测试；建议由主管跑 `pytest tests/py/test_rules_routing.py tests/py/test_conn_states.py`），没有做提交范围 diff 对比（本次评审按当前工作区文件内容进行），未在生产数据上验证 FP 率（所有 FP 场景为可推证的构造/经验例子，已逐条标注置信度）。

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "输出了 13 条规则逐条结论（本组小结 + 逐条：逻辑/误报/漏报/修复/置信度）+ 本组 Top 3，每条结论引用具体字段、正则、阈值与文件行号（如 builtin.py:46/63/76/1104/1142/1189/1206/1222/1236/1247/1258，normalizer.py:548/561/674，runner.py:699/709-712，service.py:15，config.py:73-75/170/177/186-187，conn_states.py:42，schemas.py:60-61），并附未做事项与残余风险。"
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [],
  "validationOutput": [
    "静态代码评审，未执行任何命令；未运行测试。建议主管执行：pytest tests/py/test_rules_routing.py tests/py/test_conn_states.py"
  ],
  "residualRisks": [
    "FP/FN 场景为基于代码语义的构造与经验例子，未在真实流量上量化误报率（例如 SMB/RDP 正常会话量、内网备份大流量占比）。",
    "未运行测试，也未做提交范围 diff 对比；结论基于当前工作区 builtin.py 等文件内容。",
    "agent/backend/app/rules/builtin.py 是逐字节相同的副本，本报告只给出修复建议未同步两侧，需修复时同时改动否则两栈规则漂移。",
    "C2/矿池默认端口与 DDNS 域名清单（50050/1080、duckdns.org/ddns.net/noip.com 等）按公开资料列举，未在本仓库验证。",
    "频率规则阈值（min_count/min_distinct/window）是否与本环境流量规模匹配需以线上统计标定，报告未给最终数值。"
  ],
  "noStagedFiles": true,
  "diffSummary": "只读评审，无改动。",
  "reviewFindings": [
    "blocker: builtin.py:1134 - 内置-横向移动管理端口 无方向/无白名单的逐条端口命中（445/139/135/3389/5985/5986/2049），会占满 config.py:170 的 24 摘要/分钟并遮蔽 builtin.py:1449 在 3389 上的低危规则",
    "blocker: builtin.py:1194 - 内置-DNS-TXT隧道 count key 含 query（同一名字重复10次）与隧道语义相反，且 qtype 仅接受 \"16\"（normalizer.py:548 有 qtype_name 回落路径）→ 结构性漏报",
    "blocker: builtin.py:1229/1240/1251 - 三条流量外传规则无 dst_external/dst_internal，无按源字节求和，且 bytes_* 为 None 时 engine 数值比较静默返回 False",
    "note: builtin.py:35/52 - 无边界短词子串（xmr/conti/beacon）在 critical/high 级放大误报；priority=5 平级依赖 service.py:15 的 DB 顺序不确定",
  ],
  "manualNotes": "本组 13 条规则未发现引擎/字段层面的实现缺陷；问题集中在规则内容（方向限定缺失、阈值与真实业务量不匹配、正则无边界、count 规则 key 选错、priority 对频率规则无效）。最该先修的三条见 Top 3；所有修复建议需同步 agent/backend/app/rules/builtin.py 的同名副本。"
}
```