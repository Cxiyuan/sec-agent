# 深瞳 NDR 内置规则质量评审报告

> **状态（2026-10-04）**：本报告的全部 P0/P1/P2 结论与跨组结构性问题**均已落地修复**，
> 并在 `tests/py/test_rules_quality.py` 里钉住；修复记录见
> [`docs/ndr-redesign.md`](ndr-redesign.md) 的「2026-10-04 内置规则质量评审与修复」。
> 本文件保留评审当时的原始结论，便于对照。内置规则数 82 → 84（新增 2 条补漏规则）。
>
> 评审对象：`ndr/backend/app/rules/builtin.py`（82 条内置规则）+ 执行链路（`rules/engine.py`、
> `detector/runner.py`、`detector/frequency.py`、`detector/aggregate.py`、`triage_policy.py`、
> `ingestion/normalizer.py`、`config.py`）。评审基线：`main@599c9b0`，工作区无改动。
> 方法：7 条独立只读评审车道（每车道带全新上下文），逐条给出文件:行号依据。
> 原始车道报告见 [`docs/review/ndr-rules/`](review/ndr-rules/)（7 份，共约 20 万字符）。
>
> ⚠️ **重要前提**：`agent/backend/app/rules/builtin.py` 与 `normalizer.py` 是同内容副本，
> **任何修复必须两侧同改**，否则静默漂移。

## 一、总体结论

**规则覆盖面广、方向设计（内网常规流量分级放行）思路正确，但当前状态不建议直接上线：
存在 7 个 P0 级问题，其中「按请求路径判 WebShell 上传」「cookie 字段恒空导致整类检测为零」
「大面积目标探测实为无条件计数」会同时造成大量误报与关键漏报。**

另一个更根本的问题：`agent_push_url` 缺省为空（`config.py:57`），检测器把每条摘要 ack 掉并计
`undelivered` —— 实机 `delivered=0 / undelivered=41880`。**在推送打通之前，82 条规则的检测结论
一条也没有到达分析侧**，"规则质量"目前无法用实机 FP/FN 率衡量，本报告全部结论均来自代码级推导
（每条都给出可复现的文件:行号依据）。

统计（82 条）：

| 判定 | 条数 | 说明 |
| --- | --- | --- |
| 疑似死规则 / 永不触发 | 6 | 943、1405、1416、1371、284(cookie 分支)、676(index.php 分支) |
| P0 必修 | 7 组 | 见下 |
| P1 高优先（误报洪泛或关键漏报） | 15 组 | 见下 |
| P2 中优先 | 12 组 | 见下 |
| 引擎/链路结构性问题 | 5 | 见第四节 |
| 明确 OK | 约 10 条 | 含 926、1296 等（不展开） |

## 二、P0 阻塞项（必修）

### P0-1 `内置-WebShell上传`（builtin.py:464-484）判据用错字段
用 `POST 的请求路径 uri_path` + 成功码 `200/201/202/204/302` 判「上传脚本」。
后果：**任何传统站点每次表单提交都报 critical**（`POST /login.php`→302、`POST /index.php`→200、
`POST /wp-login.php`→302、`POST /submit.jsp`→200）；而真正的 `multipart` 上传
`shell.php` 到 `/api/upload` **漏报**。又因 p8 小于 WebShell访问(p10)，首个命中即停还会把归因抢走。
修：判据改为 `content_type multipart/form-data` + `body regex filename="…\.(php|jsp|aspx|war)"`；
302 从成功码里删掉或加白名单。

### P0-2 `cookie` 字段在 Zeek 链路恒空 → 整类检测为零
`normalizer.py:536` 只读顶层 `cookie`，而 Zeek `http.log` 没有该列，Cookie 值只在
`req_headers`（`zeek/site/shentong-httpheaders.zeek`）。连锁死规则：
- `内置-会话跨IP复用`（943，**critical 级"会话劫持/凭证盗用"检测实际为零**；且条件
  `log_type==http` 与 `cookie exists` 两侧永不同真）
- `内置-反序列化特征`（284，rememberMe/Shiro 分支永不可达）
- `builtin.py:684` 的 `cookie rememberMe=` 条件（recon 车道确认与 298 行重复定义）
修：normalizer 从 `req_headers` 解析 `Cookie:` 进 `cookie` 字段（照既有 `_auth_from_headers` 做法）。

### P0-3 `内置-大面积目标探测`（781-794）实为无条件计数规则
唯一条件 `src_ip exists` **恒真**，跨全部 log_type 按源计数，5 分钟遇到 25 个不同 `dst_ip` 即 medium。
监控服务器、备份、代理、更新客户端、NAT 后多用户全部命中 —— 是本组最可能贡献 `hit 3076` 洪泛、
并吃掉 24 条/分钟投递额度的规则；同时又漏掉「单目标多端口深扫」。
修：条件换成未建立连接（`scan_attempt`/`rejected_connection`），`min_distinct` 提到 40，
另加一条 `distinct="dst_port"` 的深扫规则。

### P0-4 路由把真实取证路径路由掉了（`_FIELD_TYPES` 与 `UnifiedLog` 漂移）
`engine.py:249-298` 的 `_FIELD_TYPES` **没有 `dst_ip` 的 owner**，导致
`内置-云元数据访问`（660）的 `dst_ip eq 169.254.169.254` 分支在 conn 日志上永不求值；
`内置-SSRF`（308）同理只有 query 分支。另外 12 个 `_FIELD_TYPES` 键在 `UnifiedLog` 里
已无对应字段（僵尸键）。
修：给这两条规则补显式 conn 分支；加守卫测试
`set(_FIELD_TYPES) ⊆ set(UnifiedLog.model_fields)`。

### P0-5 三条规则在当前采集契约下永不触发（却显示"有覆盖"）
- `内置-协议异常`（1405）：`event_type protocol_anomaly` 只由 notice 的 note 产出，
  而 `shentong-policies.zeek:32` 显式 `Log::disable_stream(Notice::LOG)`；
  `weird.log` 又被 `_zeek_event_type` 归成 `generic`。
- `内置-TLS异常`（1416）：同因，**TLS/证书异常检测零覆盖**。
- `内置-上传类型不匹配`（1371）：`content_type` 在 Zeek 链路无任何生产者 → AND 恒假。
修：加 `log_type=="weird" → protocol_anomaly` 映射、从 `req_headers` 解出 Content-Type；
或明确删除以免形成"有覆盖"的假象。

### P0-6 `内置-表达式注入与JNDI（Log4Shell）`（241-264）正则无词边界
`(?i)(ognl|spel|…)` 经 `re.search` 子串匹配 → `/spellcheck`、含 `spel` 的域名都报
**critical 且 priority=5**，还抢走更具体规则的归因；同时**完全不看 `req_headers`**，
而 Zeek 的头值只在 `req_headers` 里 → **CVE-2021-44228 头注入向量一条不报**。
修：`\bspel\b`/`\bognl\b` + 补 `req_headers`/`resp_headers` 条件。

### P0-7 `内置-命令注入特征`（147-167）漏掉最常见形态
要求「分隔符 + 命令 + 空白」才命中：`;id`、`|id`、`&&id`、换行分隔**全漏**；
query 的反引号分支同时过宽。
修：分隔符后允许命令结束（`;[a-z]+\b` 形态），并收窄反引号分支。

## 三、P1 / P2 问题清单

### P1（高优先）
| 规则/位置 | 问题 | 影响 |
| --- | --- | --- |
| `内置-横向移动管理端口`(1134) | 无方向、无白名单，445/139/135/3389/5985/5986/2049 逐条命中；抑制白名单恰好卡在 `severity < medium` 门槛外 | 内网海量正常会话，挤占 24 条/分钟额度；并遮蔽 1449 在 3389 上的低危规则 |
| `内置-弱TLS版本`(523) / `内置-自签或异常证书`(541) | 无方向/次数约束；`cert_issuer` 只取顶层字段，x509 的 issuer 嵌套未解析 → 很可能恒空；令牌 `self/openssl` 抓不到真自签 DN | 内网每条 TLS1.0/1.1 会话一条 medium，量级数千-上万/天 |
| `内置-恶意文件传输`(505) + `policy_skip_rules` | 未用 `file_is_orig/file_source/filename`；且 `config.py:73` 把它列进跳过白名单，但 `severity=high ≥ min_severity=medium` 使**抑制永不生效**（死配置，合规上等于静默降噪失效） | 软件更新/内部 JAR 下载全报 high |
| 账号类 count 规则：`密码喷洒`(888) / `登录接口爆破`(870) / `撞库`(907) | key 只有 src_ip、无失败条件、无 dst_ip | **NAT 出口下必然 critical 误报**：同出口 5 个员工登录=密码喷洒；15 次正常登录=爆破；移动端切网=撞库 |
| `内置-Token/JWT异常使用`(999) | `auth_scheme in [bearer,jwt]` 分支命中**每一个** Bearer 请求 | 所有前后端分离应用的正常 API 调用都报，与描述"高频使用"完全不符 |
| `内置-内网慢速横向`(1454) / `内置-内网慢速服务枚举`(1474) | 无 `conn_state`/`log_type` 限定、服务器回包也计入；阈值取「任意内网源 6h ≥5 目标」「同目标 ≥10 端口」；且 `window==cooldown=300` → 每 5 分钟重复触发（单主机 6h 最多 72 条） | 域控/文件服务器/代理**常驻触发**；单键累计上万（实机已见）；模式与窗口设计均需重做 |
| `内置-高频扫描连接`(808) + `扫描尝试连接`(822) + `端口扫描`(797) | 三条同行为规则语义/覆盖/定级三处打架，同一扫描出 2-3 份摘要；只认 `S0`，漏 `REJ/RSTOS0/RSTRH` 型扫描；NAT 与容器重试的正常 S0 被当扫描 | 重复告警 + 漏真实扫描 |
| `内置-框架漏洞探测特征`(676) | 一条规则里混合：死条件 `/index\.php\?s=`（`uri_path` 已去查询串）、大面积 FP 的 `\.do$\|\.action$`、与 298 行重复的 `rememberMe=` | ThinkPHP 探测漏报 + 遗留 Java 应用正常请求误报 |
| `内置-敏感文件与源码泄露探测`(609) | 无白名单 | K8s 探针 `/actuator/health` 持续 high |
| `内置-未授权访问探测成功`(641) | `auth_scheme ne basic` 对空值恒真 | 只排掉 HTTP Basic，放过所有会话式登录访问 |
| `内置-开放重定向探测`(394) | 与 SSRF(316-331) 关键字几乎重合且优先级更低(20>10) | 真实遮蔽，`?redirect=https://evil` 永远归因给 SSRF |
| 数据外传三兄弟(1229/1240/1251) | 全部缺 `dst_external/dst_internal`；全仓没有"按源字节求和"的规则类型（频率规则只计数/基数）；`bytes_*` 为 `-` 时数值比较静默返回 False | 内网备份/更新分发/媒体大量 FP；1GB 分片慢速外传结构性漏报 |
| `内置-DNS-TXT隧道`(1194) | `key` 含 `query`（同一名字重复 10 次）与隧道语义相反；`qtype in ["16"]` 与 `normalizer.py:548` 的 `qtype_name` 回落不兼容（静默恒假） | 真隧道永不触发 |

### P2（中优先）
- **同优先级无 tiebreaker**：`rules/service.py:15` 只 `order_by(priority)`，p10 有 6-8 条 → 同一请求命中多条时留下哪条**不保证稳定**，分析报告里的规则名会误导人。修：`order_by(Rule.priority, Rule.id)`。
- `内置-SMTP滥用`(1427)：`OR log_type==smtp` ⇒ **每封正常邮件**报 medium；真正的 `smtp_abuse` 分支已死。
- `engine.py:90` 缺省 `op='eq'` + `None==None` → 错字段名或 `whitelist:[{}]` 会**静默全命中**；`exists` 把 `False` 当存在。
- 正则无边界短词：`xmr`/`conti`/`beacon` 在 critical/high 级放大误报（`conti`→continue、`beacon`→/cdn-cgi/beacon）。
- `aggregate.py`：samples 只留最早 3 条 + `_MAX_SET=50` 被基线复用为 distinct → >50 扇出后 2σ 基线失真。

## 四、跨组结构性问题（Top 5）

1. **P0 路由把真实取证路径路由掉**（见 P0-4）——并叠加 notice 断供：协议异常/TLS异常/端口扫描/暴力破解 的 Zeek 侧生产者被 `disable_stream(Notice::LOG)` 掐断。
2. **P1 优先级跨列表失序**（`types + wild` 拼接 + 首个命中即停）→ 判错性质/等级。
3. **P1 频率规则在实机流量下必然误报且自我重复**，且 `src_ip` 作 key 在反代/NAT 下把整站塌成一组；`密码喷洒`(888) 与 `会话跨IP复用`(943) 因 `distinct` 字段为空而永不触发。
4. **P1 交付侧把产出全部丢弃，且额度策略对噪声没有优先级**：`_flush` 超额 FIFO requeue + 1800s 超龄丢弃 + 队列裁最旧，噪声规则会挤掉高价值告警；**per-event 规则当前没有任何抑制手段**。

## 五、Top 修复清单（按性价比分层）

### 第 1 层：一行级（立竿见影，成本最低）
1. `rules/service.py:15` → `order_by(Rule.priority, Rule.id)`（修同号归因不确定）。
2. `engine.py:365-371` 拼接后按 `(priority, name)` 排序（修跨列表遮蔽）。
3. `内置-敏感文件与源码泄露探测`(609) 补 `whitelist: _WHITELIST_HEALTH`。
4. `内置-未授权访问探测成功`(641) `auth_scheme ne basic` → `not auth_scheme exists`。
5. `内置-大面积目标探测`(781) 去掉恒真的 `src_ip exists`，换未建立连接判据 + `min_distinct=40`。
6. `内置-表达式注入`(241) 加词边界 `\bspel\b`/`\bognl\b`。
7. `内置-协议异常`(1405)/`内置-TLS异常`(1416) 补 `log_type=="weird" → protocol_anomaly` 映射（否则删除，别留假覆盖）。
8. `config.py:73` 的 `内置-恶意文件传输` 从 `policy_skip_rules` 移除，或把该规则降到 `<medium`（否则"配了不生效"）。
9. `内置-WebShell访问`(487) 正则放宽（`shell2.php`/`x_shell.php`/`b374k-3.php`/`wso.php` 现全漏）。

### 第 2 层：字段/上游级（一处修、多条规则复活）
10. **normalizer 从 `req_headers` 解析 `Cookie:` 进 `cookie` 字段** → 救活 943（critical 会话劫持）、284、684。
12. **x509 嵌套 issuer 解析**（`certificate.issuer`）→ 救 `内置-自签或异常证书`(541)。
13. **`_FIELD_TYPES` 与 `UnifiedLog` 对齐**（补 `dst_ip` owner、清 12 个僵尸键）+ 守卫测试 → 救 660/308。
14. **`正常登录路径正则` 补 `.php/.do/.action/authenticate/sign_in`**（`web_login_path_regex`）→ 救 870/888/962/1020 整链漏报。

### 第 3 层：结构级（需要设计决策 + 回归测试）
15. `内置-WebShell上传`(464) 判据改为 `multipart filename`，删 302 成功码。
16. 合并 `端口扫描`(797)/`高频扫描连接`(808)/`扫描尝试连接`(822) 为一条 high + 一条 `window:21600` 低速版，补齐 `REJ/RSTOS0/RSTRH`。
17. 频率规则统一补 `log_type=="conn"` + `conn_state in [S0,REJ,SH,RHR,RSTOS0,RSTRH,OTH]`，`内网慢速横向/服务枚举` 阈值收到 10 目标/25 端口、窗口收到 1800s。
18. 账号类 count 规则补 `key=[src_ip,dst_ip]` + 失败定向（401/403/429 或 `distinct: account`）。
19. `_flush` 超额时按 severity 降序保留（低危先丢）而非 FIFO；增加 per-rule 摘要速率上限。
20. 数据外传三兄弟补方向谓词 + 新增"按 (src,dst) 窗口字节求和"的规则类型。
21. `内置-内网慢速横向`(1454) 等长窗频率规则的 `window` 与全局 `freq_cooldown_seconds` 解耦。

### 配套：测试缺口
现有 `tests/py` **没有任何一条内置规则的行为断言**（只有 `_FIELD_TYPES` 路由、conn_state 语义等契约测试）。
建议新增：① 每条内置规则一个正例/反例样本（至少覆盖本报告 P0/P1 条目）；
② "每条规则的每个 typed 字段至少有 1 个 owner log_type 会填它"的结构守卫；
③ 事件类型词表守卫改成"按当前采集配置可产出"（notice 关掉时，只有 notice 能产的标签必须让 CI 失败）。

## 六、评审限制与残余风险

- **未做运行时验证**：全部结论来自静态代码推导，未连实机 ES、未跑规则命中统计。阈值类结论
  （如"数千-上万/天"）是量级估计，落地前建议先按「规则名 × 源IP」拉一周命中分布再定阈值。
  默认约定推断（相关结论置信度标为"中"）。
- **待实机确认两点**：① `ssl.log` 是否实际产出 `cert_issuer`/`issuer`（决定 541 是否死规则）；
  ② 重复 Host 头是否真的落进 `req_headers`（决定 `hostname contains ","` 是否恒假）。
- **推送未打通**：在 `ST_AGENT_PUSH_URL` 配置前，无法用实机数据量化任何规则的 FP/FN 率。

---


---

## 后续处置（2026-10，评审后第 16 条的落地）

评审第 105 行「三条同行为规则打架、只认 `S0` 漏 `REJ/RSTOS0/RSTRH`」与建议第 16 条
（合并扫描规则、补齐失败判据）已落地：

- **退役 `内置-扫描尝试连接`**：实测误报率 ≈ 100%（近 15 分钟 9,165 条 S0 / 92 个源，
  不同目的端口最多的源只有 3 个）、占全部摘要的 55~79%。名字进 `builtin.RETIRED_RULES`，
  播种时**幂等置停用**（保留行、可一键回滚）。
- **新增 `内置-快速端口扫描`**（5 分钟、同源 ≥10 次失败且 ≥8 个不同目的端口，
  `event_type in [scan_attempt, rejected_connection]`）：补齐评审指出的 RST 型漏报，
  并把「窄端口扫描（8~29 个端口）」这个既有规则打不中的区间补上。
  `RSTO`/`RSTR`（握手已建立后的 RST）**不计入** —— 那是正常业务断连。
- **未动**：`内置-端口扫描`（notice 型 `port_scan`）在本部署是死规则（采集面关掉了 notice）；
  `内置-高频扫描连接`（30 分钟/30 次/8 端口）与两条 6h 慢速规则按评审建议保留，与此形成分工。
- 详见 `docs/ndr-redesign.md` 文末「2026-10 扫描规则改「扇出判据」」一节。
