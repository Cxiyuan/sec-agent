# 深瞳 NDR 检测引擎与执行链路评审（引擎语义 · 全链路视角）

**评审对象**：`ndr/backend/app/rules/engine.py`、`rules/builtin.py`（82 条）、`detector/runner.py`、`detector/frequency.py`、`detector/aggregate.py`、`triage_policy.py`、`ingestion/normalizer.py`、`ingestion/log_types.py`、`ingestion/conn_states.py`、`config.py`、`zeek/site/*.zeek`、`tests/py/test_rules_routing.py`、`tests/py/test_conn_states.py`。
**方法**：逐行读引擎与执行链路 + 全量扫 82 条规则；每条结论都落到具体字段/正则/阈值/行号。**未做**：没有运行任何代码或测试（本任务只读分析），因此所有"永不触发/死规则"结论给出的是**代码路径证明 + 反证方法**，未用运行时数据验证。

**结论速览**

| 项 | 结论 |
|---|---|
| 路由 | 设计 fail-open 是对的；但 `_FIELD_TYPES` 与 `UnifiedLog` 已经漂移（12 个键无对应字段），且"混合类型 AND"会造成条件恒假（云元数据访问的 dst_ip 分支） |
| 匹配语义 | `eq/ne/in` 不做大小写归一；`contains` 大小写敏感；`exists` 把 `False` 视为存在；`op` 缺省为 `eq` 且 `None==None` → 空条件/错字段名可静默全命中 |
| 优先级 | **typed 列表整体排在 wild 列表之前**（`rules_for_log_type` 只是拼接），跨列表的 priority 顺序被破坏 → wild 的 p5/p10 规则会被 typed 的 p25 规则遮蔽 |
| 频率规则 | cooldown 缺省 == window，6h 窗规则会每 5 分钟重复告警；多条规则 key 用 `src_ip`（反代/NAT 聚合）；`distinct` 字段为空即永不达标（密码喷洒/会话跨IP复用） |
| 抑制/限流 | `policy_skip_rules` 只列 2 条，其中 `内置-恶意文件传输` 是 high，**永远进不了 severity<medium 的门**（死配置）；24/分钟额度 + 1800s 超龄丢弃在噪声规则下必然长期饱和（与 undelivered 41880 / delivered 0 一致；主因是 `agent_push_url` 缺省空，摘要被 ack 计入 undelivered） |
| 聚合 | `(src_ip, rule)` 会把不同性质攻击并成一条；`dst_ips` 上限 50 且 baseline 也用它算 distinct_dst_ips（>50 后基线失真）；samples 只留前 3 条（常是探活请求） |

---

## (1) log_type 规则路由

### 1.1 机制与现状（正常的部分）
- `_FIELD_TYPES`(engine.py:249-298) / `_COMMON_FIELDS`(engine.py:300-320)，`build_rule_index`(engine.py:334-362) 三条判定：显式 `log_type eq` → 字段归属 → 通配；`rules_for_log_type`(engine.py:365-371) 返回 `types[kind] + wild`。
- 显式 log_type 全部是**可检测类型**，没有「挂在 OPS 类上」的规则：`files`/`ssl`/`dns`/`http`/`smtp` 都在 `zeek_event_log_types`(config.py:109) 里；OPS 类(`ntp/packet_filter/reporter/stats/ja4ssh/ja4d`，config.py:110) 在 runner 的 `is_detectable` 闸门就被挡掉（runner.py ②b 分支）。这部分没问题。
- **count 规则完全绕过路由**：`build_rule_index` 只喂 `per_event`（runner.py `_with_index`），频率规则在主循环里对所有 log_type 无条件求值（runner.py:709）。它们各自用条件里的 `log_type eq` 自限，逻辑上说得通，但意味着「路由表」对 18 条频率规则零约束——审查时容易漏看。

### 1.2 规则引用了 `_FIELD_TYPES` 未覆盖的字段 → 落通配（代价：每次全跑）
| 字段 | 规则（builtin.py 行） | 后果 |
|---|---|---|
| `hostname` | 内置-Host头攻击:416 | 通配，在每个 log_type 上求值 |
| `cookie` | 反序列化特征:284、框架漏洞探测特征:676、会话跨IP复用:943 | 前两条另有 body/uri_path 已能路由；**会话跨IP复用是 count 规则，直接绕过索引** |
| `auth_scheme` | 未授权访问探测成功:641、Token/JWT异常使用:999 | 靠 status_code/uri_path/query 已能路由 |
| `account` | 密码喷洒:888、撞库:907、多账号同机登录:1037 | count 规则，不受路由影响 |


### 1.3 反向漂移：`_FIELD_TYPES` 里有 12 个字段在 `UnifiedLog` 里根本不存在【P1，规则作者陷阱】
核对 `schemas.py` 的字段全集后，`_FIELD_TYPES` 中存在以下**无对应字段**的键：
`uri`(engine.py:251)、`request_body_len`、`response_body_len`、`rcode`、`answers`、`duration`、`orig_bytes`、`resp_bytes`、`proto`(真名 `protocol`)、`service`、`seen_bytes`、`server_name`(真名 `hostname`)、`issuer`(真名 `cert_issuer`)。
- 后果：任何引用这些名字的规则（用户自定义、导入的社区规则集、以后有人按 Zeek 字段名写规则）会被**"正确地"挂到一个 log_type 上，但字段恒为 None → 永远不命中**，而且它在界面上看起来是启用状态。这正是 `tests/py/test_rules_routing.py::test_dead_field_names_no_longer_fake_http_ownership` 想防的坑（该测试只钉了 `host`/`referrer` 两个词，其余 12 个没人守）。
- 最小修复：加一条守卫测试 `assert set(engine._FIELD_TYPES) <= set(UnifiedLog.model_fields)`，把 `server_name→hostname`、`issuer→cert_issuer`、`proto→protocol`、`resp_bytes→bytes_in`、`orig_bytes→bytes_out` 改正，删掉 `uri/request_body_len/response_body_len/rcode/answers/duration/service/seen_bytes`。

### 1.4 「同一条件树混合多类型专有字段 → 某 log_type 上条件恒假」的具体条目【P0（漏报）】
**内置-云元数据访问（builtin.py:660，priority=5，critical）**
```
logic=or: query contains 169.254.169.254
          body  contains 169.254.169.254
          query contains metadata.google.internal
          dst_ip eq 169.254.169.254        ← 这一支
```
- **conn 日志上这条规则根本不参与求值**（runner.py:697 只取该 log_type 的候选），而"内网主机/被入侵的 Web 服务器真的去连 169.254.169.254"恰恰只体现在 conn.log（`dst_ip` + `dst_port=80`）上。
- 结果：SSRF 成功利用后的**真实取证线索被路由掉了**，只剩"客户端把 metadata IP 写进 URL/body"这类以扫描器为主的信号。

### 1.5 显式 log_type 被丢弃：内置-SMTP滥用【P2，语义）
`build_rule_index` 的第二个判断（engine.py:350-352）：`if not owner or not (fields - _COMMON_FIELDS - {"log_type"}): wild`。
内置-SMTP滥用（builtin.py:1427）的条件是 `event_type eq smtp_abuse` **or** `log_type eq smtp`，字段全是通用字段 → 第二个子句为真 → **显式 log_type 被忽略、整条进通配**。后果不是漏报而是两个：
1. 它在每个 log_type 上白跑；
2. 语义上 `log_type eq smtp` 这一支会让**每一条 smtp.log 事件**（正常收发邮件）命中 medium「SMTP滥用」——见 §3.3 FP。
修复：显式 log_type 应当直接决定 owner（把该子句改成"仅在无 owner 时才因通用字段落通配"），或删掉 `log_type eq smtp` 这一支，只保留 `event_type eq smtp_abuse`（但见 §1.6：该 event_type 没有生产者）。

### 1.6 「有生产者」是静态结论，不等于线上真的有【P1，静默死规则】
`tests/py/test_conn_states.py:69-95` 的 `OTHER_EVENT_TYPES` 把 `port_scan/brute_force/tls_anomaly/protocol_anomaly/dns_anomaly/smtp_abuse` 列为"有生产者"，但它们的 Zeek 生产路径**全部走 `notice.log`**（`normalizer._zeek_event_type` 的 note 分支），而本项目明确把 notice 流关掉了：
- `ndr/zeek/site/shentong-policies.zeek:28-31` `Log::disable_stream(Notice::LOG)`；
- `docs/ndr-collect-plan.md:29`「路线 A：不加载任何 Zeek 自带检测策略；`Log::disable_stream(Notice::LOG)`」。
因此：
- **内置-协议异常（builtin.py:1405，event_type eq protocol_anomaly）实际无生产者**：weird.log 进 `_zeek_event_type("weird", note=None, conn_state=None)` → 不匹配任何分支、无 conn_state → 返回 `conn_states.GENERIC_EVENT_TYPE = "generic"`（conn_states.py:33 + `event_type_of` 空值返回 None）。它不是"路由死了"，是**标签永远不会出现**。
- SMTP滥用（1427）的 `event_type eq smtp_abuse` 支同理死，真正在跑的是 `log_type eq smtp`（过度宽）。
- 建议：把这条词表守卫升级为"**按当前采集配置**可产出"的守卫（该标签的生产者路径若依赖 notice，而 notice 已关，则测试应失败），否则 CI 永远绿、线上永远不触发这种规则。

---

## (2) 匹配语义

### 2.1 正确的部分（明确记 OK）
- `dst_port eq 80`（明文凭证传输:962）、`dst_port in [...]`（横向移动管理端口:1134 等）同理是 int，无类型坑。
- 数字操作符对 None/脏值安全：`gt/gte/lt/lte` 转 float 失败返回 False（engine.py:111-116）→ `服务端错误突变`(764) 遇到 status_code 缺失不会误报。
- `qtype in ["16"]`（DNS-TXT隧道:1194）能工作，因为 normalizer 明确按数字码存：`"qtype": str(doc.get("qtype") or doc.get("qtype_name") or "")[:16]`（normalizer.py:548，含注释）。
- `ja3 in []`（JA3指纹命中:594）空列表永不命中，配合 `main.py` 的 `_dynamic_rule_spec` 从 `ST_JA3_BLOCKLIST` 播种（config.py:88 缺省空）＝安全默认，是设计取舍而非 bug（代价：TLS 工具指纹默认关闭，界面上这条规则看起来像死规则）。

### 2.2 `contains/eq/in` 的大小写与归一化【P2】
- `contains` 大小写敏感（engine.py:102-104）：`内置-云元数据访问`（660）的第二支 `contains "metadata.google.internal"` → `metadata.GOOGLE.internal` 形式（DNS 大小写不敏感）漏报。

### 2.3 `exists` 把 `False` 当存在【P2，当前无内置规则触发】（engine.py:95-97）
`return actual is not None and str(actual).strip() != ""` → `str(False) == "False"` → **`{"field":"dst_internal","op":"exists"}` 永真**；`0`（如 bytes_out=0）同样算"存在"。内置规则里 `exists` 只用于 `account`(888/907/1037)/`cookie`(943)/`mitre`(1307)/`src_ip`(781)，都是字符串，暂未踩雷；但用户自定义规则很容易踩。修复：`if isinstance(actual, bool): return True` 显式化，或对 bool/number 分开判定。

### 2.4 缺省 `op` + `None == None` → 可静默"全命中"【P2，引擎健壮性】
- `op = cond.get("op", "eq")`（engine.py:90），`_get_field` 对不存在的字段名返回 None（engine.py:61-68）。
- 于是 `{"field": "url"}`（字段名写错、漏写 op）→ `None == None` → **True**；`"whitelist": [{}]`（UI 存了个空条件）→ `whitelisted()` 走 `_eval_node`(engine.py:156-167) → `_match({})` → True → **该规则对所有日志放过 = 静默停用**。
- 这与"空条件组视为命中"（engine.py:141-143）叠加；`match_rule` 只拦"顶层 rules 为空"（engine.py:176-177），拦不住 `[{}]`。启动自检 `validate_rule_regexes` 只看正则（engine.py:200-245、selfcheck.py:10-17），不看结构。修复：`_match` 里 `if not field or "op" not in cond: return False`（fail-closed），并把"白名单里存在空条件"纳入启动自检。

### 2.5 `not` 语义（结论：实现正确，但内置规则一条没用）【OK + 取舍】
`_eval_node` 支持 `{"not": {...}}` 与 `{"not": {"rules": [...]}}`（engine.py:121-131），语义无歧义。但 82 条内置规则里 **0 处使用 `not`**，所有排除都靠 `ne`（横向移动管理端口:1134、异常外联端口:1149 的 `event_type ne scan_attempt`）。代价：`ne` 对**缺失/空值也为真**（`None != "scan_attempt"`），所以那两条规则实际等价于"dst_port in [...] 就打"，过滤条件形同虚设（见 §3.3 的 FP 分析）。

### 2.6 URL 解码只覆盖 `_DECODE_FIELDS`，且只解一层【P2，FN】
`_DECODE_FIELDS = {query, query_string, uri_path, body, referer, filename}`（engine.py:37）。
- 不在其中但规则在用的字段：`hostname`（Host头攻击:416）→ `Host: %6cocalhost`、`Host: 169.254.169.254` 的编码变体不命中；`cookie`（反序列化:284/框架漏洞探测:676）→ 编码的 rememberMe 不命中；`req_headers` 完全不解码（但它本来就不参与 contains/regex，除 2.8 建议的用法外）。
- 只解一层（`unquote` + `unquote_plus` 各一次，engine.py:77-85）：三重编码（`%25252e%252e%252f`）漏报；规则里显式列到双重编码（路径穿越:169 的 `%252e%252e`）说明作者知道这一点。
- 反向副作用（可接受）：`unquote_plus` 把 `+` 变空格，使 `\s` 类正则（SQL注入 `or\s+1\s*=\s*1`:81、命令注入 `;\s*(cat|...)`:147）能命中 `or+1=1`、`;cat+...` 这类"半编码"载荷——这是想要的加宽，但代价是"任何含 `+` 的正常参数都可能凭空多出一个空格上下文"。目前没有找到明确的正常流量误报样例，故只作 report-only。

### 2.7 具体"失效"与"误判"例子（本节最硬的几条）
**(a) FP｜内置-勒索/僵尸网络域名（builtin.py:35，p5，critical）**：正则 `(?i)(ransom|lockbit|blacksuit|conti|emotet|trickbot|cobaltstrike|meterpreter|beacon)` 是**无边界子串**；而 http 上 `query` = 完整 URI（normalizer Zeek 分支 `query = str(doc.get("query") or uri or "")`）。正常流量：
- `conti` 命中 `?continue=/dashboard`、`/api/continent`、`continue.example.com`（GitLab/Spring 登录跳转参数 `?continue=` 极常见）；
- `beacon` 命中 Cloudflare 自动注入的 `/cdn-cgi/beacon/expect-ct`、Snowplow 的 `/beacon.js`、各类 `?event=beacon` 埋点。
→ 一次正常网页访问即可产出 critical 告警。收窄建议：域名语义用带边界+后缀锚定的写法并对 http 侧降权，例如
`(?i)(^|[.\-/])(ransom(ware)?|lockbit|conti|emotet|trickbot|cobaltstrike|meterpreter)([.\-/]|$)` 且把 `beacon`/`conti` 这类高歧义词移到"需配合 `src_external`/低信誉域名"的分支；更稳的做法是接威胁情报域名表（用 `in`/后缀匹配）替代关键字。
**(b) FP｜内置-表达式注入与JNDI(Log4Shell)（builtin.py:241，p5，critical）**：第 5 支 `(?i)(ognl|spel|%24%7bjndi)` 中 `spel` 会命中 **spelling / spellchecker**（`?q=spelling`、`/api/spellcheck`），也无边界。→ critical FP。收窄：`(?i)(\bognl\b|\bspel\b|\$\{|%24%7b)` 或要求与 `${`/`%24%7b` 同现。
**(c) FN｜JSON 登录体（影响 密码喷洒:888 / 默认口令尝试:977）**：
- `默认口令尝试` 的两支都要求 `pass(word)?=(...)`（`=`），JSON 体 `{"password":"123456"}` 里是 `":"` → 永不命中；而现代前后端分离系统的登录几乎全是 JSON。
- `account` 抽取 `_extract_account`（normalizer.py:343-357）用 `(?:^|[&;,\s])username\s*[=:]\s*([^&;,\s"']+)`，前导必须是行首/`&`/`;`/逗号/空白，且捕获值不能以引号开头 → `{"username":"alice"}`、`"username": "alice"` 都提不到 → `密码喷洒`（min_distinct=5，distinct=account）**永不达标**（frequency.py:67-75）。这是"字段为空则 distinct 永不满足"的教科书案例。
- 修复：`_extract_account` 增加一段 JSON 解析（`json.loads(body)` 失败再回退正则），或把正则放宽为 `["']?{name}["']?\s*[=:]\s*["']?([^&;,\s"']+)`；`默认口令尝试` 同理加 `["']?password["']?\s*[:=]\s*["']?(admin|123456|...)["']?`。
**(d) 死条件｜cookie 分支（反序列化特征:284、框架漏洞探测特征:676）= Shiro/Fastjson 检测缺口【P0 级漏报】**
`UnifiedLog.cookie` 的唯一来源是 `doc.get("cookie")`（normalizer.py `_http_fields` 的 `"cookie": _clip(doc.get("cookie"), ...)`，normalizer.py:536）。而 Zeek 侧该键不存在时是空串：
- `ndr/zeek/README.md` 的 http.log 字段清单只列 `method/host/uri/user_agent/status_code` + 自写的 `req_headers/resp_headers`（并明确"Cookie / Authorization 的值由 `shentong-httpheaders.zeek` 采集"）；
- `tests/py/samples.py` 的 HTTP 样例文档里也没有 `cookie`/`content_type` 键（只有 `req_headers` 里带 `AUTHORIZATION: Basic ...`）。
- **可抄修复（最小改动）**：把 cookie 条件改成打 `req_headers`：
  `{"field":"req_headers","op":"regex","value":"(?i)^rememberme=([A-Za-z0-9+/=]{40,})"}`（`req_headers` 是多行 `Name: value`，Zeek 侧头名**已大写**，见 shentong-httpheaders.zeek 注释），或更彻底：在 normalizer 里从 `req_headers` 解析出 `cookie` 头值填进 `UnifiedLog.cookie`（这样 baseline 的会话画像 `session_id_from_cookie`，config.py:203 `session_cookie_names`，也才有输入）。
- 置信度：**中高**。依据是采集脚本注释与 README/samples 的字段清单；反证方法（一条命令）：发一个带 Cookie 的请求，看 ES 文档里顶层 `cookie` 是否为空（README 的批 3 实测只记了 `raw.cookie_vars`，从未出现顶层 cookie 值）。
**(e) 死规则｜内置-会话跨IP复用（builtin.py:943，p8，critical）**：条件 `cookie exists` **AND** `log_type eq http`。
- Zeek 侧 `log_type=http` 成立但 `cookie` 恒空（同 (d)）→ 不成立；
→ **两侧都不成立 = 永不触发**。而且即便修好字段，`key=["cookie"]` 用的是整条 Cookie 串：`Cookie: lang=zh; consent=1` 这种静态 cookie 在全站所有用户间都相同（distinct src_ip ≥2 立刻满足）→ 会变成 critical 误报机器。正确修法：先按 `session_cookie_names`（config.py:203）只取会话 cookie 的**值**做 key（baseline/profile.py 已有这个函数），再复用。

---

## (3) 优先级遮蔽（priority 升序 + 首个命中即停）

### 3.1 结构性缺陷：typed 列表整体压过 wild 列表【P1】
- `get_enabled_rules` 按 `priority` 升序取（rules/service.py:15）→ `index["types"][k]` 与 `index["wild"]` **各自**是有序的；
- 但 `rules_for_log_type` 返回 `list(types[kind]) + list(wild)`（engine.py:365-371），runner 取第一个命中（runner.py:699）。
→ **跨列表的全局优先级被破坏：任何 typed 规则都先于任何 wild 规则求值，无论 priority 数字多大。**
具体后果（真实规则名 + priority）：
- 修复（一行）：`return sorted(types + wild, key=lambda r: (int(r.get("priority") or 999), str(r.get("name") or "")))`。顺带解决同 priority 时依赖 SQL/插入顺序的**不确定性**（当前 p20 的 端口扫描:797 与 扫描尝试连接:822、p10 的一堆规则，命中哪条不可复现）。

### 3.2 正确的遮蔽（记录为设计取舍，非 bug）
- `超大流量外传`（p15，>100MB，builtin.py:1240）先于 `大流量外传`（p25，>10MB，1229）→ 100MB+ 报 high、10–100MB 报 medium，分层正确。
- `横向移动管理端口`（p30，medium，1134）先于 `常见敏感端口访问`（p40，low，1441）→ 3389 报 medium，不是 low，符合危害。
- 代价：高优先级规则"吃掉"了同事件的多标签（一次会话同时弱 TLS + 自签证书只报 `弱TLS版本` p25，`自签或异常证书` p30 的信号丢失）；摘要里没有 related_rules 字段，分析师看不到被遮蔽的第二规则。

### 3.3 重叠簇（语义重复，建议合并或明确分工）
| 簇 | 规则（priority） | 说明 |
|---|---|---|
| 扫描/扇出 | 端口扫描(797,p20)、扫描尝试连接(822,p20)、高频扫描连接(count,808,p24)、大面积目标探测(count,781,p24)、横向移动多目标(count,1116,p18)、内网慢速横向(count,1454,p27) | 6 条规则描述同一种"同源多目标"行为，且**count 与 per-event 会各产一条摘要**（runner.py:699 + 709） |
| WebShell | WebShell上传(464,p8)、WebShell访问(487,p10)、敏感文件探测(609,p12)、上传类型不匹配(1371,p20，已死)、未授权访问(641,p15) | `/actuator/health` 200 会先命中 敏感文件探测(p12)，未授权访问(p15) 被遮蔽；两条都是 high，报告名与分析师预期不符 |
**派生 FP（必须单列）**：`内置-横向移动管理端口`（1134，medium）与 `内置-SMTP滥用`（1427，medium）；前者对**任何** dst_port ∈ {445,139,135,3389,5985,5986,2049} 的日志命中（`event_type ne scan_attempt` 对空值也为真，见 §2.5），即**每一次正常的 SMB 共享访问 / NFS 挂载 / RDP 登录** → medium，而 severity=medium 进不了 triage 的 `<medium` 门（triage_policy.py:172-173）→ 全部进分析、全部吃投递额度。后者 `log_type eq smtp` = **每一封正常邮件** → medium。这两条是本组最廉价的降噪靶子。

---

## (4) 频率规则（frequency.py）

### 4.1 语义要点
- key：`cond.get("key")`，非法/缺失回落 `["src_ip"]`（frequency.py:39-42）；`count_key` 只做 `getattr` 拼接（engine.py:196-197），**不做归一化、不做回退**（缺失字段 → `""`，多条这样的记录会塌成同一个组）。
- window：规则级 `window` 覆盖全局 300s（frequency.py:50，config.py:186）。
- cooldown：全局 300s，键 `{rule}:{group}:cool`，`set(nx=True, ex=cooldown)`（frequency.py:79-81）→ **同一组在冷却期内只触发一次**。
- min_count：当前事件先 `zadd` 再 `zcard`（frequency.py:56-72）→ 第 N 条即触发。
- distinct：只有字段值非空才 `zadd`（frequency.py:67-70）；`min_distinct` 只在该字段存在时判定（frequency.py:75）→ **字段为空 = 永不达标**。

### 4.2 cooldown == window 的后果（含 6h 长窗）【P1】
冷却与窗口缺省同为 300s（config.py:186-187）。对 5 分钟窗规则这是"最多每 5 分钟报一次"，可接受；对 `内网慢速横向`(1454) 与 `内网慢速服务枚举`(1474)（`window=21600`）则是：
窗口内计数长期 ≥ 阈值 → 每 300s 冷却一过就再触发一次 → **单台主机 6 小时内最多重复 72 条 high 摘要**，且每次都进 24/分钟额度。samples 的 3 条样例、dst 集合每次重新累计（聚合窗 300s，config.py:165）→ 上游看到的是一堆近似的重复告警。

### 4.3 key 选择不当（NAT / 反向代理）【P1】
以下规则 `key=["src_ip"]`：目录/路径爆破(714)、多路径探测(732)、暴力路径枚举(749)、服务端错误突变(764)、大面积目标探测(781)、高频扫描连接(808)、高频认证失败(856)、登录接口爆破(870)、密码喷洒(888)、HTTPBasic凭证暴力(926)、密码重置接口滥用(1017)、API高频调用(1390)。
`src_ip` 是**TCP 对端**（schemas.py 注释、normalizer 只把代理头放进 `real_client_ip`，且要求直连对端在 `ST_ZEEK_TRUSTED_PROXIES` 里才认，config.py:114 缺省空 = 一律不认）。因此：
- 反代后面的整站用户会被塌成"同一个源"：`登录接口爆破` 会把**所有用户的登录**（含各自输错密码）算进一个 src_ip 组；`目录/路径爆破` 会把全站 404 汇成一个源；
- 外部 NAT 出口同理。
修复方向：在 normalizer 增加 `client_ip = real_client_ip or src_ip` 字段并让频率规则 key 用它（`count_key` 不支持表达式，必须新字段）；配套打开 `ST_ZEEK_TRUSTED_PROXIES`。

### 4.4 阈值/条件与实机流量不匹配的具体条目【P1（FP）
| 规则（行，priority，severity） | 触发条件 | 现实 FP |
|---|---|---|
| 内网慢速横向（1454，p27，high，window 21600，distinct dst_ip ≥5，条件只有 `src_internal/dst_internal`） | 内网主机 6h 内连 ≥5 个内网 IP | 几乎**每台工作站**都满足（DC/文件服务器/打印机/WSUS/监控/DNS）；且 severity=high 过不了 triage 的 `<medium` 门 → 永久噪声 |
| 内网慢速服务枚举（1474，p26，medium，window 21600，distinct dst_port ≥10） | 内网主机对同一目标摸 ≥10 端口 | 工作站连网关/服务器的 10+ 端口（DNS/NTP/HTTP/HTTPS/445/SMTP/…)必中 |
| 大面积目标探测（781，p24，medium，distinct dst_ip ≥25/5min，无方向过滤） | 任意事件 | 单个浏览器访问 CDN/分析/广告域就会产生 25+ 个目的 IP |
| 多路径探测（732，p24，high，distinct uri_path ≥40/5min） | 同源 40 个不同路径 | 打开一个重型 SPA（40+ JS/CSS chunk）即触发 |
| 暴力路径枚举（749，p26，medium，key=src_ip+uri_path ≥60/5min） | 同一 path 高频 | uri_path 去参数，所以"2 秒轮询 /api/status?v=n"会被算成同一 path 60 次 |
| 目录/路径爆破（714，p26，high，403/404 ≥30/5min） | 同源 404 | 单个坏静态资源被反复请求、爬虫、用户乱点 |
| DNS-TXT隧道（1194，p20，high，key=src_ip+query，≥10） | 同一查询名 10 次 TXT | 合法 TXT 轮询（SPF/DMARC 校验、DDNS 客户端）误报；反而**真隧道（每次换随机子域）永远不中** → 同时 FP + FN |
| 横向移动高频连接（1096，p22，high，key=src_ip+dst_ip ≥10/5min，管理端口） | 10 个管理端口连接 | Windows SMB3 客户端对同一文件服务器可开多条 TCP 会话 |
**修复模板**（可抄）：
- 内网两条：加端口白名单排除（`{"not":{"field":"dst_port","op":"in","value":[53,123,137,138,5353,67,68,1900]}}`）＋把阈值提到实机量级（内网慢速横向 `min_distinct=50`）＋降级为 medium；或要求"无成功连接"（`event_type in [scan_attempt, rejected_connection, connection_shutdown]`）。
- 大面积目标探测：加 `{"field":"src_external","op":"eq","value":False}` 与排除 443/53 出口，或改成"多目标 **且** 多端口"的组合条件。
- 多路径探测：加 `{"not":{"field":"uri_path","op":"regex","value":"(?i)\\.(js|css|png|jpg|gif|svg|woff2?|ico|map)$"}}`。
- DNS-TXT隧道：`key=["src_ip"]`、`distinct` 换成"随机子域父域"（可用 `distinct: "query"` 只在父域维度上，需引擎支持 `distinct` 带截断/正则，当前不具备）＋加 `rcode eq "NOERROR"`、阈值 ≥50。

### 4.5 `min_count` 与 `min_distinct` 冗余（可读性/调参）【P2】
密码喷洒(888) 5/5、撞库(907) 3/3、多账号同机登录(1037) 8/8、大面积目标探测(781) 25/25、多路径探测(732) 40/40、内网慢速横向(1454) 5/5 —— `distinct ≥ N` 已经蕴含 `count ≥ N`，`min_count` 是死参数。真实触发条件只有 distinct，调参时容易被误导。

---

## (5) 抑制与限流导致的漏报

### 5.1 `internal_routine_reason` 的门槛（triage_policy.py:145-190）
跳过必须**同时**满足：`policy_internal_routine_skip=true`（config.py:71）、**规则名在 `policy_skip_rules` 里**（config.py:73）、`severity < medium`（config.py:74）、方向 `in→in`、`dst ≤ 1`（config.py:75）、无成功连接（config.py:76）。
- **死配置【P2】**：`policy_skip_rules = ["内置-扫描尝试连接", "内置-恶意文件传输"]`，而 `内置-恶意文件传输`(builtin.py:505) 的 severity 是 **high** → `_rank("high") >= _rank("medium")` → 直接 `return None`（triage_policy.py:172-173）→ **它永远不会被这条策略跳过**。这行配置给了"已经降噪"的错觉。修：删掉它，或加一条测试断言 `policy_skip_rules 里每条规则的 severity 都 < policy_internal_routine_min_severity`。
- 副作用（漏报）：名单只有 2 条 → 其余所有低危/中危噪声（常见敏感端口访问 p40、横向移动管理端口 p30、异常外联端口 p20…）**照旧全量分析**，24/分钟额度被噪声占满；同时 `内置-扫描尝试连接`（low，p20）正是"内网慢速单目标扫描"的唯一覆盖者，一旦被跳过（in→in、单目标、无成功连接），慢速内网扫描在分析侧不可见（次数不够 30/5min 时连 `高频扫描连接` 也不触发）。这是明确的取舍代价，建议把 `policy_internal_routine_max_dst`（缺省 1）放宽到 2-3 或给"内网新源首次扫描"开例外。

### 5.2 `has_success` 依赖一个**没有生产者**的标签【P1，潜在漏报】
`SUCCESS_EVENT_TYPES = {"conn_established", "conn_http"}`（triage_policy.py:49，注释说 "conn_http 来自 HTTP 日志"）。但全仓搜索 `conn_http`：只有 triage_policy 的常量与其测试/文档命中，**两个 normalizer 都不产这个标签**（HTTP 日志产 `http_request/http_login/http_upload/http_error`，见 `_http_event_type`；conn 日志产 `conn_established/scan_attempt/...`）。而 `tests/py/test_conn_states.py:69-95` 的"生产者词表"里也**没有** `conn_http`，且词表守卫只校验"规则/技能引用的 event_type"，不校验 `SUCCESS_EVENT_TYPES`。
后果：HTTP 类命中永远判不出"成功连接"（HTTP 200 不算成功）→ 今天唯一被跳过的规则是 conn 类扫描规则（S0 本来就不算成功，结论恰好正确），所以**当前无可见危害**；但一旦有人把某条低危 HTTP 规则加进 `policy_skip_rules`，真实成功的 HTTP 告警就会因为"无成功连接"被当作内网常规流量跳过 → 静默漏报。修复：要么给 conn.log 之外的 HTTP 成功（`status_code < 400` 且 `conn_state ∈ ESTABLISHED`）补一个真标签，要么把 `conn_http` 从集合里删掉并在测试里加"SUCCESS_EVENT_TYPES ⊆ 生产者词表"的断言。

### 5.3 24/分钟投递额度 + 超龄丢弃 + 队列裁剪
- 额度：`detector_max_digests_per_minute=24`（config.py:170），`_flush` 严格按剩余额度投递、超出 requeue（runner.py:514-550）；额度耗尽时**空转等待**（runner.py:516-522）。
- 超龄：`detector_digest_max_age_seconds=1800`（config.py:177）→ 排队超过 30 分钟的摘要直接 ack + 计 `dropped.expired`（runner.py:_flush 的 expired 分支 → `_drop`）。
- 队列上限 20000（config.py:171）+ `_trim_queue` **裁最旧**（runner.py:_trim_queue，LPUSH 头部最新）→ 拥堵时先丢的是**最早的**摘要，也就是"攻击首次接触"的证据，留下的是持续噪声的复制品。
- 与实机计数的一致性：`agent_push_url` 缺省为空（config.py:57）→ `push.deliver` 返回 `off` → **每条摘要被 ack 并计 `undelivered`**（runner.py:_flush 的 off 分支：`_drop(client, "undelivered", ...)` + `push.record`）。这与"undelivered 累计 41880、本进程 2091、delivered 0"完全吻合：**当前不是"限流丢了"，而是"根本没有投递目的地、摘要被正常 ack 掉了"**。也就是说在修好地址/令牌之前，任何规则调优的收益都无法度量。
- 额度与规则噪声的量级关系（结构性结论）：`内网慢速横向` 这类规则每台主机每 5 分钟产 1 条摘要（§4.2），几百台内网主机 = 每分钟上百条新摘要 > 24/分钟 → 额度永久饱和 → 队列单调增长 → 到达 20000 后开始裁最旧 → **一条噪声规则可以把其他规则的所有告警挤出分析**。这是"高命中率下丢多少"的答案：**只要噪声规则的摘要产出速率 > 24/分钟，其余规则的摘要就全部排队、30 分钟后被丢**。
- 建议顺序：① 补 `agent_push_url/token`（先让 delivered>0，否则一切调优不可观测）；② 摘要队列改为**按 severity 淘汰**（低危先丢），而不是 FIFO 裁最旧；③ 按规则维度加"每分钟摘要配额/静默期"（当前只有频率规则的 300s 冷却，per-event 规则无任何抑制）；④ 最后再动 `detector_max_digests_per_minute`。

---

## (6) 聚合语义（aggregate.py）

### 6.1 会丢细节的键与字段
- 键 `_agg_key(src_ip, rule, excluded)`（aggregate.py 的 `_agg_key`，sha256 前 20 位）→ **同源 + 同规则** 合并：`内置-SQL注入-基础特征`(81) 是 `union select / or 1=1 / sleep() / benchmark()` 的 OR 规则，同一 src_ip 在 5 分钟内打 10 个不同应用、4 种载荷 → **1 条摘要**，`count`/`dst_ips`/`event_types` 全部混在一起，无法回答"哪次是成功的注入"。
- `samples` 只保留前 3 条（`_MAX_SAMPLES = 3`，append 时 `if len(samples) < _MAX_SAMPLES`）→ **留下的是最早 3 条**。慢速攻击的前几条通常是探活/404，真正成功的入侵请求被丢弃；而分析链路的证据展示正是拿这 3 条 `raw` 文档跑 normalize（runner.py `_aggregate` 注释、agent 侧 nodes.py）。
- `dst_ips`/`dst_ports` 上限 50（`_MAX_SET = 50`）→ 扇出被低估；更要注意它被**基线**复用：`baseline.annotate` 用 `len(dst_ips)` 当 `distinct_dst_ips`（docs/ndr-redesign.md:456），>50 之后该特征恒定 50 → 2σ 基线对"扇出继续扩大"不再敏感（`内网慢速横向` 打到 300 台与 100 台读数相同）。triage 的 `dst_count = len(dst_ips)`（runner.py `_apply_routine_policy`）只用于 `<=1` 判定，上限不影响该分支。

### 6.2 未丢的部分（OK）
- `excluded` 位入键（避免"只排除部分命中"把两类事件混桶）——设计正确。
- 窗口到期产出 + `_DUE_KEY` ZSET 排序、`pending()` 可观测、满额丢弃写权威计数 `detector_drop_key.agg_full`（aggregate.py `_record_dropped`）+ 限频告警，属"降级可见"的正确做法（`agg_full` 也有 stats 计数，runner.py `_aggregate`）。

---

## 跨组 Top 5 结构性问题 + 修复建议

**#1 路由把"真实取证路径"路由掉了（漏报，P0）**
证据：`_FIELD_TYPES`(engine.py:249-298) 无 `dst_ip` owner + 内置-云元数据访问(660) 的 `dst_ip eq 169.254.169.254` 支 → conn 日志不求值；内置-SSRF(308) 只有 query 支同理。叠加 §1.3 的 12 个僵尸键与 §1.6 的 notice 断供（协议异常/TLS异常/端口扫描/暴力破解 的 Zeek 侧生产者被 `disable_stream(Notice::LOG)` 掐断，shentong-policies.zeek:28-31）。
修复：① 给这两条规则补显式 conn 分支；② 加守卫测试 `set(_FIELD_TYPES) ⊆ set(UnifiedLog.model_fields)` 与"每条规则的每个 typed 字段至少有 1 个 owner log_type 会填它"；③ 把事件类型词表守卫改成"按当前采集配置可产出"（notice 关掉时，只有 notice 能产出的标签必须让 CI 失败）。

**#2 优先级跨列表失序（判错性质/等级，P1）**
修复：拼接后按 `(priority, name)` 排序（一行）；并把"被遮蔽的规则名"写进摘要（`related_rules`）供分析师参考。

**#3 频率规则在实机流量下必然误报且自我重复（P1，噪声 = 漏报）**
证据：`内网慢速横向`(1454) 只以 `src_internal/dst_internal` 为条件、6h 窗、cooldown=300s（frequency.py:79-81）→ 每台内网主机每 5 分钟一条 high；`横向移动管理端口`(1134)、`SMTP滥用`(1427)、`大面积目标探测`(781)、`多路径探测`(732)、`暴力路径枚举`(749) 同族；`src_ip` 作为 key 在反代/NAT 下把整站塌成一组（§4.3）；`密码喷洒`(888)/`会话跨IP复用`(943) 因 `distinct` 字段为空而永不触发。
修复：见 §4.4 的具体 regex/阈值/key 建议；同时把"内网常规"策略的 `policy_skip_rules` 白名单机制从"按规则名"扩到"按规则名 + 最大摘要速率"。

**#4 交付侧把产出全部丢弃，且额度策略对噪声没有优先级（P1，可观测性）**
证据：`agent_push_url` 缺省空（config.py:57）→ `outcome == "off"` → 摘要 ack + 计 `undelivered`（runner.py:_flush），与实机 delivered=0 / undelivered 41880 完全对应；即便修好地址，`_flush` 的 FIFO 超额 requeue + 1800s 超龄 `dropped.expired`（config.py:177）+ 队列裁最旧（runner.py:_trim_queue）会让"持续命中的噪声规则"挤掉其他规则的告警。
修复：① 先修推送地址/令牌；② `_flush` 超额时按 severity 降序保留（低危先丢）而不是 FIFO；③ 增加 per-rule 摘要速率上限（per-event 规则当前没有任何抑制手段）。

**#5 字段语义被"跨来源复用"污染（误报，P1/P2）**
修复：① 把"来源相关语义"拆成显式字段（如 `host_header` vs `agent_name`，或规则里显式 `source_system eq zeek`）；② 高风险规则加语义边界/白名单，或给 `query` 按 log_type 分设不同规则的版本（dns 用域名表，http 用 URI 参数语义）。

---

## 复核建议（需主管或后续 worker 运行，我未执行任何命令）
- 只读断言现况：`pytest tests/py --stack=ndr -q`（现有 `test_rules_routing.py` / `test_conn_states.py` 会绿，因为 §1.3/§1.6/§5.2 三个缺口**没有测试覆盖**）。
- 快速证伪 §2.7(d)：造一条带 `Cookie: rememberMe=xxx` 的 HTTP 请求 → 看 ES 文档顶层 `cookie` 是否为空；同时看 `raw.cookie_vars` 是否只有名字。
- 快速证伪 §1.4：把 `{"field":"log_type","op":"eq","value":"conn"}`+`dst_ip eq 169.254.169.254` 写成临时规则，确认当前内置版本对同一条 conn 日志不命中。
- 快速证伪 §5.2：`grep -rn "conn_http" ndr/backend/app` 应只有 triage_policy 常量（我已核对全仓）。

## Review
- **Correct**：路由 fail-open 的总体设计、`match_rule` 对空规则的拒绝（engine.py:176-177）、数字操作符的脏值安全（engine.py:111-116）、count 规则在逐条规则命中后仍继续评估（runner.py:699-712，避免频率规则被饿死）、丢弃/跳过全部落计数不静默（runner._drop / triage_policy.count_skip / aggregate._record_dropped）、`excluded` 位入聚合键——这些是本组**该保留的**部分。
- **Finding（P0）**：`engine.py:249-298` 的 `_FIELD_TYPES` 缺 `dst_ip`（及 12 个僵尸键）导致 `builtin.py:660` 云元数据访问 / `:308` SSRF 的 conn 侧分支永不求值；`normalizer.py:536` 的 `cookie` 无 Zeek 来源导致 `builtin.py:284/676/943` 的 cookie 条件恒假（含 Shiro 检测缺口、`会话跨IP复用` 整体不可达）。证据行号见 §1.3/§1.4/§2.7(d)(e)。
- **Finding（P1）**：`engine.py:365-371` 的 typed+wild 拼接破坏全局 priority 顺序（遮蔽 `builtin.py:69/834`）；`frequency.py:79-81` 的 cooldown==window 使 `builtin.py:1454/1474` 每 5 分钟重复；`config.py:57` 空推送地址使全部摘要计 `undelivered`（delivered=0）；`triage_policy.py:49` 的 `conn_http` 无生产者（潜在漏报）；`config.py:73` 白名单里 `内置-恶意文件传输` 因 severity=high 永不生效。
- **Finding（P2）**：`engine.py:90` 缺省 op + `None == None` 造成"错字段名/空白名单条件 → 静默全命中"；`engine.py:95-97` `exists` 把 `False` 当存在；`contains/eq/in` 无大小写归一（`builtin.py:439/962`）；`bulitin.py:977/888` 对 JSON 登录体失效；`builtin.py:1427` 的 `log_type eq smtp` 语义过宽且显式 log_type 被通配分支吞掉（`engine.py:350-352`）；`aggregate.py` 的 samples 只留前 3 条 + `dst_ips` 上限 50 污染基线特征。
- **Merge verdict**：**BLOCK（针对"检测质量达标"）**。引擎骨架（fail-open 路由、不静默丢弃、conn_state 单一事实来源）是合格的，但 §1.3/§1.4/§2.7(d)(e) 属于"规则看着在跑、实际不跑或判错"的静默失效，§5.3 的现实（delivered=0）意味着当前任何检测结论都没有到达分析侧——这两类必须先修，再谈 FP/FN 调优。

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "按 (1)-(6) 分节输出，每条结论给出 engine.py/builtin.py/runner.py/frequency.py/aggregate.py/normalizer.py/config.py 行号与规则名；末尾给出跨组 Top 5 结构性问题与修复建议；并在 Review 段给出 BLOCK 结论与残余风险"
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "read/grep/find/ls (只读分析；未执行任何 shell 命令或测试)",
      "result": "not-run",
      "summary": "仅做源码阅读与符号检索，未运行 pytest/构建"
    }
  ],
  "validationOutput": [
    "engine.py:249-298 _FIELD_TYPES 含 uri/rcode/answers/duration/orig_bytes/resp_bytes/proto/service/seen_bytes/server_name/issuer/request_body_len 等 UnifiedLog 中不存在的键",
    "engine.py:365-371 rules_for_log_type 返回 list(types[kind]) + list(wild)；rules/service.py:15 仅按 priority 排序 → 跨列表顺序失序",
    "runner.py:697/699 首个命中即停；runner.py:709 继续评估全部 count 规则；runner.py:514 budget 严格额度；config.py:170 24/分钟；config.py:177 1800s 超龄",
    "frequency.py:79-81 cooldown 用 set(nx,ex)；config.py:186-187 window=cooldown=300；builtin.py:1454/1474 window=21600",
    "triage_policy.py:49 SUCCESS_EVENT_TYPES 含 conn_http，全仓无生产者（只在常量与测试/文档出现）；config.py:73 白名单含 high 级规则 → triage_policy.py:172-173 永不跳过",
    "normalizer.py:536 cookie 仅取 doc.get('cookie')；normalizer.py:537 content_type 同理；zeek/site/shentong-httpheaders.zeek 只把 Cookie/Content-Type 收进 req_headers；ndr/zeek/README.md 与 tests/py/samples.py 的 http 字段清单无 cookie/content_type",
    "normalizer.py:343-357 _extract_account 正则要求 name=value 形态，无法抽取 JSON 登录体 → 密码喷洒(builtin.py:888) distinct account 永不达标",
    "shentong-policies.zeek:28-31 Log::disable_stream(Notice::LOG) → _zeek_event_type 的 notice 分支（port_scan/brute_force/tls_anomaly/protocol_anomaly/smtp_abuse）在实机不产"
  ],
  "residualRisks": [
    "未运行代码：所有'死规则/恒假条件'结论是代码路径证明，未经运行时验证（已给出反证命令）",
    "cookie/content_type 为空的结论依赖 Zeek http.log 无该列 + 仓库内的字段清单与采集脚本注释（置信度中高，未在实机 ES 文档上核验）",
    "未评估 agent 侧（智能体图/模型）对摘要的解释行为，也未评估前端展示口径"
  ],
  "noStagedFiles": true,
  "diffSummary": "无 diff：本次为只读评审，未修改任何文件",
  "reviewFindings": [
    "P0: engine.py:249-298 _FIELD_TYPES 无 dst_ip owner → builtin.py:660 云元数据访问的 dst_ip 分支在 conn 日志上永不求值（SSRF 真实取证路径漏报）；builtin.py:308 SSRF 同样无 conn 覆盖",
    "P0: normalizer.py:536 cookie 无 Zeek 来源 → builtin.py:284/676 cookie 条件恒假（Shiro 利用漏报）、builtin.py:943 会话跨IP复用（p8 critical）条件 log_type=http 与 cookie exists 两侧永不同真 = 永不触发",
    "P1: config.py:73 policy_skip_rules 含 high 级规则「内置-恶意文件传输」→ triage_policy.py:172-173 的 severity<medium 门槛使它永不生效（死配置）",
    "P1: triage_policy.py:49 SUCCESS_EVENT_TYPES 含无生产者的 conn_http（全仓仅常量+测试）→ 一旦把低危 HTTP 规则加入跳过白名单，真实成功的 HTTP 告警会被当'无成功连接'跳过",
    "P1: config.py:186-187 window==cooldown=300s + frequency.py:79-81 → builtin.py:1454/1474（6h 窗）每 5 分钟重复触发，单主机 6h 最多 72 条 high 摘要",
    "P1: config.py:57 agent_push_url 缺省空 → runner.py:_flush 的 outcome=='off' 把每条摘要 ack 并计 undelivered（与 delivered=0/undelivered 41880 一致），当前所有检测结论都未到达分析侧",
    "P2: engine.py:90 缺省 op='eq' + engine.py:95-100 的 None==None → 错字段名或 'whitelist':[{}] 会静默全命中/停用规则；engine.py:95-97 exists 把 False 当存在",
    "P2: builtin.py:977/888 正则要求 name=value，JSON 登录体（现代主流）漏报；builtin.py:439/962 的 method in/eq 无大小写归一可被小写方法绕过",
    "P2: builtin.py:1427 的 log_type eq smtp 使每一封正常邮件命中 medium；显式 log_type 被 engine.py:350-352 的通用字段子句吞掉转通配",
    "P2: aggregate.py samples 只留最早 3 条 + _MAX_SET=50 被 baseline 复用为 distinct_dst_ips → >50 扇出后 2σ 基线失真、证据样例常是探活请求"
  ],
  "manualNotes": "本组为跨切面（引擎语义+执行链路）评审，非 diff 评审，因此 Findings 按 P0/P1/P2 列出当前代码的具体缺陷，并要求与真实 diff 一起看时按'由该 diff 造成/使可达'过滤。另注：内置规则里明确无误的部分已在 §2.1 与 Review 的 Correct 段列出（status_code/dst_port 的 int 类型、数字操作符脏值安全、JA3 空列表安全默认、not/空条件组的引擎实现、丢弃与跳过的计数可见性）——不要把它们当问题修。"
}
```