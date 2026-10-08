## 本组小结

| 规则名 | 结论 | 一句话 |
|---|---|---|
| 内置-高频认证失败(856) | 需修（阈值/级别 + 上游误标） | min_count=10 基于被误标的 `brute_force`，5 分钟内 10 次正常 SSH 登录就报 critical |
| 内置-登录接口爆破(870) | 需修（误报为主） | key 只有 src_ip、无失败条件，NAT 出口下 5 分钟 15 次正常登录= critical 爆破 |
| 内置-密码喷洒(888) | 需修（误报为主） | 同一 NAT 出口 5 个员工登录= 5 个账号 → critical 密码喷洒，本组最大误报源 |
| 内置-撞库(907) | 需修（误报 + 阈值） | 3 个源 IP/5 分钟即 critical，共享服务账号、移动端切网、多出口必然命中 |
| 内置-HTTPBasic凭证暴力(926) | OK（建议微调） | 条件与语义基本对得上；建议补白名单、只计 401、key 加 dst |
| 内置-会话跨IP复用(943) | 疑似死规则(P1) | http 链路 `cookie` 恒空，规则永不触发 |
| 内置-明文凭证传输(962) | 需修（漏报 + 误报） | 只认 dst_port=80，8080 等明文登录全漏；内网登录页高误报 |
| 内置-默认口令尝试(977) | 需修（漏报 + 描述不符） | 只认 `=` 形态，JSON `"password":"admin"` 全漏；OR 分支未写进描述 |
| 内置-Token/JWT异常使用(999) | 需修（严重误报） | bearer 分支对**每一个**带 Bearer 头的请求命中，与描述"高频使用"矛盾 |
| 内置-密码重置接口滥用(1017) | 需修（正则过宽） | `(?i)/(reset\|forgot\|password…)` 未锚定，/password-policy、/password/strength 都算 |

---

### 内置-暴力破解（builtin.py:834，priority=10，severity=high）

- 结论：严重度不当（叠加上游误标）
- 漏报：Zeek 侧永不触发（无 notice）；NTLM/RDP 之外的 Web/API 爆破不产出 `brute_force`，只能靠 870/888 兜。
- 修复建议：① 治本在 `normalizer.py:835`，把 `"sshd"` 从 `brute_force` 判据里去掉（改为只在 groups 含 `authentication_failed*` 或描述含 "failed password"/"brute" 时判 `brute_force`）；② 治标在本规则加 `{"not": {"field": "rule_id", "op": "in", "value": ["5715","5716"]}}` 之类的成功登录豁免，或把 severity 降到 medium、让它只作为"证据"，真正的判定交给 856。


- 结论：重复 / 被遮蔽（近似死规则）
- 误报：几乎没有（能命中的场景很少），属于"注释型规则"。
- 漏报/遮蔽：`hit = next(...)`（`runner.py` 的 `_handle`）只取第一条命中；834（priority 10 < 20）先命中 `brute_force`，所以本规则只有在"groups 含 `authentication_fail` 但没被判成 brute_force"（例如组名恰好是 `authentication_fail` 无 ed、且没被 web/attack/malware/windows 等前面的分支先吃掉）时才生效——实际近乎空跑。
- 修复建议：要么删掉（834 已覆盖），要么把它改成"未被 834 覆盖"的补集，例如只匹配 `rule_groups regex (?i)authentication_fail` **且** `{"not": {"field": "event_type", "op": "eq", "value": "brute_force"}}`，并把 severity 提到与覆盖面对齐（否则会出现"更具体的规则反而更低危"）。
- 置信度：高（normalizer 前缀/全 token 差异、priority 与 next() 语义均可查）。

### 内置-高频认证失败（builtin.py:856，priority=12，severity=critical）

- 结论：需修（阈值/级别都建立在被污染的事件类型上）
- 逻辑问题：`mode=count, key=[src_ip], min_count=10`（862-866），窗口取全局 `freq_window_seconds=300`（`config.py:186`），即 5 分钟 10 次。规则语义是"认证失败 ≥10"，但它数的是 `brute_force` 事件，而该事件类型被 `normalizer.py:835` 传染（成功登录也进）。
- 误报：Windows/Linux 域环境下一台机器 5 分钟内 10 条带 `sshd`/`authentication_failed` 的告警非常常见（含成功与失败混合）→ 单源 critical。加上 `policy_skip_rules` 默认只有两条（`config.py:73`），本规则不可能被"内网常规流量"跳过；critical 只在分析侧被压级（`agent/backend/app/agents/triage_policy.py:249-261`：内→内封顶 medium、critical 仅限外→内），但摘要照样吃掉 24 条/分钟的投递额度（`config.py:170`）。
- 漏报：慢速爆破（如 1~2 次/分钟）在 300s 窗口内到不了 10 次；规则没有 `window` 参数（对比 1017 之外的同类也没有），对"低频长时"爆破无效。
- 置信度：高（阈值/窗口/路由/限流参数全部可查；severity 上游误标为直接代码证据）。

### 内置-登录接口爆破（builtin.py:870，priority=12，severity=critical）

- 结论：需修（误报为主，本组第二大噪声源）
- 逻辑问题：`mode=count, key=["src_ip"], min_count=15`（877-884）+ `event_type eq http_login` + `method in [POST, PUT]`。key 里**只有 src_ip，没有 dst_ip，也没有成功/失败区分**——"同源"在 NAT/共享出口下等于"同一栋楼"。
- 误报（具体场景）：公司出口 NAT 一个公网/私网出口 IP，1 万号办公室 09:00 前后 5 分钟内 15 个员工分别登录 OA/邮箱/内部系统（哪怕目标是不同 dst_ip、不同账号、全部 200 成功）→ 直接 critical"登录接口爆破"。Wi-Fi 漫游/移动 App 令牌过期重登同样会凑够 15 次。`_WHITELIST_HEALTH`（`builtin.py:23-31`）只挡 /health、/metrics 与探针 UA，挡不住这个。
- 漏报：`event_type=http_login` 由 `_http_event_type`（`normalizer.py:379-383`）产生，要求 `method==POST` **且** `path` 命中 `settings.web_login_path_regex`（`config.py:115-117`）——该正则要求关键词后紧跟 `$`、`/`、`?`，所以 `/wp-login.php`（WordPress 登录页，最典型的爆破目标）、`/admin/login.do`、`/api/v2/authenticate`、`/user/sign_in` 都不算 http_login，整条链（870/888/962）一起漏。
- 修复建议：① `key` 改成 `["src_ip","dst_ip"]`（同一出口打多个站点不再累加）；② 加失败定向：`{"field": "status_code", "op": "in", "value": [401, 403, 400, 429]}`（注意部分系统失败返回 200，可用 `distinct: "account"` + `min_distinct: 5` 替代）；③ `min_count` 提到 30；④ 登录路径正则补 `\.php|\.do|\.action|authenticate|sign_in` 后缀形态（改 `web_login_path_regex` 或规则侧自建判断）。
- 置信度：高（条件与配置项均可查；误报机理由 key 构成与 `count_key` 实现决定）。

### 内置-密码喷洒(同源多账号)（builtin.py:888，priority=8，severity=critical）

- 结论：需修（本组最大误报源）
- 逻辑问题：`key=["src_ip"], min_count=5, distinct="account", min_distinct=5`（894-902）。5 分钟窗口内同源出现 5 个不同账号即 critical。语义上"密码喷洒"确实看多账号，但**少了两个必要限定**：没有失败条件（改成"成功登录 5 个账号"反而更像横向/共享终端）、没有排除内网源。
- 误报（具体场景）：NAT 出口场景下 5 个员工 5 分钟内分别登录（5 个不同账号、全部成功、目标是不同系统）→ critical"密码喷洒"。共享终端/收银台/营业厅/教室机也天然满足。移动端用户切 Wi-Fi↔4G 时同账号多 IP 由 907 命中的同时，还可能与其他账号拼成 888。
- 漏报：`account exists` 依赖 `_extract_account`（`normalizer.py:343-354`）：① 路径必须先命中 `web_login_path_regex`；② 字段名必须命中 `account_form_fields`（`config.py:91` = `username,user,email,login,account,uname,userid`）且正则要求字段名前有 `^`/`&`/`;`/`,`/空白 分隔——所以 `j_username=alice`（Spring Security 默认）、`loginName=`、`user_name=` 都提取不到 → 账号为空 → 规则永不触发（这正是实机上 account 非空仅约 1.37 万/340 万条的主因之一：只有"登录路径 + 白名单字段名 + 采到 body/query"的极小子集才填 account）。
- 修复建议：① 加方向限定 `{"field": "src_external", "op": "eq", "value": True}`（或加 `dst_external`）避开内网 NAT 误报；② 加失败定向（status 401/403 或 `account` 计数与失败事件绑定）；③ 阈值提到 `min_count: 10, min_distinct: 8`，severity 降 high；④ `account_form_fields` 补 `j_username,loginname,user_name,userid,email,phone`，并把分隔符类放宽为 `(?:^|[&;,\s\[\{])`（同时覆盖 `user[username]=` 这类表单）。
- 置信度：高（阈值/窗口/字段提取三处代码可查；account 稀疏由提取条件决定）。

### 内置-撞库(同账号多源)（builtin.py:907，priority=8，severity=critical）

- 结论：需修（阈值过低 + 无方向/账号类型限定）
- 逻辑问题：`key=["account"], min_count=3, distinct="src_ip", min_distinct=3`（913-921）。"3 个源 IP / 5 分钟"对撞库来说太敏感：真实撞库是"多账号 × 多 IP × 长时段"，单账号 3 个 IP 更像正常用户多设备。
- 修复建议：① `min_count/min_distinct` 提到 5；② 加 `{"field": "src_external", "op": "eq", "value": True}`（撞库通常来自外部），或至少要求 `dst_external`；③ severity 降 high（现在与"扫描尝试/恶意文件"之外的任何 critical 同级，会把 critical 通道挤满）；④ 用排除过滤器把已知服务账号剔掉。
- 置信度：高（阈值/窗口/key 与方向判定代码均可查）。

### 内置-HTTPBasic凭证暴力（builtin.py:926，priority=N/A（count），severity=high）

- 结论：OK（建议微调，不算 bug）
- 误报：配置了旧口令的客户端（IoT 设备、备份脚本、老旧 SOAP 客户端）会每几秒轮询一次并持续 401，5 分钟轻松 15 次 → high。这类"凭证失效"确实值得看，但和"爆破"不是一回事；规则没有 `_WHITELIST_HEALTH`（对比 870 有），探针类 UA 也会计入。
- 漏报：`status_code in [401,403]` 是**取交集**（`in` 为精确相等，engine.py `_match`），对只回 401 的正常服务没问题；但只统计"同源次数"、不区分目标，NAT 场景同样会把多个内网 Basic 服务累加；另外 `auth_scheme` 只认 `Authorization` 头，`X-Auth-Token`/Cookie 里的 Basic 不覆盖（属既有取舍）。
- 修复建议：加 `_WHITELIST_HEALTH`（与 870 保持一致），`key` 改 `["src_ip","dst_ip"]`，`min_count` 提到 30，或要求 `status_code eq 401` 且 `dst_external eq True` 作为"面向外部服务的 Basic 爆破"。
- 置信度：高（auth_scheme 填充路径有单测与 normalizer 代码双重证据）。

### 内置-会话跨IP复用（builtin.py:943，priority=N/A（count），severity=critical）

- 结论：**疑似死规则（P1）**
- 误报：无（因为不触发）。
- 漏报：整类会话劫持/凭证盗用检测空缺，而且是 critical 位空缺。旁证：同因同源的 `cookie` 规则（`内置-反序列化特征` 的 `rememberMe=`、`内置-框架漏洞探测特征` 的 `rememberMe=|shiro`）在 Zeek 上同样永不命中——`cookie` 是一个"schema 有、采集不填"的死字段。
- 修复建议：治本在采集/归一化——把 `Cookie:` 头从 `req_headers` 解析进 `cookie`（照 `_auth_from_headers`/`_AUTH_HEADER_RE` 的既有做法，`normalizer.py:319-328`，正则示意 `re.compile(r"(?im)^[ \t]*cookie[ \t]*:[ \t]*([^\r\n]+)")`）；治标方案是改规则：`{"field": "cookie", "op": "exists"}` 换成"对 `req_headers` 的 contains（正则不可用，因为 engine 不支持对 req_headers 解码，但 contains 可用）"，即 `{"field": "req_headers", "op": "contains", "value": "SESSION"}` 之类，key 也换成 `["req_headers"]`（注意 `count_key` 用 getattr，`req_headers` 是真字段，可行，但会把整串头值当 key，建议先落地解析字段）。
- 置信度：高（规则条件 + 归一化字段来源 + Zeek 脚本输出字段三处对齐；未在实机 ES 采样验证，但代码路径是唯一来源）。

### 内置-明文凭证传输(HTTP登录)（builtin.py:962，priority=15，severity=high）

- 结论：需修（漏报 + 内网高误报）
- 逻辑问题：`event_type eq http_login` + `dst_port eq 80` + `method eq POST`（968-971），AND 语义与描述"HTTP（非 TLS）端口上出现登录"只对了"80"这一种。Zeek 的 `http.log` 本身就是明文 HTTP（分析器按特征识别，不限端口），把 `dst_port=80` 当"明文"判据既多余又造成漏报。
- 误报（具体场景）：内网一律是明文 HTTP 登录——OA、报表、监控台、打印机管理页、工单系统。任何内网 POST 登录页命中即 high；`policy_skip_rules` 不含本规则（`config.py:73`），只有"内→内 + 单目标 + 无成功连接 + 级别<medium"才可能被跳过，而登录是成功连接（`has_success` 里有 `conn_http`），所以照旧全量进分析。
- 漏报：① 端口只认 80，`8080/8000/8081/8888/3000/5000` 上的明文登录全漏（这些在 Zeek 同样进 http.log）；② 继承 `http_login` 的判定缺陷（`/wp-login.php`、`/admin/login.do` 等不算 http_login，见 870）；③ GET 型登录（老系统 `GET /login?user=&pass=`）不报。
- 修复建议：① 删掉 `dst_port eq 80`，改为 `{"field": "dst_port", "op": "in", "value": [80, 8080, 8000, 8080, 8081, 8888, 5000, 3000, 8008]}`（或直接去掉端口条件，因为 http.log 已是明文）；② 加 `{"field": "dst_external", "op": "eq", "value": True}` 只报"明文凭证出网"，内网明文登录降为低危规则（另开一条 severity=low 的"内网明文登录面"），避免与 870 一起把内网登录刷成告警墙；③ 若要保留内网覆盖，就把本规则改成 count（`min_count: 5`）以压噪。
- 置信度：高（条件、Zeek 日志语义、策略跳过条件均可查）。

### 内置-默认口令尝试（builtin.py:977，priority=15，severity=high）

- 结论：需修（漏报 + 描述与实现不一致）
- 逻辑问题：`logic: "or"`，两条分支分别是 `body` 与 `query` 的 `(?i)pass(word)?=(admin|123456|root|test|guest|admin123)`（983-995）。描述只写"请求体中出现"，实现却把 `query` 也算进来；且条件里**没有** `event_type`/`method` 限定，任何请求（含 GET 文档、含上传的配置文件正文）只要正文里出现该字符串就命中。注意 engine 对 `body`/`query` 会额外匹配 URL 解码变体（`_DECODE_FIELDS`，engine.py:41），所以 `password%3Dadmin` 是能命中的。
- 误报：① 安全培训/渗透测试/工单里粘贴的示例正文（`password=admin` 出现在 Wiki、Issue、聊天记录、样例配置文件里）；② 运维改配时表单里有 `admin_password=admin`（`pass(word)?=` 是子串匹配，`admin_password=admin` 里的 `password=admin` 会被搜到）；③ 参数名撞车：`?newpassword=root`。
- 漏报：① JSON/XML 形态（现代 API 主流）：`{"username":"admin","password":"admin"}` 用的是 `":"` 不是 `=` → 永不命中（分支只写 `=`）；② `pwd=`、`passwd=`（注意 `pass(word)?=` 里 `passwd` 不匹配，因为 `word` 与 `wd` 不是同一分支）、`user_pass=`、`Passwd:`、Base64 提交；③ 缺少 `admin@123/admin888/P@ssw0rd/qwerty/1qaz2wsx/12345678/root123/test123/oracle/postgres/tomcat/jenkins/guest123/changeme` 等高频默认口令（`password=admin1` 能命中，因为 `admin` 是前缀子串）。
- 修复建议：给两条分支补上分隔符与形态，并加登录上下文与成功态：
  - body 分支：`(?i)["'\s&,;{]?(pass(word|wd)?|pwd)["'\s]*[=:]\s*["']?(admin@?123|admin888|admin|12345678|123456|root123|root|test123|test|guest|changeme|P@ssw0rd|qwerty|1qaz2wsx|oracle|postgres|tomcat|jenkins)["'\s&;,}]`
  - 加一条 `{"field": "event_type", "op": "in", "value": ["http_login", "http_upload"]}` 或 `{"field":"uri_path","op":"regex","value":"(?i)/(login|signin|auth|admin)"}` 作为上下文（避免正文里随便提到就报），并把 `status_code in [200,302]` 作为"可能成功"的加权证据（条件树不支持加权，可拆成两条规则：低危"尝试" + 高危"尝试且成功"）。
- 置信度：高（regex 行为、解码字段集合、`_http_event_type` 来源均可查）。

### 内置-Token/JWT异常使用（builtin.py:999，priority=20，severity=medium）

- 结论：需修（严重误报 + 实现与描述矛盾）
- 逻辑问题：`logic: "or"`，第二条分支 `{"field": "auth_scheme", "op": "in", "value": ["bearer", "jwt"]}`（1011）**单独成立**即命中——即"只要这个请求带了 Bearer 令牌"。规则描述写的是"Bearer/JWT 令牌出现在 URL 参数**或被用于高频请求**"，高频这个限定完全没有实现。`auth_scheme` 的取值是 `Authorization` 头的第一个 token 小写化（`normalizer.py:331-341`，单测 `tests/py/test_rules_routing.py:106-118` 证实 Zeek 侧现在能填）——也就是说，**所有**用 Bearer 认证的 HTTP 请求都命中。
- 误报（具体场景）：任何一个前后端分离的内网应用（SPA + REST API），用户刷一次页面就是几十个带 `Authorization: Bearer eyJ...` 的 XHR；每个 src_ip 每 5 分钟聚合出一条摘要（`aggregate.py:32-39`，`detector_agg_seconds=300`），几十个内网客户端就能把 24 条/分钟的投递额度（`config.py:170`）吃满，其他真正的 high/critical 摘要被回队、超龄后被丢（`_flush` 的 requeue/expired 逻辑），是"真告警被挤掉"的典型原因。
- 漏报：① 只用 `Authorization` 头取 scheme，`X-Auth-Token`/`Authorization: ApiKey`/Cookie 里的会话令牌不覆盖；② URL 分支要求值以 `ey` 开头，不透明 token（`?token=abc123...`、`?api_key=`）不命中（属有意取舍）；③ 描述里的"高频使用"完全没实现，所以"同一 token 被反复使用/多 IP 复用"这个真正有价值的信号缺失。
- 修复建议：拆成两条——
  1) URL 里的 JWT（保留现分支）：`(?i)(token|jwt|access_token|id_token|refresh_token|idtoken)=ey[A-Za-z0-9_-]{10,}\.` （补 `refresh_token`，并要求出现 `.` 段提高 JWT 置信度）；
  2) Bearer 的异常使用改成低频信号：`mode: count, key: ["src_ip"], min_count: 60, window: 300` 且 `rules: [{"field":"auth_scheme","op":"in","value":["bearer","jwt"]}]`，或改成"Bearer + 明文端口"（`dst_port in [80,8080,...]` → token 明文出网）——后者单一事件即可报，且几乎不误报。
- 置信度：高（auth_scheme 来源、or 短路语义、聚合与限流参数均可查）。

### 内置-密码重置接口滥用（builtin.py:1017，priority=15，severity=high）

- 结论：需修（正则过宽导致误报；与 870 语义重叠）
- 逻辑问题：`mode=count, key=["src_ip"], min_count=10`（1024-1033），唯一条件是 `uri_path regex (?i)/(reset|forgot|password|passwd|recover|unlock)`（1030-1031）。既没锚定（`re.search`，engine.py 的 regex 是子串搜索），也没有方法/状态码/目标限定，任何"路径里含 /password 或 /unlock"的 GET 都计入。
- 误报（具体场景）：① 自服务改密页面自带的前端校验接口（`/api/password/strength`、`/api/password/policy`）会被逐字输入触发，10 次/5 分钟极容易；② `/account/password` 页面 F5 刷新 10 次；③ `/docs/unlock-instructions`、`/help/recover-guide`、`/admin/password-policy`；④ NAT 出口下 10 个员工点"忘记密码"（正常操作）→ 同源 10 次 → high。
- 漏报：`/pwd/reset`（`pwd` 不在列表）、`/api/v1/account-recovery`（`recovery` 不匹配 `recover`？——实际 `recovery` 含 `recover`，能命中）、`/forgot-password-email`（含 `/forgot` 能命中）；真正漏的是非 GET/POST 无关紧要，主要漏法是"重置接口路径不含这些词"的自研命名（`/api/auth/otp/resend`）。
- 修复建议：把正则收紧为"路径段边界"并排除 UI/统计类：`(?i)^/(?:[^/]+/)*(?:password|passwd|pwd|reset|resetpassword|forgot|recover|unlock)(?:[/?.]|$)`，并加 `{"field":"method","op":"in","value":["POST","PUT"]}`、`{"field":"status_code","op":"in","value":[200,201,202,302]}`，`min_count` 提到 30；同时明确与 870 的分工（870 抓"登录接口爆破"，本条只抓"重置/解锁类接口"，现在 `web_login_path_regex` 里含 `password`，POST `/password/reset` 会同时算 http_login，两条 count 规则重复计数、重复告警）。
- 置信度：高（regex 语义 + 路径样例可推导；未在实机流量上验证误报条数，故误报量级标注为"按条件推演"）。

### 内置-多账号同机登录（builtin.py:1037，priority=18，severity=medium）

- 结论：需修（误报/空键归并 + 与 888 语义重复）
- 修复建议：① 条件补 `{"field": "src_ip", "op": "exists"}`（这能同时消灭 `-` 归并误报，`exists` 对空串返回 False，engine.py `_match`）；② 若要保留"netflow 侧共享终端"的覆盖，另外加 `dst_external eq True` 或改成 key `["src_ip","dst_ip"]`；③ 与 888 合并成一条不限定 `log_type` 的 count 规则（同一语义，两个 log_type 两套阈值会让同一行为报两次）。
- 置信度：高（空键归并、exists 语义、src_ip 缺失时 direction=unknown 均在代码里可查）。


- 结论：需修（漏报为主 + 被高优规则遮蔽）


- 逻辑问题：`logic: "or"`，第一条 `rule_groups regex (?i)(privilege_escalation|sudo|su_)`（1084-1085）**没有区分成功/失败**，也没有级别门槛；第二条 `summary regex (?i)(privilege escalation|sudo:|su: )`（1088-1089）反倒偏向"失败/命令行"文本。两条分支的严格程度不对称：只要组串里出现 `sudo` 就 high。

---

## 本组 Top 3 问题

2. **账号类 count 规则在共享出口/服务账号下必然误报，而且是 critical**：`内置-密码喷洒`（888，5 账号/5 分钟）= 一个 NAT 出口 5 个员工登录；`内置-登录接口爆破`（870，15 次/5 分钟）key 只有 src_ip、无失败条件，同一出口 15 次正常登录即 critical；`内置-撞库`（907，3 个源 IP/5 分钟）被移动端切网和多出口 IP 打穿。三条都要补"是否失败""是否涉内网源""key 是否含 dst_ip"这三类限定（具体条件见各条 修复建议）。
3. **`内置-Token/JWT异常使用`（999）的 `auth_scheme in [bearer,jwt]` 分支命中每一个 Bearer 请求**：所有前后端分离应用的正常 API 调用都会命中（与描述里的"高频使用"完全不符），按 (src_ip, 规则) 每 5 分钟产一条摘要，几十个客户端即可吃满 24 条/分钟的投递额度并把真正的 high/critical 摘要顶掉。应改为 count（≥60 次/5 分钟）或"Bearer + 明文端口"这类真正异常的形态。

**另外必须一并处理的上游两点**（不在本组行号内，但决定了本组一半规则的成败）：
- `_http_event_type`/`web_login_path_regex`（`normalizer.py:379-383`、`config.py:115-117`）漏掉 `/wp-login.php`、`/admin/login.do`、`/api/v2/authenticate`、`/user/sign_in` 等常见登录形态 → 870/888/962/1020 一起漏报；`account_form_fields`（`config.py:91`）的字段名与分隔符限制又把 `j_username`、`user_name` 类表单的 account 提取漏掉。

