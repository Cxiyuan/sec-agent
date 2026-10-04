# B 组（注入 / 漏洞利用）规则评审 · builtin.py:79-375（13 条）

## 本组小结

| 规则名 | 结论 | 一句话 |
|---|---|---|
| 内置-SQL注入-基础特征（81） | 需修（FN 不对称 + FP 边界） | body 分支少了 `and 1=1`，注释绕过漏；正文里贴 payload（工单/LLM 对话）必误报 |
| 内置-SQL注入-元数据与文件读写（103） | 需修（轻微） | body 分支缺 `pg_sleep`；`information_schema` 在 DBA/BI 工具流量上会报 high |
| 内置-NoSQL注入（125） | 需修（FN） | 只认 5 个操作符，`$or/$in/$expr/$function` 等常见注入全漏 |
| 内置-命令注入特征（147） | 需修（FN 为主） | 必须「分隔符+命令后跟空格」才命中：`;id`、`\|id`、`&&id`、换行分隔全漏；`\|` 分支外反引号分支过宽 |
| 内置-路径穿越-编码变体（169） | 严重度不当 + FN | 裸 `../` 就定 high 太宽（还遮蔽 LFI 归因）；`..%252f`/`..;/`/`....//` 漏 |
| 内置-XSS/脚本注入特征（197） | 需修（FP+FN） | 富文本/JSON 正文必报；`svg onload`、`onmouseover`、`srcdoc` 等漏 |
| 内置-模板注入SSTI（219） | 严重度不当（FP 大） | `{{...}}`/`${...}` 在 Helm/Jinja/CI/YAML 正文上定 high；`{% %}`、body 的 `#{}`/`<%=` 漏 |
| 内置-表达式注入与JNDI(Log4Shell)（241） | 需修（严重 FP + FN） | `ognl\|spel` 子串让 `spellcheck` 报 critical 且 priority 5 抢命中；req_headers/Cookie 头向量完全不看 |
| 内置-XXE外部实体注入（266） | OK（小瑕疵） | `<!ENTITY`/`<!DOCTYPE[` 覆盖够用；`SYSTEM` 只认 file/http，但别的 scheme 由文件包含规则兜住 |
| 内置-反序列化特征（284） | 疑似死条件 + 严重度不当 | `cookie` 字段 Zeek 路径恒空（Cookie 值只在 `req_headers`），line 298 的 rememberMe 分支永不触发；弱证据也定 critical |
| 内置-SSRF敏感参数与协议（308） | 需修（FP 大 + FN 大） | `redirect_uri=/next=https://` 正常 SSO 误报；**完全没有 body 条件**，JSON SSRF 漏；云元数据只知 169.254 |
| 内置-文件包含/协议流（336） | 需修（FN，小） | `data:`（单斜杠，浏览器常见 data URI）漏、`php://temp/fd` 漏；FP 很低 |
| 内置-CRLF/响应头注入（358） | 需修（FP） | 任意 `%0d%0a` 即命中（表单多行文本很常见）；`%0a` 单换行注入漏；`%0a%0d` 是死分支 |

**组内共性（先说清楚，后面不再重复）**

- **操作符语义**：`regex` = `re.search`（子串匹配，无锚点）、`contains` = 区分大小写子串、`in` 精确匹配、`exists` 要求非空串；`query/query_string/uri_path/body/referer/filename` 在 contains/regex 时会**额外匹配 unquote / unquote_plus 一次**的结果（`engine.py:107-123`）；字段为空 → 候选文本为空 → regex 返回 False（`engine.py:96-105`）。
- **命中即停**：`hit = next((r for r in candidates if match_rule(r, entry)), None)`（`runner.py:697-699`），规则按 priority 升序（`rules/service.py:15` 只 `order_by(Rule.priority)`，**同优先级没有二级排序键**）。
- **本组 13 条全部是单层 `logic: "or"`，没有 AND 混挂多类型专有字段**，所以任务里点名的「混合专有字段 → AND 恒不成立 → 死规则」在本组**不存在**；但存在一个**分支级死条件**（反序列化的 `cookie`，见下）。
- **路由**：本组用到的字段 `query`（dns/http/wazuh）、`body`/`user_agent`（http/wazuh）在引擎表里都有归属，`referer`/`cookie` **不在 `_FIELD_TYPES`**（`engine.py` 的 `_FIELD_TYPES`），只影响 owner 计算，不造成死规则。
- **triage 不影响本组**：`policy_skip_rules` 默认只有 `["内置-扫描尝试连接","内置-恶意文件传输"]`（`config.py:73`），本组 13 条不在名单里，内网常规策略不会跳过它们；但 `severity_cap_internal="medium"` / `severity_critical_requires_external=True`（`config.py:77-79`）会把**内→内**的 Log4Shell / 反序列化 critical **降级到 medium**（横向移动场景的代价，属既定取舍，不算 bug，但要知道）。
- **投递预算是共享的**：`_rate_remaining` 用 `settings.detector_max_digests_per_minute`（`runner.py` 限流函数），命中按（源IP+规则）聚合成摘要后受每分钟额度限制，超额回队/超龄丢。**任何一条高噪声规则都会挤掉真检测**——下面多个 FP 的严重性都建立在这条上。

---

### 内置-SQL注入-基础特征（builtin.py:81-101，priority=10，severity=high）

- **结论**：需修（FN 不对称 + FP 边界）
- **逻辑问题**：`logic: "or"` 与「URL 或参数」描述一致，没有 AND/OR 错配。问题在**两个分支能力不对等**：query 分支有 `or\s+1\s*=\s*1|and\s+1\s*=\s*1`，body 分支**只有** `or\s+1\s*=\s*1`（没有 `and 1=1`）。
- **误报**：`body` 是「正文里的任何子串」。真实场景：安全培训/靶场平台、工单系统、以及**LLM 对话类应用**（本项目自己就带模型分析）里，用户正文写「为什么 `or 1=1` 能绕过登录」→ 直接 `high`；`sleep\s*\(`、`benchmark\s*\(` 也会被 JSON 正文命中，例如定时任务接口 `{"delay":"sleep(1000)"}`。triage 不会跳过（severity high），命中按（源IP+规则）聚合成摘要**占用 24/分钟额度**。
- **漏报**：① body 里 `and 1=1` 恒不报（两分支能力不一致，证据：query 分支有、body 分支无）；② 经典变体全漏：`' or '1'='1`、`or 2>1`、`1=1--`、`' or 1=1#`；③ **注释绕过** `union/**/select`、`union%09select`（`\s+` 不含 `/`）漏，`union distincy select` 也漏；④ 报错型注入 `extractvalue(` / `updatexml(` / `convert(` 完全没覆盖。
- **修复建议**（可直接抄，query 与 body 两分支用同一份）：
  `(?i)(union(?:\s|/\*.*?\*/|\+)+(?:all\s+|distinct\s+)?select|(?:or|and)\s+['"\d]+\s*(?:=|<|>)\s*['"\d]+|(?:sleep|benchmark|pg_sleep|extractvalue|updatexml)\s*\(|waitfor\s+delay)`
  并在该规则加 `whitelist`（见「组内共性」里的 `_WHITELIST_HEALTH` 写法）覆盖自家靶场/培训路径，或把「正文里出现 payload 且 `content_type` 为文本聊天」的场景交给排除过滤器。
- **置信度**：高（差异在源码中可直接比对；`re.search` 语义确定）

### 内置-SQL注入-元数据与文件读写（builtin.py:103-123，priority=10，severity=high）

- **结论**：需修（轻微，FN + 少量 FP）
- **逻辑问题**：同样是 or，一致。**两个分支不对称**：query 分支有 `pg_sleep`（第 114 行一带），body 分支（builtin.py:119，grep 已确认该行）没有 `pg_sleep` → PostgreSQL 时间盲注走 POST 时漏。
- **误报**：`information_schema` 是**合法库管/BI 工具的高频词**（Adminer/phpMyAdmin/自研 SQL 控制台把 SQL 放 POST body）→ high。可行降噪：给该规则加 whitelist（`uri_path` 命中自家 DB 控制台路径）或用排除过滤器按规则名关。
- **漏报**：`into/**/outfile`、`load_file/**/(`（注释穿插）漏；PostgreSQL `copy ... to program`、`lo_export(`、MSSQL `sp_configure`/`OPENROWSET`、SQLite `load_extension(` 未覆盖。
- **修复建议**：body 分支补 `pg_sleep`；两分支统一为
  `(?i)(information_schema|into\s+(?:out|dump)file|load_file\s*\(|xp_cmdshell|pg_sleep|copy\s+\w+\s+to\s+program|lo_export\s*\(|load_extension\s*\()`
- **置信度**：高（两分支源码差异证据确凿）

### 内置-NoSQL注入（builtin.py:125-145，priority=12，severity=high）

- **结论**：需修（FN 为主）
- **逻辑问题**：`(?i)(\$ne|\$gt|\$regex|\$where|\$exists)` 对 query/body 各一次，逻辑没错；问题是**操作符白名单太窄**，而 `(?i)` 对 `$` 操作符其实没有意义。
- **误报**：较低但有：任何把**合法 MongoDB 查询 JSON** 传给管理/BI 接口的流量（`{"$gt": ...}` 形式的查询 DSL）会报 high；`$ne` 是子串，`$new`/`$net` 之类含 `$ne` 的文本也会误命中（无边界锚点）。
- **漏报**（重点）：认证绕过的常见 payload 是 `$or` / `$and` / `$in` / `$nin` / `$not` / `$expr` / `$function` / `$accumulator`：`{"username":"admin","password":{"$ne":null}}` 能命中，但 `{"$or":[{"u":"admin"},{"p":{"$gt":""}}]}` 里若只用 `$or` 就漏；Mongo 服务端 JS 执行 `$where`/`$function` 的变体 `{"$function":...}` 也漏；`' || '1'=='1`、`';return true;var x='` 这类 JS 注入漏；`\u0024` 转义的 `$ne` 也漏（引擎只做 URL 解码，不做 JSON unicode 解码）。
- **修复建议**：用「操作符当 JSON key」的上下文把 FP 压住，同时把操作符补齐：
  query（GET 形态）：`(?i)\[(?:\$?(?:ne|gt|gte|lt|lte|regex|where|exists|in|nin|or|and|not|expr|function|accumulator))\]`
  body：`(?i)"\$(?:ne|gt|gte|lt|lte|regex|where|exists|in|nin|or|and|not|expr|function|accumulator|jsonSchema)"\s*:`
  再补 JS 注入分支：`(?:'|")\s*(?:\|\||&&)\s*(?:'|")?\s*1\b`
- **置信度**：高（操作符清单差异是源码事实）

### 内置-命令注入特征（builtin.py:147-167，priority=10，severity=high）

- **结论**：需修（FN 为主，另有 1 处过宽）
- **逻辑问题**：query 分支 `;\s*(cat|ls|id|...)\s` **要求命令后必须跟空白**，这导致「`;id` 结尾」这种最常见写法恒不命中（正则不是 `\b`，是 `\s`）。body 分支只有 `;`、`/bin/(sh|bash)`、`cmd.exe`、`powershell\s+-`、`\$\(`，**没有 `|`/`&&`/换行分隔**。
- **误报**：query 分支的反引号分支 `` `[^`]+` `` 是「任意一对反引号」→ 用户搜 Markdown 代码片段 `?q=%60npm%20install%60`、文件名带反引号的请求都会报 high。
- **漏报**：`;id`、`|id`、`||id`、`&&whoami`、`%0acat /etc/passwd`（换行分隔命令是标准注入手法）、`$(id)` 只在 body 有（query 没有）、`;uname`/`;nc` 只在 query 有（body 没有）、Windows `cmd /c`、`powershell.exe -enc`、`pwsh -c`、`%COMSPEC%`、`${IFS}` 分隔符、`$'\x69'd` 混淆。
- **修复建议**（query 与 body 统一）：
  `(?i)(?:;|\||&&|\|\||%0a|%0d|\$\(|`)\s*(?:cat|ls|id|whoami|uname|hostname|curl|wget|nc|ncat|bash|sh|python[23]?|perl|php|echo|rm|touch|chmod|base64|xxd|ping|nslookup)\b|/bin/(?:sh|bash)|cmd(?:\.exe)?\s*/c|powershell(?:\.exe)?\s+[-/\w]*c\b|pwsh\b|\$\{IFS\}`
  若担心反引号 FP，把反引号分支限定成「反引号内是命令名」：`` `\s*(?:cat|ls|id|whoami|curl|wget|nc|bash|sh)\b[^`]*` ``
- **置信度**：高（`;id` 不匹配是 `\s` 的后缀要求决定的，可静态判定）

### 内置-路径穿越-编码变体（builtin.py:169-195，priority=10，severity=high）

- **结论**：严重度不当 + FN
- **逻辑问题**：4 个条件 OR：裸 `\.\./|\.\.\\`、编码变体、敏感文件、body（`\.\./|\.\.\\|/etc/passwd`）。条件之间是「同类不同粒度」混在一条里，导致**同一 payload 的归因随条件顺序漂移**（见「重复/遮蔽」）。另外 body 分支只查 `\.\./|\.\.\\|/etc/(passwd|shadow)`，**丢了 query 分支有的 `/proc/self|win\.ini|boot\.ini`**。
- **误报**：裸 `../`（含 `..\`）在第一条件里**没有任何上下文要求**，正常业务命中面很大：老系统的相对资源参数 `?src=../images/logo.png`、文件管理/网盘类接口 `?path=../docs`、代码检索 `?q=../`。定 high 偏高。
- **漏报**：① `..%252f`（**双重编码的斜杠**）——引擎只 unquote 一层的解码结果是 `..%2f`，第一条件要 `../`、第二条件列的是 `%2e%2e%2f`/`\.\.%5c`（`..%5c`），都不匹配 → 恒不报（`%2e%2e%252f` 反而能报，因为解码成 `%2e%2e%2f`）；② Tomcat/Spring 的 `..;/`（分号绕过）——`\.\./` 要求斜杠紧随点，`..;/` 不匹配，也不解码；③ 过滤绕过 `....//....//etc/passwd` 里若目标不是清单内文件（如 `/WEB-INF/web.xml`、应用自身配置）就漏；④ 单层编码 `..%2f` 靠引擎解码兜住（解码成 `../`），**属于巧合而非规则设计**。
- **修复建议**：拆成两条严重度不同的规则，或至少收窄泛化分支：
  - 高危（保留 high）：`(?i)(?:\.\.[/\\%]|%2e%2e[/\\%])(?:\.\.[/\\%]|%2e%2e[/\\%])|\.\.(?:%2f|%5c|%252f|%255c|;/)`
  - 中危（改 medium）：`(?i)\.\.[/\\](?:etc|proc|root|var|home|usr|windows|boot|sys|WEB-INF|META-INF)[/\\]`
  并给 body 分支补 `/proc/self|win\.ini|boot\.ini`。
- **置信度**：高（`..%252f` 的漏报可由 `_DECODE_FIELDS` 单层解码 + 正则字面量静态推出）

### 内置-XSS/脚本注入特征（builtin.py:197-217，priority=15，severity=medium）

- **结论**：需修（FP + FN）
- **逻辑问题**：query 分支（builtin.py:208）含 `<script|</script|javascript:|onerror=|onload=|alert(|document.cookie|<img[^>]+src=`；body 分支（builtin.py:213）只有 `<script|javascript:|onerror=|document.cookie`——**两分支能力不一致**（`<img src=`、`onload=`、`alert(` 只在 query）。
- **误报**：body 是「正文原文」。真实场景：CMS/工单/wiki/邮件/评论把用户 HTML 原样 POST（`<p>…</p><script>` 或编辑器回传的 `<img onerror=…>`）→ medium；**JS 错误上报/监控接口**的正文里有 `onerror=`、`document.cookie` 也会命中；模板/JS bundle 通过 API 上传同理。
- **漏报**：`<svg onload=`、`onmouseover=`、`onfocus=`、`onpointerover=`、`<iframe srcdoc=`、`<body onpageshow=`、`javascript&colon;`、`java\tscript:`、HTML 实体 `&#x3c;script`、`eval(atob(`、`document['cookie']`；JSON 里 `\u003cscript` 形式的转义（引擎只做 URL 解码）。
- **修复建议**：两分支统一为
  `(?i)(<script[^>]*>|</script|<svg[^>]*\bon\w+\s*=|on(?:error|load|focus|blur|mouse\w+|pointer\w+|animation\w+|toggle)\s*=|javascript\s*:|data:text/html|srcdoc\s*=|document\s*[.\[]\s*['"]?cookie|<\s*img[^>]+\bonerror)`
  （把 `alert(` 这种「孤立函数名」删掉，它在查询串里 FP 高于收益）
- **置信度**：高（分支差异与正则原文均为源码事实）

### 内置-模板注入SSTI（builtin.py:219-239，priority=10，severity=high）

- **结论**：严重度不当（FP 面很大）+ FN
- **逻辑问题**：`(\{\{[^}]*\}\}|\$\{[^}]+\}|#\{[^}]+\}|<%=[^%]+%>)`（query）与少了 `#{}` 的 body 版本。两个细节：① `[^}]*` 允许「立即闭合」，所以 `{{}` 也会命中（把 `{{` 后任意位置的一个 `}` 当闭合）；② query 与 body 的能力又不一样（body 缺 `#{...}` 和 `<%= %>`）。
- **误报**：这是**组内除 Log4Shell 外最吵的一条**。`{{...}}`/`${...}` 在日常内容里到处都是：Helm chart / Jinja2 / Ansible / Vue / Angular 模板、K8s YAML、Docker Compose、Jenkinsfile、Grafana 面板 JSON——这些**经常被当作文件内容提交到接口**（网盘/知识库/CI API）→ high。query 分支同理（URL 编码的 `${` 会被引擎解码后命中）。
- **漏报**：`{% ... %}`（Jinja/Twig 语句，`{% for x in [].__class__.__base__.__subclasses__() %}`）**两边都不查**；body 缺 `#{...}`（Spring SpEL / Ruby）、缺 `<%= %>`；Thymeleaf `*{...}`、`[[${...}]]`、`__${...}__` 未覆盖。
- **修复建议**：**高精度化**——只有「表达式求值特征」或「已知对象」才 high：
  `(?i)(\{\{\s*[\w'".]*(?:config|self|_self|request|application|settings|7\*7|lipsum)\b|\$\{\s*(?:T\(|Runtime|getClass|class\.forName|7\*7)|#\{\s*(?:T\(|Runtime)|<%=\s*(?:Runtime|getClass)|__class__|__globals__)`
  泛化形态（`{{...}}`、`{%...%}`、`${...}`）单独一条 severity=medium，同时补上：
  `(\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#\{.*?\}|<%=[^%]*%>|\*\{.*?\})`
- **置信度**：高（正则放宽点 `[^}]*`、分支缺项都能直接指出）

### 内置-表达式注入与JNDI(Log4Shell)（builtin.py:241-264，priority=5，severity=critical）

- **结论**：需修（**本组最严重 FP** + 关键 FN）
- **逻辑问题**：第 5 个条件是 `(?i)(ognl|spel|%24%7bjndi)`——**`ognl`/`spel` 没有词边界**，而 `re.search` 是子串匹配。于是 `/api/spellcheck?word=x`、`/spell`、`SpellingBee`、DNS 查询名 `spellcheck.corp.local`（`query` 字段在 `dns` 路由上就是域名）都会命中。另外第 5 个条件里的 `%24%7bjndi` 与第 1 个条件重复：`query` 属于 `_DECODE_FIELDS`，`%24%7Bjndi%3a` 会被引擎解码成 `${jndi:` 由第 1 条件命中，这一支是冗余的（但无害）。
- **误报**（具体场景）：① `?q=spell`/路径含 `spel` 的请求 → **critical + priority 5**，且因为「命中即停」会**抢走**本该由 priority ≥6 的规则（敏感文件探测、扫描器 UA 等）给出的命中，把归因和级别都拉高；② DNS 日志：内网主机解析任何含 `spel` 的域名（如 `spellcheck.corp.local`）→ critical + src=内网解析器；③ body 里合法内容 `${env:...}`（工单/CI 配置/对话正文）→ critical。
  这些命中**不会**被 triage 跳过（severity critical ≥ medium），会吃满 `detector_max_digests_per_minute`（默认 24/分钟）额度，把真检测挤成回队/超龄丢弃。
- **漏报**（关键）：**头向量完全不看**。Zeek 侧所有请求头值只在 `req_headers`（`docs/ndr-collect-plan.md:26,101`、`docs/ndr-redesign.md:539-541,555`、`zeek/README.md:293-298`、`zeek/site/shentong-httpheaders.zeek`），本规则只查 `query/body/user_agent/referer`，因此 CVE-2021-44228 最典型的 `X-Api-Version: ${jndi:ldap://…}`（以及 `Cookie`、`Authorization`、`X-Forwarded-For` 注入）**一条都不报**；`user_agent` 也不在 `_DECODE_FIELDS` 里，`User-Agent: %24%7bjndi%3a…` 编码形态同样漏（`%24%7bjndi` 只写进了 query 分支）。此外 lookup 名只列了 `jndi|lower|upper|env|sys|java`，`${ctx:`、`${date:`、`${main:`、`${marker:`、`${docker:`、`${k8s:`、`${spring:`、`${log4j:` 漏。
- **修复建议**：① 给 `ognl|spel` 加词边界：`(?i)(\bognl\b|\bspel\b)`（`\bspel\b` 不会命中 `spellcheck`）；② 补头向量条件（`req_headers` 在引擎里只挂 http，正确）：
  `{"field": "req_headers", "op": "regex", "value": "(?i)\\$\\{(?:jndi|lower|upper|env|sys|java|ctx|date|main|log4j|spring|docker|k8s|marker):"}`，另加 `cookie` 一条（注意 cookie 恒空问题，见下条）与 `resp_headers`（响应头回显探测）；③ 建议把「jndi 精确命中」保持 critical/priority 5，「ognl/spel 关键词」降为 high 并挪到 priority ≥20，避免抢命中。
- **置信度**：高（`re.search` 子串语义 + `_FIELD_TYPES` 无 `cookie`/头向量未写 + 文档明示 Cookie 只在 req_headers）

### 内置-XXE外部实体注入（builtin.py:266-282，priority=8，severity=high）

- **结论**：OK（有小瑕疵，非阻塞）
- **逻辑问题**：body 条件 `(?i)(<!DOCTYPE[^>]*\[|<!ENTITY|SYSTEM\s+["']file:|SYSTEM\s+["']http)` 与 query 条件 `(?i)(<!DOCTYPE|<!ENTITY)`。`<!ENTITY` 实际上已经覆盖了所有真实 XXE payload（含外部 DTD、参数实体、billion laughs），`<!DOCTYPE[^>]*\[` 只在「有内部子集但没有 ENTITY」（比如只有 ATTLIST）时才额外有用 → 价值低但无害。
- **误报**：很低。唯一场景是「合法 XML 带内部 DTD 子集」被当正文提交（DocBook/FOP/某些 SOAP 报文）→ high，量级很小。普通 `<!DOCTYPE html>` 不匹配（`[^>]*\[` 要求同一标签内出现 `[`）。
- **漏报**：`SYSTEM "php://filter/…"`、`SYSTEM "jar:http://…"`、`SYSTEM "netdoc:///etc/passwd"`、`SYSTEM "ftp://…"` 不在 `file:|http` 里；不过 `php://input|filter|data`/`expect://` 会被**文件包含规则（priority 12）**接住，`jar:`/`netdoc:`/`ftp:` 则完全漏（且没有任何其它规则覆盖）——归因也从 XXE 变成文件包含。
- **修复建议**：把 scheme 白名单化：`(?i)(<!ENTITY\b[^>]*(?:SYSTEM|PUBLIC)\b|SYSTEM\s+["'](?:file|http|https|ftp|php|jar|netdoc|gopher|expect|dict):)`；UTF-16 编码的 XML 正文（`<\x00!\x00D…`）目前必然漏，若要覆盖需在归一化层解编码（跨文件改动，记为已知缺口）。
- **置信度**：高（正则原文 + 其它规则覆盖关系可直接比对）

### 内置-反序列化特征（builtin.py:284-306，priority=8，severity=critical）

- **结论**：**疑似死条件** + 严重度不当
- **逻辑问题（死条件）**：第 3 个条件是 `{"field": "cookie", "op": "regex", "value": "(?i)rememberMe="}`（builtin.py:298）。而 `cookie` 的值来自 `doc.get("cookie")`（`normalizer.py:536`），**Zeek http.log 根本没有 `cookie` 列**：`HTTP::Info` 只有 `user_agent/referrer/proxied…`，自写脚本只加了 `req_headers`/`resp_headers`（`zeek/site/shentong-httpheaders.zeek` 的 `redef record HTTP::Info += { req_headers, resp_headers }`），Cookie **值**落在 `req_headers` 里（`docs/ndr-collect-plan.md:26,101`、`docs/ndr-redesign.md:541,555`、`zeek/README.md:293-298` 实机探针 `COOKIE: probe=abc123` 出现在 `req_headers`，`cookie_vars` 只在 `raw.*`）。→ **`UnifiedLog.cookie` 在 Zeek 路径上恒空**，`regex` 对空值返回 False（`engine.py` `_text_candidates` 返回 `[]`）→ 这个分支**永远不可能为真**，Shiro `rememberMe=` 反序列化（CVE 类）在流量侧**不会被这条规则发现**。即使将来 `cookie` 被填上，`http_cookie_max_chars=200`（`config.py:102`）+ `_clip`（`normalizer.py:536`）也会让 `rememberMe=` 出现在第 200 字符之后时漏掉。
  （同根因的另外两处可顺带核对：builtin.py:684 的 `cookie` 条件、builtin.py:956 的 `{"field":"cookie","op":"exists"}`——后者让「会话跨IP复用」在 Zeek http 上同样永不触发。属于别的分组，仅作交叉提示。）
- **误报**：`(?i)(java\.io\.Serializable|ObjectInputStream|readObject)`（builtin.py:302）对 body 是全子串匹配——源码上传、API 文档、Java 异常栈、日志正文都会命中 → **critical**；`O:8:"`/`O:4:"`（PHP 序列化）在合法 PHP 序列化数据（老框架的表单/会话传参）上也命中。首条 `rO0AB|aced0005|AAEAAAD` 中 `rO0AB` 只有 5 字符，16KB 正文里出现随机 base64 时碰撞概率约 1.5e-5/条（4^… 口径：1/64^5 × 16384），数据量大时会零星出现。
- **漏报**：base64 包裹的 pickle（如 `Y29zCnN5c3RlbQ==` = base64("cos\nsystem")）永远不报（引擎不做 base64 解码）；`cos\nsystem`（builtin.py:296）经 Python 字面量转义后在正则里是「cos+真实换行+system」，**pickle 流里确实是真实换行**，所以这一支是对的（不是 bug），但只覆盖原始/URL 编码形态（URL 编码的 body 会被 unquote 成真实换行后命中）。
- **修复建议**：① **把 rememberMe 改成头向量**并去掉无意义的名字匹配：
  `{"field": "req_headers", "op": "regex", "value": "(?i)rememberme=[A-Za-z0-9+/=_-]{16,}"}`
  （`req_headers` 在引擎里只挂 http，单头截 256 字符是新的漏报边界，但比现状「恒不触发」好得多；根治要在 `normalizer.py` 里从 `req_headers` 解析出 Cookie 头填进 `cookie`，属跨文件改动）；② 严重度：`rememberMe=`/`shiro` 这种「名字级证据」单独一条 medium，`rO0AB|aced0005|AAEAAAD` 保持 critical，`java.io.Serializable|ObjectInputStream|readObject` 降 high 且建议改成「符号 + 序列化特征」共现（如要求同现 `rO0AB`/`aced0005`）；③ 收紧 base64 形态：`rO0AB` 前不允许 base64 字符（`(?:^|[^A-Za-z0-9+/])rO0AB`），随机碰撞再降一档；④ 补 pickle 的 base64 形态 `Y29zCnN5c3RlbQ`。
- **置信度**：高（字段填充链路：`schemas.py:54` → `normalizer.py:536` → Zeek 侧字段清单/文档三处相互印证）

### 内置-SSRF敏感参数与协议（builtin.py:308-334，priority=10，severity=high）

- **结论**：需修（FP 大 + FN 大）
- **逻辑问题**：4 个条件都是 query 上的正则/contains：① `(url|uri|link|src|dest|redirect|target|callback|image|fetch|proxy|next)=[^&]*(https?://|file://|gopher://|dict://|ftp://)`；② 危险协议裸串 `file://|gopher://|dict://|ldap://|tftp://`；③ `contains 169.254.169.254`；④ `(url|redirect|next|target)=[^&]*(127\.0\.0\.1|localhost|0\.0\.0\.0)`。问题有三：**参数名无边界**（`url=` 是子串，`xurl=`/`avatarUrl=` 也算，宽了一点但方向对）、**带 scheme 的分支不看目标是不是内网**、**完全没有 body 条件**。
- **误报**（典型且量大的正常业务）：`GET /oauth/authorize?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb`——原文里 `%3A%2F%2F` 会被引擎 unquote 成 `https://`，于是**每一次 SSO/OAuth/SAML 登录**都报 high；`?next=https://portal.example.com`、图片代理/链接预览的 `?url=https://cdn.example.com/x.png`、`?image=`、webhook 自测 `?callback=https://…` 同理。这些都是产品的**正常功能参数**，量级能到业务流量级。
- **漏报**（重点）：① **JSON body 里的 SSRF 完全不报**——现代 API 常见 `POST /api/fetch {"url":"http://169.254.169.254/latest/meta-data/"}`，规则里没有任何 `body` 条件 → 恒不触发；② 参数名表缺 `img=`、`avatar=`、`file=`、`path=`、`host=`、`domain=`、`webhook=`、`page=`、`feed=`、`returnUrl=`（`returnUrl=` 因含子串 `url=` 侥幸命中，属巧合）；③ 云元数据只认 `169.254.169.254`：漏 `100.100.100.100`（阿里云，**本产品面向国内环境尤其要紧**）、`metadata.google.internal`、`fd00:ec2::254`；④ 数字/十六进制/八进制/短写混淆：`2852039166`、`0xA9FEA9FE`、`2130706433`、`0x7f000001`、`0177.0.0.1`、`127.1`、`[::ffff:169.254.169.254]` 全漏；⑤ 协议相对 `?url=//127.0.0.1/`（无 scheme）漏，`?url=127.0.0.1:8080`（无 scheme、参数名在 `url|redirect|next|target` 内才命中，否则漏）；⑥ `ftp://`/`tftp://` 无差别，但内网文件读取的 `file:///etc/passwd` 又与路径穿越规则抢归因。
- **修复建议**：① 拆两级——危险协议/元数据/内网地址 → high；「带 http(s) 且目标是外网」→ low（或直接删掉，因为正常外链请求没有检测价值）；② 补 body 条件（把上面 query 的判定原样套一份到 `body`）；③ 把参数名表补全并加边界：`(?i)[?&](?:url|uri|link|src|img|image|avatar|dest|destination|redirect|redirect_uri|return|returnurl|callback|target|host|domain|webhook|fetch|proxy|next|page|file|path|feed|rss)\s*=\s*(?:https?://|//)?(?:127\.|0\.0\.0\.0|localhost|169\.254\.169\.254|100\.100\.100\.100|metadata\.google\.internal|\d{8,10}\b|0x[0-9a-f]{6,8}|0177\.)`；④ 元数据分支补齐：`(?:169\.254\.169\.254|100\.100\.100\.100|metadata\.google\.internal|fd00:ec2::254|2852039166|0xA9FEA9FE)`。
- **置信度**：高（正常 SSO 参数命中可由「`query` 在 `_DECODE_FIELDS` 内 + 正则原文」直接推出；body 缺项是源码事实）

### 内置-文件包含/协议流（builtin.py:336-356，priority=12，severity=high）

- **结论**：需修（FN，小）
- **逻辑问题**：query 分支 `(?i)(php://(input|filter|data)|data://|expect://|zip://|phar://)`，body 分支少 `zip://|phar://`。逻辑没错，覆盖面偏窄。
- **误报**：很低（`phar://`/`zip://` 出现在参数里通常确实可疑；PHP 应用自身用 `phar://` 当队列 payload 的极少数场景会误报，medium 级别即可）。
- **漏报**：① **`data:`（单斜杠）data URI 完全漏**——浏览器侧常见的 `?next=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`（base64 包着 `<script>`，XSS 规则也认不出）就是个典型绕行；② `php://temp`、`php://memory`、`php://fd`、`php://stdin` 漏（alternation 只留了 input/filter/data）；③ `glob://`、`rar://`、`ogg://`、`zlib://`、`compress.zlib://` 漏；④ body 分支缺 `zip://|phar://`（与 query 不对称）；⑤ `file://` 由 SSRF 规则覆盖，但**内→内 SSRF 命中会被归到 SSRF 名下**（见重复/遮蔽）。
- **修复建议**：
  `(?i)(?:php://(?:input|filter|data|temp|memory|fd|stdin)|(?:data|zip|phar|glob|rar|ogg|zlib|expect)://|compress\.zlib://|data:(?:text/html|application/x-httpd-php|image/svg\+xml))`
  body 分支用同一份（至少补 `zip://|phar://`）。注意 `data:text/html` 这类要与 XSS 规则去重（见 Top 3）。
- **置信度**：高（alternation 清单可直接比对；`data:` 单斜杠漏是字面事实）

### 内置-CRLF/响应头注入（builtin.py:358-374，priority=15，severity=medium）

- **结论**：需修（FP 为主 + 一个死分支 + FN）
- **逻辑问题**：query 分支 `(?i)(%0d%0a|%0a%0d|\r\n)`（builtin.py:366）——三个选择项里：`%0a%0d`（LFCR）**没有任何服务端会把它当换行分隔**，是死分支；`\r\n` 裸 CRLF 在真实 URI 里几乎不可能出现（Zeek 的 `uri` 字段不会带裸换行），也基本是死分支。body 分支 `(?i)(%0d%0a|\r\n(set-cookie|location):)`（builtin.py:370）的 `%0d%0a` **没有任何上下文要求**。
- **误报**（具体）：`application/x-www-form-urlencoded` 里多行文本（评论、工单描述、Markdown、邮件正文、笔记、富文本 HTML 片段）换行就是 `%0D%0A` → **体量级的正常流量**都会报 medium；query 侧 `?text=a%0D%0A%0D%0Ab`（Markdown 空行）、`?html=<p>…%0D%0A%0D%0A<p>` 同理。medium 虽不致命，但会稳定占用聚合/投递额度。
- **漏报**：① **LF-only 注入**（`%0a` 单个换行，对很多服务端一样能拆响应头）漏；② 双重编码 `%250d%250a` 漏（引擎只解一层 → `%0d%0a` …注意：解一层后得到 `%0d%0a` 恰好能被 query 分支字面匹配，所以 query 上「双重编码」其实**能**命中，但 body 分支同理也依赖这层巧合）；③ body 分支只认 `set-cookie|location`，`content-length` / `http/1.1`（响应拆分的真目标）漏；④ `\u000d\u000a`（JSON/JS 转义换行）漏。
- **修复建议**：加「上下文要求」，一次解决 FP 与 FN：
  query/body 统一：
  `(?i)(?:%0d%0a|%0a|%0d|\r\n)(?:%20|\s)*(?:set-cookie|location|content-length|http/1\.[01])\s*:?`
  另保留一条「任意 `%0d%0a`」但降为 low（或删掉 `%0a%0d` 死分支）。
- **置信度**：高（FP 触发路径 = 「body/query 里字面 `%0d%0a`」+ 表单编码事实；死分支可直接指出）

---

## 重复 / 遮蔽 / 合并（本组内）

1. **优先级的「同号决胜」不确定**：本组 priority=10 的有 6 条（SQL基础 81、SQL元数据 103、命令注入 147、路径穿越 169、SSTI 219、SSRF 308）。`rules/service.py:15` 只 `order_by(Rule.priority)`，**没有二级键**，而内置规则每次启动都会 upsert（行会被重写），因此「同一请求命中多条同优先级规则时留下哪条名字/严重度」在实践中**不保证稳定**。例子：`?file=php://filter/convert.base64-encode/resource=/etc/passwd` 同时满足「文件包含」（12）与「路径穿越」条件 3 的 `/etc/passwd`（10）→ 归因几乎总落在**路径穿越**；`?id=1 union select … /etc/passwd` 则同号竞争 SQL基础 vs 路径穿越。两者 severity 都是 high，所以危害有限，但**分析报告里的规则名会误导人**（P2，修法：`order_by(Rule.priority, Rule.id)`）。
2. **语义重复**：路径穿越条件 3 的 `(/etc/(passwd|shadow)|/proc/self|win\.ini|boot\.ini)` 本质是 **LFI 特征**，与「文件包含/协议流」是同一件事的两个入口；SSRF 条件 2 的 `dict://|gopher://|tftp://` 与文件包含的 `expect://`/`data://` 也属同一族「危险协议」。建议把「本地文件/危险协议」收敛成一条规则，或在描述里写清分工，避免同一攻击按目标文件不同落到不同规则名。
3. **Wazuh 侧双报**：Wazuh 告警也会填 `query`（`normalizer.py:759` `query=url`）与 `body`，所以一条 Wazuh 的 SQL 注入告警会同时产生「内置-Web攻击（Wazuh规则组）」（559）与「内置-SQL注入-*」两个不同规则名的摘要（聚合键是源IP+规则名）→ 同一攻击两份摘要，多花一倍投递额度（P2）。
4. **合并建议**：SQL 基础（81）+ 元数据与文件读写（103）目标一致、都是 high@10，可合成一条含两族特征的正则，减少同号竞争与重复投递；NSQL/SSTI/命令注入保持独立。

---

## 本组 Top 3 问题

1. **内置-表达式注入与JNDI（builtin.py:241-264）**：`(?i)(ognl|spel|…)` 无词边界（`re.search` 子串语义）→ `/spellcheck`、`spell**spel**…`、DNS 域名含 `spel` 都报 **critical + priority 5**，还因「命中即停」抢走更具体规则的归因、吃掉 24/分钟投递额度；同时**完全不看 `req_headers`**，而 Zeek 的 Cookie/各请求头值只在 `req_headers` 里，CVE-2021-44228 的头注入向量一条不报。修法：`\bspel\b`/`\bognl\b` + 补 `req_headers`/`resp_headers` 条件 + lookup 名单补齐。
2. **内置-反序列化特征（builtin.py:284-306，尤其 line 298）**：`cookie` 在 Zeek 路径恒空（Zeek http.log 无该列，Cookie 值只在 `req_headers`），rememberMe/Shiro 分支**永不可能触发**；同时 `java.io.Serializable|ObjectInputStream|readObject` 这类弱证据被定成 **critical**（源码/文档/异常栈即触发）。修法：改用 `req_headers` 匹配 `rememberme=<base64>`、把弱证据降为 high 或要求共现 `rO0AB/aced0005`。
3. **内置-SSRF敏感参数与协议（builtin.py:308-334）**：`redirect_uri=/next=https://…` 这类**正常 SSO/图片代理参数**经引擎解码后必然命中 high（每次登录都可能报），而 JSON body 形态的 SSRF（`{"url":"http://169.254.169.254/…"}`）因为**规则里没有 body 条件**永远不报，云元数据还漏了 `100.100.100.100`（阿里云）等。修法：外链分支降级/要求内网目标 + 补 body 条件 + 参数名与元数据清单补齐。

> 需要跑但没有执行的验证（供 supervisor 在 NDR 栈执行）：
> 1. `cd ndr/backend && python -c "import re;print(bool(re.search(r'(?i)(ognl|spel)','GET /api/spellcheck http://x')))"`（预期 `True`，即实证 `spel` 子串 FP；建议同时构造 `re.search(r'(?i)(\bognl\b|\bspel\b)',…)` 对照）
> 2. `pytest tests/py --stack=ndr -q -k "rules_routing or normalizer_fields"`（路由/字段契约，含 `query→dns/http/wazuh` 与 Web 字段 wazuh 归属）
> 3. 造一条 Zeek `http.log` 样本（带 `req_headers: "COOKIE: rememberMe=…"`，无 `cookie` 键）经 `normalize_zeek` 断言 `entry.cookie == ""`，即可复现「反序列化 rememberMe 分支为死条件」。

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "按任务要求的格式给出 13 条规则的逐条结论（结论/逻辑问题/误报/漏报/修复建议/置信度）+ 本组小结表 + Top 3，每条结论都引用具体文件行号、正则原文、阈值或字段填充链路（如 builtin.py:296/298/208/213/366/370/119、engine.py 的 _match/_text_candidates/_FIELD_TYPES、normalizer.py:536/671、config.py:73/77-79/102、runner.py:697-699、triage_policy.py 与 docs/ndr-collect-plan.md:26,101）"
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "python -c \"import re; print(bool(re.search(r'(?i)(ognl|spel)','GET /api/spellcheck')))\"",
      "result": "not-run",
      "summary": "无 shell/执行权限，未运行；用于实证 Log4Shell 规则的 spel 子串 FP（预期 True）"
    },
    {
      "command": "pytest tests/py --stack=ndr -q -k \"rules_routing or normalizer_fields\"",
      "result": "not-run",
      "summary": "未运行；用于核对 query→dns/http/wazuh 路由与 Web 字段归属契约"
    },
    {
      "command": "normalize_zeek(带 req_headers=COOKIE: rememberMe=... 且无 cookie 键的 http 样本) 断言 entry.cookie == \"\"",
      "result": "not-run",
      "summary": "未运行；用于复现「反序列化 rememberMe 分支恒假」的死条件"
    }
  ],
  "validationOutput": [
    "只读静态评审：结论均来自源码与仓库文档，未做运行时验证（无 shell/执行工具）。",
    "关键静态证据：engine.py 的 regex 用 re.search（子串，无锚点）；_DECODE_FIELDS 只含 query/query_string/uri_path/body/referer/filename 且仅 unquote/unquote_plus 一层；_FIELD_TYPES 里无 cookie/referer；runner.py:697-699 为 hit=next(...)；rules/service.py:15 仅 order_by(priority)。",
    "字段填充证据：normalizer.py:536 cookie=doc.get('cookie')；Zeek http.log 无 cookie 列，Cookie 值只在 req_headers（zeek/site/shentong-httpheaders.zeek、docs/ndr-collect-plan.md:26,101、docs/ndr-redesign.md:539-541,555、zeek/README.md:293-298）。"
  ],
  "residualRisks": [
    "无运行时验证：FP/FN 结论基于正则语义与字段填充链路静态推导，未经实机/单测复现（建议 supervisor 跑上面 3 条验证命令）。",
    "优先级同号决胜顺序依赖 DB 行序（order_by(priority) 无二级键），实机归因可能与本文举例不同。",
    "Wazuh 分支的实际字段填充（data.body/data.cookie/data.user_agent 是否存在）未逐字段实测，相关判断仅就 Zeek 主路径给出。",
    "请求体/头字段的截断边界（req_headers 单头 256、总量 4KB；cookie 200 字符）会让部分建议（用 req_headers 判 rememberMe/jndi）存在新的漏报边界，需在实现时评估。"
  ],
  "noStagedFiles": true,
  "diffSummary": "无改动（只读评审，未修改任何文件）",
  "reviewFindings": [
    "blocker: ndr/backend/app/rules/builtin.py:241-264 - Log4Shell 规则用 (?i)(ognl|spel|%24%7bjndi) 无词边界，re.search 子串匹配使 /spellcheck 等正常请求报 critical 且 priority=5 抢命中；同时缺 req_headers 条件导致头向量 CVE-2021-44228 漏报",
    "blocker: ndr/backend/app/rules/builtin.py:298 - cookie 字段在 Zeek 路径恒空（Cookie 值只在 req_headers），rememberMe 反序列化分支永不触发；同规则 302 行弱证据（readObject 等）定为 critical 偏高",
    "blocker: ndr/backend/app/rules/builtin.py:308-334 - SSRF 规则无 body 条件（JSON SSRF 永不触发）、redirect_uri/next=https:// 正常 SSO 流量误报 high、云元数据仅覆盖 169.254.169.254（漏 100.100.100.100 等）",
    "blocker: ndr/backend/app/rules/builtin.py:147-167 - 命令注入要求分隔符后命令再跟空白，;id / |id / &&id / 换行分隔等常见注入形态漏报（query 反引号分支同时过宽）",
    "blocker: ndr/backend/app/rules/builtin.py:366,370 - CRLF 规则命中任意 %0d%0a（表单多行文本常见，量级误报），%0a 单换行注入漏，%0a%0d 与裸 \\r\\n 为死分支",
    "blocker: ndr/backend/app/rules/builtin.py:219-239 - SSTI 以 {{...}}/${...} 泛匹配定 high，Helm/Jinja/CI/YAML 正文必误报；{% %} 与 body 的 #{} / <%= 漏"
  ],
  "manualNotes": "本次为只读评审，未改任何文件；评审范围严格限定在 builtin.py:79-375 的 13 条规则，对 builtin.py:684（cookie 条件）与 956（cookie exists）只做同根因交叉提示，未展开评审。全部 13 条规则的条件树都是单层 or、无 AND 混挂多类型专有字段，故任务点名的「混合专有字段致 AND 恒不成立」死规则在本组不存在；本组唯一的死条件是 反序列化 的 cookie 分支。triage（policy_skip_rules 默认只含 内置-扫描尝试连接/内置-恶意文件传输）不会跳过本组，但 severity_cap_internal=medium 会把内→内的 Log4Shell/反序列化 critical 降级，属既定取舍。"
}
```