## 本组小结

| 规则 | 判定 | 一句话结论 |
|---|---|---|
| 内置-LDAP注入 (376) | 需修 | 条件树与描述一致、字段真实，但缺 `)(uid=*`/`)(|(cn=*` 等常见变体（漏报），且 medium 与 SQL 注入同危害不同级 |
| 内置-开放重定向探测 (394) | 需修/重复 | and 逻辑对，但正常外链参数（`?return=https://…`）即命中，且被 p10 的 SSRF 规则大面积遮蔽 |
| 内置-危险HTTP方法 (439) | 需修 | `OPTIONS`（CORS 预检）/`DELETE`/`PUT` 是常规业务方法，白名单只挡 3 种巡检 UA，命中量=正常前端流量 |
| **内置-WebShell上传 (464)** | **需修（最严重）** | 用的是**请求路径**不是上传文件名 → "POST 任意 .php 页面返回 302/200" 即报 critical；真正上传 `.php` 到 `/api/upload` 反而漏报 |
| 内置-WebShell访问 (487) | 需修 | 正则要求 `/` 紧邻关键字前缀、关键字后紧邻扩展名 → `shell2.php`/`x_shell.php`/`b374k-3.php` 全漏；又被 p8 上传规则遮蔽 |
| 内置-恶意文件传输 (505) | 需修 | 字段真实但方向（`file_is_orig`）未用 → 软件更新/内部 JAR 全报 high；`policy_skip_rules` 里配的抑制**因严重度门槛失效** |
| 内置-弱TLS版本 (523) | 需修（严重度/量级） | 正则覆盖 Zeek `TLSv10/TLSv11` 无漏，但内网每条 TLS1.x 会话必报 medium → 必然吃掉 24 条/分钟投递额度 |
| 内置-自签或异常证书 (541) | 疑似死规则+判据错 | `cert_issuer` 只取顶层字段（x509 的 issuer 是嵌套 `certificate.issuer`）→ 很可能恒空；令牌 `self/openssl` 也不出现在真自签 DN 里 |

## Review

- 说明：本次为只读评审，未修改任何文件（`watchdog_diff`（stat）：No working-tree changes against reviewer-launch HEAD 599c9b057549），也未执行任何命令；仓库内**没有一条测试**覆盖本组规则的正/反例行为（仅路由测试），所以所有 FP/FN 结论均由代码路径推得并标注置信度。

### 内置-LDAP注入（builtin.py:376-391，priority=15，severity=medium）
- 结论：需修（漏报 + 严重度偏低）
- 误报：`)|` 与 `(&` 只有 2-3 个字符，正常提交正则/布尔表达式会命中：如搜索框输入 `(cat|dog)|(bird)`、代码片段 `if (a)|(b)`、接口传公式 `expr=(x)|(y)` → body 命中 medium。量级低但真实。
- 漏报（因正则不覆盖，非路由原因）：`)(uid=*`、`)(cn=*`、`)(|(cn=*`（"|(" 前是 "(" 不是 ")"，`\)\|` 不命中）、`)(!(...`（`(&` 只覆盖 AND，不覆盖 NOT 盲注）。这些是目录服务认证绕过的常用形态。
- 修复建议：把正则扩为 `(?i)(\)\||\(&|\(!|\*\)\(|\)\(cn=|\)\(uid=|\)\(objectclass=|\)\(userpassword|\|\(objectclass)`；严重度 medium→high（命中即认证绕过/目录数据泄露，与同组 SQL 注入 p10/high 对齐）。
- 置信度：高（正则逐字符可推；FP 场景是通用字符串事实）。

### 内置-开放重定向探测（builtin.py:394-413，priority=20，severity=medium）
- 结论：需修 + 与 SSRF 规则重复/被遮蔽
- 逻辑问题：`logic=and` 与"跳转参数指向外部地址"一致，字段真实（http 的 `query`=完整 URL，schemas.py:43）。但条件 1（405 行）无边界，`url=` 会命中 `callback_url=`/`myurl=`/`tourl=`；条件 2（411 行）`//[a-z0-9-]+\.[a-z]{2,}` 也会命中路径里的任意 `//host.tld`。**没有任何 status_code 或"本站域"约束**。
- 误报：`GET /sso/login?return=https://mail.corp.com/`、`?redirect_uri=https://app.corp.com/cb`、`?next=https://portal.corp.com/home`、分享链接 `?url=https%3A%2F%2Fcdn.corp.com%2Fa.pdf`（解码后命中）——都是正常业务，直接报 medium。
- 漏报：短参数名不覆盖：`?redir=//evil.com`、`?r=https://evil.com`、`?to=`、`?forward=`、`?jumpto=` 全部不命中（正则只认 `redirect|url|next|return|continue|dest|goto|target`）。
- 重复/遮蔽：`内置-SSRF敏感参数与协议`（p10，builtin.py:316-331，第 319 行含 `url|uri|link|src|dest|redirect|target|callback|image|fetch|proxy|next)=…https?://`）与本规则关键字集合几乎重合且优先级更小 → `?redirect=https://evil.com` 永远归因给 SSRF，本规则只剩 `return|continue|goto` 与"无 scheme 的 `//host.tld`"场景；`runner.py:699` 首个命中即停，故这是真实遮蔽，不是理论风险。
- 修复建议：加 `{"field":"status_code","op":"in","value":[301,302,303,307,308]}`（HTTP 跳转才叫开放重定向）；关键字补 `redir|jumpto|forward|to|u|r`；建议与 SSRF 规则合并成"外链参数"一条并在描述里写清归因，避免同一请求被两条规则争抢。
- 置信度：高（SSRF 正则在 319 行逐字可查，优先级差可复算）。

### 内置-Host头攻击（builtin.py:416-436，priority=15，severity=medium）
- 结论：需修（描述与实现不一致 + 字段口径错 + 疑死条件）
- 逻辑问题：条件只有三类（425-434 行）：`localhost|127.0.0.1|169.254.169.254`、`hostname contains ","`、`burpcollaborator|interact.sh|oast.|canarytokens`。描述写"含外部域名/内网地址/多值"，但**外部域名与内网地址判据根本没写**，条件 2"多值"在 Zeek 上也难成立（`http.log` 的 `host` 只有单值，重复 Host 头落 `req_headers`，见 ndr/zeek/README.md 批 3 段）→ 描述与实现契约不符（P1）。
- 漏报：Host 头投毒类攻击（`Host: attacker.com` 触发的口令重置链接污染、缓存投毒）**完全无覆盖**；`Host: 10.0.0.5`（内网 IP 探测）也不覆盖。这是本组第二重要的漏报点。
- 置信度：高（字段来源行号 + 路由表逐项可查）；"逗号条件恒假"置信度中（需实机看一次重复 Host 的 Zeek 输出）。

### 内置-危险HTTP方法（builtin.py:439-461，priority=20，severity=medium）
- 结论：需修（FP 量级大、严重度不分级）
- 误报：白名单只有 `kube-probe|prometheus|healthcheck`（455-459 行）。① `OPTIONS` 是**浏览器 CORS 预检的常规方法**（跨域前端每次非简单请求都先发 OPTIONS + `Access-Control-Request-Method`）；② `DELETE`/`PUT` 是 REST 规范方法（`DELETE /api/v1/items/3`、`PUT /api/v1/items/3`）。→ 正常前端/网管流量按请求数比例报 medium，量级可与站点 QPS 同阶。
- 漏报：无实质漏报（TRACE 也覆盖）；但 `CONNECT`、`PROPFIND` 之外的方法族（`COPY/MOVE/LOCK` WebDAV 续传）未列入。
- 修复建议（可抄）：白名单补预检放过 `{"field":"req_headers","op":"regex","value":"(?i)access-control-request-method"}`（`shentong-httpheaders.zeek` 把头名转大写后逐行落 `req_headers`，故必须忽略大小写匹配）；`TRACE/TRACK`（XST）单列一条 high，`PUT/DELETE/PROPFIND/OPTIONS` 降为 low 且优先级挪到 35+，避免挤占投递额度。
- 置信度：高（白名单内容与字段可用性都有代码依据）。

### 内置-WebShell上传（builtin.py:464-484，priority=8，severity=critical）
- 结论：需修（**同时是 P0 误报与致命漏报**）
- 逻辑问题：条件用 `method + uri_path(upload.php 之类) + status_code(200/201/202/204/302)`（472-482 行），但**`uri_path` 是请求路径**（normalizer.py:520-525，`_split_uri(uri)` 的 path 部分），不是上传文件名。于是规则的语义退化为"POST/PUT 到任何以 `.php/.jsp/.aspx/.jspx/asp/ashx/war/sh/pl/py` 结尾的 URL，且服务器回 2xx/302"。
- 漏报：真实上传（`POST /api/files` + multipart 里 `filename="shell.php"`，或 `PUT /upload/shell.php` 之外的常规上传端点）**完全不命中**，因为路径不以脚本扩展结尾。攻击者只要不走"路径即脚本名"的写法即可绕过。
- 修复建议（可抄，两条并行）：
  ① 真实上传判据：`{"logic":"and","rules":[{"field":"content_type","op":"regex","value":"(?i)multipart/form-data"},{"field":"body","op":"regex","value":"(?i)filename=\"[^\"]*\\.(php\\d?|phtml|jspx?|aspx?|ashx|war|sh|pl|py)\""}]}`（`body` 已归一化、默认 16KB 上限，multipart 头段必在前几百字节内）；可参考同类写法 `内置-上传类型不匹配`（builtin.py:1371-1387）与 normalizer 的 `http_upload` 定义（normalizer.py:386-389）。
  ② 保留现值时必须收窄：从成功码里删掉 `302`，`uri_path` 加 `$` 锚并加白名单 `(?i)/(wp-login|login|index|admin)\\.php$`，severity critical→medium；另加一条 files 线规则（`log_type=="files"` + `filename` 正则）覆盖"确有 `.php` 文件落地"。
- 置信度：高（字段语义 + 成功码 + 优先级遮蔽三处均有行号）。

### 内置-WebShell访问（builtin.py:487-502，priority=10，severity=high）
- 结论：需修（漏报面大 + 被 p8 遮蔽）
- 逻辑问题：条件 1（498 行）`/(shell|cmd|webshell|c99|b374k|r57|antsword|behinder|godzilla)(\.php|\.jsp|\.aspx|/|$)` 要求关键字**前面紧跟 `/`**、**后面紧跟扩展名/`/`/行尾**。条件 2（500 行）`/\.(php|jsp|aspx)$` 只覆盖"以 `/.php` 结尾"的隐藏文件路径——FP 极低但覆盖面也极低（真实 webshell 极少叫 `.php`），属近乎凑数的条件。
- 误报：`/cmd/`、`/shell/`（运维控制台/API 命名，如 `/api/shell/exec`）、`/godzilla/…`（影视/游戏站点）→ high 偏高；无 status_code 约束，扫描 `/shell.php` 的 404 也报 high（这一点可接受，扫 webshell 本身是强信号）。
- 漏报（正则结构决定，非路由）：`/shell2.php`、`/shell_v2.php`、`/webshell_1.php`（关键字后是数字/下划线 → 不匹配）、`/x_shell.php`、`/my_cmd.jsp`（关键字前不是 `/` → 不匹配）、`b374k-3.php`、以及常见名 `wso.php`、`alfa.php`、`mysql.php`、`uploader.jsp`、`symlink.php` 全部未列入。攻击者改个名即可绕过；这才是该规则的主要失效点（本组 Top3 之一）。
- 遮蔽：POST 到 `/shell.php` 且 200/302 时，p8 的 `内置-WebShell上传` 先命中 → 分析员看到的是"critical WebShell上传"，而语义正确的"WebShell访问"永不出现在摘要里。此外同优先级 p10 的 SQL/SSRF/扫描器UA/框架漏洞 与它竞争（`service.py:15` 只有 `ORDER BY priority`、无 id tiebreaker → 同优先级归属不确定）。
- 修复建议（可抄）：`(?i)(^|[_/.\-])(wso|alfa|shell|webshell|cmd|mysql|symlink|uploader|c99|b374k|r57|antsword|behinder|godzilla)\d*[\w\-]*\.(php\d?|phtml|jspx?|aspx?|ashx)(\?|$)`（去掉前缀必须为 `/` 的硬约束、允许数字后缀、补常见家族名）；对 POST 类命中可与上传规则统一归因（或把本规则提到 p7）。
- 置信度：高（正则逐段推导）；同优先级不确定性有代码依据（service.py:15）。

### 内置-恶意文件传输（builtin.py:505-520，priority=12，severity=high）
- 结论：需修（FP 量级大 + 抑制机制静默失效 + mime 清单有漏）
- 逻辑问题：`log_type=="files"` + `mime_type` 正则（513-518 行）与描述一致，字段真实（`mime_type` 来自 files.log，normalizer.py:550；实机带 `; charset=` 也不影响子串匹配）。**但 files.log 已有的方向字段完全没用**：`file_is_orig`（normalizer.py:559，`is_orig`：True=客户端上传）、`file_source`（:558），`filename` 也没用。
- 误报：合法的可执行文件分发全命中 high —— Windows/厂商 `.exe` 安装器与更新包、内部 Maven/JAR 下载（`application/java-archive`）、`wget` 下来的 `.sh` 安装脚本、内部 PyInstaller 工具；files.log 是**每文件一条**，量级可达每天数百至上千条，全部 high 并逐条聚合投递。
- **抑制机制失效（P1，最容易被忽略）**：默认配置把本规则名放进了 `policy_skip_rules`（config.py:73），但 `triage_policy.internal_routine_reason` 要求 `_rank(rule_severity) < _rank(policy_internal_routine_min_severity="medium")`（triage_policy.py:141-149）才允许跳过；本规则 `severity=high`(3) ≥ medium(2) → **直接 return None，永不跳过**。即：运营以为配了抑制，实际只对 low 的"内置-扫描尝试连接"生效——这正是"以为降噪了、其实没有"的静默失效。
- 漏报：`mime_type` 清单（515-518 行）漏掉 Zeek 会实际报出的 `application/x-pie-executable`、`application/x-sharedlib`、`application/x-object`、`application/x-mach-binary`、`application/vnd.microsoft.portable-executable`、`text/x-shellscript`/`text/x-python`；且 mime 来自 Content-Type 可被伪造（README 记载 `mime_type` 直接取自 HTTP Content-Type），只靠 mime 判"可执行"可被改名/改 Content-Type 绕过。
- 修复建议（可抄）：拆两条——① 上传方向（high）：`{"logic":"and","rules":[{"field":"log_type","op":"eq","value":"files"},{"field":"file_is_orig","op":"eq","value":true},{"field":"mime_type","op":"regex","value":"(?i)(x-dosexec|x-pie-executable|x-sharedlib|x-object|x-executable|x-elf|java-archive|portable-executable|text/x-shellscript|text/x-python)"}]}`；② 下载方向改 low（或 count：同 src 15 分钟 ≥N 个不同可执行文件），并把文件名维度补上 `{"field":"filename","op":"regex","value":"(?i)\\.(exe|dll|scr|sys|ps1|vbs|js|jar|elf|so|bin)$"}`。改 low 后 `policy_skip_rules` 的抑制才会真正生效。
- 置信度：高（跳过判据与严重度门槛可逐行复算）。

### 内置-弱TLS版本（builtin.py:523-538，priority=25，severity=medium）
- 结论：需修（严重度/量级不当；正则本身 OK）
- 逻辑问题：`log_type=="ssl"` + `tls_version` 正则（531-535 行）正确；`tls_version` 取自 Zeek ssl.log 的 `version`（normalizer.py:542），实机值是 `TLSv12` 这种写法（samples.py、test_normalizer_fields.py:139），正则把 `TLSv10|TLSv11` 与 `TLSv1\.0|TLSv1\.1` 两套命名都写了 → 对 Zeek 与 OpenSSL 口径都不漏（`SSLv3` 也在）。`ssl` 属 event 类（config.py:109）会进检测，路由只挂 ssl ✔。
- 误报（内网必然量级）：规则**没有任何方向/资产/次数约束**。内网仍启 TLS1.0/1.1 的打印机、iDRAC/iLO、老 Java 客户端、旧 OA/自建服务、老 SMTP STARTTLS 中继，每一条会话在 ssl.log 里都是一行 → 每条命中 medium 并按 `(src_ip+规则)` 聚合投递。命中量 ≈ 内网 TLS1.x 会话数（首次上线常达数千至数万/天），受 `detector_max_digests_per_minute=24`（config.py:170）限流后，超龄摘要（`detector_digest_max_age_seconds=1800`，config.py:177）会被丢弃（runner.py:557-558）——低价值规则把额度吃掉，高危规则投不出去。
- 漏报：无重要漏报（Zeek 不会写 `TLSv1` 裸写法，故未覆盖它风险很低）；但 `SSLv3`（POODLE）与 TLS1.0/1.1 同报 medium → 不分级，真出现 SSLv3 时严重度被稀释。
- 修复建议：① 加外发约束 `{"field":"dst_external","op":"eq","value":true}`（或至少排除 `dst_internal==true`）——外发弱 TLS 才是主要风险；② 改 count 规则：`{"mode":"count","key":["src_ip","dst_ip"],"min_count":5,"rules":[…]}`，避免首连即报；③ severity medium→low、priority 25→45（给高危规则让出额度）；④ `SSLv3` 单独一条 critical。
- 置信度：高（字段来源、路由、限流阈值均有行号）。

### 内置-自签或异常证书（builtin.py:541-556，priority=30，severity=low）
- 结论：疑似死规则 + 判据选错（FP/FN 同时存在）
- 逻辑问题（字段是否真会被填）：`cert_issuer` 只从**顶层**取值 `str(doc.get("cert_issuer") or doc.get("issuer") or "")`（normalizer.py:543）。而 x509.log 的 issuer 是**嵌套**在 `certificate.issuer`（tests/py/samples.py:135-140 就是实机结构），normalizer 没有拆嵌套 → x509 行恒空。ssl.log 是否真带 `cert_issuer` 只有 site 脚本注释声称（ndr/zeek/site/shentong-extra.zeek:5），但实机字段核对表只列了 `server_name/version/cipher/curve/established/resumed/ssl_history`（ndr/zeek/README.md §「上线后专项检查」第 3 行/实机结果），SSL 样本里没有 `issuer`，且**全仓没有任何测试断言 cert_issuer 被填充**。→ 很有可能是"看着在、永不命中"的静默死规则。需实机核对（命令见下方"需 supervisor 执行"）。
- 误报：即便字段有值，令牌法也会误报——`test` 会命中企业内 `O=…Test CA` / `CN=test-web…`、厂商名含 Test 的证书，报 low（噪声）。
- 漏报（判据错）：自签证书的 DN 里**不会出现 `self`/`openssl`**（`openssl req -x509` 生成的证书 subject/issuer 形如 `/C=…/O=Internet Widgits Pty Ltd/CN=<host>`），`unknown` 也极少出现在 issuer 里 → 真自签（issuer == subject）大面积漏报。可靠判据是"issuer == subject"（x509.log 两个字段都有）或 ssl.log 的 `validation_status`，而后者本项目**刻意不产**（未加载 validate-certs、notice 流已关，docs/ndr-collect-plan.md:142 记载该取舍）——想用必须先改采集口径。
- 修复建议：① 先修字段：normalizer 增补 `cert_subject`（x509 取 `certificate.subject`、ssl 取 `cert_subject/subject`）并让 `cert_issuer` 兼容嵌套 `certificate.issuer`；② 判据改为"issuer==subject 或 issuer 含内网域"（`(?i)(cn=)?(localhost|\\*\\.(local|lan|internal)|\\d{1,3}(\\.\\d{1,3}){3})`），或在引擎里加一个虚拟字段做 issuer/subject 相等比较；③ 若接受改采集口径，优先用 `validation_status`（self signed / unable to get local issuer certificate）。严重度 low、priority 30 保持即可。
- 置信度：中高（"x509 嵌套未解析"是代码事实，置信高；"ssl.log 是否带 cert_issuer"需实机核对，故整体留中）。

- 结论：需修（FP 源自上游分类 + 严重度被降级）
- 重叠/优先级：p10 有 8 条规则同号，`service.py:15` 只有 `ORDER BY priority` 无 tiebreaker，命中归属在 Postgres 返回顺序变化时可能变（对"提权告警 p10"等同号规则）→ 报告项。
- 置信度：高（分类函数与返回顺序逐行可查）。

### 需 supervisor 执行的验证命令（本次只读评审未运行任何命令）
1. 确认 ssl.log 是否真带 issuer（决定"自签证书"是死规则还是仅判据差）：
   `docker exec <zeek> sh -lc "head -1 /logs/ssl.log" | python3 -c "import sys,json;print(sorted(json.loads(sys.stdin.read()).keys()))"`
   预期看点：是否有 `cert_issuer`/`issuer`/`subject`/`validation_status`。同法查 x509.log（看 issuer 是否嵌套在 `certificate` 下）。
2. 量化"必然误报"：`http://<ndr>/api/events` 或 ES 聚合 `log_type:ssl` 且 `tls_version:(TLSv10 OR TLSv11 OR SSLv3)` 的条数；以及 `log_type:files` 且 `mime_type:(*dosexec* OR *java-archive*)` 的条数 —— 即为本组两条 high/medium 规则的日命中量级。
3. 一次性核对我的字段推断：`cd tests/py && python -m pytest test_rules_routing.py test_normalizer_fields.py -q`，并 grep `cert_issuer` 是否在任何测试里被断言非空（当前结论：没有）。

### 本组 Top 3 问题
1. **P0 内置-WebShell上传（builtin.py:464-484）**：判据用请求路径而非上传文件名，成功码含 302 → "POST 任意 .php 页面"报 critical；同时真实 multipart 上传 `shell.php` 漏报。影响：critical 噪声 + 额度被吃 + 真攻击漏检，且遮蔽 p10 的 WebShell访问。最小修：加 `content_type multipart/form-data` + `body regex filename="…\.(php|jsp|aspx|war)"`，或删 302/加白名单并降级。
2. **P1 内网必然误报 × 抑制失效（弱TLS builtin.py:523-538 / 恶意文件传输 builtin.py:505-520 + config.py:73 vs triage_policy.py:141-149）**：两条规则无方向约束、severity 高/中，量级各自可达成千/天；而 `policy_skip_rules` 里列的"内置-恶意文件传输"因严重度门槛（high ≥ medium）**永不生效**。最小修：给弱TLS 加 `dst_external==true` + 改 count + 降级；给文件传输加 `file_is_orig==true` 才 high，下载方向降 low（之后抑制才会生效）。

- Merge verdict：**BLOCK（按现状态不建议上线）**；阻塞项 = Top1（WebShell上传 FP/FN）+ Top2 中"抑制失效"（合规性/可解释性要求：配了不生效等于静默降噪失效）。其余为 OK with notes（可在首轮调优中一并处理）。
- 残留风险：本次无法确认 ssl.log 是否实际产出 `cert_issuer`（自签规则"死规则"结论依赖此点，置信中）；`hostname contains ","` 是否恒假需实机重复 Host 头验证；本仓库无本组规则的 FP/FN 回归测试，改动后行为仅靠人工核对。

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "逐条给出 10 条规则的结论/逻辑/FP/FN/修复/置信度，全部引用 builtin.py 行号、engine.py 路由表、normalizer.py 字段来源、triage_policy.py 跳过判据、config.py 阈值；并给出本组 Top 3 与需 supervisor 执行的验证命令。"
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [],
  "validationOutput": [
    "watchdog_diff(stat): No working-tree changes against reviewer-launch HEAD 599c9b057549 → 评审对象即 HEAD 内容；只读评审，未修改、未运行命令。"
  ],
  "residualRisks": [
    "ssl.log 是否实际产出 cert_issuer/issuer 无法本地核实（依赖 ndr/zeek/README 实机字段表与 site 脚本注释的冲突证据），'内置-自签或异常证书=死规则'结论置信中，需实机 head -1 /logs/ssl.log 核对。",
    "'内置-Host头攻击' 的 hostname contains ',' 是否恒为死条件，需实机重复 Host 头样本验证（当前依据 shentong-httpheaders.zeek 把重复头拼进 req_headers）。",
    "投递额度吞噬（24/分钟 + 1800s 超龄丢弃）的量化影响需上线后用命中统计复测。"
  ],
  "noStagedFiles": true,
  "diffSummary": "无代码改动（review-only）。评审范围：ndr/backend/app/rules/builtin.py:376-574 的 10 条内置规则。",
  "reviewFindings": [
    "P0: builtin.py:464-484 内置-WebShell上传 - 用 uri_path(POST 的请求路径)+status 200/201/202/204/302 判'上传脚本'，任何 POST 到 .php/.jsp 页面即报 critical（含 /login.php→302），而 multipart 上传 shell.php 到 /api/files 漏报；p8 还遮蔽 p10 的 WebShell访问。",
    "P1: config.py:73 与 triage_policy.py:141-149 - policy_skip_rules 里的'内置-恶意文件传输'因 severity=high ≥ min_severity=medium 永不跳过，抑制静默失效。",
    "P1: builtin.py:505-520 内置-恶意文件传输 - 未用 file_is_orig/file_source/filename，软件更新与内部 JAR 下载全部报 high。",
    "P1: builtin.py:523-538 内置-弱TLS版本 - 无方向/次数约束，内网每条 TLS1.0/1.1 会话报 medium，量级可达数千-上万/天并挤占 24/分钟摘要额度。",
    "P1: builtin.py:541-556 内置-自签或异常证书 - cert_issuer 只取顶层字段（x509 的 issuer 嵌套在 certificate.issuer，normalizer.py:543 未解析）→ 很可能恒空；令牌 self/openssl 也不出现在真自签 DN 中。",
    "P2: builtin.py:439-461 内置-危险HTTP方法 - OPTIONS(CORS 预检)/DELETE/PUT 属常规业务方法，白名单仅 3 种巡检 UA。",
    "P2: builtin.py:394-413 内置-开放重定向探测 - 与 builtin.py:316-331 SSRF 规则关键字重叠且优先级更低(20>10)被遮蔽；缺 status_code 与短参数名(redir/r/to/forward)。",
    "P2: builtin.py:487-502 内置-WebShell访问 - 正则要求 '/' 紧邻关键字且关键字后紧邻扩展名，shell2.php/x_shell.php/b374k-3.php/wso.php 等常见名漏报。",
    "P2: builtin.py:376-391 内置-LDAP注入 - 缺 ')(uid=*'、')(|(cn=*'、')(!(' 变体；medium 相对同危害的 SQL 注入(high)偏低。",
    "P2: rules/service.py:15 - ORDER BY priority 无 tiebreaker，p10 同号 8 条规则的命中归属不确定。"
  ],
  "manualNotes": "只读评审，未修改任何文件、未运行命令。所有结论均附文件:行号依据；两条需要实机确认的点（ssl.log 是否产出 cert_issuer；重复 Host 头是否落 req_headers）已在正文'需 supervisor 执行的验证命令'里列出，未执行。评审对象为 reviewer-launch HEAD 的已提交内容，未审查任何 committed range/diff。"
}
```