## 评审报告：NDR 内置规则 C 组（builtin.py 575-831，15 条探测类规则）

### 0. 先说明我核对过的引擎/运行时语义（后面所有结论的行号依据）

| 事实 | 依据 |
|---|---|
| 逐条规则 `hit = next(...)` 命中即停，只保留**第一条**；命中后仍继续跑全部频率规则 | `ndr/backend/app/detector/runner.py:686`（`hit = next(...)`）、`runner.py:695-703`（count 循环） |
| 候选规则顺序 = `types[log_type]` **整体在前**，`wild` 整体在后（不是全局按 priority 排序） | `ndr/backend/app/rules/engine.py:rules_for_log_type`（`return types[kind] + wild`） |
| 规则表按 priority 升序装载 | `ndr/backend/app/rules/service.py:15`（`order_by(Rule.priority)`） |
| `regex`/`contains` 用 `re.search` 子串匹配；`in` 精确相等；`exists` 要求非空 | `engine.py:_match` |
| `eq` 是严格相等（`status_code` 归一化为 int，`_to_int`），`ne` 对空值恒真 | `normalizer.py:647/731`（`_to_int`）、`engine.py:_match` |
| `uri_path` **不含查询串**（`_split_uri` 切 `?`），截断 512；`query_string` 截断 1024 | `normalizer.py:307-313`、`normalizer.py:525-526` |
| http 日志里 `query` = `uri`（路径+参数），不是完整 URL | `normalizer.py:644-645` |
| `scan_attempt` 仅由 `conn_state=S0` 产出；`REJ/RSTOS0/RSTRH` → `rejected_connection`，**不在任何 C 组规则的取值里** | `ingestion/conn_states.py:41-55` |
| Wazuh：描述里含 `scan` → `event_type=port_scan`；含 `sql|injection` → `web_attack` | `normalizer.py:855-860` |
| 频率窗口默认 300s、冷却 300s、`key` 缺省 `src_ip`；member = `fingerprint():ts`（毫秒级） | `config.py:186-187`、`frequency.py:observe` |
| 摘要聚合键 = (src_ip, rule)；投递限流 24 条/分钟，超出回队，超龄 1800s 丢弃；**被 excluded 的摘要也走同一条投递通道、同样占额度** | `detector/aggregate.py:_agg_key`、`runner.py:_flush`、`detector/push.py:deliver`（不区分 excluded） |
| 分级放行白名单默认只有 `内置-扫描尝试连接`、`内置-恶意文件传输` | `config.py:71-76`，`triage_policy.py:internal_routine_reason` |
| 健康检查白名单：`uri_path` **精确 in** `["/health","/healthz","/ping","/metrics"]` + UA 正则 `(kube-probe|prometheus|zabbix|nagios|uptime|healthcheck|ELB-HealthChecker)` | `builtin.py:23-30` |

关于任务里点名的「混合多类型专有字段 → 某些 log_type 上恒空的死规则」：**C 组不存在完全死规则**。逐条核算：`云元数据访问` 引用 `query`(dns/http/wazuh)+`body`(http/wazuh)+`dst_ip`(通用) → 挂 dns/http/wazuh，逻辑是 `or`，dns 上 `body` 恒空不影响；`敏感文件`/`框架漏洞`/`参数fuzzing`/`未授权访问` 全部落在 http+wazuh（`auth_scheme`、`cookie` 不在 `_FIELD_TYPES` 里，只是不贡献类型，不会把规则推到 wild 或推到错误类型，见 `engine.py:build_rule_index` 的判定顺序）。真正的死条件只有一处：**`框架漏洞探测特征` 的 `/index\.php\?s=` 分支永不成立**（`uri_path` 不含查询串）。这点在下面逐条写。

（另：C 组只有 `端口扫描`、`扫描尝试连接` 两条进 wild 集合，其余都是 http/wazuh/ssl 绑定；但这两条的 `event_type` 是通用字段，实际每个 log_type 都会跑，这是引擎的 fail-open 设计，代价是匹配次数增加，不算 bug。）

---

### 本组小结

| 规则 | 结论 | 一句话 |
|---|---|---|
| 内置-Web攻击扫描器UA | 需修 | `httpx` 太宽（python-httpx 是正常客户端库）；缺 ZAP/afrog/vulmap/yakit |
| 内置-JA3指纹命中 | OK（有取舍） | 默认禁用、路由正确；`in` 精确匹配对小写/空白无归一，代价写清 |
| 内置-敏感文件与源码泄露探测 | 需修 | 无白名单，`/actuator` 打在 K8s 探针上必误报；裸 `backup\|dump` 子串过宽；与「未授权访问」重复且优先级抢走归因 |
| 内置-未授权访问探测成功 | 需修 | `auth_scheme ne basic` 逻辑不成立（空值恒真），只排 Basic、放过所有会话式登录 |
| 内置-云元数据访问 | 需修 | critical 且无白名单，云内自监控 agent 访问 169.254.169.254 必报；漏 Aliyun/腾讯/IPv6 元数据地址 |
| 内置-框架漏洞探测特征 | 需修 | `/index.php?s=` 是死分支；`.do$\|.action$` 打到所有遗留 Java 应用；`rememberMe=` 分支被 priority 8 的反序列化规则完全遮蔽 |
| 内置-参数fuzzing超长载荷 | 需修 | 逐条规则而非频率规则；SAML/OAuth/中文 URL 编码路径正常超长即命中；缺白名单 |
| 内置-目录/路径爆破 | 需修 | 缺 401；健康白名单缺 datadog/blackbox/consul/go-http-client；与「多路径探测」同一行为双报 |
| 内置-多路径探测(漏洞挖掘) | 需修 | 无状态码过滤，40 个正常 200 路径（爬虫/压测/SPA 用户）即 high；与目录爆破重复 |
| 内置-暴力路径枚举(单路径高频) | 需修 | 无状态码过滤，轮询接口（2s 刷新）必报；key 缺 dst_ip 跨目标混算；资源 ID 枚举不覆盖 |
| 内置-服务端错误突变 | 需修 | 本组唯一没有健康白名单的频率规则；反代作为 src 时把全体用户的 5xx 全算到一个 IP |
| 内置-大面积目标探测 | 疑似死规则级别的空条件 | 唯一条件是 `src_ip exists`，等于「按源计数所有事件」，5 分钟 25 个目标就报，FP 洪泛吞掉 24/分钟投递额度 |
| 内置-端口扫描 | 需修 | 依赖 notice，Wazuh 侧「描述含 scan」即命中（如“漏洞扫描完成”）；与 808/822 三重重叠 |
| 内置-高频扫描连接 | 需修 | 只认 S0，漏 REJ/RSTOS0 扫描；防火墙丢包/NAT 造成误报；与 822 同行为、严重度不一致 |
| 内置-扫描尝试连接 | OK（设计取舍） | 匹配全部 S0、priority 20 是设计使然，且被 `policy_skip_rules` 放行；代价是仍占用投递额度 |

---

### 内置-Web攻击扫描器UA（builtin.py:577，priority=10，severity=high）

- 结论：需修（FP）
- 逻辑问题：`user_agent` 是 `_FIELD_TYPES` 里 `("http","wazuh")`，路由正确；`(?i)` 大小写处理正确。问题全在关键词表的粒度：整条是「子串或集」，`httpx`、`goby`、`dirb`、`hydra`、`xray` 这类短词在任意 UA 里出现即命中（builtin.py:588-589）。
- 误报：`python-httpx/0.27.0` 是现代 Python 服务/脚本/Agent 框架的默认 UA（大量 LLM/API 网关、LangChain、k8s 运维脚本），命中 high；`Go-http-client` 类不改 UA 的上游不命中但 `httpx` 会。`hydra` 会命中任何含 "hydra" 的产品名 UA；`xray` 会命中含 X-Ray 的自研客户端。这类误报无法靠 uri/状态码收窄（规则没有其它条件）。
- 漏报：UA 是可随意伪造的字段，`sqlmap --random-agent`、`nuclei -H 'User-Agent: Mozilla/5.0'`、Burp 改头后一律不命中；清单缺常用工具：`zaproxy|OWASP ZAP`、`afrog`、`vulmap`、`yakit`、`dirmap`、`pocsuite|pocsuite3`、`springbootscan`、`weblogic` 扫描器（绿盟 `RSAS`/极光 UA）。另外 UA 只在 http/wazuh 上有值，ssl/conn 上的工具特征（JA3）另由 594 条覆盖，这是合理分工。
- 修复建议：把短词改成带边界的版本，例如
  `(?i)(sqlmap|nikto|nmap|masscan|acunetix|nessus|w3af|\bdirb\b|gobuster|wfuzz|\bhydra\b|zgrab|\bnuclei\b|xray|goby|ffuf|feroxbuster|python-httpx|whatweb|jaeles|wpscan|dirsearch|zaproxy|afrog|vulmap|yakit|dirmap|pocsuite)`
  并把 `httpx` 单列为 `(?i)(^|[ /\-_])httpx[ /\-_]?\d` 之类（避免裸 `httpx` 命中 "python-httpx" 之外的正常 UA 的同时保留真正的 httpx 工具）。同时降级为 medium（UA 是启发式证据，不是行为证据），或把 high 保留给「同源 UA 命中 + 30 分钟内多个 4xx/5xx」的组合规则。
- 置信度：中—高（UA 字符串泛滥是行业事实；`httpx` 在生产 Python 栈里出现是常见现象，但本环境实际 UA 分布未能取到，故留一档）。

### 内置-JA3指纹命中（builtin.py:594，priority=15，severity=medium）

- 结论：OK（设计取舍明确，代价已记录）
- 逻辑问题：无。字段 `ja3` 归属 `("ssl",)`，规则只挂 ssl，与 `normalizer.py:539` 只在 http/ssl 分支填 `ja3` 一致（http 也填，但规则不挂 http —— 这其实是**漏报**：Zeek 的 http.log 在 443/8443 上也会带 `ja3`（当 SSL 分析器同时产出），只挂 ssl 会漏掉未生成 ssl.log 的场景。不过 ssl.log 通常在，影响小）。
- 误报：默认 `ja3_blocklist=""` → `main.py:47-64` 把 `enabled` 置 False，规则不出库，不会误报，这是安全的默认。
- 漏报：`in` 是**精确相等**且区分大小写、不做 strip。运维在 `ST_JA3_BLOCKLIST` 里粘贴带空格/大写十六进制的指纹时规则静默失效（无任何告警）。建议在 `_dynamic_rule_spec` 里统一 `x.strip().lower()`（`main.py:55` 已 strip 但没 lower），并在 `engine._match` 的 `in` 分支对 `ja3/ja3s/ja4/md5/sha1/sha256` 做大小写归一。
- 修复建议：`main.py:55` 改为 `[x.strip().lower() for x in ...]`；`in` 匹配加 `str(actual).strip().lower()`（或在 builtin 规则里改用 regex + `(?i)`）。
- 置信度：高（依据 `main.py:55` 与 `engine.py:_match` 的 `in` 实现）。

### 内置-敏感文件与源码泄露探测（builtin.py:609，priority=12，severity=high）

- 结论：需修（FP + 重复 + 归因抢占）
- 逻辑问题：`or` 4 条 `uri_path` 正则（builtin.py:618/623/628/635）。**没有 `_WHITELIST_HEALTH`**——本组其它 http 规则都有，这条没有，是明显的遗漏（对比 builtin.py:728/745/760 都挂了白名单）。第 4 条把 `/actuator|/swagger|/api-docs|/graphql|/debug/|/console` 归到「敏感文件泄露」，语义偏了：这些是**正常业务端点**，不是备份文件。
- 误报：①任何 Spring Boot 服务（`/actuator/health`、`/actuator/prometheus`）被 K8s 探针秒级轮询 → 每个请求 high，且因为没有白名单，`kube-probe` UA 也拦不住（白名单里那条 UA 正则用不上）；②第 2 条裸子串 `backup|dump` 会命中 `/api/backup/list`、`/assets/db-backup.svg`、`/docs/backup-policy`、`/v1/dump-config` 等正常业务路径；③`/console` 会命中自研后台的 `/console/telemetry`（且 `/(console)` 无右边界，`(?i)(...|/console)` 是前缀子串）；④`/info\.php` 分支在自建测试机上常见。
- 漏报：`/\.git/` `?` 带尾斜杠的写法漏掉 `GET /.git`（无尾斜杠）与 `/.git/config`... 后者命中，前者漏；常见备份名 `web.zip/www.zip/backup.*` 之外的全漏（`/wwwroot.zip`、`/1.zip`、`/site.tar.gz`、`/sql.zip`、`/db.sql.bak`、`/.idea/`、`/id_rsa`、`/.svn/entries` 只部分覆盖）。且**没有 `status_code` 条件**：403/404 也报（对「探测」是合理的，但对正常爬虫抓历史 URL 是纯噪声；与「未授权访问探测成功」的语义边界因此模糊）。
- 修复建议：拆两条并各挂白名单——(a) 真泄露类（要求 `status_code eq 200` 或 `in [200,206]`）：`(?i)(/\.git/|/\.svn/|/\.env|\?\.(zip|tar|gz|rar|7z|sql|bak|old|swp)$|/(wwwroot|web|site|www|backup|db|database)\.(zip|tar|gz|rar|7z|sql))`；(b) 端点暴露类（去掉 `/graphql`，与「未授权访问探测成功」合并）。两条都加 `"whitelist": _WHITELIST_HEALTH`，并把 `_WHITELIST_HEALTH` 的第 2 项扩成 `(?i)(kube-probe|prometheus|zabbix|nagios|uptime|healthcheck|ELB-HealthChecker|datadog|blackbox|consul|telegraf|go-http-client|netdata)`。
- 置信度：高（无白名单是可直接读出的代码事实，builtin.py:609-638 全文无 `whitelist`；探针访问 `/actuator/*` 是 Spring Boot 默认行为）。

### 内置-未授权访问探测成功（builtin.py:641，priority=15，severity=high）

- 结论：需修（FP），逻辑不成立
- 逻辑问题：三条 AND（builtin.py:649-654）：`status_code eq 200` + `uri_path regex ^/(admin|manager|manage|console|dashboard|api/v[0-9]+/(users|config|admin)|actuator)` + `auth_scheme ne basic`。第三条达不到描述的目的：`ne` 在 `actual != expected` 时为真，而 `auth_scheme` 在无 `Authorization` 头时是 `""`（`normalizer.py:331-340`），`"" != "basic"` → **恒真**。所以实际语义是「除 HTTP Basic 之外的一切 200」，包括用 Cookie/SSO/会话登录的**已授权**访问。描述说「疑似未授权访问」，实际无法区分授权与否。
- 误报：①运维用带会话 Cookie 的浏览器正常打开 `/admin/xxx`、`/dashboard`、`/console` → 每个请求 high（且 cookie 会话下 `_auth_from_headers` 找不到 Authorization）；②`^/(admin|...)` 没有右边界：`/administrator/`、`/administration/list`、`/managers`、`/dashboards`（Kibana 老路径）都命中；③内部 REST `/api/v1/users` GET 200（正常业务接口）→ high；④`/manager/html`(Tomcat) 是**正确**命中，但同一正则也命中正常 `/management` 页面。
- 漏报：①带 Basic 认证但**凭证泄露/爆破成功**的 200 被显式排除（这是最该报的一类）；②返回 302→登录页的未授权访问不报（合理，但 401→302 的中间态不覆盖）；③路径带前缀（反向代理 `/_internal/admin`）或大小写/编码变体虽是 `(?i)`+解码字段（`uri_path` 在 `_DECODE_FIELDS`，`engine.py:_DECODE_FIELDS`）覆盖，但 `^` 锚定使带前缀的部署漏掉。
- 修复建议：把「排除 basic」改成「要求无任何认证证据」，例如把第三条替换为
  `{"not": {"field": "auth_scheme", "op": "exists"}}`（配合新增 cookie 条件就变成 `not auth_scheme exists AND not cookie exists`），并对路径加右边界与常见后缀：
  `(?i)^/(admin|administrator|manager|manage|console|dashboard|actuator|api/v[0-9]+/(users|config|admin)|wp-admin)(/|$)`。
  另建议加 `dst_port not in [本地管理口]`? —— 引擎不支持「not in」，可用 `not` 包裹 `event_type eq ...` 的现有形式实现（见 builtin.py:1143 的 `ne` 用法）；更简单的是保留 `status_code eq 200` 并叠加 `{"field": "src_external", "op": "eq", "value": true}` 作为**独立低优先级版本**（外→内的 200 未授权访问才 high，内→内降 medium）。
- 置信度：高（`ne` 对空值恒真可直接从 `engine.py:_match` 与 `normalizer.go:331-340` 推出）。

### 内置-云元数据访问（builtin.py:660，priority=5，severity=critical）

- 结论：需修（FP，白名单缺失）
- 逻辑问题：`or` 四条（builtin.py:665-672），字段路由 dns/http/wazuh 正常。问题是不加任何方向/白名单/`log_type` 约束——`dst_ip eq 169.254.169.254` 这一条会把**云主机自己的监控 agent**当成 SSRF。
- 误报：AWS SSM/CloudWatch/Datadog/kubelet/cloud-init 每几十秒 PUT/GET 一次 IMDS（`http://169.254.169.254/latest/api/token`、`/latest/meta-data/instance-id`），Zeek conn/http 都会看到 → 每条 critical、priority 5 排在最前，且没有 whitelist。GCP 侧 `metadata.google.internal` 同理。这类主机数量一多，critical 队列直接被自己人填满。
- 漏报：只覆盖 AWS/GCP/Azure/Oracle 的 `169.254.169.254` 与 `metadata.google.internal`。缺 **Aliyun `100.100.100.200`**、**腾讯云 `169.254.0.23`**、**IPv6 IMDS `fd00:ec2::254`**、`metadata.goog`、`metadata.azure.com`；也缺「SSRF 打内网 K8s API」`kubernetes.default.svc` / `https://10.0.0.1:…/api/v1/namespaces` 这类同族特征。
- 修复建议：加白名单 + 扩地址表：
  ```python
  "rules": [
    {"field": "query",   "op": "contains", "value": "169.254.169.254"},
    {"field": "body",    "op": "contains", "value": "169.254.169.254"},
    {"field": "query",   "op": "contains", "value": "metadata.google.internal"},
    {"field": "query",   "op": "contains", "value": "100.100.100.200"},
    {"field": "query",   "op": "contains", "value": "fd00:ec2::254"},
    {"field": "dst_ip",  "op": "in", "value": ["169.254.169.254", "100.100.100.200", "169.254.0.23", "fd00:ec2::254"]},
  ],
  "whitelist": [
    {"field": "user_agent", "op": "regex",
     "value": "(?i)(amazon-ssm-agent|aws-sdk|aws-cli|cloud-init|datadog|cloudwatch|google-cloud-sdk|Amazon-Route53|kubelet|amazon-ecs-agent)"},
    {"not": {"field": "dst_port", "op": "eq", "value": 80}},   # IMDSv1 走 80 才需要报，反之视环境
  ]
  ```
  更稳的收窄：把 `dst_ip eq` 那条降级成 medium 独立规则（区分「主机自己访问元数据」与「外部/内网其他源经应用 SSRF 访问」），critical 只保留「src 不是该云主机自身」的场景——引擎无「自身」概念，落地可简化为 `{"field": "dst_external", "op": "eq", "value": false}` + 要求 `query` 命中而非 `dst_ip` 命中。
- 置信度：高（地址与 agent 行为是云环境通用事实；`engine.py:VIRTUAL_FIELDS` 提供了可用的收窄手段）。

### 内置-框架漏洞探测特征（builtin.py:676，priority=10，severity=high）

- 结论：需修（死分支 + FP + 被高优先规则遮蔽）
- 逻辑问题：
  1. **死分支**：`(?i)(\.action$|\.do$|/index\.php\?s=|/struts/)`（builtin.py:688）里的 `/index\.php\?s=` 永不成立——`uri_path` 由 `_split_uri` 去掉了 `?` 之后的所有内容（`normalizer.py:307-313`，`normalizer.py:525`）。ThinkPHP 最常见的 `?s=/index/\think\app/invokefunction` 探测因此**完全不报**。
  2. **归因被抢**：`cookie regex (?i)(rememberMe=|shiro)`（builtin.py:684）与 `内置-反序列化特征`（builtin.py:298，priority=8，severity=critical）里的 `cookie regex "(?i)rememberMe="` 是同一条件，priority 8 先命中即停（`runner.py:686`），所以本规则的 `rememberMe=` 分支在默认配置下**恒不生效**（只有 `shiro` 子串还能命中）。同一条 cookie 特征被两条规则以 critical/high 两种定级重复定义。
  3. 第 4 条（builtin.py:692-694，`/seeyon/|/weaver/|/e-mobile/|/mobile/plugin/`）把 OA 指纹识别塞进「框架漏洞探测」，摘要只带规则名（`aggregate.py` 的 `rule` 字段），分析侧看不出是哪个分支命中。
- 误报：`.do$`/`.action$` 是本组**最重的 FP 源**——任何 Struts1/JSP 老系统、大量国内 ERP/OA 的 `/login.do`、`/user/list.do`、`/index.action` 正常业务请求全部 high，且 priority 10 排在敏感文件(12)/未授权(15) 之前。`/mobile/plugin/` 在自研移动端应用上也可能正常存在。
- 漏报：除 ThinkPHP 分支死掉外，`jndi:` 只查 `body`（不查 `req_headers`，Log4Shell 打 `X-Api-Version: ${jndi:ldap://…}` 的头部注入不在本规则内——不过 builtin.py:259 有 user_agent 版，属于分组边界问题）；缺 Spring4Shell `class\.module\.classLoader`、缺 WebLogic `/wls-wsat|/_async/`、缺泛微 `/weaver/weaver.file.FileDownload` 之外的 `/services/` 路径。
- 修复建议：
  ```python
  {"field": "uri_path",     "op": "regex", "value": r"(?i)(/struts/|/wls-wsat/|/_async/|/(seeyon|weaver|e-mobile)/)"},
  {"field": "query_string", "op": "regex", "value": r"(?i)(^|&)s=/index/|/index/\\think|invokefunction"},
  {"field": "body",         "op": "regex", "value": r"(?i)(@type\s*[:=]\s*\"?com\.sun|fastjson|jndi:|class\.module\.classLoader)"},
  {"field": "req_headers",  "op": "regex", "value": r"(?i)\$\{jndi:"},
  ```
  并且 **删掉 `.do$|.action$`**，或把它单列成 medium 的「遗留 Java 框架指纹」规则（明确 FP 预期）。`rememberMe=` 条件应删除（由 298 条反序列化规则负责），本规则只保留 `shiro`（`(?i)shiro`）。
- 置信度：高（死分支由 `_split_uri` 直接证明；遮蔽由 priority 8 < 10 + `hit = next(...)` 直接证明）。

### 内置-参数fuzzing超长载荷（builtin.py:700，priority=25，severity=medium）

- 结论：需修（FP + 类型不当）
- 逻辑问题：`or` 两条正则 `^.{600,}$`（query_string）/ `^.{400,}$`（uri_path）（builtin.py:708-709）。这是**逐条规则**（无 `mode: count`），单次请求就报，与「自动化 fuzzing 特征」的描述不匹配——fuzzing 是高频行为，应做成频率规则或加次数条件。`^.{400,}$` 在 `uri_path` 已被截断为 512 字节的前提下，只有原始路径 ≥400 才成立（截断不产生假阳性，但 `$` 锚点失去意义）。规则没有 `_WHITELIST_HEALTH`（本组其它 http 规则都有）。
- 误报：①SAML/OAuth/OIDC 的 GET redirect binding（`SAMLRequest=` 常 >600 字符）；②站内搜索长查询串、GraphQL GET 大查询、S3/Azure 预签名 URL；③**中文等非 ASCII 路径 URL 编码膨胀 3 倍**：150 个汉字的路径编码后 450+ 字节，直接命中 `^.{400,}$`，这是中文环境里最现实的 FP；④把 base64/JSON 塞进查询串的内网接口。
- 漏报：只看 query_string/uri_path，不看 `body`（fuzzing 常常是超长 POST body）与 `referer`；`^` 锚定要求整串超长，若上限被降到 1024 之前就截断（`query_string[:1024]`，`normalizer.py:526`）会稳定命中，但**长度阈值没有随截断上限校验**——`>1024` 的载荷与恰好 1024 的载荷不可区分。
- 修复建议：改成频率规则并放宽字母表判据，例如
  ```python
  {"mode": "count", "key": ["src_ip"], "min_count": 10, "window": 300,
   "logic": "and",
   "rules": [{"field": "log_type", "op": "eq", "value": "http"},
             {"logic": "or", "rules": [
                {"field": "query_string", "op": "regex", "value": r"^[A-Za-z0-9%&=_\-+./:]{500,}$"},
                {"field": "body", "op": "regex", "value": r"^[A-Za-z0-9%&=_\-+./:{}<>\"]{2000,}$"}]}],
   "whitelist": _WHITELIST_HEALTH}
  ```
  至少要把 `min_count`/窗口补上，并把 severity 降到 `low`（超长参数本身危害低）。
- 置信度：中—高（截断/字段事实为高置信；`httpx`/SAML 场景为通用事实，实机比例未取到）。

### 内置-目录/路径爆破（builtin.py:714，priority=26，severity=high）

- 结论：需修（FP + 重复 + 漏 401）
- 逻辑问题：`mode=count`，`key=["src_ip"]`，`min_count=30`，窗口取全局 300s（`config.py:186`），条件 `log_type eq http` + `status_code in [403,404]`（builtin.py:726），白名单 `_WHITELIST_HEALTH`（builtin.py:728，逐条事件生效，方向正确）。缺陷：①状态码列表缺 **401**（受保护 vhost 的目录枚举典型返回码）与 **400**；②`min_count=30/5min` 在「一个 NAT 出口 / 一个代理后面几百个终端」的实机里是个很低的门槛；③白名单 UA 集合太窄（见修复建议）。
- 误报：①**NAT/正向代理**：一个 src_ip 代表整栋楼，任何用户点几个失效链接就能凑 30 个 404；②站点改版/迁移后大量旧 URL 返回 404，一个浏览器打开一个引用了 30+ 失效静态资源的页面（或爬虫/搜索引擎抓历史 URL，`Googlebot`/`Baiduspider` 不在白名单）即命中 high；③SPA 直接访问深链返回 404 后前端再补请求；④健康探测走非标准路径：`curl` 脚本探 `/health/ready`、`/actuator/health`（未被 in 列表覆盖）、`blackbox_exporter`（UA `Blackbox Exporter`，不在白名单正则里）在没有部署的端点上每 10s 一次 → 5 分钟 30 次正好压线；⑤Datadog/consul/telegraf 探针同样不在白名单。
- 漏报：①**分布式/慢速扫描**：每个源 29 次以下，或超过 5 分钟窗口（本组所有频率规则都用默认 300s；而 G 组已有 `window: 21600` 的先例，见 builtin.py:1462/1482 —— 慢速扫描覆盖是 C 组没复用的模式）；②全 200 的通配重写站点上的目录枚举完全不报；③`status_code` 缺失（Wazuh 未带 `data.status`）的事件不计数；④扫描器被 CDN/反代挡在 200 错误页上不报。
- 修复建议：
  ```python
  "min_count": 60,  # 或保留 30 但要求 uri_path 去重
  "rules": [{"field": "log_type", "op": "eq", "value": "http"},
            {"field": "status_code", "op": "in", "value": [400, 401, 403, 404]}],
  "distinct": "uri_path", "min_distinct": 20,
  ```
  并扩白名单 UA：`(kube-probe|prometheus|zabbix|nagios|uptime|healthcheck|ELB-HealthChecker|Googlebot|bingbot|Baiduspider|YandexBot|Datadog|Blackbox|consul|telegraf|netdata|Go-http-client|wget|curl)`（把 `curl/wget` 列入是取舍：会放过「用 curl 扫」的低端攻击，但能止住脚本探针的持续噪声，建议只在内→内方向放行，可用 `src_internal` 条件实现）。
- 置信度：高（阈值/状态码/白名单均可直接引用；NAT 与探针路径是实机常见形态，任务给的「内网互扫占比很高」亦支持该判断）。

### 内置-多路径探测(漏洞挖掘)（builtin.py:732，priority=24，severity=high）

- 结论：需修（FP 明确、与上一条重复）
- 逻辑问题：`mode=count`，`key=["src_ip"]`，`min_count=40`，`distinct="uri_path"`，`min_distinct=40`，**没有任何状态码条件**（builtin.py:740-745），只有 `log_type eq http` + 健康白名单。也就是说「40 个不同路径且全部 200」＝ high 告警。
- 误报：①搜索引擎爬虫：任何有 40+ 页面的站点，Googlebot/Baiduspider 在 5 分钟内抓 40 个不同 URL 是常态 → high；②站点地图抓取器、RSS 阅读器、内容同步工具；③k6/JMeter/Locust 压测（每个 VU 走不同路径）→ high；④SPA 用户正常浏览（前端路由产生多个真实 GET）；⑤监控大盘逐页巡检。白名单只有健康探针 UA，完全不覆盖上面这些。
- 漏报：①受限速的扫描器（1 请求/10s → 5 分钟 30 个路径）永不触发；②小字典扫描（<40 条）不报；③`distinct` 只支持单字段（`frequency.py` 的 `distinct` 是单值），所以「同路径不同参数」的 fuzzing 这条看不到（那是 749 条的领域，而 749 又不管状态码）。
- 修复建议：加证据门槛，避免「正常浏览」触发：
  ```python
  "min_count": 60, "distinct": "uri_path", "min_distinct": 60,
  "rules": [{"field": "log_type", "op": "eq", "value": "http"},
            {"field": "status_code", "op": "in", "value": [401, 403, 404]}],   # 或加 min_ratio
  ```
  并且**与 714 条合并/分工**：714 管「同一批失败请求的量」，732 管「路径离散度」，两者同时命中时应只出一条（现在会出两条摘要：`aggregate.py` 的键是 (src_ip, rule)，规则名不同 → 两条），建议保留一条频率规则、把另一条改成 `priority` 更靠后的补充规则，或在 `triage_policy` 层做去重。
- 置信度：高（无状态码条件 + 白名单不覆盖爬虫，可直接从 builtin.py:737-745 与 builtin.py:23-30 读出；爬虫行为是通用事实）。

### 内置-暴力路径枚举(单路径高频)（builtin.py:749，priority=26，severity=medium）

- 结论：需修（FP + key 设计 + 漏 IDOR 枚举）
- 逻辑问题：`key=["src_ip","uri_path"]`，`min_count=60`，**无状态码条件**、无 `distinct`（builtin.py:754-760）。描述说「疑似参数/账号枚举」，但实际统计的是「同一路径的请求总数」，无法区分成功轮询与失败爆破；`key` 里没有 `dst_ip`，同一路径打到不同后端会被合并计数（好处：扫 25 台机器的同一漏洞路径会累加；坏处：跨站点正常轮询也被合并）。
- 误报：①**轮询型客户端**：大盘 5s 刷新（60 次/5min 正好压线）、2s 刷新（150 次）直接 high-ish；②长轮询/SSE/心跳 `/api/events/stream`、`/api/session/refresh`；③客户端网络抖动后的重试风暴（一个坏请求重试 60 次）；④负载均衡/容器健康检查走非白名单路径（`kube-probe` 被白名单救了，但 HAProxy、F5、`Go-http-client` 探针不在）；⑤分页抓取 `/api/list?page=1..100`（路径不变，参数在变）——正是描述想抓的「枚举」，但同一模式也是正常导出/翻页。
- 漏报：①**资源 ID 枚举**（`/api/user/1001`、`/api/order/20260101`）路径每次不同 → 该规则（按 uri_path 计数）永不触发，这是最典型的 IDOR/遍历漏报；②慢速枚举（1 次/10s → 30 次/5min）不报；③扫描器把路径与参数分离（`/index.php?s=xxx`）时路径恒定——这条能报，但 688 行的框架规则报不出来（那条死分支），整体仍能覆盖一部分。
- 修复建议：把「高频同路径」和「同路径多参数值枚举」拆开，并要求失败证据：
  ```python
  # A：同路径高频 + 失败/限流证据
  {"mode": "count", "key": ["src_ip", "uri_path"], "min_count": 60,
   "rules": [{"field": "log_type", "op": "eq", "value": "http"},
             {"field": "status_code", "op": "in", "value": [401, 403, 429]}],
   "whitelist": _WHITELIST_HEALTH}
  # B：同路径、多参数值（覆盖 IDOR/参数枚举）
  {"mode": "count", "key": ["src_ip", "uri_path"], "min_count": 40,
   "distinct": "query_string", "min_distinct": 40,
   "rules": [{"field": "log_type", "op": "eq", "value": "http"}], ...}
  ```
  另外建议把轮询路径类型加入白名单（`uri_path regex (?i)(/stream|/events|/heartbeat|/longpoll|/sse)`）。
- 置信度：高（无条件状态码是代码事实；轮询/翻页是通用形态）。

### 内置-服务端错误突变（builtin.py:764，priority=22，severity=medium）

- 结论：需修（FP，且与同组规则不一致）
- 逻辑问题：`mode=count`，`key=["src_ip"]`，`min_count=20`，条件 `log_type eq http` + `status_code gte 500`（builtin.py:770-777）。**本组唯一没有 `whitelist` 的频率规则**（对比 714/732/749/1401 都有）。描述写「疑似打挂或注入成功」，但 `key` 只看源，无法区分「攻击者打出 5xx」与「后端自己坏了」；也没有要求同源还有 4xx/高频证据。
- 误报：①**反向代理/网关作为 src**：若传感器看到的是 nginx→后端 的请求，全体用户的 5xx 都聚到一个 src_ip，20 次几分钟内必到 → 纯噪声 high-ish；②探针：`/actuator/health` 启动期返回 503、探针 5-10s 一次 → 5 分钟正好 30-60 次命中（没有健康白名单拦）；③App 后端不可用时的客户端重试风暴（移动端/浏览器自动重试、`axios-retry`）→ 单个终端自然过 20；④NAT 后多用户共用一个 src。
- 漏报：①**服务端整体故障**（每个客户端 <20 次）不报——`key` 缺 `dst_ip` 时无法按「被打击的目标」聚合；②攻击者刻意压低频率（<20/5min）打注入致使偶发 5xx 不报；③Wazuh 侧 5xx 事件因 `log_type eq http` 被过滤（Wazuh 的 `log_type` 是 `wazuh`，见 `normalizer.py:743`），丢失了 Wazuh 上报的 Web 500 事实。
- 修复建议：加白名单（与 714 一致）、把 key 扩成 `["src_ip","dst_ip"]` 或新增一条 key=`["dst_ip"]` 的「目标端错误突增」规则，并要求源侧伴随证据：
  ```python
  "key": ["src_ip", "dst_ip"], "min_count": 20,
  "rules": [{"field": "log_type", "op": "eq", "value": "http"},
            {"field": "status_code", "op": "gte", "value": 500},
            {"field": "uri_path", "op": "regex", "value": r"(?i)^/(api|rest|graphql|login|admin|upload)"}],
  "whitelist": _WHITELIST_HEALTH
  ```
- 置信度：中—高（缺白名单与 key 语义是代码事实；反代作为 src 的前提是部署形态，需现场确认传感器位置，故留一档）。

### 内置-大面积目标探测（builtin.py:781，priority=24，severity=medium）

- 结论：疑似空条件规则（等于无条件计数），FP 洪泛并吞掉投递额度
- 逻辑问题：条件树只有 `[{"field": "src_ip", "op": "exists"}]`（builtin.py:793）。`exists` 在 `src_ip` 非空时恒真——这就是一条**没有过滤**的全量计数规则：`min_count=25`、`distinct="dst_ip"`、`min_distinct=25`、窗口默认 300s，跨所有 log_type（dns/conn/http/ssl/wazuh 都算，`frequency.py` 的 count 路径不看规则路由）。任何主机 5 分钟内与 25 个不同 dst_ip 通信就命中。
- 误报：①浏览器/客户端 / DNS 客户端 / 邮件客户端 / 补丁与软件更新（多个 CDN IP）；②监控服务器（Prometheus/Ansible/Zabbix 轮询几十上百台，5 分钟 25 个目标是**正常工作量**）；③备份服务器、堡垒机、域控、代理；④任何做服务发现的组件（Consul/k8s）；⑤NAT 后多用户；⑥内网资产巡检本身（任务给出「内网互扫占比很高」）。在 7k-10k 事件/分钟、内网互扫占大头的实机里，这条规则会贡献大量 medium 摘要。
- 漏报/精度问题：只按 `dst_ip` 去重，**完全不看端口**——一个源对 10 台主机的 65535 个端口做全端口扫描（经典 nmap `-p-`）反而不报（distinct dst_ip=10 <25）；反之正常主机打 25 个目标的 443 就报。也就是说它把「正常广度」当异常、把「高精度深扫」漏掉。
- 修复建议（三条一起改才有效）：
  ```python
  "mode": "count", "key": ["src_ip"], "min_count": 40,
  "distinct": "dst_ip", "min_distinct": 40,
  "rules": [{"field": "src_internal", "op": "eq", "value": true},
            {"field": "event_type", "op": "in",
             "value": ["scan_attempt", "rejected_connection"]},      # 只认未建立的连接
            {"not": {"field": "dst_port", "op": "in", "value": [80, 443, 53, 123, 445, 8080, 8888]}}],
  ```
  若引擎不便支持，最低限度是把 `src_ip exists` 换成「未建立连接」的判据（`event_type ne conn_established`，用 `ne` 表达，见 builtin.py:1143 的写法），并把 `min_distinct` 提到 40。补充：`distinct` 只支持单字段，若要抓「单目标多端口」需要另加一条 `distinct="dst_port"` 的规则（G 组已有先例：builtin.py:1482-1486 用 `distinct: dst_port`）。
- 置信度：高（条件树恒真是可读出的代码事实；主机 5 分钟 25 个目标的普遍性由任务给出的实机流量特征支持）。

### 内置-端口扫描（builtin.py:797，priority=20，severity=medium）

- 结论：需修（依赖上游 + 与 808/822 重叠 + 语义过宽）
- 逻辑问题：单条件 `event_type eq "port_scan"`（builtin.py:805）。该 event_type 有两个来源：Zeek notice 的 `note` 含 `scan`（`normalizer.py:786-788`）与 **Wazuh 告警描述里含 `scan`**（`normalizer.py:857-858`）。后者是明显的宽匹配：「某某扫描任务完成」「Vulnerability scan finished」这类描述会直接变成 medium 端口扫描告警。
- 误报：①Wazuh 描述里的 `scan` 泛匹配（上面）；②Zeek 侧合法的漏洞管理/资产扫描（Nessus/OpenVAS/合规扫描）与巡检脚本默认就会触发 notice，没有源白名单，也没有内→外/内→内的区分。
- 漏报：①完全依赖 notice 框架：若 `site` 脚本没开 scan 检测，本规则永不触发（引擎不负责补，靠 808 兜底）；②note 里不含 "scan" 的扫描类 notice（如自定义 `Shentong::Probe`）落到 `note.split("::")[-1]` 不匹配。
- 修复建议：Medium 保留但加限定：`{"field": "event_type", "op": "eq", "value": "port_scan"}` + `{"field": "src_external", "op": "eq", "value": true}`，或加白名单（已登记的漏扫平台 IP / `user_agent`）。Wazuh 侧建议把 `_wazuh_event_type` 里 `if "scan" in text` 收窄为 `re.search(r"\b(port ?scan|portscan|port scanning)\b", text)`（`normalizer.py:857-858`）。
- 置信度：中—高（引擎语义与匹配路径确凿；Wazuh 描述多样性需现场样本确认）。

### 内置-高频扫描连接（builtin.py:808，priority=24，severity=high）

- 结论：需修（FP + 漏报 + 与 822/797 重复、严重度不一致）
- 逻辑问题：`mode=count`，`key=["src_ip"]`，`min_count=30`，条件 `event_type in ["scan_attempt","port_scan"]`（builtin.py:816），窗口默认 300s，冷却 300s，无白名单。两个结构性问题：
  1. **只认 S0**：`scan_attempt` 唯一来源是 `conn_state=S0`（`conn_states.py:41`），而目标回了 RST 的扫描（`REJ`）、发 SYN 后 RST（`RSTOS0`）、SYN-ACK 后 RST（`RSTRH`）都是 `rejected_connection`，**不在取值列表里**。对开放/关闭端口罩有回应的主机做 SYN 扫描时大量连接是 REJ，本规则计数偏小 → 漏报（与 builtin.py:1141-1143 用 `event_type ne scan_attempt` 兜「真实服务连接」的写法对照，说明项目已经意识到 S0 语义的粗糙，但没有把反面纳入）。
  2. **S0 ≠ 扫描**：S0 也包含「正常服务被防火墙静默丢弃」「容器启动时反复重试一个还没起来/被墙的端口」。这类流在实机里量很大（任务给出「内网互扫占比很高」，很可能相当一部分是这种被丢包的正常流量）。`min_count=30/5min`＝一个重试间隔 10s 的客户端就能自己触发。
- 误报：①NAT/代理后的多用户；②服务依赖不可达时的重试风暴（RabbitMQ/Redis/DB 端口被墙）；③单机多进程启动并发连接同一批端口；④云主机向不可达的元数据/内部服务发 SYN。
- 漏报：①REJ 型扫描（上）；②慢速扫描（`nmap -T1`、每 10s 一发 → 30 次/5min 压线，`masscan --rate 1` 完全不报）；③分布式扫描（每个 IP 只扫几个端口）——需要长窗口 + `distinct="src_ip"` 的补充规则；④扫描器先扫一遍开放端口再打，S0 更少。
- 修复建议：
  ```python
  {"mode": "count", "key": ["src_ip"], "min_count": 30, "window": 300,
   "distinct": "dst_port", "min_distinct": 8,        # 近似「多端口」= 扫描，而不是「连不上」
   "rules": [{"field": "event_type", "op": "in",
              "value": ["scan_attempt", "rejected_connection"]}],
   "whitelist": [{"not": {"field": "dst_internal", "op": "eq", "value": true}}]}   # 或反白名单：登记扫描平台
  ```
  另外把「同源 5 分钟 ≥30 个未建立连接且涉及 ≥8 个不同端口」作为唯一判据后，可以**合并 822 条**（见下）。
- 置信度：高（`conn_states.py:41-55` 与 builtin.py:816 的取值可直接对照；重试/丢包产生 S0 是 TCP 语义事实）。

### 内置-扫描尝试连接（builtin.py:822，priority=20，severity=low）

- 结论：OK（设计取舍清晰，代价已明确）
- 逻辑问题：单条件 `event_type eq "scan_attempt"`（builtin.py:829），wild 集合（`event_type` 是通用字段）→ 每个 log_type 都会求值；`priority=20` 早于 G 组大量高编号规则，但同类型内其它 per-event 规则普遍带专有字段（`dst_port`/`bytes_out` 等），S0 事件本身没有字节数，实际遮蔽风险低（对比 builtin.py:1141-1143 已用 `event_type ne scan_attempt` 主动避让）。
- 误报：命中「所有 S0」，因此量级最大（任务给的 `hit 3076 / 5min` 里很可能有它很大一份）。**但这是有意为之**：它被 `policy_skip_rules` 默认放行（`config.py:73`），`internal_routine_reason` 要求「内→内 + 严重度 < medium + 目标数 ≤1 + 无成功连接」才跳过（`triage_policy.py:135-160`），即内网单目标低危探活只落库不进模型——取舍合理，代价写清：**被 excluded 的摘要依然走投递通道、依然占用 24 条/分钟的额度**（`runner.py:_flush` → `push.deliver` 不区分 `excluded`），所以大量内网 S0 摘要会挤占真正需要分析的摘要的投递额度，把 1800s 超龄丢弃（`detector_digest_max_age_seconds`）推高——这是「3 万扫描 → 3076 命中 → 只有 138 条摘要投出去」的关键机制之一。
- 漏报：①REJ/RSTOS0/RSTRH 型扫描不覆盖（同 808）；②被排除的摘要虽落库但不出报告，若某次真实横向移动恰好只产生 1 个目标的 S0，会被静默降噪（这是取舍的代价，需要在界面把 `policy_skip_rules` 计数暴露给分析师）。
- 修复建议：保留现状，但建议（a）把该规则改成频率规则（同源 ≥N 才出一份摘要），降低摘要条数；（b）在 `_flush` 里让 `excluded` 摘要**不占**投递额度（或走单独的批量落库通道），避免噪声挤占 24/分钟额度。
- 置信度：高（`config.py:73`、`triage_policy.py:135-160`、`runner.py:_flush`/`push.deliver` 三处均可直接引用）。

---

### 本组 Top 3 问题

1. **`内置-大面积目标探测`（builtin.py:781-794）实质是无条件计数规则**：唯一条件 `src_ip exists` 恒真，跨全部 log_type 按源计数，5 分钟遇到 25 个不同 `dst_ip` 即 medium（监控服务器、备份、代理、更新客户端、NAT 后多用户全部命中），同时又漏掉「单目标多端口深扫」（`distinct` 只看 `dst_ip`）。它是本组最可能贡献 `hit 3076`/摘要洪泛、并与 24 条/分钟投递额度冲突的规则。最小修复：把条件换成未建立连接（`scan_attempt`/`rejected_connection`）+ `min_distinct` 提到 40，另加一条 `distinct="dst_port"` 的深扫规则。
2. **`内置-高频扫描连接`（808）+ `内置-扫描尝试连接`（822）+ `内置-端口扫描`（797）三条同行为规则，语义、覆盖、定级三处打架**：只有 S0 被计（漏 `REJ/RSTOS0/RSTRH` 型扫描，`conn_states.py:41-55`），防火墙丢包与容器重试造成的正常 S0 被当扫描（NAT 放大），同一次扫描会产出 2-3 份不同规则名的摘要（`aggregate.py` 键含规则名），severity 分别是 high/low/medium。建议合并为「同源 ≥30 个未建立连接且 ≥8 个不同端口」一条 high + 一条长窗口（`window: 21600`，与 builtin.py:1462/1482 的既有做法对齐）低速扫描规则。
3. **`内置-框架漏洞探测特征`（676）**：一条规则里同时有「永不成立的死条件」（`/index\.php\?s=`，因 `uri_path` 已去查询串，`normalizer.py:307-313`）、「大面积 FP」（`\.do$|\.action$` 命中所有遗留 Java 应用的正常业务请求）、「被 priority 8 完全遮蔽的重复条件」（`rememberMe=` 与 builtin.py:298 同条件，critical/high 双份定义）。最小修复：拆出 query_string 分支抓 ThinkPHP、删除 `.do$|.action$` 或降级单列、删掉 `rememberMe=` 只留 `shiro`。

补充（不占 Top 3 但落地成本最低的两处）：`内置-敏感文件与源码泄露探测` 补 `whitelist: _WHITELIST_HEALTH`（一行，直接止住 K8s 探针打 `/actuator/*` 的持续 high）；`内置-未授权访问探测成功` 把 `auth_scheme ne basic` 换成 `not auth_scheme exists`（一行，修掉「只排 Basic、放过所有会话登录」的逻辑漏洞）。

---

## 评审结论

- Correct：15 条规则的**字段与路由**基本正确——C 组没有「混合多类型专有字段导致某些 log_type 上 AND 恒假」的死规则；`ja3` 只挂 ssl、Web 字段同时挂 http+wazuh（与 `engine.py:_FIELD_TYPES`、`normalizer.py` 的 Wazuh 分支一致）；`端口扫描`/`扫描尝试连接` 的 event_type 均有真实生产者（`tests/py/test_conn_states.py:227` 有守卫测试）。
- Fixed：无（本次只做分析，未修改任何文件；按评审指令不写 `progress.md`）。
- Finding（按影响排序，均为 P1）：
  1. P1 `builtin.py:793` — `src_ip exists` 恒真，`大面积目标探测` 退化为无条件计数（证据：`engine.py:_match` 的 exists 语义 + `frequency.py` 按 src 分组）。
  2. P1 `builtin.py:816` — 仅认 `scan_attempt`（S0），漏 `rejected_connection`（`conn_states.py:44-52`）。
  3. P1 `builtin.py:688` — `/index\.php\?s=` 死分支（`normalizer.py:307-313` 去查询串）。
  4. P1 `builtin.py:653` + `normalizer.py:337-340` — `auth_scheme ne basic` 对空值恒真，未授权访问规则语义不成立。
  5. P1 `builtin.py:609-638` — 缺 `whitelist`，`/actuator` 分支打 K8s 探针（同文件 728/745/760/1401 都有白名单，唯独这条没有）。
  6. P1 `builtin.py:145-146...`（本组相关）`builtin.py:684` 与 `builtin.py:298` 同条件重复，priority 8 遮蔽 10。
  7. P2 780 段 `内置-服务端错误突变` 无白名单、key 缺 `dst_ip`；`内置-端口扫描` 依赖 Wazuh 描述含 `scan`（`normalizer.py:857`）过宽；`内置-参数fuzzing` 应为频率规则。
- Merge verdict：**OK with notes**（C 组无 P0；建议先做 5 处一行级修复——白名单补齐、`ne basic` 改 `not exists`、`src_ip exists` 换判据、删死分支与重复条件——再评估阈值类改动，因为阈值改动需要实机流量对账）。
- 需主管执行的验证（我不执行构建/测试）：`pytest tests/py/test_conn_states.py tests/py/test_rules_routing.py tests/py/test_detector_runner.py`；另建议用近一周实机数据按「规则名 × 源IP」统计各条命中量，确认 `大面积目标探测`、`扫描尝试连接`、`敏感文件`、`框架漏洞探测` 四条的 FP 占比，再定最终阈值。

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "逐条覆盖 builtin.py:577/594/609/641/660/676/700/714/732/749/764/781/797/808/822 共 15 条规则，每条给出结论/逻辑/FP/FN/修复建议/置信度；结论均有行号与代码路径依据（engine.py:_match、normalizer.py:307-313/525-526/857-858、conn_states.py:41-55、frequency.py:observe、runner.py:686/_flush、config.py:71-76/186-187、triage_policy.py:135-160、main.py:47-64、detector/push.py:deliver、aggregate.py:_agg_key）。"
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "pytest tests/py/test_conn_states.py tests/py/test_rules_routing.py tests/py/test_detector_runner.py",
      "result": "not-run",
      "summary": "评审只读，不执行命令；请主管按仓库规范在 CI/流水线侧运行"
    }
  ],
  "validationOutput": [
    "路由核算：C 组无「混合多类型专有字段 → 某些 log_type 上 AND 恒假」的死规则；云元数据(dns/http/wazuh,or 逻辑)、敏感文件/框架漏洞/参数fuzzing/未授权访问(http+wazuh) 归属正确。",
    "死条件唯一定位：builtin.py:688 的 /index\\.php\\?s= 永不成立（uri_path 已由 normalizer.py:307-313 去掉查询串）。",
    "遮蔽核对：builtin.py:684 cookie rememberMe= 与 builtin.py:298（priority 8）同条件，runner.py:686 首个命中即停导致前者恒不生效。",
    "恒真条件定位：builtin.py:793 src_ip exists 恒真（engine.py:_match exists 语义），大面积目标探测退化为无条件全量计数。",
    "S0 语义核对：conn_states.py:41-55 显示只有 S0→scan_attempt，REJ/RSTOS0/RSTRH→rejected_connection，而 builtin.py:816 取值仅 scan_attempt/port_scan。",
    "投递额度机制：runner.py:_flush + detector/push.py:deliver 不区分 excluded 摘要，被 triage 跳过的摘要仍占用 24 条/分钟额度。"
  ],
  "residualRisks": [
    "FP/FN 比例未做量化：我无法访问实机流量与规则命中分布，Top 3 的优先级依据是代码事实 + 通用流量形态，不是本环境的实测占比；建议按「规则名 × 源IP」拉一周统计后再定阈值。",
    "阈值类结论（min_count 30/40/60、窗口 300s、白名单 UA 名单）依赖部署形态：传感器是否看到代理→后端流量、是否存在 NAT 出口、内网探针种类，都会显著改变 FP 判断。",
    "内置-端口扫描 的 Wazuh 侧宽匹配（描述含 scan → port_scan）需要 Wazuh 告警样本才能确认实际影响面。",
    "JA3 规则的 in 大小写/ strip 问题在 ja3_blocklist 为空时不可见，需在启用该配置的实例上复验。",
    "本次未评审 D-G 组与 agent 侧仓库的同名规则，跨栈一致性（两侧种子规则是否逐字一致）未核对。"
  ],
  "noStagedFiles": true,
  "diffSummary": "无代码改动：本次为只读评审，未修改、未暂存任何文件。",
  "reviewFindings": [
    "P1: ndr/backend/app/rules/builtin.py:793 - 大面积目标探测 唯一条件 src_ip exists 恒真，等于无条件按源计数(25 distinct dst_ip/5min)，FP 洪泛并占用 24 条/分钟投递额度",
    "P1: ndr/backend/app/rules/builtin.py:816 - 高频扫描连接 只认 scan_attempt(S0)，漏 rejected_connection(REJ/RSTOS0/RSTRH)，且 NAT/重试造成的正常 S0 被当扫描",
    "P1: ndr/backend/app/rules/builtin.py:688 - 框架漏洞探测特征 的 /index\\.php\\?s= 分支永不成立(uri_path 去查询串)，ThinkPHP 探测漏报",
    "P1: ndr/backend/app/rules/builtin.py:653 - 未授权访问探测成功 的 auth_scheme ne basic 对空值恒真，仅排除 HTTP Basic、放过所有会话式登录访问",
    "P1: ndr/backend/app/rules/builtin.py:609-638 - 敏感文件与源码泄露探测 无 whitelist，/actuator 分支命中 K8s 探针(/actuator/health)持续 high",
    "P1: ndr/backend/app/rules/builtin.py:684 vs builtin.py:298 - cookie rememberMe= 条件重复定义(critical/high)，priority 8 遮蔽 priority 10",
    "P2: ndr/backend/app/rules/builtin.py:770-777 - 服务端错误突变 无 whitelist 且 key 缺 dst_ip，反代作为 src 时把全体用户 5xx 归一到单个 IP",
    "P2: ndr/backend/app/rules/builtin.py:805 - 端口扫描 依赖 Wazuh 描述含 scan(normalizer.py:857) 宽匹配，与 808/822 三重重叠",
    "P2: ndr/backend/app/rules/builtin.py:708-709 - 参数fuzzing超长载荷 是逐条规则(单次超长即报)、无白名单，SAML/OAuth/中文 URL 编码路径正常超长即命中",
    "P2: ndr/backend/app/rules/builtin.py:740-745 - 多路径探测 无 status_code 过滤，爬虫/压测/正常浏览 40 个 200 路径即 high，且与 714 条同一行为双报",
    "P2: ndr/backend/app/rules/builtin.py:756-760 - 暴力路径枚举 无 status_code 过滤、key 缺 dst_ip，轮询接口(2s 刷新)必报；资源 ID 枚举(路径变化)不覆盖"
  ],
  "manualNotes": "本次为只读评审，未修改任何文件，也未写 progress.md（评审只读指令优先）。产物为 C 组 15 条规则的逐条评审报告 + 本组 Top 3。最重要的三条落地建议：①大面积目标探测把 src_ip exists 换成未建立连接判据并提高 min_distinct；②合并 797/808/822 并补齐 REJ/RSTOS0/RSTRH；③框架漏洞探测 拆 query_string 分支、删 .do$/.action$ 与重复的 rememberMe=。另有两处一行级修复（敏感文件规则补 whitelist、未授权访问规则 ne basic 改 not exists）成本最低、收益立竿见影。需要主管执行 pytest tests/py/test_conn_states.py tests/py/test_rules_routing.py tests/py/test_detector_runner.py 复核；阈值类改动建议先用实机流量做规则×源IP 命中统计再定。"
}
```