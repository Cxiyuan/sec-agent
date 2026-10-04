## 本组小结

**H 组（builtin.py:1261-1327）**

| 规则 | 结论 | 一句话 |
|---|---|---|
| 内置-Wazuh高危告警(1263) | 严重度不当/与描述不符 | 只覆盖「没被规则组分类」的 level≥12 事件；组内高危反而被压成 medium/low |
| 内置-Wazuh文件完整性变更(1274) | 误报 | syscheck 全量文件变更都是 medium，且路径(data.file)没进 schema，想收窄都收窄不了 |
| 内置-Wazuh漏洞告警(1285) | 误报/优先级不当 | 每个 CVE×每台 agent 一条 medium，没有宿主机/严重度维度 |
| 内置-Wazuh网络告警(1296) | 基本 OK（有分类顺序隐患） | 单条件规则没问题，但 event_type 分类顺序可能把防火墙告警归到 system_change |
| 内置-Wazuh MITRE映射命中(1307) | 严重度不当/重复 | 只要带 mitre 就 medium，不看告警等级；MITRE 本身已随告警一起投递 |
| 内置-Wazuh策略违规(1318) | 严重度不当 | audit 组全量 low/priority=34，高危 audit 事件被埋在最后 |
| 内置-CSRF可疑来源(1330) | 与描述不符/漏报 | 只在 referer 含 evil/attacker/burp/interact.sh 时报，不是 CSRF 检测 |
| 内置-CORS配置错误探测(1349) | 疑似死规则（字段错） | Origin 头落在 req_headers，规则查的是 query/body |
| 内置-上传类型不匹配(1371) | 疑似死规则 | content_type 在 Zeek 链路根本没人填（内容类型只在 req_headers 里） |
| 内置-API高频调用(1390) | 误报/白名单失效 | src_ip 单键 200/5min，NAT 与 SPA 轻松超；/health 白名单永不生效 |
| 内置-协议异常(1405) | 疑似死规则 | weird.log 的 event_type 是 generic，notice.log 被显式关闭 |
| 内置-TLS异常(1416) | 疑似死规则 | tls_anomaly 只能由 notice 的 note 产出，本部署不产 notice |
| 内置-SMTP滥用(1427) | 误报（严重） | OR log_type==smtp ⇒ 每封正常邮件都报 medium |
| 内置-常见敏感端口访问(1441) | 误报/重复 | 内→内运维与 DB 连接全报 low；3389 被 priority=30 的规则遮蔽 |
| 内置-内网慢速横向(1454) | 误报（严重）+可运营性 | src_ip 单键 6h，5 个内网目标即 high；服务器常驻告警并撑出大键 |
| 内置-内网慢速服务枚举(1474) | 误报（严重） | 同一目标 10 个端口（RPC 动态端口/DC 服务）即 medium |

---

### 内置-Wazuh高危告警（builtin.py:1263，priority=10，severity=high）
- 结论：严重度不当（描述与实现不一致）
- 逻辑问题：描述写「Wazuh 规则等级 >= 12」，实现是 `event_type == "wazuh_high_alert"`；而 `normalizer._wazuh_event_type()`（normalizer.py:830-861）里等级判定是**最后**的兜底分支：只要 rule.groups 命中 `web/attack`(833)、`authentication_failed/sshd`(835)、`malware/ransomware/virus/rootcheck/trojan`(837)、`syscheck/ossec/sysmon/windows`(839)、`vulnerability/cve`(841)、`firewall/ids/ips`(843)、`audit/policy`(845) 就提前返回，**等级完全不参与**。所以 level 13/15 的 FIM、漏洞、防火墙、audit 告警永远不会走到 `wazuh_high_alert`。
- 误报：单条件 `eq`，本身不产生额外误报（`event_type` 由归一化给定）。
- 漏报：不是漏检（那些事件仍会被 H 组其它规则命中），而是**等级信号丢失**：level 15（`_map_wazuh_level` → critical，normalizer.py:869-878）的 syscheck 事件被「内置-Wazuh文件完整性变更」以 **medium** 投递。真正决定摘要等级的是规则自身 `severity`（runner.py `_aggregate`：`severity=str(rule.get("severity") or "medium")`），归一化算出的 `log.severity` 不进这个字段。
- 修复建议：`wazuh_high_alert` 这条保留给「非分组高危」，同时给 H 组每条分组规则加等级闸门，例如在「文件完整性变更」里加 `{"field": "severity", "op": "in", "value": ["high", "critical"]}`；或者把 `_wazuh_event_type` 改成「先按等级切 high/其它、再细分组」（`level>=12` 时统一 `wazuh_high_alert` 并在分组规则里用 severity 二次判定）。描述也要改成「未落入已知规则组的 level≥12 告警」。
- 置信度：高（normalizer.py:830-861 分支顺序可逐行核对）

### 内置-Wazuh文件完整性变更（builtin.py:1274，priority=30，severity=medium）
- 结论：误报（噪声量级不可运营）
- 逻辑问题：单条件 `event_type == "wazuh_system_change"`，而该标签来自 groups 含 `syscheck|ossec|sysmon|windows` 的**全部**告警，含最常见的 level 7「Integrity checksum changed」、软件包升级、日志轮转、配置写入。
- 误报：真实例子——`apt upgrade` 一次改动能产出几百条 syscheck 告警；Windows 事件日志（groups 含 `windows`）也会被判成「系统变更」。全部按 medium 投递，聚合键是（src_ip + 规则名）（aggregate.py:32-39），一台机器一天几十条摘要。
- 漏报：无（反向问题是过报）。
- 修复建议：① 加 `{"field": "severity", "op": "in", "value": ["medium", "high", "critical"]}`（丢掉 level<8）；② 按路径收窄——但**当前做不到**：Wazuh 分支（normalizer.py:711-780）没有把 `data.file` 映进任何字段（`filename` 只在 `_http_fields` 里从 Zeek 文档取，normalizer.py:539），FIM 路径只留在 `raw`。建议先在 `normalize_wazuh` 增补 `filename=str(data.get("file") or "")[:256]`，再按 `(?i)^/etc/(passwd|shadow|sudoers|ssh/)|/www/|\.jsp$` 之类做白/黑名单；否则这条规则在现网只能靠排除过滤器按 src_ip 粗粒度压噪。
- 置信度：高（normalizer.py:711-780 无 data.file 映射；FIELD 表见 schemas.py:56/80-84）

### 内置-Wazuh漏洞告警（builtin.py:1285，priority=30，severity=medium）
- 结论：误报/优先级不当
- 逻辑问题：`event_type == "wazuh_vulnerability"`（groups 含 `vulnerability|cve`，normalizer.py:841-842）。Wazuh vulnerability-detector 是**每台 agent × 每个 CVE 一条告警**，level 通常 5-10，因此 `_map_wazuh_level` 会给 low/medium，但规则一律 medium。
- 误报：真实例子——一次全量漏洞扫描后 200 台主机 × 平均 50 个 CVE = 上万条告警，全部进 medium 摘要，直接冲掉每分钟 24 条投递额度（config.py:170 `detector_max_digests_per_minute: int = 24`），真实攻击摘要被回队后超龄丢弃（runner.py `_flush` 里 `expired` 丢弃）。
- 漏报：无。
- 修复建议：加 `severity in ["high","critical"]` 闸门（只报高危 CVE）；或改成频率规则（`key: ["src_ip"], min_count: 20, window: 3600`）把「同一主机大量 CVE」聚成一条；同时把 severity 降到 low 并明确说明它是清单类信息，不与攻击告警抢投递额度。
- 置信度：高（规则条件 + normalizer.py:841-842 + 投递额度配置）

### 内置-Wazuh网络告警（builtin.py:1296，priority=28，severity=medium）
- 结论：基本 OK（分类顺序有隐患）
- 逻辑问题：单条件 `event_type == "wazuh_network_alert"`（groups 含 `firewall|ids|ips`，normalizer.py:843-844）。字段真实、路由是通配集合（只引用 `event_type` → `_COMMON_FIELDS`，engine.py `_COMMON_FIELDS`/`build_rule_index`），预期 log_type 上一定会求值。
- 误报：规则本身不引入；噪声取决于上游 Wazuh 规则（pfSense/iptables 规则量很大），属取舍代价。
- 漏报：**分类顺序隐患**：`syscheck|ossec|sysmon|windows` 分支(839) 在 `firewall|ids|ips`(843) 之前，而 Wazuh 默认规则组里 `ossec` 是常见前缀组；若某条防火墙/IDS 规则组同时含 `ossec`，会被归成 `wazuh_system_change`（priority=30 的 FIM 规则）而不是网络告警。这条我无法在仓库里枚举客户的 Wazuh 规则集，置信度中。
- 修复建议：把 event_type 的计算改成「组名按**完整词**匹配」而不是子串（例如 `groups.split(",")` 后做集合交），`ossec` 这类过泛的子串应移除；或者在规则侧同时接受两种标签：`{"field":"event_type","op":"in","value":["wazuh_network_alert","wazuh_system_change"]}`（不推荐，会把 FIM 噪声也拉进来）。优先改 `_wazuh_event_type`（两个栈都要改，见文末）。
- 置信度：中（分支顺序确凿；「客户规则组里同时含 ossec + firewall」无法在本仓库证实）

### 内置-Wazuh MITRE映射命中（builtin.py:1307，priority=32，severity=medium）
- 结论：严重度不当/信息重复
- 逻辑问题：唯一条件是 `{"field":"mitre","op":"exists"}`。`mitre` 由 `_wazuh_rule_info` 从 `rule.mitre.id/technique` 拼出（normalizer.py:692-710），只要 Wazuh 规则带 ATT&CK 映射就有值 → **不看等级、不看规则组**。语义完全等同于「Wazuh 里配了 MITRE 的告警」，等级 3 的信息类告警也会被投成 medium。
- 误报：真实例子——Wazuh 默认规则集里带 `mitre.id` 的规则（各类 audit/sysmon/自定义 decoder）数量很大，任何一条 level 3-6 的此类告警，若无更高优先级规则命中，就会被报成 medium「MITRE映射命中」。
- 漏报：无（纯泛化规则）。
- 路由/开销：`mitre` 既不在 `_FIELD_TYPES` 也不在 `_COMMON_FIELDS`（engine.py 两表），所以 `build_rule_index` 的 `owner` 为空 → 进 **wild 通配集合**，每条 Zeek 日志（conn/dns/http/ssl…）都会白跑一次 `getattr(log,'mitre')`。不影响正确性，纯浪费。
- 修复建议：① 加等级闸门 `severity in ["high","critical"]`；② 若要保留「MITRE 命中」信息，应做成**标注**而不是独立规则（摘要里带 `raw.rule.mitre` 就够了），否则它与上游告警是同一事实的两遍投递；③ 从规则名去掉误导：叫「Wazuh 高危 MITRE 告警」。若坚持保留，至少降级为 `severity: low, priority: 45`。
- 置信度：高（规则条件 + normalizer.py:692-710 + engine.py 路由表）

### 内置-Wazuh策略违规（builtin.py:1318，priority=34，severity=low）
- 结论：严重度不当
- 逻辑问题：`event_type == "wazuh_policy_violation"` 来自 groups 含 `audit|policy`（normalizer.py:845-846）。`audit` 组覆盖 auditd 全谱：既有「文件权限变更」这类低危，也有「audit 规则被删除 / 提权执行 / 可疑命令」这类高危（Wazuh 里常见 level 10-13）。
- 误报：数量大但不是规则错；错在**所有** audit 事件都被压成 low，并且 priority=34 意味着只要任何更早优先级的规则命中（含 32 的 MITRE 规则、30 的 FIM 规则——`audit` 事件通常不带 syscheck 组，所以主要被 32 号截走）它就不会被报；MITRE 规则存在时，带 mitre 的 audit 高危事件实际报的是「Wazuh MITRE映射命中/medium」，名字与语义都不对。
- 漏报：无检测遗漏，但有**定级错误**：高危 audit 事件的处置优先级被 low 掩盖。
- 修复建议：加等级闸门 `severity in ["medium","high","critical"]`（auditd 高危都在 level≥8），并把 priority 前移到 20 附近，避免被泛化的 MITRE 规则(32)遮蔽；描述改为「auditd/策略类且等级≥中危」。
- 置信度：高（规则条件 + 分支语义 + 优先级遮蔽链条可由 runner.py `hit = next(...)` 推出）

### 内置-CSRF可疑来源（builtin.py:1330，priority=30，severity=low）
- 结论：与描述不符/漏报
- 逻辑问题：AND 三条：`method in [POST,PUT,DELETE]`（`in` 精确匹配、大小写敏感，Zeek method 是大写，OK）、`referer` 匹配 `^https?://`、`referer` 匹配 `(?i)(evil|attacker|burpcollaborator|interact\.sh)`。第三条把规则绑死成「referer 里出现这几个词」，而描述写的是「状态变更请求携带外部站点 Referer」。第三条是 re.search 子串匹配 → `https://evil-corp.example`、`https://media-evil.example` 这类含 `evil` 子串的真实域名同样命中（低概率但存在）。前两条对第三条几乎无约束力（第三条本身不限 scheme），因此三条本质是「一个关键字黑名单」。
- 误报：公司内部授权渗透测试/红队用 Burp（`burpcollaborator.net`）或 `interact.sh` 做外带验证时，POST 的 referer 会被打上自己的协作域名 → 每次都报；这也是唯一的高频来源，说明这条规则实际是「靶场/工具自检」规则。
- 漏报：真正的 CSRF 完全不覆盖——(a) 攻击者服务器域名不含这些关键字（含 99% 场景）；(b) 现代浏览器 `Referrer-Policy: no-referrer`/`strict-origin-when-cross-origin` 下跨站 POST 常常**无 referer**；(c) 规则要求 referer 以 `http(s)://` 开头，OCR/伪协议 referer（`Referer: null`、`about:blank`）不匹配。另外 `referer` 字段在 Zeek 侧确实会被填（normalizer.py:531 `doc.referrer`），Wazuh 侧来自 `data.referer`（normalizer.py:757），字段是真的，问题在条件。
- 修复建议（可抄）：保留一条「已知测试/协作域名」规则但改名并降级，另建真正的 CSRF 规则：
  `{"logic":"and","rules":[{"field":"method","op":"in","value":["POST","PUT","DELETE"]},{"field":"referer","op":"exists"},{"not":{"field":"referer","op":"regex","value":"(?i)^https?://[^/]*(<自家域名填管理界面白名单>)"}}]}` —— 但规则语言里没有「本站域名」概念，落地只能靠**规则级 whitelist**（`whitelist` 支持 `regex`，engine.py `whitelisted`）把本公司域填进去；这属于环境配置，别写死进内置规则。同时新增「无 referer 的跨站状态变更」规则时必须依赖 cookie/session 字段，否则误报会失控——这一点要写进规则注释。
- 置信度：高（三条条件是自足的关键字黑名单，可从 builtin.py:1335-1347 直接读出；referer 字段填充见 normalizer.py:531/757）

### 内置-CORS配置错误探测（builtin.py:1349，priority=30，severity=low）
- 结论：疑似死规则（字段错）
- 逻辑问题：`logic: or`，两条条件分别是 `query` 与 `body` 匹配 `(?i)origin=(null|https?://(evil|attacker))`。CORS 探测的特征是**请求头** `Origin:`，而 Zeek 的请求头全量落在 `req_headers`（`shentong-httpheaders.zeek`，normalizer.py:531 `"req_headers": str(doc.get("req_headers") or "")[:8192]`），`query` 在 http 上是完整 URI（`normalizer._http_fields`：`path, qs = _split_uri(uri)`，query = uri 或 doc.query），**不含请求头**。所以 `curl -H 'Origin: null'`、`Origin: https://evil.example` 这类标准探测永不命中——除非攻击者把 `origin=null` 塞进 query/body，那不是 CORS 探测。
- 误报：即便命中（query 里真有 `origin=...`），`(?i)origin=(null|https?://(evil|attacker))` 里的 `origin=` 没有边界约束，`?redirect_origin=...`、`?x_origin=https://evil...` 也算；`evil|attacker` 是子串，不含词边界。属低概率但由于这是「低危」规则，代价可接受。
- 漏报：真实变体全漏：`Origin: https://attacker.com`（头）、`Origin: null`（头）、任意非 evil/attacker 域名的跨域探测、`Access-Control-Allow-Origin: *` 误配的**响应**（在 `resp_headers`，本规则完全不看）。
- 修复建议（可抄）：
  - 头路径：`{"field":"req_headers","op":"regex","value":"(?im)^[\\t ]*origin[\\t ]*:[\\t ]*(null|https?://[^\\r\\n]+)(\\r?\\n|$)"}`，再配一条「非本站域白名单」思路（同上，靠 whitelist 配本公司域）；
  - 响应误配：`{"field":"resp_headers","op":"regex","value":"(?im)^[\\t ]*access-control-allow-origin[\\t ]*:[\\t ]*(\\*|null)"}`，命中 `*`+凭据类组合才报才有价值。
  - 路由注意：`req_headers`/`resp_headers` 在 `_FIELD_TYPES` 里只挂 `("http",)`（engine.py），加这两条会把规则从 `dns/http/wazuh` 收成 `http` 专有——这正是想要的（`query` 在 dns 上能命中 `origin=` 纯属巧合噪声）。
- 置信度：高（req_headers 填充路径确凿；Zeek http.log 无头字段进 query 的通路）

### 内置-上传类型不匹配（builtin.py:1371，priority=20，severity=medium）
- 结论：疑似死规则（字段永远为空）
- 逻辑问题：AND 三条：`event_type == "http_upload"`、`content_type` 匹配 `(?i)(image/|text/plain)`、`uri_path` 匹配 `(?i)\.(php|jsp|aspx|sh|war)`。关键在 `content_type`：
  - Zeek 侧 `content_type = str(doc.get("content_type") or doc.get("request_content_type") or "")`（normalizer.py:521），但 Zeek `http.log` **没有** content_type 列，`ndr/zeek/site/*.zeek` 里也没有任何脚本产出该列（对 `content_type|request_content_type` 全仓 grep，只有 builtin.py 与 normalizer.py 命中；`shentong-httpheaders.zeek` 只做 `req_headers/resp_headers`）。→ 该 AND 在 Zeek 线恒为假。
  - Wazuh 侧 `content_type=str(data.get("content_type") or "")[:128]`（normalizer.py:767），Wazuh 告警极少带这个字段；而且 `event_type == "http_upload"` 只在 `_http_event_type` 里产生（normalizer.py:379-388，**Zeek 专用**），Wazuh 分支永远不产 `http_upload`。两边合起来 ⇒ 规则永不命中。
  - 另外 `http_upload` 自身的判定（normalizer.py:383-387）是 `"multipart/form-data" in content_type.lower() or path.endswith((.php,.jsp,.jspx,.aspx,.ashx,.war))`；因为 content_type 空，实际只剩「路径以脚本后缀结尾」这一条分支——这恰好说明**只要把 content_type 从 req_headers 里解出来，这条规则就能活**。
- 误报：一旦补上 content_type 解析会立刻出现一类误报：`text/plain` 到 `*.php` 的合法 API 调用（很多 PHP 接口用 `Content-Type: text/plain` 收纯文本/JSON 串）会被报成「上传绕过」。所以修复时必须同时加「body 里真有上传文件名」的条件。
- 漏报：真正的上传绕过（`Content-Type: image/png` + multipart 里 `filename="shell.php"`，或上传到 `/upload`、`/api/v1/upload` 这种**没有脚本后缀的路径**）全漏；而且条件查的是**端点路径**，描述却写「Content-Type 与文件名不符」——字段与语义不一致。上传文件名在 `filename` 字段里只有 files.log 才有（normalizer.py:539 从 doc.filename 取，_FIELD_TYPES 里 `filename → ("files",)`），http 上传的文件名只在 multipart body 里。
- 修复建议（可抄）：
  1. 先在 `normalizer._http_fields` 里补解析：`content_type = str(doc.get("content_type") or doc.get("request_content_type") or _header_value(doc.get("req_headers"), "CONTENT-TYPE") or "")`（`req_headers` 是 `Name: value` 逐行文本，可用 `re` 提取，注意 Zeek 侧头名**被统一成大写**，见 ndr/zeek/README.md:214）；
  2. 规则改成「上传端点 + 声明是图片/文本 + body 里出现可执行文件名」：
     `{"logic":"and","rules":[{"field":"method","op":"in","value":["POST","PUT"]},{"field":"content_type","op":"regex","value":"(?i)^(image/|text/plain)"},{"field":"body","op":"regex","value":"(?i)filename=\\s*[\"']?[^\"'\\r\\n]*\\.(php\\d?|phtml|phar|jspx?|asp|aspx|ashx|war|sh)\\b"}]}`
  3. 若坚持用 `uri_path`，至少把 `\.(php|jsp|aspx|sh|war)` 扩成 `\.(php\d?|phtml|phar|jsp|jspx|asp|aspx|ashx|war|sh)$`（当前缺 `phtml/phar/jspx/ashx`，且无 `$` 会连带匹配 `/x.php.txt`——后者算「好处」但也带来 `/download.php` 这类噪声）。
  4. 后端 body 采集有「二进制块跳过」的口径（ndr/zeek/README.md:254），真实图片 multipart 体的 body 可能为空 → 依赖 body 的条件仍有漏报，需在规则注释里写清这条上限。
- 置信度：高（content_type 全仓只有两处引用、Zeek 无该列；`http_upload` 只由 Zeek 分支产出）

### 内置-API高频调用（builtin.py:1390，priority=34，severity=low）
- 结论：误报 + 白名单失效
- 逻辑问题：`mode:count`、`key:["src_ip"]`、`min_count:200`，**没有 `window`**，所以沿用全局 `freq_window_seconds=300`（config.py:186）→「单个 src_ip 300 秒内对 `/api|/rest|/graphql` 开头路径 ≥200 次」。没有 `distinct`、没有 `dst_ip`/`uri_path` 维度、没有方向条件。
- 误报：真实例子——(a) NAT/出口代理后面的整栋办公楼共用一个出口 IP，前端 SPA 每 10 秒轮询 3 个接口即 18 rps，300 秒 200 次是几分钟的事；(b) 内部巡检/自研探针没有用白名单里的 UA（`_WHITELIST_HEALTH` 只认 kube-probe/prometheus/zabbix/nagios/uptime/healthcheck/ELB-HealthChecker，builtin.py:28-34），`python-requests`/`curl` 打 `/api/health` 照算；(c) 合规扫描器、日志采集回传、移动端。
- 白名单失效（重要）：`{"field":"uri_path","op":"in","value":["/health","/healthz","/ping","/metrics"]}` 这一条**永远不可能命中**——同一个规则的 `rules` 要求 `uri_path` 匹配 `^/(api|rest|graphql)`（engine.py `_match` 的 `in` 是精确相等），而 `/health` 不满足那个正则；由此这条 `whitelist` 元素是死配置，只剩 UA 分支有效。如果本意是「放过 `/api/health`」，写法必须是正则或后缀匹配。
- 漏报：无（纯泛化）；但它与另外两条 count 规则重复计费——同一爬取流量会同时触发「内置-暴力路径枚举(单路径高频)」(priority=26, key=src_ip|uri_path, min 60) 与「内置-多路径探测」(priority=24, distinct uri_path≥40)，产出 2-3 份语义重叠的摘要（count 规则全部独立求值，runner.py 末尾 for 循环）。
- 修复建议（可抄）：
  - 白名单改成 `{"field":"uri_path","op":"regex","value":"(?i)^/(api/)?(health|healthz|ping|metrics|readyz|livez)$"}`；
  - 参数改成「有区分度」的组合：`"key":["src_ip","dst_ip"]`、`min_count: 600`、`distinct: "uri_path"`、`min_distinct: 50`（API 爬取的形态是多路径而非单路径），或加 `{"field":"src_external","op":"eq","value":True}` 只报外部源（内部 API 调用交给画像/基线，避免和「暴力路径枚举」重报）；
  - 明确降级为 `severity: info`，它已是最低优先级 34，信息价值不足以占投递额度。
- 置信度：高（步骤与字段可逐项核对；白名单恒假可由 `_match` 的 `in` 语义直接推出）

### 内置-协议异常（builtin.py:1405，priority=30，severity=medium）
- 结论：疑似死规则（本部署永不触发）
- 逻辑问题：唯一条件 `event_type == "protocol_anomaly"`。该标签**只能**由 `_zeek_event_type` 的 note 分支产出：`if "weird" in n: return "protocol_anomaly"`（normalizer.py:797-798），`note = doc.get("note")` 只在 `notice.log` 里存在。
  - 而 `ndr/zeek/site/shentong-policies.zeek:32` 显式 `Log::disable_stream(Notice::LOG)`，注释写明「现在没加载任何会 raise notice 的策略」；`ndr/zeek/README.md:272` 的验收表也记「无 notice.log（未加载 policy/protocols/*），符合预期」。→ `note` 恒空。
  - 真正的协议异常在 `weird.log`，它是 EVENT 类（config.py:109 含 `weird`，会进检测器），但 `_zeek_event_type` 里**没有 `weird` 分支**（normalizer.py:801-827 只处理 dns/http/ssl/files/smtp/ssh/dhcp/notice），`conn_state` 为空 → 落到 `return conn_states.GENERIC_EVENT_TYPE`（值 `"generic"`，conn_states.py:32）。所以 `weird.log` 的每一条都被标成 `generic`，规则收不到。
- 误报：无（死规则）。
- 漏报：**Zeek 协议异常全量漏检**（畸形 HTTP、非法 DNS 响应、TCP 异常等），且这是静默的：`tests/py/test_conn_states.py:74-97` 的 `OTHER_EVENT_TYPES` 只断言「normalizer 有产出该标签的函数」，notice 流被关闭这件事它查不到，所以 CI 不会拦住。
- 修复建议：给 weird 明确事件类型（这才是修复点，不是改规则）——在 `normalizer._zeek_event_type` 加 `if log_type == "weird": return "protocol_anomaly"`（放在 conn_state 分支之前），并把 `协议异常` 规则加富化条件：`{"field":"raw.weird","op":"..."}` 不支持，改用 `summary`（weird.log 的 summary 来自 `doc.get("msg")`/log_type）或直接按 `log_type=="weird"`：`{"logic":"and","rules":[{"field":"log_type","op":"eq","value":"weird"}]}` 配合白名单过滤已知无害 name（如 `bad_TCP_checksum`）。注意 `log_type` 属 `_COMMON_FIELDS`，规则会进通配集合，开销可忽略。
- 置信度：高（notice 流关闭有代码与文档两处证据；weird 无分支可由 `_zeek_event_type` 全文核对）

### 内置-TLS异常（builtin.py:1416，priority=30，severity=medium）
- 结论：疑似死规则（本部署永不触发）
- 逻辑问题：唯一条件 `event_type == "tls_anomaly"`，而该标签只由 note 分支产出（`if "ssl" in n or "cert" in n: return "tls_anomaly"`，normalizer.py:793-794）。同「协议异常」：`Notice::LOG` 被关闭 → `note` 恒空。ssl.log 的正常事件类型是 `tls_session`（normalizer.py:806）。
- 误报：无。
- 漏报：证书类异常（自签、过期、域名不匹配、弱协议）在当前采集下没有任何规则覆盖——仓库里只有「内置-弱TLS版本」这类依赖 `log_type==ssl + tls_version`（builtin.py:529-533）和 `cert_issuer`（builtin.py:547-551）的规则，它们靠 ssl.log 字段，与本规则无关。也就是说这条规则名下的检测能力是 0。
- 修复建议：本部署不产 notice ⇒ 要么删掉这条规则（避免「看着有覆盖」的假象），要么改用 ssl.log 字段派生：新增 `event_type` 到 `tls_session` + `tls_version in ["tls10","tls11","sslv3"]` / `cert_issuer` 为空 + `server_name` 存在等条件。若确实要恢复 notice 线，则需要在 `shentong-policies.zeek` 里重新加载 `policy/protocols/ssl/*` 并把 notice 采回——那是采集变更，必须同步 `ndr/zeek/README.md` 的验收表（当前写着"符合预期：无 notice.log"）。
- 置信度：高（同「协议异常」，代码 + 文档两处证据）

### 内置-SMTP滥用（builtin.py:1427，priority=30，severity=medium）
- 结论：误报（严重，语义完全错位）
- 逻辑问题：`logic: or` —— 条件二是 `log_type == "smtp"`。`smtp` 在 EVENT 白名单里（config.py:109），`normalize_zeek` 对 smtp.log 的 `event_type` 是 `smtp_activity`（normalizer.py:809-810），于是**每一条 SMTP 会话日志**都直接命中这条「SMTP垃圾邮件/滥用行为」规则。条件一（`event_type == "smtp_abuse"`）只在 note 含 smtp/spam 时产出（normalizer.py:791-792），而 notice 已被关闭 ⇒ 实际生效的只有那个 OR 兜底分支。
- 误报：真实例子——内网用户通过 Zeek 可见的邮件中继（25/587）发正常邮件，每条会话报一次 medium；邮件中继/群发系统（HR、OA 通知）一天上千条，聚合成（src_ip, 规则名）摘要后每 5 分钟一条 medium，且 `triage_policy` 不会跳过它（`policy_skip_rules` 默认只有「内置-扫描尝试连接」「内置-恶意文件传输」，config.py:73；且内→内 + medium 已等于 `policy_internal_routine_min_severity="medium"`，条件是 `<` 门槛才跳过 → 不跳）。
- 漏报：条件一死掉后，真正的 SMTP 滥用（单源大量收件人、HELO 与 IP 不匹配、垃圾主题）没有任何检测；而 Zeek smtp.log 的 `mailfrom/rcptto/subject/helo` 字段**没有被归一化映射**（`_http_fields` 里没有它们，normalizer.py:514-556；Wazuh 分支也没有），所以想写内容规则必须先在 schema 里加字段。
- 修复建议（可抄）：
  1. 立即把 `{"field":"log_type","op":"eq","value":"smtp"}` 从 OR 里删掉（否则这条规则等同于「所有邮件」）；
  2. 用可用的维度做频率规则：`{"mode":"count","key":["src_ip"],"min_count":200,"window":3600,"logic":"and","rules":[{"field":"log_type","op":"eq","value":"smtp"}]}`，捕获短时间内大量投递；
  3. 若要内容级检测：在 `normalizer._http_fields` 增补 `mailfrom/rcptto/subject/helo`（schema 也要加），再写「同一会话多收件人 / subject 含 spam 关键字 / helo 与 server_name 不符」的规则。
- 置信度：高（OR 分支 + log_type 白名单 + note 关闭，三处证据链闭合）

### 内置-常见敏感端口访问（builtin.py:1441，priority=40，severity=low）
- 结论：误报/重复（与被遮蔽规则功能重叠）
- 逻辑问题：唯一条件 `dst_port in [22,23,3389,3306,5432,6379,27017]`，没有方向、没有 `conn_state`、没有成功/失败区分、没有 `log_type` 限定。`in` 是精确相等，`dst_port` 在 Zeek 侧是 int（`id.resp_p`，normalizer.py:661）→ 类型对得上，字段真实存在。
- 误报：真实例子——DBA 客户端整天连 3306、运维 SSH 连 22、开发连内网 Redis(6379)/Mongo(27017)/Postgres(5432)，全部是 src_internal→dst_internal 且 `conn_state=SF`（成功）→ 每条命中，按 (src_ip, 规则) 聚合成 low 摘要。因为 `internal_routine` 策略要求「无成功连接」，这类命中**不会**被跳过（triage_policy.py:141-175），所以合法运维流量会稳定占用投递额度。
- 漏报/遮蔽：`3389` 在这里是**冗余项**——「内置-横向移动管理端口」(priority=30, dst_port 含 3389) 更早命中，按 runner.py `hit = next(...)` 首命中即停，本条规则实际只剩 `22/23/3306/5432/6379/27017` 有表达力。反过来说，来自公网的 6379/27017 暴露（真实高危）与内网运维同等级（low），**严重度与危害不匹配**。
- 修复建议（可抄）：
  - 拆成两条：外→内高危：`{"logic":"and","rules":[{"field":"dst_port","op":"in","value":[22,23,3306,5432,6379,27017]},{"field":"src_external","op":"eq","value":True}]}` severity=high；内→内低危保留原条件但 severity=info，并加扫探特征 `{"not":{"field":"conn_state","op":"in","value":["SF","S1","S2","S3","RSTO","RSTR"]}}` 只报「没建成的连接」；
  - 去掉 3389（已被 30 号规则覆盖），避免同一事件两条规则竞争；
  - 建议在规则描述里写明：内部运维连接由排除过滤器/白名单在后台配置（不要把客户网段写死进内置规则）。
- 置信度：高（条件、优先级遮蔽、策略分支都可逐行核对）

### 内置-内网慢速横向（builtin.py:1454，priority=27，severity=high）
- 结论：误报（严重）+ 可运营性缺陷（正是「单键累计上万」的成因）
- 逻辑问题：
  - `mode:count, key:["src_ip"], window:21600, min_count:5, distinct:"dst_ip", min_distinct:5`，条件是 `src_internal==True AND dst_internal==True`。也就是「**任意**内网源 6 小时内出现 ≥5 个不同内网目标」——不含端口/协议/成功失败/事件类型任何限定。计数对象是**所有内网→内网日志**（conn/dns/http/ssl/files/smtp/ssh/dhcp 全算，count 规则不走 log_type 索引，runner.py 末尾 for 循环直接 `evaluate_conditions`）。
  - `min_count=5` 与 `min_distinct=5` 同时成立才触发，前者在后者之前早就满足了（frequency.py:73-78），因此它只是噪声参数；真正决定灵敏度的是 5 个目标。
  - 计数与去重用的 `count_key/getattr`（frequency.py:41-42、76）不经过 `_get_field` → 虚拟字段不能当 key/distinct，所以规则只能用条件表达方向；这是设计取舍，但代价是**无法按「排除服务器角色/扫描器 IP」细分键**，只能靠 whitelist/排除过滤器。
- 误报：真实例子——任何一台工作站 6 小时内都会访问 ≥5 台内网服务器（AD、DNS、文件共享、打印、WSUS、内网门户）；更糟的是**服务器自身也当源**：域控/文件服务器/内网反向代理对每个客户端的回包事件都是 src=服务器、dst=客户端且都是内网，于是这些主机的 `distinct dst_ip` 常在几百量级 → **长期处于「已触发」状态**；频率规则冷却 `freq_cooldown_seconds=300`（config.py:187），所以每 5 分钟最多再触发一次 → 单台服务器一天可达 ~288 条 high 摘要。这些摘要进入 `detector_max_digests_per_minute=24`（config.py:170）的额度里，直接挤掉真实攻击摘要（超出的回队后在 `_flush` 里按 `detector_digest_max_age_seconds=1800` 被丢弃，runner.py `_drop(client,"expired",...)`）——这会成为新的漏报源。
- 关于「单键累计上万」：member = `f"{entry.fingerprint()}:{ts:.3f}"`（frequency.py:59），`fingerprint()` 是 `sha256(source_system|event_type|src_ip|dst_ip|src_port|dst_port|protocol)[:32]`（schemas.py:fingerprint），即每个命中事件 ~47 字符、Redis 里约 60-70 字节；一台机器 6 小时内 2 万条内网事件 → 键 `shentong:freq:内置-内网慢速横向:<ip>:cnt` 约 2 万成员（≈1.3-1.5MB，含 `:dst` 另一个 ZSET），且 TTL = `window*2+60 = 43320s`（frequency.py:51），事件停了还要留 12 小时。每条事件还要跑一次 `ZREMRANGEBYSCORE`（O(logN+M)）+ `ZADD` + `ZCARD`，热路径开销随键大小线性上升。`ndr/zeek/README.md:274` 也记录了实测里这些键已存在。
- 漏报：不是漏报问题，是**信噪比**问题（真横向会淹没在 288 条/天的同类摘要里）。另外 `_is_internal` 对非 IP 字符串返回 True（iputil.is_public_ip 解析失败 → False → `_is_internal=True`），若某来源的 src_ip/dst_ip 是主机名（Wazuh 的 `data.srcip` 可能是非 IP 文本），会被当内网参与计数——低概率但存在。
- 修复建议（可抄，目标是「失败的、非服务的、低慢的横向」）：
  ```
  {"mode":"count","key":["src_ip"],"window":1800,"min_count":20,
   "distinct":"dst_ip","min_distinct":10,
   "logic":"and","rules":[
     {"field":"log_type","op":"eq","value":"conn"},
     {"field":"src_internal","op":"eq","value":true},
     {"field":"dst_internal","op":"eq","value":true},
     {"field":"conn_state","op":"in","value":["S0","REJ","SH","SHR","RSTOS0","RSTRH","OTH"]}
   ]}
  ```
  理由：`conn_state` 只在 conn.log 上非空，加 `log_type=="conn"` 才能让该条件真正生效；非 established 集合取自 conn_states.py:41-52（S0/REJ/SH/SHR/RSTOS0/RSTRH/OTH），建立成功的正常业务连接不再计数。若必须保留 6h 长窗，则 `min_distinct` 提到 ≥25 并另加「目标非服务器」的思路（用规则级 `whitelist` 让客户在后台配自己的 AD/文件服务器/扫描器 IP，不要写死内置规则）。
- 置信度：高（键/窗口/冷却/TTL/额度/丢弃路径均可定位到行；触发量的具体数字是量级估算，非实测）

### 内置-内网慢速服务枚举（builtin.py:1474，priority=26，severity=medium）
- 结论：误报（严重）
- 逻辑问题：`key:["src_ip","dst_ip"], window:21600, min_count:10, distinct:"dst_port", min_distinct:10`，条件同样是「内→内」两个虚拟字段。即「同一内网源 6 小时内对同一内网目标出现 ≥10 个不同**目的端口**」。没有 `conn_state`/`log_type`/协议限定，成功连接也计数。
- 误报：真实例子——① Windows RPC 的动态端口（服务端 49152-65535 段）在 6 小时内轻松出现几十个不同 dst_port：一台工作站用域管工具/资源管理器访问一台服务器就够；② 域控（53/88/135/139/389/445/464/636/3268/5985/9389）本身就有 ≥10 个服务端口，任何一次正常登录-组策略-共享访问的组合都会凑齐；③ 反向代理（80/443/8080/8443）+ 管理端口组合。冷却 300 秒 + 6 小时窗 ⇒ 一旦凑齐，6 小时内每 5 分钟告警一次（最多 ~72 次），且 `triage_policy` 不跳过它（不在 `policy_skip_rules`；medium 不低于门槛 `medium`，条件是 `<` 才跳）。
- 漏报：无；但它与「内置-内网慢速横向」(27) 会对同一台扫描器同时命中，产出两份重叠摘要；`distinct` 只支持单字段（frequency.py:44 `distinct_field = str(cond.get("distinct"))`），无法用「dst_ip+dst_port 组合去重」，这是引擎限制，编写规则时要认清。
- 修复建议（可抄）：
  ```
  {"mode":"count","key":["src_ip","dst_ip"],"window":1800,"min_count":30,
   "distinct":"dst_port","min_distinct":25,
   "logic":"and","rules":[
     {"field":"log_type","op":"eq","value":"conn"},
     {"field":"src_internal","op":"eq","value":true},
     {"field":"dst_internal","op":"eq","value":true},
     {"field":"conn_state","op":"in","value":["S0","REJ","SH","SHR","RSTOS0","RSTRH","OTH"]}
   ]}
  ```
  把阈值提到 25 个端口 + 只算未建立连接，即可把「正常访问多服务」与「慢速端口扫描」分开；若想保留 6h 语义，建议 `min_distinct ≥ 100`（真扫描 6 小时通常成百上千）。同时在规则描述里注明「日常服务器多端口访问由排除过滤器按客户环境豁免」。
- 置信度：高（条件/键/阈值/冷却与横向规则同源，推理一致；具体端口数示例基于常见 Windows/AD 服务组合）

---

## 本组 Top 3 问题

1. **三条规则在当前采集契约下是死的**：「内置-协议异常」(1405)、「内置-TLS异常」(1416) 依赖 `notice.log` 的 note，而 `ndr/zeek/site/shentong-policies.zeek:32` 显式 `Log::disable_stream(Notice::LOG)`；「内置-上传类型不匹配」(1371) 的 `content_type` 在 Zeek 链路没有任何生产者（`http.log` 无该列，site 脚本只产出 `req_headers`）。同时真正的协议异常在 `weird.log` 里被归成 `generic`（`_zeek_event_type` 无 weird 分支）。建议：加 `log_type=="weird" → protocol_anomaly` 映射、从 `req_headers` 解出 Content-Type，或直接删掉这两条以免形成「有覆盖」的假象。

2. **两条 6 小时长窗频率规则的阈值与计数面完全失控**：「内置-内网慢速横向」(1454) 把「任意内网源 6h 内 ≥5 个内网目标」定为 high，「内置-内网慢速服务枚举」(1474) 把「同一目标 ≥10 个端口」定为 medium，且都无 `conn_state`/`log_type` 限定、服务器回包也计入 → 域控/文件服务器/代理长期处于已触发状态（每 5 分钟一条），并且每个键一个成员/事件、TTL 12 小时（frequency.py:51）、`window*2+60`，正是「单键累计上万」的成因；这些摘要还会挤掉每分钟 24 条的投递额度（config.py:170）。修法：加 `log_type=="conn"` + `conn_state in [S0,REJ,SH,SHR,RSTOS0,RSTRH,OTH]`，窗口收到 1800s，阈值收到 10 目标 / 25 端口。

3. **Wazuh 五条规则的严重度与等级脱钩**：`_wazuh_event_type` 先按规则组分类、等级只在最后兜底（normalizer.py:830-861），而摘要等级取的是规则自身 `severity`（runner.py `_aggregate`）——结果 level 15 的 syscheck 事件报「文件完整性变更/medium」、level 13 的 audit 事件报「策略违规/low」、只要带 mitre 就报「MITRE映射命中/medium」（1307，priority=32 还会遮蔽 34 号的策略违规）。建议给这四条分组规则统一加 `severity in ["high","critical"]`（或 medium 起）闸门，并把 MITRE 规则改成标注或大幅降级。

---

### 两个跨范围提醒（不改文件，仅告知）
- 仓库里有两份逐字相同的实现：`ndr/backend/app/rules/builtin.py` 与 `agent/backend/app/rules/builtin.py`（同行号同内容，normalizer 亦然）。上述任何修复都要两边一起改，否则会静默漂移。
- 本次评审对象是 HEAD 上的规则本体（`watchdog_diff` 显示工作区相对 reviewer-launch HEAD 无任何改动，因此没有可比对的 diff）。我没有运行任何测试，也没有任何规则行为测试覆盖这 16 条（`find ndr/**/test_*.py` 为空；现有测试只有 `tests/py/test_conn_states.py` 之类的契约测试，它只能证明「normalizer 有产出标签的函数」，证明不了「notice 被关闭后该标签仍可达」）。

```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "按任务要求的格式给出了 16 条规则的逐条结论（含逻辑/误报/漏报/修复/置信度）、本组小结与 Top 3；每条结论均引用 builtin.py 行号、normalizer.py/engine.py/frequency.py/runner.py 具体行或 config.py 阈值"
    }
  ],
  "changedFiles": [],
  "testsAddedOrUpdated": [],
  "commandsRun": [
    {
      "command": "watchdog_diff --stat",
      "result": "passed",
      "summary": "工作区相对 reviewer-launch HEAD 599c9b057549 无改动；本次为 HEAD 状态静态评审，无 diff 可比对"
    },
    {
      "command": "pytest tests/py -q （建议由 supervisor 执行）",
      "result": "not-run",
      "summary": "评审只做分析、未运行测试；现有测试不含这 16 条内置规则的行为断言，通过也证明不了本报告的结论"
    }
  ],
  "validationOutput": [
    "engine.py: _match 的 in 为精确相等、regex 用 re.search、exists 要求非空、whitelist 命中即放过；count 规则 match_rule 恒 False，由 runner 单独循环 evaluate_conditions 求值",
    "runner.py: hit = next((r for r in candidates if match_rule(r, entry)), None) → priority 升序首命中即停；count 规则不走 log_type 索引；摘要 severity 取 rule.severity",
    "frequency.py: member=fingerprint:ts、window 可覆盖全局 300s、ttl=window*2+60、冷却默认 300s；key/distinct 走 count_key/getattr，虚拟字段不可用",
    "normalizer.py:830-861 _wazuh_event_type 分支顺序（等级仅兜底）；692-710 mitre/rule_groups 映射；711-780 Wazuh 字段集不含 data.file、headers 未映射；379-388 http_upload 仅 Zeek；797-798 protocol_anomaly / 793-794 tls_anomaly 仅由 notice note 产出；801-827 无 weird 分支",
    "ndr/zeek/site/shentong-policies.zeek:32 Log::disable_stream(Notice::LOG)；ndr/zeek/README.md:272 验收表记录“无 notice.log，符合预期”；README.md:274 记录 shentong:freq:* 已出现慢速横向/服务枚举键",
    "全仓 grep content_type：仅 builtin.py:1380 与 normalizer.py 两处引用 → Zeek 链路无生产者；config.py:109 smtp/weird 属 EVENT 类",
    "config.py: policy_skip_rules 仅两条、policy_internal_routine_min_severity=medium、freq_window_seconds=300、freq_cooldown_seconds=300、detector_max_digests_per_minute=24、detector_digest_max_age_seconds=1800"
  ],
  "residualRisks": [
    "未运行测试（评审限定只做分析）：死规则与误报结论全部来自静态代码路径，缺少实测印证",
    "Wazuh 侧真实规则集不在仓库内：‘ossec 子串导致分类错位’、漏洞/FIM 告警量级属推理与量级估算，非现场计数",
    "内网慢速两条规则的触发频率（如 ~288 条/天/主机）是按冷却 300s + 6h 窗推算的上界，未经现场数据校准",
    "req_headers 中 Content-Type 的解析方案需与 Zeek 侧头名大写规则（README.md:214）对齐，落地时要验证",
    "agent/backend 与 ndr/backend 两份规则文件内容相同，修复必须双改，否则会漂移"
  ],
  "noStagedFiles": true,
  "diffSummary": "无工作区改动（watchdog_diff 报 No working-tree changes against HEAD 599c9b05）；评审对象为 HEAD 中 ndr/backend/app/rules/builtin.py 第 1261-1493 行（H 组 6 条 + I 组 10 条）",
  "reviewFindings": [
    "P1: builtin.py:1405 内置-协议异常 — event_type protocol_anomaly 仅由 notice 的 note 产出，而 shentong-policies.zeek:32 关闭 Notice::LOG；weird.log 在 _zeek_event_type 中被归为 generic → 本部署永不触发",
    "P1: builtin.py:1416 内置-TLS异常 — tls_anomaly 同样只由 notice note 产出 → 本部署永不触发（TLS/证书异常零覆盖）",
    "P1: builtin.py:1371 内置-上传类型不匹配 — content_type 在 Zeek 链路无生产者（仅 req_headers 有头值），event_type http_upload 又只由 Zeek 分支产出 → AND 恒假",
    "P1: builtin.py:1427 内置-SMTP滥用 — OR log_type==smtp ⇒ 每封正常邮件报 medium；真正的 smtp_abuse 分支已死",
    "P1: builtin.py:1454 内置-内网慢速横向 — src_ip 单键 6h、5 个内网目标即 high、无 conn_state 限定、服务器回包计入 → 常驻告警 + 大键 + 挤占 24/分钟投递额度",
    "P1: builtin.py:1474 内置-内网慢速服务枚举 — 同一目标 10 个端口即 medium，RPC 动态端口/域控服务组合即可触发",
    "P1: builtin.py:1307 内置-Wazuh MITRE映射命中 — 只判 mitre exists、不看等级即 medium，且遮蔽 priority=34 的策略违规；信息与告警 raw 重复",
    "P2: builtin.py:1263 高危告警描述与实现不符（分组规则优先级更高，等级信号在摘要层丢失）；1296 网络告警存在 ossec 子串分类错位隐患",
    "P2: builtin.py:1330 CSRF 规则实为测试域名黑名单（漏真实 CSRF）；1349 CORS 规则查 query/body 而 Origin 在 req_headers",
    "P2: builtin.py:1390 API高频调用白名单中 uri_path in [/health…] 恒不成立（与 rules 的 ^/(api|rest|graphql) 冲突）；key 仅 src_ip，NAT 即误报",
    "P2: builtin.py:1441 常见敏感端口访问无方向/状态限定，内网运维 DB 流量全报；3389 项被 priority=30 规则遮蔽"
  ],
  "manualNotes": "评审模式为只读分析（未修改任何文件、未写 progress.md，也无写入工具可用）。输出路径不可写时由运行时落盘：本响应即完整 artifact。建议 supervisor 复跑的命令：`pytest tests/py -q`（现有契约测试不含本组规则行为断言），以及现场核对 `redis-cli --bigkeys` 与 `redis-cli ZCARD shentong:freq:内置-内网慢速横向:<ip>:cnt` 验证“单键累计上万”的实际量级。"
}
```