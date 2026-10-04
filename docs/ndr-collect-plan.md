# 深瞳 NDR 采集面改造计划（主题 0–8 已逐条确认）

> 状态：计划已确认（2026-10-02）。实施分四批，每批独立部署验收；证据写进 `docs/ndr-redesign.md`。
> 范围：**本轮只做 NDR**；智能体侧对等适配下一轮做。

## 一、目标

按智能体做 Web 攻击分析的需要，把 NDR 采集面补全并可控：

- Zeek 补出 TLS 指纹（JA3/JA3S/JA4 系列）、文件哈希、请求头值；
- 类型识别与流分类不再靠猜（Filebeat 的类型标记优先，猜只是兜底）；
- 正文采集上限可在界面调整；
- 文件可提取、可下载（有鉴权、防目录穿越）；
- 关掉 Zeek 自带检测与 notice（检测只由本项目规则引擎负责）；
- Filebeat 采集不丢事件。

## 二、已确认的决定

| 主题 | 决定 |
|---|---|
| 0 纪律 | 测试搬进仓库 `tests/` 并进 CI；**本轮只做 NDR**，智能体侧后续对等开发；类型判定只在归一化层做一处 |
| 1 类型识别 | `log_type` 优先 → 特征猜兜底 → unknown；unknown 入 ES 但不进检测/告警，用 `log_type.keyword` 聚合巡检；raw 补 `log_type` + `source_file`；白名单外类型保留原名 + `log_type_known:false`；运维流只入 ES |
| Filebeat | ① 显式"文件名→类型"规则 + CI 样本测试；② 非事件文件排除名单；③ 落盘缓冲，Redis 不可用时不丢事件（**实机定案：用 `queue.disk`** —— 本镜像的 Filebeat 是 OSS 构建，`queue.spool` 实测报 `unrecognized queue type 'spool'`） |
| 2 流分类 | E（入 ES+归一化+可检测）= conn/dns/http/ssl/files/dhcp/x509/weird/notice/smtp/ssh；O（只入 ES）= ntp/packet_filter/reporter/stats/ja4ssh/ja4d；关掉 `tlsfp`/`ja3sfp` |
| 3 指纹 | vendor `salesforce/ja3`（BSD-3-Clause）+ `FoxIO-LLC/ja4-zeek-scripts`（全量 JA4+，**不做 JA4X**，内部自用不对外变现）；自写 `shentong-fingerprints.zeek` 管开关；只归一化 `ja4/ja4s/ja4h`，conn 的 `ja4l/ja4t` 等只留 raw；加载 `ssl-log-ext` |
| 4 头与凭证 | body/resp_body **不脱敏**；请求头**全量头值**（客户端+服务端）；敏感头（Cookie/Authorization）**截断明文**；每头 256 字符、总量 4KB。**已接受风险** |
| 5 正文上限 | 默认**请求 16KB / 响应 64KB**，**界面可设置**（现有 Zeek 设置页，单位 KB）；机制 = 写 `/config/interface.conf` + 落库 `system_config` → entrypoint 渲染 `shentong-limits.zeek` → Zeek 约 10 秒重载；Python 用同一数字当字符上限（永不二次截断）；UTF-8 截断容忍尾部乱码 |
| 6 文件 | 哈希+元数据全做（`fuid/md5/sha1/sha256/filename/mime_type/seen_bytes/total_bytes/is_orig/source/tx_hosts/rx_hosts`）；提取 = HTTP+FTP、**先提后筛**（MIME 白名单=可执行+脚本+压缩包+文档）、单文件 16MB；目录 **10G 满按 mtime 淘汰最老**；**加下载 API** + 新卷 `zeek-extract`（rw→zeek、ro→backend） |
| 7 notice | **路线 A**：不加载任何 Zeek 自带检测策略；`Log::disable_stream(Notice::LOG)`；检测全由本项目规则引擎负责；丢包可见性改用 `policy/misc/stats.zeek` → `stats.log` |
| 8 批次 | 四批按序，**每批独立部署验收**，证据写进 `docs/ndr-redesign.md` |

## 三、分批实施

### 批 1：类型识别 + 流分类 + Filebeat（不碰采集内容，先上）

计划内容（原样保留，便于对照）：

- `ndr/backend/app/ingestion/normalizer.py`（+ `agent/backend/app/ingestion/normalizer.py`）：`_zeek_log_type()`（:220-224）改为「`log_type` 优先 → `_ZEEK_TYPE_HINTS`（:26-37）猜 → unknown」；`_ZEEK_TYPE_HINTS` 补 x509/weird/ntp/stats/ja4ssh/ja4d 等；raw 改 `{**_sanitize_raw(doc), "log_type": …, "source_file": …}`；未知类型写 `log_type_known:false` 并保留原名。
- `config.py`（两侧）：已知类型/E 类名单集中配置（加类型只改配置）。
- `schemas.py`（两侧）：加 `log_type_known: bool = True`、`source_file: str = ""`。
- 检测闸门：`ndr/backend/app/detector/runner.py` 入口按 E 类名单过滤（O 类只入 ES）。
- `ndr/zeek/filebeat.yml`：显式「文件名→log_type」映射 + 排除名单 + `queue.spool` 落盘缓冲。
- 测试：`tests/py/` 类型判定矩阵、Filebeat 文件名→类型样本测试。
- 验收探针：ES 断言 `log_type`/`log_type_known`/`raw.log_type`/`raw.source_file`；停 Redis 发事件再启，确认不丢。

**实施记录（as-built）**：

- 新增 `ndr/backend/app/ingestion/log_types.py`（**原样复制到 `agent/backend/app/ingestion/log_types.py`**，`diff` 一致）：`EVENT/OPS/UNKNOWN` 三个去向、`canonical_log_type()`（去 `.log` 与两种轮转后缀、去目录前缀）、`classify()`/`classify_entry()`/`is_detectable()`/`is_known()`。**非 Zeek 来源（Wazuh）一律按事件类**，闸门不套到 Wazuh 线路上。
- `config.py`（两侧）：`zeek_event_log_types`（默认 `conn,dns,http,ssl,files,dhcp,x509,weird,notice,smtp,ssh`）、`zeek_ops_log_types`（默认 `ntp,packet_filter,reporter,stats,ja4ssh,ja4d`）—— 加类型只改配置。
- `_ZEEK_TYPE_HINTS` 扩到 17 条，顺序改为特异性从高到低（`any()` 撞一个字段就定案，故 ja4ssh 排在 ssh 前）；`_zeek_log_type()` 返回 `(类型, 是否已知)`，猜不出返回 `unknown`（**不再兜底 `conn`**）。
- raw 走 `_raw_with_type()`：解包后的内层原文 + `log_type` + `source_file`（Filebeat 的 `log.file.path` 末段）。
- 闸门两处（都必要）：`ndr/backend/app/collector/normalizer_service.py`（正常链路，O 类/unknown 只入库）+ `ndr/backend/app/detector/runner.py`（队列里可能还压着升级前的旧文档/人工重放数据，兜底挡一道）。
- `ndr/zeek/filebeat.yml`：显式文件名→类型（JS 处理器去 `.log` + `.YYYY-MM-DD`/`.HH-MM-SS`）、**不再 `drop_event`**（认不出也发，下游标 unknown）、排除名单（stderr/stdout/loaded_scripts/debug/prof/telemetry/threading/capture_loss；stats/packet_filter/reporter 不排除）、落盘队列 `queue.disk`（`/usr/local/bin/data/spool/filebeat`，1GB，与注册表同在命名卷 `zeek-filebeat` 上）。**`queue.spool` 在本镜像不可用**（OSS 构建），已在服务器容器内 `filebeat test config` 实测 `Config OK`。
- 测试（进 CI）：`tests/py/`（`test_log_types.py` 判定矩阵、`test_normalizer_fields.py` 字段契约、`test_xff_respbody.py` 由 `/tmp` 搬入、`test_stack_consistency.py` 子进程比对两侧、`test_filebeat_yml.py` 采集配置形状）+ `tests/zeek/hb_test.zeek`（由 `/tmp` 搬入，`tests/zeek/run.sh` 在官方 Zeek 容器里跑）。
- CI（`.github/workflows/ci.yml`）：新增 `test` 作业（ruff + pyright + 两个栈各跑一遍 pytest + Zeek 容器单测）与 `web` 作业（`npm ci` + 两侧 `tsc --noEmit`）；根 `ruff.toml` 补统一规则（`tests/` 不在任何 pyproject 层级下）、`pyrightconfig.json` 加 `tests/py` 执行环境。
- **服务器验收已完成（2026-10-02）**：ES 断言 `log_type`/`log_type_known`/`raw.log_type`/`raw.source_file`、未知流保留原名、停 Redis 不丢事件、两侧闸门计数（归一化「类型闸门只入库」/检测器「类型跳过(运维 N)」）全部实测通过；完整证据见 `docs/ndr-redesign.md` 第 9 期。
- 验收抓出并修掉的缺陷：排除名单原写在 filestream 输入**顶层** `exclude_files`（那是旧 `log` 输入的键）**实测完全无效**，已改为 `prospector.scanner.exclude_files`；`filebeat test config` 对两种写法都回 `Config OK`、`filebeat --once` 也在首次扫描前就退出（约 40ms），**只有端到端探针能判定** —— `tests/py/test_filebeat_yml.py` 已加「顶层不得再出现该键」的断言。**修复后已部署复验**：`/logs/stderr.log` 探针 ES 命中 0、注册表条数不增长，同批 `/logs/stats.log` 探针正常入库（`log_type=stats` / `known=true` / `source_file=stats.log`）；保留策略探针（mtime 10 天前 vs 1 天前）在容器重建时由启动清理循环自动处理（旧删新留）。


### 批 2：Zeek 指纹与文件元数据

计划内容（原样保留，便于对照）：

- vendor：`ndr/zeek/site/vendor/ja3/`（`ja3.zeek`、`ja3s.zeek`、BSD `LICENSE.txt`）+ `ndr/zeek/site/vendor/ja4-zeek-scripts/`（整树 + `License FAQ.md` + FoxIO License 1.1，记录来源与版本）。
- 新增 `ndr/zeek/site/shentong-fingerprints.zeek`：redef 开关（JA4 全量、`JA4X_enabled=F`）、`Log::disable_stream(tlsfp.log/ja3sfp.log/Notice::LOG)`。
- `ndr/zeek/site/local.zeek`：加载 `shentong-fingerprints`、`policy/protocols/ssl/ssl-log-ext`、`policy/frameworks/files/hash-all-files`、`policy/misc/stats.zeek`（注释写明为何不加载 detect 类）。
- 归一化：`ja4`/`ja4s`/`ja4h` 入 `UnifiedLog`；files.log 元数据入统一面；注册 `ndr/backend/app/investigation/catalog.py` 与 `ndr/backend/app/rules/engine.py:288-324`；两侧 `schemas.py` 加 `fuid/ja4/ja4s/ja4h/sha256/file_size/tx_hosts/rx_hosts`。
- 验收探针：HTTPS → `ja3/ja3s/ja4/ja4s/orig_alpn`；HTTP → `ja4h`；下载 → 三哈希；`stats.log` 出现且不进检测。

**实施记录（as-built）**：

- **许可证收窄（用户 2026-10-02 决策：本产品对外售卖/托管给客户）→ 只收 BSD-3-Clause**：
  - 收录：JA3 / JA3S（`salesforce/ja3`，BSD-3-Clause）与 **JA4 本体**（TLS 客户端指纹，`FoxIO-LLC/ja4-zeek-scripts` 里唯一 BSD-3 的部分）。
  - **不收录**：JA4S / JA4H / JA4L / JA4LS / JA4T / JA4TS / JA4D / JA4SSH / JA4X —— 这些是 `FoxIO License 1.1`（仅非商业用途、专利待批），其 FAQ 明确「作为产品功能出售、托管给客户、用它给付费客户提供价值」都需先拿 FoxIO OEM 授权。**故原计划的 `ja4s`/`ja4h` 归一化取消**，不 vendor 整树、不带 FoxIO 许可证文件。
- vendor 位置与文件（**必须在 `site/` 下**：`ndr/zeek/Dockerfile:28` 只 `COPY site/`）：
  - `ndr/zeek/site/vendor/ja3/{ja3.zeek,ja3s.zeek,LICENSE.txt,zkg.meta}`（上游逐字，commit `502cc6395811c54743b0561419d61900a6df3ff7`）+ **自建** `__load__.zeek`（只加载 `ja3.zeek`/`ja3s.zeek`；上游 `__load__.zeek` 还会加载 `intel_ja3.zeek`——那把 JA3 接进 Intel 框架并另开 `ja3sfp.log`，本项目不用）。
  - `ndr/zeek/site/vendor/ja4/LICENSE-JA4.txt` + 逐字 `ja4/{__load__,helpers,main}.zeek`、`utils/{common,ssl-consts}.zeek`（commit `8bf9feca52790ae8c926c6a8d79a3547ac19541a`）+ **自建** `vendor/ja4/__load__.zeek`（Zeek 9 的 base 里没有 `FINGERPRINT` 模块，`FINGERPRINT::Info` 与 `connection$fp` 必须自己声明）与最小 `config.zeek`（只留 `delimiter`/`JA4_raw`，不含 JA4+ 的开关）。
  - `ndr/zeek/site/vendor/README.md`：来源 commit、逐字 vs 自建、**为什么 JA4+ 不进仓库**、位置约束。
- `ndr/zeek/site/shentong-fingerprints.zeek`（自建开关）：`option ja3_enabled = T` / `option ja4_enabled = T`，在 `@if` 里 `@load ./vendor/ja3` / `./vendor/ja4`（编译期常量，加载后再 redef 无效）。
- `ndr/zeek/site/shentong-policies.zeek`（自建清单）：`@load policy/protocols/ssl/ssl-log-ext.zeek`、`policy/frameworks/files/hash-all-files.zeek`、`policy/misc/stats.zeek` + `event zeek_init() &priority=-10 { Log::disable_stream(Notice::LOG); }`。**不再需要 `Log::disable_stream(tlsfp/ja3sfp)`**：两家的脚本都没有给这两个流写入口（实测也没有 `fingerprint_ja4.log`）。
- `ndr/zeek/site/local.zeek` 顺序：json → extra → policies → httpbody → fingerprints → nets → scripts-d。
- 归一化（两侧逐字一致，只差 NDR 的 `source_of()`）：`schemas.py` 加 `ja4`、`fuid`、`md5`、`sha1`、`sha256`、`file_source`、`file_is_orig`；`normalizer.py` 新增 `_to_bool()`（`"T"/"F"` 兼容），`_ZEEK_TYPE_HINTS` 的 ssl 加 `ja4`、files 加 `sha256`，`_http_fields` 搬运这些字段（哈希/FUID 各 64 字符、`file_source` 32）；`catalog.py` 注册新字段并进 SUMMARY/AGG（`sha256` 的 path 从 `raw.sha256` **改为 `sha256`**，因为现在真有这个归一化字段了）；`rules/engine.py` 的 `_FIELD_TYPES` 把 `md5/sha1/sha256/file_source/file_is_orig` 挂 `files`、`ja4` 挂 `ssl`（之前规则根本取不到哈希）。
- 测试：`tests/py` 加 ssl `ja4`、files 哈希/方向/来源断言（含 `is_orig` 的 `"T"/"F"` 字符串）；新增 `tests/zeek/batch2_test.zeek`（断言 `SSL::Info$ja4` 字段存在、分隔符与两个开关默认值、`Stats::report_interval` 已加载、`Notice::LOG` 已关）；`tests/zeek/run.sh` 改为复制**整棵 site 树**并逐个跑 `*_test.zeek`（原来只扁平 `cp *.zeek`，相对 `@load ./vendor/...` 会找不到文件）。
- **容器实测（`zeek/zeek:9.0`，`-i lo`）**：真实 TLS 握手 → `ssl.log` 得 `ja3`/`ja3s`/`ja4` 三值 + `client_version`/`server_version`（ssl-log-ext 生效）✓；HTTP 下载 5000 字节 → `files.log` 的 `md5`/`sha1`/`sha256` 与 Python hashlib **逐字一致**，`fuid`/`source:"HTTP"`/`is_orig:false`/`seen_bytes=total_bytes=5000` ✓；`stats.log` 有行 ✓；无 `notice.log`，无 `tlsfp.log`/`ja3sfp.log`/`fingerprint_ja4.log` ✓。（回环上用 200KB 单文件会 `truncated_tcp_payload` 导致 `resp_fuids` 为空——测试环境的回环大包现象，小文件正常。）
- 服务器验收（2026-10-02）已完成，实机证据见 `docs/ndr-redesign.md` 第 10 期：真实 HTTPS 得 `ja3`/`ja3s`/`ja4` 落库、明文下载的 `md5`/`sha256` 与本地 `md5sum`/`sha256sum` 逐字一致、`stats` 流只入库不进检测。

### 批 3：请求头 + 正文上限可设置

- Zeek：`@load policy/protocols/http/header-names` + `var-extraction-cookies`；自写 `ndr/zeek/site/shentong-httpheaders.zeek`（客户端+服务端全量头值，单头 256 字符、总量 4KB 封顶）。
- 上限可配：`ndr/zeek/entrypoint.sh`（:57-83 同套路）渲染 `shentong-limits.zeek`（`redef ShentongHTTP::max_body_len/max_resp_body_len`，读 `interface.conf` 新键 `body_max_bytes`/`resp_body_max_bytes`，默认 16384/65536）；`ndr/backend/app/api/routes/zeek.py`（:166-235）扩展接口写 conf + `system_config`；前端现有 Zeek 设置页加两个 KB 输入框。
- `config.py`：`http_body_max_chars=16384`/`http_resp_body_max_chars=65536`，运行时读 `system_config` 同数字覆盖；`schemas.py:46-47` 两句"不落明文凭证"的注释按新口径改掉。
- 验收探针：ES 断言头值存在且被截断；改界面值 → 重载后正文长度变化；`resp_body_len` 仍为完整字节数。

**实施记录（as-built，2026-10-02）**

- **Zeek 侧**：新增 `site/shentong-httpheaders.zeek`（`req_headers`/`resp_headers` 两个 `&log &optional` 字段；`max_header_value_len=256`、`max_headers_len=4096`；`append_header()` 单头截断 + 总量封顶；`clean_header_value()` 把含**任意 C0 控制字符（含 `\r`/`\n`）**的值换成 `<binary>` —— 初版沿用正文脚本的字符类漏掉了 `\r`/`\n`，被 `batch3_test.zeek` 的注入用例抓出来改成 `[\x00-\x1f\x7f]`；两个函数在 `export` 里声明为 `global` 才能在模块外调用/单测）；`site/shentong-policies.zeek` 增到 5 个 `@load`（新加 `policy/protocols/http/header-names.zeek` 与 `.../var-extraction-cookies.zeek`）；新增 `site/shentong-limits.zeek`（镜像内默认 16384/65536）；`entrypoint.sh` 新增 `render_limits()`（只接受纯数字、缺失或非法回落默认值）并在 `main` 与看门狗触发重载时各调一次；`local.zeek` 顺序 json → extra → policies → httpbody → **limits** → **httpheaders** → fingerprints → nets → scripts-d。
- **后端**：`api/routes/zeek.py` 的 `CONF_KEYS`/`DEFAULT_CONF` 加两个新键（否则 `_read_conf` 读不到）；`ZeekIfaceIn` 加 `body_max_kb`/`resp_body_max_kb`（`None` = 沿用当前值，范围 1~1024，越界 400 `field_error`）；`PUT /interface` 同时写 `interface.conf` 与 `system_config.http.body_max_chars`/`http.resp_body_max_chars` 并 `runtime_config.invalidate()`；`GET /status` 回这两个值。两侧 `config.py` 默认值 2000 → 16384/65536；两侧 `normalizer.py` 新增 `http_body_limit()`/`http_resp_body_limit()`（`runtime_config.get`，30 秒 TTL，读不到回落 settings）替换原来直接读 settings 的截断；`schemas.py` 加 `req_headers`/`resp_headers`（后端 8192 字符兜底截断）；`catalog.py` + `rules/engine.py` 的 `_FIELD_TYPES` 同步注册（挂 `http`）。
- **前端**：`ndr/frontend/components/zeek-panel.tsx`（监控网段页）加两个 KB 输入框（留空/非法不提交，后端沿用当前值）+「当前生效」显示当前上限；`lib/api.ts` 的 `ZeekStatus` 加两字段。
- **测试**：`tests/py` 新增 `test_http_headers_captured`、`test_http_limits_follow_settings`、`tests/py/test_zeek_limits.py`（默认值与 settings 一致、`limits` 在 `httpbody` 之后、用 bash 真跑 `render_limits` 三种 conf）；新增 `tests/zeek/batch3_test.zeek`（9 条）；原来两处「上限 2000」断言改为按 `settings` 造超限输入。
- **容器实测**（`zeek/zeek:9.0`，`-i lo`）：默认上限下 `req_headers` 总长 4096 / 单头 256、`resp_headers` 单头 256、POST 4000 → `body` 4000、响应 8000 → `resp_body` 8000；把 limits 换成 1024/1500 → `body` 1024、`resp_body` 1500，而 `response_body_len` 仍 8000（截断不影响完整字节数）。
- 服务器验收（2026-10-02）已完成：清理旧镜像与容器后全新部署（10 容器 Up），回落路径（conf 无新键 → 16384/65536）被实机走通；探针得 `req_headers` 450 字符（单头截 256）、`Cookie` 明文、`cookie_vars=['probe','sid']`；`body_max_kb:1`/`resp_body_max_kb:4` 热改后 `body` 落 1024、254968 字节响应的 `resp_body` 落 4096 而 `resp_body_len` 仍 254968，改回 16K/64K 亦生效。实机证据与 Filebeat 偶发解析失败（非本期引入）见 `docs/ndr-redesign.md` 第 11 期 ④ 与 `ndr/zeek/README.md` 的「批 3 实机复验」。

### 批 4：文件提取 + 下载通道

- 新增 `ndr/zeek/site/shentong-file-extract.zeek`：`redef FileExtract::default_limit = 16777216`、`redef FileExtract::prefix = "/extract/"`；`file_new` 按 `f$source`（HTTP/FTP）挂 `Files::ANALYZER_EXTRACT`，并把 `extract_filename` 指定成 `f$id`（fuid）→ files.log 的 `extracted` 与磁盘文件名都是 fuid，下载接口据此拼路径。
- **MIME 白名单判定与删除不放 Zeek 里做**（Zeek 没有删文件的 BIF）：改由 `ndr/zeek/extract_cleanup.py` 承担 —— 容器入口每 5 分钟跑一次，读 `/logs/files.log` + `files.*.log` 的 `mime_type`，白名单外或没有记录就删文件；**白名单的唯一来源就是这个助手**（下载接口不重复判定）。files.log 记录保留。
- 容量：同一个助手每轮按 mtime 从最老开始淘汰，直到目录不超过 10 GiB（`ZEEK_EXTRACT_MAX_BYTES`）；`--min-age`（默认 120 秒）跳过可能还在写的文件。
- compose 加 `zeek-extract` 卷（zeek rw / backend ro）。
- API：`GET /api/files/{fuid}`（鉴权；从 ES 取 `extracted` 文件名后读卷，**绝不接受客户端路径**）。
- 前端调查页的下载入口**不在本轮**：NDR 前端没有事件/调查页（事件组调查 UI 在智能体侧），留到「智能体侧对等适配」那轮接上。
- 验收探针：上传白名单文件 → 落盘且字节数与 `files.log` 的 `total_bytes` 一致（**完整件的 `extracted_size` 是 NULL**，只有被上限截断时才写）；上传图片/二进制 → 5 分钟内被清理助手删掉、下载回 404；临时调小上限与容量阈值分别验证截断与淘汰。
  **（2026-10-02 实机复验后修正**：原写「落盘且 `extracted_size == total_bytes`」不成立 —— FileExtract 只在 `file_extraction_limit` 事件里写 `extracted_size`，见下面的实测记录。）

**实施记录（as-built，2026-10-02）**

- **Zeek 侧**：新增 `site/shentong-file-extract.zeek`（`module ShentongFileExtract`；`redef FileExtract::prefix = "/extract/"`、`redef FileExtract::default_limit = 16777216`、`const sources: set[string] = { "HTTP", "FTP" } &redef`；`event file_new` 里 `if ( ! f?$source || f$source !in sources ) return;` 再 `Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=f$id])`）；`site/local.zeek` 在 httpheaders 与 fingerprints 之间加 `@load ./shentong-file-extract`（共 10 个 @load）。
- **容器入口**：新增 `ndr/zeek/extract_cleanup.py`（只用标准库，镜像自带 python3 跑）；`entrypoint.sh` 新增第 5 段 `extract_cleanup_once()` + `start_extract_cleanup_loop()`（`ZEEK_EXTRACT_DIR` / `ZEEK_EXTRACT_CLEAN_INTERVAL=300` / `ZEEK_EXTRACT_MAX_BYTES=10737418240` / `ZEEK_EXTRACT_MIN_AGE=120` / `ZEEK_EXTRACT_MIME_ALLOW` / `ZEEK_EXTRACT_HELPER` 可覆盖），`main()` 里建目录并在常规清理循环之后起循环；`Dockerfile` COPY 助手 + `RUN chmod +x`，`VOLUME` 加 `/extract`。
- **助手口径**：读 `files.*.log`（轮转件）**再**读 `files.log`（活动日志），后者覆盖前者；跳过非 JSON 行与半行（Zeek 正在写的最后一行）；`DEFAULT_MIME_ALLOW` 覆盖 text/*、XML/JSON、PDF、邮件、Office（`application/vnd.openxmlformats-officedocument.*` / `application/vnd.oasis.opendocument.*` 前缀）与常见压缩包，**不含** `application/octet-stream` 与可执行体；`--dry-run` 只统计不删。
- **后端**：`config.py` 加 `extract_dir = "/extract"`；新增 `api/routes/files.py`（`GET /api/files/{fuid}`：fuid 正则 `^[A-Za-z0-9_-]{8,64}$` → 查 ES 最新一条带 `extracted` 的文件事件 → `resolve_extract_path()` 只接裸文件名并把 `resolve()` 结果钉在提取目录里（同时挡住目录穿越与符号链接逃逸）→ `FileResponse`；被清理的文件回 404 并说明原因；`extracted_cutoff` 为真时带 `X-Extract-Cutoff: 1` / `X-Extract-Size` 响应头）；`api/router.py` 注册。
- **字段**：两侧 `schemas.py` 加 `extracted` / `extracted_size` / `extracted_cutoff`（`tests/py/test_stack_consistency.py` 要求两侧 UnifiedLog 字段集一致，所以两侧都加），两侧 `normalizer.py` 取值入库（`extracted` 截 128 字符），两侧 `rules/engine.py` 的 `_FIELD_TYPES` 与 `investigation/catalog.py` 同步注册。
- **测试**：`tests/py/test_extract_cleanup.py`（白名单、日志覆盖顺序、半行容忍、在写保护、容量淘汰、dry-run、CLI 端到端、entrypoint/Dockerfile/local.zeek 接线）与 `tests/py/test_files_api.py`（路径安全：穿越/符号链接/下载名头注入/ fuid 正则；Zeek prefix 与后端 `extract_dir` 一致性）；`tests/zeek/batch4_test.zeek`（prefix/limit/来源集合/三个新字段）。
- 本地质量门：`pytest --stack=ndr` **179 passed**、`--stack=agent` **160 passed / 19 skipped**（下载接口测试仅 NDR 侧）、ruff/pyright 全绿、`sh tests/zeek/run.sh` 四套 Zeek 单测 `ZEEK TESTS: ALL PASS`。
- **实机复验（2026-10-02，172.16.196.77，镜像 `sha256:9adedfe6053d`）**：三段上传（2400B `text/plain`、3000B `application/octet-stream`、18.7MB `text/plain`）→ 白名单件落盘且 sha256 与本机原文一致、`GET /api/files/<fuid>` 200（`content-type` 取自 `mime_type`、`content-length` 与落盘字节一致）、无令牌 401、非法 fuid（`short` / 带空格 / 编码斜杠）400 或 404；二进制件（`mime_type` 为空）被清理助手判为白名单外删除、清理后下载回 404；`--max-bytes 2000` 从最老淘汰 8 件留 1 件；**截断链路**用容器内临时把 `default_limit` 改成 1000 验证（`extracted_size=1000`、`extracted_cutoff=true` 落 ES，下载响应带 `X-Extract-Cutoff: 1` + `X-Extract-Size: 1000`），测后按备份复原并校验 sha256 一致。
- **实机复验暴露的三件事**（已分别修正/登记）：① `DEFAULT_MIME_ALLOW` 缺 `text/json`（Zeek 对 JSON 请求体实测报 `text/json` 而非 `application/json`）→ 已补 + 测试；② `shentong-ndr` 镜像被 backend/normalizer/detector/ndr-mcp **四个服务共用**，只 `up -d zeek backend` 会让 normalizer 继续跑旧镜像、新字段永远进不了 ES → 必须四个一起重建（本次执行 `up -d normalizer detector ndr-mcp` 后才在 ES 里看到 `extracted`）；③ 镜像口对**采集机自身**的部分外网目标（Cloudflare/postman-echo）不可见，且高带宽流丢包严重（18.7MB 上传 Zeek 只见到 184432 字节、落盘 5.3MB 而 `extracted_cutoff` 仍是 false）→ 实机验收必须挑可见目标（`mirrors.aliyun.com`），并把「落盘件可能因丢包不完整」记进 `ndr/zeek/README.md` 已知限制。

### 收尾

- 文档：`README.md`、`ndr/zeek/README.md` 检查表（第 2 项轮转/清理复核、第 3/4 项 XFF 与正文）、`docs/ndr-redesign.md`（每批实测证据 + 主题 4 风险记录 + "轮转是平铺改名不是日期子目录"的更正）。
- CI：`.github/workflows/ci.yml` 增加 pytest + `ruff`/`pyright` + 两侧 `tsc --noEmit`（现在只有 `compileall` 冒烟）。
- 把 `/tmp/test_xff_respbody.py`（58 项）、`/tmp/hb_test.zeek`（9 项）搬进 `tests/`。

## 四、每批统一验收四步

1. 仓库内 Zeek 单测通过（注意：`ja3.zeek` 在 `-b` bare 模式下报 `unknown identifier Version::number`，harness 不带 `-b` 或先 `@load base/misc/version`）；
2. 本地两侧一致性测试 + `ruff check ndr/backend/app agent/backend/app` + `pyright` + 两侧 `npx tsc --noEmit`；
3. 推送后 CI 绿（只用 GitHub Actions 构建镜像，不本地 build）；
4. 服务器 `docker compose pull` 后用真实探针验证字段落库（ES 查询断言），结果写进 `docs/ndr-redesign.md`。

## 五、已接受的风险与取舍

- **明文凭证进 ES**：登录口令（body）、Bearer token、会话 Cookie 均为明文（头值截断对短凭据等于明文）；ES 无鉴权、只听 `127.0.0.1`、ILM 30 天。已二次确认接受，文档记为已知风险。
- **关 notice**：没有 Zeek 自带检测，也不会有 `ssl.log.validation_status`（以后需要就单独加载 validate-certs 并保持关流）。
- **提取目录只按 10G 淘汰**：不设年龄闸，低流量时文件会长期留存。
- **JA4+ 许可**：本产品会对外售卖/托管给客户，所以 JA4S/JA4H/JA4L/JA4LS/JA4T/JA4TS/JA4D/JA4SSH/JA4X **一律不收录**（FoxIO License 1.1 仅非商业，出售/托管/给付费客户提供价值都需 OEM 授权）；只收 BSD-3-Clause 的 JA3/JA3S 与 JA4 本体。将来拿到 OEM 授权，把脚本丢进 `ndr/zeek/site/vendor/ja4/` 再 `@load` 即可。
- **改上限/网段需重载 Zeek**：约 1~2 秒抓包中断。

## 六、后续未决

- 智能体侧对等适配（下一轮）。
- 智能体线路部署：`NDR_REDIS_URL` 写 `redis://10.255.12.4:6379/0`，推送需配地址+令牌并开启。
- Zeek 检查表第 2 项（24h 轮转与 3 天清理）**已实机复验（2026-10-04）**：在跑的生产容器上放 mtime 4 天前、轮转命名、两层子目录的探针 → 到点的清理轮把它删掉（观察任务 `18:57Z` 命中），同期活动 `conn.log` 仍在增长、Filebeat 存活 ⇒ 「保留 3 天」端到端成立。轮转形态（同目录平铺改名、时间戳带时分秒）已在 2026-10-02 核对。
- Zeek 检查表第 9 项（反向代理的原始客户端 IP）**已收口（2026-10-04）**：可信代理白名单 `ST_ZEEK_TRUSTED_PROXIES` + `X-Real-IP` 进采集清单；四层代理的 PROXY protocol 明确不做（Zeek 9.0 无该分析器）。
- Filebeat `ndjson` 解析失败产生的空壳文档**已修（2026-10-04）**：normalizer 认得 `zeek.error.type=json` 后从顶层 `message` 抢救，拼不回就进死信，不再落空壳（未改 Filebeat 链路配置）。
