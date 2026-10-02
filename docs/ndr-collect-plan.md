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

### 批 4：文件提取 + 下载通道

- 新增 `ndr/zeek/site/shentong-file-extract.zeek`：`redef FileExtract::default_limit = 16777216`、`redef FileExtract::prefix = "/extract/"`；`file_new` 按 `f$source`（HTTP/FTP）挂 `Files::ANALYZER_EXTRACT`；`file_sniff`/`file_state_remove` 按 MIME 白名单判定，非白名单删文件（files.log 记录保留）。
- `entrypoint.sh` 看门狗：每 5 分钟 `du` 超 10G → 按 mtime 删最老至 ≤10G（留日志）。
- compose 加 `zeek-extract` 卷（zeek rw / backend ro）。
- API：`GET /api/files/{fuid}`（鉴权；从 ES 取 `extracted` 文件名后读卷，**绝不接受客户端路径**）；前端调查页加下载入口。
- 验收探针：上传白名单文件 → 落盘且 `extracted_size == total_bytes`；上传图片 → 不落盘；临时调小阈值验证淘汰。

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
- Zeek 检查表第 2 项（24h 轮转与 3 天清理）待日期归档出现后复核。
