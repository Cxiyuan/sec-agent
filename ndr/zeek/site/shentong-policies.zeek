## 深瞳 · Zeek 自带策略脚本加载清单
##
## 只做两件事：**多产字段**、**运行状态可见**。刻意不加载任何 Zeek 自带检测策略
## （capture-loss / validate-certs / weak-keys / expiring-certs / heartbleed / detect-sql-injection 等），
## 检测一律交给本项目的规则引擎，理由见 docs/ndr-collect-plan.md 主题 7。
##
## 五个 @load：
##   ssl-log-ext            —— ssl.log 补 server_version / client_version / client_ciphers /
##                             ssl_client_exts / ssl_server_exts / orig_alpn / client_supported_versions 等
##   hash-all-files         —— 给每个文件挂 MD5/SHA1/SHA256 分析器，files.log 才有 md5/sha1/sha256
##   misc/stats             —— 每 5 分钟写一行 stats.log（收包/丢包/事件处理/内存等运行状态）
##   http/header-names      —— http.log 记客户端头名清单 client_header_names（**只有头名、没有头值**）
##   http/var-extraction-cookies
##                          —— 从请求 Cookie 里抽出变量名清单 cookie_vars（同样只有名、没有值）
##
## 头值（含 Cookie / Authorization）由自写的 shentong-httpheaders.zeek 单独采集，
## 见该文件顶部说明。
##
## stats.log 属「运维类」：只入 ES 当证据，不进检测器（见 log_types.py 与 zeek_ops_log_types）。

@load policy/protocols/ssl/ssl-log-ext.zeek
@load policy/frameworks/files/hash-all-files.zeek
@load policy/misc/stats.zeek
@load policy/protocols/http/header-names.zeek
@load policy/protocols/http/var-extraction-cookies.zeek

## 显式关掉 Notice 流。现在没加载任何会 raise notice 的策略，它本来就是空的；
## 关掉是为了将来有人误加载检测策略时，也不会凭空多出一个 notice.log 被 Filebeat 采走。
## （NOTICE() 调用本身不受影响，只是不再写文件。）
event zeek_init() &priority=-10
	{
	Log::disable_stream(Notice::LOG);
	}
