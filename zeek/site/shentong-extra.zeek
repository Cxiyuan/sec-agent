## 深瞳 · 补充采集：确保 DNS / TLS / 文件 / 连接 等分析器加载
##
## 本项目 Web 深检与画像依赖以下字段（Zeek 默认脚本已提供，这里显式加载以免被裁剪）：
##   dns.log   -> query / qtype / qtype_name / answers / rcode
##   ssl.log   -> version / cipher / server_name / ja3 / ja3s / cert_issuer / subject
##   files.log -> mime_type / filename / md5 / sha1 / source / tx_hosts / rx_hosts
##   conn.log  -> id / conn_state / orig_bytes / resp_bytes / history
##   http.log  -> method / host / uri / referrer / user_agent / status_code / username / password

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/files
@load base/protocols/smtp
@load base/protocols/ssh
@load base/protocols/dhcp
@load base/frameworks/notice
@load base/frameworks/software
