## 深瞳 · 「按 TLS 解析的端口」（HTTP 端口表排除名单）
## ⚠️ 本文件由容器入口（entrypoint.sh: render_ports）按 /config/interface.conf 的
##    tls_ports 字段自动重写；这里是镜像内的默认版本（不排除任何端口 = 沿用 Zeek 默认判定）。
##    请不要手工修改，改动会被后台配置覆盖。
##
## 为什么需要它：Zeek 自带的 HTTP 端口表包含 8000/8008，如果这些端口在本环境实际跑的是 TLS，
## Zeek 会把 TLS 字节按 HTTP 文本行去解析，刷出大量 `bad_HTTP_request` /
## `line_terminated_with_single_CR` 之类的假协议异常（2026-10 实机实测：15 分钟一万多条）。
## 端口是环境相关的（同一个环境里 8013 就是真的明文 HTTP），所以按部署配置下发。

@load base/protocols/http

# tls_ports 为空时不生成下面这行（保持 Zeek 默认）
# redef HTTP::ports -= { 8000/tcp, 8008/tcp };
