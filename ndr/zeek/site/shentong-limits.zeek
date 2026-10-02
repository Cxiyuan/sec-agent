## 深瞳 · 采集限值（正文上限）
## ⚠️ 本文件由容器入口（entrypoint.sh: render_limits）按 /config/interface.conf 的
##    body_max_bytes / resp_body_max_bytes 自动重写；这里是镜像内的默认版本。
##    请不要手工修改，改动会被后台配置覆盖。
##
## 这两个上限是 Zeek 侧**抓取**的字节数上限（HTTP::Info$body / $resp_body）；
## 后台「监控网段」页可改，改完看门狗约 10 秒内自动重载 Zeek。
## 归一化侧还有一层字符上限（config.py 的 http_body_max_chars / http_resp_body_max_chars）。

redef ShentongHTTP::max_body_len = 16384;
redef ShentongHTTP::max_resp_body_len = 65536;
