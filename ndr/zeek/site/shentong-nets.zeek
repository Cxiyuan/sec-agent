## 深瞳 · 本地网段（Site::local_nets）
## ⚠️ 本文件由容器入口（entrypoint.sh: render_nets）按 /config/interface.conf 的
##    local_nets 字段自动重写；这里是镜像内的默认版本（本地网段留空 = 用 Zeek 默认判定）。
##    请不要手工修改，改动会被后台配置覆盖。

module Site;

# local_nets 由后台「监控网段」生成；为空时注释掉，沿用 Zeek 默认
# redef Site::local_nets = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, };
