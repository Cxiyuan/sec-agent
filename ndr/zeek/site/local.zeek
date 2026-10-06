## 深瞳 · 站点脚本总入口
## Zeek 以本文件启动（entrypoint.sh 执行 `zeek -i <iface> <site>/local.zeek`）
##
## 说明：shentong-nets.zeek 与 shentong-scripts-d.zeek 由容器入口自动生成，
##      镜像内带有默认版本，保证即使入口渲染失败也能起得来。

@load ./shentong-json
@load ./shentong-extra
@load ./shentong-policies
@load ./shentong-httpbody
@load ./shentong-limits
@load ./shentong-httpheaders
@load ./shentong-file-extract
@load ./shentong-fingerprints
@load ./shentong-nets
@load ./shentong-ports
@load ./shentong-scripts-d

## Community ID（社区流标识，CIS 标准）
## 为什么需要：签名引擎（Suricata）的告警里带 `community_id`，这里让 conn.log 也带上同值，
## 两个采集器的事实就能按「同一条流」对上（比五元组稳：不受 NAT、端口复用影响，加密流量也能对）。
## 加载失败也不会拖垮采集：本行只是多产出一个字段，Zeek 起不来才是大事故。
@load policy/protocols/conn/community-id-logging
