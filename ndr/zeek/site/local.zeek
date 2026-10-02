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
@load ./shentong-scripts-d
