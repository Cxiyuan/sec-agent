## 深瞳 · 可扩展脚本目录（占位文件）
##
## 用法：把自定义 Zeek 脚本（*.zeek）放进本目录，容器入口会自动生成加载器把它 @load 进来。
##      加载是「启动时」完成，所以新增/修改脚本后需要重启容器生效：
##          docker compose restart zeek
##
## 建议：文件名用数值前缀控制加载顺序，例如 010-my-rules.zeek、020-my-enrich.zeek
##
## 注意：本文件本身是可被加载的脚本（只含注释），不要删掉，否则空目录会导致加载器无内容。

# 示例（取消注释后按需修改）：
# event zeek_init() {
#     print "shentong custom script loaded";
# }
