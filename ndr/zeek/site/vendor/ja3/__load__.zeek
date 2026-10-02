## 深瞳自建加载器（本文件不是上游文件）
##
## 上游 salesforce/ja3 的 zeek/__load__.zeek 会额外 @load ./intel_ja3.zeek，
## 那个脚本把 JA3 接进 Zeek 的 Intel 情报框架、并另开 ja3sfp 流；本项目不用情报框架，
## 所以只加载真正产出指纹字段的两个脚本：
##   ja3.zeek  → SSL::Info::ja3（客户端指纹）
##   ja3s.zeek → SSL::Info::ja3s（服务端指纹）
##
## 许可证：BSD-3-Clause（见同目录 LICENSE.txt）。

@load ./ja3.zeek
@load ./ja3s.zeek
