## 深瞳 · JSON 日志输出 + 24 小时轮转 + 固定输出目录
##
## ⚠️ 重要：Zeek 的日志框架只负责「轮转」（rotation），**不负责过期删除**。
##    Zeek 生态里「删除过期归档」是 zeekctl 的能力（LogExpireInterval + bin/expire-logs，
##    由 `zeekctl cron` 执行）。本项目采用单进程方式运行（不用 zeekctl 集群），
##    因此「只保留 3 天」由容器入口的清理循环保证（见 entrypoint.sh: cleanup_once）。

@load policy/tuning/json-logs   # 等价于 redef LogAscii::use_json = T;

# 日志输出根目录（与 Filebeat / 清理循环的 ZEEK_LOG_DIR 对齐）
redef Log::default_logdir = "/logs";

# 每 24 小时轮转一次
redef Log::default_rotation_interval = 24hrs;

# 轮转后的文件放到日期子目录（清理循环只删这些，不动正在写的活动日志）
redef Log::default_rotation_date_format = "%Y-%m-%d";
