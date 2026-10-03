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

# 轮转归档与活动日志**同目录平铺**（不是日期子目录）：conn.log → conn.<时间戳>.log。
# 时间戳**必须带时分秒**：只精确到「天」时（曾用 %Y-%m-%d），同一天内第二次启动 Zeek 会用
# 同名文件覆盖当天已归档的数据 —— 2026-10 实测：同配置连跑两次，第二次的 rot.2026-10-02.log
# 覆盖第一次（sha256 变化、前一次内容消失）。界面改网段触发的重载、compose restart、崩溃自愈
# 都会触发重启，因此这是常态风险。
# 这里用 Zeek 上游默认值 "%Y-%m-%d-%H-%M-%S"（base/frameworks/logging/main.zeek），
# 别为"好看"再把它改回只到天的格式。
redef Log::default_rotation_date_format = "%Y-%m-%d-%H-%M-%S";
