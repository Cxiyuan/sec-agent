# 深瞳 · 签名引擎（Suricata）镜像
#
# 基底：官方社区镜像（内含 suricata 与 suricatasc）。tag 固定，升级走一次提交。
#
# 规则来源（2026-10 用户口径）：
#   **不使用任何内置规则集，也不联网自动更新** —— 没有 suricata-update、不拉 ET Open。
#   镜像只带一个**空占位规则文件**（0 条规则 ⇒ 开箱不产生任何告警）；真实规则由项目开发人员
#   维护，通过界面「检测规则 → 签名规则」配置的在线地址（manifest：文件列表 + sha256）下发，
#   校验通过且人工确认后才生效。引擎自带事件规则（SURICATA *）按口径一律不加载。
#   因为不再需要下载规则，**镜像构建不需要外网**。
ARG SURICATA_BASE=jasonish/suricata:7.0
FROM ${SURICATA_BASE}

USER root

# 规则（内置默认分类集 + 空占位兜底）/ manifest 示例 / 配置模板 / 入口
#（网卡、网段、HTTP 端口、规则列表都由入口渲染）
COPY rules/ /usr/local/share/shentong/rules/
COPY manifest.example.json /usr/local/share/shentong/manifest.example.json
COPY suricata.yaml.tmpl /usr/local/share/shentong/suricata.yaml.tmpl
COPY entrypoint.sh /usr/local/bin/shentong-suricata-entrypoint.sh
COPY healthcheck.sh /usr/local/bin/shentong-suricata-healthcheck.sh
RUN set -eux; \
    chmod +x /usr/local/bin/shentong-suricata-entrypoint.sh /usr/local/bin/shentong-suricata-healthcheck.sh; \
    test -f /usr/local/share/shentong/rules/shentong.rules; \
    test "$(ls /usr/local/share/shentong/rules/builtin/*.rules | wc -l)" -ge 1; \
    test -f /usr/local/share/shentong/rules/builtin/index.json; \
    mkdir -p /rules/active /rules/staging /rules/previous /rules/rejected

# /rules：规则集与状态（后端与本容器共写各自的文件，见 README 的目录约定）
VOLUME ["/logs", "/config", "/rules"]

# 采集面健康检查：Suricata 起不来（规则加载失败/网卡不可用）时容器变 unhealthy。
# 判据由入口写的哨兵文件提供；unhealthy 不会触发重启（重启由入口的守护循环负责）。
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD /usr/local/bin/shentong-suricata-healthcheck.sh

ENTRYPOINT ["/usr/local/bin/shentong-suricata-entrypoint.sh"]
