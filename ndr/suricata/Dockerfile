# 深瞳 · 签名引擎（Suricata）镜像
#
# 基底：官方社区镜像（内含 suricata 与 suricata-update）。**tag 固定**，升级走一次提交。
# 构建期就把 ET Open 规则拉下来固化进镜像：容器运行时**不需要外网**（客户环境常无外网），
# 规则更新 = 重出镜像，和本仓库其它镜像一样只由 GitHub Actions 构建（本地不构建、不拉镜像）。
#
# ET Open 的许可是 MIT（OISF/suricata-intel-index 里 `license: MIT`），随镜像分发无许可风险；
# ET Pro 是商业许可，不在这里拉取。
ARG SURICATA_BASE=jasonish/suricata:7.0
FROM ${SURICATA_BASE}

USER root

# 只留我们需要的规则集，并按 disable/modify 清单裁剪（第一版两个清单都是空的，见文件里的说明）
COPY disable.conf modify.conf /etc/suricata/
RUN set -eux; \
    if command -v suricata-update >/dev/null 2>&1; then \
      suricata-update \
        --no-test \
        --disable-conf /etc/suricata/disable.conf \
        --modify-conf /etc/suricata/modify.conf; \
      test -s /var/lib/suricata/rules/suricata.rules; \
      wc -l /var/lib/suricata/rules/suricata.rules; \
    else \
      echo "镜像内没有 suricata-update：跳过规则更新（部署时需自带规则文件）" >&2; \
    fi

# 配置模板 + 入口（网卡/网段/端口由 entrypoint 从共享采集配置渲染）
COPY suricata.yaml.tmpl /usr/local/share/shentong/suricata.yaml.tmpl
COPY entrypoint.sh /usr/local/bin/shentong-suricata-entrypoint.sh
COPY healthcheck.sh /usr/local/bin/shentong-suricata-healthcheck.sh
RUN chmod +x /usr/local/bin/shentong-suricata-entrypoint.sh /usr/local/bin/shentong-suricata-healthcheck.sh

VOLUME ["/logs", "/config"]

# 采集面健康检查：Suricata 起不来（规则加载失败/网卡不可用）时容器变 unhealthy。
# 判据由 entrypoint 写的哨兵文件提供；unhealthy 不会触发重启（重启由入口的守护循环负责）。
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD /usr/local/bin/shentong-suricata-healthcheck.sh

ENTRYPOINT ["/usr/local/bin/shentong-suricata-entrypoint.sh"]
