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

# 只留我们需要的规则集，并按 disable/modify 清单裁剪。
# 注意（CI 实测 2026-10-07）：`--disable-conf` 在这个版本上**没有拦住**那两类噪音
# （STREAM 引擎事件 67 条、ET 的 2054407 都还在里面）—— 所以后面再加一道确定性的
# 内容级后处理（并打印前后行数），两道都保留：规则来源变了也不会静默失效。
COPY disable.conf modify.conf /etc/suricata/
RUN set -eux; \
    if command -v suricata-update >/dev/null 2>&1; then \
      suricata-update \
        --no-test \
        --disable-conf /etc/suricata/disable.conf \
        --modify-conf /etc/suricata/modify.conf; \
    else \
      echo "镜像内没有 suricata-update：跳过规则更新（部署时需自带规则文件）" >&2; \
    fi; \
    RULES=/var/lib/suricata/rules/suricata.rules; \
    test -s "$RULES"; \
    before="$(wc -l < "$RULES")"; \
    grep -v -e 'msg:"SURICATA STREAM' -e 'sid:2054407;' "$RULES" > "${RULES}.filtered"; \
    mv "${RULES}.filtered" "$RULES"; \
    after="$(wc -l < "$RULES")"; \
    echo "规则裁剪：${before} → ${after} 行（引擎流异常 + banner 类）"; \
    test "$after" -lt "$before"; \
    test "$(grep -c 'SURICATA STREAM' "$RULES" || true)" = "0"; \
    wc -l "$RULES"

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
