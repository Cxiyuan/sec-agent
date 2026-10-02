# 深瞳 · Zeek 9.0 适配镜像
# 基底：官方 zeek/zeek（Debian，Zeek 9.0 LTS），内含 Zeek + zkg
# 追加：Filebeat 发运、JSON 日志、24h 轮转、本地只留 3 天、自定义脚本
ARG ZEEK_BASE=zeek/zeek:9.0
FROM ${ZEEK_BASE}

USER root

# ---- 安装 Filebeat（按 CPU 架构选择 tarball；不启 JVM，轻量）----
ARG FILEBEAT_VERSION=8.15.3
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates tini; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) fb_arch=x86_64 ;; \
      arm64) fb_arch=aarch64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-${FILEBEAT_VERSION}-linux-${fb_arch}.tar.gz" -o /tmp/filebeat.tgz; \
    tar -xzf /tmp/filebeat.tgz -C /opt; \
    mv "/opt/filebeat-${FILEBEAT_VERSION}-linux-${fb_arch}" /opt/filebeat; \
    ln -sf /opt/filebeat/filebeat /usr/local/bin/filebeat; \
    rm -f /tmp/filebeat.tgz; \
    rm -rf /var/lib/apt/lists/*

# ---- 站点脚本（自带脚本 + 可扩展目录）----
COPY site/ /usr/local/zeek/share/zeek/site/
COPY scripts.d/ /usr/local/zeek/share/zeek/site/scripts.d/
COPY filebeat.yml /etc/filebeat/filebeat.yml
COPY entrypoint.sh /start.sh
# 提取件清理助手（批 4）：用镜像自带的 python3 跑（zeek/zeek 基础镜像为 zkg 装有 python3），
# 读 files.log 判定 MIME 白名单并控制 /extract 容量。
COPY extract_cleanup.py /usr/local/bin/extract_cleanup.py
RUN chmod +x /start.sh /usr/local/bin/extract_cleanup.py

VOLUME ["/logs", "/config", "/extract"]

# 抓包需要 root + NET_RAW/NET_ADMIN；看门狗与清理循环在 start.sh 内
ENTRYPOINT ["/usr/bin/tini", "--", "/start.sh"]
