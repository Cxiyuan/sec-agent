# 深瞳 · NDR 检测后端镜像（Python 3.11，无报告渲染依赖）
#
# 构建上下文是 **ndr/**（不是 ndr/backend/）：检测规则页要把签名规则（特征匹配）
# 和行为分析规则列在同一张表里，所以镜像里要带一份规则文件（`suricata/rules/builtin/`，
# 与签名引擎同源）。见 ndr/backend/app/suricata/catalog.py。
FROM python:3.11-slim

WORKDIR /app

COPY backend/pyproject.toml ./
COPY backend/app ./app
# 离线地理库（可视化流量的「访问地域 TOP5」）：**构建期现下**（DB-IP City Lite，CC BY 4.0），
# 仓库里只放脚本、不放 57MB 数据文件。下载失败不阻断构建（没库时该能力自动关闭）。
COPY backend/geoip ./geoip
RUN sh ./geoip/fetch.sh /app/geoip
# 签名规则目录（只读展示用）：保持与仓库同构 → /app/suricata/rules/builtin，
# catalog.py 按 `Path(app/suricata/catalog.py).parents[2]/suricata/rules/builtin` 找它。
COPY suricata/rules/builtin ./suricata/rules/builtin

RUN pip install --no-cache-dir .

# 让 app 包从源码目录解析（数据文件随源码走，不依赖 wheel 打包）
ENV PYTHONPATH=/app
# 地理库默认路径（app/geoip.py 读它；没库时该能力自动关闭，不影响其它功能）
ENV ST_GEOIP_DB=/app/geoip/ip.mmdb

EXPOSE 8000

# 默认启动配置管理 API；detector 在 docker-compose 里用 command 覆盖
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app"]
