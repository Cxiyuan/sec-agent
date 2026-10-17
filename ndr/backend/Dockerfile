# 深瞳 · NDR 检测后端镜像（Python 3.11，无报告渲染依赖）
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY app ./app
# 离线地理库（可视化流量的「访问地域 TOP5」）：gz 随仓库发布，构建时解压进镜像。
# 解压后删掉 .gz：运行期只需要 .mmdb，少占 60MB 镜像体积。
COPY geoip ./geoip
RUN gunzip -c ./geoip/*.mmdb.gz > /app/geoip/ip.mmdb && rm -f ./geoip/*.mmdb.gz

RUN pip install --no-cache-dir .

# 让 app 包从源码目录解析（数据文件随源码走，不依赖 wheel 打包）
ENV PYTHONPATH=/app
# 地理库默认路径（app/geoip.py 读它；没库时该能力自动关闭，不影响其它功能）
ENV ST_GEOIP_DB=/app/geoip/ip.mmdb

EXPOSE 8000

# 默认启动配置管理 API；detector 在 docker-compose 里用 command 覆盖
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app"]
