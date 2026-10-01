# 深瞳 · NDR 检测后端镜像（Python 3.11，无报告渲染依赖）
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY app ./app

RUN pip install --no-cache-dir .

# 让 app 包从源码目录解析（数据文件随源码走，不依赖 wheel 打包）
ENV PYTHONPATH=/app

EXPOSE 8000

# 默认启动配置管理 API；detector 在 docker-compose 里用 command 覆盖
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app"]
