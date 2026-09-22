# 深瞳后端镜像（Python 3.11 + WeasyPrint 渲染依赖）
FROM python:3.11-slim

# WeasyPrint PDF 渲染所需系统库 + CJK 字体
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libharfbuzz0b shared-mime-info fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
COPY app ./app

RUN pip install --no-cache-dir .

# 让 app 包从源码目录解析（报告模板等数据文件随源码走，不依赖 wheel 打包）
ENV PYTHONPATH=/app

EXPOSE 8000

# 默认启动 API；worker/beat 在 docker-compose 里用 command 覆盖
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app"]
