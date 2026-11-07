# 必须用 noble（自带 Python 3.12）；jammy 镜像是 Python 3.10
# 若更换 tag，需同步改 requirements.txt 的 playwright== 与 compose 的 PW_VERSION
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble

WORKDIR /app
ENV PYTHONUNBUFFERED=1 TZ=Asia/Shanghai PW_VERSION=1.49.1 USER_DATA_DIR=/app/user_data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8055
# 全部状态在内存 + 单浏览器实例，必须单 worker
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8055", "--workers", "1"]
