FROM python:3.11-slim

WORKDIR /app

# 系统依赖：nmap 可选；不装也能跑（socket 降级）
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==21.2.0

COPY . .

EXPOSE 5000

# 使用 gunicorn 启动，4 个 worker
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
