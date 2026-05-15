# ============================================================
# SHARD Enterprise SIEM — Docker Image
# 10 нейросетей, 20+ модулей, fully autonomous AI defence
# ============================================================

FROM python:3.11-slim

LABEL org.shard.siem="Enterprise SIEM"
LABEL org.shard.version="5.1.0"
LABEL org.shard.ai_modules="10"

# Системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    libsnappy-dev \
    iptables \
    net-tools \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Рабочая директория
WORKDIR /app

# Копируем зависимости
COPY requirements_docker.txt .

# Устанавливаем Python пакеты
RUN pip install --no-cache-dir -r requirements_docker.txt && \
    pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu \
    xgboost \
    scikit-learn

# Копируем весь проект
ARG CACHEBUST=1
COPY . .

# Создаём директории для данных
RUN mkdir -p /app/data /app/logs /app/reports /app/models

# Переменные окружения
ENV PYTHONUNBUFFERED=1
ENV SHARD_ENV=production
ENV SHARD_CONFIG_SECRET=change_me_in_production

# Открываем порты
EXPOSE 8080 8081 9090 5000

# Точка входа
ENTRYPOINT ["python3", "run_shard.py"]
CMD ["--config", "config.yaml"]
