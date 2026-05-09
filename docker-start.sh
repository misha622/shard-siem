#!/bin/bash
# SHARD Docker Quick Start

echo "🛡️ SHARD Enterprise SIEM — Docker Launch"
echo "========================================"

# Генерируем секретный ключ
export SHARD_CONFIG_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "🔑 Secret key: $SHARD_CONFIG_SECRET"

# Собираем образ
echo ""
echo "📦 Building Docker image..."
docker build -t shard-siem:latest .

# Запускаем
echo ""
echo "🚀 Starting SHARD..."
docker-compose up -d

# Ждём запуска
echo ""
echo "⏳ Waiting for SHARD to start..."
sleep 10

# Проверяем
echo ""
echo "✅ SHARD is running!"
echo ""
echo "📊 Dashboards:"
echo "   http://localhost:8080 — SHARD Dashboard (admin / ShardAdmin2026!)"
echo "   http://localhost:3000 — Grafana (admin / shard2026)"
echo "   http://localhost:9090 — Prometheus Metrics"
echo "   http://localhost:5000 — Mobile API"
echo ""
echo "🛑 To stop: docker-compose down"
echo "📋 To view logs: docker-compose logs -f shard-siem"
