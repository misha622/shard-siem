#!/bin/bash
# SHARD Enterprise SIEM — One-Click Deploy
# Запуск на любом Linux сервере за 1 минуту

set -e

echo "🛡️ SHARD Enterprise SIEM — Deploy"
echo "=================================="

# Проверка Docker
if ! command -v docker &> /dev/null; then
    echo "📦 Устанавливаем Docker..."
    curl -fsSL https://get.docker.com | bash
fi

# Клонируем репозиторий
if [ ! -d "shard-siem" ]; then
    echo "📥 Клонируем SHARD..."
    git clone https://github.com/misha622/shard-siem.git
    cd shard-siem
else
    cd shard-siem
    git pull
fi

# Собираем образ
echo "🔧 Сборка Docker образа..."
docker build -t shard-siem .

# Запускаем
echo "🚀 Запуск SHARD..."
docker rm -f shard-enterprise 2>/dev/null || true
docker run -d \
  --name shard-enterprise \
  --restart=unless-stopped \
  --memory="2g" \
  -p 8080:8080 -p 8081:8081 -p 5001:5001 \
  -p 2222:2222 -p 3306:3306 -p 5432:5432 \
  -p 6379:6379 -p 21:21 -p 23:23 \
  --cap-add NET_ADMIN \
  shard-siem \
  bash -c "python3 run_shard.py --no-capture & \
           sleep 25 && \
           python3 -c 'from shard_swagger_api import start_api_server; start_api_server(port=5001); import time; time.sleep(99999)'"

# Ждём запуск
echo "⏳ Ожидание запуска..."
sleep 30

# Проверяем
if curl -s http://localhost:5001/api/health | grep -q "ok"; then
    echo ""
    echo "✅ SHARD ЗАПУЩЕН!"
    echo ""
    echo "📊 Дашборд: http://$(curl -s ifconfig.me):8081"
    echo "📚 Swagger API: http://$(curl -s ifconfig.me):5001/api/docs"
    echo "🔑 Логин: admin / ShardAdmin2026!"
    echo ""
    echo "📋 Команды:"
    echo "   docker logs shard-enterprise    # Логи"
    echo "   docker restart shard-enterprise # Перезапуск"
    echo "   docker stop shard-enterprise    # Остановка"
else
    echo "❌ Ошибка запуска. Проверь логи:"
    docker logs shard-enterprise --tail 20
fi
