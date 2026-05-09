#!/bin/bash
# test_honeypot.sh

echo "🧪 Тестирование Honeypot..."

# Подключение к портам
for port in 22 80 443 2222 8888; do
    echo "Проверка порта $port..."
    timeout 1 nc -zv 127.0.0.1 $port 2>&1
done

echo "✅ Проверка завершена. Смотрим алерты..."
sleep 2

curl -u admin:ShardAdmin2026! http://localhost:8080/api/stats | python3 -m json.tool | grep "Honeypot"