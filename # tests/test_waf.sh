#!/bin/bash
# test_waf.sh

echo "🧪 Тестирование WAF Rate Limit..."

# 150 запросов за 1 секунду
for i in {1..150}; do
    curl -s -u admin:ShardAdmin2026! http://localhost:8080/ -o /dev/null &
done
wait

echo "✅ Флуд завершён. Проверяем алерты..."
sleep 2

curl -u admin:ShardAdmin2026! http://localhost:8080/api/stats | python3 -m json.tool | grep -A5 "attack_types"