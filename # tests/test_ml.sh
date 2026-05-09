#!/bin/bash
# test_ml.sh

echo "🧪 Тестирование ML детекции..."

# Генерируем аномальный трафик
for i in {1..50}; do
    # Большие пакеты на нестандартный порт
    curl -s -X POST -d "$(head -c 50000 /dev/urandom | base64)" \
         -u admin:ShardAdmin2026! \
         http://localhost:8080/api/test -o /dev/null &
done
wait

echo "✅ Аномальный трафик отправлен. Проверяем ML алерты..."
sleep 5

curl -u admin:ShardAdmin2026! http://localhost:8080/api/stats | python3 -m json.tool | grep -E "Anomaly|Data Exfiltration"