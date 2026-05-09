#!/bin/bash
# test_sqli.sh

echo "🧪 Тестирование SQL Injection детекции..."

# SQLi попытки
curl -u admin:ShardAdmin2026! "http://localhost:8080/?id=1' OR '1'='1"
curl -u admin:ShardAdmin2026! "http://localhost:8080/?id=1; SELECT * FROM users--"
curl -u admin:ShardAdmin2026! "http://localhost:8080/?id=1' UNION SELECT password FROM users--"

echo "✅ SQLi тесты отправлены. Проверяем WAF алерты..."
sleep 2

curl -u admin:ShardAdmin2026! http://localhost:8080/api/stats | python3 -m json.tool | grep -E "SQL|Web Attack"