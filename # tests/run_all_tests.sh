#!/bin/bash
# run_all_tests.sh

echo "============================================================"
echo "🧪 ЗАПУСК ВСЕХ ТЕСТОВ SHARD ENTERPRISE"
echo "============================================================"

# 1. Юнит-тесты
echo -e "\n📌 Юнит-тесты..."
python3 -m pytest tests/test_core.py -v 2>/dev/null || python3 tests/test_core.py

# 2. WAF тест
echo -e "\n📌 WAF Rate Limit тест..."
./test_waf.sh

# 3. Honeypot тест
echo -e "\n📌 Honeypot тест..."
./test_honeypot.sh

# 4. SQLi тест
echo -e "\n📌 SQL Injection тест..."
./test_sqli.sh

# 5. ML тест
echo -e "\n📌 ML детекция тест..."
./test_ml.sh

# 6. Интеграционный тест
echo -e "\n📌 Интеграционный тест..."
python3 tests/test_integration.py

echo -e "\n============================================================"
echo "✅ ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ"
echo "============================================================"