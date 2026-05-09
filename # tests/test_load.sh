#!/bin/bash
# test_load.sh

echo "🧪 Нагрузочное тестирование..."

# Установить apache2-utils если нет
if ! command -v ab &> /dev/null; then
    sudo apt install apache2-utils -y
fi

# 1000 запросов, 100 одновременных
ab -n 1000 -c 100 -A admin:ShardAdmin2026! http://localhost:8080/api/stats

echo "✅ Нагрузочный тест завершён"
