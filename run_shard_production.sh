#!/bin/bash
# SHARD Enterprise — Production Launcher
# Запуск с правами root для захвата трафика и iptables

if [ "$EUID" -ne 0 ]; then 
    echo "🔐 SHARD требует права root для:"
    echo "   - Захвата сетевого трафика (Scapy)"
    echo "   - Блокировки IP через iptables"
    echo ""
    echo "Перезапускаю с sudo..."
    exec sudo bash "$0" "$@"
    exit
fi

# Активируем окружение
source ~/.venv-linux/bin/activate 2>/dev/null || source /home/*/.venv-linux/bin/activate 2>/dev/null

# Загружаем переменные окружения
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Создаём цепочку iptables если её нет
iptables -L SHARD_BLOCK >/dev/null 2>&1 || iptables -N SHARD_BLOCK
iptables -C INPUT -j SHARD_BLOCK 2>/dev/null || iptables -I INPUT 1 -j SHARD_BLOCK

echo "🛡️ Запуск SHARD Enterprise в БОЕВОМ режиме..."
echo "   - Захват трафика: ВКЛЮЧЕН"
echo "   - Автоблокировка: ВКЛЮЧЕНА"
echo "   - iptables: НАСТРОЕНЫ"
echo ""

# Запускаем SHARD
cd "$(dirname "$0")"
python3 run_shard.py --config config.yaml "$@"
