#!/bin/bash
# SHARD Enterprise Launcher — запускает Engine + WebUI

cd /mnt/c/Users/user/PycharmProjects/Shard
source ~/.venv-linux/bin/activate

echo "🚀 Запуск SHARD Enterprise + WebUI..."

# Запускаем WebUI в фоне
cd shard-webui/backend
uvicorn app.main:app --host 0.0.0.0 --port 5000 &
WEBUI_PID=$!
cd ../..

# Ждём запуска WebUI
sleep 3

# Запускаем SHARD Engine
python run_shard.py --no-capture

# При остановке SHARD — останавливаем WebUI
kill $WEBUI_PID 2>/dev/null
echo "👋 SHARD остановлен"
