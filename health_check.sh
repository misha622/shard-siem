#!/bin/bash
# SHARD Health Check Script

echo "🔍 SHARD Enterprise Health Check"
echo "================================"

# Проверка Python
echo -n "Python: "
python3 --version 2>/dev/null || echo "❌ Not found"

# Проверка виртуального окружения
echo -n "Virtual Env: "
if [ -d ~/.venv-linux ]; then
    echo "✅ $(~/.venv-linux/bin/python --version)"
else
    echo "❌ Not found"
fi

# Проверка прав на захват пакетов
echo -n "Packet Capture: "
if getcap $(which python3) 2>/dev/null | grep -q cap_net_raw; then
    echo "✅ Capabilities set"
else
    echo "⚠️ Run: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)"
fi

# Проверка портов
echo -n "Dashboard (8080): "
ss -tlnp | grep -q :8080 && echo "✅ Running" || echo "⏹️ Stopped"

echo -n "WebUI (8000): "
ss -tlnp | grep -q :8000 && echo "✅ Running" || echo "⏹️ Stopped"

echo -n "Prometheus (9090): "
ss -tlnp | grep -q :9090 && echo "✅ Running" || echo "⏹️ Stopped"

# Проверка файлов
echo -n "Config: "
[ -f config.yaml ] && echo "✅ Exists" || echo "❌ Missing"

echo -n "Database: "
[ -f shard_siem.db ] && echo "✅ $(du -h shard_siem.db | cut -f1)" || echo "❌ Missing"

echo -n "Models: "
[ -d models ] && echo "✅ $(ls models/*.pkl 2>/dev/null | wc -l) files" || echo "❌ Missing"

# Проверка логов
echo -n "Logs: "
[ -f shard.log ] && echo "✅ $(du -h shard.log | cut -f1)" || echo "⏹️ No logs yet"

# Проверка systemd
echo -n "Systemd Service: "
systemctl is-active shard-enterprise 2>/dev/null || echo "Not running"
