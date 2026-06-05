#!/bin/bash
# SHARD Enterprise One-Click Installer
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       SHARD Enterprise SIEM — Установщик             ║"
echo "║       Версия 5.2.0 Production                       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Проверка прав
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Запустите от root: sudo ./install.sh${NC}"
    exit 1
fi

# Параметры
INSTALL_DIR="${1:-/opt/shard}"
SERVER_IP=$(hostname -I | awk '{print $1}')
echo -e "${GREEN}📁 Директория установки: $INSTALL_DIR${NC}"
echo -e "${GREEN}🌐 IP сервера: $SERVER_IP${NC}"

# 1. Установка зависимостей
echo -e "\n${CYAN}📦 Установка системных зависимостей...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv tcpdump iptables sqlite3 curl 2>/dev/null

# Создаём пользователя shard
if ! id -u shard &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false shard
fi

# 2. Виртуальное окружение
echo -e "${CYAN}🐍 Создание виртуального окружения...${NC}"
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate

# 3. Установка Python-зависимостей
echo -e "${CYAN}📦 Установка Python-пакетов...${NC}"
pip install -q --upgrade pip
pip install -q numpy scipy scikit-learn xgboost joblib requests psutil pyyaml fastapi uvicorn sqlalchemy pydantic-settings python-jose passlib bcrypt python-multipart apscheduler

# 4. Копирование файлов SHARD
echo -e "${CYAN}📁 Копирование файлов SHARD...${NC}"
# Копирование файлов из текущей директории (где запущен install.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR"/* $INSTALL_DIR/

# 5. Создание директорий
mkdir -p $INSTALL_DIR/data $INSTALL_DIR/logs $INSTALL_DIR/models $INSTALL_DIR/reports
chmod 750 $INSTALL_DIR/data $INSTALL_DIR/logs

# 6. Генерация пароля администратора
ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# 7. Создание .env
cat > $INSTALL_DIR/shard-webui/backend/.env << ENVEOF
SECRET_KEY=${SECRET_KEY}
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
HOST=0.0.0.0
PORT=5000
ALLOWED_ORIGINS=["http://${SERVER_IP}:5000","https://${SERVER_IP}:5000"]
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}
ENVEOF

# 8. Systemd сервисы
echo -e "${CYAN}⚙️ Настройка systemd сервисов...${NC}"

cat > /etc/systemd/system/shard-engine.service << SYSTEMD
[Unit]
Description=SHARD Enterprise SIEM Engine
After=network.target

[Service]
Type=simple
User=shard
WorkingDirectory=$INSTALL_DIR
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
ExecStart=$INSTALL_DIR/venv/bin/python run_shard.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SYSTEMD

cat > /etc/systemd/system/shard-webui.service << SYSTEMD
[Unit]
Description=SHARD Enterprise WebUI
After=network.target shard-engine.service

[Service]
Type=simple
User=shard
WorkingDirectory=$INSTALL_DIR/shard-webui/backend
ExecStart=$INSTALL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 5000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable shard-engine shard-webui

# 9. Права на захват трафика
REAL_PYTHON=$(readlink -f $INSTALL_DIR/venv/bin/python3)
setcap cap_net_raw,cap_net_admin=eip $REAL_PYTHON

# 10. Запуск
echo -e "${GREEN}🚀 Запуск SHARD Enterprise...${NC}"
systemctl start shard-engine shard-webui

# 11. Вывод информации
echo -e "\n${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         SHARD Enterprise установлен!                  ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}║  🌐 Дашборд:   http://${SERVER_IP}:5000              ║${NC}"
echo -e "${GREEN}║  📊 API Docs:  http://${SERVER_IP}:5000/docs         ║${NC}"
echo -e "${GREEN}║  🔑 Логин:     admin                                  ║${NC}"
echo -e "${GREEN}║  🔐 Пароль:    ${ADMIN_PASSWORD}                      ║${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}║  📁 Директория: $INSTALL_DIR                         ║${NC}"
echo -e "${GREEN}║  📋 Статус:     systemctl status shard-engine         ║${NC}"
echo -e "${GREEN}║  📋 Логи:       journalctl -u shard-engine -f         ║${NC}"
echo -e "${GREEN}║                                                       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"

# Сохраняем пароль
echo "admin:${ADMIN_PASSWORD}" > $INSTALL_DIR/admin_credentials.txt
chmod 600 $INSTALL_DIR/admin_credentials.txt
echo -e "\n🔐 Учётные данные сохранены в: $INSTALL_DIR/admin_credentials.txt"
