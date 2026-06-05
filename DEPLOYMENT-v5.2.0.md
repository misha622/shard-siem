# SHARD Enterprise v5.2.0 — Production Deployment

## Что сделано
- 17 багов исправлено (C-1 до L-3)
- WebUI интегрирован с SHARD Engine (общая БД)
- Systemd сервисы (shard-engine.service + shard-webui.service)
- Захват трафика через setcap
- Honeypot на 13 портах
- iptables файрвол активен
- One-click установщик install.sh
- Агент для клиентов shard_agent.py
- Автоматический дашборд на порту 5000

## Доступ
- URL: http://127.0.0.1:5000/login.html
- Логин: admin

## Системные требования
- Ubuntu 22.04+
- Python 3.11+
- 2GB+ RAM
- Root-доступ для iptables
