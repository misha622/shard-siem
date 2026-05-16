# SHARD Enterprise SIEM — Security Policy

## Reporting a Vulnerability
Email: misha622@github — PGP ключ пришлю по запросу. Не создавай публичный issue.

## Supported Versions
| Version | Supported |
|---------|-----------|
| 5.1.x   | ✅ Active |
| 5.0.x   | ❌ EOL |
| < 5.0   | ❌ EOL |

## Security Architecture
- **10 нейросетей** для детекции атак
- **EventBus** с per-subscriber очередями (lock-free)
- **iptables** интеграция с валидацией IP (инъекции заблокированы)
- **API ключи** в переменных окружения, не в коде
- **RBAC** для Dashboard (admin/analyst/viewer)
- **HMAC-подпись** конфигурации (защита от подмены)
- **WAF** защита от SQLi/XSS/Path Traversal

## Threat Model
- **Доверенная зона:** localhost, внутренняя сеть
- **Недоверенная зона:** внешний трафик, API запросы
- **Векторы атак:** сетевые пакеты → валидация через Scapy, shell-инъекции → строгая валидация IP
- **Модель нарушителя:** внешний атакующий с доступом к сети

## Security Headers (Dashboard)
- Content-Security-Policy
- X-Content-Type-Options: nosniff
- Access-Control-Allow-Origin ограничен

## Audit
Рекомендуется независимый пентест перед production-деплоем.
