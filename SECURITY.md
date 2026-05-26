# SHARD Enterprise SIEM — Security Policy

## Reporting a Vulnerability
Email: shard019@mail.ru — PGP I'll send you the key upon request. Don't create a public one. issue.

## Supported Versions
| Version | Supported |
|---------|-----------|
| 5.1.x   | ✅ Active |
| 5.0.x   | ❌ EOL |
| < 5.0   | ❌ EOL |

## Security Architecture
- 10 neural networks for attack detection
- EventBus with per-subscriber queues (lock-free)
- iptables integration with IP validation (injections blocked)
- API keys in environment variables, not in code
- RBAC for Dashboard (admin/analyst/viewer)
- HMAC signature of configuration (anti-spoofing)
- WAF protection against SQLi/XSS/Path Traversal

## Threat Model
- Trusted zone: localhost, internal network
- Untrusted zone: external traffic, API requests
- Attack vectors: network packets → validation via Scapy, shell injections → strong IP validation
- Attacker model: external attacker with network access

## Security Headers (Dashboard)
- Content-Security-Policy
- X-Content-Type-Options: nosniff
- Access-Control-Allow-Origin limited

## Audit
An independent pentest is recommended before production deployment.
