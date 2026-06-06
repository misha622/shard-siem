# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please email shard-security@proton.me instead of opening a public issue.

## Pre-deployment Checklist

- [ ] Change all default passwords (admin, viewer, API keys)
- [ ] Rotate SECRET_KEY in .env
- [ ] Run penetration test
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Set up firewall rules
- [ ] Configure rate limiting
- [ ] Review access logs

## Known Limitations

- Requires root for iptables packet capture
- Single-instance deployment (no horizontal scaling yet)
- shard_enterprise_complete.py is legacy monolithic file — use modular imports from core/ and modules/
