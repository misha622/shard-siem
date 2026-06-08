<div align="center">

<img src="https://raw.githubusercontent.com/misha622/shard-siem/main/shard-webui/frontend/assets/favicon.svg" width="80" height="80" alt="SHARD Logo"/>

# SHARD Enterprise SIEM

**Autonomous AI-powered Security Information and Event Management**

[![CI/CD](https://github.com/misha622/shard-siem/actions/workflows/ci.yml/badge.svg)](https://github.com/misha622/shard-siem/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-175%20passing-brightgreen)](https://github.com/misha622/shard-siem/actions)
[![Python](https://img.shields.io/badge/python-3.11-blue)](https://python.org)
[![Version](https://img.shields.io/badge/version-5.2.7-orange)](https://github.com/misha622/shard-siem/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Code Quality](https://img.shields.io/badge/pylint-8.29%2F10-yellow)](https://github.com/misha622/shard-siem)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-835%20techniques-red)](https://attack.mitre.org)

*Detect. Analyze. Respond. Automatically.*

[🚀 Quick Start](#-quick-start) · [📖 Documentation](#-documentation) · [💰 Pricing](#-pricing) · [🎥 Demo](#-demo)

</div>

---

## 🧠 What is SHARD?

SHARD is an **enterprise-grade, AI-native SIEM** that autonomously detects, investigates, and responds to cyber threats in real time. It combines 10 neural networks, 835 MITRE ATT&CK techniques, and 22 security modules into a unified platform that your team can deploy in minutes.

> Built for security teams that can't afford to miss a threat.

---

## ⚡ Key Numbers

| Metric | Value |
|--------|-------|
| 🤖 Neural Networks | **10** concurrent ML models |
| 🎯 MITRE ATT&CK | **835** techniques mapped |
| 🧪 Test Coverage | **175** tests passing |
| 🛡️ Security Modules | **22** active modules |
| 🍯 Honeypots | **13** configurable services |
| ⚡ Detection Latency | **< 1 second** |
| 🐛 Bugs Fixed | **250+** across 52+ audits |

---

## 🤖 AI Detection Engine

SHARD runs 10 neural networks in parallel — each specialized for different threat types:

| Model | Threat Type |
|-------|-------------|
| **XGBoost** | Attack classification with SHAP explanations |
| **IsolationForest** | Network anomaly detection |
| **Temporal GNN** | Lateral movement via graph analysis |
| **Variational Autoencoder** | Zero-day / unknown attack detection |
| **RL DQN Agent** | Autonomous response decisions |
| **Seq2Seq Transformer** | Attack sequence prediction |
| **Attention LSTM** | Temporal behavior patterns |
| **Random Forest** | Multi-class threat scoring |
| **Multi-Modal Fusion** | Cross-source signal correlation |
| **Federated Learning** | Privacy-preserving distributed detection |

---

## 🛡️ Security Modules

```
✅ Web Application Firewall        ✅ Deep Packet Inspection
✅ Honeypot System (13 services)   ✅ DNS Analyzer
✅ Threat Intelligence             ✅ User Behavior Analytics (UBA)
✅ EDR Integration                 ✅ Exfiltration Detector
✅ Encrypted Traffic Analysis      ✅ LDAP Integration
✅ Report Generator                ✅ Agentic AI Response
✅ Traffic Capture (setcap)        ✅ SOAR Integration
✅ Cloud Security Monitoring       ✅ Digital Forensics
✅ CVE Intelligence                ✅ Deception Technology
✅ Attack Chain Tracker            ✅ Lateral Movement Detection
✅ Threat Hunting AI               ✅ Compliance Engine
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Traffic Sources                     │
│     Network · Endpoints · Cloud · Logs · DNS         │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│              SHARD Core Engine                       │
│  EventBus → ModuleRegistry → 10 ML Models           │
│  ConfigManager (HMAC) · LoggingService               │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│           Threat Correlation Engine                  │
│   835 MITRE ATT&CK techniques · Attack chains        │
│   Behavioral baseline · Anomaly scoring              │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│         Autonomous Response System                   │
│   Auto-block IPs · WAF rules · Honeypot redirect    │
│   Forensic reports · Slack/email alerts             │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│            WebUI Dashboard (FastAPI)                 │
│   Real-time charts · Geo map · Multi-tenant RBAC    │
│   WebSocket alerts · Prometheus metrics             │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Requirements

- Docker & Docker Compose
- 8+ GB RAM
- 20+ GB disk space

### One-Command Deploy

```bash
git clone https://github.com/misha622/shard-siem.git
cd shard-siem
cp shard-webui/backend/.env.example shard-webui/backend/.env
# Edit .env with your credentials
docker-compose up -d
```

Dashboard available at `http://localhost:5000`

### Manual Install (Linux)

```bash
git clone https://github.com/misha622/shard-siem.git
cd shard-siem
chmod +x install.sh
sudo ./install.sh
```

---

## 🔍 Real Detection Examples

### SSH Brute Force

```
[14:32:01] ALERT   SSH brute force — 185.142.53.101 (847 attempts/min)
           Technique: T1110 - Brute Force
           Models: IsolationForest (94.7%) + Behavioral baseline
[14:32:01] AUTO    IP blocked via iptables + honeypot redirect
```

### SQL Injection

```
[15:17:44] ALERT   SQL injection attempt on port 8080
           Payload: ' OR '1'='1'; DROP TABLE users--
           Technique: T1190 - Exploit Public-Facing Application
           Models: WAF signature + Seq2Seq Transformer
[15:17:44] AUTO    Request blocked, IP rate-limited
```

### Lateral Movement

```
[16:03:12] CRIT    Lateral movement detected — 10.0.0.23 → 10.0.0.x/24
           Technique: T1021 - Remote Services
           Models: Temporal GNN (attack graph analysis)
[16:03:12] AUTO    Network segment isolated, alert escalated
```

---

## 🏢 Multi-Tenant Architecture

SHARD supports multiple organizations on a single deployment:

- **7-tier RBAC**: superadmin → admin → manager → analyst → operator → viewer → agent
- **JWT authentication** with refresh tokens
- **Row-level isolation** — tenants never see each other's data
- **Invite-based onboarding** with company_id embedding in tokens
- **Per-tenant dashboards** and alert streams

---

## 📊 Tech Stack

| Layer | Technology |
|-------|-----------|
| Core Engine | Python 3.11, AsyncIO |
| AI/ML | PyTorch, Scikit-learn, XGBoost |
| Web API | FastAPI, SQLAlchemy |
| Frontend | Vanilla JS, Plotly, WebSocket |
| Storage | SQLite (dev) → PostgreSQL / TimescaleDB (prod) |
| Infrastructure | Docker Compose, systemd |
| Monitoring | Prometheus + Grafana |
| CI/CD | GitHub Actions (lint + test + security + docker) |

---

## 🧪 CI/CD Pipeline

Every push to `main` automatically runs:

```
Code Quality (flake8 + pylint)
    ↓
Core Tests — 155 tests (pytest + coverage)
    ↓
WebUI Tests — 20 tests (FastAPI + httpx)
    ↓
Security Scan (Bandit — 0 critical findings)
    ↓
Docker Build (both images)
    ↓
Deploy to VPS (manual trigger)
```

---

## 💰 Pricing

| Plan | Price | What's included |
|------|-------|----------------|
| **Community** | Free | Core engine, basic ML, single tenant, GitHub |
| **Professional** | $299/mo | All 10 ML models, multi-tenant, 835 MITRE, priority support |
| **Enterprise** | $999/mo | On-premise, federated learning, custom integrations, SLA |

**💳 Payments:** USDT (TRC-20 / ERC-20) · Bitcoin  
**📧 Contact:** shard-security@proton.me

---

## 🎥 Demo

[![Demo Video](https://img.shields.io/badge/▶%20Watch%20Demo-YouTube-red)](https://youtube.com/shorts/aeyiGMYsbn0)

---

## 🗺️ Roadmap

**v5.3**
- [ ] Kubernetes / Helm chart
- [ ] Advanced SOAR playbooks
- [ ] Slack / Teams / PagerDuty notifications
- [ ] Load testing & horizontal scaling

**v6.0**
- [ ] Autonomous SOC mode
- [ ] AI-generated threat reports
- [ ] SOC 2 Type I certification
- [ ] Real-time adaptive policies

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git fork → feature branch → pull request
```

---

## ⚠️ Legal

SHARD is intended for **authorized environments only** — research, education, and systems you own or have explicit permission to monitor. Users are responsible for compliance with applicable laws.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**⭐ Star this repo if SHARD helped you — it means a lot!**

[🚀 Get Started](https://github.com/misha622/shard-siem#-quick-start) · [💬 Contact](mailto:shard-security@proton.me) · [🐛 Issues](https://github.com/misha622/shard-siem/issues)

</div>

