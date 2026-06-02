# SHARD Enterprise SIEM v5.2.0

Production-grade WebUI for SHARD Enterprise SIEM System.

## Features

- 🔐 JWT Authentication with role-based access control
- 📊 Real-time dashboard with KPI metrics
- 🚨 Live alert monitoring via WebSocket
- 📈 Interactive charts (Plotly.js)
- 🚫 IP blocking management
- 📥 Export to CSV and Excel
- 🔍 Advanced search and filtering
- 📱 Mobile responsive design
- 🌙 Dark theme with cyberpunk aesthetics
- 🛡️ Security headers and XSS protection
- 📊 Prometheus metrics endpoint
- 🐳 Docker support

## Quick Start

### Using Docker Compose

```bash
# Clone repository
git clone https://github.com/shard-enterprise/webui.git
cd webui

# Start services
docker-compose up -d

# Access dashboard
open http://localhost:8000