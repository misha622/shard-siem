# SHARD Enterprise SIEM — API Documentation v5.1.0

## Dashboard API (port 8080/8081)

### Authentication
Basic Auth: `Authorization: Basic <base64(user:pass)>`

### Endpoints

| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/` | any | Dashboard HTML |
| GET | `/api/health` | any | System health + DB status |
| GET | `/api/stats` | any | Alert statistics |
| GET | `/api/alerts` | any | Recent alerts list |
| GET | `/api/report/<id>` | any | Incident report |
| POST | `/api/block` | admin | Block IP manually |

### Roles
- **admin**: full access
- **analyst**: read + write, no blocking
- **viewer**: read-only
