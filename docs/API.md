# SHARD Enterprise SIEM — API Documentation v5.2.0

## Base URL
http://localhost:8081/api

text

## Authentication
Basic Auth: `Authorization: Basic <base64(user:pass)>`

Default: `admin` / `change_me_immediately`

---

## Endpoints

### GET /health
System health check with component status.

**Response:**
```json
{
  "status": "healthy",
  "version": "5.2.0",
  "timestamp": 1716812345.0,
  "modules": {
    "dashboard": true,
    "database": "sqlite_ok",
    "total_alerts": 42
  },
  "system": {
    "cpu_percent": 12.5,
    "memory_percent": 45.2,
    "disk_percent": 30.1
  }
}
GET /stats
Real-time alert statistics.

Response:

json
{
  "total_alerts": 156,
  "blocked_ips": 23,
  "active_threats": 7,
  "top_attackers": {
    "45.155.205.233": 34,
    "185.142.53.101": 28
  },
  "top_targets": {
    "192.168.1.10": 56
  },
  "attack_types": {
    "Brute Force": 45,
    "Port Scan": 38,
    "Web Attack": 29
  },
  "recent_alerts": [...]
}
GET /alerts
Recent alerts list.

Query Parameters:

Param	Type	Default	Description
limit	int	50	Max alerts to return (1-1000)
Response:

json
[
  {
    "timestamp": 1716812345.0,
    "src_ip": "45.155.205.233",
    "dst_ip": "192.168.1.10",
    "dst_port": 22,
    "attack_type": "Brute Force",
    "score": 0.92,
    "severity": "HIGH",
    "explanation": "Multiple failed SSH attempts detected"
  }
]
POST /block
Block an IP address. Requires admin role.

Request:

json
{
  "ip": "45.155.205.233"
}
Response:

json
{
  "status": "ok",
  "ip": "45.155.205.233",
  "duration": 3600
}
Errors:

Status	Description
401	Unauthorized
403	Insufficient permissions
400	Invalid IP address
429	Rate limit exceeded
Rate Limiting
10 requests per second per IP

429 Too Many Requests when exceeded

Roles
Role	Read	Write	Block
admin	✅	✅	✅
analyst	✅	✅	❌
viewer	✅	❌	❌
EOF			
echo "✅ docs/API.md создан"

Создаём OpenAPI спецификацию
cat > docs/openapi.yaml << 'EOF'
openapi: 3.0.3
info:
title: SHARD Enterprise SIEM API
version: 5.2.0
description: Autonomous AI-driven SIEM platform API
servers:

url: http://localhost:8081/api
description: Local development server

security:

basicAuth: []

paths:
/health:
get:
summary: System health check
responses:
'200':
description: System status
content:
application/json:
schema:
type: object
properties:
status:
type: string
example: healthy
version:
type: string
example: "5.2.0"
modules:
type: object

/stats:
get:
summary: Alert statistics
responses:
'200':
description: Real-time statistics
content:
application/json:
schema:
type: object
properties:
total_alerts:
type: integer
blocked_ips:
type: integer
active_threats:
type: integer

/alerts:
get:
summary: Recent alerts
parameters:

name: limit
in: query
schema:
type: integer
default: 50
responses:
'200':
description: List of alerts

/block:
post:
summary: Block IP address
requestBody:
required: true
content:
application/json:
schema:
type: object
required:

ip
properties:
ip:
type: string
format: ipv4
responses:
'200':
description: IP blocked
'403':
description: Insufficient permissions

components:
securitySchemes:
basicAuth:
type: http
scheme: basic
