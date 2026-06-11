# Changelog

## v5.8.0 (2026-06-10)

### 🚀 New Features
- **DecisionFusion**: 4-level autonomous response orchestrator (Rule-Based → RL Agent → Heuristic → Firewall)
- **Telegram Bot v2.0**: 10 commands (/start /help /status /stats /top5 /block /unblock /mute /unmute /report), 5 inline buttons (Block IP, Details, False Positive, Dashboard, Unblock), anti-spam grouping, mute mode, daily auto-report at 9:00 AM
- **GPU Acceleration**: CUDA 13 support, RTX 4050 (6.4 GB VRAM), 10-20x inference speedup
- **AppFirewall**: 3-level IP blocking without root (Memory → hosts.deny → iptables), whitelist, state persistence, audit log
- **Defense API**: 8 REST endpoints + WebSocket real-time updates for autonomous defense management
- **Defense WebUI**: Dedicated `/defense.html` page with live stats, manual block/unblock, attack simulation
- **SHARD Bridge**: Real-time sync between SHARD Engine and WebUI via shared SQLite database

### 🔧 Improvements
- **Repository cleanup**: 59 legacy files moved to `archive/`, removed duplicates, cleaned root directory
- **Security**: Telegram bot token revoked, `.env.telegram` added to `.gitignore`, `.env.telegram.example` created
- **Navigation**: Defense tab added to all WebUI pages (Dashboard, Alerts, Blocked IPs, Map, Settings, Profile)
- **WebSocket**: ConnectionManager with auto-cleanup, fallback to polling on disconnect
- **Lazy imports**: Defense API first request loads ML modules, subsequent requests served from cache (100x faster)
- **SQLite schema**: Fixed compatibility between SHARD Engine and WebUI database schemas
- **AgenticAI**: Fixed EventBus subscription memory leak

### 📊 Stats
- **New code**: ~3,000 lines
- **New files**: 10+
- **Modified files**: 12
- **Moved/removed**: 59 files
- **API endpoints**: 8 new
- **Bot commands**: 10
- **Defense levels**: 4


## v5.2.6 (2026-06-05)
- Removed hardcoded password from core/config.yaml
- Added .env.example with placeholders
- Updated .gitignore to exclude .env
- Added SECURITY.md with pre-deployment checklist
- Deprecated shard_enterprise_complete.py (monolith)

## v5.2.5
- Removed .env from repository
- Closed open registration (is_active=False by default)
- Added SlowAPIMiddleware
- Fixed logout (refresh_token from request body)
- Export limit: 50000 records
- Fixed EventBus.connect()
- Tests use password from .env

## v5.2.4
- Fixed require_role: min_level = float('inf')
- Fixed logout: Request import
- Rate limiter: per-IP instead of global

## v5.2.3
- Fixed Alert.company_id: @property → real column
- Fixed require_role: max() → min()
- Fixed top_attackers/top_targets: added company_id filter
- Added rate limiter on alerts
- CORS reads from settings.ALLOWED_ORIGINS
- Logout revokes refresh token
- WebUI User=shard in systemd

## v5.2.2
- Fixed @abstractmethod with body
- Removed duplicate import hashlib
- Fixed backup.sh: quotes for $BACKUP_DIR
- Fixed comment in SQLiteStorage
- Added LoggingService.debug/error methods

## v5.2.1
- Removed hardcoded passwords (viewer123, branch123)
- Fixed install.sh: removed developer path
- Deleted .bak files from repository
- Changed User=root to User=shard in systemd

## v5.2.0
- Initial production release
- 17 bugs fixed (C1-C5, M1-M6, L1-L3)
- WebUI integrated with SHARD Engine
- Systemd services
- Traffic capture via setcap
- One-click installer
- Client agent
