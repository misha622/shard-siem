# Changelog

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
