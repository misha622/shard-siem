# SHARD Enterprise SIEM — Changelog

## v5.1.0 (2026-05-16)
### Added
- ModuleLoader with topological dependency sorting
- PostgreSQL/TimescaleDB support with connection pooling
- Graceful degradation: PG → SQLite → JSON file
- Health check endpoint (GET /api/health)
- RBAC for Dashboard API (admin/analyst/viewer)
- Per-IP rate limiting on honeypots
- Welford online algorithm for O(1) variance
- 4 integration tests

### Changed
- Unified IP validation (single strict function)
- XGBoost training with balanced batches (attacks + normal)
- Single EventBus instance across all modules
- API keys in .env (not config.yaml)

### Fixed
- Cyclic imports (SelfSupervisedEncoder, ThreatGNN)
- Debug prints replaced with proper logging
- F.mse_loss import in get_anomaly_score
- RL DQN state_size (32→156)

## v5.0.0 (2026-05-09)
- Initial release with 10 neural networks
- 22 security modules
- Docker support
