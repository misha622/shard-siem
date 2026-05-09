-- Инициализация базы данных SHARD
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(50),
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10),
    severity VARCHAR(20),
    confidence REAL,
    raw_data JSONB
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alert_type VARCHAR(50),
    attack_type VARCHAR(50),
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    severity VARCHAR(20),
    confidence REAL,
    model_prediction VARCHAR(50),
    model_confidence REAL,
    threat_level VARCHAR(20),
    description TEXT,
    raw_data JSONB
);

CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    indicator VARCHAR(255) UNIQUE NOT NULL,
    indicator_type VARCHAR(20),
    threat_type VARCHAR(50),
    confidence REAL,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(100),
    tags TEXT[]
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reason TEXT,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    blocked_by VARCHAR(50)
);

-- Индексы для производительности
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type);
CREATE INDEX IF NOT EXISTS idx_iocs_indicator ON iocs(indicator);

-- Вывод
SELECT 'SHARD Database initialized!' as status;