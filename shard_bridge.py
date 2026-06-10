#!/usr/bin/env python3
"""
SHARD Bridge — синхронизация SHARD Engine ↔ WebUI
Запускается как фоновый поток в SHARD Engine.
Пишет алерты в общую БД и статистику DecisionFusion в JSON.
"""

import sys
import os
import json
import time
import sqlite3
import threading
from pathlib import Path
from datetime import datetime

class ShardBridge:
    """Мост между SHARD Engine и WebUI"""
    
    def __init__(self, db_path: str = None):
        # БД WebUI
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__),
                'shard-webui', 'backend', 'shard_siem.db'
            )
        self.db_path = db_path
        
        # JSON для Defence статистики
        self.stats_path = os.path.join(
            os.path.dirname(__file__), 'data', 'defense_stats.json'
        )
        
        self._lock = threading.Lock()
        self._running = False
        self.engine = None  # Будет установлен при подключении
        
        # Создаём таблицы если нужно
        self._ensure_tables()
    
    def _ensure_tables(self):
        """Создаёт таблицы WebUI если их нет"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS companies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    ip_ranges TEXT,
                    max_alerts_per_day INTEGER DEFAULT 50000,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER DEFAULT 0,
                    attack_type TEXT DEFAULT 'Unknown',
                    score REAL DEFAULT 0.0,
                    confidence REAL DEFAULT 0.0,
                    severity TEXT DEFAULT 'MEDIUM',
                    explanation TEXT DEFAULT '',
                    is_blocked BOOLEAN DEFAULT 0,
                    blocked_at TIMESTAMP,
                    company_id INTEGER,
                    source_lat REAL,
                    source_lon REAL,
                    features_json TEXT,
                    kill_chain_stage TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    reason TEXT,
                    blocked_by TEXT,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_permanent BOOLEAN DEFAULT 0
                )
            ''')
            # Убедимся что компания есть
            conn.execute('''
                INSERT OR IGNORE INTO companies (id, name, ip_ranges)
                VALUES (1, 'Headquarters', '["192.168.1.0/24","10.0.0.0/16"]')
            ''')
            conn.commit()
            conn.close()
            print("✅ Bridge: Database tables ready")
        except Exception as e:
            print(f"⚠️ Bridge DB error: {e}")
    
    def connect(self, shard_engine):
        """Подключиться к SHARD Engine"""
        self.engine = shard_engine
        self._running = True
        
        # Подписываемся на алерты
        if hasattr(shard_engine, 'event_bus'):
            shard_engine.event_bus.subscribe('alert.detected', self.on_alert)
            print("✅ Bridge: Subscribed to alert.detected")
        
        # Запускаем поток экспорта статистики
        threading.Thread(target=self._stats_loop, daemon=True).start()
        print("✅ Bridge: Stats export loop started")
    
    def on_alert(self, alert: dict):
        """Сохраняет алерт в общую БД"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                INSERT INTO alerts (timestamp, src_ip, dst_ip, dst_port,
                    attack_type, score, confidence, severity, explanation, company_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.get('timestamp', time.time()),
                alert.get('src_ip', 'unknown'),
                alert.get('dst_ip', 'unknown'),
                alert.get('dst_port', 0),
                alert.get('attack_type', 'Unknown'),
                alert.get('score', 0.0),
                alert.get('confidence', 0.0),
                alert.get('severity', 'MEDIUM'),
                alert.get('explanation', ''),
                1  # Headquarters
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"⚠️ Bridge alert error: {e}")
    
    def _stats_loop(self):
        """Периодически экспортирует статистику DecisionFusion в JSON"""
        while self._running:
            time.sleep(5)
            try:
                if self.engine and hasattr(self.engine, 'decision_fusion'):
                    fusion = self.engine.decision_fusion
                    data = {
                        'stats': fusion.get_stats(),
                        'active': fusion.get_active_defenses(),
                        'timestamp': time.time()
                    }
                    os.makedirs(os.path.dirname(self.stats_path), exist_ok=True)
                    with open(self.stats_path, 'w') as f:
                        json.dump(data, f, default=str)
            except Exception as e:
                pass  # Тихо игнорируем ошибки
    
    def stop(self):
        self._running = False


# Глобальный экземпляр
bridge = ShardBridge()
