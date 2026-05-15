#!/usr/bin/env python3
"""SHARD SIEMStorage Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import os, time, threading, queue, json, sqlite3, re
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from pathlib import Path

class SIEMStorage(BaseModule):
    """Хранилище SIEM (исправлено - WAL checkpoint, пул соединений, ограничения)"""

    def __init__(self, config, event_bus, logger):
        super().__init__("SIEM", config, event_bus, logger)
        self.sqlite_path = config.get('storage.sqlite.path', 'shard_siem.db')
        self.timescale_enabled = config.get('storage.timescaledb.enabled', False)
        self.es_enabled = config.get('storage.elasticsearch.enabled', False)
        self.es_client = None
        self.pg_pool = None
        self.pg_conn = None
        # Буферы для пакетной записи
        self.es_buffer: List[Dict] = []
        self.pg_buffer: List[Dict] = []
        self.buffer_lock = threading.RLock()
        self.batch_size = 100
        self.flush_interval = 5

        # Пул соединений SQLite
        self._sqlite_pool = queue.Queue(maxsize=10)
        self._sqlite_pool_lock = threading.RLock()
        self._active_connections = set()

        # Буфер для пакетной записи алертов
        self._alert_buffer: List[Dict] = []
        self._alert_buffer_lock = threading.RLock()
        self._alert_batch_size = 100
        self._alert_flush_interval = 5

        # WAL checkpoint
        self._last_checkpoint = time.time()
        self._checkpoint_interval = 3600  # 1 час
        self._wal_size_threshold = 10 * 1024 * 1024  # 10 MB

        # Ограничение размера JSON
        self._max_features_json_size = 10240  # 10KB
        self._max_explanation_length = 500
        self._flush_in_progress = False
        self._flush_lock = threading.RLock()

        # Инициализация хранилищ
        self._init_sqlite()
        self._init_timescale()
        self._init_elasticsearch()

        # Подписки на события
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('packet.processed', self.on_packet)
        self.event_bus.subscribe('siem.query.request', self.on_query_request)
        self.event_bus.subscribe('siem.ips.request', self.on_ips_request)


    def _init_sqlite(self) -> None:
        """Инициализация пула соединений SQLite с партициями по датам"""
        try:
            db_dir = Path(self.sqlite_path).parent
            if db_dir and str(db_dir) != '' and not db_dir.exists():
                db_dir.mkdir(parents=True, exist_ok=True)

            # Создаём пул соединений
            for _ in range(5):
                conn = sqlite3.connect(self.sqlite_path, check_same_thread=False, timeout=10)
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute('PRAGMA synchronous=NORMAL')
                conn.execute('PRAGMA cache_size=10000')
                conn.execute('PRAGMA temp_store=MEMORY')
                conn.execute('PRAGMA busy_timeout=5000')

                # ============================================================
                # ИСПРАВЛЕНИЕ: Таблица с партициями по датам
                # ============================================================
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        date TEXT GENERATED ALWAYS AS (date(timestamp, 'unixepoch')) STORED,
                        src_ip TEXT,
                        dst_ip TEXT,
                        dst_port INTEGER,
                        attack_type TEXT,
                        score REAL,
                        confidence REAL,
                        severity TEXT,
                        explanation TEXT,
                        kill_chain_stage TEXT,
                        features_json TEXT
                    )
                ''')

                # Индексы для быстрых запросов
                conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_date ON alerts(date)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')

                # Автоматическая ротация: удаление алертов старше 30 дней
                conn.execute('''
                    CREATE TRIGGER IF NOT EXISTS cleanup_old_alerts
                    AFTER INSERT ON alerts
                    BEGIN
                        DELETE FROM alerts 
                        WHERE date < date('now', '-30 days')
                        AND id IN (
                            SELECT id FROM alerts 
                            WHERE date < date('now', '-30 days') 
                            LIMIT 1000
                        );
                    END;
                ''')

                conn.commit()
                self._sqlite_pool.put(conn)

            self.logger.info(f"Пул SQLite инициализирован: 5 соединений (с партициями по датам)")

        except Exception as e:
            self.logger.error(f"Ошибка инициализации SQLite: {e}")
            self.sqlite_path = ':memory:'

    def _get_sqlite_connection(self) -> sqlite3.Connection:
        """Получить соединение из пула"""
        try:
            conn = self._sqlite_pool.get(timeout=1)
            self._active_connections.add(conn)
            return conn
        except queue.Empty:
            conn = sqlite3.connect(self.sqlite_path, check_same_thread=False, timeout=10)
            conn.execute('PRAGMA journal_mode=WAL')
            self._active_connections.add(conn)
            return conn

    def _return_sqlite_connection(self, conn: sqlite3.Connection) -> None:
        """Вернуть соединение в пул"""
        try:
            if conn:
                self._active_connections.discard(conn)
                self._sqlite_pool.put_nowait(conn)
        except queue.Full:
            conn.close()

    def _init_timescale(self) -> None:
        """Инициализация TimescaleDB"""
        if not self.timescale_enabled:
            return
        try:
            import psycopg2
            from psycopg2 import pool
        except ImportError:
            self.logger.warning("psycopg2 не установлен")
            self.timescale_enabled = False

    def _init_elasticsearch(self) -> None:
        """Инициализация Elasticsearch"""
        if not self.es_enabled:
            return
        try:
            from elasticsearch import Elasticsearch
        except ImportError:
            self.logger.warning("elasticsearch не установлен")
            self.es_enabled = False

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._stats_loop, daemon=True).start()
        threading.Thread(target=self._flush_loop, daemon=True).start()
        threading.Thread(target=self._checkpoint_loop, daemon=True).start()  # ← WAL checkpoint
        self.logger.info(f"SIEM запущен (SQLite: {self.sqlite_path})")

    def stop(self) -> None:
        """Остановка с принудительным закрытием соединений"""
        self.running = False
        self._flush_alerts()

        # Закрываем все соединения в пуле
        closed = 0
        while not self._sqlite_pool.empty():
            try:
                conn = self._sqlite_pool.get_nowait()
                conn.close()
                closed += 1
            except:
                pass

        # Принудительно закрываем активные соединения
        for conn in list(self._active_connections):
            try:
                conn.close()
                closed += 1
            except:
                pass

        self._active_connections.clear()
        self.logger.debug(f"Закрыто {closed} соединений SQLite")

        if self.pg_pool:
            self.pg_pool.closeall()

    def _flush_loop(self) -> None:
        """Периодический сброс буфера алертов"""
        while self.running:
            time.sleep(self._alert_flush_interval)
            self._flush_alerts()

    def _checkpoint_loop(self) -> None:
        """Периодический checkpoint WAL файла"""
        while self.running:
            time.sleep(300)  # Каждые 5 минут

            try:
                wal_path = Path(f"{self.sqlite_path}-wal")
                if wal_path.exists():
                    wal_size = wal_path.stat().st_size
                    if wal_size > self._wal_size_threshold or time.time() - self._last_checkpoint > self._checkpoint_interval:
                        conn = self._get_sqlite_connection()
                        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                        self._return_sqlite_connection(conn)
                        self._last_checkpoint = time.time()
                        self.logger.debug(f"WAL checkpoint выполнен, размер был {wal_size // 1024}KB")
            except Exception as e:
                self.logger.debug(f"Ошибка checkpoint: {e}")

    def _flush_and_reset(self):
        try:
            self._flush_alerts()
        finally:
            with self._flush_lock:
                self._flush_in_progress = False

    
    def _flush_alerts(self) -> None:
        """Пакетная запись алертов в БД (с ограничением размера)"""
        if not self._alert_buffer:
            return

        alerts_to_write = []
        with self._alert_buffer_lock:
            alerts_to_write = self._alert_buffer[:]
            self._alert_buffer.clear()

        if not alerts_to_write:
            return

        conn = None
        try:
            conn = self._get_sqlite_connection()
            cursor = conn.cursor()

            data = []
            for alert in alerts_to_write:
                # Ограничиваем features_json
                features = alert.get('features', {})
                features_json = None
                if features:
                    try:
                        features_json = json.dumps(features)
                        if len(features_json) > self._max_features_json_size:
                            truncated = {
                                'packet_size': features.get('packet_size', 0),
                                'protocol': features.get('protocol', 0),
                                'dst_port': features.get('dst_port', 0),
                                'entropy': features.get('entropy', 0)
                            }
                            features_json = json.dumps(truncated)
                    except:
                        features_json = None

                # Ограничиваем explanation
                explanation = alert.get('explanation', '')
                if len(explanation) > self._max_explanation_length:
                    explanation = explanation[:self._max_explanation_length - 3] + '...'

                data.append((
                    alert.get('timestamp', time.time()),
                    str(alert.get('src_ip', ''))[:45],
                    str(alert.get('dst_ip', ''))[:45],
                    alert.get('dst_port', 0),
                    str(alert.get('attack_type', 'Unknown'))[:50],
                    alert.get('score', 0.0),
                    alert.get('confidence', 0.0),
                    alert.get('severity', 'LOW')[:20],
                    explanation,
                    alert.get('kill_chain', {}).get('stage', '')[:50],
                    features_json
                ))

            cursor.executemany('''
                INSERT INTO alerts 
                (timestamp, src_ip, dst_ip, dst_port, attack_type, score, confidence, severity, explanation, kill_chain_stage, features_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', data)

            conn.commit()
            self.logger.debug(f"Записано {len(data)} алертов в БД")

        except Exception as e:
            self.logger.error(f"SQLite ошибка сохранения: {e}")
        finally:
            if conn:
                self._return_sqlite_connection(conn)

    def on_alert(self, alert: Dict) -> None:
        """Сохранение алерта (буферизованная версия)"""
        with self._alert_buffer_lock:
            alert_copy = alert.copy()

            # Ограничиваем features перед буферизацией
            features = alert_copy.get('features', {})
            if features:
                try:
                    features_json = json.dumps(features)
                    if len(features_json) > self._max_features_json_size:
                        truncated = {
                            'packet_size': features.get('packet_size', 0),
                            'protocol': features.get('protocol', 0),
                            'dst_port': features.get('dst_port', 0),
                            'entropy': features.get('entropy', 0)
                        }
                        alert_copy['features'] = truncated
                except:
                    alert_copy['features'] = {}

            self._alert_buffer.append(alert_copy)

            should_flush = len(self._alert_buffer) >= self._alert_batch_size
        
        if should_flush:
            with self._flush_lock:
                if not self._flush_in_progress:
                    self._flush_in_progress = True
                    threading.Thread(target=self._flush_and_reset, daemon=True).start()

    def on_packet(self, data: Dict) -> None:
        pass

    def on_query_request(self, data: Dict) -> None:
        """Обработка запроса алертов"""
        request_id = data.get('request_id')
        src_ip = data.get('src_ip')
        time_range = data.get('time_range', 1800)
        limit = min(data.get('limit', 50), 1000)

        try:
            conn = self._get_sqlite_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cutoff = time.time() - time_range
            cursor.execute(
                '''SELECT * FROM alerts 
                   WHERE src_ip = ? AND timestamp > ? 
                   ORDER BY timestamp DESC LIMIT ?''',
                (src_ip, cutoff, limit)
            )

            alerts = [dict(row) for row in cursor.fetchall()]

            self.event_bus.publish('siem.query.response', {
                'request_id': request_id,
                'alerts': alerts
            })
        except Exception as e:
            self.logger.error(f"Ошибка запроса алертов: {e}")
            self.event_bus.publish('siem.query.response', {
                'request_id': request_id,
                'alerts': []
            })
        finally:
            if conn:
                self._return_sqlite_connection(conn)

    def on_ips_request(self, data: Dict) -> None:
        """Обработка запроса IP для пользователя"""
        request_id = data.get('request_id')
        username = data.get('username')
        hours = data.get('hours', 24)

        ips = []
        try:
            conn = self._get_sqlite_connection()
            cursor = conn.cursor()

            cutoff = time.time() - (hours * 3600)
            cursor.execute(
                '''SELECT DISTINCT src_ip FROM alerts 
                   WHERE explanation LIKE ? AND timestamp > ? 
                   LIMIT 100''',
                (f'%{username}%', cutoff)
            )

            ips = [row[0] for row in cursor.fetchall() if row[0]]
        except Exception as e:
            self.logger.debug(f"Ошибка запроса IP: {e}")
        finally:
            if conn:
                self._return_sqlite_connection(conn)

        self.event_bus.publish('siem.ips.response', {
            'request_id': request_id,
            'ips': ips
        })

    def _stats_loop(self) -> None:
        while self.running:
            time.sleep(300)

    def query_alerts(self, src_ip: str = None, attack_type: str = None, limit: int = 100) -> List[Dict]:
        """Запрос алертов с валидацией"""
        if not isinstance(limit, int) or limit < 1:
            limit = 100
        limit = min(limit, 1000)

        if src_ip and not re.match(r'^[\d\.:a-fA-F]+$', str(src_ip)):
            return []

        conn = None
        try:
            conn = self._get_sqlite_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT * FROM alerts WHERE 1=1"
            params = []

            if src_ip:
                query += " AND src_ip = ?"
                params.append(src_ip)
            if attack_type:
                query += " AND attack_type = ?"
                params.append(attack_type)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Ошибка запроса: {e}")
            return []
        finally:
            if conn:
                self._return_sqlite_connection(conn)

    def get_stats(self, hours: int = 24) -> Dict:
        conn = None
        try:
            conn = self._get_sqlite_connection()
            cursor = conn.cursor()
            cutoff = time.time() - (hours * 3600)
            cursor.execute(
                'SELECT COUNT(*), AVG(score), COUNT(DISTINCT src_ip), MAX(score) FROM alerts WHERE timestamp > ?',
                (cutoff,))
            row = cursor.fetchone()
            return {
                'period_hours': hours,
                'total_alerts': row[0] if row else 0,
                'avg_score': round(row[1], 3) if row and row[1] else 0.0,
                'unique_sources': row[2] if row else 0,
                'max_score': round(row[3], 3) if row and row[3] else 0.0
            }
        except Exception as e:
            return {'error': str(e), 'total_alerts': 0}
        finally:
            if conn:
                self._return_sqlite_connection(conn)


# ============================================================
# ГЛАВНЫЙ КЛАСС SHARD ENTERPRISE
# ============================================================

