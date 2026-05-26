#!/usr/bin/env python3
"""SHARD SIEMStorage Module - Исправленная версия с разделением ответственности"""
import os
import time
import threading
import queue
import json
import sqlite3
import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Generator
from collections import defaultdict, deque
from pathlib import Path
from contextlib import contextmanager
from abc import ABC, abstractmethod

from core.base import BaseModule, ConfigManager, EventBus, LoggingService


class StorageBackend(ABC):
    """Абстрактный класс для всех бэкендов хранилища"""

    @abstractmethod
    def initialize(self) -> bool:
        """Инициализация хранилища"""
        pass

    @abstractmethod
    def store_alerts(self, alerts: List[Dict]) -> bool:
        """Сохранение пакета алертов"""
        pass

    @abstractmethod
    def query_alerts(self, src_ip: str = None, attack_type: str = None,
                     time_range: int = None, limit: int = 100) -> List[Dict]:
        """Запрос алертов"""
        pass

    @abstractmethod
    def get_stats(self, hours: int = 24) -> Dict:
        """Получение статистики"""
        pass

    @abstractmethod
    def query_ips_by_user(self, username: str, hours: int = 24) -> List[str]:
        """Поиск IP по имени пользователя"""
        pass

    @abstractmethod
    def close(self) -> None:
        """Закрытие соединений"""
        pass


class SQLiteStorage(StorageBackend):
    """SQLite бэкенд с пулом соединений и WAL"""

    def __init__(self, db_path: str, logger):
        self.db_path = db_path
        self.logger = logger
        self._pool = queue.Queue(maxsize=10)
        self._pool_lock = threading.RLock()
        self._active_connections = set()
        self._last_checkpoint = time.time()
        self._checkpoint_interval = 3600  # 1 час
        self._wal_size_threshold = 10 * 1024 * 1024  # 10 MB
        self._checkpoint_thread = None
        self._running = False

    def initialize(self) -> bool:
        """Инициализация SQLite с пулом соединений"""
        try:
            db_dir = Path(self.db_path).parent
            if db_dir and str(db_dir) != '' and not db_dir.exists():
                db_dir.mkdir(parents=True, exist_ok=True)

            # Создаём пул соединений
            for i in range(5):
                conn = self._create_connection()
                self._init_schema(conn)
                self._pool.put(conn)

            # Запускаем поток checkpoint
            self._running = True
            self._checkpoint_thread = threading.Thread(
                target=self._checkpoint_loop,
                daemon=True
            )
            self._checkpoint_thread.start()

            self.logger.info(f"SQLite инициализирован: 5 соединений")
            return True

        except Exception as e:
            self.logger.error(f"Ошибка инициализации SQLite: {e}")
            return False

    def _create_connection(self) -> sqlite3.Connection:
        """Создание нового соединения с оптимальными настройками"""
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=10
        )
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=10000')
        conn.execute('PRAGMA temp_store=MEMORY')
        conn.execute('PRAGMA busy_timeout=5000')
        conn.execute('PRAGMA foreign_keys=ON')
        return conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        """Инициализация схемы БД"""
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
                features_json TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
        ''')

        # Индексы для оптимизации запросов
        indices = [
            'CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_alerts_date ON alerts(date)',
            'CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)',
            'CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)',
            'CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)',
            'CREATE INDEX IF NOT EXISTS idx_alerts_explanation ON alerts(explanation)'
        ]

        for index_sql in indices:
            conn.execute(index_sql)

        # Триггер автоматической очистки старых записей
        conn.execute('''
            CREATE TRIGGER IF NOT EXISTS cleanup_old_alerts
            AFTER INSERT ON alerts
            BEGIN
                DELETE FROM alerts 
                WHERE date < date('now', '-30 days')
                AND id IN (
                    SELECT id FROM alerts 
                    WHERE date < date('now', '-30 days') 
                    ORDER BY id
                    LIMIT 1000
                );
            END;
        ''')

        conn.commit()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Контекстный менеджер для безопасной работы с соединениями"""
        conn = None
        try:
            conn = self._pool.get(timeout=5)
            self._active_connections.add(conn)
            yield conn
        except queue.Empty:
            # Создаём временное соединение
            conn = self._create_connection()
            self._active_connections.add(conn)
            yield conn
        finally:
            if conn:
                self._active_connections.discard(conn)
                try:
                    self._pool.put_nowait(conn)
                except queue.Full:
                    conn.close()
                    conn = None

    def store_alerts(self, alerts: List[Dict]) -> bool:
        """Пакетная запись алертов"""
        if not alerts:
            return True

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                data = []

                for alert in alerts:
                    features = alert.get('features', {})
                    try:
                        features_json = json.dumps(features)
                        if len(features_json) > 10240:  # 10KB limit
                            features_json = json.dumps({
                                'packet_size': (features.get('packet_size', 0) if isinstance(features, dict) else 0),
                                'protocol': (features.get('protocol', 0) if isinstance(features, dict) else 0),
                                'truncated': True
                            })
                    except:
                        features_json = '{}'

                    data.append((
                        alert.get('timestamp', time.time()),
                        str(alert.get('src_ip', ''))[:45],
                        str(alert.get('dst_ip', ''))[:45],
                        alert.get('dst_port', 0),
                        str(alert.get('attack_type', 'Unknown'))[:50],
                        alert.get('score', 0.0),
                        alert.get('confidence', 0.0),
                        alert.get('severity', 'LOW')[:20],
                        alert.get('explanation', '')[:500],
                        alert.get('kill_chain', {}).get('stage', '')[:50],
                        features_json
                    ))

                cursor.executemany(
                    '''INSERT INTO alerts (
                        timestamp, src_ip, dst_ip, dst_port, attack_type, 
                        score, confidence, severity, explanation, 
                        kill_chain_stage, features_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    data
                )
                conn.commit()
                self.logger.debug(f"SQLite: записано {len(data)} алертов")
                return True

        except Exception as e:
            self.logger.error(f"Ошибка записи в SQLite: {e}")
            return False

    def query_alerts(self, src_ip: str = None, attack_type: str = None,
                     time_range: int = None, limit: int = 100) -> List[Dict]:
        """Запрос алертов с валидацией параметров"""
        if not self._validate_limit(limit):
            limit = 100

        if src_ip and not self._validate_ip(src_ip):
            return []

        try:
            with self._get_connection() as conn:
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

                if time_range:
                    cutoff = time.time() - time_range
                    query += " AND timestamp > ?"
                    params.append(cutoff)

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Ошибка запроса алертов: {e}")
            return []

    def get_stats(self, hours: int = 24) -> Dict:
        """Получение статистики за период"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cutoff = time.time() - (hours * 3600)

                cursor.execute(
                    '''SELECT COUNT(*), AVG(score), COUNT(DISTINCT src_ip), 
                       MAX(score), MIN(timestamp), MAX(timestamp)
                       FROM alerts WHERE timestamp > ?''',
                    (cutoff,)
                )
                row = cursor.fetchone()

                return {
                    'period_hours': hours,
                    'total_alerts': row[0] if row else 0,
                    'avg_score': round(row[1], 3) if row and row[1] else 0.0,
                    'unique_sources': row[2] if row else 0,
                    'max_score': round(row[3], 3) if row and row[3] else 0.0,
                    'first_alert': row[4] if row and row[4] else None,
                    'last_alert': row[5] if row and row[5] else None
                }

        except Exception as e:
            self.logger.error(f"Ошибка получения статистики: {e}")
            return {'error': str(e), 'total_alerts': 0}

    def query_ips_by_user(self, username: str, hours: int = 24) -> List[str]:
        """Поиск IP-адресов по имени пользователя"""
        if not username:
            return []

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cutoff = time.time() - (hours * 3600)

                # Экранирование специальных символов LIKE
                escaped_username = (
                    username.replace('\\', '\\\\')
                    .replace('%', '\\%')
                    .replace('_', '\\_')
                )

                cursor.execute(
                    '''SELECT DISTINCT src_ip 
                       FROM alerts 
                       WHERE explanation LIKE ? ESCAPE '\\' 
                       AND timestamp > ? 
                       LIMIT 100''',
                    (f'%{escaped_username}%', cutoff)
                )

                return [row[0] for row in cursor.fetchall() if row[0]]

        except Exception as e:
            self.logger.error(f"Ошибка поиска IP: {e}")
            return []

    def _checkpoint_loop(self) -> None:
        """Цикл периодического checkpoint WAL"""
        while self._running:
            time.sleep(300)  # Каждые 5 минут

            try:
                wal_path = Path(f"{self.db_path}-wal")
                if wal_path.exists():
                    wal_size = wal_path.stat().st_size
                    current_time = time.time()

                    if (wal_size > self._wal_size_threshold or
                            current_time - self._last_checkpoint > self._checkpoint_interval):
                        with self._get_connection() as conn:
                            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

                        self._last_checkpoint = current_time
                        self.logger.debug(
                            f"WAL checkpoint выполнен (размер: {wal_size // 1024}KB)"
                        )

            except Exception as e:
                self.logger.debug(f"Ошибка checkpoint: {e}")

    def close(self) -> None:
        """Закрытие всех соединений"""
        self._running = False

        closed_count = 0
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
                closed_count += 1
            except:
                pass

        for conn in list(self._active_connections):
            try:
                conn.close()
                closed_count += 1
            except:
                pass

        self._active_connections.clear()
        self.logger.debug(f"SQLite: закрыто {closed_count} соединений")

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Валидация IP-адреса"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def _validate_limit(limit: int) -> bool:
        """Валидация лимита записей"""
        return isinstance(limit, int) and 0 < limit <= 1000


class TimescaleStorage(StorageBackend):
    """TimescaleDB/PostgreSQL бэкенд с пулом соединений"""

    def __init__(self, config: ConfigManager, logger):
        self.config = config
        self.logger = logger
        self.pool = None
        self._pool_lock = threading.RLock()

    def initialize(self) -> bool:
        """Инициализация PostgreSQL с пулом соединений"""
        try:
            import psycopg2
            from psycopg2 import pool

            dsn = self.config.get('storage.timescaledb.dsn', '')
            if not dsn:
                self.logger.warning("TimescaleDB DSN не настроен")
                return False

            min_conn = self.config.get('storage.timescaledb.pool_min', 5)
            max_conn = self.config.get('storage.timescaledb.pool_max', 20)

            self.pool = pool.ThreadedConnectionPool(min_conn, max_conn, dsn)

            # Инициализация схемы
            with self._get_connection() as conn:
                self._init_schema(conn)

            self.logger.info("TimescaleDB инициализирован")
            return True

        except ImportError:
            self.logger.warning("psycopg2 не установлен")
            return False
        except Exception as e:
            self.logger.error(f"Ошибка инициализации TimescaleDB: {e}")
            return False

    @contextmanager
    def _get_connection(self) -> Generator[Any, None, None]:
        """Безопасное получение соединения из пула"""
        conn = None
        try:
            conn = self.pool.getconn()
            yield conn
        finally:
            if conn:
                try:
                    conn.rollback()  # Откат незавершённых транзакций
                except:
                    pass
                self.pool.putconn(conn)

    def _init_schema(self, conn) -> None:
        """Инициализация схемы с партициями"""
        cursor = conn.cursor()

        # Создание основной таблицы
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id BIGSERIAL,
                timestamp DOUBLE PRECISION NOT NULL,
                date DATE GENERATED ALWAYS AS (to_timestamp(timestamp)::date) STORED,
                src_ip VARCHAR(45),
                dst_ip VARCHAR(45),
                dst_port INTEGER,
                attack_type VARCHAR(50),
                score REAL,
                confidence REAL,
                severity VARCHAR(20),
                explanation TEXT,
                kill_chain_stage VARCHAR(50),
                features_json JSONB
            ) PARTITION BY RANGE (date)
        """)

        # Создание индексов
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)')

        # Создание партиций на 6 месяцев вперёд
        self._create_partitions(cursor)

        conn.commit()

    def _create_partitions(self, cursor) -> None:
        """Создание партиций по месяцам"""
        today = datetime.now().replace(day=1)

        for i in range(6):
            partition_date = today + timedelta(days=32 * i)
            partition_month = partition_date.replace(day=1)
            from dateutil.relativedelta import relativedelta
            next_month = partition_month + relativedelta(months=1)

            partition_name = f"alerts_{partition_month.strftime('%Y_%m')}"

            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {partition_name}
                PARTITION OF alerts
                FOR VALUES FROM ('{partition_month.date()}') 
                TO ('{next_month.date()}')
            """)

        self.logger.debug("Партиции PostgreSQL созданы")

    def store_alerts(self, alerts: List[Dict]) -> bool:
        """Пакетная запись в PostgreSQL"""
        if not alerts:
            return True

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                data = []
                for alert in alerts:
                    features = alert.get('features', {})
                    try:
                        features_json = json.dumps(features)
                    except:
                        features_json = '{}'

                    data.append((
                        alert.get('timestamp', time.time()),
                        str(alert.get('src_ip', ''))[:45],
                        str(alert.get('dst_ip', ''))[:45],
                        alert.get('dst_port', 0),
                        str(alert.get('attack_type', 'Unknown'))[:50],
                        alert.get('score', 0.0),
                        alert.get('confidence', 0.0),
                        alert.get('severity', 'LOW')[:20],
                        alert.get('explanation', '')[:500],
                        alert.get('kill_chain', {}).get('stage', '')[:50],
                        features_json
                    ))

                cursor.executemany(
                    '''INSERT INTO alerts (
                        timestamp, src_ip, dst_ip, dst_port, attack_type,
                        score, confidence, severity, explanation,
                        kill_chain_stage, features_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                    data
                )

                conn.commit()
                self.logger.debug(f"TimescaleDB: записано {len(data)} алертов")
                return True

        except Exception as e:
            self.logger.error(f"Ошибка записи в TimescaleDB: {e}")
            return False

    def query_alerts(self, src_ip: str = None, attack_type: str = None,
                     time_range: int = None, limit: int = 100) -> List[Dict]:
        """Запрос алертов из PostgreSQL"""
        if limit < 1 or limit > 1000:
            limit = 100

        if src_ip and not self._validate_ip(src_ip):
            return []

        try:
            with self._get_connection() as conn:
                from psycopg2.extras import RealDictCursor
                cursor = conn.cursor(cursor_factory=RealDictCursor)

                query = "SELECT * FROM alerts WHERE 1=1"
                params = []

                if src_ip:
                    query += " AND src_ip = %s"
                    params.append(src_ip)

                if attack_type:
                    query += " AND attack_type = %s"
                    params.append(attack_type)

                if time_range:
                    cutoff = time.time() - time_range
                    query += " AND timestamp > %s"
                    params.append(cutoff)

                query += " ORDER BY timestamp DESC LIMIT %s"
                params.append(limit)

                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]

        except Exception as e:
            self.logger.error(f"Ошибка запроса к TimescaleDB: {e}")
            return []

    def get_stats(self, hours: int = 24) -> Dict:
        """Статистика из PostgreSQL"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cutoff = time.time() - (hours * 3600)

                cursor.execute(
                    '''SELECT COUNT(*), AVG(score), COUNT(DISTINCT src_ip),
                       MAX(score), MIN(timestamp), MAX(timestamp)
                       FROM alerts WHERE timestamp > %s''',
                    (cutoff,)
                )
                row = cursor.fetchone()

                return {
                    'period_hours': hours,
                    'total_alerts': row[0] if row else 0,
                    'avg_score': round(row[1], 3) if row and row[1] else 0.0,
                    'unique_sources': row[2] if row else 0,
                    'max_score': round(row[3], 3) if row and row[3] else 0.0,
                    'first_alert': row[4] if row and row[4] else None,
                    'last_alert': row[5] if row and row[5] else None
                }

        except Exception as e:
            self.logger.error(f"Ошибка статистики TimescaleDB: {e}")
            return {'error': str(e), 'total_alerts': 0}

    def query_ips_by_user(self, username: str, hours: int = 24) -> List[str]:
        """Поиск IP по пользователю в PostgreSQL"""
        if not username:
            return []

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cutoff = time.time() - (hours * 3600)

                escaped_username = username.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                cursor.execute(
                    '''SELECT DISTINCT src_ip 
                       FROM alerts 
                       WHERE explanation LIKE %s 
                       AND timestamp > %s 
                       LIMIT 100''',
                    (f'%{escaped_username}%', cutoff)
                )

                return [row[0] for row in cursor.fetchall() if row[0]]

        except Exception as e:
            self.logger.error(f"Ошибка поиска IP в TimescaleDB: {e}")
            return []

    def close(self) -> None:
        """Закрытие пула соединений"""
        if self.pool:
            try:
                self.pool.closeall()
                self.logger.debug("TimescaleDB: пул соединений закрыт")
            except Exception as e:
                self.logger.error(f"Ошибка закрытия пула TimescaleDB: {e}")

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Валидация IP-адреса"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


class AlertBuffer:
    """Потокобезопасный буфер для пакетной записи алертов"""

    def __init__(self, batch_size: int = 100, flush_interval: int = 5):
        self._buffer: List[Dict] = []
        self._lock = threading.RLock()
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._flush_in_progress = False
        self._flush_lock = threading.RLock()
        self._last_flush = time.time()
        self._total_buffered = 0
        self._total_flushed = 0

    def add(self, alert: Dict) -> bool:
        """Добавление алерта в буфер, возвращает True если нужен flush"""
        with self._lock:
            self._buffer.append(alert)
            self._total_buffered += 1
            buffer_size = len(self._buffer)

        return (buffer_size >= self.batch_size or
                time.time() - self._last_flush > self.flush_interval)

    def get_and_clear(self) -> List[Dict]:
        """Получить и очистить буфер"""
        with self._lock:
            alerts = self._buffer[:]
            self._buffer.clear()
            self._last_flush = time.time()
            return alerts

    def flush_if_needed(self, callback) -> None:
        """Выполнить flush если буфер не пуст и callback не выполняется"""
        with self._flush_lock:
            if not self._flush_in_progress and self._buffer:
                self._flush_in_progress = True
                try:
                    alerts = self.get_and_clear()
                    if alerts:
                        success = callback(alerts)
                        if success:
                            self._total_flushed += len(alerts)
                finally:
                    self._flush_in_progress = False
                    # Проверяем, не накопились ли новые данные
                    if len(self._buffer) >= self.batch_size:
                        self.flush_if_needed(callback)

    @property
    def stats(self) -> Dict:
        """Статистика буфера"""
        return {
            'buffer_size': len(self._buffer),
            'total_buffered': self._total_buffered,
            'total_flushed': self._total_flushed,
            'flush_in_progress': self._flush_in_progress
        }


class SIEMStorage(BaseModule):
    """Хранилище SIEM с множественными бэкендами"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("SIEM", config, event_bus, logger)

        # Конфигурация хранилищ
        self.sqlite_enabled = config.get('storage.sqlite.enabled', True)
        self.timescale_enabled = config.get('storage.timescaledb.enabled', False)

        # Инициализация бэкендов
        self.backends: List[StorageBackend] = []
        self._init_backends()

        # Буфер алертов
        self.alert_buffer = AlertBuffer(
            batch_size=config.get('storage.batch_size', 100),
            flush_interval=config.get('storage.flush_interval', 5)
        )

        # Потоки
        self._flush_thread = None
        self._stats_thread = None

        # Настройка graceful shutdown

    def _init_backends(self) -> None:
        """Инициализация бэкендов хранилища"""
        # SQLite (всегда как fallback)
        if self.sqlite_enabled:
            sqlite_path = self.config.get('storage.sqlite.path', 'shard_siem.db')
            sqlite_backend = SQLiteStorage(sqlite_path, self.logger)
            if sqlite_backend.initialize():
                self.backends.append(sqlite_backend)
                self.logger.info("SQLite бэкенд добавлен")

        # TimescaleDB
        if self.timescale_enabled:
            timescale_backend = TimescaleStorage(self.config, self.logger)
            if timescale_backend.initialize():
                self.backends.insert(0, timescale_backend)  # Приоритетный бэкенд
                self.logger.info("TimescaleDB бэкенд добавлен")

        if not self.backends:
            self.logger.critical("Не удалось инициализировать ни один бэкенд!")



    def start(self) -> None:
        """Запуск модуля"""
        self.running = True

        # Подписки на события
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('packet.processed', self.on_packet)
        self.event_bus.subscribe('siem.query.request', self.on_query_request)
        self.event_bus.subscribe('siem.ips.request', self.on_ips_request)

        # Запуск фоновых потоков
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            daemon=True,
            name="FlushLoop"
        )
        self._flush_thread.start()

        self._stats_thread = threading.Thread(
            target=self._stats_loop,
            daemon=True,
            name="StatsLoop"
        )
        self._stats_thread.start()

        self.logger.info(
            f"SIEM запущен с {len(self.backends)} бэкендами"
        )

    def stop(self) -> None:
        """Остановка модуля с гарантированным сбросом данных"""
        self.running = False

        # Сброс буфера
        self.logger.info("Сброс буфера перед остановкой...")
        self.flush_buffer()

        # Закрытие всех бэкендов
        for backend in self.backends:
            try:
                backend.close()
            except Exception as e:
                self.logger.error(f"Ошибка закрытия бэкенда: {e}")

        self.logger.info("SIEM остановлен")

    def on_alert(self, alert: Dict) -> None:
        """Обработка нового алерта"""
        # Подготовка алерта
        processed_alert = self._prepare_alert(alert)

        # Добавление в буфер
        should_flush = self.alert_buffer.add(processed_alert)

        if should_flush:
            self.flush_buffer()

    def on_packet(self, data: Dict) -> None:
        """Обработка пакета (метрики, не сохраняем)"""
        pass

    def on_query_request(self, data: Dict) -> None:
        """Обработка запроса алертов"""
        request_id = data.get('request_id')
        src_ip = data.get('src_ip')
        time_range = data.get('time_range', 1800)
        limit = min(data.get('limit', 50), 1000)

        # Пробуем запросить у первого доступного бэкенда
        alerts = []
        for backend in self.backends:
            try:
                alerts = backend.query_alerts(
                    src_ip=src_ip,
                    time_range=time_range,
                    limit=limit
                )
                if alerts is not None:
                    break  # Успешный ответ — не фолбечим
            except Exception as e:
                self.logger.warning(f"Ошибка запроса у бэкенда: {e}")

        self.event_bus.publish('siem.query.response', {
            'request_id': request_id,
            'alerts': alerts
        })

    def on_ips_request(self, data: Dict) -> None:
        """Обработка запроса IP по пользователю"""
        request_id = data.get('request_id')
        username = data.get('username')
        hours = data.get('hours', 24)

        ips = []
        for backend in self.backends:
            try:
                ips = backend.query_ips_by_user(username, hours)
                if ips:
                    break
            except Exception as e:
                self.logger.warning(f"Ошибка запроса IP: {e}")

        self.event_bus.publish('siem.ips.response', {
            'request_id': request_id,
            'ips': ips
        })

    def query_alerts(self, src_ip: str = None, attack_type: str = None,
                     limit: int = 100) -> List[Dict]:
        """Публичный метод запроса алертов"""
        alerts = []
        for backend in self.backends:
            try:
                alerts = backend.query_alerts(
                    src_ip=src_ip,
                    attack_type=attack_type,
                    limit=limit
                )
                if alerts is not None:
                    break  # Успешный ответ — не фолбечим
            except Exception as e:
                self.logger.warning(f"Ошибка запроса: {e}")

        return alerts

    def get_stats(self, hours: int = 24) -> Dict:
        """Получение статистики"""
        stats = {}

        for i, backend in enumerate(self.backends):
            backend_name = backend.__class__.__name__
            try:
                stats[f"backend_{i}_{backend_name}"] = backend.get_stats(hours)
            except Exception as e:
                stats[f"backend_{i}_{backend_name}"] = {'error': str(e)}

        # Добавляем статистику буфера
        stats['buffer'] = self.alert_buffer.stats

        return stats

    def flush_buffer(self) -> None:
        """Принудительный сброс буфера во все бэкенды"""
        self.alert_buffer.flush_if_needed(self._store_alerts)

    def _store_alerts(self, alerts: List[Dict]) -> bool:
        """Сохранение алертов с fallback по цепочке бэкендов"""
        stored = False

        for backend in self.backends:
            try:
                if backend.store_alerts(alerts):
                    stored = True
                    break
            except Exception as e:
                self.logger.warning(f"Ошибка сохранения в {backend.__class__.__name__}: {e}")

        # Last resort - файл
        if not stored:
            stored = self._save_to_file(alerts)

        return stored

    def _save_to_file(self, alerts: List[Dict]) -> bool:
        """Сохранение в JSON-файл как последний fallback"""
        try:
            backup_path = Path('data/alerts_backup.json')
            backup_path.parent.mkdir(parents=True, exist_ok=True)

            existing = []
            if backup_path.exists():
                try:
                    with open(backup_path, 'r') as f:
                        existing = json.load(f)
                except:
                    existing = []

            existing.extend(alerts)

            # Ограничиваем размер файла
            if len(existing) > 10000:
                existing = existing[-5000:]

            with open(backup_path, 'w') as f:
                json.dump(existing, f, indent=2)

            self.logger.warning(
                f"CRITICAL: {len(alerts)} алертов сохранены в {backup_path}"
            )
            return True

        except Exception as e:
            self.logger.critical(f"Все хранилища недоступны: {e}")
            return False

    def _prepare_alert(self, alert: Dict) -> Dict:
        """Подготовка алерта с ограничением размера полей"""
        processed = alert.copy()

        # Ограничение features_json
        features = processed.get('features', {})
        if features:
            try:
                features_json = json.dumps(features)
                if len(features_json) > 10240:  # 10KB
                    # Сохраняем только ключевые поля
                    truncated = {
                        'packet_size': (features.get('packet_size', 0) if isinstance(features, dict) else 0),
                        'protocol': (features.get('protocol', 0) if isinstance(features, dict) else 0),
                        'dst_port': features.get('dst_port', 0),
                        'entropy': features.get('entropy', 0),
                        'truncated': True
                    }
                    processed['features'] = truncated
            except:
                processed['features'] = {}

        # Ограничение строковых полей
        processed['explanation'] = str(processed.get('explanation', ''))[:500]
        processed['attack_type'] = str(processed.get('attack_type', 'Unknown'))[:50]
        processed['severity'] = str(processed.get('severity', 'LOW'))[:20]

        return processed

    def _flush_loop(self) -> None:
        """Цикл периодического сброса буфера"""
        while self.running:
            time.sleep(self.alert_buffer.flush_interval)
            self.flush_buffer()

    def _stats_loop(self) -> None:
        """Цикл сбора и публикации статистики"""
        while self.running:
            time.sleep(300)  # Каждые 5 минут

            try:
                stats = self.get_stats(hours=1)  # Статистика за час
                self.event_bus.publish('siem.stats', stats)
                self.logger.debug(f"Статистика: {stats}")
            except Exception as e:
                self.logger.error(f"Ошибка сбора статистики: {e}")


# ============================================================
# Точка входа для тестирования
# ============================================================
if __name__ == "__main__":
    # Тестовый запуск
    class MockConfig:
        def get(self, key, default=None):
            config = {
                'storage.sqlite.enabled': True,
                'storage.sqlite.path': 'test_shard.db',
                'storage.timescaledb.enabled': False,
                'storage.batch_size': 100,
                'storage.flush_interval': 5
            }
            return config.get(key, default)


    class MockEventBus:
        def subscribe(self, event, handler):
            pass

        def publish(self, event, data):
            print(f"Event: {event}, Data: {data}")


    class MockLogger:
        def info(self, msg): print(f"INFO: {msg}")

        def error(self, msg): print(f"ERROR: {msg}")

        def warning(self, msg): print(f"WARN: {msg}")

        def debug(self, msg): print(f"DEBUG: {msg}")

        def critical(self, msg): print(f"CRITICAL: {msg}")


    config = MockConfig()
    event_bus = MockEventBus()
    logger = MockLogger()

    storage = SIEMStorage(config, event_bus, logger)

    # Тестовые данные
    storage.start()

    test_alert = {
        'timestamp': time.time(),
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'dst_port': 443,
        'attack_type': 'SQL_INJECTION',
        'score': 0.95,
        'confidence': 0.8,
        'severity': 'HIGH',
        'explanation': 'Possible SQL injection detected',
        'kill_chain': {'stage': 'exploitation'},
        'features': {
            'packet_size': 1500,
            'protocol': 6,
            'entropy': 4.5
        }
    }

    # Тестирование
    storage.on_alert(test_alert)
    time.sleep(1)

    alerts = storage.query_alerts(src_ip='192.168.1.100')
    print(f"Найдено алертов: {len(alerts)}")

    stats = storage.get_stats(hours=24)
    print(f"Статистика: {stats}")

    storage.stop()