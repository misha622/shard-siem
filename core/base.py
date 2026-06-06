#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SHARD Core — ConfigManager, EventBus, LoggingService, BaseModule"""
import os
import sys
import time
import threading
import queue
import json
import yaml
import logging
import hashlib
import hmac
import re
import tempfile
import warnings
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Tuple
from collections import defaultdict
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


# ============================================================
# КОНФИГУРАЦИОННЫЙ МЕНЕДЖЕР
# ============================================================

class ConfigManager:
    """
    Менеджер конфигурации с проверкой целостности и безопасным доступом.

    Возможности:
    - HMAC-подпись конфигурации для обнаружения изменений
    - Атомарное сохранение через временные файлы
    - Подстановка переменных окружения в значения
    - Безопасный доступ через dotted keys
    - Ротация ключей подписи
    - Автоматическое создание директорий
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.signature_path = Path(str(config_path) + '.sig')
        self._load_secret_key()
        self.data = self._load()
        self._setup_dirs()

    def _load_secret_key(self) -> None:
        """Загрузка секретного ключа с проверкой безопасности"""
        self.secret_key = os.environ.get('SHARD_CONFIG_SECRET', 'change_me_in_production').encode()

        if self.secret_key == b'change_me_in_production':
            if os.environ.get('SHARD_PRODUCTION', '').lower() == 'true':
                raise RuntimeError(
                    "\n🔴 FATAL: SHARD_CONFIG_SECRET must be set in production mode!\n"
                    "   Generate: python -c \"import secrets; print(secrets.token_hex(32))\"\n"
                    "   Then: export SHARD_CONFIG_SECRET=<generated_key>\n"
                )
            else:
                print("⚠️ WARNING: Using default secret key - NOT FOR PRODUCTION!")

    def rotate_secret_key(self, new_key: bytes) -> None:
        """
        Безопасная ротация ключа подписи конфигурации.

        Args:
            new_key: Новый секретный ключ (минимум 32 байта)
        """
        if len(new_key) < 32:
            raise ValueError("Secret key must be at least 32 bytes")

        old_key = self.secret_key
        self.secret_key = new_key
        try:
            # Переподписываем с новым ключом
            self.save()
            os.environ['SHARD_CONFIG_SECRET'] = new_key.decode()
        except Exception:
            # Откат при ошибке
            self.secret_key = old_key
            raise

    def _calculate_signature(self, data: Any) -> str:
        """
        Вычисление HMAC подписи данных.

        Args:
            data: Данные для подписи (dict, str или любой объект)

        Returns:
            HMAC-SHA256 подпись в hex формате
        """
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        elif not isinstance(data, str):
            data = str(data)

        return hmac.new(self.secret_key, data.encode(), hashlib.sha256).hexdigest()

    def _verify_signature(self, data: str, signature: str) -> bool:
        """
        Проверка HMAC подписи с защитой от timing attacks.

        Args:
            data: Проверяемые данные
            signature: Ожидаемая подпись

        Returns:
            True если подпись верна
        """
        expected = self._calculate_signature(data)
        return hmac.compare_digest(expected, signature)

    def _load(self) -> Dict:
        """Загрузка и верификация конфигурации"""
        if self.config_path.exists():
            with open(self.config_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Проверяем подпись если она есть
            if self.signature_path.exists():
                with open(self.signature_path, 'r', encoding='utf-8') as f:
                    signature = f.read().strip()

                if not self._verify_signature(content, signature):
                    self._log_security_alert("Конфигурационный файл был изменён!")
            else:
                self._log_security_alert("Отсутствует файл подписи конфигурации!")

            return yaml.safe_load(content)

        return self._default_config()

    def _default_config(self) -> Dict:
        """Конфигурация по умолчанию"""
        return {
            'network': {
                'interface': 'auto',
                'capture_filter': 'ip',
                'local_networks': ['192.168.', '10.', '172.16.', '127.']
            },
            'ml': {
                'model_path': './models/',
                'online_learning': True,
                'ensemble': ['isolation_forest', 'xgboost'],
                'explain_with_shap': True,
                'retrain_interval': 300,
                'retrain_min_samples': 100
            },
            'protection': {
                'auto_block': False,
                'block_duration': 3600,
                'rate_limit': {'enabled': True, 'threshold': 100, 'window': 60},
                'honeypot': {'enabled': True, 'ports': [22, 80, 443, 3389, 2222, 8888]}
            },
            'waf': {'enabled': True},
            'storage': {
                'timescaledb': {'enabled': False, 'dsn': ''},
                'elasticsearch': {'enabled': False, 'url': ''},
                'sqlite': {'path': 'shard_siem.db'}
            },
            'telemetry': {
                'prometheus': {'enabled': True, 'port': 9090},
                'telegram': {'enabled': False, 'token': '', 'chat_id': ''}
            },
            'logging': {'level': 'INFO', 'file': 'shard.log'},
            'threat_intel': {
                'abuseipdb_key': '',
                'virustotal_key': ''
            },
            'ldap': {
                'server': '',
                'domain': ''
            },
            'dashboard': {
                'port': 8080,
                'enabled': True,
                'auth': {
                    'enabled': True,
                    'username': 'admin',
                    'password': '',
                    'api_keys': []
                }
            }
        }

    def _setup_dirs(self) -> None:
        """Создание необходимых директорий"""
        Path(self.get('ml.model_path', './models/')).mkdir(exist_ok=True)

    def _log_security_alert(self, message: str) -> None:
        """Логирование события безопасности"""
        try:
            with open('shard_security.log', 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now().isoformat()} - SECURITY ALERT - {message}\n")
        except Exception:
            pass  # Не можем логировать - продолжаем работу

    def get(self, key: str, default: Any = None) -> Any:
        """
        Безопасное получение значения по dotted key с подстановкой переменных окружения.

        Поддерживает синтаксис:
        - ${VAR} - простая подстановка переменной
        - ${VAR:-default} - с значением по умолчанию

        Args:
            key: Ключ в формате dotted notation (например 'ml.model_path')
            default: Значение по умолчанию если ключ не найден

        Returns:
            Значение из конфигурации или default
        """
        if not key:
            return default

        keys = key.split('.')
        value = self.data

        for k in keys:
            if isinstance(value, dict):
                if k in value:
                    value = value[k]
                else:
                    return default
            else:
                return default

        # Подстановка переменных окружения
        if isinstance(value, str) and '${' in value:
            def replace_env(match):
                var_name = match.group(1)
                def_val = match.group(2) if match.group(2) else ''
                return os.environ.get(var_name, def_val)

            value = re.sub(r'\$\{([^:}]+):-([^}]+)\}', replace_env, value)
            value = re.sub(r'\$\{([^}]+)\}', lambda m: os.environ.get(m.group(1), ''), value)

        return value if value is not None else default

    def set(self, key: str, value: Any) -> None:
        """
        Установка значения по dotted key.

        Args:
            key: Ключ в формате dotted notation
            value: Устанавливаемое значение
        """
        if not key:
            return

        keys = key.split('.')
        target = self.data

        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            elif not isinstance(target[k], dict):
                target[k] = {}
            target = target[k]

        target[keys[-1]] = value

    def save(self) -> None:
        """Атомарное сохранение конфигурации с подписью"""
        temp_fd = None
        temp_path = None
        temp_sig_path = None

        try:
            # Создаём временный файл для конфига
            temp_fd, temp_path = tempfile.mkstemp(
                dir=str(self.config_path.parent),
                prefix='.config_',
                suffix='.tmp'
            )

            # Записываем данные
            content = yaml.dump(self.data, default_flow_style=False, allow_unicode=True)
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                f.write(content)

            # Создаём временный файл для подписи
            temp_sig_fd, temp_sig_path = tempfile.mkstemp(
                dir=str(self.config_path.parent),
                prefix='.config_sig_',
                suffix='.tmp'
            )

            signature = self._calculate_signature(content)
            with os.fdopen(temp_sig_fd, 'w', encoding='utf-8') as f:
                f.write(signature)

            # Атомарное переименование с учетом платформы
            if sys.platform == 'win32':
                # Windows требует специальной обработки
                try:
                    import ctypes
                    MOVEFILE_REPLACE_EXISTING = 0x1
                    MOVEFILE_WRITE_THROUGH = 0x8

                    ctypes.windll.kernel32.MoveFileExW(
                        str(temp_path), str(self.config_path),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
                    )
                    ctypes.windll.kernel32.MoveFileExW(
                        str(temp_sig_path), str(self.signature_path),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
                    )
                except Exception:
                    # Fallback для Windows без ctypes
                    if self.config_path.exists():
                        self.config_path.unlink()
                    if self.signature_path.exists():
                        self.signature_path.unlink()
                    os.replace(temp_path, self.config_path)
                    os.replace(temp_sig_path, self.signature_path)
            else:
                os.replace(temp_path, self.config_path)
                os.replace(temp_sig_path, self.signature_path)

            # Устанавливаем права на Unix-системах
            if sys.platform != 'win32':
                os.chmod(self.config_path, 0o600)
                os.chmod(self.signature_path, 0o600)

        except Exception as e:
            # Очищаем временные файлы при ошибке
            for path in [temp_path, temp_sig_path]:
                if path and os.path.exists(path):
                    try:
                        os.unlink(path)
                    except Exception:
                        pass
            raise e


# ============================================================
# СЕРВИС ЛОГИРОВАНИЯ
# ============================================================

class LoggingService:
    """
    Сервис логирования с централизованной обработкой критических событий.

    Возможности:
    - Централизованное логирование через стандартный logging
    - Публикация критических событий в EventBus
    - Разграничение security-алертов и системных ошибок
    - Поддержка разных уровней логирования для разных модулей
    """

    def __init__(self, config: ConfigManager, event_bus: Optional['EventBus'] = None):
        self.config = config
        self.event_bus = event_bus
        self.log_level = getattr(logging, config.get('logging.level', 'INFO'))
        self.log_file = config.get('logging.file', 'shard.log')

        # Инициализируем корневой логгер SHARD если ещё не инициализирован
        if not logging.getLogger('SHARD').handlers:
            logging.basicConfig(
                level=self.log_level,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.StreamHandler(sys.stdout),
                    logging.FileHandler(self.log_file, encoding='utf-8')
                ]
            )

        self.logger = logging.getLogger('SHARD')

    def debug(self, msg: str, *args, **kwargs):
        """Debug логирование"""
        self.logger.debug(msg, *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs):
        """Error логирование"""
        self.logger.error(msg, *args, **kwargs)
    
    def get_logger(self, name: str = None) -> logging.Logger:
        """
        Получить логгер для модуля.

        Args:
            name: Имя модуля (опционально)

        Returns:
            Настроенный логгер
        """
        return logging.getLogger(f"SHARD.{name}") if name else self.logger

    def critical_event(self, module: str, message: str, data: Dict = None) -> None:
        """
        Критическое событие - логируется И публикуется в EventBus.

        Args:
            module: Имя модуля-источника
            message: Текст сообщения
            data: Дополнительные данные
        """
        self.logger.critical(f"[{module}] {message}")

        if self.event_bus:
            self.event_bus.publish('system.critical', {
                'timestamp': time.time(),
                'module': module,
                'message': message,
                'data': data or {}
            })

    def security_alert(self, module: str, message: str, severity: str = 'HIGH', data: Dict = None) -> None:
        """
        Событие безопасности - публикуется как алерт.

        Args:
            module: Имя модуля-источника
            message: Текст сообщения
            severity: Уровень критичности (LOW/MEDIUM/HIGH/CRITICAL)
            data: Дополнительные данные
        """
        self.logger.warning(f"[SECURITY] [{module}] {message}")

        if self.event_bus:
            severity_scores = {
                'LOW': 0.3,
                'MEDIUM': 0.5,
                'HIGH': 0.7,
                'CRITICAL': 0.9
            }

            self.event_bus.publish('alert.detected', {
                'timestamp': time.time(),
                'attack_type': 'Security Event',
                'severity': severity,
                'score': severity_scores.get(severity, 0.5),
                'explanation': f"[{module}] {message}",
                'is_attack': True,
                'details': data or {}
            })


# ============================================================
# EVENT BUS
# ============================================================

@dataclass
class Subscriber:
    """Структура данных подписчика"""
    queue: queue.Queue
    callback: Callable
    worker: threading.Thread
    stop_event: threading.Event = field(default_factory=threading.Event)


class EventBus:
    """
    Масштабируемая шина событий с per-subscriber очередями.

    Возможности:
    - Per-subscriber очереди для устранения contention
    - Три уровня приоритета (high, normal, low)
    - Lock-free публикация через put_nowait
    - Автоматическая очистка умерших подписчиков
    - Метрики для мониторинга
    - Health-check механизм
    - Graceful degradation при перегрузках

    Использование:
        bus = EventBus()
        bus.subscribe('alert.detected', my_handler)
        bus.publish('alert.detected', {'message': 'Attack detected!'})
    """

    def __init__(self, max_queue_size: int = 10000):
        # Карта приоритетов
        self.priority_map = {
            'alert.detected': 'high',
            'exfiltration.detected': 'high',
            'firewall.blocked': 'high',
            'system.critical': 'high',
            'honeypot.connection': 'high',
            'encrypted.threat': 'high',
            'packet.received': 'normal',
            'dpi.http': 'low',
            'dpi.dns': 'low',
        }

        # Per-subscriber подписчики
        self._subscribers: Dict[str, List[Subscriber]] = defaultdict(list)
        self._subscriber_lock = threading.RLock()

        # Приоритетные очереди для новых событий
        self._queues = {
            'high': queue.Queue(maxsize=max_queue_size),
            'normal': queue.Queue(maxsize=max_queue_size * 2),
            'low': queue.Queue(maxsize=max_queue_size * 5)
        }

        self._running = True
        self.max_queue_size = max_queue_size
        self._cleanup_interval = 60  # Интервал очистки умерших подписчиков

        # Статистика
        self.stats = {
            'high': 0,
            'normal': 0,
            'low': 0,
            'dropped': 0,
            'subscribers': 0,
            'events_published': 0,
            'events_delivered': 0,
            'events_published_unique': 0  # Уникальные события (один publish)
        }
        self._stats_lock = threading.RLock()

        # Emergency thread pool для high-priority событий при переполнении
        from concurrent.futures import ThreadPoolExecutor
        self._emergency_executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="EventBus-Emergency"
        )

        # Запускаем диспетчеры
        self._dispatchers = []
        for priority in ['high', 'normal', 'low']:
            for i in range(2):  # По 2 диспетчера на приоритет
                t = threading.Thread(
                    target=self._dispatcher_worker,
                    args=(priority,),
                    daemon=True,
                    name=f"EventBus-Dispatcher-{priority}-{i}"
                )
                t.start()
                self._dispatchers.append(t)

        # Запускаем очиститель умерших подписчиков
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_worker,
            daemon=True,
            name="EventBus-Cleanup"
        )
        self._cleanup_thread.start()

    def _dispatcher_worker(self, priority: str):
        """
        Диспетчер событий.
        Читает из приоритетной очереди и распределяет по подписчикам.
        """
        q = self._queues[priority]

        while self._running:
            try:
                event_type, data = q.get(timeout=1)

                # Находим активных подписчиков
                with self._subscriber_lock:
                    subscribers = [
                        sub for sub in self._subscribers.get(event_type, [])
                        if sub.worker.is_alive()
                    ]

                # Распределяем событие
                delivered = 0
                for sub in subscribers:
                    try:
                        sub.queue.put_nowait(data)
                        delivered += 1
                    except queue.Full:
                        with self._stats_lock:
                            self.stats['dropped'] += 1

                # Обновляем статистику
                with self._stats_lock:
                    self.stats[priority] += 1
                    self.stats['events_published'] += 1
                    self.stats['events_delivered'] += delivered

            except queue.Empty:
                continue
            except Exception:
                continue

    def _cleanup_worker(self):
        """Периодическая очистка умерших подписчиков"""
        while self._running:
            time.sleep(self._cleanup_interval)
            self._cleanup_dead_subscribers()

    def _cleanup_dead_subscribers(self):
        """Очистка подписчиков с умершими воркерами (join вне лока)"""
        dead_subs = []  # Собираем мёртвых вне лока
        
        with self._subscriber_lock:
            for event_type in list(self._subscribers.keys()):
                alive_subs = []

                for sub in self._subscribers[event_type]:
                    if sub.worker.is_alive():
                        alive_subs.append(sub)
                    else:
                        # Очищаем очередь умершего подписчика
                        while not sub.queue.empty():
                            try:
                                sub.queue.get_nowait()
                            except queue.Empty:
                                break
                        dead_subs.append((event_type, sub))

                if alive_subs:
                    self._subscribers[event_type] = alive_subs
                else:
                    del self._subscribers[event_type]
        
        # Join вне лока — не блокирует диспетчеры
        for event_type, sub in dead_subs:
            if sub.worker.is_alive():
                sub.worker.join(timeout=1)

    def _safe_callback_executor(self, callback: Callable, data: Any):
        """Безопасное выполнение callback в отдельном потоке"""
        try:
            callback(data)
        except Exception as e:
            # Логируем ошибку, но не роняем систему
            print(f"EventBus callback error: {e}", file=sys.stderr)

    def publish(self, event_type: str, data: Any = None):
        """
        Публикация события.

        Для high-priority событий при переполнении очереди
        callback вызывается в отдельном потоке для избежания блокировки.

        Args:
            event_type: Тип события
            data: Данные события
        """
        priority = self.priority_map.get(event_type, 'normal')
        q = self._queues[priority]

        with self._stats_lock:
            self.stats['events_published_unique'] += 1

        try:
            q.put_nowait((event_type, data))
        except queue.Full:
            with self._stats_lock:
                self.stats['dropped'] += 1

            # Для высокоприоритетных - прямая доставка в отдельном потоке
            if priority == 'high':
                with self._subscriber_lock:
                    subscribers = [
                        sub for sub in self._subscribers.get(event_type, [])
                        if sub.worker.is_alive()
                    ]

                for sub in subscribers:
                    try:
                        # Используем пул потоков вместо неограниченного создания
                        self._emergency_executor.submit(
                            self._safe_callback_executor, sub.callback, data
                        )
                    except Exception:
                        pass

    def subscribe(self, event_type: str, callback: Callable) -> Callable:
        """
        Подписка на события.
        Возвращает функцию для отписки.

        Args:
            event_type: Тип события
            callback: Функция-обработчик

        Returns:
            Функция unsubscribe()
        """
        sub_queue = queue.Queue(maxsize=self.max_queue_size)
        stop_event = threading.Event()

        def subscriber_worker():
            while self._running and not stop_event.is_set():
                try:
                    data = sub_queue.get(timeout=1)
                    try:
                        callback(data)
                    except Exception as e:
                        print(f"EventBus subscriber error: {e}", file=sys.stderr)
                except queue.Empty:
                    continue

        worker = threading.Thread(
            target=subscriber_worker,
            daemon=True,
            name=f"EventBus-Subscriber-{event_type}"
        )
        worker.start()

        subscriber = Subscriber(
            queue=sub_queue,
            callback=callback,
            worker=worker,
            stop_event=stop_event
        )

        with self._subscriber_lock:
            self._subscribers[event_type].append(subscriber)
            self.stats['subscribers'] += 1

        # Возвращаем функцию отписки
        def unsubscribe():
            self._unsubscribe_internal(event_type, subscriber)

        return unsubscribe

    def _unsubscribe_internal(self, event_type: str, subscriber: Subscriber) -> None:
        """Внутренняя реализация отписки (join вне лока)"""
        # Сигнализируем остановку и очищаем очередь под локом
        with self._subscriber_lock:
            if event_type in self._subscribers:
                subscriber.stop_event.set()

                # Очищаем очередь
                while not subscriber.queue.empty():
                    try:
                        subscriber.queue.get_nowait()
                    except queue.Empty:
                        break

                # Удаляем из списка подписчиков
                self._subscribers[event_type] = [
                    s for s in self._subscribers[event_type]
                    if s is not subscriber
                ]

                if not self._subscribers[event_type]:
                    del self._subscribers[event_type]

                self.stats['subscribers'] -= 1

        # Join вне лока — не блокирует диспетчеры
        if subscriber.worker.is_alive():
            subscriber.worker.join(timeout=1)

    def unsubscribe(self, event_type: str, callback: Callable) -> None:
        """
        Отписка от событий.

        Args:
            event_type: Тип события
            callback: Функция-обработчик для удаления
        """
        subscriber_to_join = None
        with self._subscriber_lock:
            if event_type in self._subscribers:
                for sub in self._subscribers[event_type]:
                    if sub.callback is callback:
                        sub.stop_event.set()
                        while not sub.queue.empty():
                            try:
                                sub.queue.get_nowait()
                            except queue.Empty:
                                break
                        self._subscribers[event_type] = [
                            s for s in self._subscribers[event_type] if s is not sub
                        ]
                        if not self._subscribers[event_type]:
                            del self._subscribers[event_type]
                        self.stats['subscribers'] -= 1
                        subscriber_to_join = sub
                        break
        if subscriber_to_join and subscriber_to_join.worker.is_alive():
            subscriber_to_join.worker.join(timeout=1)

    def get_stats(self) -> Dict:
        """
        Получить полную статистику EventBus.

        Returns:
            Словарь с метриками (events_published=total dispatches, 
            events_published_unique=unique publish calls)
        """
        with self._stats_lock:
            stats = dict(self.stats)
            # Добавляем пояснение к метрикам
            stats['events_avg_subscribers'] = (
                stats['events_delivered'] / max(1, stats['events_published_unique'])
            )

        with self._subscriber_lock:
            # Информация о подписчиках
            event_counts = {}
            total_alive = 0
            total_dead = 0

            for event_type, subscribers in self._subscribers.items():
                alive = sum(1 for s in subscribers if s.worker.is_alive())
                event_counts[event_type] = {
                    'total': len(subscribers),
                    'alive': alive,
                    'dead': len(subscribers) - alive
                }
                total_alive += alive
                total_dead += len(subscribers) - alive

            stats['events_subscribed'] = event_counts
            stats['total_event_types'] = len(self._subscribers)
            stats['subscribers_alive'] = total_alive
            stats['subscribers_dead'] = total_dead

            # Размеры очередей
            for priority, q in self._queues.items():
                stats[f'{priority}_queue_size'] = q.qsize()
                stats[f'{priority}_queue_saturation'] = q.qsize() / q.maxsize if q.maxsize > 0 else 0

        return stats

    def health_check(self) -> Dict:
        """
        Проверка здоровья EventBus.

        Returns:
            Словарь со статусом компонентов
        """
        dispatchers_alive = sum(1 for d in self._dispatchers if d.is_alive())
        cleanup_alive = self._cleanup_thread.is_alive()

        with self._subscriber_lock:
            total_subs = sum(len(subs) for subs in self._subscribers.values())
            alive_subs = sum(
                1 for subs in self._subscribers.values()
                for s in subs if s.worker.is_alive()
            )

        # Определяем статус
        if not self._running:
            status = 'stopped'
        elif dispatchers_alive < len(self._dispatchers) * 0.5:
            status = 'degraded'
        elif alive_subs < total_subs * 0.7 and total_subs > 0:
            status = 'degraded'
        else:
            status = 'healthy'

        return {
            'status': status,
            'running': self._running,
            'dispatchers': {
                'total': len(self._dispatchers),
                'alive': dispatchers_alive
            },
            'subscribers': {
                'total': total_subs,
                'alive': alive_subs
            },
            'cleanup_worker': cleanup_alive,
            'queue_saturation': {
                priority: self._queues[priority].qsize() / self._queues[priority].maxsize
                if self._queues[priority].maxsize > 0 else 0
                for priority in self._queues
            }
        }

    def shutdown(self, timeout: float = 5.0):
        """
        Graceful shutdown шины событий.

        Args:
            timeout: Время ожидания завершения потоков
        """
        self._running = False

        # Shutdown emergency executor
        if hasattr(self, '_emergency_executor'):
            self._emergency_executor.shutdown(wait=False)

        # Ждём завершения диспетчеров
        for t in self._dispatchers:
            t.join(timeout=timeout)

        # Ждём завершения очистителя
        self._cleanup_thread.join(timeout=timeout)

        # Останавливаем всех подписчиков
        with self._subscriber_lock:
            for event_type in list(self._subscribers.keys()):
                for subscriber in self._subscribers[event_type]:
                    subscriber.stop_event.set()
                    if subscriber.worker.is_alive():
                        subscriber.worker.join(timeout=timeout)

            self._subscribers.clear()


# ============================================================
# РЕЕСТР МОДУЛЕЙ
# ============================================================

class ModuleRegistry:
    """
    Центральный реестр модулей SHARD.
    Позволяет модулям находить друг друга без жёстких связей.

    Использование:
        registry = ModuleRegistry()
        registry.register('firewall', firewall_instance)
        firewall = registry.get('firewall')
    """

    def __init__(self):
        self._modules: Dict[str, Any] = {}
        self._lock = threading.RLock()

    def register(self, name: str, module: Any) -> None:
        """
        Зарегистрировать модуль.

        Args:
            name: Имя модуля
            module: Экземпляр модуля
        """
        with self._lock:
            if name in self._modules:
                warnings.warn(f"Module '{name}' is already registered. Overwriting.")
            self._modules[name] = module

    def unregister(self, name: str) -> Optional[Any]:
        """
        Удалить модуль из реестра.

        Args:
            name: Имя модуля

        Returns:
            Удаленный модуль или None
        """
        with self._lock:
            return self._modules.pop(name, None)

    def get(self, name: str) -> Optional[Any]:
        """
        Получить модуль по имени.

        Args:
            name: Имя модуля

        Returns:
            Экземпляр модуля или None
        """
        with self._lock:
            return self._modules.get(name)

    def get_all(self) -> Dict[str, Any]:
        """
        Получить все зарегистрированные модули.

        Returns:
            Словарь имя: модуль
        """
        with self._lock:
            return dict(self._modules)

    def get_by_type(self, module_type: type) -> List[Any]:
        """
        Найти модули по типу.

        Args:
            module_type: Класс модуля

        Returns:
            Список модулей указанного типа
        """
        with self._lock:
            return [m for m in self._modules.values() if isinstance(m, module_type)]

    def list_names(self) -> List[str]:
        """
        Список имён всех модулей.

        Returns:
            Список имен модулей
        """
        with self._lock:
            return list(self._modules.keys())

    def clear(self) -> None:
        """Очистить реестр"""
        with self._lock:
            self._modules.clear()

    @property
    def count(self) -> int:
        """Количество зарегистрированных модулей"""
        with self._lock:
            return len(self._modules)


# ============================================================
# БАЗОВЫЙ МОДУЛЬ
# ============================================================

class BaseModule(ABC):
    """
    Базовый класс для всех модулей SHARD.

    Все модули должны наследоваться от этого класса
    и реализовывать методы start() и stop().

    Использование:
        class MyModule(BaseModule):
            def start(self):
                self.running = True
                # инициализация модуля

            def stop(self):
                self.running = False
                # очистка ресурсов
    """

    def __init__(self, name: str, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        self.name = name
        self.config = config
        self.event_bus = event_bus
        self.logger = logger.get_logger(name)
        self.running = False
        self._stop_event = threading.Event()

    @abstractmethod
    def start(self) -> None:
        """Запуск модуля"""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Остановка модуля"""
        pass

    def is_running(self) -> bool:
        """Проверка активности модуля"""
        return self.running and not self._stop_event.is_set()

    def health_check(self) -> Dict:
        """
        Проверка здоровья модуля.

        Returns:
            Словарь с состоянием модуля
        """
        return {
            'module': self.name,
            'status': 'running' if self.is_running() else 'stopped',
            'running': self.running,
            'stop_event_set': self._stop_event.is_set()
        }


# ============================================================
# ТЕСТЫ И ДЕМОНСТРАЦИЯ
# ============================================================

if __name__ == "__main__":
    """Демонстрация работы компонентов"""

    print("=" * 60)
    print("SHARD Core - Demo & Tests")
    print("=" * 60)

    # 1. ConfigManager
    print("\n📋 Testing ConfigManager...")
    config = ConfigManager("test_config.yaml")
    config.set('test.key', 'value')
    assert config.get('test.key') == 'value', "ConfigManager get/set failed"
    print("✅ ConfigManager: OK")

    # 2. EventBus
    print("\n📡 Testing EventBus...")
    event_bus = EventBus(max_queue_size=100)

    received_events = []


    def test_handler(data):
        received_events.append(data)


    # Подписка с возвратом функции отписки
    unsubscribe = event_bus.subscribe('test.event', test_handler)

    # Публикация
    event_bus.publish('test.event', {'message': 'Hello'})
    time.sleep(0.1)

    assert len(received_events) == 1, "EventBus publish/subscribe failed"
    assert received_events[0]['message'] == 'Hello', "EventBus data corrupted"
    print("✅ EventBus publish/subscribe: OK")

    # Отписка
    unsubscribe()
    event_bus.publish('test.event', {'message': 'World'})
    time.sleep(0.1)
    assert len(received_events) == 1, "EventBus unsubscribe failed"
    print("✅ EventBus unsubscribe: OK")

    # Health check
    health = event_bus.health_check()
    assert health['status'] in ['healthy', 'degraded'], f"Unexpected health status: {health['status']}"
    print(f"✅ EventBus health check: {health['status']}")

    # Статистика
    stats = event_bus.get_stats()
    print(f"✅ EventBus stats: {stats['events_published']} published, {stats['events_delivered']} delivered")

    # 3. LoggingService
    print("\n📝 Testing LoggingService...")
    logger = LoggingService(config, event_bus)

    test_logger = logger.get_logger('test')
    test_logger.info("Test log message")
    print("✅ LoggingService: OK")

    # 4. ModuleRegistry
    print("\n🗂️ Testing ModuleRegistry...")
    registry = ModuleRegistry()


    class TestModule:
        pass


    module = TestModule()
    registry.register('test', module)
    assert registry.get('test') is module, "ModuleRegistry get failed"
    assert registry.count == 1, "ModuleRegistry count failed"
    assert 'test' in registry.list_names(), "ModuleRegistry list_names failed"

    registry.unregister('test')
    assert registry.get('test') is None, "ModuleRegistry unregister failed"
    assert registry.count == 0, "ModuleRegistry cleanup failed"
    print("✅ ModuleRegistry: OK")

    # 5. BaseModule
    print("\n🔌 Testing BaseModule...")


    class TestModuleImpl(BaseModule):
        def start(self):
            self.running = True

        def stop(self):
            self.running = False


    test_module = TestModuleImpl('test', config, event_bus, logger)
    assert not test_module.is_running(), "Module should not be running initially"

    test_module.start()
    assert test_module.is_running(), "Module should be running after start()"

    health = test_module.health_check()
    assert health['status'] == 'running', f"Unexpected module health: {health['status']}"

    test_module.stop()
    assert not test_module.is_running(), "Module should not be running after stop()"
    print("✅ BaseModule: OK")

    # Shutdown EventBus
    event_bus.shutdown()

    # Cleanup test file
    if Path("test_config.yaml").exists():
        Path("test_config.yaml").unlink()

    print("\n" + "=" * 60)
    print("✅ All tests passed successfully!")
    print("=" * 60)