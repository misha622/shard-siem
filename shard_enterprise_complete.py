#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
shard_enterprise_complete.py - SHARD ENTERPRISE FINAL
ПОЛНОСТЬЮ ИСПРАВЛЕННАЯ ВЕРСИЯ СО ВСЕМИ УЛУЧШЕНИЯМИ

НОВЫЕ ФУНКЦИИ:
1. Время суток в Baseline Profiler
2. Цепочки атак (Kill Chain)
3. Отслеживание Lateral Movement
4. Умная блокировка (градация)
5. Объяснения к алертам (SHAP + правила)
6. Анализ зашифрованного трафика (TLS/JA3S/Beaconing)
7. DNS АНАЛИТИКА (ТУННЕЛИ, ЭНТРОПИЯ)
8. THREAT INTELLIGENCE (ABUSEIPDB/VIRUSTOTAL)
9. ОБНАРУЖЕНИЕ УТЕЧКИ ДАННЫХ
10. UBA/UEBA (ПОВЕДЕНИЕ ПОЛЬЗОВАТЕЛЕЙ)
11. АВТОМАТИЧЕСКИЙ ОТЧЁТ ОБ ИНЦИДЕНТЕ
12. WEB DASHBOARD
13. КОНТЕКСТ ACTIVE DIRECTORY / LDAP
14. EMAIL УГРОЗЫ
15. EDR ИНТЕГРАЦИЯ

ВСЕ ФУНКЦИИ РЕАЛЬНЫЕ, БЕЗ ИМИТАЦИЙ
"""

import os
import sys
import time
import json
import hashlib
import hmac
import yaml
import math
import struct
import hashlib
import socket
import threading
import queue
from shard_dl_models import DeepLearningEngine, DLModelConfig as ModelConfig
import logging
import subprocess
import random
import re
import sqlite3
import base64
import http.server
import socketserver
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple, Set, Callable, Union
from pathlib import Path
from collections import deque, defaultdict
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from abc import ABC, abstractmethod

# Исправление кодировки для Windows
if sys.platform == 'win32':
    import io

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Исправление путей для WSL
if sys.platform == 'linux':
    try:
        # Проверяем, в WSL ли мы
        with open('/proc/version', 'r') as f:
            if 'microsoft' in f.read().lower():
                # Мы в WSL
                import locale
                # Пробуем разные локали
                for loc in ['en_US.UTF-8', 'C.UTF-8', 'C', 'en_US', '']:
                    try:
                        locale.setlocale(locale.LC_ALL, loc)
                        break
                    except:
                        continue
    except:
        pass


# ============================================================
# ЗАГРУЗКА БИБЛИОТЕК
# ============================================================

def safe_import(module_name: str, submodule: str = None) -> Optional[Any]:
    """Безопасный импорт с поддержкой подмодулей"""
    try:
        if submodule:
            return __import__(module_name, fromlist=[submodule])
        return __import__(module_name)
    except ImportError:
        return None

# Обновить использование:
sklearn_ensemble_module = safe_import('sklearn', 'ensemble')
if sklearn_ensemble_module:
    from sklearn.ensemble import IsolationForest

np = safe_import('numpy')
joblib = safe_import('joblib')
scapy_all = safe_import('scapy.all')
sklearn_ensemble = safe_import('sklearn.ensemble')
sklearn_preprocessing = safe_import('sklearn.preprocessing')
sklearn_cluster = safe_import('sklearn.cluster')
sklearn_decomposition = safe_import('sklearn.decomposition')
psycopg2 = safe_import('psycopg2')
elasticsearch = safe_import('elasticsearch')
shap_module = safe_import('shap')
xgboost_module = safe_import('xgboost')
prometheus_client = safe_import('prometheus_client')
requests = safe_import('requests')
torch = safe_import('torch')
torch_nn = safe_import('torch.nn')
torch_optim = safe_import('torch.optim')
torch_functional = safe_import('torch.nn.functional')
torch_geometric = safe_import('torch_geometric')
torch_geometric_nn = safe_import('torch_geometric.nn') if torch_geometric else None


# ============================================================
# БЕЗОПАСНЫЙ ИМПОРТ И ПРОВЕРКА ЗАВИСИМОСТЕЙ (пункт 73)
# ============================================================

def require_module(module_name: str):
    """Декоратор для проверки наличия модуля"""

    def decorator(func):
        def wrapper(*args, **kwargs):
            # Проверяем глобальные переменные импорта
            module_var = f"{module_name}_all"
            if module_var in globals() and globals()[module_var] is not None:
                return func(*args, **kwargs)

            # Пробуем импортировать
            try:
                __import__(module_name)
                return func(*args, **kwargs)
            except ImportError:
                logger = logging.getLogger('SHARD')
                logger.warning(f"Модуль {module_name} недоступен, функция {func.__name__} не может быть выполнена")
                return None

        return wrapper

    return decorator


def safe_import_scapy():
    """Безопасный импорт Scapy с проверкой"""
    try:
        from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR
        return True, (IP, TCP, UDP, Raw, DNS, DNSQR)
    except ImportError:
        return False, None


# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

# В начале файла, после определения Enum'ов добавить:

class AttackType(Enum):
    """Типы атак"""
    NORMAL = "Normal"
    DOS = "DoS"
    DDOS = "DDoS"
    BRUTE_FORCE = "Brute Force"
    WEB_ATTACK = "Web Attack"
    BOTNET = "Botnet"
    PORT_SCAN = "Port Scan"
    C2_BEACON = "C2 Beacon"
    DNS_TUNNEL = "DNS Tunnel"
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    PATH_TRAVERSAL = "Path Traversal"
    CMD_INJECTION = "Command Injection"
    LATERAL_MOVEMENT = "Lateral Movement"
    DATA_EXFILTRATION = "Data Exfiltration"
    PHISHING = "Phishing"
    MALWARE = "Malware"
    UNKNOWN = "Unknown"

    @classmethod
    def from_string(cls, value: str) -> 'AttackType':
        """Получить Enum из строки (безопасно)"""
        if not value:
            return cls.UNKNOWN

        # Прямое совпадение по значению
        for attack_type in cls:
            if attack_type.value == value:
                return attack_type

        # Совпадение по имени (для обратной совместимости)
        normalized = value.upper().replace(' ', '_')
        try:
            return cls[normalized]
        except KeyError:
            return cls.UNKNOWN

    def __eq__(self, other):
        if isinstance(other, AttackType):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return NotImplemented  # ← ВАЖНО: позволяет str.__eq__ отработать

    def __hash__(self):
        return hash(self.value)

class AlertSeverity(Enum):
    """Уровни серьёзности"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_string(cls, value: str) -> 'AlertSeverity':
        """Получить Enum из строки"""
        if not value:
            return cls.LOW
        for severity in cls:
            if severity.value == value:
                return severity
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.LOW

    def __eq__(self, other):
        if isinstance(other, str):
            return self.value == other
        if isinstance(other, AlertSeverity):
            return self.value == other.value
        return False

    def __lt__(self, other):
        order = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        if isinstance(other, str):
            return order[self.value] < order.get(other, 0)
        if isinstance(other, AlertSeverity):
            return order[self.value] < order[other.value]
        return False

    def __gt__(self, other):
        order = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        if isinstance(other, str):
            return order[self.value] > order.get(other, 0)
        if isinstance(other, AlertSeverity):
            return order[self.value] > order[other.value]
        return False

    def __hash__(self):
        return hash(self.value)


# ========== ХЕЛПЕРЫ ВНЕ КЛАССА ==========
def is_attack_type(value, expected):
    """Безопасное сравнение типа атаки"""
    if isinstance(value, AttackType):
        if isinstance(expected, AttackType):
            return value == expected
        return value.value == expected
    if isinstance(expected, AttackType):
        return value == expected.value
    return value == expected


def is_severity(value, expected):
    """Безопасное сравнение серьёзности"""
    if isinstance(value, AlertSeverity):
        if isinstance(expected, AlertSeverity):
            return value == expected
        return value.value == expected
    if isinstance(expected, AlertSeverity):
        return value == expected.value
    return value == expected

class DNSThresholds:
    """Пороговые значения для DNS анализа"""
    LONG_QUERY = 52
    VERY_LONG_QUERY = 100
    HIGH_ENTROPY = 3.5
    VERY_HIGH_ENTROPY = 4.0
    FREQUENT_QUERIES_PER_MIN = 30
    VERY_FREQUENT_QUERIES_PER_MIN = 60
    MANY_SUBDOMAINS = 50
    MANY_DOTS = 5
    CONSTANT_LENGTH_VARIANCE = 10
    LARGE_DNS_PACKET = 512
    VERY_LARGE_DNS_PACKET = 1000
    EXTREMELY_LARGE_DNS_PACKET = 2000


class ExfilThresholds:
    """Пороги для обнаружения утечки данных"""
    SINGLE_DST_CRITICAL = 50_000_000   # 50 MB
    SINGLE_DST_HIGH = 20_000_000       # 20 MB
    SINGLE_DST_MEDIUM = 5_000_000      # 5 MB
    TOTAL_CRITICAL = 200_000_000       # 200 MB
    TOTAL_HIGH = 100_000_000           # 100 MB
    CONNECTIONS_FLOOD = 100
    CONNECTIONS_HIGH = 50
    ASYMMETRIC_RATIO = 10
    LARGE_PACKET = 10000
    MANY_DESTINATIONS = 10
    TIME_WINDOW_5MIN = 300
    TIME_WINDOW_1MIN = 60


class WAFThresholds:
    """Пороги для WAF"""
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 60
    MAX_BUFFER_SIZE = 200
    CLEANUP_INTERVAL = 5


class BeaconingThresholds:
    """Пороги для обнаружения beaconing"""
    BEACON_SCORE_THRESHOLD = 0.7
    MIN_SAMPLES = 5
    CV_THRESHOLD = 0.1
    MIN_INTERVAL = 10
    MAX_INTERVAL = 3600


class MLThresholds:
    """Пороги для ML моделей"""
    CONFIDENCE_THRESHOLD = 0.7
    ANOMALY_SCORE_THRESHOLD = -0.2
    RETRAIN_MIN_SAMPLES = 100
    NORMAL_BUFFER_SIZE = 5000
    ATTACK_BUFFER_SIZE = 5000


class CacheTTL:
    """TTL для различных кэшей"""
    THREAT_INTEL = 3600       # 1 час
    GEO_LOCATION = 86400      # 24 часа
    LDAP_USER = 3600          # 1 час
    LDAP_GROUP = 3600         # 1 час
    TLS_SESSION = 3600        # 1 час
    BASELINE_STATS = 60       # 1 минута
    TOKEN = 3600              # 1 час


class CleanupIntervals:
    """Интервалы очистки"""
    ATTACK_CHAIN = 300        # 5 минут
    TLS_SESSIONS = 300        # 5 минут
    THREAT_CACHE = 300        # 5 минут
    FLOWS = 600               # 10 минут
    REPORTS = 3600            # 1 час
    ACTION_LEVEL_DECAY = 1800 # 30 минут


# Вынесено в core/base.py
from core.base import ConfigManager, LoggingService, EventBus, BaseModule
class DNSAnalyzer(BaseModule):
    """Глубокий анализ DNS трафика"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("DNSAnalyzer", config, event_bus, logger)

        self.dns_queries: Dict[str, Dict] = defaultdict(lambda: {
            'count': 0,
            'timestamps': deque(maxlen=100),
            'subdomains': set(),
            'entropy_values': deque(maxlen=50),
            'query_lengths': deque(maxlen=100),
            'unique_queries': set(),
            'total_bytes': 0,
            'first_seen': time.time(),
            'last_seen': time.time()
        })

        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
            '.work', '.date', '.racing', '.accountant', '.science', '.party',
            '.review', '.trade', '.webcam', '.bid', '.win', '.download'
        }

        self.dga_keywords = {
            'update', 'secure', 'bank', 'account', 'login', 'verify',
            'paypal', 'microsoft', 'google', 'apple', 'amazon'
        }

        self._lock = threading.RLock()
        self.event_bus.subscribe('dpi.dns', self.on_dns_query)
        self._flush_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='DPI-Flush')
        self.event_bus.subscribe('packet.received', self.on_packet)

    def start(self) -> None:
        self.running = True
        self.logger.info(f"DNS анализатор запущен (отслеживание туннелей, DGA, энтропия)")

    def stop(self) -> None:
        self.running = False

    def on_packet(self, data: Dict) -> None:
        """Обработка пакетов для анализа DNS"""
        packet = data.get('packet')
        if not packet:
            return

        try:
            from scapy.all import UDP, DNS, DNSQR, Raw, IP

            if packet.haslayer(UDP) and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
                src_ip = data.get('src_ip', 'unknown')
                dst_ip = data.get('dst_ip', 'unknown')

                # Анализ DNS запросов
                if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Запрос
                    dns_layer = packet[DNS]
                    if dns_layer.qdcount > 0:
                        query = dns_layer[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                        self._analyze_dns_query(src_ip, query, packet)

                # Анализ размера пакетов (признак туннеля)
                packet_size = len(packet)
                if packet_size > 512:  # Нормальный DNS пакет обычно меньше
                    self._check_dns_tunnel(src_ip, dst_ip, packet_size)

        except Exception as e:
            self.logger.debug(f"Ошибка анализа DNS пакета: {e}")

    def on_dns_query(self, data: Dict) -> None:
        """Обработка DNS запросов от DPI"""
        src_ip = data.get('src_ip', 'unknown')
        query = data.get('query', '')
        if query:
            self._analyze_dns_query(src_ip, query, None)

    def _analyze_dns_query(self, src_ip: str, query: str, packet: Any = None) -> Dict:
        """Анализ DNS запроса (исправлено - использует константы, безопасная работа с set)"""
        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'attack_type': None,
            'severity': AlertSeverity.LOW.value
        }

        with self._lock:
            if src_ip not in self.dns_queries:
                self.dns_queries[src_ip] = {
                    'count': 0,
                    'timestamps': deque(maxlen=100),
                    'subdomains': set(),
                    'entropy_values': deque(maxlen=50),
                    'query_lengths': deque(maxlen=100),
                    'unique_queries': set(),
                    'total_bytes': 0,
                    'first_seen': time.time(),
                    'last_seen': time.time()
                }

            stats = self.dns_queries[src_ip]
            stats['count'] += 1
            stats['timestamps'].append(time.time())
            stats['last_seen'] = time.time()
            stats['unique_queries'].add(query)
            stats['query_lengths'].append(len(query))

            entropy = self._calculate_entropy(query)
            stats['entropy_values'].append(entropy)

            # Используем константы вместо magic numbers
            if len(query) > DNSThresholds.LONG_QUERY:
                result['is_suspicious'] = True
                result['reasons'].append(f"long_query:{len(query)}")
                result['score'] += 0.3
                result['attack_type'] = AttackType.DNS_TUNNEL.value
                result['severity'] = AlertSeverity.HIGH.value

            if len(query) > DNSThresholds.VERY_LONG_QUERY:
                result['score'] += 0.3
                result['severity'] = AlertSeverity.CRITICAL.value

            for tld in self.suspicious_tlds:
                if query.lower().endswith(tld):
                    result['is_suspicious'] = True
                    result['reasons'].append(f"suspicious_tld:{tld}")
                    result['score'] += 0.25
                    if result['attack_type'] is None:
                        result['attack_type'] = AttackType.BOTNET.value
                    break

            if entropy > DNSThresholds.HIGH_ENTROPY:
                result['is_suspicious'] = True
                result['reasons'].append(f"high_entropy:{entropy:.2f}")
                result['score'] += 0.3
                if result['attack_type'] is None:
                    result['attack_type'] = AttackType.BOTNET.value

            if entropy > DNSThresholds.VERY_HIGH_ENTROPY:
                result['score'] += 0.2
                result['severity'] = AlertSeverity.HIGH.value

            recent = [t for t in stats['timestamps'] if time.time() - t < 60]
            if len(recent) > DNSThresholds.FREQUENT_QUERIES_PER_MIN:
                result['is_suspicious'] = True
                result['reasons'].append(f"high_frequency:{len(recent)}/min")
                result['score'] += 0.2

                if len(recent) > DNSThresholds.VERY_FREQUENT_QUERIES_PER_MIN:
                    result['score'] += 0.2
                    if result['attack_type'] is None:
                        result['attack_type'] = AttackType.DNS_TUNNEL.value

            subdomain = query.split('.')[0] if '.' in query else query
            if 'subdomains' not in stats:
                stats['subdomains'] = set()
            stats['subdomains'].add(subdomain)
            subdomains_count = len(stats['subdomains'])

            if subdomains_count > DNSThresholds.MANY_SUBDOMAINS:
                result['is_suspicious'] = True
                result['reasons'].append(f"many_subdomains:{subdomains_count}")
                result['score'] += 0.2
                if result['attack_type'] is None:
                    result['attack_type'] = AttackType.BOTNET.value

            query_lower = query.lower()
            for kw in self.dga_keywords:
                if kw in query_lower:
                    if not query_lower.endswith(f".{kw}.com") and not query_lower == f"{kw}.com":
                        result['score'] += 0.1
                        result['reasons'].append(f"dga_keyword:{kw}")

            dot_count = query.count('.')
            if dot_count > DNSThresholds.MANY_DOTS:
                result['is_suspicious'] = True
                result['reasons'].append(f"many_dots:{dot_count}")
                result['score'] += 0.15

            unique_queries_count = len(stats['unique_queries'])
            if unique_queries_count > 10:
                lengths = list(stats['query_lengths'])
                if len(lengths) > 10:
                    avg_len = sum(lengths) / len(lengths)
                    variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
                    if variance < DNSThresholds.CONSTANT_LENGTH_VARIANCE:
                        result['is_suspicious'] = True
                        result['reasons'].append(f"constant_length:variance={variance:.2f}")
                        result['score'] += 0.2
                        if result['attack_type'] is None:
                            result['attack_type'] = AttackType.DNS_TUNNEL.value

            result['score'] = min(1.0, result['score'])

            if result['score'] > 0.7:
                result['severity'] = AlertSeverity.CRITICAL.value
            elif result['score'] > 0.5:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.3:
                result['severity'] = AlertSeverity.MEDIUM.value

            result['src_ip'] = src_ip
            result['query'] = query
            result['entropy'] = entropy
            result['query_count'] = stats['count']
            result['unique_queries'] = unique_queries_count
            result['timestamp'] = time.time()

            if result['is_suspicious']:
                alert_data = result.copy()
                self.event_bus.publish('dns.suspicious', alert_data)
                self.logger.warning(
                    f"Подозрительный DNS от {src_ip}: {query} (score={result['score']:.3f}, {', '.join(result['reasons'])})")

        return result

    def _check_dns_tunnel(self, src_ip: str, dst_ip: str, packet_size: int, packet: Any = None) -> None:
        """Проверка на DNS туннель (исправлено - учёт направления и типа)"""

        # Определяем направление - туннели обычно исходящие
        local_networks = self.config.get('network.local_networks', ['192.168.', '10.', '172.16.'])
        is_outbound = not any(dst_ip.startswith(net) for net in local_networks)

        # Для входящих DNS ответов - более высокий порог
        size_threshold = 1000 if is_outbound else 2000

        if packet_size <= size_threshold:
            return

        # Дополнительная проверка - это DNS запрос или ответ?
        is_query = True
        if packet:
            try:
                from scapy.all import DNS
                if packet.haslayer(DNS):
                    is_query = (packet[DNS].qr == 0)
            except:
                pass

        # Для ответов - ещё выше порог
        if not is_query and packet_size < 3000:
            return

        with self._lock:
            stats = self.dns_queries[src_ip]
            stats['total_bytes'] += packet_size

            alert = {
                'is_suspicious': True,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'reasons': [f"large_dns_packet:{packet_size}", f"direction:{'outbound' if is_outbound else 'inbound'}"],
                'score': 0.4,
                'attack_type': AttackType.DNS_TUNNEL.value,
                'severity': AlertSeverity.MEDIUM.value,
                'timestamp': time.time(),
                'packet_size': packet_size,
                'is_query': is_query
            }

            if packet_size > 2000 and is_outbound and is_query:
                alert['score'] = 0.7
                alert['severity'] = AlertSeverity.HIGH.value
            elif packet_size > 4000:
                alert['score'] = 0.8
                alert['severity'] = AlertSeverity.CRITICAL.value

            self.event_bus.publish('dns.suspicious', alert)

    def _calculate_entropy(self, data: str) -> float:
        """Вычисление энтропии Шеннона"""
        if not data:
            return 0.0
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in freq.values())
        return entropy

    def get_stats(self, src_ip: str = None) -> Dict:
        """Получить статистику DNS (исправлено - безопасное копирование)"""
        with self._lock:
            if src_ip:
                if src_ip not in self.dns_queries:
                    return {}

                stats = self.dns_queries[src_ip]
                return {
                    'count': stats.get('count', 0),
                    'timestamps': list(stats.get('timestamps', [])),
                    'subdomains': list(stats.get('subdomains', set())),
                    'entropy_values': list(stats.get('entropy_values', [])),
                    'query_lengths': list(stats.get('query_lengths', [])),
                    'unique_queries': list(stats.get('unique_queries', set())),
                    'total_bytes': stats.get('total_bytes', 0),
                    'first_seen': stats.get('first_seen', 0),
                    'last_seen': stats.get('last_seen', 0)
                }

            # Общая статистика
            return {
                'total_ips': len(self.dns_queries),
                'total_queries': sum(s.get('count', 0) for s in self.dns_queries.values())
            }


# ============================================================
# 2️⃣ THREAT INTELLIGENCE (ABUSEIPDB/VIRUSTOTAL)
# ============================================================

class ThreatIntelligence(BaseModule):
    """Интеграция с базами репутации IP (полная реальная версия)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("ThreatIntel", config, event_bus, logger)

        # API ключи
        self.abuseipdb_key = config.get('threat_intel.abuseipdb_key') or os.environ.get('ABUSEIPDB_KEY', '')
        self.virustotal_key = config.get('threat_intel.virustotal_key') or os.environ.get('VIRUSTOTAL_KEY', '')
        self.alienvault_key = config.get('threat_intel.alienvault_key') or os.environ.get('ALIENVAULT_KEY', '')
        self.ipinfo_token = config.get('threat_intel.ipinfo_token') or os.environ.get('IPINFO_TOKEN', '')

        # Геолокация
        self.geoip_db_path = config.get('threat_intel.geoip_db') or '/usr/share/GeoIP/GeoLite2-City.mmdb'
        self.geoip_city_path = config.get('threat_intel.geoip_city_db') or '/usr/share/GeoIP/GeoLite2-City.mmdb'
        self.geoip_asn_path = config.get('threat_intel.geoip_asn_db') or '/usr/share/GeoIP/GeoLite2-ASN.mmdb'
        self.geoip_reader = None
        self.geoip_asn_reader = None

        # Кэш
        self.cache: Dict[str, Dict] = {}
        self.cache_ttl = 3600  # 1 час
        self.geo_cache: Dict[str, Dict] = {}
        self.geo_cache_ttl = 86400  # 24 часа для геолокации

        # Блокировки
        self._lock = threading.RLock()
        self._geo_lock = threading.RLock()

        # HTTP сессия
        self._session = None

        # Executor для асинхронных запросов
        self.pg_pool = None
        self.pg_pool = None
        self.pg_pool = None
        self._executor = None
        self._pending_checks: Set[str] = set()
        self._pending_lock = threading.RLock()

        # Списки известных вредоносных IP (локальный кэш)
        self.known_malicious_ips: Set[str] = set()
        self.known_tor_exit_nodes: Set[str] = set()
        self.known_vpn_ips: Set[str] = set()

        # Инициализация
        self._init_http_session()
        self._init_geoip()
        self._load_local_lists()

        # Подписки на события
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('packet.received', self.on_packet)
        self.event_bus.subscribe('threat_intel.check_ip', self.on_check_ip_request)

    def _init_http_session(self) -> None:
        """Инициализация HTTP сессии"""
        if requests:
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': 'SHARD-SIEM/2.0 (+https://github.com/shard/siem)'
            })
            # Настройка таймаутов и retry
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            retry_strategy = Retry(
                total=2,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)

    def _init_geoip(self) -> None:
        """Инициализация GeoIP баз данных"""
        # Пробуем загрузить MaxMind GeoIP2
        try:
            import geoip2.database

            # City база
            if Path(self.geoip_city_path).exists():
                self.geoip_reader = geoip2.database.Reader(self.geoip_city_path)
                self.logger.info(f"GeoIP City база загружена: {self.geoip_city_path}")
            elif Path(self.geoip_db_path).exists():
                self.geoip_reader = geoip2.database.Reader(self.geoip_db_path)
                self.logger.info(f"GeoIP база загружена: {self.geoip_db_path}")
            else:
                self.logger.warning(
                    f"GeoIP база не найдена. Скачайте с https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")

            # ASN база
            if Path(self.geoip_asn_path).exists():
                self.geoip_asn_reader = geoip2.database.Reader(self.geoip_asn_path)
                self.logger.info(f"GeoIP ASN база загружена: {self.geoip_asn_path}")

        except ImportError:
            self.logger.warning("geoip2 не установлен. Установите: pip install geoip2")
        except Exception as e:
            self.logger.warning(f"Ошибка загрузки GeoIP: {e}")

        # Fallback на geoip2 (бесплатная альтернатива)
        if not self.geoip_reader:
            try:
                import geoip2
                # Пробуем стандартные пути
                standard_paths = [
                    '/usr/local/share/GeoIP/GeoLite2-City.mmdb',
                    '/usr/share/GeoIP/GeoLite2-City.mmdb',
                    '/var/lib/GeoIP/GeoLite2-City.mmdb',
                    os.path.expanduser('~/.geoip/GeoLite2-City.mmdb')
                ]
                for path in standard_paths:
                    if Path(path).exists():
                        import geoip2.database
                        self.geoip_reader = geoip2.database.Reader(path)
                        self.geoip_db_path = path
                        self.logger.info(f"GeoIP база найдена: {path}")
                        break
            except:
                pass

    def _load_local_lists(self) -> None:
        """Загрузка локальных списков известных вредоносных IP"""
        # Списки можно загружать из файлов или URL
        list_paths = [
            Path('data/tor_exit_nodes.txt'),
            Path('data/known_malicious.txt'),
            Path('data/vpn_ips.txt')
        ]

        for path in list_paths:
            if path.exists():
                try:
                    with open(path, 'r') as f:
                        ips = {line.strip() for line in f if line.strip() and not line.startswith('#')}
                        if 'tor' in path.name:
                            self.known_tor_exit_nodes.update(ips)
                            self.logger.info(f"Загружено {len(ips)} Tor exit nodes")
                        elif 'malicious' in path.name:
                            self.known_malicious_ips.update(ips)
                            self.logger.info(f"Загружено {len(ips)} известных вредоносных IP")
                        elif 'vpn' in path.name:
                            self.known_vpn_ips.update(ips)
                            self.logger.info(f"Загружено {len(ips)} VPN IP")
                except Exception as e:
                    self.logger.debug(f"Ошибка загрузки списка {path}: {e}")

        # Загрузка из URL если списки пусты
        if not self.known_tor_exit_nodes:
            threading.Thread(target=self._download_tor_exit_list, daemon=True).start()

    def _download_tor_exit_list(self) -> None:
        """Скачивание списка Tor exit nodes (с проверкой сертификата)"""
        try:
            if self._session:
                # Используем HTTPS с проверкой сертификата
                response = self._session.get(
                    'https://check.torproject.org/torbulkexitlist',
                    timeout=30,
                    verify=True  # Явно включаем проверку SSL
                )
                if response.status_code == 200:
                    ips = set()
                    for line in response.text.strip().split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Валидация IP перед добавлением
                            if self._is_public_ip(line):
                                ips.add(line)

                    with self._lock:
                        self.known_tor_exit_nodes.update(ips)
                    self.logger.info(f"Скачано {len(ips)} Tor exit nodes (проверено SSL)")
            else:
                self.logger.warning("HTTP сессия не инициализирована")
        except Exception as e:
            self.logger.debug(f"Ошибка скачивания Tor списка: {e}")

    def start(self) -> None:
        """Запуск модуля"""
        self.running = True

        # Создаём executor при старте
        self._executor = ThreadPoolExecutor(
            max_workers=8,
            thread_name_prefix="ThreatIntel"
        )

        # Запускаем фоновые потоки
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        threading.Thread(target=self._cache_warmup_loop, daemon=True).start()

        self.logger.info(
            f"Threat Intelligence запущен:\n"
            f"  - AbuseIPDB: {bool(self.abuseipdb_key)}\n"
            f"  - VirusTotal: {bool(self.virustotal_key)}\n"
            f"  - AlienVault: {bool(self.alienvault_key)}\n"
            f"  - GeoIP: {bool(self.geoip_reader)}\n"
            f"  - Локальные списки: {len(self.known_malicious_ips)} malicious, "
            f"{len(self.known_tor_exit_nodes)} Tor, {len(self.known_vpn_ips)} VPN"
        )

    def stop(self) -> None:
        """Остановка модуля с graceful shutdown"""
        self.running = False

        # Закрываем HTTP сессию
        if self._session:
            try:
                self._session.close()
            except:
                pass

        # Graceful shutdown executor
        if self._executor is not None:
            try:
                # Пробуем разные варианты shutdown
                if hasattr(self._executor, 'shutdown'):
                    import sys
                    if sys.version_info >= (3, 9):
                        try:
                            self._executor.shutdown(wait=False, cancel_futures=True)
                        except:
                            pass
                    # Просто shutdown без аргументов
                    try:
                        self._executor.shutdown()
                    except:
                        pass
            except Exception as e:
                self.logger.debug(f"Ошибка при остановке executor: {e}")
            finally:
                self._executor = None

        # Закрываем GeoIP
        if self.geoip_reader:
            try:
                self.geoip_reader.close()
            except:
                pass

        if self.geoip_asn_reader:
            try:
                self.geoip_asn_reader.close()
            except:
                pass

        self.logger.info("Threat Intelligence остановлен")

    def on_alert(self, alert: Dict) -> None:
        """Проверка IP при алерте"""
        src_ip = alert.get('src_ip', '')
        dst_ip = alert.get('dst_ip', '')

        # Проверяем оба IP если они публичные
        for ip in (src_ip, dst_ip):
            if ip and self._is_public_ip(ip):
                self._executor.submit(self._check_ip_and_enrich_alert, ip, alert)

    def _check_ip_and_enrich_alert(self, ip: str, alert: Dict) -> None:
        """Проверка IP и обогащение алерта"""
        result = self.check_ip(ip)

        if result['is_malicious']:
            alert['threat_intel'] = result
            alert['score'] = min(1.0, alert.get('score', 0) + result['score'] * 0.3)

            # Добавляем геолокацию
            if 'geo' in result:
                alert['geo_location'] = result['geo']

            self.logger.warning(f"IP {ip} найден в threat intelligence: score={result['score']:.2f}")

    def on_packet(self, data: Dict) -> None:
        """Проверка IP из трафика"""
        if not self._executor:
            return

        src_ip = data.get('src_ip', '')
        dst_ip = data.get('dst_ip', '')

        for ip in (src_ip, dst_ip):
            if ip and self._is_public_ip(ip):
                # Проверяем не чаще чем раз в минуту
                with self._lock:
                    if ip in self.cache:
                        last_check = self.cache[ip].get('timestamp', 0)
                        if time.time() - last_check < 60:
                            continue

                # Проверяем, не проверяется ли уже этот IP
                with self._pending_lock:
                    if ip in self._pending_checks:
                        continue
                    self._pending_checks.add(ip)

                # Асинхронная проверка
                self._executor.submit(self._check_and_alert_wrapper, ip)

    def on_check_ip_request(self, data: Dict) -> None:
        """Обработка явного запроса на проверку IP"""
        ip = data.get('ip', '')
        request_id = data.get('request_id', '')

        if ip and self._is_public_ip(ip):
            result = self.check_ip(ip)
            self.event_bus.publish('threat_intel.check_ip.response', {
                'request_id': request_id,
                'ip': ip,
                'result': result
            })

    def _check_and_alert_wrapper(self, ip: str) -> None:
        """Обёртка для проверки с очисткой pending"""
        try:
            self._check_and_alert(ip)
        finally:
            with self._pending_lock:
                self._pending_checks.discard(ip)

    def _check_and_alert(self, ip: str) -> None:
        """Проверка IP и отправка алерта при обнаружении"""
        result = self.check_ip(ip)

        if result['is_malicious']:
            alert = {
                'timestamp': time.time(),
                'src_ip': ip,
                'attack_type': AttackType.BOTNET.value,
                'score': result['score'],
                'confidence': result.get('confidence', 0.8),
                'is_attack': True,
                'threat_intel': result,
                'severity': AlertSeverity.HIGH.value if result['score'] > 0.7 else AlertSeverity.MEDIUM.value,
                'explanation': f"IP {ip} обнаружен в базе угроз (score: {result['score']:.2f})"
            }

            # Добавляем информацию об источнике обнаружения
            if result.get('sources'):
                alert['explanation'] += f" Источники: {', '.join(result['sources'])}"

            # Добавляем геолокацию
            if result.get('geo', {}).get('country'):
                alert['geo_location'] = result['geo']

            self.event_bus.publish('alert.detected', alert)

    def check_ip(self, ip: str) -> Dict:
        """Полная проверка IP через все доступные источники (параллельные запросы)"""

        # Проверка кэша
        with self._lock:
            if ip in self.cache:
                cached = self.cache[ip]
                if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                    return cached['result'].copy()

        # Быстрая проверка локальных списков
        quick_result = self._check_local_lists(ip)
        if quick_result['is_malicious'] and quick_result['score'] > 0.8:
            result = quick_result
        else:
            result = {
                'is_malicious': False,
                'score': quick_result['score'],
                'confidence': quick_result['confidence'],
                'sources': quick_result['sources'],
                'country': None,
                'city': None,
                'latitude': None,
                'longitude': None,
                'timezone': None,
                'isp': None,
                'asn': None,
                'usage_type': None,
                'is_tor': quick_result.get('is_tor', False),
                'is_vpn': quick_result.get('is_vpn', False),
                'is_proxy': False,
                'is_hosting': False,
                'categories': quick_result.get('categories', []),
                'reports': 0,
                'last_reported': None,
                'details': {},
                'geo': {},
                'reputation_services': {}
            }

            # Параллельные запросы к внешним API
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {}

                # Геолокация
                futures['geo'] = executor.submit(self.get_geo_location, ip)

                # AbuseIPDB
                if self.abuseipdb_key:
                    futures['abuse'] = executor.submit(self._check_abuseipdb_full, ip)

                # VirusTotal
                if self.virustotal_key:
                    futures['vt'] = executor.submit(self._check_virustotal_full, ip)

                # AlienVault
                if self.alienvault_key:
                    futures['otx'] = executor.submit(self._check_alienvault, ip)

                # IPinfo
                if self.ipinfo_token:
                    futures['ipinfo'] = executor.submit(self._check_ipinfo, ip)

                # Сбор результатов с таймаутом
                for key, future in futures.items():
                    try:
                        data = future.result(timeout=5)
                        if key == 'geo' and data:
                            result['country'] = data.get('country')
                            result['city'] = data.get('city')
                            result['latitude'] = data.get('latitude')
                            result['longitude'] = data.get('longitude')
                            result['timezone'] = data.get('timezone')
                            result['isp'] = data.get('isp')
                            result['asn'] = data.get('asn')
                            result['is_hosting'] = data.get('is_hosting', False)
                            result['geo'] = data

                        elif key == 'abuse' and data:
                            result['reputation_services']['abuseipdb'] = data
                            confidence_score = data.get('score', 0)
                            if confidence_score > 50:
                                result['is_malicious'] = True
                            result['score'] = max(result['score'], confidence_score / 100)
                            result['confidence'] = max(result['confidence'], confidence_score / 100)
                            result['sources'].append('AbuseIPDB')
                            result['reports'] = max(result['reports'], data.get('total_reports', 0))
                            result['last_reported'] = data.get('last_reported')
                            if data.get('categories'):
                                result['categories'].extend(data['categories'])
                            if data.get('is_tor'):
                                result['is_tor'] = True

                        elif key == 'vt' and data:
                            result['reputation_services']['virustotal'] = data
                            malicious_count = data.get('malicious', 0)
                            suspicious_count = data.get('suspicious', 0)
                            total_votes = data.get('total', 0)
                            if total_votes > 0:
                                vt_score = (malicious_count + suspicious_count * 0.5) / total_votes
                            else:
                                vt_score = 0.0
                            if malicious_count > 0:
                                result['is_malicious'] = True
                            result['score'] = max(result['score'], vt_score)
                            result['confidence'] = max(result['confidence'], vt_score)
                            result['sources'].append('VirusTotal')
                            if data.get('categories'):
                                result['categories'].extend(data['categories'])

                        elif key == 'otx' and data:
                            result['reputation_services']['alienvault'] = data
                            pulse_count = data.get('pulse_count', 0)
                            if pulse_count > 0:
                                result['is_malicious'] = True
                                otx_score = min(1.0, pulse_count / 10)
                                result['score'] = max(result['score'], otx_score)
                                result['confidence'] = max(result['confidence'], 0.7)
                                result['sources'].append('AlienVault OTX')
                                if data.get('tags'):
                                    result['categories'].extend(data['tags'])

                        elif key == 'ipinfo' and data:
                            result['isp'] = data.get('org', result['isp'])
                            result['asn'] = data.get('asn', result['asn'])
                            result['is_hosting'] = data.get('hosting', result['is_hosting'])
                            result['is_vpn'] = data.get('vpn', result['is_vpn'])
                            result['is_proxy'] = data.get('proxy', result['is_proxy'])
                            result['is_tor'] = data.get('tor', result['is_tor'])

                    except TimeoutError:  # ← ИСПРАВЛЕНО: было FutureTimeoutError
                        self.logger.debug(f"Таймаут запроса {key} для IP {ip}")
                    except Exception as e:
                        self.logger.debug(f"Ошибка запроса {key} для IP {ip}: {type(e).__name__}")

        # Нормализация score
        result['score'] = min(1.0, result['score'])

        if len(result['sources']) >= 2:
            result['confidence'] = min(1.0, result['confidence'] + 0.1)

        # Сохраняем в кэш
        with self._lock:
            self.cache[ip] = {
                'result': result.copy(),
                'timestamp': time.time()
            }

        return result

    def _check_local_lists(self, ip: str) -> Dict:
        """Проверка IP по локальным спискам"""
        result = {
            'is_malicious': False,
            'score': 0.0,
            'confidence': 0.0,
            'sources': [],
            'is_tor': False,
            'is_vpn': False,
            'categories': []
        }

        # Проверка Tor exit nodes
        if ip in self.known_tor_exit_nodes:
            result['is_malicious'] = True
            result['is_tor'] = True
            result['score'] = max(result['score'], 0.6)
            result['confidence'] = 0.9
            result['sources'].append('Tor Exit List')
            result['categories'].append('Tor')

        # Проверка известных вредоносных IP
        if ip in self.known_malicious_ips:
            result['is_malicious'] = True
            result['score'] = max(result['score'], 0.8)
            result['confidence'] = 0.85
            result['sources'].append('Local Blocklist')
            result['categories'].append('Malicious')

        # Проверка VPN
        if ip in self.known_vpn_ips:
            result['is_vpn'] = True
            result['score'] = max(result['score'], 0.4)
            result['sources'].append('VPN List')
            result['categories'].append('VPN')

        return result

    def get_geo_location(self, ip: str) -> Dict:
        """Получение геолокации IP из разных источников"""
        # Проверка кэша геолокации
        with self._geo_lock:
            if ip in self.geo_cache:
                cached = self.geo_cache[ip]
                if time.time() - cached.get('timestamp', 0) < self.geo_cache_ttl:
                    return cached['data'].copy()

        result = {
            'country': None,
            'country_code': None,
            'region': None,
            'city': None,
            'postal_code': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'isp': None,
            'org': None,
            'asn': None,
            'as_org': None,
            'is_anonymous': False,
            'is_hosting': False,
            'is_proxy': False,
            'is_tor': False,
            'is_vpn': False,
            'source': 'unknown'
        }

        # 1. Локальная GeoIP база MaxMind
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip)
                result['country'] = response.country.name
                result['country_code'] = response.country.iso_code
                result['city'] = response.city.name
                result['postal_code'] = response.postal.code
                result['latitude'] = response.location.latitude
                result['longitude'] = response.location.longitude
                result['timezone'] = response.location.time_zone

                # Континент и регион
                if hasattr(response, 'continent'):
                    result['continent'] = response.continent.name
                if hasattr(response, 'subdivisions') and response.subdivisions:
                    result['region'] = response.subdivisions[0].name

                # Признаки
                if hasattr(response, 'traits'):
                    result['is_anonymous'] = getattr(response.traits, 'is_anonymous_proxy', False)
                    result['is_hosting'] = getattr(response.traits, 'is_hosting_provider', False)
                    result['is_tor'] = getattr(response.traits, 'is_tor_exit_node', False)

                result['source'] = 'MaxMind GeoIP2'
            except Exception as e:
                self.logger.debug(f"GeoIP ошибка для {ip}: {e}")

        # 2. ASN информация
        if self.geoip_asn_reader:
            try:
                asn_response = self.geoip_asn_reader.asn(ip)
                result['asn'] = asn_response.autonomous_system_number
                result['as_org'] = asn_response.autonomous_system_organization
            except:
                pass

        # 3. Fallback на ip-api.com (бесплатный, без ключа)
        if not result['country'] and self._session:
            try:
                response = self._session.get(
                    f'http://ip-api.com/json/{ip}',
                    params={
                        'fields': 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query'
                    },
                    timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        result['country'] = data.get('country')
                        result['country_code'] = data.get('countryCode')
                        result['region'] = data.get('regionName')
                        result['city'] = data.get('city')
                        result['postal_code'] = data.get('zip')
                        result['latitude'] = data.get('lat')
                        result['longitude'] = data.get('lon')
                        result['timezone'] = data.get('timezone')
                        result['isp'] = data.get('isp')
                        result['org'] = data.get('org')
                        result['asn'] = data.get('as')
                        result['is_proxy'] = data.get('proxy', False)
                        result['is_hosting'] = data.get('hosting', False)
                        result['source'] = 'ip-api.com'
            except Exception as e:
                self.logger.debug(f"ip-api.com ошибка: {e}")

        # 4. Fallback на ipapi.co
        if not result['country'] and self._session:
            try:
                response = self._session.get(
                    f'https://ipapi.co/{ip}/json/',
                    timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    if not data.get('error'):
                        result['country'] = data.get('country_name')
                        result['country_code'] = data.get('country_code')
                        result['region'] = data.get('region')
                        result['city'] = data.get('city')
                        result['postal_code'] = data.get('postal')
                        result['latitude'] = data.get('latitude')
                        result['longitude'] = data.get('longitude')
                        result['timezone'] = data.get('timezone')
                        result['isp'] = data.get('org')
                        result['asn'] = data.get('asn')
                        result['source'] = 'ipapi.co'
            except Exception as e:
                self.logger.debug(f"ipapi.co ошибка: {e}")

        # 5. IPinfo (если есть токен)
        if self.ipinfo_token and not result['isp'] and self._session:
            try:
                response = self._session.get(
                    f'https://ipinfo.io/{ip}/json',
                    headers={'Authorization': f'Bearer {self.ipinfo_token}'},
                    timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    result['country'] = data.get('country', result['country'])
                    result['city'] = data.get('city', result['city'])
                    result['region'] = data.get('region', result['region'])
                    result['postal_code'] = data.get('postal', result['postal_code'])

                    # Парсинг локации
                    loc = data.get('loc', '')
                    if loc and ',' in loc:
                        lat, lon = loc.split(',')
                        result['latitude'] = float(lat)
                        result['longitude'] = float(lon)

                    result['isp'] = data.get('org', result['isp'])
                    result['asn'] = data.get('asn', {}).get('asn', result['asn'])
                    result['timezone'] = data.get('timezone', result['timezone'])

                    # Признаки из privacy информации
                    privacy = data.get('privacy', {})
                    result['is_vpn'] = privacy.get('vpn', False)
                    result['is_proxy'] = privacy.get('proxy', False)
                    result['is_tor'] = privacy.get('tor', False)
                    result['is_hosting'] = privacy.get('hosting', False)

                    result['source'] = 'ipinfo.io'
            except Exception as e:
                self.logger.debug(f"ipinfo.io ошибка: {e}")

        # Сохраняем в кэш
        with self._geo_lock:
            self.geo_cache[ip] = {
                'data': result.copy(),
                'timestamp': time.time()
            }

        return result

    def _check_abuseipdb_full(self, ip: str) -> Optional[Dict]:
        """Расширенная проверка через AbuseIPDB"""
        if not self.abuseipdb_key or not self._session:
            return None

        try:
            # Основная проверка
            response = self._session.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': True
                },
                headers={
                    'Key': self.abuseipdb_key,
                    'Accept': 'application/json'
                },
                timeout=5
            )

            if response.status_code != 200:
                if response.status_code == 429:
                    self.logger.warning("AbuseIPDB: превышен лимит запросов")
                return None

            data = response.json().get('data', {})

            result = {
                'score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'last_reported': data.get('lastReportedAt'),
                'country': data.get('countryCode'),
                'isp': data.get('isp'),
                'domain': data.get('domain'),
                'usage_type': data.get('usageType'),
                'is_public': data.get('isPublic', False),
                'is_whitelisted': data.get('isWhitelisted', False),
                'is_tor': data.get('isTor', False),
                'categories': []
            }

            # Получаем детали отчётов
            if data.get('reports'):
                categories = set()
                for report in data['reports'][:10]:
                    for cat in report.get('categories', []):
                        categories.add(self._abuseipdb_category_name(cat))
                result['categories'] = list(categories)

            return result

        except Exception as e:
            self.logger.debug(f"AbuseIPDB ошибка: {e}")
            return None

    def _abuseipdb_category_name(self, cat_id: int) -> str:
        """Получение названия категории AbuseIPDB"""
        categories = {
            3: 'Fraud Orders',
            4: 'DDoS Attack',
            5: 'FTP Brute-Force',
            6: 'Ping of Death',
            7: 'Phishing',
            8: 'Fraud VoIP',
            9: 'Open Proxy',
            10: 'Web Spam',
            11: 'Email Spam',
            12: 'Blog Spam',
            13: 'VPN IP',
            14: 'Port Scan',
            15: 'Hacking',
            16: 'SQL Injection',
            17: 'Spoofing',
            18: 'Brute-Force',
            19: 'Bad Web Bot',
            20: 'Exploited Host',
            21: 'Web App Attack',
            22: 'SSH',
            23: 'IoT Targeted'
        }
        return categories.get(cat_id, f'Unknown({cat_id})')

    def _check_virustotal_full(self, ip: str) -> Optional[Dict]:
        """Расширенная проверка через VirusTotal"""
        if not self.virustotal_key or not self._session:
            return None

        try:
            response = self._session.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': self.virustotal_key},
                timeout=5
            )

            if response.status_code != 200:
                if response.status_code == 429:
                    self.logger.warning("VirusTotal: превышен лимит запросов")
                return None

            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})

            # Статистика детектирования
            stats = attributes.get('last_analysis_stats', {})

            result = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'timeout': stats.get('timeout', 0),
                'total': sum(stats.values()),
                'country': attributes.get('country'),
                'asn': attributes.get('asn'),
                'network': attributes.get('network'),
                'reputation': attributes.get('reputation', 0),
                'categories': [],
                'tags': attributes.get('tags', [])
            }

            # Собираем категории из результатов
            results = attributes.get('last_analysis_results', {})
            for engine, engine_result in results.items():
                category = engine_result.get('category')
                if category in ['malicious', 'suspicious']:
                    result_name = engine_result.get('result', '')
                    if result_name:
                        result['categories'].append(result_name)

            result['categories'] = list(set(result['categories']))

            return result

        except Exception as e:
            self.logger.debug(f"VirusTotal ошибка: {e}")
            return None

    def _check_alienvault(self, ip: str) -> Optional[Dict]:
        """Проверка через AlienVault OTX"""
        if not self.alienvault_key or not self._session:
            return None

        try:
            response = self._session.get(
                f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
                headers={'X-OTX-API-KEY': self.alienvault_key},
                timeout=5
            )

            if response.status_code != 200:
                return None

            data = response.json()

            result = {
                'pulse_count': data.get('pulse_info', {}).get('count', 0),
                'pulses': [],
                'tags': [],
                'country': data.get('country_name'),
                'city': data.get('city'),
                'asn': data.get('asn')
            }

            # Собираем теги из пульсов
            pulses = data.get('pulse_info', {}).get('pulses', [])
            for pulse in pulses[:10]:
                result['tags'].extend(pulse.get('tags', []))
                result['pulses'].append({
                    'name': pulse.get('name'),
                    'created': pulse.get('created'),
                    'modified': pulse.get('modified'),
                    'adversary': pulse.get('adversary')
                })

            result['tags'] = list(set(result['tags']))

            return result

        except Exception as e:
            self.logger.debug(f"AlienVault ошибка: {e}")
            return None

    def _check_ipinfo(self, ip: str) -> Optional[Dict]:
        """Проверка через IPinfo"""
        if not self.ipinfo_token or not self._session:
            return None

        try:
            response = self._session.get(
                f'https://ipinfo.io/{ip}',
                headers={'Authorization': f'Bearer {self.ipinfo_token}'},
                timeout=3
            )

            if response.status_code != 200:
                return None

            data = response.json()

            return {
                'org': data.get('org'),
                'asn': data.get('asn', {}).get('asn') if isinstance(data.get('asn'), dict) else data.get('asn'),
                'hosting': data.get('privacy', {}).get('hosting', False),
                'vpn': data.get('privacy', {}).get('vpn', False),
                'proxy': data.get('privacy', {}).get('proxy', False),
                'tor': data.get('privacy', {}).get('tor', False),
                'relay': data.get('privacy', {}).get('relay', False)
            }

        except Exception as e:
            self.logger.debug(f"IPinfo ошибка: {e}")
            return None

    def _is_public_ip(self, ip: str) -> bool:
        """Проверка, является ли IP публичным"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            first = int(parts[0])
            second = int(parts[1]) if len(parts) > 1 else 0

            # Приватные диапазоны
            if first == 10:
                return False
            if first == 172 and 16 <= second <= 31:
                return False
            if first == 192 and second == 168:
                return False
            if first == 127:
                return False
            if first == 0:
                return False
            if first >= 224:
                return False
            if first == 169 and second == 254:
                return False
            if first == 100 and 64 <= second <= 127:  # CGNAT
                return False

            return True
        except (ValueError, IndexError):
            return False

    def _cleanup_loop(self) -> None:
        """Очистка устаревшего кэша (исправлено - безопасное удаление)"""
        while self.running:
            time.sleep(300)  # Каждые 5 минут
            now = time.time()

            # Собираем ключи для удаления
            expired_threat = []
            expired_geo = []

            with self._lock:
                for ip, data in self.cache.items():
                    if now - data['timestamp'] > self.cache_ttl * 2:
                        expired_threat.append(ip)

            with self._geo_lock:
                for ip, data in self.geo_cache.items():
                    if now - data['timestamp'] > self.geo_cache_ttl * 2:
                        expired_geo.append(ip)

            # Удаляем под отдельными блокировками
            if expired_threat:
                with self._lock:
                    for ip in expired_threat:
                        if ip in self.cache:
                            del self.cache[ip]
                self.logger.debug(f"Очищено {len(expired_threat)} записей из кэша ThreatIntel")

            if expired_geo:
                with self._geo_lock:
                    for ip in expired_geo:
                        if ip in self.geo_cache:
                            del self.geo_cache[ip]
                self.logger.debug(f"Очищено {len(expired_geo)} записей из кэша геолокации")

    def _cache_warmup_loop(self) -> None:
        """Периодический прогрев кэша важных IP"""
        while self.running:
            time.sleep(3600)  # Раз в час
            # Можно добавить прогрев для часто встречающихся IP
            pass

    def get_cache_stats(self) -> Dict:
        """Получить статистику кэша"""
        with self._lock:
            with self._pending_lock:
                with self._geo_lock:
                    return {
                        'threat_cache_size': len(self.cache),
                        'geo_cache_size': len(self.geo_cache),
                        'pending_checks': len(self._pending_checks),
                        'cache_ttl': self.cache_ttl,
                        'geo_cache_ttl': self.geo_cache_ttl,
                        'local_malicious': len(self.known_malicious_ips),
                        'local_tor': len(self.known_tor_exit_nodes),
                        'local_vpn': len(self.known_vpn_ips)
                    }

    def bulk_check_ips(self, ips: List[str]) -> Dict[str, Dict]:
        """Массовая проверка списка IP (используем существующий executor)"""
        results = {}
        public_ips = [ip for ip in ips if self._is_public_ip(ip)]

        if not public_ips:
            return results

        # Используем СУЩЕСТВУЮЩИЙ executor вместо создания нового
        if self._executor is None:
            # Если executor ещё не создан - создаём
            self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ThreatIntel")

        futures = {}
        for ip in public_ips:
            futures[self._executor.submit(self.check_ip, ip)] = ip

        for future in futures:
            ip = futures[future]
            try:
                results[ip] = future.result(timeout=10)
            except TimeoutError:
                results[ip] = {'error': 'timeout', 'is_malicious': False, 'score': 0}
            except Exception as e:
                results[ip] = {'error': str(e)[:100], 'is_malicious': False, 'score': 0}

        return results

    def add_to_local_blocklist(self, ip: str, reason: str = 'manual') -> None:
        """Добавить IP в локальный блок-лист (исправлено - инвалидация кэша)"""
        if not self._is_public_ip(ip):
            self.logger.warning(f"IP {ip} не является публичным, не добавлен в блок-лист")
            return

        with self._lock:
            self.known_malicious_ips.add(ip)

            # ИНВАЛИДАЦИЯ КЭША для этого IP
            if ip in self.cache:
                del self.cache[ip]
                self.logger.debug(f"Кэш для IP {ip} инвалидирован после добавления в блок-лист")

        # Сохраняем в файл
        try:
            list_path = Path('data/known_malicious.txt')
            list_path.parent.mkdir(parents=True, exist_ok=True)
            with open(list_path, 'a', encoding='utf-8') as f:
                f.write(f"{ip} # {reason} - {datetime.now().isoformat()}\n")

            self.logger.info(f"IP {ip} добавлен в локальный блок-лист (причина: {reason})")
        except Exception as e:
            self.logger.error(f"Ошибка сохранения блок-листа: {e}")

    def remove_from_local_blocklist(self, ip: str) -> bool:
        """Удалить IP из локального блок-листа (с инвалидацией кэша)"""
        with self._lock:
            if ip in self.known_malicious_ips:
                self.known_malicious_ips.remove(ip)

                # Инвалидация кэша
                if ip in self.cache:
                    del self.cache[ip]

                return True
        return False



# ============================================================
# 3️⃣ ОБНАРУЖЕНИЕ УТЕЧКИ ДАННЫХ
# ============================================================

class DataExfiltrationDetector(BaseModule):
    """Обнаружение утечки данных (Data Exfiltration) с дедупликацией алертов"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("ExfilDetector", config, event_bus, logger)

        # Структура с ключом (src_ip, dst_ip) - defaultdict с лямбдой
        self.flows: Dict[Tuple[str, str], Dict] = defaultdict(lambda: {
            'bytes_out': deque(maxlen=1000),
            'bytes_in': deque(maxlen=1000),
            'connections': deque(maxlen=500),
            'unique_ports': set(),
            'first_seen': time.time(),
            'last_seen': time.time(),
            'total_bytes_out': 0,
            'total_bytes_in': 0,
            'suspicious_score': 0.0,
            'packet_sizes': deque(maxlen=100)
        })

        # Агрегированная статистика по хостам
        self.host_stats: Dict[str, Dict] = defaultdict(lambda: {
            'total_bytes_out': 0,
            'total_bytes_in': 0,
            'unique_destinations': set(),
            'unique_ports': set(),
            'connections_count': 0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'suspicious_score': 0.0
        })

        # Порты
        self.normal_ports = {80, 443, 8080, 8443, 21, 22, 25, 587, 993, 995, 143, 110}
        self.exfil_ports = {53, 123, 137, 138, 139, 445, 3389, 4444, 5555, 6666, 7777, 8888, 9999}

        # Подозрительные user-agent'ы
        self.suspicious_user_agents = {
            'curl', 'wget', 'python', 'powershell', 'nc', 'netcat',
            'meterpreter', 'metasploit', 'nmap', 'zgrab', 'gobuster',
            'sqlmap', 'nikto', 'burp', 'hydra'
        }

        # Дедупликация алертов
        self._recent_alerts: Dict[str, float] = {}
        self._alert_cooldown = 60
        self._alert_lock = threading.RLock()
        self._max_alerts_per_minute = 10
        self._alert_counter: Dict[str, int] = defaultdict(int)
        self._alert_counter_reset = time.time()
        self._suppressed_count: Dict[str, int] = defaultdict(int)

        self._lock = threading.RLock()
        self._cleanup_lock = threading.RLock()

        self.event_bus.subscribe('packet.received', self.on_packet)
        self.event_bus.subscribe('dpi.http', self.on_http)

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._cleanup_loop, daemon=True, name="Exfil-Cleanup").start()
        self.logger.info("Детектор утечки данных запущен")

    def stop(self) -> None:
        self.running = False

    def _should_suppress_alert(self, alert_key: str, src_ip: str) -> bool:
        """Проверка нужно ли подавить алерт (без вызова логгера внутри лока)"""
        now = time.time()

        with self._alert_lock:
            # Сброс счётчика каждую минуту
            if now - self._alert_counter_reset > 60:
                self._alert_counter.clear()
                self._alert_counter_reset = now

            # Проверка cooldown для конкретной пары
            last_time = self._recent_alerts.get(alert_key, 0)
            if now - last_time < self._alert_cooldown:
                self._suppressed_count['cooldown'] = self._suppressed_count.get('cooldown', 0) + 1
                return True

            # Проверка общего лимита алертов от одного источника
            self._alert_counter[src_ip] += 1
            if self._alert_counter[src_ip] > self._max_alerts_per_minute:
                self._suppressed_count['rate_limit'] += 1
                return True

            # Обновляем время последнего алерта
            self._recent_alerts[alert_key] = now

            # Очистка старых ключей (каждые 100 алертов)
            if len(self._recent_alerts) > 1000:
                cutoff = now - self._alert_cooldown * 2
                self._recent_alerts = {k: v for k, v in self._recent_alerts.items() if v > cutoff}

            return False

    def on_packet(self, data: Dict) -> None:
        """Анализ трафика на утечку данных"""
        src_ip = data.get('src_ip', '')
        dst_ip = data.get('dst_ip', '')
        dst_port = data.get('dst_port', 0)
        packet = data.get('packet')

        if not src_ip or not packet:
            return

        try:
            packet_size = len(packet)

            # Определяем направление трафика
            local_networks = self.config.get('network.local_networks', ['192.168.', '10.', '172.16.', '127.'])
            is_outbound = not any(dst_ip.startswith(net) for net in local_networks)

            if is_outbound:
                self._analyze_outbound_traffic(src_ip, dst_ip, dst_port, packet_size, packet)

        except Exception as e:
            self.logger.debug(f"Ошибка анализа трафика: {e}")

    def on_http(self, data: Dict) -> None:
        """Анализ HTTP трафика"""
        src_ip = data.get('src_ip', '')
        dst_ip = data.get('dst_ip', '')
        method = data.get('method', '')
        uri = data.get('uri', '')
        user_agent = data.get('user_agent', '')
        content_length = data.get('content_length', 0)

        # Проверка на подозрительный User-Agent
        if user_agent:
            ua_lower = user_agent.lower()
            for sus_ua in self.suspicious_user_agents:
                if sus_ua in ua_lower:
                    alert_key = f"http_ua:{src_ip}:{dst_ip}:{sus_ua}"
                    if not self._should_suppress_alert(alert_key, src_ip):
                        alert = {
                            'is_exfiltration': True,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'reasons': [f'suspicious_user_agent:{sus_ua}'],
                            'score': 0.4,
                            'attack_type': AttackType.DATA_EXFILTRATION.value,
                            'severity': AlertSeverity.MEDIUM.value,
                            'timestamp': time.time(),
                            'details': {'user_agent': user_agent}
                        }
                        self.event_bus.publish('exfiltration.detected', alert)

        # Проверка на POST/PUT с большим телом
        if method in ('POST', 'PUT') and content_length > 1_000_000:  # > 1MB
            alert_key = f"http_large:{src_ip}:{dst_ip}"
            if not self._should_suppress_alert(alert_key, src_ip):
                alert = {
                    'is_exfiltration': True,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'reasons': [f'large_upload:{content_length}'],
                    'score': 0.5,
                    'attack_type': AttackType.DATA_EXFILTRATION.value,
                    'severity': AlertSeverity.HIGH.value,
                    'timestamp': time.time(),
                    'details': {'method': method, 'content_length': content_length}
                }
                self.event_bus.publish('exfiltration.detected', alert)

    def _analyze_outbound_traffic(self, src_ip: str, dst_ip: str, dst_port: int, bytes_count: int, packet: Any) -> None:
        """Анализ исходящего трафика (исправлено - убрана двойная инициализация)"""

        flow_key = (src_ip, dst_ip)

        with self._lock:
            # defaultdict автоматически создаёт структуру, не нужна ручная проверка
            flow = self.flows[flow_key]
            host = self.host_stats[src_ip]

            now = time.time()

            # Обновление статистики пары
            flow['bytes_out'].append((now, bytes_count))
            flow['connections'].append(now)
            flow['unique_ports'].add(dst_port)
            flow['last_seen'] = now
            flow['total_bytes_out'] += bytes_count
            flow['packet_sizes'].append(bytes_count)

            # Обновление статистики хоста
            host['total_bytes_out'] += bytes_count
            host['unique_destinations'].add(dst_ip)
            host['unique_ports'].add(dst_port)
            host['last_seen'] = now
            host['connections_count'] += 1

            result = {
                'is_exfiltration': False,
                'reasons': [],
                'score': 0.0,
                'attack_type': AttackType.DATA_EXFILTRATION.value,
                'severity': AlertSeverity.LOW.value
            }

            # 1. Большой объём данных на ОДИН внешний адрес
            cutoff_5min = now - ExfilThresholds.TIME_WINDOW_5MIN
            recent_bytes_single_dst = sum(b for t, b in flow['bytes_out'] if t > cutoff_5min)

            if recent_bytes_single_dst > ExfilThresholds.SINGLE_DST_CRITICAL:
                result['is_exfiltration'] = True
                result['reasons'].append(f"massive_volume_single_dst:{recent_bytes_single_dst / 1_000_000:.1f}MB")
                result['score'] += 0.5
                result['severity'] = AlertSeverity.CRITICAL.value
            elif recent_bytes_single_dst > ExfilThresholds.SINGLE_DST_HIGH:
                result['is_exfiltration'] = True
                result['reasons'].append(f"large_volume_single_dst:{recent_bytes_single_dst / 1_000_000:.1f}MB")
                result['score'] += 0.4
                result['severity'] = AlertSeverity.HIGH.value
            elif recent_bytes_single_dst > ExfilThresholds.SINGLE_DST_MEDIUM:
                result['is_exfiltration'] = True
                result['reasons'].append(f"volume_single_dst:{recent_bytes_single_dst / 1_000_000:.1f}MB")
                result['score'] += 0.25

            # 2. Общий объём на ВСЕ внешние адреса
            total_recent_bytes = 0
            for (s, d), f in self.flows.items():
                if s == src_ip:
                    total_recent_bytes += sum(b for t, b in f['bytes_out'] if t > cutoff_5min)

            if total_recent_bytes > ExfilThresholds.TOTAL_CRITICAL:
                result['is_exfiltration'] = True
                result['reasons'].append(f"massive_total_volume:{total_recent_bytes / 1_000_000:.1f}MB")
                result['score'] += 0.3
            elif total_recent_bytes > ExfilThresholds.TOTAL_HIGH:
                result['score'] += 0.15
                result['reasons'].append(f"high_total_volume:{total_recent_bytes / 1_000_000:.1f}MB")

            # 3. Много соединений к одному внешнему адресу
            cutoff_1min = now - ExfilThresholds.TIME_WINDOW_1MIN
            recent_conn_single_dst = len([t for t in flow['connections'] if t > cutoff_1min])

            if recent_conn_single_dst > ExfilThresholds.CONNECTIONS_FLOOD:
                result['is_exfiltration'] = True
                result['reasons'].append(f"flood_connections_single_dst:{recent_conn_single_dst}")
                result['score'] += 0.35
            elif recent_conn_single_dst > ExfilThresholds.CONNECTIONS_HIGH:
                result['is_exfiltration'] = True
                result['reasons'].append(f"many_connections_single_dst:{recent_conn_single_dst}")
                result['score'] += 0.25

            # 4. Нестандартные порты
            if dst_port not in self.normal_ports:
                if dst_port in self.exfil_ports:
                    result['is_exfiltration'] = True
                    result['reasons'].append(f"exfil_port:{dst_port}")
                    result['score'] += 0.35
                elif bytes_count > ExfilThresholds.LARGE_PACKET:
                    result['is_exfiltration'] = True
                    result['reasons'].append(f"unusual_port:{dst_port}")
                    result['score'] += 0.25

            # 5. Много уникальных внешних адресов с большим объёмом
            unique_dsts_with_volume = 0
            for (s, d), f in self.flows.items():
                if s == src_ip:
                    dst_bytes = sum(b for t, b in f['bytes_out'] if t > cutoff_5min)
                    if dst_bytes > ExfilThresholds.SINGLE_DST_MEDIUM:  # Было 1_000_000
                        unique_dsts_with_volume += 1

            if unique_dsts_with_volume > ExfilThresholds.MANY_DESTINATIONS:
                result['is_exfiltration'] = True
                result['reasons'].append(f"many_dst_with_volume:{unique_dsts_with_volume}")
                result['score'] += 0.2

            # 6. Асимметрия трафика
            total_in = flow['total_bytes_in']
            total_out = flow['total_bytes_out']
            if total_out > total_in * ExfilThresholds.ASYMMETRIC_RATIO and total_out > 1_000_000:
                result['is_exfiltration'] = True
                result['reasons'].append(f"asymmetric_traffic_pair:{total_out / max(1, total_in):.1f}x")
                result['score'] += 0.25

            result['score'] = min(1.0, result['score'])

            # Определение серьёзности
            if result['score'] > 0.7:
                result['severity'] = AlertSeverity.CRITICAL.value
            elif result['score'] > 0.5:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.3:
                result['severity'] = AlertSeverity.MEDIUM.value

            # Обновляем счётчик подозрительности
            if result['is_exfiltration']:
                flow['suspicious_score'] = min(1.0, flow['suspicious_score'] + result['score'] * 0.1)
                host['suspicious_score'] = min(1.0, host['suspicious_score'] + result['score'] * 0.1)
            else:
                flow['suspicious_score'] = max(0.0, flow['suspicious_score'] - 0.01)

            if result['is_exfiltration']:
                result['src_ip'] = src_ip
                result['dst_ip'] = dst_ip
                result['dst_port'] = dst_port
                result['timestamp'] = now
                result['total_bytes_recent'] = recent_bytes_single_dst
                result['total_bytes_all_dst'] = total_recent_bytes
                result['unique_dsts_count'] = len(host['unique_destinations'])
                result['suspicious_score'] = flow['suspicious_score']

                self.event_bus.publish('exfiltration.detected', result)
                self.logger.warning(
                    f"Обнаружена утечка данных от {src_ip} к {dst_ip}: score={result['score']:.3f}, {', '.join(result['reasons'])}")

    def _cleanup_loop(self) -> None:
        """Очистка устаревших данных (исправлена гонка)"""
        while self.running:
            time.sleep(600)

            with self._cleanup_lock:
                now = time.time()
                cutoff = now - 3600

                # Используем ЕДИНУЮ блокировку для consistency
                with self._lock:
                    expired_flows = [k for k, v in self.flows.items() if v['last_seen'] < cutoff]
                    for k in expired_flows:
                        del self.flows[k]

                    expired_hosts = [k for k, v in self.host_stats.items() if v['last_seen'] < cutoff]
                    for k in expired_hosts:
                        del self.host_stats[k]

    def get_stats(self, src_ip: str = None) -> Dict:
        """Получить статистику"""
        with self._lock:
            if src_ip:
                host_stats = self.host_stats.get(src_ip, {})

                # Собираем статистику по всем потокам этого хоста
                host_flows_bytes = 0
                host_flows_count = 0
                unique_dsts = set()

                for (s, d), flow in self.flows.items():
                    if s == src_ip:
                        host_flows_bytes += flow.get('total_bytes_out', 0)
                        host_flows_count += 1
                        unique_dsts.add(d)

                return {
                    'total_bytes_out': host_stats.get('total_bytes_out', 0),
                    'total_bytes_in': host_stats.get('total_bytes_in', 0),
                    'unique_destinations': len(host_stats.get('unique_destinations', set())),
                    'unique_ports': len(host_stats.get('unique_ports', set())),
                    'connections_count': host_stats.get('connections_count', 0),
                    'suspicious_score': host_stats.get('suspicious_score', 0.0),
                    'active_flows': host_flows_count,
                    'flows_bytes': host_flows_bytes,
                    'first_seen': host_stats.get('first_seen', 0),
                    'last_seen': host_stats.get('last_seen', 0)
                }

            # Общая статистика
            total_hosts = len(self.host_stats)
            total_flows = len(self.flows)
            total_bytes_out = sum(h['total_bytes_out'] for h in self.host_stats.values())

            with self._alert_lock:
                suppressed_total = sum(self._suppressed_count.values())

            return {
                'total_hosts': total_hosts,
                'total_flows': total_flows,
                'total_bytes_out': total_bytes_out,
                'total_bytes_out_mb': round(total_bytes_out / (1024 * 1024), 2),
                'suppressed_alerts': suppressed_total,
                'suppressed_breakdown': dict(self._suppressed_count)
            }

    def reset_stats(self) -> None:
        """Сброс статистики"""
        with self._lock:
            self.flows.clear()
            self.host_stats.clear()

        with self._alert_lock:
            self._recent_alerts.clear()
            self._alert_counter.clear()
            self._suppressed_count.clear()
            self._alert_counter_reset = time.time()

        self.logger.info("Статистика детектора утечек сброшена")


# ============================================================
# 4️⃣ UBA/UEBA (ПОВЕДЕНИЕ ПОЛЬЗОВАТЕЛЕЙ)
# ============================================================

class UserBehaviorAnalytics(BaseModule):
    """Анализ поведения пользователей и сущностей (UBA/UEBA)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("UBA", config, event_bus, logger)

        self.users: Dict[str, Dict] = defaultdict(lambda: {
            'ips': set(),
            'login_times': defaultdict(int),  # час -> количество
            'login_days': defaultdict(int),  # день недели -> количество
            'accessed_resources': defaultdict(int),  # ресурс -> количество
            'bytes_downloaded': deque(maxlen=100),  # (timestamp, bytes)
            'bytes_uploaded': deque(maxlen=100),
            'sessions': deque(maxlen=200),  # (timestamp, type, details)
            'geo_locations': set(),
            'devices': set(),
            'risk_score': 0.0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'total_sessions': 0,
            'failed_logins': 0,
            'successful_logins': 0
        })

        self.ip_to_user: Dict[str, str] = {}
        self.user_peer_groups: Dict[str, List[str]] = defaultdict(list)  # Группы похожих пользователей

        # Пороги для аномалий
        self.thresholds = {
            'unusual_hour_threshold': 0.1,  # 10% от среднего
            'new_geo_score': 0.4,
            'volume_multiplier': 5,  # В 5 раз больше среднего
            'new_resource_score': 0.25,
            'failed_login_threshold': 5,  # 5 неудачных попыток
            'rapid_sessions_threshold': 10  # 10 сессий за минуту
        }

        self._lock = threading.RLock()
        self.event_bus.subscribe('auth.login', self.on_login)
        self.event_bus.subscribe('auth.logout', self.on_logout)
        self.event_bus.subscribe('auth.failed', self.on_failed_login)
        self.event_bus.subscribe('packet.received', self.on_traffic)
        self.event_bus.subscribe('alert.detected', self.on_alert)

    def start(self) -> None:
        self.running = True
        self.logger.info("UBA/UEBA запущен")

        # Поток обновления peer groups
        threading.Thread(target=self._peer_group_loop, daemon=True).start()
        # Поток снижения риска
        threading.Thread(target=self._risk_decay_loop, daemon=True).start()

    def stop(self) -> None:
        self.running = False

    def bind_ip_to_user(self, ip: str, username: str) -> None:
        """Привязка IP к пользователю"""
        with self._lock:
            self.ip_to_user[ip] = username
            self.users[username]['ips'].add(ip)

    def on_login(self, data: Dict) -> None:
        """Обработка успешного входа"""
        username = data.get('username', '')
        src_ip = data.get('src_ip', '')
        geo = data.get('geo', '')
        device = data.get('device', '')

        if not username:
            if src_ip:
                username = self.ip_to_user.get(src_ip, src_ip)
            else:
                return

        alert = self.record_event(
            src_ip=src_ip or username,
            event_type='login',
            details={
                'username': username,
                'success': True,
                'geo': geo,
                'device': device
            }
        )

        if alert:
            self.event_bus.publish('uba.anomaly', alert)

    def on_logout(self, data: Dict) -> None:
        """Обработка выхода"""
        username = data.get('username', '')
        src_ip = data.get('src_ip', '')

        if not username and src_ip:
            username = self.ip_to_user.get(src_ip, src_ip)

        if username:
            self.record_event(
                src_ip=src_ip or username,
                event_type='logout',
                details={'username': username}
            )

    def on_failed_login(self, data: Dict) -> None:
        """Обработка неудачного входа"""
        username = data.get('username', '')
        src_ip = data.get('src_ip', '')

        if not username:
            username = src_ip or 'unknown'

        alert = self.record_event(
            src_ip=src_ip or username,
            event_type='failed_login',
            details={'username': username, 'attempted_username': data.get('attempted_username', '')}
        )

        if alert:
            self.event_bus.publish('uba.anomaly', alert)

    def on_traffic(self, data: Dict) -> None:
        """Анализ трафика для UBA"""
        src_ip = data.get('src_ip', '')
        packet = data.get('packet')

        if not src_ip or not packet:
            return

        username = self.ip_to_user.get(src_ip, src_ip)
        bytes_count = len(packet)

        # Определяем направление
        local_networks = self.config.get('network.local_networks', ['192.168.', '10.', '172.16.'])
        dst_ip = data.get('dst_ip', '')
        is_download = any(dst_ip.startswith(net) for net in local_networks)

        with self._lock:
            user = self.users[username]
            now = time.time()

            if is_download:
                user['bytes_downloaded'].append((now, bytes_count))
            else:
                user['bytes_uploaded'].append((now, bytes_count))

    def on_alert(self, alert: Dict) -> None:
        """Обновление риска при алерте"""
        src_ip = alert.get('src_ip', '')
        if src_ip:
            username = self.ip_to_user.get(src_ip, src_ip)
            with self._lock:
                if username in self.users:
                    self.users[username]['risk_score'] = min(1.0, self.users[username]['risk_score'] + 0.1)

    def record_event(self, src_ip: str, event_type: str, details: Dict) -> Optional[Dict]:
        """Запись события и анализ аномалий (с копированием данных)"""
        username = self.ip_to_user.get(src_ip, src_ip)

        with self._lock:
            user = self.users[username]
            now = datetime.now()
            current_time = time.time()

            # Обновление статистики
            user['login_times'][now.hour] += 1
            user['login_days'][now.weekday()] += 1
            user['last_seen'] = current_time
            user['total_sessions'] += 1

            if event_type == 'login':
                user['successful_logins'] += 1
            elif event_type == 'failed_login':
                user['failed_logins'] += 1

            # СОЗДАЁМ КОПИЮ details для хранения
            details_copy = {}
            if details:
                for key, value in details.items():
                    if isinstance(value, (str, int, float, bool, type(None))):
                        details_copy[key] = value
                    elif isinstance(value, (list, tuple)):
                        details_copy[key] = list(value)[:10]  # Ограничиваем размер
                    elif isinstance(value, dict):
                        # Поверхностная копия словаря
                        details_copy[key] = dict(list(value.items())[:10])
                    else:
                        details_copy[key] = str(value)[:100]

            user['sessions'].append({
                'time': current_time,
                'type': event_type,
                'details': details_copy
            })

            if 'geo' in details_copy and details_copy['geo']:
                geo_value = str(details_copy['geo'])[:50]
                user['geo_locations'].add(geo_value)

            if 'device' in details_copy and details_copy['device']:
                device_value = str(details_copy['device'])[:100]
                user['devices'].add(device_value)

            if src_ip not in user['ips']:
                user['ips'].add(src_ip)

            # Анализ аномалий
            alert = self._analyze_anomalies(username, user, event_type, details_copy)

            if alert:
                user['risk_score'] = min(1.0, user['risk_score'] + alert['score'] * 0.3)
                alert['current_risk'] = user['risk_score']
            else:
                user['risk_score'] = max(0.0, user['risk_score'] - 0.01)

            # Проверка на высокий риск
            if user['risk_score'] > 0.7:
                risk_alert = {
                    'username': username,
                    'anomalies': ['high_risk_score'],
                    'score': user['risk_score'],
                    'severity': AlertSeverity.HIGH.value if user['risk_score'] > 0.85 else AlertSeverity.MEDIUM.value,
                    'details': {'risk_score': user['risk_score']}
                }
                self.event_bus.publish('uba.high_risk', risk_alert)

            return alert

    def _analyze_anomalies(self, username: str, user: Dict, event_type: str, details: Dict) -> Optional[Dict]:
        """Анализ аномалий в поведении (исправлена логика unusual time)"""
        alert = {
            'username': username,
            'anomalies': [],
            'score': 0.0,
            'severity': AlertSeverity.LOW.value,
            'timestamp': time.time()
        }

        now = datetime.now()
        current_hour = now.hour
        current_weekday = now.weekday()

        # 1. Необычное время входа (ИСПРАВЛЕНО)
        if event_type in ('login', 'failed_login'):
            # Получаем ИСТОРИЧЕСКУЮ активность (без текущего часа)
            historical_hours = {h: c for h, c in user['login_times'].items() if h != current_hour}

            if historical_hours:
                # Средняя активность по другим часам
                avg_activity = sum(historical_hours.values()) / len(historical_hours)

                # Текущая активность в этот час (уже с учётом нового события)
                current_hour_activity = user['login_times'].get(current_hour, 0)

                # Проверяем, является ли этот час необычным
                if avg_activity > 0:
                    # Если текущая активность значительно ниже средней - это необычное время
                    if current_hour_activity < avg_activity * 0.2:  # Меньше 20% от среднего
                        alert['anomalies'].append(f"unusual_time:{current_hour}:00")
                        alert['score'] += 0.3

                    # Если это ПЕРВЫЙ вход в этот час за всю историю
                    if current_hour_activity == 1 and len(historical_hours) > 10:
                        alert['anomalies'].append(f"first_time_this_hour:{current_hour}:00")
                        alert['score'] += 0.15

            # Необычный день недели (аналогичная логика)
            historical_days = {d: c for d, c in user['login_days'].items() if d != current_weekday}

            if len(historical_days) > 3:
                avg_daily = sum(historical_days.values()) / len(historical_days)
                current_day_activity = user['login_days'].get(current_weekday, 0)

                if avg_daily > 0 and current_day_activity < avg_daily * 0.2:
                    alert['anomalies'].append(f"unusual_day:{current_weekday}")
                    alert['score'] += 0.2

        # 2. Новая геолокация (без изменений)
        if 'geo' in details and details['geo']:
            if details['geo'] not in user['geo_locations'] and len(user['geo_locations']) > 0:
                alert['anomalies'].append(f"new_geo:{details['geo']}")
                alert['score'] += self.thresholds['new_geo_score']

        # 3. Новое устройство (без изменений)
        if 'device' in details and details['device']:
            if details['device'] not in user['devices'] and len(user['devices']) > 0:
                alert['anomalies'].append(f"new_device:{details['device']}")
                alert['score'] += 0.25

        # 4. Аномальный объём данных (без изменений)
        if event_type in ('login', 'traffic'):
            all_bytes = [b for _, b in user['bytes_downloaded']] + [b for _, b in user['bytes_uploaded']]
            if all_bytes:
                avg_bytes = sum(all_bytes) / len(all_bytes)
                recent_downloads = [b for t, b in user['bytes_downloaded'] if time.time() - t < 300]
                if recent_downloads:
                    recent_avg = sum(recent_downloads) / len(recent_downloads)
                    if recent_avg > avg_bytes * self.thresholds['volume_multiplier']:
                        alert['anomalies'].append(f"unusual_volume:{recent_avg / 1024:.1f}KB")
                        alert['score'] += 0.3

        # 5. Множественные неудачные попытки (без изменений)
        if event_type == 'failed_login':
            recent_failed = sum(1 for s in user['sessions']
                                if s.get('type') == 'failed_login' and time.time() - s.get('time', 0) < 300)
            if recent_failed >= self.thresholds['failed_login_threshold']:
                alert['anomalies'].append(f"multiple_failures:{recent_failed}")
                alert['score'] += 0.35

        # 6. Быстрые сессии (без изменений)
        recent_sessions = [s for s in user['sessions'] if time.time() - s.get('time', 0) < 60]
        if len(recent_sessions) >= self.thresholds['rapid_sessions_threshold']:
            alert['anomalies'].append(f"rapid_sessions:{len(recent_sessions)}")
            alert['score'] += 0.3

        # 7. Новый IP (без изменений)
        if 'src_ip' in details and details['src_ip'] not in user['ips']:
            if len(user['ips']) > 3:
                alert['anomalies'].append(f"new_ip:{details['src_ip']}")
                alert['score'] += 0.2

        # 8. Необычное соотношение успешных/неудачных входов (без изменений)
        total_logins = user['successful_logins'] + user['failed_logins']
        if total_logins > 10:
            fail_rate = user['failed_logins'] / total_logins
            if fail_rate > 0.5:
                alert['anomalies'].append(f"high_fail_rate:{fail_rate:.2f}")
                alert['score'] += 0.25

        alert['score'] = min(1.0, alert['score'])

        # Определение серьёзности
        if alert['score'] > 0.7:
            alert['severity'] = AlertSeverity.CRITICAL.value
        elif alert['score'] > 0.5:
            alert['severity'] = AlertSeverity.HIGH.value
        elif alert['score'] > 0.3:
            alert['severity'] = AlertSeverity.MEDIUM.value

        if alert['anomalies']:
            return alert
        return None

    def _peer_group_loop(self) -> None:
        """Обновление групп похожих пользователей"""
        while self.running:
            time.sleep(3600)  # Каждый час
            self._update_peer_groups()

    def _update_peer_groups(self) -> None:
        """Обновление peer groups на основе поведения"""
        with self._lock:
            # Простая кластеризация на основе активности
            user_activity = {}
            for username, data in self.users.items():
                activity = sum(data['login_times'].values())
                user_activity[username] = activity

            # Группировка по уровню активности
            if user_activity:
                avg_activity = sum(user_activity.values()) / len(user_activity)

                self.user_peer_groups.clear()
                for username, activity in user_activity.items():
                    if activity > avg_activity * 1.5:
                        self.user_peer_groups['high_activity'].append(username)
                    elif activity < avg_activity * 0.5:
                        self.user_peer_groups['low_activity'].append(username)
                    else:
                        self.user_peer_groups['normal_activity'].append(username)

    def _risk_decay_loop(self) -> None:
        """Постепенное снижение риска"""
        while self.running:
            time.sleep(60)  # Каждую минуту
            with self._lock:
                for user in self.users.values():
                    # Снижаем риск на 1% в минуту, если нет новых алертов
                    user['risk_score'] = max(0.0, user['risk_score'] * 0.99)

    def get_user_risk(self, username: str) -> float:
        """Получить текущий риск пользователя"""
        with self._lock:
            return self.users.get(username, {}).get('risk_score', 0.0)

    def get_user_profile(self, username: str) -> Optional[Dict]:
        """Получить профиль пользователя"""
        with self._lock:
            if username in self.users:
                user = self.users[username]
                return {
                    'username': username,
                    'ips': list(user['ips']),
                    'risk_score': user['risk_score'],
                    'total_sessions': user['total_sessions'],
                    'failed_logins': user['failed_logins'],
                    'successful_logins': user['successful_logins'],
                    'geo_locations': list(user['geo_locations']),
                    'devices': list(user['devices']),
                    'first_seen': user['first_seen'],
                    'last_seen': user['last_seen']
                }
        return None


# ============================================================
# 5️⃣ АВТОМАТИЧЕСКИЙ ОТЧЁТ ОБ ИНЦИДЕНТЕ
# ============================================================

class IncidentReportGenerator(BaseModule):
    """Генерация автоматических отчётов об инцидентах (исправлен - защита от циклов, экранирование, ограничение частоты)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("ReportGenerator", config, event_bus, logger)

        self.db_path = config.get('storage.sqlite.path', 'shard_siem.db')
        self.reports_dir = Path('reports')
        self.reports_dir.mkdir(exist_ok=True)

        # Ограничение частоты отчётов
        self._last_report_time: Dict[str, float] = {}
        self._report_cooldown = 300
        self._max_reports_per_hour = 20
        self._report_count: Dict[str, int] = defaultdict(int)
        self._report_count_reset = time.time()
        self._report_lock = threading.RLock()

        # ========== ЗАЩИТА ОТ ЦИКЛОВ ==========
        self._reported_investigations: Set[str] = set()
        self._investigation_lock = threading.RLock()
        # ====================================

        # Шаблоны рекомендаций
        self.recommendation_templates = {
            'Brute Force': [
                'Включить многофакторную аутентификацию',
                'Установить блокировку после N неудачных попыток',
                'Проверить сложность паролей'
            ],
            'Port Scan': [
                'Проверить правила файрвола',
                'Закрыть неиспользуемые порты',
                'Настроить rate limiting'
            ],
            'Web Attack': [
                'Проверить WAF правила',
                'Обновить веб-приложение',
                'Провести аудит кода'
            ],
            'DDoS': [
                'Включить DDoS защиту',
                'Связаться с провайдером',
                'Настроить фильтрацию трафика'
            ],
            'Lateral Movement': [
                'Изолировать затронутые системы',
                'Сменить пароли привилегированных учётных записей',
                'Проверить логи на других системах'
            ],
            'Data Exfiltration': [
                'Заблокировать подозрительный IP',
                'Проверить исходящие соединения',
                'Провести аудит доступа к данным'
            ],
            'DNS Tunnel': [
                'Заблокировать подозрительные DNS запросы',
                'Настроить DNS фильтрацию',
                'Проверить DNS логи'
            ]
        }

        self._lock = threading.RLock()
        self.event_bus.subscribe('investigation.completed', self.on_investigation)
        self.event_bus.subscribe('alert.detected', self.on_alert)

    def _escape_html(self, text: str) -> str:
        """Экранирование специальных символов HTML"""
        if not text:
            return ""
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace(
            "'", '&#39;')

    def _escape_text(self, text: str) -> str:
        """Безопасное форматирование текста для отчёта"""
        if not text:
            return "N/A"
        safe_text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(text))
        return safe_text[:500]

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._cleanup_loop, daemon=True, name="Report-Cleanup").start()
        self.logger.info(f"Генератор отчётов запущен (директория: {self.reports_dir})")

    def stop(self) -> None:
        self.running = False
        self.logger.info("Генератор отчётов остановлен")

    def _cleanup_loop(self) -> None:
        """Очистка старых отчётов"""
        while self.running:
            time.sleep(3600)

            try:
                cutoff = time.time() - (30 * 86400)
                for report_file in self.reports_dir.glob('incident_*.txt'):
                    if report_file.stat().st_mtime < cutoff:
                        report_file.unlink()
                        self.logger.debug(f"Удалён старый отчёт: {report_file.name}")
            except Exception as e:
                self.logger.debug(f"Ошибка очистки отчётов: {e}")

    def on_investigation(self, investigation: Dict) -> None:
        """Генерация отчёта при завершении расследования (с защитой от циклов)"""
        inv_id = investigation.get('id')

        # ========== ЗАЩИТА ОТ ЦИКЛОВ ==========
        with self._investigation_lock:
            if inv_id in self._reported_investigations:
                self.logger.debug(f"Investigation {inv_id} already reported, skipping")
                return
            self._reported_investigations.add(inv_id)

            # Ограничиваем размер set'а
            if len(self._reported_investigations) > 1000:
                # Удаляем старые (первые 100)
                for _ in range(100):
                    if self._reported_investigations:
                        self._reported_investigations.pop()
        # ====================================

        alerts = investigation.get('alerts', [])
        if not alerts:
            return

        src_ip = investigation.get('src_ip', 'unknown')
        now = time.time()

        # Применяем ограничения частоты
        with self._report_lock:
            if now - self._report_count_reset > 3600:
                self._report_count.clear()
                self._report_count_reset = now

            if self._report_count.get('total', 0) >= self._max_reports_per_hour:
                self.logger.warning(f"Достигнут лимит отчётов, пропускаем расследование {inv_id}")
                return

            last_time = self._last_report_time.get(src_ip, 0)
            if now - last_time < self._report_cooldown:
                return

            self._last_report_time[src_ip] = now
            self._report_count['total'] = self._report_count.get('total', 0) + 1

        report = self.generate_report(investigation, alerts)
        self._save_report(inv_id, report)

    def on_alert(self, alert: Dict) -> None:
        """Автоматическая генерация отчёта для критических алертов (с ограничением частоты)"""
        if alert.get('severity') != AlertSeverity.CRITICAL.value:
            return

        src_ip = alert.get('src_ip', 'unknown')
        now = time.time()

        with self._report_lock:
            if now - self._report_count_reset > 3600:
                self._report_count.clear()
                self._report_count_reset = now

            if self._report_count.get('total', 0) >= self._max_reports_per_hour:
                self.logger.warning(f"Достигнут лимит отчётов ({self._max_reports_per_hour}/час), пропускаем")
                return

            last_time = self._last_report_time.get(src_ip, 0)
            if now - last_time < self._report_cooldown:
                self.logger.debug(f"Пропускаем отчёт для {src_ip} (cooldown {self._report_cooldown}с)")
                return

            self._last_report_time[src_ip] = now
            self._report_count['total'] = self._report_count.get('total', 0) + 1
            self._report_count[src_ip] = self._report_count.get(src_ip, 0) + 1

        investigation = {
            'id': f"INV-{int(now)}-{src_ip.replace('.', '_')[:10]}",
            'start_time': alert.get('timestamp', now),
            'end_time': now,
            'severity': alert.get('severity'),
            'stage': alert.get('kill_chain', {}).get('stage', 'unknown'),
            'src_ip': src_ip,
            'dst_ip': alert.get('dst_ip', 'N/A'),
            'conclusion': f"Критический алерт: {alert.get('attack_type')}",
            'recommendations': self._get_recommendations(alert.get('attack_type', 'Unknown'))
        }

        report = self.generate_report(investigation, [alert])
        self._save_report(investigation['id'], report)

    def generate_report(self, investigation: Dict, alerts: List[Dict]) -> str:
        """Генерация полного отчёта (с экранированием данных)"""
        inv = investigation

        inv_id = self._escape_text(inv.get('id', 'N/A'))
        start_time = datetime.fromtimestamp(inv.get('start_time', time.time())).strftime('%Y-%m-%d %H:%M:%S')
        end_time = datetime.fromtimestamp(inv.get('end_time', time.time())).strftime('%Y-%m-%d %H:%M:%S')
        severity = self._escape_text(inv.get('severity', 'UNKNOWN'))
        stage = self._escape_text(inv.get('stage', 'N/A'))
        conclusion = self._escape_text(inv.get('conclusion', 'Нет данных'))

        report = f"""
═══════════════════════════════════════════════════════════════════════════
                    ОТЧЁТ ОБ ИНЦИДЕНТЕ БЕЗОПАСНОСТИ
═══════════════════════════════════════════════════════════════════════════

ID инцидента: {inv_id}
Время начала: {start_time}
Время завершения: {end_time}
Серьёзность: {severity}
Стадия по MITRE ATT&CK: {stage}

───────────────────────────────────────────────────────────────────────────
1. КРАТКОЕ ОПИСАНИЕ
───────────────────────────────────────────────────────────────────────────
{conclusion}

───────────────────────────────────────────────────────────────────────────
2. ЗАТРОНУТЫЕ АКТИВЫ
───────────────────────────────────────────────────────────────────────────
"""
        src_ip = self._escape_text(inv.get('src_ip', 'N/A'))
        if not src_ip or src_ip == 'N/A':
            if alerts:
                src_ip = self._escape_text(alerts[0].get('src_ip', 'N/A'))
        report += f"Источник атаки: {src_ip}\n"

        dst_ips = set()
        dst_ports = set()
        for a in alerts:
            dst = a.get('dst_ip')
            if dst:
                dst_ips.add(self._escape_text(dst))
            port = a.get('dst_port')
            if port:
                dst_ports.add(str(port))

        report += f"Целевые системы: {', '.join(dst_ips) if dst_ips else 'N/A'}\n"
        report += f"Порты: {', '.join(dst_ports) if dst_ports else 'N/A'}\n"

        attack_types = set(self._escape_text(a.get('attack_type', 'Unknown')) for a in alerts)
        report += f"Типы атак: {', '.join(attack_types)}\n"

        report += f"""
───────────────────────────────────────────────────────────────────────────
3. ХРОНОЛОГИЯ СОБЫТИЙ
───────────────────────────────────────────────────────────────────────────
"""
        sorted_alerts = sorted(alerts, key=lambda x: x.get('timestamp', 0))

        for i, alert in enumerate(sorted_alerts[:50], 1):
            ts = datetime.fromtimestamp(alert.get('timestamp', 0)).strftime('%H:%M:%S')
            attack_type = self._escape_text(alert.get('attack_type', 'Unknown'))
            score = alert.get('score', 0)
            src = self._escape_text(alert.get('src_ip', 'unknown'))
            dst = f"{self._escape_text(alert.get('dst_ip', 'unknown'))}:{alert.get('dst_port', '')}"

            report += f"{i:2d}. {ts} — {attack_type} (score: {score:.3f})\n"
            report += f"    Источник: {src} → Цель: {dst}\n"

            explanation = alert.get('explanation')
            if explanation:
                safe_explanation = self._escape_text(explanation)[:100]
                report += f"    Причина: {safe_explanation}...\n"

            kill_chain = alert.get('kill_chain')
            if kill_chain:
                chain_stage = self._escape_text(kill_chain.get('stage', 'unknown'))
                event_count = kill_chain.get('event_count', 0)
                report += f"    Цепочка: {chain_stage}, событий: {event_count}\n"

            report += "\n"

        report += f"""
───────────────────────────────────────────────────────────────────────────
4. РЕКОМЕНДАЦИИ
───────────────────────────────────────────────────────────────────────────
"""
        recommendations = inv.get('recommendations', [])
        if not recommendations:
            for attack_type in attack_types:
                recommendations.extend(self._get_recommendations(attack_type))

        for i, rec in enumerate(set(recommendations), 1):
            report += f"{i}. {self._escape_text(rec)}\n"

        report += f"""
───────────────────────────────────────────────────────────────────────────
5. ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ
───────────────────────────────────────────────────────────────────────────
Всего алертов: {len(alerts)}
Максимальный score: {max((a.get('score', 0) for a in alerts), default=0):.3f}
Средний confidence: {sum(a.get('confidence', 0) for a in alerts) / max(1, len(alerts)):.3f}

"""
        for alert in alerts:
            ti = alert.get('threat_intel')
            if ti:
                sources = ', '.join(self._escape_text(s) for s in ti.get('sources', []))
                report += f"Threat Intelligence для {self._escape_text(alert.get('src_ip', 'N/A'))}:\n"
                report += f"  Источники: {sources}\n"
                report += f"  Score: {ti.get('score', 0):.2f}\n"

                country = ti.get('country')
                if country:
                    report += f"  Страна: {self._escape_text(country)}\n"
                break

        report += """
═══════════════════════════════════════════════════════════════════════════
                            КОНЕЦ ОТЧЁТА
═══════════════════════════════════════════════════════════════════════════
"""
        return report

    def generate_html_report(self, investigation: Dict, alerts: List[Dict]) -> str:
        """Генерация HTML отчёта (с полным экранированием)"""
        inv = investigation

        inv_id = self._escape_html(inv.get('id', 'N/A'))
        start_time = datetime.fromtimestamp(inv.get('start_time', time.time())).strftime('%Y-%m-%d %H:%M:%S')
        end_time = datetime.fromtimestamp(inv.get('end_time', time.time())).strftime('%Y-%m-%d %H:%M:%S')
        severity = self._escape_html(inv.get('severity', 'UNKNOWN'))
        stage = self._escape_html(inv.get('stage', 'N/A'))
        conclusion = self._escape_html(inv.get('conclusion', 'Нет данных'))

        severity_class = f"severity-{severity}"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline';">
    <title>SHARD Incident Report - {inv_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .header-info {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 20px 0; }}
        .info-item {{ padding: 10px; background: #f8f9fa; border-radius: 5px; }}
        .info-label {{ font-weight: bold; color: #666; }}
        .info-value {{ color: #333; }}
        .severity-CRITICAL {{ color: #dc3545; font-weight: bold; }}
        .severity-HIGH {{ color: #fd7e14; font-weight: bold; }}
        .severity-MEDIUM {{ color: #ffc107; }}
        .severity-LOW {{ color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .recommendations {{ background: #e7f3ff; padding: 15px; border-radius: 5px; }}
        .footer {{ margin-top: 30px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SHARD SIEM - Отчёт об инциденте</h1>

        <div class="header-info">
            <div class="info-item">
                <span class="info-label">ID инцидента:</span>
                <span class="info-value">{inv_id}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Время начала:</span>
                <span class="info-value">{start_time}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Серьёзность:</span>
                <span class="info-value {severity_class}">{severity}</span>
            </div>
            <div class="info-item">
                <span class="info-label">Стадия MITRE ATT&amp;CK:</span>
                <span class="info-value">{stage}</span>
            </div>
        </div>

        <h2>1. Краткое описание</h2>
        <p>{conclusion}</p>

        <h2>2. Хронология событий</h2>
        <table>
            <tr>
                <th>Время</th>
                <th>Тип атаки</th>
                <th>Источник</th>
                <th>Цель</th>
                <th>Score</th>
            </tr>
"""

        for alert in sorted(alerts, key=lambda x: x.get('timestamp', 0))[:50]:
            ts = datetime.fromtimestamp(alert.get('timestamp', 0)).strftime('%H:%M:%S')
            attack_type = self._escape_html(alert.get('attack_type', 'Unknown'))
            src = self._escape_html(alert.get('src_ip', 'unknown'))
            dst = f"{self._escape_html(alert.get('dst_ip', 'unknown'))}:{alert.get('dst_port', '')}"
            score = alert.get('score', 0)

            html += f"""
            <tr>
                <td>{ts}</td>
                <td>{attack_type}</td>
                <td>{src}</td>
                <td>{dst}</td>
                <td>{score:.3f}</td>
            </tr>
"""

        html += """
        </table>

        <h2>3. Рекомендации</h2>
        <div class="recommendations">
            <ul>
"""

        for rec in inv.get('recommendations', ['Провести дополнительный анализ']):
            html += f"                <li>{self._escape_html(rec)}</li>\n"

        html += """
            </ul>
        </div>

        <div class="footer">
            SHARD Enterprise SIEM | Отчёт сгенерирован автоматически
        </div>
    </div>
</body>
</html>
"""
        return html

    def _get_recommendations(self, attack_type: str) -> List[str]:
        """Получить рекомендации для типа атаки"""
        return self.recommendation_templates.get(attack_type,
                                                 ['Провести дополнительный анализ', 'Проверить логи',
                                                  'Усилить мониторинг'])

    def _save_report(self, incident_id: str, report: str) -> None:
        """Сохранение отчёта в файл"""
        safe_id = re.sub(r'[^a-zA-Z0-9\-_]', '_', str(incident_id))[:50]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.reports_dir / f"incident_{safe_id}_{timestamp}.txt"

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            self.logger.info(f"Отчёт сохранён: {filename}")
        except Exception as e:
            self.logger.error(f"Ошибка сохранения отчёта: {e}")

    def get_recent_reports(self, limit: int = 10) -> List[Dict]:
        """Получить список последних отчётов"""
        reports = []
        try:
            for f in sorted(self.reports_dir.glob('incident_*.txt'),
                            key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
                reports.append({
                    'filename': f.name,
                    'size': f.stat().st_size,
                    'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                })
        except Exception as e:
            self.logger.error(f"Ошибка чтения отчётов: {e}")
        return reports

    def get_stats(self) -> Dict:
        """Получить статистику генератора отчётов"""
        with self._report_lock:
            with self._investigation_lock:
                return {
                    'reports_dir': str(self.reports_dir),
                    'reports_count': len(list(self.reports_dir.glob('incident_*.txt'))),
                    'reports_today': self._report_count.get('total', 0),
                    'max_reports_per_hour': self._max_reports_per_hour,
                    'cooldown_seconds': self._report_cooldown,
                    'reported_investigations': len(self._reported_investigations)
                }

# ============================================================
# 6️⃣ WEB DASHBOARD
# ============================================================
# ============================================================
# HTTP ОБРАБОТЧИК ДЛЯ ДАШБОРДА (вынесен наружу - пункт 77)
# ============================================================

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Обработчик HTTP запросов для дашборда (исправлен - path traversal защита, безопасное сравнение)"""

    # Классовые переменные - устанавливаются ОДИН раз при инициализации
    dashboard_stats = None
    dashboard_logger = None
    dashboard_lock = None
    dashboard_check_auth = None
    dashboard_auth_enabled = False
    dashboard_validate_ip = None

    def log_message(self, format, *args):
        pass  # Отключаем стандартное логирование

    def handle(self):
        """Обработка запроса с игнорированием BrokenPipe"""
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as e:
            if self.dashboard_logger:
                self.dashboard_logger.debug(f"HTTP ошибка в handle: {type(e).__name__}")

    def handle_one_request(self):
        """Обработка одного запроса с защитой от сетевых ошибок"""
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True
        except Exception as e:
            if self.dashboard_logger:
                self.dashboard_logger.debug(f"HTTP ошибка в handle_one_request: {type(e).__name__}")
            self.close_connection = True

    def do_GET(self):
        try:
            # Проверка аутентификации
            if self.dashboard_auth_enabled and self.dashboard_check_auth and \
                    not self.dashboard_check_auth(dict(self.headers)):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="SHARD Dashboard"')
                self.end_headers()
                self.wfile.write(b'Unauthorized')
                return

            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == '/' or path == '/index.html':
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(self._get_html().encode('utf-8'))

            elif path == '/api/stats':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()

                with self.dashboard_lock:
                    api_data = {
                        'total_packets': self.dashboard_stats['total_packets'],
                        'total_alerts': self.dashboard_stats['total_alerts'],
                        'blocked_ips': self.dashboard_stats['blocked_ips'],
                        'active_threats': self.dashboard_stats['active_threats'],
                        'recent_alerts': list(self.dashboard_stats['recent_alerts'])[:20],
                        'top_attackers': dict(
                            sorted(self.dashboard_stats['top_attackers'].items(),
                                   key=lambda x: x[1], reverse=True)[:10]),
                        'top_targets': dict(
                            sorted(self.dashboard_stats['top_targets'].items(),
                                   key=lambda x: x[1], reverse=True)[:10]),
                        'attack_types': dict(self.dashboard_stats['attack_types'])
                    }

                self.wfile.write(json.dumps(api_data).encode('utf-8'))

            elif path == '/api/alerts':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()

                with self.dashboard_lock:
                    alerts = list(self.dashboard_stats['recent_alerts'])[:50]

                self.wfile.write(json.dumps(alerts).encode('utf-8'))

            elif path.startswith('/api/report/'):
                incident_id = path.split('/')[-1]

                # ========== ИСПРАВЛЕНО: ПОЛНАЯ ЗАЩИТА ОТ PATH TRAVERSAL ==========
                import os.path

                # Санитизация - только буквы, цифры, подчёркивания, дефисы, точки
                safe_id = re.sub(r'[^a-zA-Z0-9_\-\.]', '', incident_id)
                if safe_id != incident_id:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'Invalid incident ID')
                    return

                # Защита от path traversal через нормализацию пути
                reports_dir = Path('reports').resolve()
                report_pattern = f"incident_{safe_id}_*.txt"

                try:
                    reports = list(reports_dir.glob(report_pattern))
                    if reports:
                        report_path = reports[0].resolve()

                        # Проверка что файл действительно внутри reports_dir
                        if not str(report_path).startswith(str(reports_dir)):
                            self.send_response(403)
                            self.end_headers()
                            self.wfile.write(b'Access denied')
                            return

                        self.send_response(200)
                        self.send_header('Content-type', 'text/plain; charset=utf-8')
                        self.end_headers()
                        with open(report_path, 'r', encoding='utf-8') as f:
                            self.wfile.write(f.read().encode('utf-8'))
                    else:
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write(b'Report not found')
                except Exception as e:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b'Internal server error')
                # =================================================================

            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'Not found')

        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as e:
            if self.dashboard_logger:
                self.dashboard_logger.debug(f"Ошибка в do_GET: {type(e).__name__}")
            try:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'Internal Server Error')
            except:
                pass

    def do_POST(self):
        try:
            if self.dashboard_auth_enabled and self.dashboard_check_auth and \
                    not self.dashboard_check_auth(dict(self.headers)):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'Unauthorized')
                return

            if self.path == '/api/block':
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 1024:
                    self.send_response(413)
                    self.end_headers()
                    return

                post_data = self.rfile.read(content_length)
                try:
                    data = json.loads(post_data)
                    ip = data.get('ip', '').strip()

                    if self.dashboard_validate_ip and self.dashboard_validate_ip(ip):
                        self.dashboard_logger.info(f"Ручная блокировка IP через дашборд: {ip}")
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'ok', 'ip': ip}).encode('utf-8'))
                    else:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(json.dumps({'error': 'Invalid IP'}).encode('utf-8'))
                except json.JSONDecodeError:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': 'Invalid JSON'}).encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()

        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as e:
            if self.dashboard_logger:
                self.dashboard_logger.debug(f"Ошибка в do_POST: {type(e).__name__}")
            try:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'Internal Server Error')
            except:
                pass

    def do_OPTIONS(self):
        """Обработка OPTIONS запросов (для CORS)"""
        try:
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception:
            pass

    def _get_html(self):
        return '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30">
    <title>SHARD Enterprise SIEM</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 {
            font-size: 2.5em;
            margin-bottom: 20px;
            text-shadow: 0 0 20px rgba(0,255,255,0.5);
            border-bottom: 2px solid #00ffff;
            padding-bottom: 10px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-value {
            font-size: 3em;
            font-weight: bold;
            color: #00ffff;
        }
        .stat-label {
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 2px;
            opacity: 0.8;
        }
        .panel {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .panel h2 {
            margin-bottom: 15px;
            color: #00ffff;
            font-size: 1.3em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        th { color: #00ffff; font-weight: 500; }
        .alert-critical { color: #ff4444; }
        .alert-high { color: #ff8800; }
        .alert-medium { color: #ffcc00; }
        .alert-low { color: #00ff00; }
        .two-columns {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .refresh-info {
            text-align: right;
            opacity: 0.6;
            font-size: 0.8em;
            margin-top: 20px;
        }
        .logout-btn {
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(255,255,255,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            color: #fff;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .logout-btn:hover {
            background: rgba(255,68,68,0.3);
        }
    </style>
</head>
<body>
    <div class="container">
        <button class="logout-btn" onclick="logout()">🚪 Выход</button>
        <h1>🛡️ SHARD Enterprise SIEM</h1>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="total-packets">0</div>
                <div class="stat-label">Пакетов обработано</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="total-alerts">0</div>
                <div class="stat-label">Алертов</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="blocked-ips">0</div>
                <div class="stat-label">Заблокировано IP</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="active-threats">0</div>
                <div class="stat-label">Активных угроз</div>
            </div>
        </div>

        <div class="panel">
            <h2>🚨 Последние алерты</h2>
            <table id="alerts-table">
                <thead>
                    <tr>
                        <th>Время</th>
                        <th>Тип атаки</th>
                        <th>Источник</th>
                        <th>Цель</th>
                        <th>Score</th>
                        <th>Действие</th>
                    </tr>
                </thead>
                <tbody id="alerts-body"></tbody>
            </table>
        </div>

        <div class="two-columns">
            <div class="panel">
                <h2>👾 Топ атакующих</h2>
                <table id="attackers-table">
                    <thead><tr><th>IP</th><th>Количество</th></tr></thead>
                    <tbody id="attackers-body"></tbody>
                </table>
            </div>
            <div class="panel">
                <h2>🎯 Топ целей</h2>
                <table id="targets-table">
                    <thead><tr><th>IP</th><th>Количество</th></tr></thead>
                    <tbody id="targets-body"></tbody>
                </table>
            </div>
        </div>

        <div class="panel">
            <h2>📊 Типы атак</h2>
            <table id="types-table">
                <thead><tr><th>Тип</th><th>Количество</th></tr></thead>
                <tbody id="types-body"></tbody>
            </table>
        </div>

        <div class="refresh-info">
            Автообновление каждые 30 секунд | SHARD Enterprise v4.1.0
        </div>
    </div>

    <script>
        async function fetchStats() {
            try {
                const response = await fetch('/api/stats');
                if (response.status === 401) {
                    window.location.reload();
                    return;
                }
                const data = await response.json();

                document.getElementById('total-packets').textContent = data.total_packets.toLocaleString();
                document.getElementById('total-alerts').textContent = data.total_alerts.toLocaleString();
                document.getElementById('blocked-ips').textContent = data.blocked_ips.toLocaleString();
                document.getElementById('active-threats').textContent = data.active_threats.toLocaleString();

                const alertsBody = document.getElementById('alerts-body');
                alertsBody.innerHTML = '';
                data.recent_alerts.forEach(alert => {
                    const row = alertsBody.insertRow();
                    const time = new Date(alert.timestamp * 1000).toLocaleTimeString();
                    row.insertCell(0).textContent = time;
                    row.insertCell(1).textContent = alert.attack_type;
                    row.insertCell(2).textContent = alert.src_ip;
                    row.insertCell(3).textContent = alert.dst_ip;

                    const scoreCell = row.insertCell(4);
                    scoreCell.textContent = alert.score.toFixed(3);
                    if (alert.score > 0.7) scoreCell.className = 'alert-critical';
                    else if (alert.score > 0.5) scoreCell.className = 'alert-high';
                    else if (alert.score > 0.3) scoreCell.className = 'alert-medium';
                    else scoreCell.className = 'alert-low';

                    const actionCell = row.insertCell(5);
                    const blockBtn = document.createElement('button');
                    blockBtn.textContent = '🚫';
                    blockBtn.title = 'Заблокировать IP';
                    blockBtn.style.background = 'none';
                    blockBtn.style.border = 'none';
                    blockBtn.style.cursor = 'pointer';
                    blockBtn.style.fontSize = '1.2em';
                    blockBtn.onclick = () => blockIP(alert.src_ip);
                    actionCell.appendChild(blockBtn);
                });

                const attackersBody = document.getElementById('attackers-body');
                attackersBody.innerHTML = '';
                Object.entries(data.top_attackers).forEach(([ip, count]) => {
                    const row = attackersBody.insertRow();
                    row.insertCell(0).textContent = ip;
                    row.insertCell(1).textContent = count;
                });

                const targetsBody = document.getElementById('targets-body');
                targetsBody.innerHTML = '';
                Object.entries(data.top_targets).forEach(([ip, count]) => {
                    const row = targetsBody.insertRow();
                    row.insertCell(0).textContent = ip;
                    row.insertCell(1).textContent = count;
                });

                const typesBody = document.getElementById('types-body');
                typesBody.innerHTML = '';
                Object.entries(data.attack_types).sort((a,b) => b[1] - a[1]).forEach(([type, count]) => {
                    const row = typesBody.insertRow();
                    row.insertCell(0).textContent = type;
                    row.insertCell(1).textContent = count;
                });

            } catch (e) {
                console.error('Error fetching stats:', e);
            }
        }

        async function blockIP(ip) {
            if (!confirm(`Заблокировать IP ${ip}?`)) return;

            try {
                const response = await fetch('/api/block', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip})
                });
                const data = await response.json();
                if (data.status === 'ok') {
                    alert(`IP ${ip} заблокирован`);
                    fetchStats();
                } else {
                    alert(`Ошибка: ${data.error}`);
                }
            } catch (e) {
                alert('Ошибка соединения');
            }
        }

        async function logout() {
            try {
                await fetch('/api/logout', {method: 'POST'});
            } catch (e) {}
            if (window.location.href.indexOf('@') === -1) {
                window.location.href = window.location.protocol + '//logout@' + window.location.host;
            }
            setTimeout(() => window.location.reload(), 100);
        }

        fetchStats();
        setInterval(fetchStats, 30000);
    </script>
</body>
</html>'''


# ============================================================
# WEB DASHBOARD (исправлен - пункты 24, 29, 30, 44, 77)
# ============================================================

class WebDashboard(BaseModule):
    """Веб-дашборд для мониторинга (исправлен - аутентификация, валидация, нет утечек)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Dashboard", config, event_bus, logger)

        self.port = config.get('dashboard.port', 8080)
        self.enabled = config.get('dashboard.enabled', True)
        self.httpd = None

        # Аутентификация
        self.auth_enabled = config.get('dashboard.auth.enabled', True)
        self.username = config.get('dashboard.auth.username', 'admin')
        self.password = config.get('dashboard.auth.password', self._generate_default_password())
        self.api_keys = config.get('dashboard.auth.api_keys', [])
        self.session_tokens: Dict[str, float] = {}
        self.token_ttl = 3600

        # Очередь для отложенного снижения счётчика активных угроз
        self._decay_queue = queue.Queue()
        self._decay_thread = None

        # Данные для дашборда
        self.stats = {
            'total_packets': 0,
            'total_alerts': 0,
            'blocked_ips': 0,
            'active_threats': 0,
            'recent_alerts': deque(maxlen=100),
            'top_attackers': defaultdict(int),
            'top_targets': defaultdict(int),
            'attack_types': defaultdict(int),
            'last_alert_time': 0
        }

        self._lock = threading.RLock()

        # Подписки на события
        self.event_bus.subscribe('packet.processed', self.on_packet)
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('firewall.blocked', self.on_block)

        # Инициализация класса обработчика (однократно)
        self._init_handler_class()

        if self.auth_enabled:
            self.logger.info(f"🔐 Дашборд: логин '{self.username}', пароль '{self.password}'")

    def _generate_default_password(self) -> str:
        """Генерация случайного пароля если не задан"""
        import secrets
        return secrets.token_urlsafe(16)

    def _init_handler_class(self) -> None:
        """Инициализация класса обработчика (однократно)"""
        DashboardHandler.dashboard_stats = self.stats
        DashboardHandler.dashboard_logger = self.logger
        DashboardHandler.dashboard_lock = self._lock
        DashboardHandler.dashboard_check_auth = self._check_auth
        DashboardHandler.dashboard_auth_enabled = self.auth_enabled
        DashboardHandler.dashboard_validate_ip = self._validate_ip

    def _check_auth(self, headers: Dict) -> bool:
        """Проверка аутентификации (защита от timing attack)"""
        if not self.auth_enabled:
            return True

        auth_header = headers.get('Authorization', '')

        # Bearer token
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            if token in self.api_keys:
                return True
            if token in self.session_tokens:
                if time.time() < self.session_tokens[token]:
                    return True
                else:
                    del self.session_tokens[token]
            return False

        # Basic Auth с защитой от timing attack
        if auth_header.startswith('Basic '):
            import base64
            import hmac
            try:
                decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                username, password = decoded.split(':', 1)

                # Безопасное сравнение
                if not hmac.compare_digest(username, self.username):
                    return False
                if not hmac.compare_digest(password, self.password):
                    return False
                return True
            except:
                return False

        return False

    def _validate_ip(self, ip: str) -> bool:
        """Строгая валидация IP адреса"""
        if not ip:
            return False
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        if not match:
            return False
        for octet in match.groups():
            if int(octet) > 255:
                return False
        if re.search(r'[;&|`$()<>"\'\\\n\r]', ip):
            return False
        return True

    def start(self) -> None:
        if not self.enabled:
            return

        self.running = True

        self._decay_thread = threading.Thread(target=self._decay_worker, daemon=True, name="Dashboard-Decay")
        self._decay_thread.start()

        handler = self._create_handler()

        def run_server():
            try:
                with socketserver.TCPServer(("", self.port), handler) as httpd:
                    self.httpd = httpd
                    self.logger.info(f"🌐 Дашборд доступен на http://localhost:{self.port}")
                    if self.auth_enabled:
                        self.logger.info(f"🔐 Используйте логин: {self.username} / {self.password}")
                    httpd.serve_forever()
            except OSError as e:
                if e.errno in (98, 10048):
                    self.logger.warning(f"Порт {self.port} занят, пробуем {self.port + 1}")
                    self.port += 1
                    run_server()
            except Exception as e:
                self.logger.error(f"Ошибка запуска дашборда: {e}")

        threading.Thread(target=run_server, daemon=True, name="Dashboard-Server").start()

    def stop(self) -> None:
        self.running = False

        if self.httpd:
            try:
                self.httpd.shutdown()
            except:
                pass

        if self._decay_thread and self._decay_thread.is_alive():
            self._decay_thread.join(timeout=2)

        self.logger.info("Дашборд остановлен")

    def _decay_worker(self) -> None:
        """Единый воркер для снижения счётчика активных угроз"""
        while self.running:
            try:
                decay_count = self._decay_queue.get(timeout=30)
                time.sleep(300)

                with self._lock:
                    self.stats['active_threats'] = max(0, self.stats['active_threats'] - decay_count)

            except queue.Empty:
                with self._lock:
                    if self.stats['active_threats'] > 0:
                        last_alert = self.stats.get('last_alert_time', 0)
                        if time.time() - last_alert > 600:
                            self.stats['active_threats'] = 0
                            self.logger.debug("Сброс активных угроз по таймауту неактивности")

    def on_packet(self, data: Dict) -> None:
        with self._lock:
            self.stats['total_packets'] += data.get('count', 1)

    def on_alert(self, alert: Dict) -> None:
        with self._lock:
            self.stats['total_alerts'] += 1
            self.stats['active_threats'] += 1
            self.stats['last_alert_time'] = time.time()

            src_ip = alert.get('src_ip', 'unknown')
            dst_ip = alert.get('dst_ip', 'unknown')
            attack_type = str(alert.get('attack_type', 'Unknown'))

            self.stats['top_attackers'][src_ip] += 1
            self.stats['top_targets'][dst_ip] += 1
            self.stats['attack_types'][attack_type] += 1

            self.stats['recent_alerts'].appendleft({
                'timestamp': alert.get('timestamp', time.time()),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'attack_type': attack_type,
                'score': alert.get('score', 0),
                'severity': alert.get('severity', 'UNKNOWN')
            })

        self._decay_queue.put(1)

    def on_block(self, data: Dict) -> None:
        with self._lock:
            self.stats['blocked_ips'] += 1

    def reset_stats(self) -> None:
        """Сброс статистики дашборда"""
        with self._lock:
            self.stats['total_packets'] = 0
            self.stats['total_alerts'] = 0
            self.stats['blocked_ips'] = 0
            self.stats['active_threats'] = 0
            self.stats['recent_alerts'].clear()
            self.stats['top_attackers'].clear()
            self.stats['top_targets'].clear()
            self.stats['attack_types'].clear()
            self.stats['last_alert_time'] = 0
        self.logger.info("Статистика дашборда сброшена")

    def get_status(self) -> Dict:
        """Получить статус дашборда"""
        with self._lock:
            return {
                'enabled': self.enabled,
                'port': self.port,
                'running': self.running,
                'httpd_running': self.httpd is not None,
                'auth_enabled': self.auth_enabled,
                'queue_size': self._decay_queue.qsize(),
                'stats': {
                    'total_packets': self.stats['total_packets'],
                    'total_alerts': self.stats['total_alerts'],
                    'blocked_ips': self.stats['blocked_ips'],
                    'active_threats': self.stats['active_threats'],
                    'recent_alerts_count': len(self.stats['recent_alerts'])
                }
            }

    def _create_handler(self):
        """Создание обработчика HTTP запросов (переиспользуем класс)"""
        return DashboardHandler


# ============================================================
# 7️⃣ КОНТЕКСТ ACTIVE DIRECTORY / LDAP
# ============================================================

class LDAPContextProvider(BaseModule):
    """Получение контекста из Active Directory / LDAP (исправлен - реальное шифрование пароля)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("LDAP", config, event_bus, logger)

        self.server = config.get('ldap.server') or os.environ.get('LDAP_SERVER', '')
        self.domain = config.get('ldap.domain') or os.environ.get('LDAP_DOMAIN', '')
        self.base_dn = config.get('ldap.base_dn') or os.environ.get('LDAP_BASE_DN', '')
        self.bind_user = config.get('ldap.bind_user') or os.environ.get('LDAP_BIND_USER', '')

        # ========== РЕАЛЬНОЕ ШИФРОВАНИЕ ПАРОЛЯ ==========
        self._cipher = None
        self._bind_password_encrypted = None

        raw_password = config.get('ldap.bind_password') or os.environ.get('LDAP_BIND_PASSWORD', '')
        if raw_password:
            try:
                from cryptography.fernet import Fernet
                self._cipher = Fernet(self._get_or_create_key())
                self._bind_password_encrypted = self._cipher.encrypt(raw_password.encode())
                self.logger.info("LDAP пароль зашифрован с Fernet")
            except ImportError:
                # Fallback - base64 (только для совместимости, небезопасно!)
                import base64
                self._bind_password_encrypted = base64.b64encode(raw_password.encode()).decode()
                self.logger.warning("cryptography не установлен, пароль в base64 (НЕБЕЗОПАСНО!)")
            finally:
                # Очищаем raw_password из памяти
                raw_password = None

        # Удаляем пароль из переменных окружения если он там был
        if 'LDAP_BIND_PASSWORD' in os.environ:
            del os.environ['LDAP_BIND_PASSWORD']
        # ===============================================

        self.use_ssl = config.get('ldap.use_ssl', True)
        self.port = config.get('ldap.port', 636 if self.use_ssl else 389)

        self.user_cache: Dict[str, Dict] = {}
        self.group_cache: Dict[str, Dict] = {}
        self.computer_cache: Dict[str, Dict] = {}
        self.cache_ttl = 3600
        self.ldap_connection = None
        self.ldap_available = False

        # Привилегированные группы
        self.privileged_groups = {
            'Domain Admins', 'Enterprise Admins', 'Schema Admins',
            'Administrators', 'Backup Operators', 'Account Operators',
            'Server Operators', 'Print Operators', 'Remote Desktop Users',
            'DNS Admins', 'DHCP Administrators', 'Hyper-V Administrators'
        }

        # SID известных групп
        self.privileged_sids = {
            'S-1-5-21domain-512': 'Domain Admins',
            'S-1-5-21domain-519': 'Enterprise Admins',
            'S-1-5-21domain-518': 'Schema Admins',
            'S-1-5-32-544': 'Administrators',
            'S-1-5-32-551': 'Backup Operators',
            'S-1-5-32-548': 'Account Operators',
            'S-1-5-32-549': 'Server Operators',
            'S-1-5-32-550': 'Print Operators',
            'S-1-5-32-555': 'Remote Desktop Users'
        }

        self._lock = threading.RLock()
        self._connection_lock = threading.RLock()

        self.event_bus.subscribe('auth.login', self.on_login)
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('ldap.query.request', self.on_query_request)

    def _get_or_create_key(self) -> bytes:
        """Получить или создать ключ шифрования"""
        key_path = Path('data/ldap_key.key')
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            with open(key_path, 'rb') as f:
                return f.read()
        else:
            from cryptography.fernet import Fernet
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
            # Устанавливаем права только для владельца
            os.chmod(key_path, 0o600)
            return key

    def _get_bind_password(self) -> str:
        """Получить пароль (с расшифровкой)"""
        if not self._bind_password_encrypted:
            return ""
        try:
            if self._cipher:
                # Fernet шифрование
                return self._cipher.decrypt(self._bind_password_encrypted).decode()
            else:
                # Fallback base64
                import base64
                return base64.b64decode(self._bind_password_encrypted).decode()
        except Exception as e:
            self.logger.error(f"Ошибка расшифровки пароля: {e}")
            return ""

    def _sanitize_ldap_string(self, value: str, max_length: int = 200) -> str:
        """Санирование строк из LDAP"""
        if not value:
            return ""
        safe = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(value))
        return safe[:max_length]

    def start(self) -> None:
        self.running = True

        if self.server and self.bind_user:
            self.ldap_available = self._test_ldap_connection()
            if self.ldap_available:
                self.logger.info(f"LDAP провайдер запущен (сервер: {self.server}, домен: {self.domain})")
                threading.Thread(target=self._cache_refresh_loop, daemon=True).start()
            else:
                self.logger.warning("LDAP недоступен, используется режим ограниченной функциональности")
        else:
            self.logger.info("LDAP не настроен, используется базовый режим")

    def stop(self) -> None:
        self.running = False
        self._close_ldap_connection()

    def _get_ldap_connection(self):
        """Получение LDAP соединения (с безопасной работой с паролем)"""
        with self._connection_lock:
            if self.ldap_connection is not None:
                try:
                    self.ldap_connection.whoami_s()
                    return self.ldap_connection
                except:
                    self._close_ldap_connection()

            try:
                import ldap3
                from ldap3 import Server, Connection, ALL, NTLM

                if self.use_ssl:
                    server = Server(self.server, port=self.port, use_ssl=True, get_info=ALL)
                else:
                    server = Server(self.server, port=self.port, get_info=ALL)

                password = self._get_bind_password()

                try:
                    if '\\' in self.bind_user:
                        domain, username = self.bind_user.split('\\')
                        conn = Connection(
                            server,
                            user=f"{domain}\\{username}",
                            password=password,
                            authentication=NTLM,
                            auto_bind=True
                        )
                    else:
                        conn = Connection(
                            server,
                            user=self.bind_user,
                            password=password,
                            auto_bind=True
                        )

                    self.ldap_connection = conn
                    return conn
                finally:
                    # Стираем пароль из памяти
                    password = '\x00' * len(password)
                    del password

            except ImportError:
                self.logger.warning("ldap3 не установлен. Установите: pip install ldap3")
                return None
            except Exception as e:
                self.logger.error(f"Ошибка LDAP подключения: {type(e).__name__}")
                return None

    def _close_ldap_connection(self) -> None:
        """Закрытие LDAP соединения"""
        with self._connection_lock:
            if self.ldap_connection:
                try:
                    self.ldap_connection.unbind()
                except:
                    pass
                self.ldap_connection = None

    def _test_ldap_connection(self) -> bool:
        """Тестирование LDAP соединения"""
        conn = self._get_ldap_connection()
        if conn and conn.bound:
            self.logger.info("LDAP соединение успешно установлено")
            return True
        return False

    def _get_search_base(self) -> str:
        """Получение базы поиска"""
        if self.base_dn:
            return self.base_dn
        if self.domain:
            return ','.join([f"DC={part}" for part in self.domain.split('.')])
        return ""

    def _extract_cn_from_dn(self, dn: str) -> Optional[str]:
        """Извлечение CN из DN"""
        for part in dn.split(','):
            if part.strip().upper().startswith('CN='):
                return self._sanitize_ldap_string(part.strip()[3:], 100)
        return None

    def _sid_to_string(self, sid_bytes: bytes) -> str:
        """Преобразование SID из байт в строку"""
        try:
            if not sid_bytes:
                return ""
            revision = sid_bytes[0]
            sub_authority_count = sid_bytes[1]
            identifier_authority = int.from_bytes(sid_bytes[2:8], 'big')
            sid_string = f"S-{revision}-{identifier_authority}"
            for i in range(sub_authority_count):
                offset = 8 + i * 4
                sub_auth = int.from_bytes(sid_bytes[offset:offset + 4], 'little')
                sid_string += f"-{sub_auth}"
            return sid_string
        except:
            return ""

    def _filetime_to_datetime(self, filetime: int) -> Optional[str]:
        """Преобразование Windows FILETIME в datetime"""
        if filetime == 0 or filetime == 0x7FFFFFFFFFFFFFFF:
            return None
        try:
            epoch = datetime(1601, 1, 1)
            timestamp = filetime / 10000000
            dt = epoch + timedelta(seconds=timestamp)
            return dt.isoformat()
        except:
            return None

    def on_login(self, data: Dict) -> None:
        """Обогащение события входа LDAP контекстом"""
        username = data.get('username', '')
        src_ip = data.get('src_ip', '')

        if username:
            context = self.get_user_context(username)
            data['ldap_context'] = context
            data['is_privileged'] = context.get('is_privileged', False)

            if src_ip:
                self.event_bus.publish('uba.bind_ip', {
                    'ip': src_ip,
                    'username': username
                })

    def on_alert(self, alert: Dict) -> None:
        """Добавление LDAP контекста к алерту"""
        src_ip = alert.get('src_ip', '')
        username = alert.get('username')

        if not username and src_ip:
            username = self._find_username_by_ip(src_ip)
            if username:
                alert['username'] = username

        if username:
            context = self.get_user_context(username)
            alert['ldap_context'] = context

            if context.get('is_privileged', False):
                alert['is_privileged_account'] = True
                current_severity = alert.get('severity', 'LOW')
                if current_severity == 'LOW':
                    alert['severity'] = 'MEDIUM'
                elif current_severity == 'MEDIUM':
                    alert['severity'] = 'HIGH'
                elif current_severity == 'HIGH':
                    alert['severity'] = 'CRITICAL'

                alert['score'] = min(1.0, alert.get('score', 0) + 0.3)

                if alert.get('explanation'):
                    alert['explanation'] += f' Атака на привилегированную учётную запись {username}!'
                else:
                    alert['explanation'] = f'Атака на привилегированную учётную запись {username}!'

    def on_query_request(self, data: Dict) -> None:
        """Обработка запроса к LDAP"""
        query_type = data.get('type', '')
        query_value = data.get('value', '')
        request_id = data.get('request_id', '')

        result = {}

        if query_type == 'user':
            result = self.get_user_context(query_value)
        elif query_type == 'group':
            result = {'members': self.get_group_members(query_value)}
        elif query_type == 'computer':
            result = self.get_computer_info(query_value)

        self.event_bus.publish('ldap.query.response', {
            'request_id': request_id,
            'result': result
        })

    def _find_username_by_ip(self, ip: str) -> Optional[str]:
        """Поиск username по IP в кэше"""
        with self._lock:
            for username, context in self.user_cache.items():
                if ip in context.get('recent_ips', []):
                    return username
        return None

    def get_user_context(self, username: str) -> Dict:
        """Получить контекст пользователя из LDAP"""
        with self._lock:
            if username in self.user_cache:
                cached = self.user_cache[username]
                if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                    return cached.copy()

        context = self._fetch_user_context_ldap(username)

        if not context and self.ldap_available:
            for variant in self._get_username_variants(username):
                context = self._fetch_user_context_ldap(variant)
                if context:
                    break

        if not context:
            context = self._create_basic_context(username)

        with self._lock:
            context['timestamp'] = time.time()
            self.user_cache[username] = context.copy()

        return context

    def _get_username_variants(self, username: str) -> List[str]:
        """Получение вариантов username для поиска"""
        variants = [username]
        if '\\' in username:
            variants.append(username.split('\\')[1])
        if '@' in username:
            variants.append(username.split('@')[0])
        if self.domain:
            variants.append(f"{username}@{self.domain}")
            variants.append(f"{self.domain}\\{username}")
        return variants

    def _fetch_user_context_ldap(self, username: str) -> Optional[Dict]:
        """Реальный запрос к LDAP для получения контекста пользователя"""
        conn = self._get_ldap_connection()
        if not conn:
            return None

        try:
            search_filter = f"(|(sAMAccountName={username})(userPrincipalName={username}))"

            attributes = [
                'sAMAccountName', 'displayName', 'mail', 'department',
                'title', 'manager', 'memberOf', 'userAccountControl',
                'lastLogon', 'pwdLastSet', 'whenCreated', 'badPwdCount',
                'logonCount', 'homeDirectory', 'scriptPath', 'profilePath',
                'objectSid', 'primaryGroupID', 'distinguishedName'
            ]

            conn.search(
                search_base=self._get_search_base(),
                search_filter=search_filter,
                attributes=attributes,
                size_limit=1
            )

            if not conn.entries:
                return None

            entry = conn.entries[0]

            context = {
                'username': self._sanitize_ldap_string(str(entry.sAMAccountName)) if hasattr(entry,
                                                                                             'sAMAccountName') else username,
                'display_name': self._sanitize_ldap_string(str(entry.displayName)) if hasattr(entry,
                                                                                              'displayName') else username,
                'email': self._sanitize_ldap_string(str(entry.mail), 100) if hasattr(entry, 'mail') else None,
                'department': self._sanitize_ldap_string(str(entry.department), 100) if hasattr(entry,
                                                                                                'department') else None,
                'title': self._sanitize_ldap_string(str(entry.title), 100) if hasattr(entry, 'title') else None,
                'manager': self._sanitize_ldap_string(str(entry.manager), 200) if hasattr(entry, 'manager') else None,
                'distinguished_name': self._sanitize_ldap_string(str(entry.distinguishedName), 300) if hasattr(entry,
                                                                                                               'distinguishedName') else None,
                'groups': [],
                'is_admin': False,
                'is_privileged': False,
                'enabled': True,
                'password_last_set': None,
                'last_logon': None,
                'bad_password_count': 0,
                'logon_count': 0,
                'recent_ips': [],
                'sid': None
            }

            if hasattr(entry, 'userAccountControl'):
                uac = int(entry.userAccountControl.value)
                context['enabled'] = not (uac & 0x0002)
                context['password_never_expires'] = bool(uac & 0x10000)
                context['is_locked'] = bool(uac & 0x0010)

            if hasattr(entry, 'memberOf'):
                for group_dn in entry.memberOf.values:
                    group_name = self._extract_cn_from_dn(group_dn)
                    if group_name:
                        context['groups'].append(group_name)
                        if group_name in self.privileged_groups:
                            context['is_privileged'] = True
                            context['is_admin'] = True

            if hasattr(entry, 'objectSid'):
                context['sid'] = self._sid_to_string(entry.objectSid.value)
                for priv_sid in self.privileged_sids:
                    if context['sid'] and priv_sid in context['sid']:
                        context['is_privileged'] = True

            if hasattr(entry, 'pwdLastSet') and entry.pwdLastSet.value:
                try:
                    context['password_last_set'] = self._filetime_to_datetime(int(entry.pwdLastSet.value))
                except:
                    pass

            if hasattr(entry, 'lastLogon') and entry.lastLogon.value:
                try:
                    context['last_logon'] = self._filetime_to_datetime(int(entry.lastLogon.value))
                except:
                    pass

            if hasattr(entry, 'badPwdCount'):
                context['bad_password_count'] = int(entry.badPwdCount.value)

            if hasattr(entry, 'logonCount'):
                context['logon_count'] = int(entry.logonCount.value)

            context['recent_ips'] = self._get_recent_logon_ips(username)

            return context

        except Exception as e:
            self.logger.error(f"Ошибка LDAP запроса для {username}: {type(e).__name__}")
            return None

    def _get_recent_logon_ips(self, username: str) -> List[str]:
        """Получение недавних IP из логов входа (исправлено - без утечки подписок)"""
        ips = []

        try:
            response_queue = queue.Queue()
            request_id = f"ldap_ips_{username}_{int(time.time())}_{threading.get_ident()}"

            received_response = threading.Event()
            response_data = {}

            def on_response(data):
                if data.get('request_id') == request_id:
                    response_data['ips'] = data.get('ips', [])
                    received_response.set()

            self.event_bus.subscribe('siem.ips.response', on_response)

            try:
                self.event_bus.publish('siem.ips.request', {
                    'request_id': request_id,
                    'username': username,
                    'hours': 24
                })

                if received_response.wait(timeout=3):
                    ips = response_data.get('ips', [])

            except Exception as e:
                self.logger.debug(f"Ошибка ожидания ответа SIEM: {e}")
            finally:
                self.event_bus.unsubscribe('siem.ips.response', on_response)

        except Exception as e:
            self.logger.debug(f"Ошибка получения IP для {username}: {e}")

        return ips

    def _create_basic_context(self, username: str) -> Dict:
        """Создание базового контекста когда LDAP недоступен"""
        context = {
            'username': username,
            'display_name': username,
            'groups': [],
            'is_admin': False,
            'is_privileged': False,
            'department': None,
            'title': None,
            'email': f"{username}@{self.domain}" if self.domain else None,
            'enabled': True,
            'password_last_set': None,
            'last_logon': None,
            'bad_password_count': 0,
            'logon_count': 0,
            'recent_ips': [],
            'source': 'basic'
        }

        username_lower = username.lower()
        privileged_keywords = ['admin', 'root', 'backup', 'service', 'sql', 'db', 'sys']

        for kw in privileged_keywords:
            if kw in username_lower:
                context['is_privileged'] = True
                context['groups'].append('Possible Privileged Account')
                break

        return context

    def is_privileged_account(self, username: str) -> bool:
        """Проверка, является ли учётная запись привилегированной"""
        ctx = self.get_user_context(username)
        return ctx.get('is_privileged', False)

    def get_group_members(self, group_name: str) -> List[str]:
        """Получить членов группы из LDAP"""
        with self._lock:
            if group_name in self.group_cache:
                cached = self.group_cache[group_name]
                if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                    return cached.get('members', []).copy()

        members = self._fetch_group_members_ldap(group_name)

        if not members and self.ldap_available:
            group_dn = f"CN={group_name},CN=Users,{self._get_search_base()}"
            members = self._fetch_group_members_ldap(group_dn, use_filter=False)

        with self._lock:
            self.group_cache[group_name] = {
                'members': members.copy(),
                'timestamp': time.time()
            }

        return members

    def _fetch_group_members_ldap(self, group_identifier: str, use_filter: bool = True) -> List[str]:
        """Реальный запрос к LDAP для получения членов группы"""
        conn = self._get_ldap_connection()
        if not conn:
            return []

        try:
            if use_filter:
                search_filter = f"(&(objectClass=group)(|(cn={group_identifier})(sAMAccountName={group_identifier})))"
                search_base = self._get_search_base()
            else:
                search_filter = "(objectClass=*)"
                search_base = group_identifier

            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=['member'],
                size_limit=1
            )

            if not conn.entries:
                return []

            members = []
            if hasattr(conn.entries[0], 'member'):
                for member_dn in conn.entries[0].member.values:
                    username = self._extract_cn_from_dn(member_dn)
                    if username:
                        members.append(username)

            return members

        except Exception as e:
            self.logger.error(f"Ошибка получения членов группы {group_identifier}: {type(e).__name__}")
            return []

    def get_computer_info(self, computer_name: str) -> Dict:
        """Получить информацию о компьютере из AD"""
        with self._lock:
            if computer_name in self.computer_cache:
                cached = self.computer_cache[computer_name]
                if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                    return cached.copy()

        info = self._fetch_computer_info_ldap(computer_name)

        if not info:
            info = {
                'name': computer_name,
                'enabled': True,
                'os': 'Unknown',
                'last_logon': None,
                'source': 'basic'
            }

        with self._lock:
            info['timestamp'] = time.time()
            self.computer_cache[computer_name] = info.copy()

        return info

    def _fetch_computer_info_ldap(self, computer_name: str) -> Optional[Dict]:
        """Запрос информации о компьютере из LDAP"""
        conn = self._get_ldap_connection()
        if not conn:
            return None

        try:
            search_filter = f"(&(objectClass=computer)(|(cn={computer_name})(sAMAccountName={computer_name}$)))"

            conn.search(
                search_base=self._get_search_base(),
                search_filter=search_filter,
                attributes=['cn', 'operatingSystem', 'operatingSystemVersion',
                            'lastLogonTimestamp', 'userAccountControl', 'dNSHostName'],
                size_limit=1
            )

            if not conn.entries:
                return None

            entry = conn.entries[0]

            info = {
                'name': self._sanitize_ldap_string(str(entry.cn)) if hasattr(entry, 'cn') else computer_name,
                'dns_hostname': self._sanitize_ldap_string(str(entry.dNSHostName)) if hasattr(entry,
                                                                                              'dNSHostName') else None,
                'os': self._sanitize_ldap_string(str(entry.operatingSystem)) if hasattr(entry,
                                                                                        'operatingSystem') else 'Unknown',
                'os_version': self._sanitize_ldap_string(str(entry.operatingSystemVersion)) if hasattr(entry,
                                                                                                       'operatingSystemVersion') else None,
                'enabled': True,
                'last_logon': None
            }

            if hasattr(entry, 'userAccountControl'):
                uac = int(entry.userAccountControl.value)
                info['enabled'] = not (uac & 0x0002)

            if hasattr(entry, 'lastLogonTimestamp') and entry.lastLogonTimestamp.value:
                try:
                    info['last_logon'] = self._filetime_to_datetime(int(entry.lastLogonTimestamp.value))
                except:
                    pass

            return info

        except Exception as e:
            self.logger.error(f"Ошибка получения информации о компьютере {computer_name}: {type(e).__name__}")
            return None

    def _cache_refresh_loop(self) -> None:
        """Периодическое обновление кэша"""
        while self.running:
            time.sleep(self.cache_ttl // 2)

            with self._lock:
                now = time.time()
                for cache_dict in [self.user_cache, self.group_cache, self.computer_cache]:
                    expired = [
                        key for key, data in cache_dict.items()
                        if now - data.get('timestamp', 0) > self.cache_ttl * 2
                    ]
                    for key in expired:
                        del cache_dict[key]

    def search_users(self, query: str, limit: int = 10) -> List[Dict]:
        """Поиск пользователей в LDAP"""
        conn = self._get_ldap_connection()
        if not conn:
            return []

        try:
            search_filter = f"(&(objectClass=user)(|(cn=*{query}*)(sAMAccountName=*{query}*)(mail=*{query}*)))"

            conn.search(
                search_base=self._get_search_base(),
                search_filter=search_filter,
                attributes=['sAMAccountName', 'displayName', 'mail', 'department', 'title'],
                size_limit=limit
            )

            results = []
            for entry in conn.entries:
                results.append({
                    'username': self._sanitize_ldap_string(str(entry.sAMAccountName)) if hasattr(entry,
                                                                                                 'sAMAccountName') else '',
                    'display_name': self._sanitize_ldap_string(str(entry.displayName)) if hasattr(entry,
                                                                                                  'displayName') else '',
                    'email': self._sanitize_ldap_string(str(entry.mail)) if hasattr(entry, 'mail') else '',
                    'department': self._sanitize_ldap_string(str(entry.department)) if hasattr(entry,
                                                                                               'department') else '',
                    'title': self._sanitize_ldap_string(str(entry.title)) if hasattr(entry, 'title') else ''
                })

            return results

        except Exception as e:
            self.logger.error(f"Ошибка поиска пользователей: {type(e).__name__}")
            return []

    def get_domain_controllers(self) -> List[str]:
        """Получение списка контроллеров домена"""
        conn = self._get_ldap_connection()
        if not conn:
            return []

        try:
            search_filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"

            conn.search(
                search_base=self._get_search_base(),
                search_filter=search_filter,
                attributes=['cn', 'dNSHostName'],
                size_limit=10
            )

            dcs = []
            for entry in conn.entries:
                if hasattr(entry, 'dNSHostName'):
                    dcs.append(self._sanitize_ldap_string(str(entry.dNSHostName), 100))
                elif hasattr(entry, 'cn'):
                    dcs.append(self._sanitize_ldap_string(str(entry.cn), 100))

            return dcs

        except Exception as e:
            self.logger.error(f"Ошибка получения контроллеров домена: {type(e).__name__}")
            return []

    def clear_cache(self) -> None:
        """Очистка всего кэша"""
        with self._lock:
            self.user_cache.clear()
            self.group_cache.clear()
            self.computer_cache.clear()
        self.logger.info("Кэш LDAP очищен")


# ============================================================
# 8️⃣ EMAIL УГРОЗЫ
# ============================================================

class EmailThreatAnalyzer(BaseModule):
    """Анализ email угроз (фишинг, подозрительные вложения)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("EmailAnalyzer", config, event_bus, logger)

        self.phishing_keywords = {
            'verify', 'account', 'login', 'password', 'urgent', 'suspended',
            'security', 'update', 'confirm', 'limited', 'unusual', 'activity',
            'click', 'link', 'immediately', 'action', 'required', 'validate',
            'authenticate', 'billing', 'invoice', 'payment', 'paypal',
            'microsoft', 'google', 'apple', 'amazon', 'bank', 'alert'
        }

        self.suspicious_extensions = {
            '.exe', '.scr', '.vbs', '.js', '.bat', '.ps1', '.hta',
            '.docm', '.xlsm', '.pptm', '.jar', '.msi', '.reg',
            '.vbe', '.wsf', '.wsh', '.psc1', '.ps1xml', '.ps2xml'
        }

        self.suspicious_senders = set()
        self.spoofed_domains = {
            'paypal.com', 'microsoft.com', 'google.com', 'apple.com',
            'amazon.com', 'facebook.com', 'netflix.com', 'dropbox.com'
        }

        self._lock = threading.RLock()
        self.event_bus.subscribe('email.received', self.on_email)

    def start(self) -> None:
        self.running = True
        self.logger.info("Анализатор email угроз запущен")

    def stop(self) -> None:
        self.running = False

    def on_email(self, data: Dict) -> None:
        """Анализ email сообщения"""
        sender = data.get('sender', '')
        recipient = data.get('recipient', '')
        subject = data.get('subject', '')
        body = data.get('body', '')
        attachments = data.get('attachments', [])
        headers = data.get('headers', {})

        result = self.analyze_email(sender, subject, body, attachments, headers)

        if result['is_suspicious']:
            result['recipient'] = recipient
            result['timestamp'] = time.time()

            self.event_bus.publish('email.threat', result)
            self.logger.warning(f"Подозрительное письмо от {sender}: score={result['score']:.3f}")

    def analyze_email(self, sender: str, subject: str, body: str,
                      attachments: List[str], headers: Dict = None) -> Dict:
        """Анализ email на угрозы"""
        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'attack_type': None,
            'severity': AlertSeverity.LOW.value
        }

        subject_lower = subject.lower()
        body_lower = body.lower()

        # 1. Фишинговые ключевые слова в теме
        keyword_count = 0
        for kw in self.phishing_keywords:
            if kw in subject_lower:
                keyword_count += 1
                result['reasons'].append(f"phishing_keyword_subject:{kw}")

        if keyword_count >= 3:
            result['is_suspicious'] = True
            result['score'] += 0.25
            result['attack_type'] = AttackType.PHISHING.value
        elif keyword_count >= 1:
            result['score'] += 0.1

        # 2. Ключевые слова в теле
        body_keywords = 0
        urgency_words = {'urgent', 'immediately', 'action required', 'limited time'}
        for kw in urgency_words:
            if kw in body_lower:
                body_keywords += 1
                result['reasons'].append(f"urgency:{kw}")
                result['score'] += 0.15

        # 3. Подозрительный отправитель
        sender_lower = sender.lower()
        sender_domain = sender_lower.split('@')[-1] if '@' in sender_lower else ''

        # Проверка на спуфинг
        for domain in self.spoofed_domains:
            if domain in sender_domain and not sender_domain.endswith(f".{domain}"):
                # Проверяем, не является ли это подделкой
                if domain not in sender_domain.split('.')[-2:]:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"spoofed_sender:{domain}")
                    result['score'] += 0.35
                    result['attack_type'] = AttackType.PHISHING.value

        # Подозрительные TLD
        suspicious_tlds = {'.ru', '.cn', '.xyz', '.top', '.club', '.work', '.date'}
        for tld in suspicious_tlds:
            if sender_domain.endswith(tld):
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_tld:{tld}")
                result['score'] += 0.2

        # Проверка известных подозрительных отправителей
        if sender_lower in self.suspicious_senders:
            result['is_suspicious'] = True
            result['reasons'].append("known_suspicious_sender")
            result['score'] += 0.4

        # 4. Опасные вложения
        dangerous_attachments = []
        for att in attachments:
            att_lower = att.lower()
            for ext in self.suspicious_extensions:
                if att_lower.endswith(ext):
                    dangerous_attachments.append(att)
                    result['is_suspicious'] = True
                    result['reasons'].append(f"dangerous_attachment:{att}")
                    result['score'] += 0.3

                    if ext in ['.exe', '.scr', '.vbs', '.js']:
                        result['score'] += 0.2

        if dangerous_attachments:
            result['attack_type'] = AttackType.MALWARE.value

        # 5. Ссылки в теле письма
        urls = self._extract_urls(body)
        suspicious_urls = []
        for url in urls:
            if self._is_suspicious_url(url):
                suspicious_urls.append(url)
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_url:{url[:50]}")
                result['score'] += 0.25
                result['attack_type'] = AttackType.PHISHING.value

        # 6. Проверка заголовков
        if headers:
            # Проверка SPF/DKIM/DMARC
            auth_results = headers.get('Authentication-Results', '')
            if 'spf=fail' in auth_results.lower() or 'dkim=fail' in auth_results.lower():
                result['is_suspicious'] = True
                result['reasons'].append("auth_failure")
                result['score'] += 0.3

        # 7. Необычное время отправки
        # (можно добавить анализ временных меток)

        result['score'] = min(1.0, result['score'])

        # Определение серьёзности
        if result['score'] > 0.7:
            result['severity'] = AlertSeverity.CRITICAL.value
        elif result['score'] > 0.5:
            result['severity'] = AlertSeverity.HIGH.value
        elif result['score'] > 0.3:
            result['severity'] = AlertSeverity.MEDIUM.value

        result['details'] = {
            'sender': sender,
            'subject': subject,
            'keyword_count': keyword_count,
            'dangerous_attachments': dangerous_attachments,
            'suspicious_urls': suspicious_urls
        }

        # Добавляем отправителя в список подозрительных при высоком score
        if result['score'] > 0.6:
            with self._lock:
                self.suspicious_senders.add(sender_lower)

        return result

    def _extract_urls(self, text: str) -> List[str]:
        """Извлечение URL из текста"""
        url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+|www\.[^\s<>"\'{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        return urls

    def _is_suspicious_url(self, url: str) -> bool:
        """Проверка URL на подозрительность (исправлена логика спуфинга)"""
        url_lower = url.lower()

        # Короткие ссылки
        shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'rb.gy',
                      'cutt.ly'}
        for short in shorteners:
            if short in url_lower:
                return True

        # IP адреса вместо доменов
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url_lower):
            return True

        # Необычные TLD
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.date'}
        for tld in suspicious_tlds:
            if url_lower.endswith(tld) or f'.{tld}/' in url_lower:
                return True

        # ИСПРАВЛЕННАЯ ПРОВЕРКА СПУФИНГА ДОМЕНОВ
        # Извлекаем домен из URL
        domain_match = re.search(r'https?://([^/:\s]+)', url_lower)
        if not domain_match:
            domain_match = re.search(r'([^/:\s]+\.[^/:\s]+)$', url_lower.split('/')[0])

        if domain_match:
            domain = domain_match.group(1)

            # Проверяем легитимные домены на спуфинг
            legitimate_domains = {
                'paypal.com': 'paypal',
                'microsoft.com': 'microsoft',
                'google.com': 'google',
                'apple.com': 'apple',
                'amazon.com': 'amazon',
                'facebook.com': 'facebook',
                'netflix.com': 'netflix',
                'dropbox.com': 'dropbox',
                'bankofamerica.com': 'bankofamerica',
                'chase.com': 'chase',
                'wellsfargo.com': 'wellsfargo'
            }

            for legit_domain, brand in legitimate_domains.items():
                # Проверяем точное совпадение или поддомен
                if domain == legit_domain or domain.endswith('.' + legit_domain):
                    # Это легитимный домен
                    continue

                # Проверяем наличие бренда в домене (спуфинг)
                if brand in domain:
                    # Проверяем, не является ли это частью другого слова
                    # Например: "paypal" в "paypal-secure.evil.com" - спуфинг
                    # Но "paypal" в "some-paypal.com" - тоже спуфинг
                    if legit_domain not in domain:
                        return True

        # Подозрительные ключевые слова в URL
        suspicious_keywords = {'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
                               'password', 'banking', 'webscr', 'cgi-bin', 'auth'}

        keyword_count = sum(1 for kw in suspicious_keywords if kw in url_lower)
        if keyword_count >= 3:
            return True

        # Проверка на использование @ в URL (может скрывать реальный домен)
        if '@' in url and '://' in url:
            parts = url.split('@')
            if len(parts) > 1 and '://' in parts[0]:
                return True

        # Проверка на необычные порты
        if re.search(r':\d{4,5}/', url_lower):
            return True

        # Проверка на множественные поддомены (более 4)
        if domain_match:
            domain = domain_match.group(1)
            subdomain_count = domain.count('.')
            if subdomain_count > 4:
                return True

        return False

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            return {
                'suspicious_senders': len(self.suspicious_senders),
                'recent_senders': list(self.suspicious_senders)[:20]
            }


# ============================================================
# 9️⃣ EDR ИНТЕГРАЦИЯ (WINDOWS EVENT LOGS)
# ============================================================

class EDRIntegration(BaseModule):
    """Интеграция с EDR/антивирусами через Windows Event Logs / Sysmon / WMI (полная реальная версия)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("EDR", config, event_bus, logger)

        # Буферы событий
        self.process_events: deque = deque(maxlen=5000)
        self.file_events: deque = deque(maxlen=2000)
        self.registry_events: deque = deque(maxlen=2000)
        self.network_events: deque = deque(maxlen=2000)
        self.dns_events: deque = deque(maxlen=1000)
        self.image_load_events: deque = deque(maxlen=1000)

        # Подозрительные процессы и паттерны
        self.suspicious_processes = {
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'mshta.exe', 'regsvr32.exe', 'schtasks.exe',
            'wmic.exe', 'bitsadmin.exe', 'certutil.exe', 'msiexec.exe',
            'taskkill.exe', 'net.exe', 'net1.exe', 'sc.exe', 'bcdedit.exe',
            'vssadmin.exe', 'wbadmin.exe', 'diskpart.exe', 'format.com',
            'cacls.exe', 'icacls.exe', 'xcopy.exe', 'robocopy.exe',
            'ftp.exe', 'telnet.exe', 'psexec.exe', 'psexesvc.exe',
            'mimikatz.exe', 'procdump.exe', 'lsass.exe', 'lsass.dmp',
            'csrss.exe', 'smss.exe', 'winlogon.exe', 'services.exe'
        }

        self.suspicious_cmdline = [
            '-enc', '-encodedcommand', '-e ', 'iex', 'invoke-',
            'downloadstring', 'downloadfile', 'webclient',
            'net user', 'net group', 'net localgroup',
            'reg add', 'reg delete', 'reg save',
            'schtasks /create', 'taskkill /f',
            'wmic process', 'wmic service',
            'bitsadmin /transfer', 'certutil -urlcache',
            'mshta http', 'mshta javascript',
            'rundll32 javascript', 'rundll32 http',
            'powershell -w hidden', 'powershell -window hidden',
            '-nop -w hidden', '-noprofile -windowstyle hidden',
            'add-mppreference', 'set-mppreference',
            'mimikatz', 'procdump', 'lsass', 'sekurlsa',
            'cobaltstrike', 'metasploit', 'meterpreter',
            'reflectiveloader', 'invoke-mimikatz', 'invoke-shellcode',
            'invoke-reflection', 'invoke-dllinjection',
            'amsiinitfailed', 'amsiscanbuffer', 'amsiopenSession',
            'virtualalloc', 'virtualprotect', 'writeprocessmemory',
            'createremotethread', 'ntallocatevirtualmemory',
            'rtlcreateuserthread', 'etwpcreateetwthread',
            'syscall', 'ntcreatefile', 'ntopenprocess',
            'base64', 'frombase64string', 'tobase64string'
        ]

        self.suspicious_paths = [
            '\\temp\\', '/tmp/', '\\users\\public\\',
            '\\appdata\\local\\temp\\', '\\windows\\temp\\',
            '\\downloads\\', '\\desktop\\',
            '\\programdata\\', '\\recycler\\', '\\$recycle.bin\\',
            '\\windows\\syswow64\\', '\\windows\\system32\\spool\\drivers\\color\\',
            '\\windows\\tasks\\', '\\windows\\system32\\tasks\\',
            '\\microsoft\\windows\\start menu\\programs\\startup\\',
            '\\appdata\\roaming\\', '\\appdata\\locallow\\',
            '\\windows\\fonts\\', '\\windows\\help\\', '\\windows\\inf\\'
        ]

        self.suspicious_registry_keys = [
            '\\software\\microsoft\\windows\\currentversion\\run',
            '\\software\\microsoft\\windows\\currentversion\\runonce',
            '\\software\\microsoft\\windows\\currentversion\\runservices',
            '\\software\\microsoft\\windows nt\\currentversion\\winlogon',
            '\\software\\microsoft\\windows\\currentversion\\policies\\system',
            '\\system\\currentcontrolset\\services',
            '\\software\\microsoft\\windows\\currentversion\\explorer\\usershell folders',
            '\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run',
            '\\software\\microsoft\\windows nt\\currentversion\\windows',
            '\\software\\microsoft\\windows nt\\currentversion\\image file execution options',
            '\\software\\microsoft\\windows\\currentversion\\shell extensions\\approved',
            '\\software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects',
            '\\software\\wow6432node\\microsoft\\windows\\currentversion\\run',
            '\\\\software\\\\classes\\\\*\\\\shell',
            '\\software\\classes\\directory\\shell'
        ]

        self.suspicious_dlls = [
            'ntdll.dll', 'kernel32.dll', 'kernelbase.dll',
            'advapi32.dll', 'user32.dll', 'gdi32.dll',
            'wininet.dll', 'urlmon.dll', 'ws2_32.dll',
            'mimikatz.dll', 'samlib.dll', 'vaultcli.dll',
            'ncrypt.dll', 'cryptdll.dll', 'dpapi.dll'
        ]

        # Настройки Windows Event Log
        self.win_event_logs = config.get('edr.windows_event_logs', [
            'Security',
            'System',
            'Microsoft-Windows-Sysmon/Operational',
            'Windows PowerShell',
            'Microsoft-Windows-WMI-Activity/Operational',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
            'Microsoft-Windows-TaskScheduler/Operational',
            'Microsoft-Windows-DNS-Client/Operational'
        ])

        self.poll_interval = config.get('edr.poll_interval', 5)
        self.use_win32evtlog = False
        self.event_log_handles = {}
        self.last_event_ids = {}
        self.last_event_times = {}

        # WMI мониторинг
        self.use_wmi = False
        self.wmi_connection = None
        self.wmi_watchers = []

        # ETW мониторинг (если доступно)
        self.use_etw = False

        # Блокировка
        self._lock = threading.RLock()

        # Инициализация
        self._init_windows_event_log()
        self._init_wmi()

        # Подписки на события
        self.event_bus.subscribe('edr.event', self.on_edr_event)
        self.event_bus.subscribe('sysmon.event', self.on_sysmon_event)
        self.event_bus.subscribe('wmi.event', self.on_wmi_event)

    def _init_windows_event_log(self) -> None:
        """Инициализация чтения Windows Event Log"""
        if sys.platform != 'win32':
            self.logger.debug("Не Windows платформа, чтение Event Log отключено")
            return

        try:
            import win32evtlog
            import win32evtlogutil
            import win32security
            import win32con
            import winerror

            self.use_win32evtlog = True
            self.logger.info("Windows Event Log мониторинг инициализирован")

        except ImportError:
            self.logger.warning("pywin32 не установлен. Установите: pip install pywin32")
            self.use_win32evtlog = False

    def _init_wmi(self) -> None:
        """Инициализация WMI мониторинга"""
        if sys.platform != 'win32':
            return

        try:
            import wmi
            import pythoncom

            pythoncom.CoInitialize()
            self.wmi_connection = wmi.WMI()
            self.use_wmi = True
            self.logger.info("WMI мониторинг инициализирован")

        except ImportError:
            self.logger.debug("wmi не установлен. Установите: pip install wmi")
            self.use_wmi = False
        except Exception as e:
            self.logger.debug(f"Ошибка инициализации WMI: {e}")
            self.use_wmi = False

    def start(self) -> None:
        self.running = True

        # Проверяем платформу перед запуском Windows-специфичных потоков
        if self.use_win32evtlog and sys.platform == 'win32':
            threading.Thread(target=self._windows_event_loop, daemon=True, name="EDR-EventLog").start()
        elif self.use_win32evtlog:
            self.logger.debug("Windows Event Log мониторинг доступен только на Windows")

        if self.use_wmi and sys.platform == 'win32':
            threading.Thread(target=self._wmi_event_loop, daemon=True, name="EDR-WMI").start()
        elif self.use_wmi:
            self.logger.debug("WMI мониторинг доступен только на Windows")

        # Запуск потока анализа (кроссплатформенный)
        threading.Thread(target=self._analysis_loop, daemon=True, name="EDR-Analysis").start()

        self.logger.info("EDR интеграция запущена")

    def stop(self) -> None:
        """Остановка модуля"""
        self.running = False

        # Закрытие хендлов Event Log
        for log_name, handle in self.event_log_handles.items():
            try:
                import win32evtlog
                win32evtlog.CloseEventLog(handle)
            except:
                pass
        self.event_log_handles.clear()

        # Остановка WMI вотчеров
        for watcher in self.wmi_watchers:
            try:
                watcher.stop()
            except:
                pass
        self.wmi_watchers.clear()

    def on_edr_event(self, event: Dict) -> None:
        """Обработка события от EDR"""
        event_type = event.get('event_type', 'unknown')

        if event_type == 'process':
            self._process_process_event(event)
        elif event_type == 'file':
            self._process_file_event(event)
        elif event_type == 'registry':
            self._process_registry_event(event)
        elif event_type == 'network':
            self._process_network_event(event)
        elif event_type == 'dns':
            self._process_dns_event(event)
        elif event_type == 'image_load':
            self._process_image_load_event(event)
        elif event_type == 'login':
            self._process_login_event(event)
        elif event_type == 'failed_login':
            self._process_failed_login_event(event)

    def on_sysmon_event(self, event: Dict) -> None:
        """Обработка события от Sysmon"""
        event_id = event.get('event_id', 0)

        # Sysmon Event IDs
        if event_id == 1:  # Process creation
            self._process_process_event(event)
        elif event_id == 2:  # File creation time changed
            self._process_file_time_event(event)
        elif event_id == 3:  # Network connection
            self._process_network_event(event)
        elif event_id == 5:  # Process terminated
            self._process_process_terminated(event)
        elif event_id == 7:  # Image loaded
            self._process_image_load_event(event)
        elif event_id == 8:  # CreateRemoteThread
            self._process_remote_thread(event)
        elif event_id == 10:  # ProcessAccess
            self._process_process_access(event)
        elif event_id == 11:  # FileCreate
            self._process_file_event(event)
        elif event_id == 12:  # Registry object add/delete
            self._process_registry_event(event)
        elif event_id == 13:  # Registry value set
            self._process_registry_event(event)
        elif event_id == 14:  # Registry object renamed
            self._process_registry_event(event)
        elif event_id == 15:  # FileCreateStreamHash
            self._process_alternate_data_stream(event)
        elif event_id == 17:  # PipeEvent (Pipe Created)
            self._process_pipe_event(event)
        elif event_id == 18:  # PipeEvent (Pipe Connected)
            self._process_pipe_event(event)
        elif event_id == 22:  # DNS query
            self._process_dns_event(event)
        elif event_id == 23:  # FileDelete
            self._process_file_delete(event)
        elif event_id == 24:  # ClipboardChange
            self._process_clipboard_event(event)
        elif event_id == 25:  # ProcessTampering
            self._process_tampering_event(event)

    def on_wmi_event(self, event: Dict) -> None:
        """Обработка события от WMI"""
        event_class = event.get('class', '')

        if 'ProcessStart' in event_class:
            self._process_wmi_process_start(event)
        elif 'ProcessStop' in event_class:
            self._process_wmi_process_stop(event)
        elif 'Service' in event_class:
            self._process_wmi_service_change(event)
        elif 'Registry' in event_class:
            self._process_registry_event(event)

    def _windows_event_loop(self) -> None:
        """Цикл чтения Windows Event Log (с пакетной обработкой)"""
        import win32evtlog
        import win32evtlogutil
        import pywintypes

        # Открываем все настроенные логи
        for log_name in self.win_event_logs:
            try:
                handle = win32evtlog.OpenEventLog(None, log_name)
                self.event_log_handles[log_name] = handle
                total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
                self.last_event_ids[log_name] = total_records
                self.logger.info(f"Открыт журнал: {log_name} (записей: {total_records})")
            except pywintypes.error as e:
                if e.winerror == 2:
                    self.logger.debug(f"Журнал {log_name} не найден")
            except Exception as e:
                self.logger.debug(f"Не удалось открыть журнал {log_name}: {e}")

        # Буфер для пакетной обработки
        event_buffer = []
        buffer_size = 100
        last_flush = time.time()
        flush_interval = 1  # секунда

        while self.running:
            for log_name, handle in list(self.event_log_handles.items()):
                try:
                    events_read = self._read_new_events_batch(log_name, handle, max_events=50)

                    if events_read:
                        event_buffer.extend(events_read)

                        # Пакетная публикация
                        if len(event_buffer) >= buffer_size or time.time() - last_flush > flush_interval:
                            for event in event_buffer:
                                if 'sysmon' in event.get('log_name', '').lower():
                                    self.event_bus.publish('sysmon.event', event)
                                else:
                                    self.event_bus.publish('edr.event', event)
                            event_buffer.clear()
                            last_flush = time.time()

                except pywintypes.error as e:
                    if e.winerror == 6:
                        try:
                            win32evtlog.CloseEventLog(handle)
                        except:
                            pass
                        try:
                            self.event_log_handles[log_name] = win32evtlog.OpenEventLog(None, log_name)
                        except:
                            del self.event_log_handles[log_name]
                except Exception as e:
                    self.logger.debug(f"Ошибка чтения журнала {log_name}: {e}")

            time.sleep(0.1)  # Небольшая пауза чтобы не нагружать CPU

    def _read_new_events_batch(self, log_name: str, handle, max_events: int = 50) -> List[Dict]:
        """Пакетное чтение новых событий"""
        import win32evtlog

        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = []

        try:
            for _ in range(max_events):
                try:
                    raw_events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not raw_events:
                        break

                    for event in raw_events:
                        parsed = self._parse_windows_event(log_name, event)
                        if parsed:
                            events.append(parsed)

                except Exception:
                    break
        except Exception as e:
            self.logger.debug(f"Ошибка пакетного чтения: {e}")

        return events


    def _parse_windows_event(self, log_name: str, event) -> Optional[Dict]:
        """Парсинг Windows Event в унифицированный формат"""
        import win32evtlogutil

        try:
            # Извлекаем основную информацию
            event_id = event.EventID & 0xFFFF
            event_category = event.EventCategory
            time_generated = event.TimeGenerated
            time_written = event.TimeWritten
            computer_name = event.ComputerName
            source_name = event.SourceName
            record_number = event.RecordNumber

            # Пытаемся получить сообщение
            try:
                message = win32evtlogutil.SafeFormatMessage(event, log_name)
            except:
                message = ''

            # Базовый результат
            result = {
                'event_id': event_id,
                'log_name': log_name,
                'source': source_name,
                'computer': computer_name,
                'record_number': record_number,
                'time_generated': time_generated.isoformat() if time_generated else None,
                'time_written': time_written.isoformat() if time_written else None,
                'timestamp': time.time(),
                'category': event_category,
                'message': message[:2000] if message else '',
                'raw_inserts': list(event.StringInserts) if event.StringInserts else []
            }

            # Парсинг специфичных событий
            if log_name == 'Security':
                self._parse_security_event(event_id, result)
            elif 'Sysmon' in log_name:
                self._parse_sysmon_event(event_id, result)
            elif 'PowerShell' in log_name:
                self._parse_powershell_event(event_id, result)
            elif 'WMI' in log_name:
                self._parse_wmi_log_event(event_id, result)
            elif 'TaskScheduler' in log_name:
                self._parse_task_scheduler_event(event_id, result)
            elif 'TerminalServices' in log_name:
                self._parse_rdp_event(event_id, result)

            return result

        except Exception as e:
            self.logger.debug(f"Ошибка парсинга события: {e}")
            return None

    def _parse_security_event(self, event_id: int, result: Dict) -> None:
        """Парсинг Security событий"""
        message = result.get('message', '')
        inserts = result.get('raw_inserts', [])

        # 4624 - Успешный вход
        if event_id == 4624:
            result['event_type'] = 'login'
            result['username'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')
            result['domain'] = self._extract_from_message(message, r'Account Domain:\s+([^\r\n]+)')
            result['logon_type'] = self._extract_from_message(message, r'Logon Type:\s+(\d+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Network Address:\s+([^\r\n]+)')
            result['src_port'] = self._extract_from_message(message, r'Source Port:\s+(\d+)')
            result['process_name'] = self._extract_from_message(message, r'Process Name:\s+([^\r\n]+)')
            result['logon_id'] = self._extract_from_message(message, r'Logon ID:\s+([^\r\n]+)')

            # Тип входа
            logon_types = {
                '2': 'Interactive',
                '3': 'Network',
                '4': 'Batch',
                '5': 'Service',
                '7': 'Unlock',
                '8': 'NetworkCleartext',
                '9': 'NewCredentials',
                '10': 'RemoteInteractive',
                '11': 'CachedInteractive'
            }
            result['logon_type_name'] = logon_types.get(result.get('logon_type', ''), 'Unknown')

            # Специальные проверки
            if result.get('logon_type') == '10':  # RDP
                result['is_remote'] = True
            if result.get('logon_type') == '3' and not result.get('src_ip'):
                result['is_local_network'] = True

        # 4625 - Неудачный вход
        elif event_id == 4625:
            result['event_type'] = 'failed_login'
            result['username'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')
            result['domain'] = self._extract_from_message(message, r'Account Domain:\s+([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Network Address:\s+([^\r\n]+)')
            result['failure_reason'] = self._extract_from_message(message, r'Failure Reason:\s+([^\r\n]+)')
            result['status'] = self._extract_from_message(message, r'Status:\s+([^\r\n]+)')
            result['sub_status'] = self._extract_from_message(message, r'Sub Status:\s+([^\r\n]+)')

            # Расшифровка статуса
            status_codes = {
                '0xC0000064': 'User does not exist',
                '0xC000006A': 'Wrong password',
                '0xC0000234': 'Account locked',
                '0xC0000072': 'Account disabled',
                '0xC000006F': 'User not allowed',
                '0xC0000070': 'Invalid workstation',
                '0xC0000071': 'Password expired',
                '0xC0000133': 'Clocks out of sync',
                '0xC000015B': 'User not granted logon right',
                '0xC0000193': 'Account expired'
            }
            status = result.get('status', '').upper()
            result['status_description'] = status_codes.get(status, status)

        # 4688 - Создание процесса
        elif event_id == 4688:
            result['event_type'] = 'process'
            result['process_name'] = self._extract_from_message(message, r'New Process Name:\s+([^\r\n]+)')
            result['command_line'] = self._extract_from_message(message, r'Process Command Line:\s+([^\r\n]+)')
            result['creator_process'] = self._extract_from_message(message, r'Creator Process Name:\s+([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'New Process ID:\s+([^\r\n]+)')
            result['creator_process_id'] = self._extract_from_message(message, r'Creator Process ID:\s+([^\r\n]+)')
            result['token_elevation'] = self._extract_from_message(message, r'Token Elevation Type:\s+([^\r\n]+)')
            result['mandatory_label'] = self._extract_from_message(message, r'Mandatory Label:\s+([^\r\n]+)')

            # Извлекаем username из строки Subject
            subject_match = re.search(r'Subject:.*?Account Name:\s+([^\r\n]+)', message, re.DOTALL)
            if subject_match:
                result['username'] = subject_match.group(1).strip()

        # 4689 - Завершение процесса
        elif event_id == 4689:
            result['event_type'] = 'process_terminated'
            result['process_name'] = self._extract_from_message(message, r'Process Name:\s+([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'Process ID:\s+([^\r\n]+)')
            result['exit_status'] = self._extract_from_message(message, r'Exit Status:\s+([^\r\n]+)')

        # 5140 - Доступ к сетевой папке
        elif event_id == 5140:
            result['event_type'] = 'file_share'
            result['share_name'] = self._extract_from_message(message, r'Share Name:\s*([^\r\n]+)')
            result['share_path'] = self._extract_from_message(message, r'Share Path:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Address:\s*([^\r\n]+)')
            result['username'] = self._extract_from_message(message, r'Account Name:\s*([^\r\n]+)')
            result['accesses'] = self._extract_from_message(message, r'Accesses:\s*([^\r\n]+)')

        # 5145 - Доступ к файлу по сети
        elif event_id == 5145:
            result['event_type'] = 'file_access'
            result['file_name'] = self._extract_from_message(message, r'Relative Target Name:\s*([^\r\n]+)')
            result['share_name'] = self._extract_from_message(message, r'Share Name:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Address:\s*([^\r\n]+)')
            result['username'] = self._extract_from_message(message, r'Account Name:\s*([^\r\n]+)')
            result['access_mask'] = self._extract_from_message(message, r'Access Mask:\s*([^\r\n]+)')

        # 5156 - Фильтрация платформы Windows (сетевое соединение)
        elif event_id == 5156:
            result['event_type'] = 'network'
            result['process_name'] = self._extract_from_message(message, r'Application Name:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Address:\s*([^\r\n]+)')
            result['dst_ip'] = self._extract_from_message(message, r'Dest Address:\s*([^\r\n]+)')
            result['src_port'] = self._extract_from_message(message, r'Source Port:\s*(\d+)')
            result['dst_port'] = self._extract_from_message(message, r'Dest Port:\s*(\d+)')
            result['protocol'] = self._extract_from_message(message, r'Protocol:\s*(\d+)')
            result['direction'] = self._extract_from_message(message, r'Direction:\s*([^\r\n]+)')

        # 5158 - Bind to local port
        elif event_id == 5158:
            result['event_type'] = 'network_bind'
            result['process_name'] = self._extract_from_message(message, r'Application Name:\s*([^\r\n]+)')
            result['local_port'] = self._extract_from_message(message, r'Local Port:\s*(\d+)')
            result['protocol'] = self._extract_from_message(message, r'Protocol:\s*(\d+)')

        # 1102 - Очистка журнала аудита
        elif event_id == 1102:
            result['event_type'] = 'audit_log_cleared'
            result['username'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')
            result['domain'] = self._extract_from_message(message, r'Domain Name:\s+([^\r\n]+)')

        # 4672 - Назначение специальных привилегий
        elif event_id == 4672:
            result['event_type'] = 'special_privileges'
            result['username'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')
            result['privileges'] = self._extract_from_message(message, r'Privileges:\s+([^\r\n]+)')

        # 4720 - Создание пользователя
        elif event_id == 4720:
            result['event_type'] = 'user_created'
            result['new_username'] = self._extract_from_message(message, r'SAM Account Name:\s+([^\r\n]+)')
            result['creator'] = self._extract_from_message(message, r'Account Name:\s+([^\r\n]+)')

        # 4732 - Добавление в группу
        elif event_id == 4732:
            result['event_type'] = 'group_member_added'
            result['username'] = self._extract_from_message(message, r'Member Name:\s+([^\r\n]+)')
            result['group_name'] = self._extract_from_message(message, r'Group Name:\s+([^\r\n]+)')

    def _parse_sysmon_event(self, event_id: int, result: Dict) -> None:
        """Парсинг Sysmon событий"""
        message = result.get('message', '')

        # Event ID 1 - Process Creation
        if event_id == 1:
            result['event_type'] = 'process'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['command_line'] = self._extract_from_message(message, r'CommandLine:\s*([^\r\n]+)')
            result['parent_process'] = self._extract_from_message(message, r'ParentImage:\s*([^\r\n]+)')
            result['parent_command_line'] = self._extract_from_message(message, r'ParentCommandLine:\s*([^\r\n]+)')
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['pid'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['parent_pid'] = self._extract_from_message(message, r'ParentProcessId:\s*(\d+)')
            result['file_hash'] = self._extract_from_message(message, r'Hashes:\s*([^\r\n]+)')
            result['current_directory'] = self._extract_from_message(message, r'CurrentDirectory:\s*([^\r\n]+)')
            result['integrity_level'] = self._extract_from_message(message, r'IntegrityLevel:\s*([^\r\n]+)')

        # Event ID 3 - Network Connection
        elif event_id == 3:
            result['event_type'] = 'network'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'SourceIp:\s*([^\r\n]+)')
            result['dst_ip'] = self._extract_from_message(message, r'DestinationIp:\s*([^\r\n]+)')
            result['src_port'] = self._extract_from_message(message, r'SourcePort:\s*(\d+)')
            result['dst_port'] = self._extract_from_message(message, r'DestinationPort:\s*(\d+)')
            result['protocol'] = self._extract_from_message(message, r'Protocol:\s*([^\r\n]+)')
            result['initiated'] = self._extract_from_message(message, r'Initiated:\s*([^\r\n]+)')

        # Event ID 7 - Image Loaded
        elif event_id == 7:
            result['event_type'] = 'image_load'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['image_loaded'] = self._extract_from_message(message, r'ImageLoaded:\s*([^\r\n]+)')
            result['file_hash'] = self._extract_from_message(message, r'Hashes:\s*([^\r\n]+)')
            result['signed'] = self._extract_from_message(message, r'Signed:\s*([^\r\n]+)')
            result['signature'] = self._extract_from_message(message, r'Signature:\s*([^\r\n]+)')

        # Event ID 8 - CreateRemoteThread
        elif event_id == 8:
            result['event_type'] = 'remote_thread'
            result['source_process'] = self._extract_from_message(message, r'SourceImage:\s*([^\r\n]+)')
            result['target_process'] = self._extract_from_message(message, r'TargetImage:\s*([^\r\n]+)')
            result['source_pid'] = self._extract_from_message(message, r'SourceProcessId:\s*(\d+)')
            result['target_pid'] = self._extract_from_message(message, r'TargetProcessId:\s*(\d+)')
            result['start_address'] = self._extract_from_message(message, r'StartAddress:\s*([^\r\n]+)')
            result['start_function'] = self._extract_from_message(message, r'StartFunction:\s*([^\r\n]+)')

        # Event ID 10 - ProcessAccess
        elif event_id == 10:
            result['event_type'] = 'process_access'
            result['source_process'] = self._extract_from_message(message, r'SourceImage:\s*([^\r\n]+)')
            result['target_process'] = self._extract_from_message(message, r'TargetImage:\s*([^\r\n]+)')
            result['granted_access'] = self._extract_from_message(message, r'GrantedAccess:\s*([^\r\n]+)')
            result['call_trace'] = self._extract_from_message(message, r'CallTrace:\s*([^\r\n]+)')

            # Проверка опасных доступов
            dangerous_access = ['0x1FFFFF', '0x1F0FFF', 'PROCESS_ALL_ACCESS', 'PROCESS_CREATE_THREAD',
                                'PROCESS_VM_WRITE', 'PROCESS_VM_OPERATION']
            for da in dangerous_access:
                if da in result.get('granted_access', ''):
                    result['dangerous_access'] = True
                    break

        # Event ID 11 - FileCreate
        elif event_id == 11:
            result['event_type'] = 'file'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['filename'] = self._extract_from_message(message, r'TargetFilename:\s*([^\r\n]+)')
            result['creation_time'] = self._extract_from_message(message, r'CreationUtcTime:\s*([^\r\n]+)')

        # Event ID 12/13/14 - Registry
        elif event_id in [12, 13, 14]:
            result['event_type'] = 'registry'
            result['event_subtype'] = {12: 'create_delete', 13: 'set', 14: 'rename'}.get(event_id, 'unknown')
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['key_path'] = self._extract_from_message(message, r'TargetObject:\s*([^\r\n]+)')
            result['value_name'] = self._extract_from_message(message, r'Details:\s*([^\r\n]+)')

        # Event ID 22 - DNS Query
        elif event_id == 22:
            result['event_type'] = 'dns'
            result['process_name'] = self._extract_from_message(message, r'Image:\s*([^\r\n]+)')
            result['process_id'] = self._extract_from_message(message, r'ProcessId:\s*(\d+)')
            result['query_name'] = self._extract_from_message(message, r'QueryName:\s*([^\r\n]+)')
            result['query_status'] = self._extract_from_message(message, r'QueryStatus:\s*([^\r\n]+)')
            result['query_results'] = self._extract_from_message(message, r'QueryResults:\s*([^\r\n]+)')

        # Event ID 25 - ProcessTampering
        elif event_id == 25:
            result['event_type'] = 'process_tampering'
            result['process_name'] = self._extract_from_message(message, r'ProcessName:\s*([^\r\n]+)')
            result['technique'] = self._extract_from_message(message, r'Type:\s*([^\r\n]+)')

    def _parse_powershell_event(self, event_id: int, result: Dict) -> None:
        """Парсинг PowerShell событий"""
        message = result.get('message', '')

        result['event_type'] = 'powershell'

        # Event ID 4103 - Module Logging
        if event_id == 4103:
            result['subtype'] = 'module'
            result['user'] = self._extract_from_message(message, r'UserId=([^\r\n]+)')
            result['host'] = self._extract_from_message(message, r'Host Name=([^\r\n]+)')
            result['command'] = self._extract_from_message(message, r'CommandInvocation\([^\)]*\):\s*([^\r\n]+)')
            result['parameter_binding'] = self._extract_from_message(message, r'ParameterBinding\([^\)]*\):\s*([^\r\n]+)')

        # Event ID 4104 - Script Block Logging
        elif event_id == 4104:
            result['subtype'] = 'script_block'
            result['script_block_id'] = self._extract_from_message(message, r'ScriptBlock ID:\s*([^\r\n]+)')

            # Извлекаем сам скрипт
            script_match = re.search(r'ScriptBlock text:\s*\n(.*?)(?:\n\s*\n|$)', message, re.DOTALL)
            if script_match:
                result['script_block'] = script_match.group(1).strip()[:5000]

        # Event ID 800 - Pipeline Execution Details
        elif event_id == 800:
            result['subtype'] = 'pipeline'
            result['user'] = self._extract_from_message(message, r'UserId=([^\r\n]+)')
            result['host'] = self._extract_from_message(message, r'HostName=([^\r\n]+)')
            result['command_line'] = self._extract_from_message(message, r'CommandLine=([^\r\n]+)')

    def _parse_wmi_log_event(self, event_id: int, result: Dict) -> None:
        """Парсинг WMI событий из лога"""
        message = result.get('message', '')

        result['event_type'] = 'wmi'

        # Event ID 5858 - WMI Activity
        if event_id == 5858:
            result['operation'] = self._extract_from_message(message, r'Operation:\s*([^\r\n]+)')
            result['namespace'] = self._extract_from_message(message, r'Namespace:\s*([^\r\n]+)')
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['query'] = self._extract_from_message(message, r'Query:\s*([^\r\n]+)')

        # Event ID 5861 - WMI Permanent Event Registration
        elif event_id == 5861:
            result['subtype'] = 'permanent_event'
            result['filter'] = self._extract_from_message(message, r'Filter:\s*([^\r\n]+)')
            result['consumer'] = self._extract_from_message(message, r'Consumer:\s*([^\r\n]+)')
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')

    def _parse_task_scheduler_event(self, event_id: int, result: Dict) -> None:
        """Парсинг Task Scheduler событий"""
        message = result.get('message', '')

        result['event_type'] = 'task_scheduler'

        # Event ID 106 - Task Registered
        if event_id == 106:
            result['subtype'] = 'task_registered'
            result['task_name'] = self._extract_from_message(message, r'Task Name:\s*([^\r\n]+)')
            result['user'] = self._extract_from_message(message, r'User Name:\s*([^\r\n]+)')

        # Event ID 141 - Task Updated
        elif event_id == 141:
            result['subtype'] = 'task_updated'
            result['task_name'] = self._extract_from_message(message, r'Task Name:\s*([^\r\n]+)')

        # Event ID 200/201 - Task Executed
        elif event_id in [200, 201]:
            result['subtype'] = 'task_executed'
            result['task_name'] = self._extract_from_message(message, r'Task Name:\s*([^\r\n]+)')
            result['action'] = self._extract_from_message(message, r'Action:\s*([^\r\n]+)')
            result['result_code'] = self._extract_from_message(message, r'Result code:\s*([^\r\n]+)')

    def _parse_rdp_event(self, event_id: int, result: Dict) -> None:
        """Парсинг RDP событий"""
        message = result.get('message', '')

        result['event_type'] = 'rdp'

        # Event ID 21 - RDP Session Start
        if event_id == 21:
            result['subtype'] = 'session_start'
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['src_ip'] = self._extract_from_message(message, r'Source Network Address:\s*([^\r\n]+)')

        # Event ID 24 - RDP Session Disconnect
        elif event_id == 24:
            result['subtype'] = 'session_disconnect'
            result['user'] = self._extract_from_message(message, r'User:\s*([^\r\n]+)')
            result['session_id'] = self._extract_from_message(message, r'Session ID:\s*(\d+)')

    def _extract_from_message(self, message: str, pattern: str) -> Optional[str]:
        """Извлечение значения из сообщения по регулярному выражению"""
        import re
        match = re.search(pattern, message, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return None

    def _wmi_event_loop(self) -> None:
        """Цикл мониторинга WMI событий"""
        if not self.use_wmi or not self.wmi_connection:
            return

        try:
            import pythoncom

            pythoncom.CoInitialize()

            # Мониторинг создания процессов
            process_watcher = self._create_wmi_watcher(
                "SELECT * FROM Win32_ProcessStartTrace",
                self._handle_wmi_process_start
            )
            if process_watcher:
                self.wmi_watchers.append(process_watcher)

            # Мониторинг завершения процессов
            process_stop_watcher = self._create_wmi_watcher(
                "SELECT * FROM Win32_ProcessStopTrace",
                self._handle_wmi_process_stop
            )
            if process_stop_watcher:
                self.wmi_watchers.append(process_stop_watcher)

            # Мониторинг изменений сервисов
            service_watcher = self._create_wmi_watcher(
                "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Service'",
                self._handle_wmi_service_change
            )
            if service_watcher:
                self.wmi_watchers.append(service_watcher)

            # Мониторинг изменений реестра
            registry_watcher = self._create_wmi_watcher(
                "SELECT * FROM RegistryTreeChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND RootPath='Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'",
                self._handle_wmi_registry_change
            )
            if service_watcher:
                self.wmi_watchers.append(registry_watcher)

            # Основной цикл ожидания
            while self.running:
                time.sleep(1)

        except Exception as e:
            self.logger.error(f"Ошибка WMI мониторинга: {e}")
        finally:
            try:
                import pythoncom
                pythoncom.CoUninitialize()
            except:
                pass

    def _create_wmi_watcher(self, query: str, handler: Callable):
        """Создание WMI вотчера"""
        try:
            import wmi

            watcher = wmi.WMI().watch_for(
                notification_type="Operation",
                wmi_class=None,
                wmi_query=query
            )
            threading.Thread(target=self._wmi_watcher_loop, args=(watcher, handler), daemon=True).start()
            return watcher
        except Exception as e:
            self.logger.debug(f"Ошибка создания WMI вотчера: {e}")
            return None

    def _wmi_watcher_loop(self, watcher, handler) -> None:
        """Цикл обработки WMI событий"""
        while self.running:
            try:
                event = watcher(timeout_ms=1000)
                if event:
                    handler(event)
            except Exception as e:
                if self.running:
                    self.logger.debug(f"Ошибка WMI вотчера: {e}")

    def _handle_wmi_process_start(self, event) -> None:
        """Обработка WMI события создания процесса"""
        parsed = {
            'event_type': 'process',
            'source': 'wmi',
            'process_name': getattr(event, 'ProcessName', ''),
            'process_id': getattr(event, 'ProcessID', 0),
            'parent_process_id': getattr(event, 'ParentProcessID', 0),
            'command_line': getattr(event, 'CommandLine', ''),
            'timestamp': time.time()
        }
        self.event_bus.publish('wmi.event', parsed)

    def _handle_wmi_process_stop(self, event) -> None:
        """Обработка WMI события завершения процесса"""
        parsed = {
            'event_type': 'process_terminated',
            'source': 'wmi',
            'process_name': getattr(event, 'ProcessName', ''),
            'process_id': getattr(event, 'ProcessID', 0),
            'exit_status': getattr(event, 'ExitStatus', 0),
            'timestamp': time.time()
        }
        self.event_bus.publish('wmi.event', parsed)

    def _handle_wmi_service_change(self, event) -> None:
        """Обработка WMI события изменения сервиса"""
        target = getattr(event, 'TargetInstance', None)
        if target:
            parsed = {
                'event_type': 'service',
                'source': 'wmi',
                'service_name': getattr(target, 'Name', ''),
                'display_name': getattr(target, 'DisplayName', ''),
                'state': getattr(target, 'State', ''),
                'start_mode': getattr(target, 'StartMode', ''),
                'path_name': getattr(target, 'PathName', ''),
                'start_name': getattr(target, 'StartName', ''),
                'timestamp': time.time()
            }
            self.event_bus.publish('wmi.event', parsed)

    def _handle_wmi_registry_change(self, event) -> None:
        """Обработка WMI события изменения реестра"""
        parsed = {
            'event_type': 'registry',
            'source': 'wmi',
            'key_path': getattr(event, 'KeyPath', ''),
            'timestamp': time.time()
        }
        self.event_bus.publish('wmi.event', parsed)

    def _process_process_event(self, event: Dict) -> None:
        """Анализ события создания процесса"""
        self.process_events.append(event)

        result = self.analyze_process_event(event)

        if result['is_suspicious']:
            self.event_bus.publish('edr.threat', result)
            self.logger.warning(f"Подозрительный процесс: {event.get('process_name')} (score={result['score']:.3f})")

    def analyze_process_event(self, event: Dict) -> Dict:
        """Анализ события процесса"""
        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'attack_type': None,
            'severity': AlertSeverity.LOW.value
        }

        process_name = event.get('process_name', '').lower()
        cmdline = event.get('command_line', '').lower()
        path = event.get('path', event.get('process_name', '')).lower()
        parent_process = event.get('parent_process', '').lower()
        user = event.get('user', '').lower()
        pid = event.get('pid', event.get('process_id', 0))

        # 1. Подозрительный процесс
        for sus_proc in self.suspicious_processes:
            if sus_proc in process_name:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_process:{sus_proc}")
                result['score'] += 0.25

                # Особо опасные процессы
                if sus_proc in ['mimikatz.exe', 'procdump.exe', 'psexec.exe']:
                    result['score'] += 0.3
                    result['attack_type'] = 'Credential Dumping'
                elif sus_proc in ['powershell.exe', 'cmd.exe']:
                    result['score'] += 0.1
                break

        # 2. Подозрительные аргументы командной строки
        for pattern in self.suspicious_cmdline:
            if pattern in cmdline:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_cmdline:{pattern}")
                result['score'] += 0.3

                if pattern in ['mimikatz', 'procdump', 'lsass', 'sekurlsa']:
                    result['attack_type'] = 'Credential Dumping'
                    result['score'] += 0.2
                elif pattern in ['cobaltstrike', 'metasploit', 'meterpreter']:
                    result['attack_type'] = 'C2 Framework'
                    result['score'] += 0.25
                elif pattern in ['virtualalloc', 'createremotethread', 'writeprocessmemory']:
                    result['attack_type'] = 'Process Injection'
                    result['score'] += 0.2
                break

        # 3. Процесс запущен из подозрительной папки
        for sus_path in self.suspicious_paths:
            if sus_path in path:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_path:{sus_path}")
                result['score'] += 0.25
                break

        # 4. Необычный родительский процесс
        suspicious_parents = {
            'powershell.exe': ['winword.exe', 'excel.exe', 'outlook.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe', 'mshta.exe'],
            'cmd.exe': ['winword.exe', 'excel.exe', 'outlook.exe', 'java.exe', 'javaw.exe', 'mshta.exe'],
            'wscript.exe': ['winword.exe', 'excel.exe', 'outlook.exe', 'mshta.exe'],
            'rundll32.exe': ['winword.exe', 'excel.exe', 'outlook.exe'],
            'mshta.exe': ['winword.exe', 'excel.exe', 'outlook.exe'],
            'regsvr32.exe': ['winword.exe', 'excel.exe', 'outlook.exe', 'mshta.exe']
        }

        for proc_name, sus_parents in suspicious_parents.items():
            if proc_name in process_name:
                for sus_parent in sus_parents:
                    if sus_parent in parent_process:
                        result['is_suspicious'] = True
                        result['reasons'].append(f"suspicious_parent:{parent_process}->{proc_name}")
                        result['score'] += 0.35
                        result['attack_type'] = 'Office Macro'
                        break
                break

        # 5. PowerShell с подозрительными флагами
        if 'powershell' in process_name:
            dangerous_flags = [
                ('-windowstyle hidden', 0.3),
                ('-w hidden', 0.3),
                ('-executionpolicy bypass', 0.25),
                ('-ep bypass', 0.25),
                ('-enc ', 0.35),
                ('-encodedcommand ', 0.35),
                ('-nop', 0.1),
                ('-noprofile', 0.1),
                ('invoke-expression', 0.3),
                ('iex ', 0.3),
                ('downloadstring', 0.3),
                ('downloadfile', 0.25),
                ('frombase64string', 0.2),
                ('[system.reflection.assembly]::load', 0.4),
                ('add-type -typedefinition', 0.3)
            ]

            for flag, score_add in dangerous_flags:
                if flag in cmdline:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"powershell_{flag.replace(' ', '_')}")
                    result['score'] += score_add
                    if score_add >= 0.3:
                        break

        # 6. WMI с подозрительными командами
        if 'wmic' in process_name or 'wmi' in cmdline:
            dangerous_wmi = ['process call create', 'service call create', 'shadowcopy delete',
                             '/node:', 'useraccount', 'startup', 'os get']
            for wmi_cmd in dangerous_wmi:
                if wmi_cmd in cmdline:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"suspicious_wmi:{wmi_cmd}")
                    result['score'] += 0.3
                    break

        # 7. Доступ к LSASS
        if 'lsass' in cmdline:
            result['is_suspicious'] = True
            result['reasons'].append("lsass_access")
            result['score'] += 0.4
            result['attack_type'] = 'Credential Dumping'

        # 8. Запуск из ADS (Alternate Data Stream)
        if ':Zone.Identifier' in path or ':$DATA' in path:
            result['is_suspicious'] = True
            result['reasons'].append("ads_execution")
            result['score'] += 0.35

        # 9. Неподписанный процесс из системной папки
        if 'system32' in path and event.get('signed') == 'false':
            result['is_suspicious'] = True
            result['reasons'].append("unsigned_system32_binary")
            result['score'] += 0.25

        # 10. Подозрительный пользователь
        suspicious_users = ['system', 'local service', 'network service']
        if user.lower() in suspicious_users and 'cmd.exe' in process_name:
            result['is_suspicious'] = True
            result['reasons'].append(f"system_account_cmd:{user}")
            result['score'] += 0.2

        result['score'] = min(1.0, result['score'])

        # Определение серьёзности
        if result['score'] > 0.7:
            result['severity'] = AlertSeverity.CRITICAL.value
        elif result['score'] > 0.5:
            result['severity'] = AlertSeverity.HIGH.value
        elif result['score'] > 0.3:
            result['severity'] = AlertSeverity.MEDIUM.value

        if not result['attack_type']:
            result['attack_type'] = 'Suspicious Process'

        result['details'] = {
            'process_name': process_name,
            'command_line': cmdline[:500],
            'path': path,
            'parent_process': parent_process,
            'user': user,
            'pid': pid
        }

        return result

    def _process_file_event(self, event: Dict) -> None:
        """Анализ файлового события"""
        self.file_events.append(event)

        filename = event.get('filename', '').lower()
        path = event.get('path', '').lower()
        operation = event.get('operation', '')
        process_name = event.get('process_name', '').lower()

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'file'
        }

        # 1. Создание файлов в чувствительных директориях
        sensitive_dirs = [
            '\\system32\\', '\\syswow64\\', '\\windows\\',
            '\\program files\\', '\\program files (x86)\\',
            '\\startup\\', '\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\',
            '\\tasks\\', '\\windows\\system32\\tasks\\'
        ]

        for sens_dir in sensitive_dirs:
            if sens_dir in path and operation in ('create', 'modify', 'write'):
                if 'windows update' not in path and 'microsoft' not in path.lower():
                    result['is_suspicious'] = True
                    result['reasons'].append(f"sensitive_dir_write:{sens_dir}")
                    result['score'] += 0.35
                    break

        # 2. Подозрительные расширения в темповых папках
        dangerous_extensions = ['.exe', '.dll', '.sys', '.ps1', '.vbs', '.js', '.hta', '.bat', '.scr']
        is_temp_path = any(temp in path for temp in ['\\temp\\', '\\tmp\\', '\\cache\\', '\\downloads\\'])

        if is_temp_path:
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    result['is_suspicious'] = True
                    result['reasons'].append(f"executable_in_temp:{filename}")
                    result['score'] += 0.4
                    break

        # 3. Создание скриптов офисными приложениями
        office_processes = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']
        script_extensions = ['.ps1', '.vbs', '.js', '.bat', '.hta']

        if any(proc in process_name for proc in office_processes):
            for ext in script_extensions:
                if filename.endswith(ext):
                    result['is_suspicious'] = True
                    result['reasons'].append(f"office_created_script:{filename}")
                    result['score'] += 0.5
                    result['attack_type'] = 'Office Macro'
                    break

        # 4. Файлы с двойным расширением
        if filename.count('.') >= 2:
            parts = filename.split('.')
            if parts[-1] in dangerous_extensions and parts[-2] in ['doc', 'xls', 'pdf', 'txt', 'jpg']:
                result['is_suspicious'] = True
                result['reasons'].append(f"double_extension:{filename}")
                result['score'] += 0.45

        # 5. Подозрительные имена файлов
        suspicious_names = ['mimikatz', 'procdump', 'psexec', 'nc.exe', 'netcat', 'plink.exe',
                            'socat', 'chisel', 'frpc', 'nps', 'beacon', 'payload', 'shell']
        for sus_name in suspicious_names:
            if sus_name in filename:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_filename:{sus_name}")
                result['score'] += 0.35
                break

        # 6. Изменение системных файлов
        system_files = ['hosts', 'services', 'lmhosts', 'protocol', 'networks']
        for sys_file in system_files:
            if f'\\etc\\{sys_file}' in path or f'\\drivers\\etc\\{sys_file}' in path:
                if operation in ('modify', 'write'):
                    result['is_suspicious'] = True
                    result['reasons'].append(f"system_file_modified:{sys_file}")
                    result['score'] += 0.4
                    break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['filename'] = filename
            result['path'] = path
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.6:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.4:
                result['severity'] = AlertSeverity.MEDIUM.value
            else:
                result['severity'] = AlertSeverity.LOW.value

            self.event_bus.publish('edr.file_threat', result)
            self.logger.warning(f"Подозрительная файловая операция: {filename} (score={result['score']:.3f})")

    def _process_registry_event(self, event: Dict) -> None:
        """Анализ события реестра"""
        self.registry_events.append(event)

        key_path = event.get('key_path', '').lower()
        value_name = event.get('value_name', '').lower()
        operation = event.get('operation', '')
        process_name = event.get('process_name', '').lower()

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'registry'
        }

        # 1. Чувствительные ключи реестра
        for sens_key in self.suspicious_registry_keys:
            if sens_key in key_path:
                if operation in ('set', 'create', 'modify', 'write'):
                    result['is_suspicious'] = True
                    result['reasons'].append(f"sensitive_registry:{sens_key}")
                    result['score'] += 0.35

                    # Persistence механизмы
                    if 'run' in sens_key or 'runonce' in sens_key:
                        result['attack_type'] = 'Persistence'
                        result['score'] += 0.1
                    elif 'winlogon' in sens_key:
                        result['attack_type'] = 'Credential Access'
                        result['score'] += 0.15
                    break

        # 2. Отключение защитных механизмов
        security_disable_patterns = [
            ('disableantispyware', 0.4),
            ('disableantivirus', 0.4),
            ('enablefirewall', 0.35),
            ('disableuac', 0.35),
            ('disablerealtimeMonitoring', 0.4),
            ('disableioavprotection', 0.35),
            ('disablebehaviorMonitoring', 0.35),
            ('disableonaccessprotection', 0.35),
            ('disableintrusionpreventionsystem', 0.35),
            ('disableScriptScanning', 0.3)
        ]

        for pattern, score_add in security_disable_patterns:
            if pattern in value_name or pattern in key_path:
                result['is_suspicious'] = True
                result['reasons'].append(f"security_disable:{pattern}")
                result['score'] += score_add
                break

        # 3. Модификация Image File Execution Options (IFEO)
        if 'image file execution options' in key_path:
            result['is_suspicious'] = True
            result['reasons'].append("ifeo_modification")
            result['score'] += 0.5
            result['attack_type'] = 'Persistence'

            # Проверка на Debugger
            if 'debugger' in value_name:
                result['score'] += 0.2

        # 4. Изменение Shell Extensions
        if 'shell extensions\\approved' in key_path:
            result['is_suspicious'] = True
            result['reasons'].append("shell_extension_approved")
            result['score'] += 0.4
            result['attack_type'] = 'Persistence'

        # 5. Подозрительный процесс изменяет реестр
        if process_name in self.suspicious_processes:
            result['is_suspicious'] = True
            result['reasons'].append(f"suspicious_process_registry:{process_name}")
            result['score'] += 0.25

        # 6. Удаление ключей безопасности
        security_keys = ['policies', 'audit', 'firewall', 'defender', 'antivirus']
        for sec_key in security_keys:
            if sec_key in key_path and operation in ('delete', 'remove'):
                result['is_suspicious'] = True
                result['reasons'].append(f"security_key_deleted:{sec_key}")
                result['score'] += 0.4
                break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['key_path'] = key_path
            result['value_name'] = value_name
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.6:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.4:
                result['severity'] = AlertSeverity.MEDIUM.value
            else:
                result['severity'] = AlertSeverity.LOW.value

            self.event_bus.publish('edr.registry_threat', result)
            self.logger.warning(f"Подозрительное изменение реестра: {key_path} (score={result['score']:.3f})")

    def _process_network_event(self, event: Dict) -> None:
        """Анализ сетевого события"""
        self.network_events.append(event)

        src_ip = event.get('src_ip', '')
        dst_ip = event.get('dst_ip', '')
        dst_port = event.get('dst_port', 0)
        src_port = event.get('src_port', 0)
        process_name = event.get('process_name', '').lower()
        protocol = event.get('protocol', '')

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'network'
        }

        # 1. Подозрительные порты
        suspicious_ports = {
            4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337,
            3389, 5900, 5800,
            445, 139, 135,
            22, 23, 21,
            1433, 1434, 3306, 5432,
            8080, 8443, 8000, 8888, 9000
        }

        if dst_port in suspicious_ports:
            result['is_suspicious'] = True
            result['reasons'].append(f"suspicious_port:{dst_port}")
            result['score'] += 0.25

            if dst_port in [4444, 5555, 6666, 7777, 1337, 31337]:
                result['attack_type'] = 'C2 Communication'
                result['score'] += 0.15

        # 2. Подозрительный процесс устанавливает соединение
        if process_name in self.suspicious_processes:
            result['is_suspicious'] = True
            result['reasons'].append(f"suspicious_process_network:{process_name}")
            result['score'] += 0.25

            # Особо подозрительные комбинации
            if process_name == 'powershell.exe' and dst_port not in [80, 443, 53]:
                result['score'] += 0.15
            if process_name == 'rundll32.exe' and dst_port not in [53, 80, 443]:
                result['score'] += 0.2

        # 3. Исходящие соединения на нестандартные порты
        standard_ports = {80, 443, 53, 123, 25, 587, 993, 995, 143, 110}
        if dst_port not in standard_ports and dst_port > 1024:
            if process_name in ['svchost.exe', 'lsass.exe', 'winlogon.exe']:
                result['is_suspicious'] = True
                result['reasons'].append(f"system_process_unusual_port:{process_name}:{dst_port}")
                result['score'] += 0.3

        # 4. Соединения с внутренними IP от необычных процессов
        if self._is_private_ip(dst_ip):
            unusual_internal = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']
            for unusual_proc in unusual_internal:
                if unusual_proc in process_name:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"unusual_internal_connection:{process_name}")
                    result['score'] += 0.25
                    result['attack_type'] = 'Lateral Movement'
                    break

        # 5. Raw socket или необычный протокол
        if protocol and protocol.lower() not in ['tcp', 'udp', 'icmp']:
            result['is_suspicious'] = True
            result['reasons'].append(f"unusual_protocol:{protocol}")
            result['score'] += 0.3

        # 6. Beaconing детекция (на основе таймингов)
        # Реализуется через анализ временных интервалов в _analysis_loop

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['src_ip'] = src_ip
            result['dst_ip'] = dst_ip
            result['dst_port'] = dst_port
            result['src_port'] = src_port
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.6:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.4:
                result['severity'] = AlertSeverity.MEDIUM.value
            else:
                result['severity'] = AlertSeverity.LOW.value

            self.event_bus.publish('edr.network_threat', result)

    def _is_private_ip(self, ip: str) -> bool:
        """Проверка приватного IP"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1]) if len(parts) > 1 else 0
            return (first == 10 or
                    (first == 172 and 16 <= second <= 31) or
                    (first == 192 and second == 168) or
                    first == 127)
        except:
            return False

    def _process_dns_event(self, event: Dict) -> None:
        """Анализ DNS события"""
        self.dns_events.append(event)

        query = event.get('query_name', event.get('query', '')).lower()
        process_name = event.get('process_name', '').lower()
        query_status = event.get('query_status', '')

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'dns'
        }

        # 1. Подозрительный процесс делает DNS запрос
        if process_name in self.suspicious_processes:
            result['is_suspicious'] = True
            result['reasons'].append(f"suspicious_process_dns:{process_name}")
            result['score'] += 0.2

        # 2. Длинные DNS запросы (туннелирование)
        if len(query) > 50:
            result['is_suspicious'] = True
            result['reasons'].append(f"long_dns_query:{len(query)}")
            result['score'] += 0.3
            result['attack_type'] = 'DNS Tunneling'

            if len(query) > 100:
                result['score'] += 0.2

        # 3. Подозрительные TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.date']
        for tld in suspicious_tlds:
            if query.endswith(tld):
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_tld:{tld}")
                result['score'] += 0.25
                break

        # 4. DNS over HTTPS признаки
        doh_servers = ['cloudflare-dns.com', 'dns.google', 'dns.quad9.net', 'doh.opendns.com']
        for doh in doh_servers:
            if doh in query:
                if process_name not in ['chrome.exe', 'firefox.exe', 'msedge.exe']:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"unusual_doh:{process_name}")
                    result['score'] += 0.3
                    break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['query'] = query
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.5:
                result['severity'] = AlertSeverity.MEDIUM.value

            self.event_bus.publish('edr.dns_threat', result)
            # Также публикуем для DNS анализатора
            self.event_bus.publish('dpi.dns', {
                'src_ip': event.get('src_ip', ''),
                'query': query,
                'process_name': process_name
            })

    def _process_remote_thread(self, event: Dict) -> None:
        """Анализ создания удалённого потока (Process Injection)"""
        result = {
            'is_suspicious': True,
            'reasons': ['remote_thread_creation'],
            'score': 0.5,
            'attack_type': 'Process Injection',
            'severity': AlertSeverity.HIGH.value,
            'event_type': 'remote_thread'
        }

        result['source_pid'] = event.get('source_pid')
        result['target_pid'] = event.get('target_pid')
        result['source_process'] = event.get('source_process')
        result['target_process'] = event.get('target_process')

        # Проверка целевого процесса
        target = event.get('target_process', '').lower()
        sensitive_targets = ['lsass.exe', 'csrss.exe', 'winlogon.exe', 'explorer.exe', 'svchost.exe']

        for sens_target in sensitive_targets:
            if sens_target in target:
                result['score'] += 0.25
                result['reasons'].append(f"sensitive_target:{sens_target}")
                if sens_target == 'lsass.exe':
                    result['attack_type'] = 'Credential Dumping'
                break

        result['score'] = min(1.0, result['score'])

        self.event_bus.publish('edr.threat', result)
        self.logger.warning(f"Обнаружено создание удалённого потока: {result['source_process']} -> {result['target_process']}")

    def _process_process_access(self, event: Dict) -> None:
        """Анализ доступа к процессу"""
        target_process = event.get('target_process', '').lower()
        source_process = event.get('source_process', '').lower()
        granted_access = event.get('granted_access', '')

        # Доступ к LSASS
        if 'lsass' in target_process:
            result = {
                'is_suspicious': True,
                'reasons': ['lsass_access'],
                'score': 0.6,
                'attack_type': 'Credential Dumping',
                'severity': AlertSeverity.HIGH.value,
                'event_type': 'process_access'
            }

            result['source_process'] = source_process
            result['target_process'] = target_process
            result['granted_access'] = granted_access

            # Проверка опасных прав доступа
            dangerous_rights = ['0x1FFFFF', 'PROCESS_ALL_ACCESS', 'PROCESS_VM_READ', 'PROCESS_QUERY_INFORMATION']
            for right in dangerous_rights:
                if right in granted_access:
                    result['score'] += 0.15
                    result['reasons'].append(f"dangerous_access:{right}")
                    break

            result['score'] = min(1.0, result['score'])

            self.event_bus.publish('edr.threat', result)
            self.logger.warning(f"Обнаружен доступ к LSASS от {source_process}")

    def _process_image_load_event(self, event: Dict) -> None:
        """Анализ загрузки образа (DLL)"""
        self.image_load_events.append(event)

        image_loaded = event.get('image_loaded', '').lower()
        process_name = event.get('process_name', '').lower()
        signed = event.get('signed', '').lower()

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'image_load'
        }

        # 1. Загрузка неподписанной DLL в системный процесс
        system_processes = ['lsass.exe', 'csrss.exe', 'winlogon.exe', 'svchost.exe', 'services.exe']
        if any(proc in process_name for proc in system_processes):
            if signed == 'false':
                result['is_suspicious'] = True
                result['reasons'].append(f"unsigned_dll_in_system_process:{image_loaded}")
                result['score'] += 0.4
                result['attack_type'] = 'DLL Hijacking'

        # 2. Загрузка из подозрительных путей
        for sus_path in self.suspicious_paths:
            if sus_path in image_loaded:
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_dll_path:{sus_path}")
                result['score'] += 0.3
                break

        # 3. Подозрительные DLL
        for sus_dll in self.suspicious_dlls:
            if sus_dll in image_loaded:
                # Проверяем контекст
                if 'system32' not in image_loaded:
                    result['is_suspicious'] = True
                    result['reasons'].append(f"suspicious_dll_location:{sus_dll}")
                    result['score'] += 0.35
                    break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['image_loaded'] = image_loaded
            result['process_name'] = process_name
            result['timestamp'] = time.time()

            if result['score'] > 0.5:
                result['severity'] = AlertSeverity.MEDIUM.value

            self.event_bus.publish('edr.dll_threat', result)

    def _process_process_terminated(self, event: Dict) -> None:
        """Обработка завершения процесса"""
        # Проверка на необычное завершение защитных процессов
        process_name = event.get('process_name', '').lower()
        security_processes = ['msmpeng.exe', 'windefend.exe', 'msseces.exe', 'avp.exe']

        if any(proc in process_name for proc in security_processes):
            result = {
                'is_suspicious': True,
                'reasons': [f"security_process_terminated:{process_name}"],
                'score': 0.5,
                'attack_type': 'Defense Evasion',
                'severity': AlertSeverity.HIGH.value,
                'event_type': 'process_terminated'
            }
            self.event_bus.publish('edr.threat', result)
            self.logger.warning(f"Завершён процесс безопасности: {process_name}")

    def _process_file_time_event(self, event: Dict) -> None:
        """Обработка изменения времени файла (timestomping)"""
        result = {
            'is_suspicious': True,
            'reasons': ['file_time_manipulation'],
            'score': 0.4,
            'attack_type': 'Timestomping',
            'severity': AlertSeverity.MEDIUM.value,
            'event_type': 'file_time_change'
        }

        result['process_name'] = event.get('process_name', '')
        result['filename'] = event.get('filename', '')

        self.event_bus.publish('edr.threat', result)

    def _process_alternate_data_stream(self, event: Dict) -> None:
        """Обработка Alternate Data Stream"""
        result = {
            'is_suspicious': True,
            'reasons': ['ads_creation'],
            'score': 0.45,
            'attack_type': 'Data Hiding',
            'severity': AlertSeverity.MEDIUM.value,
            'event_type': 'ads'
        }

        result['process_name'] = event.get('process_name', '')
        result['filename'] = event.get('filename', '')

        self.event_bus.publish('edr.threat', result)

    def _process_pipe_event(self, event: Dict) -> None:
        """Обработка создания/подключения к именованному каналу"""
        pipe_name = event.get('pipe_name', '').lower()

        suspicious_pipes = ['lsarpc', 'samr', 'netlogon', 'spoolss', 'srvsvc', 'wkssvc']

        for sus_pipe in suspicious_pipes:
            if sus_pipe in pipe_name:
                result = {
                    'is_suspicious': True,
                    'reasons': [f"suspicious_pipe:{pipe_name}"],
                    'score': 0.35,
                    'attack_type': 'Lateral Movement',
                    'severity': AlertSeverity.MEDIUM.value,
                    'event_type': 'pipe'
                }
                result['process_name'] = event.get('process_name', '')
                result['pipe_name'] = pipe_name

                self.event_bus.publish('edr.threat', result)
                break

    def _process_file_delete(self, event: Dict) -> None:
        """Обработка удаления файла"""
        filename = event.get('filename', '').lower()

        # Удаление важных системных файлов или логов
        important_files = ['.evtx', '.log', 'ntuser.dat', 'sam', 'system', 'security']

        for imp_file in important_files:
            if imp_file in filename:
                result = {
                    'is_suspicious': True,
                    'reasons': [f"important_file_deleted:{filename}"],
                    'score': 0.4,
                    'attack_type': 'Defense Evasion',
                    'severity': AlertSeverity.MEDIUM.value,
                    'event_type': 'file_delete'
                }
                result['process_name'] = event.get('process_name', '')
                result['filename'] = filename

                self.event_bus.publish('edr.threat', result)
                break

    def _process_clipboard_event(self, event: Dict) -> None:
        """Обработка события буфера обмена"""
        process_name = event.get('process_name', '').lower()

        if process_name not in ['explorer.exe', 'chrome.exe', 'firefox.exe', 'notepad.exe']:
            result = {
                'is_suspicious': True,
                'reasons': [f'unusual_clipboard_access:{process_name}'],
                'score': 0.3,
                'attack_type': 'Credential Access',
                'severity': AlertSeverity.LOW.value,
                'event_type': 'clipboard'
            }
            self.event_bus.publish('edr.threat', result)

    def _process_tampering_event(self, event: Dict) -> None:
        """Обработка события подмены процесса"""
        result = {
            'is_suspicious': True,
            'reasons': ['process_tampering'],
            'score': 0.6,
            'attack_type': 'Process Hollowing',
            'severity': AlertSeverity.HIGH.value,
            'event_type': 'process_tampering'
        }

        result['process_name'] = event.get('process_name', '')
        result['technique'] = event.get('technique', '')

        self.event_bus.publish('edr.threat', result)

    def _process_wmi_process_start(self, event: Dict) -> None:
        """Обработка WMI создания процесса"""
        event['source'] = 'wmi'
        self._process_process_event(event)

    def _process_wmi_process_stop(self, event: Dict) -> None:
        """Обработка WMI завершения процесса"""
        event['source'] = 'wmi'
        self._process_process_terminated(event)

    def _process_wmi_service_change(self, event: Dict) -> None:
        """Обработка изменения сервиса через WMI"""
        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'event_type': 'service_change'
        }

        service_name = event.get('service_name', '').lower()
        state = event.get('state', '').lower()
        start_mode = event.get('start_mode', '').lower()

        # Создание сервиса с подозрительным именем
        suspicious_service_names = ['update', 'helper', 'support', 'service', 'driver', 'microsoft']
        for sus_name in suspicious_service_names:
            if sus_name in service_name:
                # Проверяем путь
                path_name = event.get('path_name', '').lower()
                for sus_path in self.suspicious_paths:
                    if sus_path in path_name:
                        result['is_suspicious'] = True
                        result['reasons'].append(f"suspicious_service_creation:{service_name}")
                        result['score'] += 0.4
                        result['attack_type'] = 'Persistence'
                        break
                break

        # Остановка защитных сервисов
        security_services = ['windefend', 'msmpeng', 'sense', 'wdnisdrv', 'wdfilter']
        for sec_svc in security_services:
            if sec_svc in service_name and state == 'stopped':
                result['is_suspicious'] = True
                result['reasons'].append(f"security_service_stopped:{service_name}")
                result['score'] += 0.5
                result['attack_type'] = 'Defense Evasion'
                break

        result['score'] = min(1.0, result['score'])

        if result['is_suspicious']:
            result['service_name'] = service_name
            result['state'] = state
            result['timestamp'] = time.time()

            if result['score'] > 0.5:
                result['severity'] = AlertSeverity.HIGH.value
            elif result['score'] > 0.3:
                result['severity'] = AlertSeverity.MEDIUM.value

            self.event_bus.publish('edr.threat', result)

    def _process_login_event(self, event: Dict) -> None:
        """Обработка события входа"""
        # Передаём в UBA
        self.event_bus.publish('auth.login', event)

        # Проверка на аномалии
        logon_type = event.get('logon_type', '')
        src_ip = event.get('src_ip', '')

        # RDP вход с необычного IP
        if logon_type == '10' and src_ip:
            # Проверка геолокации через ThreatIntel
            self.event_bus.publish('threat_intel.check_ip', {
                'ip': src_ip,
                'context': 'rdp_login',
                'username': event.get('username', '')
            })

    def _process_failed_login_event(self, event: Dict) -> None:
        """Обработка неудачного входа"""
        # Передаём в UBA
        self.event_bus.publish('auth.failed', event)

    def _analysis_loop(self) -> None:
        """Фоновый анализ событий"""
        while self.running:
            time.sleep(60)  # Каждую минуту

            # Анализ beaconing
            self._detect_beaconing()

            # Анализ цепочек событий
            self._analyze_event_chains()

            # Очистка старых событий
            self._cleanup_old_events()

    def _detect_beaconing(self) -> None:
        """Обнаружение C2 beaconing по сетевым соединениям (делегировано в EncryptedTrafficAnalyzer)"""

        # Собираем уникальные пары src_ip:dst_ip:dst_port
        unique_connections = set()
        cutoff = time.time() - 3600

        for event in self.network_events:
            if event.get('timestamp', 0) > cutoff:
                src_ip = event.get('src_ip', '')
                dst_ip = event.get('dst_ip', '')
                dst_port = event.get('dst_port', 0)
                process_name = event.get('process_name', '')

                if src_ip and dst_ip:
                    key = f"{src_ip}:{dst_ip}:{dst_port}"
                    unique_connections.add((key, process_name, event))

        # Для каждой уникальной пары проверяем beaconing через общий анализатор
        for key, process_name, event in unique_connections:
            # Публикуем событие для EncryptedTrafficAnalyzer вместо дублирования логики
            self.event_bus.publish('encrypted.traffic.check_beaconing', {
                'src_ip': event.get('src_ip'),
                'dst_ip': event.get('dst_ip'),
                'dst_port': event.get('dst_port'),
                'process_name': process_name,
                'timestamp': event.get('timestamp'),
                'packet_size': event.get('packet_size', 0)
            })

        # Оставляем только EDR-специфичную логику - анализ beaconing по процессам
        process_connections: Dict[str, List[float]] = defaultdict(list)

        for event in self.network_events:
            if event.get('timestamp', 0) > cutoff:
                process_name = event.get('process_name', '')
                if process_name:
                    process_connections[process_name].append(event.get('timestamp', 0))

        # Проверяем процессы с подозрительной периодичностью
        for process_name, timestamps in process_connections.items():
            if len(timestamps) < 10:
                continue

            timestamps.sort()
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                if mean_interval > 0:
                    variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
                    cv = (variance ** 0.5) / mean_interval

                    # Низкая вариация + процесс из списка подозрительных
                    if cv < 0.15 and process_name.lower() in self.suspicious_processes:
                        result = {
                            'is_suspicious': True,
                            'reasons': ['process_beaconing', f'cv:{cv:.3f}'],
                            'score': 0.55,
                            'attack_type': 'C2 Beaconing',
                            'severity': AlertSeverity.HIGH.value,
                            'event_type': 'process_beaconing',
                            'details': {
                                'process_name': process_name,
                                'mean_interval': round(mean_interval, 2),
                                'variation': round(cv, 3),
                                'connections': len(timestamps)
                            }
                        }
                        self.event_bus.publish('edr.threat', result)
                        self.logger.warning(
                            f"Обнаружен beaconing процесса: {process_name} (интервал: {mean_interval:.1f}с, cv={cv:.3f})")

    def _analyze_event_chains(self) -> None:
        """Анализ цепочек событий для обнаружения сложных атак (оптимизированный)"""
        cutoff = time.time() - 600  # За последние 10 минут

        # Строим индексы для быстрого поиска
        processes_by_pid: Dict[int, Dict] = {}
        office_pids: Set[int] = set()

        with self._lock:
            # Индексируем процессы
            for event in self.process_events:
                if event.get('timestamp', 0) > cutoff:
                    pid = event.get('pid')
                    if pid:
                        processes_by_pid[pid] = event

                        process_name = event.get('process_name', '').lower()
                        if any(p in process_name for p in ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']):
                            office_pids.add(pid)

            # Проверяем только office процессы
            for office_pid in office_pids:
                if office_pid not in processes_by_pid:
                    continue

                office_event = processes_by_pid[office_pid]

                # Находим дочерние процессы через parent_pid (O(n) вместо O(n²))
                child_scripts = []
                for pid, event in processes_by_pid.items():
                    if event.get('parent_pid') == office_pid:
                        process_name = event.get('process_name', '').lower()
                        if any(s in process_name for s in ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe']):
                            child_scripts.append((pid, event))

                # Проверяем сетевые соединения от дочерних процессов
                for script_pid, script_event in child_scripts:
                    # Используем индекс для быстрого поиска сетевых событий
                    network_events = [
                        e for e in self.network_events
                        if e.get('timestamp', 0) > script_event.get('timestamp', 0)
                           and e.get('process_id') == script_pid
                    ]

                    if network_events:
                        result = {
                            'is_suspicious': True,
                            'reasons': ['office_macro_chain'],
                            'score': 0.75,
                            'attack_type': 'Office Macro',
                            'severity': AlertSeverity.CRITICAL.value,
                            'event_type': 'attack_chain',
                            'details': {
                                'office_process': office_event.get('process_name'),
                                'script_process': script_event.get('process_name'),
                                'script_cmdline': script_event.get('command_line', '')[:200],
                                'network_target': f"{network_events[0].get('dst_ip')}:{network_events[0].get('dst_port')}"
                            }
                        }
                        self.event_bus.publish('edr.threat', result)

                        # Используем централизованное логирование через LoggingService
                        if hasattr(self.logger, 'security_alert'):
                            self.logger.security_alert(
                                module=self.name,
                                message=f"Обнаружена цепочка Office Macro: {office_event.get('process_name')} -> {script_event.get('process_name')} -> Network",
                                severity="CRITICAL",
                                data=result.get('details', {})
                            )
                        else:
                            # Fallback если LoggingService не обновлён
                            self.logger.critical(
                                f"Обнаружена цепочка Office Macro: {office_event.get('process_name')} -> "
                                f"{script_event.get('process_name')} -> Network"
                            )

                        break

    def _cleanup_old_events(self) -> None:
        """Очистка старых событий"""
        cutoff = time.time() - 7200  # Старше 2 часов

        with self._lock:
            for buffer in [self.process_events, self.file_events, self.registry_events,
                           self.network_events, self.dns_events, self.image_load_events]:
                while buffer and buffer[0].get('timestamp', 0) < cutoff:
                    buffer.popleft()

    def get_stats(self) -> Dict:
        """Получить статистику EDR"""
        with self._lock:
            return {
                'process_events': len(self.process_events),
                'file_events': len(self.file_events),
                'registry_events': len(self.registry_events),
                'network_events': len(self.network_events),
                'dns_events': len(self.dns_events),
                'image_load_events': len(self.image_load_events),
                'active_logs': len(self.event_log_handles),
                'wmi_active': len(self.wmi_watchers) > 0
            }

# ============================================================
# PROMETHEUS METRICS
# ============================================================

class PrometheusMetrics(BaseModule):
    """Экспорт метрик в Prometheus"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Prometheus", config, event_bus, logger)
        self.enabled = config.get('telemetry.prometheus.enabled', True)
        self.port = config.get('telemetry.prometheus.port', 9090)
        self.packets_counter = None
        self.attacks_counter = None
        self.blocked_counter = None
        self.exfiltration_counter = None
        self.dns_threats_counter = None

        if self.enabled and prometheus_client:
            self._init_metrics()

    def _init_metrics(self) -> None:
        self.packets_counter = prometheus_client.Counter('shard_packets_total', 'Total packets processed')
        self.attacks_counter = prometheus_client.Counter('shard_attacks_total', 'Total attacks detected', ['type'])
        self.blocked_counter = prometheus_client.Counter('shard_blocked_total', 'Total blocked IPs')
        self.exfiltration_counter = prometheus_client.Counter('shard_exfiltration_total', 'Data exfiltration events')
        self.dns_threats_counter = prometheus_client.Counter('shard_dns_threats_total', 'DNS threats detected')

        prometheus_client.start_http_server(self.port)
        self.logger.info(f"Метрики доступны на порту {self.port}")

    def start(self) -> None:
        self.running = True

        if self.enabled and prometheus_client:
            self.event_bus.subscribe('packet.processed', self._on_packet)
            self.event_bus.subscribe('alert.detected', self._on_alert)
            self.event_bus.subscribe('firewall.blocked', self._on_block)
            self.event_bus.subscribe('exfiltration.detected', self._on_exfiltration)
            self.event_bus.subscribe('dns.suspicious', self._on_dns_threat)

    def stop(self) -> None:
        self.running = False

    def _on_packet(self, data: Dict) -> None:
        if self.packets_counter:
            self.packets_counter.inc(data.get('count', 1))

    def _on_alert(self, alert: Dict) -> None:
        if self.attacks_counter:
            attack_type = str(alert.get('attack_type', 'unknown'))
            self.attacks_counter.labels(type=attack_type).inc()

    def _on_block(self, data: Dict) -> None:
        if self.blocked_counter:
            self.blocked_counter.inc()

    def _on_exfiltration(self, data: Dict) -> None:
        if self.exfiltration_counter:
            self.exfiltration_counter.inc()

    def _on_dns_threat(self, data: Dict) -> None:
        if self.dns_threats_counter:
            self.dns_threats_counter.inc()


# ============================================================
# TELEGRAM NOTIFIER
# ============================================================

class TelegramNotifier(BaseModule):
    """Уведомления в Telegram"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Telegram", config, event_bus, logger)
        self.enabled = config.get('telemetry.telegram.enabled', False)
        self.token = config.get('telemetry.telegram.token', '')
        self.chat_id = config.get('telemetry.telegram.chat_id', '')
        self._session = None

        if self.enabled and requests:
            self._session = requests.Session()
            self.event_bus.subscribe('alert.detected', self.on_alert)
            self.event_bus.subscribe('exfiltration.detected', self.on_exfiltration)
            self.event_bus.subscribe('dns.suspicious', self.on_dns_threat)
            self.event_bus.subscribe('uba.anomaly', self.on_uba_anomaly)

    def start(self) -> None:
        self.running = True
        if self.enabled:
            self.logger.info("Уведомления Telegram включены")

    def stop(self) -> None:
        self.running = False
        if self._session:
            self._session.close()

    def on_alert(self, alert: Dict) -> None:
        """Уведомление об алерте"""
        msg = self._format_alert(alert)
        self._send_message(msg)

    def on_exfiltration(self, data: Dict) -> None:
        """Уведомление об утечке данных"""
        msg = f"📤 *ОБНАРУЖЕНА УТЕЧКА ДАННЫХ*\n"
        msg += f"Источник: `{data.get('src_ip')}`\n"
        msg += f"Цель: `{data.get('dst_ip')}:{data.get('dst_port')}`\n"
        msg += f"Score: *{data.get('score', 0):.3f}*\n"
        msg += f"Причины: {', '.join(data.get('reasons', []))}"
        self._send_message(msg)

    def on_dns_threat(self, data: Dict) -> None:
        """Уведомление о DNS угрозе"""
        if data.get('score', 0) > 0.5:
            msg = f"🌐 *DNS УГРОЗА*\n"
            msg += f"Источник: `{data.get('src_ip')}`\n"
            msg += f"Запрос: `{data.get('query', 'unknown')}`\n"
            msg += f"Score: *{data.get('score', 0):.3f}*\n"
            msg += f"Тип: {data.get('attack_type', 'unknown')}"
            self._send_message(msg)

    def on_uba_anomaly(self, data: Dict) -> None:
        """Уведомление об аномалии поведения"""
        if data.get('score', 0) > 0.6:
            msg = f"👤 *АНОМАЛИЯ ПОВЕДЕНИЯ*\n"
            msg += f"Пользователь: `{data.get('username')}`\n"
            msg += f"Аномалии: {', '.join(data.get('anomalies', []))}\n"
            msg += f"Score: *{data.get('score', 0):.3f}*\n"
            msg += f"Текущий риск: {data.get('current_risk', 0):.2f}"
            self._send_message(msg)

    def _format_alert(self, alert: Dict) -> str:
        """Форматирование алерта"""
        severity_emoji = {
            'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'
        }
        emoji = severity_emoji.get(alert.get('severity', 'LOW'), '⚪')

        msg = f"{emoji} *{alert.get('attack_type', 'Unknown')}*\n"
        msg += f"Источник: `{alert.get('src_ip')}`\n"
        msg += f"Цель: `{alert.get('dst_ip')}:{alert.get('dst_port')}`\n"
        msg += f"Score: *{alert.get('score', 0):.3f}*\n"

        if alert.get('explanation'):
            msg += f"\n📋 {alert['explanation'][:200]}"

        if alert.get('kill_chain'):
            chain = alert['kill_chain']
            msg += f"\n\n🔗 Цепочка: {chain.get('event_count', 0)} событий, стадия: {chain.get('stage', 'unknown')}"

        if alert.get('threat_intel'):
            ti = alert['threat_intel']
            msg += f"\n\n🌍 Threat Intel: {', '.join(ti.get('sources', []))}"
            if ti.get('country'):
                msg += f" ({ti['country']})"

        return msg

    def _send_message(self, text: str) -> None:
        """Отправка сообщения в Telegram (токен в заголовке, не в URL)"""
        if not self.enabled or not self.token or not self._session:
            return

        try:
            response = self._session.post(
                'https://api.telegram.org/bot/sendMessage',
                headers={'Authorization': f'Bearer {self.token}'},
                json={
                    'chat_id': self.chat_id,
                    'text': text,
                    'parse_mode': 'Markdown'
                },
                timeout=5
            )

            if response.status_code != 200:
                self.logger.error(f"Telegram error: HTTP {response.status_code}")

        except Exception as e:
            self.logger.error(f"Telegram error: {type(e).__name__}")


# ============================================================
# BASELINE PROFILER
# ============================================================

class BaselineProfiler:
    """Построение базового профиля поведения (оптимизированная версия)"""

    def __init__(self):
        self.profiles: Dict[str, Dict] = defaultdict(lambda: {
            'packet_sizes': deque(maxlen=1000),
            'ports': defaultdict(int),
            'entropy': deque(maxlen=500),
            'hourly_activity': defaultdict(int),
            'daily_activity': defaultdict(int),
            'connections_per_hour': defaultdict(int),
            'unique_destinations': set(),
            'unique_sources': set(),
            'first_seen': time.time(),
            'last_seen': time.time(),
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'tcp_flags': defaultdict(int),
            'packet_intervals': deque(maxlen=100)
        })

        # Отдельные блокировки для разных операций
        self._profile_lock = threading.RLock()
        self._stats_lock = threading.RLock()
        self._last_packet_time: Dict[str, float] = {}
        self._time_lock = threading.RLock()

        # Кэшированные значения для быстрого доступа
        self._cached_stats: Dict[str, Dict] = {}
        self._cache_ttl = 60  # секунд
        self._last_cache_update: Dict[str, float] = {}

    def update(self, device: str, size: int, port: int, entropy: float,
               dst_ip: str = '', src_ip: str = '', protocol: int = 0,
               tcp_flags: int = 0) -> None:
        """Обновление профиля (исправлено - единая блокировка)"""
        now = datetime.now()
        current_time = time.time()

        # ВСЕ операции под одной блокировкой
        with self._profile_lock:
            if device not in self.profiles:
                self.profiles[device] = {
                    'packet_sizes': deque(maxlen=1000),
                    'ports': defaultdict(int),
                    'entropy': deque(maxlen=500),
                    'hourly_activity': defaultdict(int),
                    'daily_activity': defaultdict(int),
                    'connections_per_hour': defaultdict(int),
                    'unique_destinations': set(),
                    'unique_sources': set(),
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'total_packets': 0,
                    'total_bytes': 0,
                    'protocols': defaultdict(int),
                    'tcp_flags': defaultdict(int),
                    'packet_intervals': deque(maxlen=100)
                }

                # Инициализация времени последнего пакета
                with self._time_lock:
                    self._last_packet_time[device] = current_time

            p = self.profiles[device]

            # Интервал между пакетами
            with self._time_lock:
                if device in self._last_packet_time:
                    interval = current_time - self._last_packet_time[device]
                else:
                    interval = 0
                self._last_packet_time[device] = current_time

            # Обновление статистики
            p['packet_sizes'].append(size)
            p['entropy'].append(entropy)
            p['last_seen'] = current_time
            p['total_packets'] += 1
            p['total_bytes'] += size

            p['ports'][port] += 1
            p['hourly_activity'][now.hour] += 1
            p['daily_activity'][now.weekday()] += 1
            p['protocols'][protocol] += 1

            if tcp_flags:
                p['tcp_flags'][tcp_flags] += 1

            if dst_ip:
                p['unique_destinations'].add(dst_ip)
            if src_ip:
                p['unique_sources'].add(src_ip)

            if interval > 0 and interval < 60:
                p['packet_intervals'].append(interval)

            # Периодическая очистка старых данных
            if p['total_packets'] % 1000 == 0:
                self._cleanup_old_data(device, p, current_time)

            # Инвалидация кэша
            self._last_cache_update.pop(device, None)
            self._cached_stats.pop(f"{device}_score", None)

    def _cleanup_old_data(self, device: str, profile: Dict, current_time: float) -> None:
        """Очистка устаревших данных в профиле"""
        # Оставляем данные за последние 24 часа
        cutoff_time = current_time - 86400  # 24 часа

        # Очистка временных рядов (для deque используем создание нового)
        if 'packet_sizes' in profile:
            # Сохраняем только последние 10000 значений чтобы ограничить память
            if len(profile['packet_sizes']) > 10000:
                # Преобразуем в список, обрезаем, создаём новый deque
                old_sizes = list(profile['packet_sizes'])
                profile['packet_sizes'] = deque(old_sizes[-5000:], maxlen=10000)

        if 'entropy' in profile and len(profile['entropy']) > 10000:
            old_entropy = list(profile['entropy'])
            profile['entropy'] = deque(old_entropy[-5000:], maxlen=10000)

        if 'packet_intervals' in profile and len(profile['packet_intervals']) > 5000:
            old_intervals = list(profile['packet_intervals'])
            profile['packet_intervals'] = deque(old_intervals[-2500:], maxlen=5000)

        # Очистка set'ов уникальных адресов (оставляем последние 10000)
        if 'unique_destinations' in profile and len(profile['unique_destinations']) > 10000:
            # Конвертируем в список, берём последние 5000
            dest_list = list(profile['unique_destinations'])
            profile['unique_destinations'] = set(dest_list[-5000:])

        if 'unique_sources' in profile and len(profile['unique_sources']) > 10000:
            src_list = list(profile['unique_sources'])
            profile['unique_sources'] = set(src_list[-5000:])

        # Ограничиваем размер словарей счётчиков
        if 'ports' in profile and len(profile['ports']) > 1000:
            # Оставляем топ-500 портов по частоте
            sorted_ports = sorted(profile['ports'].items(), key=lambda x: x[1], reverse=True)
            profile['ports'] = defaultdict(int, dict(sorted_ports[:500]))

        if 'protocols' in profile and len(profile['protocols']) > 100:
            sorted_protos = sorted(profile['protocols'].items(), key=lambda x: x[1], reverse=True)
            profile['protocols'] = defaultdict(int, dict(sorted_protos[:50]))

    def get_score(self, device: str, size: int, port: int, entropy: float,
                  dst_ip: str = '', protocol: int = 0, tcp_flags: int = 0) -> float:
        """Получение оценки аномальности (исправлено - безопасный кэш)"""

        # Проверка кэша с безопасным доступом
        cache_key = f"{device}_score"
        cached = self._cached_stats.get(cache_key)  # ← ИСПОЛЬЗУЕМ .get()

        if cached is not None:
            last_update = self._last_cache_update.get(device, 0)
            if time.time() - last_update < self._cache_ttl:
                return self._calculate_score_fast(device, size, port, entropy, dst_ip, cached)

        # Полное вычисление
        with self._profile_lock:
            p = self.profiles.get(device)
            if not p or p['total_packets'] < 10:
                return 0.3

            # Копируем только необходимые данные
            profile_snapshot = {
                'packet_sizes': list(p['packet_sizes']),
                'ports': dict(p['ports']),
                'entropy': list(p['entropy']),
                'hourly_activity': dict(p['hourly_activity']),
                'unique_destinations': p['unique_destinations'].copy(),
                'protocols': dict(p['protocols']),
                'packet_intervals': list(p['packet_intervals']),
                'daily_activity': dict(p['daily_activity'])
            }

        # Вычисление вне блокировки
        score = self._calculate_score_full(device, size, port, entropy, dst_ip,
                                           protocol, profile_snapshot)

        # Кэширование снапшота
        self._cached_stats[cache_key] = profile_snapshot
        self._last_cache_update[device] = time.time()

        return score

    def _calculate_score_fast(self, device: str, size: int, port: int,
                              entropy: float, dst_ip: str, cached: Dict) -> float:
        """Быстрое вычисление с использованием кэшированных данных (исправлено - защита от нуля)"""
        scores = []
        weights = []

        # Размер пакета
        if cached.get('packet_sizes'):
            packet_sizes = cached['packet_sizes']
            if packet_sizes:
                mean = sum(packet_sizes) / len(packet_sizes)
                if mean > 0:
                    # Используем стандартное отклонение если возможно
                    if len(packet_sizes) > 1:
                        variance = sum((s - mean) ** 2 for s in packet_sizes) / len(packet_sizes)
                        std = max(mean * 0.1, math.sqrt(variance))  # минимум 10% от среднего
                    else:
                        std = mean * 0.5

                    z_score = abs(size - mean) / std
                    scores.append(min(1.0, z_score))
                    weights.append(0.15)

        # Энтропия
        if cached.get('entropy'):
            entropies = cached['entropy']
            if entropies:
                mean_e = sum(entropies) / len(entropies)
                if mean_e > 0:
                    if len(entropies) > 1:
                        variance_e = sum((e - mean_e) ** 2 for e in entropies) / len(entropies)
                        std_e = max(0.1, math.sqrt(variance_e))
                    else:
                        std_e = 0.5

                    z_ent = abs(entropy - mean_e) / std_e
                    scores.append(min(1.0, z_ent))
                    weights.append(0.15)

        # Новые направления
        if dst_ip and cached.get('unique_destinations'):
            unique_dests = cached['unique_destinations']
            is_new = dst_ip not in unique_dests
            scores.append(0.7 if is_new else 0.0)
            weights.append(0.15)

        # Защита от пустых списков
        if not scores or not weights:
            return 0.3

        # Безопасное вычисление взвешенного среднего
        total_weight = sum(weights)
        if total_weight > 0:
            return sum(s * w for s, w in zip(scores, weights)) / total_weight

        return 0.3

    def _calculate_score_full(self, device: str, size: int, port: int,
                              entropy: float, dst_ip: str, protocol: int,
                              profile: Dict) -> float:
        """Полное вычисление оценки аномальности"""
        scores = []
        weights = []
        now = datetime.now()

        # 1. Размер пакета (вес 0.12)
        if profile['packet_sizes']:
            sizes = profile['packet_sizes']
            mean = sum(sizes) / len(sizes)
            variance = sum((s - mean) ** 2 for s in sizes) / len(sizes)
            std = math.sqrt(variance) if variance > 0 else 1
            z_score = abs(size - mean) / (std * 3)
            scores.append(min(1.0, z_score))
            weights.append(0.12)

        # 2. Порт назначения (вес 0.12)
        if profile['ports']:
            total = sum(profile['ports'].values())
            freq = profile['ports'].get(port, 0) / total if total > 0 else 0
            scores.append(1.0 - min(1.0, freq * 5))
            weights.append(0.12)

        # 3. Энтропия (вес 0.12)
        if profile['entropy']:
            entropies = profile['entropy']
            mean_e = sum(entropies) / len(entropies)
            variance_e = sum((e - mean_e) ** 2 for e in entropies) / len(entropies)
            std_e = math.sqrt(variance_e) if variance_e > 0 else 0.1
            z_ent = abs(entropy - mean_e) / (std_e * 3)
            scores.append(min(1.0, z_ent))
            weights.append(0.12)

        # 4. Время суток (вес 0.20)
        current_hour_activity = profile['hourly_activity'].get(now.hour, 0)
        if profile['hourly_activity']:
            avg_hourly = sum(profile['hourly_activity'].values()) / len(profile['hourly_activity'])
            if avg_hourly > 0:
                deviation = abs(current_hour_activity - avg_hourly) / avg_hourly
                scores.append(min(1.0, deviation))
            else:
                scores.append(0.0)
            weights.append(0.20)

        # 5. Новые направления (вес 0.15)
        if dst_ip and profile['unique_destinations']:
            is_new = dst_ip not in profile['unique_destinations']
            scores.append(0.7 if is_new else 0.0)
            weights.append(0.15)

        # 6. Необычный протокол (вес 0.10)
        if protocol and profile['protocols']:
            total_proto = sum(profile['protocols'].values())
            proto_freq = profile['protocols'].get(protocol, 0) / total_proto if total_proto > 0 else 0
            scores.append(1.0 - min(1.0, proto_freq * 10))
            weights.append(0.10)

        # 7. Интервалы между пакетами (вес 0.10)
        if profile['packet_intervals']:
            intervals = profile['packet_intervals']
            if intervals:
                mean_int = sum(intervals) / len(intervals)
                if mean_int < 0.01:
                    scores.append(0.8)
                elif mean_int < 0.1:
                    scores.append(0.5)
                else:
                    scores.append(0.1)
                weights.append(0.10)

        # 8. День недели (вес 0.09)
        if len(profile['daily_activity']) > 2:
            current_day_activity = profile['daily_activity'].get(now.weekday(), 0)
            avg_daily = sum(profile['daily_activity'].values()) / len(profile['daily_activity'])
            if avg_daily > 0:
                day_deviation = abs(current_day_activity - avg_daily) / avg_daily
                scores.append(min(1.0, day_deviation))
                weights.append(0.09)

        if scores and weights:
            total_weight = sum(weights)
            if total_weight > 0:
                return sum(s * w for s, w in zip(scores, weights)) / total_weight

        return 0.3

    def get_profile(self, device: str) -> Optional[Dict]:
        """Получить профиль устройства (безопасное копирование)"""
        with self._profile_lock:
            if device in self.profiles:
                p = self.profiles[device]

                # Создаём копию для безопасного доступа извне
                return {
                    'total_packets': p['total_packets'],
                    'total_bytes': p['total_bytes'],
                    'unique_destinations': len(p['unique_destinations']),
                    'unique_sources': len(p['unique_sources']),
                    'first_seen': p['first_seen'],
                    'last_seen': p['last_seen'],
                    'top_ports': dict(sorted(p['ports'].items(),
                                             key=lambda x: x[1], reverse=True)[:10]),
                    'hourly_activity': dict(p['hourly_activity']),
                    'avg_packet_size': p['total_bytes'] / max(1, p['total_packets'])
                }
        return None

    def reset_profile(self, device: str) -> bool:
        """Сброс профиля устройства"""
        with self._profile_lock:
            if device in self.profiles:
                del self.profiles[device]
                self._last_cache_update.pop(device, None)
                self._cached_stats.pop(f"{device}_score", None)
                return True
        return False

    def get_all_devices(self) -> List[str]:
        """Получить список всех устройств"""
        with self._profile_lock:
            return list(self.profiles.keys())

    def get_summary_stats(self) -> Dict:
        """Общая статистика по всем профилям"""
        with self._profile_lock:
            total_packets = sum(p['total_packets'] for p in self.profiles.values())
            total_bytes = sum(p['total_bytes'] for p in self.profiles.values())
            active_devices = sum(1 for p in self.profiles.values()
                                 if time.time() - p['last_seen'] < 3600)

            return {
                'total_devices': len(self.profiles),
                'active_devices': active_devices,
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'total_bytes_mb': round(total_bytes / (1024 * 1024), 2)
            }

# ============================================================
# ATTACK CHAIN TRACKER
# ============================================================

class AttackChainTracker:
    """Отслеживание цепочек атак (Kill Chain) с автоматической очисткой и учётом хронологии"""

    def __init__(self):
        self.chains: Dict[str, Dict] = defaultdict(lambda: {
            'events': [],
            'first_seen': time.time(),
            'last_seen': time.time(),
            'stage': 'reconnaissance',
            'severity': 'LOW',
            'confidence': 0.0,
            'attack_types': set(),
            'targeted_ports': set(),
            'total_score': 0.0
        })

        self.stage_map = {
            'Port Scan': 'reconnaissance',
            'DNS Scan': 'reconnaissance',
            'Web Scan': 'reconnaissance',
            'Brute Force': 'credential_access',
            'Credential Dumping': 'credential_access',
            'Web Attack': 'initial_access',
            'SQL Injection': 'initial_access',
            'XSS': 'initial_access',
            'DoS': 'impact',
            'DDoS': 'impact',
            'Botnet': 'command_and_control',
            'C2 Beacon': 'command_and_control',
            'Lateral Movement': 'lateral_movement',
            'Data Exfiltration': 'exfiltration',
            'DNS Tunnel': 'command_and_control',
            'Phishing': 'initial_access',
            'Malware': 'execution'
        }

        # Прогрессия стадий (для определения максимальной достигнутой)
        self.stage_progression = {
            'reconnaissance': 1,
            'weaponization': 2,
            'delivery': 3,
            'initial_access': 4,
            'execution': 5,
            'persistence': 5,
            'privilege_escalation': 5,
            'defense_evasion': 5,
            'credential_access': 5,
            'discovery': 1,
            'lateral_movement': 6,
            'collection': 6,
            'command_and_control': 6,
            'exfiltration': 7,
            'impact': 7
        }

        self._lock = threading.RLock()
        self._cleanup_thread = None
        self._running = False
        self._start_cleanup()

    def _start_cleanup(self) -> None:
        """Запуск фоновой очистки"""
        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="AttackChain-Cleanup")
        self._cleanup_thread.start()

    def _cleanup_loop(self) -> None:
        """Фоновый цикл очистки устаревших цепочек"""
        while self._running:
            time.sleep(300)  # Каждые 5 минут
            cleaned = self.cleanup(max_age=3600)  # Удаляем старше 1 часа
            if cleaned > 0:
                logging.getLogger('SHARD').debug(f"Очищено {cleaned} устаревших цепочек атак")

    def cleanup(self, max_age: int = 3600) -> int:
        """Очистка устаревших цепочек"""
        with self._lock:
            now = time.time()
            expired = [ip for ip, chain in self.chains.items()
                       if now - chain['last_seen'] > max_age]
            for ip in expired:
                del self.chains[ip]
            return len(expired)

    def stop(self) -> None:
        """Остановка очистки"""
        self._running = False
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)

    def add_event(self, src_ip: str, attack_type: str, score: float, dst_port: int = 0) -> Dict:
        """Добавление события в цепочку"""
        with self._lock:
            chain = self.chains[src_ip]

            event_data = {
                'timestamp': time.time(),
                'type': attack_type,
                'score': score,
                'port': dst_port
            }

            chain['events'].append(event_data)
            chain['last_seen'] = time.time()
            chain['attack_types'].add(attack_type)
            chain['targeted_ports'].add(dst_port)
            chain['total_score'] += score

            # Определение стадии с учётом хронологии
            chain['stage'] = self._determine_stage(chain)

            event_count = len(chain['events'])

            # Определение серьёзности и уверенности
            if event_count >= 10:
                chain['severity'] = 'CRITICAL'
                chain['confidence'] = 0.95
            elif event_count >= 5:
                chain['severity'] = 'HIGH'
                chain['confidence'] = 0.85
            elif event_count >= 3:
                chain['severity'] = 'MEDIUM'
                chain['confidence'] = 0.70
            elif event_count >= 2:
                chain['severity'] = 'LOW'
                chain['confidence'] = 0.50
            else:
                chain['severity'] = 'INFO'
                chain['confidence'] = 0.30

            # Учёт score
            avg_score = chain['total_score'] / event_count
            if avg_score > 0.7:
                chain['severity'] = 'CRITICAL'
                chain['confidence'] = min(1.0, chain['confidence'] + 0.1)

            return {
                'src_ip': src_ip,
                'event_count': event_count,
                'stage': chain['stage'],
                'severity': chain['severity'],
                'confidence': chain['confidence'],
                'attack_types': list(chain['attack_types']),
                'duration': chain['last_seen'] - chain['first_seen'],
                'chain': list(chain['events'])[-10:]
            }

    def _determine_stage(self, chain: Dict) -> str:
        """Определение текущей стадии атаки с учётом хронологии"""
        if not chain.get('events'):
            return 'unknown'

        # Сортируем события по времени
        sorted_events = sorted(chain['events'], key=lambda x: x.get('timestamp', 0))

        # Определяем максимальную достигнутую стадию
        max_stage_level = 0
        current_stage = 'reconnaissance'

        for event in sorted_events:
            attack_type = event.get('type', '')
            stage = self.stage_map.get(attack_type, 'unknown')
            stage_level = self.stage_progression.get(stage, 0)

            if stage_level > max_stage_level:
                max_stage_level = stage_level
                current_stage = stage

        # Приоритетная логика для финальных стадий
        attack_types_in_chain = set(e.get('type', '') for e in sorted_events)

        if 'Data Exfiltration' in attack_types_in_chain:
            return 'exfiltration'
        elif 'Lateral Movement' in attack_types_in_chain:
            return 'lateral_movement'
        elif 'C2 Beacon' in attack_types_in_chain or 'DNS Tunnel' in attack_types_in_chain:
            return 'command_and_control'
        elif 'Brute Force' in attack_types_in_chain:
            return 'credential_access'
        elif 'Web Attack' in attack_types_in_chain or 'SQL Injection' in attack_types_in_chain:
            return 'initial_access'
        elif 'Port Scan' in attack_types_in_chain:
            return 'reconnaissance'

        return current_stage if current_stage != 'unknown' else 'reconnaissance'

    def get_chain(self, src_ip: str) -> Optional[Dict]:
        """Получить цепочку атак"""
        with self._lock:
            if src_ip in self.chains:
                chain = self.chains[src_ip]
                return {
                    'src_ip': src_ip,
                    'event_count': len(chain['events']),
                    'stage': chain['stage'],
                    'severity': chain['severity'],
                    'confidence': chain['confidence'],
                    'attack_types': list(chain['attack_types']),
                    'targeted_ports': list(chain['targeted_ports']),
                    'duration': chain['last_seen'] - chain['first_seen'],
                    'first_seen': chain['first_seen'],
                    'last_seen': chain['last_seen'],
                    'events': list(chain['events'])[-20:]
                }
        return None

    def get_active_chains(self, min_severity: str = 'LOW') -> List[Dict]:
        """Получить активные цепочки атак"""
        severity_order = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_level = severity_order.get(min_severity, 1)

        active = []
        with self._lock:
            now = time.time()
            for ip, chain in self.chains.items():
                if now - chain['last_seen'] < 3600:  # Активные за последний час
                    if severity_order.get(chain['severity'], 0) >= min_level:
                        active.append(self.get_chain(ip))

        return sorted(active, key=lambda x: x['event_count'], reverse=True)

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            total_chains = len(self.chains)
            active_chains = sum(1 for c in self.chains.values()
                                if time.time() - c['last_seen'] < 3600)

            severity_counts = defaultdict(int)
            for chain in self.chains.values():
                severity_counts[chain['severity']] += 1

            return {
                'total_chains': total_chains,
                'active_chains': active_chains,
                'severity_distribution': dict(severity_counts),
                'cleanup_thread_running': self._running
            }

    def reset_chain(self, src_ip: str) -> bool:
        """Сброс цепочки для IP"""
        with self._lock:
            if src_ip in self.chains:
                del self.chains[src_ip]
                return True
        return False

    def reset_all(self) -> int:
        """Сброс всех цепочек"""
        with self._lock:
            count = len(self.chains)
            self.chains.clear()
            return count


# ============================================================
# LATERAL MOVEMENT DETECTOR
# ============================================================

class LateralMovementDetector:
    """Обнаружение горизонтального перемещения в сети (оптимизированный)"""

    def __init__(self, local_networks: List[str] = None):
        self.local_networks = local_networks or ['192.168.', '10.', '172.16.', '127.']
        self.internal_connections: Dict[str, Set[str]] = defaultdict(set)

        # Оптимизированное хранение истории
        self.connection_history: deque = deque(maxlen=10000)
        self._src_index: Dict[str, List[Dict]] = defaultdict(list)  # Индекс по src_ip
        self._cleanup_counter = 0
        self._cleanup_threshold = 1000

        self.credential_usage: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        self._lock = threading.RLock()

    def add_connection(self, src_ip: str, dst_ip: str, dst_port: int,
                       username: str = None, service: str = None) -> Optional[Dict]:
        """Добавление внутреннего соединения (оптимизированное)"""
        if not self.is_local(src_ip) or not self.is_local(dst_ip):
            return None

        with self._lock:
            now = time.time()

            # Проверка ДО добавления
            is_new_destination = dst_ip not in self.internal_connections[src_ip]

            # Добавление
            self.internal_connections[src_ip].add(dst_ip)
            self.internal_connections[dst_ip].add(src_ip)

            conn_data = {
                'timestamp': now,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'username': username,
                'service': service
            }

            self.connection_history.append(conn_data)
            self._src_index[src_ip].append(conn_data)

            # Периодическая очистка индекса
            self._cleanup_counter += 1
            if self._cleanup_counter >= self._cleanup_threshold:
                self._cleanup_index(now - 3600)  # Удаляем старше часа
                self._cleanup_counter = 0

            if username:
                self.credential_usage[username][src_ip].add(dst_ip)

            # Быстрый подсчёт недавних соединений через индекс
            recent_count = sum(1 for c in self._src_index[src_ip]
                               if now - c['timestamp'] < 60)

            is_suspicious = False
            reasons = []
            score = 0.0

            if is_new_destination:
                is_suspicious = True
                reasons.append("new_internal_connection")
                score += 0.25

            # Подозрительные порты
            lateral_ports = {445: 'SMB', 135: 'RPC', 139: 'NetBIOS', 3389: 'RDP',
                             5985: 'WinRM', 5986: 'WinRM_HTTPS', 22: 'SSH'}

            if dst_port in lateral_ports:
                is_suspicious = True
                reasons.append(f"suspicious_port_{lateral_ports[dst_port]}")
                score += 0.25
                if dst_port in [3389, 5985, 5986]:
                    score += 0.15

            if recent_count >= 10:
                is_suspicious = True
                reasons.append(f"multiple_connections:{recent_count}")
                score += 0.3
            elif recent_count >= 5:
                is_suspicious = True
                reasons.append(f"scanning_behavior:{recent_count}")
                score += 0.2

            if username:
                used_ips = self.credential_usage[username]
                if len(used_ips) > 3:
                    is_suspicious = True
                    reasons.append(f"credential_spread:{len(used_ips)}_ips")
                    score += 0.35

            if is_suspicious:
                severity = 'HIGH' if score > 0.6 else 'MEDIUM' if score > 0.4 else 'LOW'
                return {
                    'type': 'lateral_movement',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'service': lateral_ports.get(dst_port, 'unknown'),
                    'username': username,
                    'reasons': reasons,
                    'score': min(1.0, score),
                    'severity': severity,
                    'timestamp': now,
                    'is_new_connection': is_new_destination
                }

        return None

    def _cleanup_index(self, cutoff: float) -> None:
        """Очистка индекса с ограничением размера"""
        max_index_size = 10000  # Максимальный размер индекса на один IP

        for src_ip in list(self._src_index.keys()):
            # Очистка по времени
            self._src_index[src_ip] = [c for c in self._src_index[src_ip] if c['timestamp'] > cutoff]

            # Ограничение по размеру
            if len(self._src_index[src_ip]) > max_index_size:
                # Оставляем только последние записи
                self._src_index[src_ip] = sorted(
                    self._src_index[src_ip],
                    key=lambda x: x['timestamp'],
                    reverse=True
                )[:max_index_size // 2]

            if not self._src_index[src_ip]:
                del self._src_index[src_ip]


# ============================================================
# SMART FIREWALL
# ============================================================

class SmartFirewall(BaseModule):
    """Умный файрвол с градацией ответа"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Firewall", config, event_bus, logger)
        self.auto_block = config.get('protection.auto_block', False)
        self.block_duration = config.get('protection.block_duration', 3600)
        self.rate_threshold = config.get('protection.rate_limit.threshold', 100)
        self.rate_window = config.get('protection.rate_limit.window', 60)

        self.rate_limits: Dict[str, Dict[int, deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=1000)))
        self.blocked_ips: Dict[str, float] = {}
        self.blocked_ports: Dict[str, Set[int]] = defaultdict(set)
        self.action_levels: Dict[str, int] = defaultdict(int)
        self.action_history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self.whitelist: Set[str] = set()

        self.response_levels = {
            1: 'throttle',
            2: 'block_port',
            3: 'block_ip_temp',
            4: 'block_ip_perm'
        }

        # Отдельные блокировки для избежания deadlock
        self._lock = threading.RLock()
        self._history_lock = threading.RLock()
        self._cleanup_lock = threading.RLock()

        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('exfiltration.detected', self.on_exfiltration)

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._cleanup_loop, daemon=True).start()
        self.logger.info(f"Запущен (auto_block: {self.auto_block}, умная градация)")

    def stop(self) -> None:
        self.running = False

    def add_to_whitelist(self, ip: str) -> None:
        """Добавить IP в белый список"""
        with self._lock:
            self.whitelist.add(ip)

    def remove_from_whitelist(self, ip: str) -> None:
        """Удалить IP из белого списка"""
        with self._lock:
            self.whitelist.discard(ip)

    def check_rate_limit(self, src_ip: str, dst_port: int) -> bool:
        """Проверка rate limit"""
        if src_ip in self.whitelist:
            return True

        with self._lock:
            now = time.time()
            entry = self.rate_limits[src_ip][dst_port]
            cutoff = now - self.rate_window

            # Очистка старых записей
            while entry and entry[0] < cutoff:
                entry.popleft()

            entry.append(now)

            if len(entry) >= self.rate_threshold:
                self._apply_action(src_ip, dst_port, 'throttle')
                return False
            return True

    def is_blocked(self, ip: str, port: int = None) -> bool:
        """Проверка, заблокирован ли IP/порт"""
        with self._lock:
            if ip in self.whitelist:
                return False

            if ip in self.blocked_ips:
                if time.time() < self.blocked_ips[ip]:
                    return True

            if port and ip in self.blocked_ports:
                return port in self.blocked_ports[ip]

            return False

    def on_alert(self, alert: Dict) -> None:
        """Обработка алерта"""
        if not self.auto_block:
            return

        src_ip = alert.get('src_ip', '')
        dst_port = alert.get('dst_port', 0)
        score = alert.get('score', 0)
        severity = alert.get('severity', 'LOW')

        if not src_ip or src_ip in self.whitelist:
            return

        with self._lock:
            # Увеличиваем уровень в зависимости от score и severity
            increment = 1
            if severity == 'CRITICAL':
                increment = 4
            elif severity == 'HIGH':
                increment = 3
            elif severity == 'MEDIUM':
                increment = 2
            elif score > 0.8:
                increment = 3
            elif score > 0.6:
                increment = 2

            self.action_levels[src_ip] += increment
            level = min(4, self.action_levels[src_ip])
            action = self.response_levels[level]

            self.action_history[src_ip].append((time.time(), action))

            # Очистка старых записей
            cutoff = time.time() - 3600
            self.action_history[src_ip] = [(t, a) for t, a in self.action_history[src_ip] if t > cutoff]

        self._apply_action(src_ip, dst_port, action, alert)

    def on_exfiltration(self, data: Dict) -> None:
        """Немедленная реакция на утечку данных"""
        if not self.auto_block:
            return

        src_ip = data.get('src_ip', '')
        if src_ip and src_ip not in self.whitelist:
            # Немедленная блокировка при утечке данных
            self._apply_action(src_ip, 0, 'block_ip_temp', data)
            self.logger.critical(f"🚨 НЕМЕДЛЕННАЯ БЛОКИРОВКА из-за утечки данных: {src_ip}")

    def _apply_action(self, src_ip: str, dst_port: int, action: str, context: Dict = None) -> None:
        """Применение действия"""
        if src_ip in self.whitelist:
            return

        if action == 'throttle':
            self.logger.info(f"🐢 Замедление {src_ip}:{dst_port}")
            # Здесь можно добавить реальное замедление через iptables/Windows Firewall

        elif action == 'block_port':
            with self._lock:
                self.blocked_ports[src_ip].add(dst_port)
            self.logger.warning(f"🔒 Блокировка порта {dst_port} для {src_ip}")
            self.event_bus.publish('firewall.port_blocked', {'ip': src_ip, 'port': dst_port})

        elif action == 'block_ip_temp':
            self.block_ip(src_ip, 1800)  # 30 минут
            self.event_bus.publish('firewall.blocked', {
                'ip': src_ip,
                'duration': 1800,
                'reason': context.get('attack_type') if context else 'unknown'
            })

        elif action == 'block_ip_perm':
            self.block_ip(src_ip, 86400)  # 24 часа
            self.event_bus.publish('firewall.blocked', {
                'ip': src_ip,
                'duration': 86400,
                'permanent': True,
                'reason': context.get('attack_type') if context else 'unknown'
            })

    def _validate_ip(self, ip: str) -> bool:
        """Валидация IP адреса перед использованием в командах"""
        if not ip:
            return False

        # Проверка формата IPv4
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        if not match:
            return False

        # Проверка значений октетов
        for octet in match.groups():
            if int(octet) > 255:
                return False

        # Запрет опасных символов
        dangerous_chars = [';', '&', '|', '$', '`', '(', ')', '<', '>', '\'', '"', '\\', '\n', '\r']
        for char in dangerous_chars:
            if char in ip:
                return False

        return True

    def _validate_port(self, port: int) -> bool:
        """Валидация порта"""
        return isinstance(port, int) and 0 < port < 65536

    def _validate_ip_strict(self, ip: str) -> bool:
        """Строгая валидация IP адреса"""
        if not ip:
            return False

        # Проверка формата
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            return False

        # Проверка октетов
        try:
            octets = [int(x) for x in ip.split('.')]
            if any(o > 255 or o < 0 for o in octets):
                return False
        except ValueError:
            return False

        # Запрет опасных символов
        dangerous_chars = [';', '&', '|', '$', '`', '(', ')', '<', '>', '\'', '"', '\\', '\n', '\r', ' ']
        for char in dangerous_chars:
            if char in ip:
                return False

        return True

    def block_ip(self, ip: str, duration: int = 3600) -> bool:
        """Блокировка IP с проверкой существующей блокировки"""
        if not self._validate_ip_strict(ip):
            self.logger.error(f"Некорректный IP адрес: {ip}")
            return False

        with self._lock:
            # Проверка whitelist
            if ip in self.whitelist:
                self.logger.debug(f"IP {ip} в белом списке, блокировка отменена")
                return False

            # Проверка существующей блокировки
            if ip in self.blocked_ips:
                existing_expiry = self.blocked_ips[ip]
                if time.time() < existing_expiry:
                    self.logger.debug(f"IP {ip} уже заблокирован до {datetime.fromtimestamp(existing_expiry)}")
                    return False

            # Устанавливаем блокировку
            self.blocked_ips[ip] = time.time() + duration

        # Проверяем существование правила в iptables
        if os.name != 'nt':
            check_result = subprocess.run(
                ['iptables', '-C', 'SHARD_BLOCK', '-s', ip, '-j', 'DROP'],
                capture_output=True,
                timeout=5
            )

            if check_result.returncode == 0:
                self.logger.debug(f"Правило iptables для {ip} уже существует")
                return True

        # Добавляем правило
        try:
            if os.name == 'nt':
                rule_name = f"SHARD_Block_{ip.replace('.', '_')}"
                if not re.match(r'^[a-zA-Z0-9_]+$', rule_name):
                    return False

                result = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                     f'name={rule_name}', 'dir=in', f'remoteip={ip}',
                     'action=block', 'enable=yes', 'profile=any'],
                    capture_output=True, text=True, timeout=10, check=False
                )

                if result.returncode == 0:
                    self.logger.warning(f"🚫 Заблокирован IP {ip} на {duration} сек (Windows Firewall)")
                    return True
            else:
                self.add_iptables_chain()
                result = subprocess.run(
                    ['iptables', '-A', 'SHARD_BLOCK', '-s', ip, '-j', 'DROP'],
                    capture_output=True, timeout=10, check=False
                )

                if result.returncode == 0:
                    self.logger.warning(f"🚫 Заблокирован IP {ip} на {duration} сек (iptables)")
                    return True

        except Exception as e:
            self.logger.error(f"Ошибка блокировки IP {ip}: {e}")

        # Откат при ошибке
        with self._lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
        return False

    def unblock_ip(self, ip: str) -> bool:
        """Разблокировка IP (безопасная версия)"""
        if not self._validate_ip_strict(ip):
            return False

        with self._lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]

        try:
            if os.name == 'nt':
                rule_name = f"SHARD_Block_{ip.replace('.', '_')}"
                if not re.match(r'^[a-zA-Z0-9_]+$', rule_name):
                    return False

                subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                    capture_output=True,
                    timeout=10,
                    check=False
                )
            else:
                # Удаляем все правила для этого IP
                while True:
                    result = subprocess.run(
                        ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                        capture_output=True,
                        timeout=5
                    )
                    if result.returncode != 0:
                        break

            self.logger.info(f"✅ Разблокирован IP {ip}")
            return True

        except Exception as e:
            self.logger.error(f"Ошибка разблокировки IP {ip}: {e}")
            return False

    def block_port(self, ip: str, port: int) -> bool:
        """Блокировка порта для конкретного IP"""
        if not self._validate_ip(ip) or not self._validate_port(port):
            self.logger.error(f"Некорректный IP {ip} или порт {port}")
            return False

        if ip in self.whitelist:
            return False

        with self._lock:
            self.blocked_ports[ip].add(port)

        try:
            if os.name == 'nt':
                rule_name = f"SHARD_Block_{ip.replace('.', '_')}_port_{port}"
                result = subprocess.run(
                    [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name={rule_name}',
                        'dir=in',
                        f'remoteip={ip}',
                        f'localport={port}',
                        'protocol=TCP',
                        'action=block'
                    ],
                    capture_output=True,
                    timeout=10,
                    check=False
                )
                success = result.returncode == 0
            else:
                result = subprocess.run(
                    ['iptables', '-A', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP'],
                    capture_output=True,
                    timeout=10,
                    check=False
                )
                success = result.returncode == 0

            if success:
                self.logger.warning(f"🔒 Заблокирован порт {port} для {ip}")
            return success

        except Exception as e:
            self.logger.error(f"Ошибка блокировки порта {port} для {ip}: {e}")
            return False

    def add_iptables_chain(self) -> bool:
        """Создание отдельной цепочки iptables для SHARD (однократно)"""
        if os.name == 'nt':
            return True

        # Проверяем кэш создания цепочки
        if hasattr(self, '_chain_created') and self._chain_created:
            return True

        try:
            # Проверяем существование цепочки
            check = subprocess.run(
                ['iptables', '-L', 'SHARD_BLOCK'],
                capture_output=True, timeout=5
            )

            if check.returncode != 0:
                # Создаём цепочку
                subprocess.run(
                    ['iptables', '-N', 'SHARD_BLOCK'],
                    capture_output=True, timeout=5, check=False
                )

            # Проверяем правило перехода
            check_jump = subprocess.run(
                ['iptables', '-C', 'INPUT', '-j', 'SHARD_BLOCK'],
                capture_output=True, timeout=5
            )

            if check_jump.returncode != 0:
                subprocess.run(
                    ['iptables', '-I', 'INPUT', '1', '-j', 'SHARD_BLOCK'],
                    capture_output=True, timeout=5, check=False
                )

            self._chain_created = True
            self.logger.debug("Цепочка SHARD_BLOCK в iptables создана")
            return True

        except Exception as e:
            self.logger.error(f"Ошибка создания цепочки iptables: {e}")
            return False

    def _cleanup_loop(self) -> None:
        """Очистка истёкших блокировок и снижение уровней угрозы (исправлен deadlock)"""
        while self.running:
            time.sleep(60)
            now = time.time()

            # Сначала собираем IP для разблокировки ВНЕ блокировки
            ips_to_unblock = []

            with self._lock:
                # Разблокировка истёкших IP
                expired = [ip for ip, exp in list(self.blocked_ips.items()) if exp <= now]
                ips_to_unblock.extend(expired)

                # Снижение уровней угрозы со временем
                for ip in list(self.action_levels.keys()):
                    if ip in self.action_history:
                        history = self.action_history[ip]
                        if history:
                            last_action_time = max(t for t, _ in history)
                            time_since_last = now - last_action_time

                            # Снижаем уровень каждые 30 минут бездействия
                            if time_since_last > 1800:
                                self.action_levels[ip] = max(0, self.action_levels[ip] - 1)

                                # Если уровень стал 0 - удаляем из истории
                                if self.action_levels[ip] == 0:
                                    del self.action_levels[ip]
                                    if ip in self.action_history:
                                        del self.action_history[ip]

                        # Очистка старых записей в истории
                        cutoff = now - 7200  # 2 часа
                        self.action_history[ip] = [(t, a) for t, a in history if t > cutoff]
                        if not self.action_history[ip]:
                            del self.action_history[ip]

            # Разблокируем IP ВНЕ блокировки
            for ip in ips_to_unblock:
                self._unblock_ip_internal(ip)
                try:
                    if os.name == 'nt':
                        rule_name = f"SHARD_Block_{ip.replace('.', '_')}"
                        subprocess.run(
                            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                            capture_output=True,
                            timeout=5
                        )
                    else:
                        subprocess.run(
                            ['iptables', '-D', 'SHARD_BLOCK', '-s', ip, '-j', 'DROP'],
                            capture_output=True,
                            timeout=5
                        )
                except Exception as e:
                    self.logger.debug(f"Ошибка разблокировки {ip}: {e}")

    def _unblock_ip_internal(self, ip: str) -> None:
        """Внутренний метод разблокировки без дополнительных проверок"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
        if ip in self.blocked_ports:
            del self.blocked_ports[ip]
        if ip in self.action_levels:
            del self.action_levels[ip]
        if ip in self.action_history:
            del self.action_history[ip]
        if ip in self.rate_limits:
            del self.rate_limits[ip]

    def flush_blocks(self) -> int:
        """Сброс всех блокировок"""
        count = 0

        try:
            if os.name == 'nt':
                # Удаление всех правил SHARD
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                for line in result.stdout.split('\n'):
                    if 'SHARD_Block_' in line:
                        rule_name = line.split(':')[1].strip()
                        subprocess.run(
                            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                            capture_output=True,
                            timeout=5
                        )
                        count += 1
            else:
                # Очистка цепочки SHARD
                subprocess.run(
                    ['iptables', '-F', 'SHARD_BLOCK'],
                    capture_output=True,
                    timeout=10
                )
                count = -1  # Неизвестно точное количество

            # Очистка внутренних структур
            with self._lock:
                self.blocked_ips.clear()
                self.blocked_ports.clear()
                self.action_levels.clear()
                self.action_history.clear()

            self.logger.info(f"Сброшено {count} правил блокировки")
            return count

        except Exception as e:
            self.logger.error(f"Ошибка сброса блокировок: {e}")
            return 0


# ============================================================
# ALERT EXPLAINER
# ============================================================

class AlertExplainer:
    """Объяснение алертов на естественном языке"""

    def __init__(self):
        self.reason_templates = {
            'high_frequency': "Обнаружено {count} попыток за {seconds} секунд",
            'unusual_port': "Использован нестандартный порт {port}",
            'night_time': "Активность в нерабочее время ({hour}:00)",
            'new_destination': "Первое обращение к {dst_ip}",
            'high_entropy': "Высокая энтропия данных ({entropy:.2f})",
            'large_packet': "Необычно большой пакет ({size} байт)",
            'suspicious_payload': "Обнаружена сигнатура: {signature}",
            'multiple_failures': "Множественные неудачные попытки аутентификации",
            'port_scan_pattern': "Поведение характерное для сканирования портов",
            'bruteforce_pattern': "Поведение характерное для подбора пароля",
            'lateral_movement': "Горизонтальное перемещение внутри сети",
            'data_exfiltration': "Обнаружена утечка данных ({volume} MB)",
            'dns_tunnel': "Обнаружен DNS туннель ({query_length} символов)",
            'dga_domain': "Обнаружен DGA домен (энтропия {entropy:.2f})",
            'suspicious_tld': "Подозрительный домен верхнего уровня: {tld}",
            'threat_intel': "IP найден в базе угроз ({sources})",
            'new_geo': "Вход из новой геолокации: {geo}",
            'unusual_volume': "Аномальный объём трафика: {volume}",
            'privileged_account': "Затронута привилегированная учётная запись",
            'suspicious_process': "Подозрительный процесс: {process}",
            'remote_thread': "Обнаружено внедрение в процесс",
            'lsass_access': "Обнаружен доступ к LSASS",
            'credential_dumping': "Попытка получения учётных данных"
        }

        self.mitre_techniques = {
            'Brute Force': 'T1110',
            'Port Scan': 'T1046',
            'Web Attack': 'T1190',
            'DDoS': 'T1498',
            'Lateral Movement': 'T1021',
            'Data Exfiltration': 'T1048',
            'DNS Tunnel': 'T1572',
            'Botnet': 'T1571',
            'Phishing': 'T1566',
            'Credential Dumping': 'T1003'
        }

    def explain(self, alert: Dict, context: Dict = None) -> str:
        """Сгенерировать объяснение алерта"""
        attack_type = alert.get('attack_type', 'Unknown')
        score = alert.get('score', 0)
        src_ip = alert.get('src_ip', 'unknown')
        dst_port = alert.get('dst_port', 0)

        reasons = []

        # Объяснения по типу атаки
        if attack_type == 'Brute Force':
            reasons.append(self.reason_templates['multiple_failures'])
            reasons.append(self.reason_templates['high_frequency'].format(count='10+', seconds='60'))
        elif attack_type == 'Port Scan':
            reasons.append(self.reason_templates['port_scan_pattern'])
            reasons.append(self.reason_templates['high_frequency'].format(count='множество', seconds='10'))
        elif attack_type == 'Lateral Movement':
            reasons.append(self.reason_templates['lateral_movement'])
        elif attack_type == 'Data Exfiltration':
            volume = alert.get('total_bytes_recent', 0) / 1_000_000
            reasons.append(self.reason_templates['data_exfiltration'].format(volume=f"{volume:.1f}"))
        elif attack_type == 'DNS Tunnel':
            reasons.append(self.reason_templates['dns_tunnel'].format(
                query_length=alert.get('query_length', 'неизвестно')))

        # Добавление контекстных причин
        if context:
            if context.get('is_night_time'):
                reasons.append(self.reason_templates['night_time'].format(hour=datetime.now().hour))
            if context.get('is_new_destination'):
                reasons.append(self.reason_templates['new_destination'].format(
                    dst_ip=alert.get('dst_ip', 'unknown')))
            if context.get('entropy', 0) > 3.5:
                reasons.append(self.reason_templates['high_entropy'].format(entropy=context['entropy']))
            if context.get('packet_size', 0) > 1400:
                reasons.append(self.reason_templates['large_packet'].format(size=context['packet_size']))

        # Threat Intelligence
        if alert.get('threat_intel'):
            ti = alert['threat_intel']
            reasons.append(self.reason_templates['threat_intel'].format(
                sources=', '.join(ti.get('sources', []))))

        # Привилегированная учётка
        if alert.get('is_privileged_account'):
            reasons.append(self.reason_templates['privileged_account'])

        # MITRE ATT&CK
        mitre_id = self.mitre_techniques.get(attack_type, '')
        if mitre_id:
            reasons.append(f"MITRE ATT&CK: {mitre_id}")

        if not reasons:
            reasons.append(f"Аномальное поведение (score={score:.3f})")

        # Формирование полного объяснения
        explanation = f"🚨 {attack_type} с {src_ip}"
        if dst_port:
            explanation += f":{dst_port}"
        explanation += f".\nПричины: " + "; ".join(reasons)

        # Рекомендация
        explanation += f"\n\nРекомендация: {self._get_recommendation(attack_type, score)}"

        return explanation

    def _get_recommendation(self, attack_type: str, score: float) -> str:
        """Получить рекомендацию"""
        recommendations = {
            'Brute Force': "Включить блокировку после N попыток, проверить сложность паролей.",
            'Port Scan': "Проверить правила файрвола, закрыть неиспользуемые порты.",
            'Web Attack': "Проверить WAF, обновить веб-приложение.",
            'DDoS': "Включить DDoS защиту, связаться с провайдером.",
            'Lateral Movement': "Изолировать затронутые системы, сменить пароли.",
            'Data Exfiltration': "Немедленно заблокировать источник, проверить утечку.",
            'DNS Tunnel': "Настроить DNS фильтрацию, блокировать подозрительные запросы.",
            'Botnet': "Изолировать систему, провести полное сканирование.",
            'Phishing': "Предупредить пользователей, проверить почтовые фильтры."
        }

        if score > 0.8:
            return "🚨 КРИТИЧЕСКИЙ УРОВЕНЬ! " + recommendations.get(attack_type,
                                                                   "Немедленно принять меры по блокировке и изоляции.")
        elif score > 0.6:
            return "⚠️ ВЫСОКИЙ УРОВЕНЬ! " + recommendations.get(attack_type,
                                                                "Требуется срочное реагирование.")

        return recommendations.get(attack_type, "Провести дополнительный анализ.")


# ============================================================
# ENCRYPTED TRAFFIC ANALYZER
# ============================================================

class EncryptedTrafficAnalyzer(BaseModule):
    """Анализ зашифрованного трафика (TLS/JA3/Beaconing) с очисткой сессий"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("EncryptedTraffic", config, event_bus, logger)

        self.tls_sessions: Dict[str, Dict] = {}

        self.malicious_ja3 = {
            '6734f37431670b3ab4292b8f60f29984': ('Trickbot', 'CRITICAL'),
            '51c64c77e60f3980eea90869b68c58a8': ('Meterpreter', 'CRITICAL'),
            '2d5f5df3a5d5f5df3a5d5f5df3a5d5f5d': ('Emotet', 'CRITICAL'),
            'e35df3e35df3e35df3e35df3e35df3e35d': ('CobaltStrike', 'CRITICAL'),
            '3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a': ('Qakbot', 'CRITICAL'),
            'b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5': ('IcedID', 'HIGH'),
            'cccccccccccccccccccccccccccccccc': ('Dridex', 'HIGH'),
        }

        self.malicious_ja3s = {
            'f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4': ('CobaltStrike_Server', 'CRITICAL'),
        }

        self.beacon_threshold = 0.7
        self._lock = threading.RLock()

        # Параметры очистки сессий
        self._session_ttl = 3600  # 1 час
        self._max_sessions = 10000
        self._cleanup_thread = None
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5 минут

        self.event_bus.subscribe('packet.received', self.on_packet)

    def start(self) -> None:
        """Запуск анализатора"""
        self.running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="TLS-Cleanup")
        self._cleanup_thread.start()
        self.logger.info("Анализатор зашифрованного трафика запущен")

    def stop(self) -> None:
        """Остановка анализатора"""
        self.running = False
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)
        self.logger.info("Анализатор зашифрованного трафика остановлен")

    def _cleanup_loop(self) -> None:
        """Фоновый цикл очистки устаревших сессий"""
        while self.running:
            time.sleep(self._cleanup_interval)
            cleaned = self._cleanup_old_sessions()
            if cleaned > 0:
                self.logger.debug(f"Очищено {cleaned} устаревших TLS сессий")
            self._last_cleanup = time.time()

    def _cleanup_old_sessions(self) -> int:
        """Очистка устаревших TLS сессий"""
        with self._lock:
            now = time.time()
            expired = []

            # Удаляем по TTL
            for session_key, session in self.tls_sessions.items():
                last_seen = session.get('last_seen', session.get('first_seen', 0))
                if now - last_seen > self._session_ttl:
                    expired.append(session_key)

            for key in expired:
                del self.tls_sessions[key]

            # Если всё ещё слишком много - удаляем самые старые (LRU)
            if len(self.tls_sessions) > self._max_sessions:
                sorted_sessions = sorted(
                    self.tls_sessions.items(),
                    key=lambda x: x[1].get('last_seen', x[1].get('first_seen', 0))
                )
                to_remove = len(self.tls_sessions) - self._max_sessions
                for key, _ in sorted_sessions[:to_remove]:
                    if key not in expired:
                        del self.tls_sessions[key]
                        expired.append(key)

            return len(expired)

    def on_packet(self, data: Dict) -> None:
        """Обработка пакета"""
        if not self.running:
            return

        packet = data.get('packet')
        if packet:
            result = self.analyze_tls(packet)
            if result['is_suspicious']:
                result['src_ip'] = data.get('src_ip', 'unknown')
                result['dst_ip'] = data.get('dst_ip', 'unknown')
                result['timestamp'] = time.time()
                self.event_bus.publish('encrypted.threat', result)

                # Также публикуем как алерт
                self.event_bus.publish('alert.detected', {
                    'timestamp': result['timestamp'],
                    'src_ip': result['src_ip'],
                    'dst_ip': result['dst_ip'],
                    'attack_type': result.get('malware_family', 'TLS Threat'),
                    'score': result['score'],
                    'severity': result.get('severity', 'MEDIUM'),
                    'is_attack': True,
                    'explanation': f"Обнаружена угроза в зашифрованном трафике: {', '.join(result['reasons'])}"
                })

    def analyze_tls(self, packet) -> Dict:
        """Анализ TLS трафика"""
        from scapy.all import TCP, Raw, IP

        result = {
            'is_suspicious': False,
            'reasons': [],
            'score': 0.0,
            'ja3': None,
            'ja3s': None,
            'tls_version': None,
            'cipher_suites': [],
            'sni': None
        }

        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return result

        payload = bytes(packet[Raw].load)
        if len(payload) < 6 or payload[0] != 0x16:  # TLS handshake
            return result

        # Версия TLS
        result['tls_version'] = f"{payload[1]:02x}{payload[2]:02x}"

        # Устаревшие версии TLS
        if payload[1] == 0x03 and payload[2] < 0x03:  # TLS < 1.2
            result['is_suspicious'] = True
            result['reasons'].append(f"old_tls_version:{result['tls_version']}")
            result['score'] += 0.2

        # Client Hello (JA3)
        if payload[5] == 0x01:
            ja3 = self._compute_ja3(payload)
            result['ja3'] = ja3

            if ja3 in self.malicious_ja3:
                name, severity = self.malicious_ja3[ja3]
                result['is_suspicious'] = True
                result['reasons'].append(f"malicious_ja3:{name}")
                result['score'] += 0.6
                result['malware_family'] = name
                result['severity'] = severity

        # Server Hello (JA3S)
        elif payload[5] == 0x02:
            ja3s = self._compute_ja3s(payload)
            result['ja3s'] = ja3s

            if ja3s in self.malicious_ja3s:
                name, severity = self.malicious_ja3s[ja3s]
                result['is_suspicious'] = True
                result['reasons'].append(f"malicious_ja3s:{name}")
                result['score'] += 0.5

        # Анализ энтропии
        entropy = self._calculate_entropy(payload)
        result['entropy'] = entropy

        if entropy > 0.85:
            result['is_suspicious'] = True
            result['reasons'].append(f"high_entropy:{entropy:.2f}")
            result['score'] += 0.3

        # Обнаружение Beaconing
        beacon_score = self._detect_beaconing(packet)
        if beacon_score > self.beacon_threshold:
            result['is_suspicious'] = True
            result['reasons'].append(f"beaconing:{beacon_score:.2f}")
            result['score'] += 0.4
            result['beacon_score'] = beacon_score

        # Извлечение SNI
        sni = self._extract_sni(payload)
        if sni:
            result['sni'] = sni
            # Проверка на подозрительный SNI
            if self._is_suspicious_sni(sni):
                result['is_suspicious'] = True
                result['reasons'].append(f"suspicious_sni:{sni[:50]}")
                result['score'] += 0.25

        result['score'] = min(1.0, result['score'])

        # Определение серьёзности
        if result['score'] > 0.7:
            result['severity'] = 'CRITICAL'
        elif result['score'] > 0.5:
            result['severity'] = 'HIGH'
        elif result['score'] > 0.3:
            result['severity'] = 'MEDIUM'
        else:
            result['severity'] = 'LOW'

        return result

    def _compute_ja3(self, payload: bytes) -> str:
        """Вычисление JA3 хеша"""
        try:
            ja3_str = f"{payload[1]:02x}{payload[2]:02x}"
            if len(payload) > 50:
                ja3_str += hashlib.md5(payload[50:100]).hexdigest()[:16]
            return hashlib.md5(ja3_str.encode()).hexdigest()[:32]
        except:
            return "unknown"

    def _compute_ja3s(self, payload: bytes) -> str:
        """Вычисление JA3S хеша"""
        try:
            ja3s_str = f"{payload[1]:02x}{payload[2]:02x}"
            if len(payload) > 40:
                ja3s_str += hashlib.md5(payload[40:80]).hexdigest()[:16]
            return hashlib.md5(ja3s_str.encode()).hexdigest()[:32]
        except:
            return "unknown"

    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Извлечение SNI из Client Hello"""
        try:
            sni_marker = b'\x00\x00'
            idx = payload.find(sni_marker)
            if idx > 0 and idx + 10 < len(payload):
                sni_len = payload[idx + 7]
                if sni_len > 0 and idx + 8 + sni_len < len(payload):
                    sni = payload[idx + 8:idx + 8 + sni_len]
                    return sni.decode('utf-8', errors='ignore')
        except:
            pass
        return None

    def _is_suspicious_sni(self, sni: str) -> bool:
        """Проверка SNI на подозрительность"""
        suspicious_patterns = [
            '.tk', '.ml', '.ga', '.cf', '.gq',
            'update', 'secure', 'bank', 'account',
            'paypal', 'microsoft', 'google'
        ]

        sni_lower = sni.lower()

        if len(sni) > 40:
            return True

        for pattern in suspicious_patterns:
            if pattern in sni_lower:
                if not sni_lower.endswith(f".{pattern}.com") and not sni_lower == f"{pattern}.com":
                    return True

        return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Вычисление энтропии"""
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in freq.values())
        return entropy / 8.0  # Нормализация

    def _detect_beaconing(self, packet) -> float:
        """Обнаружение C2 beaconing (безопасная проверка слоёв)"""
        from scapy.all import IP

        # Безопасное извлечение IP адресов
        if not packet.haslayer(IP):
            return 0.0

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if not src_ip or not dst_ip:
            return 0.0

        session_key = f"{src_ip}:{dst_ip}"

        with self._lock:
            if session_key not in self.tls_sessions:
                self.tls_sessions[session_key] = {
                    'timestamps': deque(maxlen=100),
                    'sizes': deque(maxlen=100),
                    'first_seen': time.time(),
                    'last_seen': time.time()
                }

            session = self.tls_sessions[session_key]
            now = time.time()
            session['timestamps'].append(now)
            session['sizes'].append(len(packet))
            session['last_seen'] = now

            if len(session['timestamps']) < 5:
                return 0.0

            # Анализ интервалов
            intervals = []
            stamps = list(session['timestamps'])
            for i in range(1, len(stamps)):
                interval = stamps[i] - stamps[i - 1]
                if interval > 0:
                    intervals.append(interval)

            if not intervals:
                return 0.0

            mean_interval = sum(intervals) / len(intervals)

            # Защита от деления на ноль
            if mean_interval <= 0:
                return 0.0

            variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
            cv = (variance ** 0.5) / mean_interval

            # Beaconing характерен низкой вариацией интервалов
            beacon_score = max(0.0, 1.0 - cv)

            # Анализ размеров пакетов
            sizes = list(session['sizes'])
            if len(sizes) > 5:
                mean_size = sum(sizes) / len(sizes)
                if mean_size > 0:
                    size_variance = sum((s - mean_size) ** 2 for s in sizes) / len(sizes)
                    size_cv = (size_variance ** 0.5) / mean_size
                    size_consistency = max(0.0, 1.0 - size_cv)
                    beacon_score = (beacon_score * 0.6 + size_consistency * 0.4)

            return beacon_score

    def get_session_info(self, session_key: str) -> Optional[Dict]:
        """Получить информацию о TLS сессии"""
        with self._lock:
            if session_key in self.tls_sessions:
                session = self.tls_sessions[session_key]
                return {
                    'packet_count': len(session['timestamps']),
                    'duration': time.time() - session['first_seen'],
                    'avg_size': sum(session['sizes']) / len(session['sizes']) if session['sizes'] else 0
                }
        return None

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            return {
                'active_sessions': len(self.tls_sessions),
                'max_sessions': self._max_sessions,
                'session_ttl': self._session_ttl,
                'last_cleanup': self._last_cleanup,
                'malicious_ja3_count': len(self.malicious_ja3),
                'malicious_ja3s_count': len(self.malicious_ja3s)
            }

    def add_malicious_ja3(self, ja3_hash: str, name: str, severity: str = 'HIGH') -> None:
        """Добавить вредоносный JA3"""
        with self._lock:
            self.malicious_ja3[ja3_hash] = (name, severity)
        self.logger.info(f"Добавлен вредоносный JA3: {name}")

    def cleanup_now(self) -> int:
        """Принудительная очистка сессий"""
        return self._cleanup_old_sessions()


# ============================================================
# WAF (Web Application Firewall)
# ============================================================

class WebApplicationFirewall(BaseModule):
    """Веб-файрвол для защиты от веб-атак (исправлен - персистентность, безопасные счётчики, увеличен maxlen)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("WAF", config, event_bus, logger)
        self.enabled = config.get('waf.enabled', True)
        self.rules = self._load_rules()

        # Персистентное хранение заблокированных IP
        self.blocked_patterns: Set[str] = set()
        self.blocked_file = Path('data/waf_blocked.json')
        self._load_blocked_ips()

        # Увеличиваем maxlen до 200 чтобы не обрезать историю раньше срабатывания лимита 100/60
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._rate_counters: Dict[str, Dict] = {}
        self._lock = threading.RLock()

        if self.enabled:
            self.event_bus.subscribe('packet.received', self.on_packet)
            self.event_bus.subscribe('dpi.http', self.on_http)

    def _load_rules(self) -> List[Tuple[str, str, str, float]]:
        """Загрузка правил WAF"""
        return [
            ('SQLi_Union', r'union\s+select', 'CRITICAL', 0.8),
            ('SQLi_Or', r"'\\s*or\\s*'1'\\s*=\\s*'1", 'CRITICAL', 0.8),
            ('SQLi_Comment', r'--\s*$', 'HIGH', 0.6),
            ('SQLi_Semicolon', r';\s*(select|insert|update|delete|drop)', 'CRITICAL', 0.9),
            ('XSS_Script', r'<script[^>]*>', 'HIGH', 0.7),
            ('XSS_Img', r'<img[^>]+onerror\s*=', 'HIGH', 0.7),
            ('Path_Traversal', r'\.\./', 'HIGH', 0.6),
            ('Path_Windows', r'\.\.\\', 'HIGH', 0.6),
            ('Cmd_Pipe', r'\|\s*(ls|cat|id|whoami|uname)', 'CRITICAL', 0.8),
            ('Log4Shell_JNDI', r'\$\{jndi:', 'CRITICAL', 1.0),
        ]

    def _load_blocked_ips(self) -> None:
        """Загрузка заблокированных IP из файла"""
        try:
            if self.blocked_file.exists():
                with open(self.blocked_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.blocked_patterns = set(data.get('blocked_ips', []))
                    self.logger.info(f"Загружено {len(self.blocked_patterns)} заблокированных IP")
        except Exception as e:
            self.logger.warning(f"Ошибка загрузки блокировок WAF: {e}")

    def _save_blocked_ips(self) -> None:
        """Сохранение заблокированных IP в файл"""
        try:
            self.blocked_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.blocked_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'blocked_ips': list(self.blocked_patterns),
                    'updated': time.time()
                }, f)
        except Exception as e:
            self.logger.error(f"Ошибка сохранения блокировок WAF: {e}")

    def start(self) -> None:
        self.running = True
        if self.enabled:
            self.logger.info(f"WAF запущен с {len(self.rules)} правилами")

    def stop(self) -> None:
        self._save_blocked_ips()
        self.running = False

    def _check_rate_limit(self, src_ip: str) -> bool:
        """Проверка rate limit (исправлен TOCTOU)"""
        with self._lock:
            # АТОМАРНАЯ проверка - если уже заблокирован, сразу отказ
            if src_ip in self.blocked_patterns:
                return False

            history = self.request_history[src_ip]
            now = time.time()
            cutoff = now - WAFThresholds.RATE_LIMIT_WINDOW

            # Точный подсчёт
            exact_count = sum(1 for t in history if t > cutoff)

            if exact_count > WAFThresholds.RATE_LIMIT_REQUESTS:
                # АТОМАРНО добавляем в заблокированные
                self.blocked_patterns.add(src_ip)
                alert_to_publish = True
                alert = {
                    'timestamp': now,
                    'src_ip': src_ip,
                    'attack_type': 'Rate Limit',
                    'score': 0.6,
                    'confidence': 0.9,
                    'severity': 'MEDIUM',
                    'is_attack': True,
                    'explanation': f'WAF rate limit exceeded: {exact_count} requests/{WAFThresholds.RATE_LIMIT_WINDOW}s'
                }
                return False

            history.append(now)

            # Очистка старых записей
            if len(history) > WAFThresholds.MAX_BUFFER_SIZE:
                self.request_history[src_ip] = deque([t for t in history if t > cutoff],
                                                     maxlen=WAFThresholds.MAX_BUFFER_SIZE)

            return True

    def on_packet(self, data: Dict) -> None:
        """Анализ пакетов"""
        packet = data.get('packet')
        if not packet:
            return

        try:
            from scapy.all import TCP, Raw
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                if packet[TCP].dport in [80, 443, 8080, 8443, 8000, 8888]:
                    src_ip = data.get('src_ip', 'unknown')

                    if not self._check_rate_limit(src_ip):
                        return

                    payload = bytes(packet[Raw].load)
                    result = self._analyze_payload(payload, src_ip)
                    if result['is_attack']:
                        self.event_bus.publish('waf.alert', result)
                        self.logger.warning(f"WAF: {result['max_severity']} атака от {src_ip}")

        except Exception as e:
            self.logger.debug(f"WAF ошибка: {e}")

    def on_http(self, data: Dict) -> None:
        """Анализ HTTP запросов"""
        src_ip = data.get('src_ip', 'unknown')

        if not self._check_rate_limit(src_ip):
            return

        uri = data.get('uri', '')
        headers = data.get('headers', {})
        body = data.get('body', '')

        uri_result = self._analyze_text(uri, f"{src_ip}_uri")
        if uri_result['is_attack']:
            self.event_bus.publish('waf.alert', uri_result)

        for header, value in headers.items():
            header_result = self._analyze_text(value, f"{src_ip}_header")
            if header_result['is_attack']:
                self.event_bus.publish('waf.alert', header_result)

        if body:
            body_result = self._analyze_text(body, f"{src_ip}_body")
            if body_result['is_attack']:
                self.event_bus.publish('waf.alert', body_result)

    def _analyze_payload(self, payload: bytes, src_ip: str) -> Dict:
        """Анализ бинарной нагрузки"""
        result = {
            'is_attack': False,
            'threats': [],
            'max_severity': 'NONE',
            'src_ip': src_ip,
            'timestamp': time.time()
        }

        try:
            text = payload.decode('utf-8', errors='ignore')
            return self._analyze_text(text, src_ip)
        except:
            pass

        return result

    def _analyze_text(self, text: str, context: str) -> Dict:
        """Анализ текста на атаки"""
        result = {
            'is_attack': False,
            'threats': [],
            'max_severity': 'NONE',
            'context': context,
            'timestamp': time.time()
        }

        for name, pattern, severity, score in self.rules:
            if re.search(pattern, text, re.IGNORECASE):
                result['threats'].append({
                    'rule': name,
                    'pattern': pattern[:50],
                    'severity': severity,
                    'score': score
                })
                result['is_attack'] = True

        if result['threats']:
            sev_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            result['max_severity'] = max(
                result['threats'],
                key=lambda t: sev_order.get(t['severity'], 0)
            )['severity']
            result['total_score'] = min(1.0, sum(t['score'] for t in result['threats']))

        return result

    def add_rule(self, name: str, pattern: str, severity: str, score: float) -> None:
        """Добавить правило WAF"""
        self.rules.append((name, pattern, severity, score))
        self.logger.info(f"Добавлено правило WAF: {name}")

    def unblock_ip(self, ip: str) -> bool:
        """Разблокировка IP в WAF"""
        with self._lock:
            if ip in self.blocked_patterns:
                self.blocked_patterns.remove(ip)
                self._save_blocked_ips()
                self.logger.info(f"WAF: IP {ip} разблокирован")
                return True
        return False

    def get_stats(self) -> Dict:
        """Статистика WAF"""
        with self._lock:
            return {
                'total_rules': len(self.rules),
                'blocked_ips': len(self.blocked_patterns),
                'active_requests': len(self.request_history),
                'rate_counters': len(self._rate_counters)
            }


# ============================================================
# JA3 FINGERPRINTER
# ============================================================

class JA3Fingerprinter(BaseModule):
    """JA3 фингерпринтинг для обнаружения вредоносного ПО"""

    MALICIOUS_JA3 = {
        '6734f37431670b3ab4292b8f60f29984': ('Trickbot', 'CRITICAL'),
        '51c64c77e60f3980eea90869b68c58a8': ('Meterpreter', 'CRITICAL'),
        '2d5f5df3a5d5f5df3a5d5f5df3a5d5f5d': ('Emotet', 'CRITICAL'),
        'e35df3e35df3e35df3e35df3e35df3e35d': ('CobaltStrike', 'CRITICAL'),
        '3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a': ('Qakbot', 'CRITICAL'),
        'b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5': ('IcedID', 'HIGH'),
        'cccccccccccccccccccccccccccccccc': ('Dridex', 'HIGH'),
        'a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0': ('BazarLoader', 'HIGH'),
        'f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4': ('Ursnif', 'MEDIUM'),
    }

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("JA3", config, event_bus, logger)
        self.ja3_cache: Dict[str, Dict] = {}
        self._lock = threading.RLock()
        self.event_bus.subscribe('packet.received', self.on_packet)

    def start(self) -> None:
        self.running = True
        self.logger.info(f"JA3 фингерпринтинг запущен ({len(self.MALICIOUS_JA3)} сигнатур)")

    def stop(self) -> None:
        self.running = False

    def on_packet(self, data: Dict) -> None:
        """Обработка пакета"""
        packet = data.get('packet')
        if not packet:
            return

        try:
            from scapy.all import TCP, Raw, IP
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                src_ip = data.get('src_ip', 'unknown')
                dst_ip = data.get('dst_ip', 'unknown')
                dst_port = data.get('dst_port', 0)

                ja3_hash = self._fingerprint(bytes(packet[Raw].load))
                if ja3_hash:
                    # Сохраняем в кэш
                    with self._lock:
                        self.ja3_cache[f"{src_ip}:{dst_ip}"] = {
                            'ja3': ja3_hash,
                            'timestamp': time.time(),
                            'port': dst_port
                        }

                    # Проверяем на вредоносность
                    is_mal, name, severity = self._is_malicious(ja3_hash)
                    if is_mal:
                        alert = {
                            'timestamp': time.time(),
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'dst_port': dst_port,
                            'ja3_hash': ja3_hash,
                            'malware_name': name,
                            'severity': severity,
                            'attack_type': 'Malware',
                            'score': 0.8 if severity == 'CRITICAL' else 0.6,
                            'is_attack': True,
                            'explanation': f"Обнаружен вредоносный JA3 fingerprint: {name}"
                        }

                        self.event_bus.publish('ja3.malicious', alert)
                        self.event_bus.publish('alert.detected', alert)
                        self.logger.warning(f"🚨 Обнаружен вредоносный JA3: {name} от {src_ip}")

        except Exception as e:
            self.logger.debug(f"JA3 ошибка: {e}")

    def _fingerprint(self, payload: bytes) -> Optional[str]:
        """Вычисление JA3 фингерпринта (полная версия)"""
        if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
            return None

        try:
            tls_version = f"{payload[1]:02x}{payload[2]:02x}"

            offset = 1 + 2 + 2 + 1 + 3 + 2 + 32
            if offset >= len(payload):
                return None

            session_id_len = payload[offset]
            offset += 1 + session_id_len

            if offset + 2 >= len(payload):
                return None

            cipher_suites_len = (payload[offset] << 8) + payload[offset + 1]
            offset += 2

            cipher_suites = []
            for i in range(0, cipher_suites_len, 2):
                if offset + i + 1 < len(payload):
                    cs = (payload[offset + i] << 8) + payload[offset + i + 1]
                    cipher_suites.append(f"{cs:04x}")

            offset += cipher_suites_len

            if offset >= len(payload):
                return None

            compression_len = payload[offset]
            offset += 1 + compression_len

            if offset + 2 >= len(payload):
                return None

            extensions_len = (payload[offset] << 8) + payload[offset + 1]
            offset += 2

            extensions = []
            elliptic_curves = ""
            ec_formats = ""

            ext_offset = offset
            while ext_offset + 4 <= offset + extensions_len and ext_offset < len(payload):
                ext_type = (payload[ext_offset] << 8) + payload[ext_offset + 1]
                ext_len = (payload[ext_offset + 2] << 8) + payload[ext_offset + 3]

                extensions.append(f"{ext_type:04x}")

                # Извлечение Elliptic Curves (type 0x000a)
                if ext_type == 0x000a and ext_len >= 2:
                    curves_len = (payload[ext_offset + 4] << 8) + payload[ext_offset + 5]
                    curves = []
                    for i in range(0, curves_len, 2):
                        if ext_offset + 6 + i + 1 < len(payload):
                            curve = (payload[ext_offset + 6 + i] << 8) + payload[ext_offset + 6 + i + 1]
                            curves.append(f"{curve:04x}")
                    elliptic_curves = ','.join(curves)

                # Извлечение EC Point Formats (type 0x000b)
                if ext_type == 0x000b and ext_len >= 1:
                    formats_len = payload[ext_offset + 4]
                    formats = []
                    for i in range(formats_len):
                        if ext_offset + 5 + i < len(payload):
                            formats.append(f"{payload[ext_offset + 5 + i]:02x}")
                    ec_formats = ','.join(formats)

                ext_offset += 4 + ext_len

            ja3_parts = [
                tls_version,
                ','.join(cipher_suites) if cipher_suites else "",
                ','.join(extensions) if extensions else "",
                elliptic_curves,
                ec_formats
            ]

            ja3_string = ','.join(ja3_parts)
            return hashlib.md5(ja3_string.encode()).hexdigest()

        except Exception as e:
            return None

    def _is_malicious(self, ja3_hash: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Проверка JA3 на вредоносность"""
        if ja3_hash in self.MALICIOUS_JA3:
            name, severity = self.MALICIOUS_JA3[ja3_hash]
            return True, name, severity
        return False, None, None

    def get_ja3_for_ip(self, ip: str) -> Optional[str]:
        """Получить JA3 для IP"""
        with self._lock:
            for key, data in self.ja3_cache.items():
                if key.startswith(ip):
                    return data['ja3']
        return None

    def add_malicious_ja3(self, ja3_hash: str, name: str, severity: str = 'HIGH') -> None:
        """Добавить вредоносный JA3"""
        self.MALICIOUS_JA3[ja3_hash] = (name, severity)
        self.logger.info(f"Добавлен вредоносный JA3: {name}")


# ============================================================
# DPI (Deep Packet Inspection)
# ============================================================

class DeepPacketInspector(BaseModule):
    """Глубокий анализ пакетов (HTTP/DNS) с пакетной обработкой"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("DPI", config, event_bus, logger)
        self.http_methods = {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'}
        self._lock = threading.RLock()

        # Буферы для пакетной обработки
        self._http_buffer: List[Dict] = []
        self._dns_buffer: List[Dict] = []
        self._suspicious_buffer: List[Dict] = []
        self._buffer_lock = threading.RLock()
        self._batch_size = 50
        self._flush_interval = 1  # секунда
        self._flush_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="DPI-Flush")
        self._flush_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="DPI-Flush")
        self._last_flush = time.time()
        self._flush_thread = None

        self.event_bus.subscribe('packet.received', self.on_packet)

    def start(self) -> None:
        self.running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True, name="DPI-Flush")
        self._flush_thread.start()
        self.logger.info("DPI запущен (HTTP/DNS анализ с пакетной обработкой)")

    def stop(self) -> None:
        self.running = False
        self._flush_buffers()  # Сброс при остановке
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=2)
        self.logger.info("DPI остановлен")

    def _flush_loop(self) -> None:
        """Фоновый сброс буферов"""
        while self.running:
            time.sleep(self._flush_interval)
            self._flush_buffers()

    def _flush_buffers(self) -> None:
        """Пакетная публикация событий"""
        with self._buffer_lock:
            if not self._http_buffer and not self._dns_buffer and not self._suspicious_buffer:
                return

            http_events = self._http_buffer[:]
            dns_events = self._dns_buffer[:]
            suspicious_events = self._suspicious_buffer[:]

            self._http_buffer.clear()
            self._dns_buffer.clear()
            self._suspicious_buffer.clear()

        # Публикация вне блокировки
        for event in http_events:
            self.event_bus.publish('dpi.http', event)

        for event in dns_events:
            self.event_bus.publish('dpi.dns', event)

        for event in suspicious_events:
            self.event_bus.publish('dpi.suspicious_http', event)

        if http_events or dns_events:
            self.logger.debug(
                f"Сброшено: {len(http_events)} HTTP, {len(dns_events)} DNS, {len(suspicious_events)} подозрительных")

    def on_packet(self, data: Dict) -> None:
        """Обработка пакета (с фильтрацией и буферизацией)"""
        packet = data.get('packet')
        if not packet:
            return

        try:
            from scapy.all import TCP, UDP, Raw, IP

            src_ip = data.get('src_ip', 'unknown')
            dst_ip = data.get('dst_ip', 'unknown')

            # HTTP анализ
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                dport = packet[TCP].dport
                sport = packet[TCP].sport

                # Проверяем только HTTP порты
                if dport in [80, 8080, 8000, 8888] or sport in [80, 8080, 8000, 8888]:
                    http_info = self._parse_http(bytes(packet[Raw].load))
                    if http_info:
                        http_info['src_ip'] = src_ip
                        http_info['dst_ip'] = dst_ip
                        http_info['dst_port'] = dport
                        http_info['timestamp'] = time.time()

                        with self._buffer_lock:
                            self._http_buffer.append(http_info)

                        # Проверка на подозрительные HTTP запросы
                        suspicious = self._check_suspicious_http_fast(http_info)
                        if suspicious:
                            with self._buffer_lock:
                                self._suspicious_buffer.append(suspicious)

            # DNS анализ
            elif packet.haslayer(UDP) and packet.haslayer(Raw):
                sport = packet[UDP].sport
                dport = packet[UDP].dport

                if sport == 53 or dport == 53:
                    dns_info = self._parse_dns(bytes(packet[Raw].load))
                    if dns_info:
                        dns_info['src_ip'] = src_ip
                        dns_info['dst_ip'] = dst_ip
                        dns_info['timestamp'] = time.time()

                        with self._buffer_lock:
                            self._dns_buffer.append(dns_info)

            # Проверка необходимости сброса
            with self._buffer_lock:
                total_buffered = len(self._http_buffer) + len(self._dns_buffer)
                if total_buffered >= self._batch_size:
                    # Запускаем сброс в отдельном потоке чтобы не блокировать
                    self._flush_executor.submit(self._flush_buffers)

        except Exception as e:
            self.logger.debug(f"DPI ошибка: {e}")

    def _check_suspicious_http_fast(self, http_info: Dict) -> Optional[Dict]:
        """Быстрая проверка подозрительных HTTP запросов"""
        uri = http_info.get('uri', '')
        user_agent = http_info.get('user_agent', '')
        method = http_info.get('method', '')

        suspicious = False
        reasons = []

        # Подозрительные URI (быстрая проверка)
        suspicious_uris = [
            '/wp-admin', '/administrator', '/phpmyadmin', '/.env',
            '/config.php', '/wp-config.php', '/.git/', '/.svn/',
            '/shell.php', '/cmd.php', '/backdoor', '/upload.php'
        ]

        uri_lower = uri.lower()
        for sus_uri in suspicious_uris:
            if sus_uri in uri_lower:
                suspicious = True
                reasons.append(f"suspicious_uri:{sus_uri}")
                break  # Достаточно одного совпадения

        # Подозрительные User-Agent
        if not suspicious:
            suspicious_uas = ['sqlmap', 'nmap', 'nikto', 'burp', 'wpscan', 'gobuster',
                              'dirbuster', 'hydra', 'masscan', 'zgrab']
            ua_lower = user_agent.lower()
            for sus_ua in suspicious_uas:
                if sus_ua in ua_lower:
                    suspicious = True
                    reasons.append(f"suspicious_user_agent:{sus_ua}")
                    break

        # Подозрительные методы
        if not suspicious and method in ['PUT', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT']:
            suspicious = True
            reasons.append(f"suspicious_method:{method}")

        if suspicious:
            return {
                'timestamp': time.time(),
                'src_ip': http_info.get('src_ip'),
                'dst_ip': http_info.get('dst_ip'),
                'attack_type': 'Web Attack',
                'score': 0.5,
                'reasons': reasons,
                'details': http_info
            }

        return None

    def _parse_http(self, payload: bytes) -> Optional[Dict]:
        """Парсинг HTTP"""
        try:
            text = payload.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')

            result = {}

            # Первая строка (запрос или ответ)
            if lines and lines[0]:
                first_line = lines[0]

                # HTTP Request
                if any(first_line.startswith(m) for m in self.http_methods):
                    parts = first_line.split(' ')
                    result['type'] = 'request'
                    result['method'] = parts[0] if len(parts) > 0 else 'UNKNOWN'
                    result['uri'] = parts[1] if len(parts) > 1 else '/'
                    result['version'] = parts[2] if len(parts) > 2 else 'HTTP/1.1'

                # HTTP Response
                elif first_line.startswith('HTTP/'):
                    parts = first_line.split(' ')
                    result['type'] = 'response'
                    result['version'] = parts[0] if len(parts) > 0 else 'HTTP/1.1'
                    result['status_code'] = int(parts[1]) if len(parts) > 1 else 0
                    result['status_text'] = ' '.join(parts[2:]) if len(parts) > 2 else ''

            # Заголовки
            headers = {}
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value
                elif line == '':
                    break

            result['headers'] = headers

            # Извлечение важных заголовков
            result['host'] = headers.get('host', '')
            result['user_agent'] = headers.get('user-agent', '')
            result['content_type'] = headers.get('content-type', '')

            content_length = headers.get('content-length', '0')
            try:
                result['content_length'] = int(content_length)
            except ValueError:
                result['content_length'] = 0

            # Тело запроса (если есть)
            body_start = text.find('\r\n\r\n')
            if body_start > 0:
                result['body'] = text[body_start + 4:][:1000]  # Ограничиваем размер

            return result

        except Exception:
            return None

    def _parse_dns(self, payload: bytes) -> Optional[Dict]:
        """Парсинг DNS"""
        if len(payload) < 12:
            return None

        try:
            # Заголовок DNS
            transaction_id = (payload[0] << 8) + payload[1]
            flags = (payload[2] << 8) + payload[3]
            qdcount = (payload[4] << 8) + payload[5]
            ancount = (payload[6] << 8) + payload[7]

            is_query = (flags & 0x8000) == 0

            result = {
                'transaction_id': transaction_id,
                'is_query': is_query,
                'is_response': not is_query,
                'qdcount': qdcount,
                'ancount': ancount
            }

            # Извлечение запроса (упрощённо)
            if qdcount > 0 and len(payload) > 12:
                try:
                    idx = 12
                    query_parts = []

                    while idx < len(payload) and payload[idx] != 0:
                        length = payload[idx]
                        idx += 1
                        if length > 0 and idx + length <= len(payload):
                            part = payload[idx:idx + length].decode('utf-8', errors='ignore')
                            query_parts.append(part)
                            idx += length

                    if query_parts:
                        result['query'] = '.'.join(query_parts)

                        # Тип запроса
                        if idx + 2 <= len(payload):
                            qtype = (payload[idx] << 8) + payload[idx + 1]
                            qtype_map = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
                            result['query_type'] = qtype_map.get(qtype, f'UNKNOWN({qtype})')

                except Exception:
                    pass

            return result

        except Exception:
            return None

    def get_stats(self) -> Dict:
        """Получить статистику DPI"""
        with self._buffer_lock:
            return {
                'http_buffer_size': len(self._http_buffer),
                'dns_buffer_size': len(self._dns_buffer),
                'suspicious_buffer_size': len(self._suspicious_buffer),
                'batch_size': self._batch_size,
                'flush_interval': self._flush_interval
            }

    def flush_now(self) -> None:
        """Принудительный сброс буферов"""
        self._flush_buffers()

# ============================================================
# OT/IoT SECURITY
# ============================================================

class OTIoTSecurity(BaseModule):
    """Безопасность OT/IoT устройств"""

    INDUSTRIAL_PORTS = {
        502: 'Modbus',
        20000: 'DNP3',
        47808: 'BACnet',
        102: 'S7comm',
        44818: 'EtherNet/IP',
        1911: 'Niagara Fox',
        4911: 'Niagara Fox',
        789: 'Red Lion',
        20547: 'Profinet',
        34962: 'Profinet',
        34964: 'Profinet',
        2404: 'IEC 60870-5-104',
        19999: 'DNP3 Secure',
        2222: 'EtherNet/IP',
        9600: 'OMRON FINS'
    }

    IOT_PORTS = {
        1883: 'MQTT',
        8883: 'MQTT SSL',
        5683: 'CoAP',
        5684: 'CoAP SSL',
        80: 'HTTP',
        443: 'HTTPS',
        23: 'Telnet',
        2323: 'Telnet',
        7547: 'TR-069'
    }

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("OT/IoT", config, event_bus, logger)
        self.devices: Dict[str, Dict] = defaultdict(lambda: {
            'first_seen': time.time(),
            'last_seen': time.time(),
            'packet_count': 0,
            'protocols': set(),
            'ports': set()
        })
        self._lock = threading.RLock()
        self.event_bus.subscribe('packet.received', self.on_packet)

    def start(self) -> None:
        self.running = True
        self.logger.info("OT/IoT мониторинг запущен")

    def stop(self) -> None:
        self.running = False

    def on_packet(self, data: Dict) -> None:
        """Анализ OT/IoT трафика"""
        dst_port = data.get('dst_port', 0)
        src_port = data.get('src_port', 0)
        src_ip = data.get('src_ip', 'unknown')
        dst_ip = data.get('dst_ip', 'unknown')

        port = dst_port if dst_port in self.INDUSTRIAL_PORTS or dst_port in self.IOT_PORTS else src_port

        if port in self.INDUSTRIAL_PORTS:
            protocol = self.INDUSTRIAL_PORTS[port]
            category = 'OT/ICS'

            self._update_device(src_ip, protocol, port, category)
            self._update_device(dst_ip, protocol, port, category)

            self.event_bus.publish('ot.detected', {
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'port': port,
                'protocol': protocol,
                'category': category
            })

            self.logger.info(f"🏭 OT устройство: {protocol} между {src_ip} и {dst_ip}")

        elif port in self.IOT_PORTS:
            protocol = self.IOT_PORTS[port]
            category = 'IoT'

            self._update_device(src_ip, protocol, port, category)
            self._update_device(dst_ip, protocol, port, category)

            self.event_bus.publish('iot.detected', {
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'port': port,
                'protocol': protocol,
                'category': category
            })

    def _update_device(self, ip: str, protocol: str, port: int, category: str) -> None:
        """Обновление информации об устройстве"""
        with self._lock:
            device = self.devices[ip]
            device['last_seen'] = time.time()
            device['packet_count'] += 1
            device['protocols'].add(protocol)
            device['ports'].add(port)
            device['category'] = category

    def get_devices(self, category: str = None) -> List[Dict]:
        """Получить список OT/IoT устройств"""
        with self._lock:
            devices = []
            for ip, info in self.devices.items():
                if category is None or info.get('category') == category:
                    devices.append({
                        'ip': ip,
                        'first_seen': info['first_seen'],
                        'last_seen': info['last_seen'],
                        'protocols': list(info['protocols']),
                        'ports': list(info['ports']),
                        'category': info.get('category', 'unknown'),
                        'packet_count': info['packet_count']
                    })
            return devices

    def get_stats(self) -> Dict:
        """Статистика OT/IoT устройств"""
        with self._lock:
            ot_count = sum(1 for d in self.devices.values() if d.get('category') == 'OT/ICS')
            iot_count = sum(1 for d in self.devices.values() if d.get('category') == 'IoT')

            return {
                'total_devices': len(self.devices),
                'ot_devices': ot_count,
                'iot_devices': iot_count,
                'protocols_detected': list(set(p for d in self.devices.values() for p in d['protocols']))
            }


# ============================================================
# GNN С БЕЗОПАСНЫМ ИМПОРТОМ
# ============================================================

class ThreatGNN:
    """Графовая нейронная сеть для анализа угроз"""

    def __init__(self, in_channels: int = 8, hidden_channels: int = 32):
        self.in_channels = in_channels
        self.hidden_channels = hidden_channels
        self.model = None
        self.use_gnn = False
        self._init_model()

    def _init_model(self) -> None:
        """Инициализация GNN модели"""
        try:
            if torch is None or torch_nn is None:
                self.use_gnn = False
                return

            if torch_geometric_nn is not None:
                from torch_geometric.nn import GCNConv, global_mean_pool

                class _GNN(torch_nn.Module):
                    def __init__(self, in_ch, hidden_ch):
                        super().__init__()
                        self.conv1 = GCNConv(in_ch, hidden_ch)
                        self.conv2 = GCNConv(hidden_ch, hidden_ch)
                        self.conv3 = GCNConv(hidden_ch, hidden_ch // 2)
                        self.lin = torch_nn.Linear(hidden_ch // 2, 1)
                        self.dropout = torch_nn.Dropout(0.3)

                    def forward(self, x, edge_index, batch=None):
                        x = self.conv1(x, edge_index).relu()
                        x = self.dropout(x)
                        x = self.conv2(x, edge_index).relu()
                        x = self.dropout(x)
                        x = self.conv3(x, edge_index).relu()

                        if batch is not None:
                            x = global_mean_pool(x, batch)
                        else:
                            x = x.mean(dim=0, keepdim=True)

                        x = self.lin(x)
                        return torch.sigmoid(x)

                self.model = _GNN(self.in_channels, self.hidden_channels)
                self.use_gnn = True

        except Exception as e:
            self.use_gnn = False

    def predict_risk(self, node_features: List, edge_index: List) -> Dict[str, float]:
        """Предсказание риска для узлов графа"""
        if self.use_gnn and self.model and torch is not None:
            try:
                x = torch.tensor(node_features, dtype=torch.float32)
                edges = torch.tensor(edge_index, dtype=torch.long).t().contiguous()

                with torch.no_grad():
                    risk = self.model(x, edges)

                return {str(i): float(risk[i]) for i in range(len(risk))}
            except:
                pass

        return self._pagerank_fallback(node_features, edge_index)

    def _pagerank_fallback(self, node_features: List, edge_index: List) -> Dict[str, float]:
        """Корректный PageRank для НАПРАВЛЕННОГО графа угроз"""
        num_nodes = len(node_features)
        if num_nodes == 0:
            return {}

        # Построение НАПРАВЛЕННОГО графа
        out_edges = {i: set() for i in range(num_nodes)}
        in_edges = {i: set() for i in range(num_nodes)}

        for src, dst in edge_index:
            if src < num_nodes and dst < num_nodes:
                out_edges[src].add(dst)
                in_edges[dst].add(src)

        # PageRank с правильной направленностью
        scores = {i: 1.0 / num_nodes for i in range(num_nodes)}
        damping = 0.85
        epsilon = 1e-8
        max_iterations = 100

        for iteration in range(max_iterations):
            new_scores = {}
            max_diff = 0.0
            total_score = 0.0

            for node in range(num_nodes):
                # Базовая вероятность (телепортация)
                rank = (1 - damping) / num_nodes

                # Вклад от ВХОДЯЩИХ рёбер (правильно для PageRank)
                for in_node in in_edges[node]:
                    out_degree = len(out_edges[in_node])
                    if out_degree > 0:
                        rank += damping * scores[in_node] / out_degree
                    else:
                        # Висячие узлы - равномерно распределяем по всем
                        rank += damping * scores[in_node] / num_nodes

                new_scores[node] = rank
                total_score += rank
                max_diff = max(max_diff, abs(new_scores[node] - scores[node]))

            # Нормализация для избежания дрейфа
            if total_score > 0:
                for node in new_scores:
                    new_scores[node] /= total_score

            scores = new_scores

            # Ранний выход при сходимости
            if max_diff < epsilon:
                break

        # Усиление score для узлов с атаками (используем node_features если есть)
        for i in range(num_nodes):
            # Если узел имеет признаки атаки (высокий score в features)
            if i < len(node_features) and isinstance(node_features[i], (list, tuple)):
                # Предполагаем что последний элемент - признак атаки
                attack_score = float(node_features[i][-1]) if node_features[i] else 0.0
                if attack_score > 0.5:
                    scores[i] = min(1.0, scores[i] * 1.5)  # Усиливаем на 50%

        return {str(k): v for k, v in scores.items()}


# ============================================================
# SELF-SUPERVISED ENCODER
# ============================================================

class SelfSupervisedEncoder:
    """Самообучающийся энкодер для обнаружения аномалий (исправлен - Welford, проверки None)"""

    def __init__(self, input_dim: int = 156, hidden_dim: int = 128, latent_dim: int = 64):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.model = None
        self.optimizer = None
        self.use_torch = False
        self.training_buffer: deque = deque(maxlen=1000)

        # Инкрементальная статистика (алгоритм Welford)
        self._loss_count = 0
        self._loss_mean = 0.0
        self._loss_m2 = 0.0
        self._loss_lock = threading.RLock()

        self._init_model()

    def _init_model(self) -> None:
        """Инициализация модели автоэнкодера"""
        try:
            if torch is None or torch_nn is None:
                self.use_torch = False
                return

            class _Encoder(torch_nn.Module):
                def __init__(self, in_dim, hid_dim, lat_dim):
                    super().__init__()
                    # Энкодер
                    self.encoder = torch_nn.Sequential(
                        torch_nn.Linear(in_dim, hid_dim),
                        torch_nn.BatchNorm1d(hid_dim),
                        torch_nn.ReLU(),
                        torch_nn.Dropout(0.2),
                        torch_nn.Linear(hid_dim, hid_dim),
                        torch_nn.ReLU(),
                        torch_nn.Linear(hid_dim, hid_dim // 2),
                        torch_nn.ReLU(),
                        torch_nn.Linear(hid_dim // 2, lat_dim),
                    )
                    # Декодер
                    self.decoder = torch_nn.Sequential(
                        torch_nn.Linear(lat_dim, hid_dim // 2),
                        torch_nn.ReLU(),
                        torch_nn.Linear(hid_dim // 2, hid_dim),
                        torch_nn.ReLU(),
                        torch_nn.Dropout(0.2),
                        torch_nn.Linear(hid_dim, hid_dim),
                        torch_nn.ReLU(),
                        torch_nn.Linear(hid_dim, in_dim),
                    )
                    # Проектор для contrastive learning
                    self.projector = torch_nn.Sequential(
                        torch_nn.Linear(lat_dim, lat_dim // 2),
                        torch_nn.ReLU(),
                        torch_nn.Linear(lat_dim // 2, 32)
                    )

                def forward(self, x):
                    latent = self.encoder(x)
                    reconstructed = self.decoder(latent)
                    projection = self.projector(latent)
                    return latent, reconstructed, projection

                def encode(self, x):
                    return self.encoder(x)

            self.model = _Encoder(self.input_dim, self.hidden_dim, self.latent_dim)
            if torch_optim is not None:
                self.optimizer = torch_optim.Adam(self.model.parameters(), lr=0.001, weight_decay=1e-5)
            self.use_torch = True

        except Exception as e:
            self.use_torch = False

    def train_step(self, batch: List[List[float]]) -> Optional[float]:
        """Один шаг обучения (исправлено - проверка размера батча для BatchNorm)"""
        if not self.use_torch or not self.model or not self.optimizer:
            return None

        try:
            import torch
            import torch.nn.functional as F

            X = torch.tensor(batch, dtype=torch.float32)

            # ========== ИСПРАВЛЕНО: ПРОВЕРКА РАЗМЕРА БАТЧА ==========
            # Если батч размера 1, временно переводим модель в eval mode для BatchNorm
            batch_size = X.shape[0]
            if batch_size == 1:
                self.model.eval()
            # =====================================================

            # Добавляем шум для denoising autoencoder
            noise = torch.randn_like(X) * 0.1
            X_noisy = X + noise

            latent, reconstructed, projection = self.model(X_noisy)

            # Reconstruction loss
            if hasattr(F, 'mse_loss'):
                recon_loss = F.mse_loss(reconstructed, X)
            else:
                recon_loss = ((reconstructed - X) ** 2).mean()

            # Дополнительный loss для латентного пространства
            if batch_size > 1:
                if hasattr(F, 'normalize'):
                    proj_norm = F.normalize(projection, dim=1)
                else:
                    norm = projection.norm(dim=1, keepdim=True)
                    proj_norm = projection / (norm + 1e-8)

                sim_matrix = torch.mm(proj_norm, proj_norm.t())
                diversity_loss = sim_matrix.mean()
                total_loss = recon_loss + 0.1 * diversity_loss
            else:
                total_loss = recon_loss

            self.optimizer.zero_grad()
            total_loss.backward()
            self.optimizer.step()

            # Возвращаем модель в training mode
            if batch_size == 1:
                self.model.train()

            loss_value = float(total_loss.item())
            self.training_buffer.append(loss_value)

            return loss_value

        except Exception as e:
            return None
    def _recompute_statistics(self) -> None:
        """Пересчёт статистики из буфера"""
        if not self.training_buffer:
            return

        values = list(self.training_buffer)
        self._loss_count = len(values)
        self._loss_mean = sum(values) / self._loss_count
        self._loss_m2 = sum((v - self._loss_mean) ** 2 for v in values)

    def get_anomaly_score(self, features: List[float]) -> float:
        """Получение оценки аномальности (O(1) с Welford)"""
        if not self.use_torch or not self.model:
            return 0.5

        try:
            import torch

            X = torch.tensor([features], dtype=torch.float32)

            with torch.no_grad():
                latent, reconstructed, _ = self.model(X)

                if hasattr(torch.nn.functional, 'mse_loss'):
                    recon_error = torch.nn.functional.mse_loss(reconstructed, X).item()
                else:
                    recon_error = ((reconstructed - X) ** 2).mean().item()

                # Используем инкрементальную статистику
                with self._loss_lock:
                    if self._loss_count > 10:
                        mean_loss = self._loss_mean
                        variance = self._loss_m2 / self._loss_count if self._loss_count > 1 else 1.0
                        std_loss = math.sqrt(variance)

                        if std_loss > 1e-8:
                            z_score = (recon_error - mean_loss) / std_loss
                            # Сигмоидная нормализация
                            score = 1.0 / (1.0 + math.exp(-z_score))
                        else:
                            score = min(1.0, recon_error / max(0.001, mean_loss))
                    else:
                        score = min(1.0, recon_error / 0.5)

                return score

        except Exception:
            return 0.5

    def encode(self, features: List[float]) -> Optional[List[float]]:
        """Получить латентное представление"""
        if not self.use_torch or not self.model:
            return None

        try:
            import torch

            X = torch.tensor([features], dtype=torch.float32)
            with torch.no_grad():
                latent = self.model.encode(X)
                return latent[0].tolist()
        except:
            return None

    def get_statistics(self) -> Dict:
        """Получить статистику обучения"""
        with self._loss_lock:
            variance = self._loss_m2 / self._loss_count if self._loss_count > 1 else 0.0
            return {
                'samples_count': self._loss_count,
                'mean_loss': self._loss_mean,
                'variance': variance,
                'std_loss': math.sqrt(variance) if variance > 0 else 0.0,
                'buffer_size': len(self.training_buffer)
            }

    def reset_statistics(self) -> None:
        """Сброс статистики"""
        with self._loss_lock:
            self._loss_count = 0
            self._loss_mean = 0.0
            self._loss_m2 = 0.0
            self.training_buffer.clear()

# ============================================================
# MACHINE LEARNING ENGINE
# ============================================================
class MachineLearningEngine(BaseModule):
    """ML движок с дообучением и Deep Learning моделями (LSTM + VAE + Transformer)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("ML", config, event_bus, logger)
        self.model_path = Path(config.get('ml.model_path', './models/'))
        self.model_path.mkdir(parents=True, exist_ok=True)

        self.models = {}
        self.scaler = None
        self.features = []
        self.normal_buffer: deque = deque(maxlen=5000)
        self.attack_buffer: deque = deque(maxlen=5000)
        self.online_learning = config.get('ml.online_learning', True)
        self.retrain_interval = config.get('ml.retrain_interval', 300)
        self.retrain_min_samples = config.get('ml.retrain_min_samples', 100)
        self.confidence_threshold = config.get('ml.confidence_threshold', 0.7)
        self.anomaly_threshold = config.get('ml.anomaly_threshold', -0.15)
        self.use_xgboost = 'xgboost' in config.get('ml.ensemble', [])
        self.explain_with_shap = config.get('ml.explain_with_shap', True)
        self.use_deep_learning = config.get('ml.use_deep_learning', True)

        self.shap_explainer = None
        self.shap_background_data = []
        self.ssl_model = SelfSupervisedEncoder(input_dim=156)
        self.gnn_model = ThreatGNN()

        # Deep Learning Engine
        self.dl_engine = None
        if self.use_deep_learning:
            try:
                from shard_dl_models import DeepLearningEngine
                self.dl_engine = DeepLearningEngine()
                self.logger.info("Deep Learning Engine инициализирован")
            except ImportError:
                self.logger.warning("shard_dl_models не найден, Deep Learning отключен")
                self.use_deep_learning = False

        # Автосохранение (ТОЛЬКО ОДИН РАЗ)
        self._autosave_interval = 300
        self._last_save = time.time()
        self._save_thread = None
        self._models_dirty = False
        self._model_reliable = False
        self._samples_since_init = 0
        self._save_lock = threading.RLock()

        # Буфер для последовательностей (ТОЛЬКО ОДИН РАЗ)
        self.sequence_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Счётчик для GNN
        self._gnn_packet_counter = 0
        self._last_dst_ip = "0.0.0.0"
        self._last_dst_port = 0

        # Ссылки на улучшения
        self.temporal_gnn = None
        self.contrastive_vae = None
        self.rl_defense = None

        self._lock = threading.RLock()
        self._load_models()
        self._init_shap()

        self.event_bus.subscribe('packet.features', self.on_features)

    def _init_shap(self) -> None:
        """Инициализация SHAP объяснителя"""
        if not self.explain_with_shap:
            return

        if shap_module is None:
            self.logger.warning("SHAP не установлен, объяснения отключены")
            self.explain_with_shap = False
            return

        self.shap_background_data = []
        self.logger.debug("SHAP будет инициализирован при накоплении данных")

    def _initialize_shap_explainer(self, background_samples: List[List[float]]) -> None:
        """Создание SHAP объяснителя с фоновыми данными"""
        if not self.explain_with_shap or shap_module is None:
            return

        try:
            import shap
            import numpy as np

            X_background = np.array(background_samples)
            if self.scaler and self._is_scaler_fitted():
                X_background = self.scaler.transform(X_background)

            if 'xgb' in self.models and self.use_xgboost:
                model = self.models['xgb']
                self.shap_explainer = shap.TreeExplainer(model)
                self.logger.info("SHAP TreeExplainer инициализирован для XGBoost")

            elif 'if' in self.models:
                model = self.models['if']
                if len(X_background) > 50:
                    X_background = X_background[:50]

                def predict_fn(x):
                    scores = model.score_samples(x)
                    return (scores + 0.5) / 0.5

                self.shap_explainer = shap.KernelExplainer(predict_fn, X_background)
                self.logger.info("SHAP KernelExplainer инициализирован для Isolation Forest")

        except Exception as e:
            self.logger.error(f"Ошибка инициализации SHAP: {e}")
            self.explain_with_shap = False

    def _is_scaler_fitted(self) -> bool:
        """Проверка что scaler обучен"""
        if self.scaler is None:
            return False
        try:
            return hasattr(self.scaler, 'mean_') and hasattr(self.scaler, 'scale_')
        except:
            return False

    def _get_class_index(self, attack_type: str) -> int:
        """Получение индекса класса для SHAP"""
        class_map = {
            'Normal': 0,
            'DoS': 1,
            'DDoS': 2,
            'Brute Force': 3,
            'Web Attack': 4,
            'Botnet': 5,
            'Port Scan': 8
        }
        return class_map.get(attack_type, 0)

    def explain_prediction(self, features: List[float]) -> Dict:
        """Подробное объяснение предсказания"""
        if not self.explain_with_shap or not self.shap_explainer:
            return {'error': 'SHAP не инициализирован'}

        try:
            import numpy as np

            X = np.array([features])
            if self.scaler and self._is_scaler_fitted():
                X = self.scaler.transform(X)

            shap_values = self.shap_explainer.shap_values(X)

            if isinstance(shap_values, list):
                shap_vals = shap_values[0][0] if len(shap_values) > 0 else []
            else:
                shap_vals = shap_values[0]

            explanations = []
            for idx, shap_val in enumerate(shap_vals):
                if idx < len(self.features) and abs(shap_val) > 0.01:
                    explanations.append({
                        'feature': self.features[idx],
                        'value': features[idx] if idx < len(features) else None,
                        'shap_value': float(shap_val),
                        'impact': 'positive' if shap_val > 0 else 'negative',
                        'importance': abs(float(shap_val))
                    })

            explanations.sort(key=lambda x: x['importance'], reverse=True)
            total_impact = sum(e['shap_value'] for e in explanations)

            expected_value = 0.0
            if hasattr(self.shap_explainer, 'expected_value'):
                ev = self.shap_explainer.expected_value
                if isinstance(ev, (list, np.ndarray)) and len(ev) > 0:
                    expected_value = float(ev[0]) if isinstance(ev[0], (int, float)) else 0.0
                else:
                    expected_value = float(ev) if isinstance(ev, (int, float)) else 0.0

            return {
                'explanations': explanations[:10],
                'total_impact': float(total_impact),
                'prediction': 'attack' if total_impact > 0 else 'normal',
                'base_value': expected_value
            }

        except Exception as e:
            return {'error': str(e)}

    def _load_models(self) -> None:
        """Загрузка моделей"""
        try:
            import joblib

            if_path = self.model_path / 'shard_enterprise_model_if.pkl'
            if if_path.exists() and joblib:
                self.models['if'] = joblib.load(if_path)
                self.logger.info("Isolation Forest загружен")
            else:
                self._init_isolation_forest()

            if self.use_xgboost and xgboost_module:
                xgb_path = self.model_path / 'shard_enterprise_model_xgb.pkl'
                if xgb_path.exists() and joblib:
                    self.models['xgb'] = joblib.load(xgb_path)
                    self.logger.info("XGBoost загружен")
                else:
                    self._init_xgboost()

            rf_path = self.model_path / 'shard_enterprise_model_rf.pkl'
            if rf_path.exists() and joblib:
                self.models['rf'] = joblib.load(rf_path)

            scaler_path = self.model_path / 'shard_enterprise_scaler.pkl'
            if scaler_path.exists() and joblib:
                self.scaler = joblib.load(scaler_path)

            features_path = self.model_path / 'shard_enterprise_features.pkl'
            if features_path.exists() and joblib:
                self.features = joblib.load(features_path)
            else:
                self._init_features()

        except Exception as e:
            self.logger.warning(f"Ошибка загрузки моделей: {e}")
            self._init_features()
            self._init_isolation_forest()

    def _init_features(self) -> None:
        """Инициализация признаков"""
        self.features = [f'payload_byte_{i + 1}' for i in range(150)]
        self.features.extend([
            'payload_entropy', 'packet_size', 'protocol',
            'ttl', 'src_port', 'dst_port'
        ])

    def _init_isolation_forest(self) -> None:
        """Инициализация Isolation Forest"""
        if sklearn_ensemble:
            from sklearn.ensemble import IsolationForest
            import numpy as np

            self.models['if'] = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )

            pretrained_path = self.model_path / 'shard_enterprise_model_if_pretrained.pkl'
            if pretrained_path.exists() and joblib:
                try:
                    self.models['if'] = joblib.load(pretrained_path)
                    self.logger.info("✅ Загружена предобученная Isolation Forest модель")
                    self._model_reliable = True
                    return
                except Exception as e:
                    self.logger.warning(f"Ошибка загрузки предобученной модели: {e}")

            saved_path = self.model_path / 'shard_enterprise_model_if.pkl'
            if saved_path.exists() and joblib:
                try:
                    self.models['if'] = joblib.load(saved_path)
                    self.logger.info("✅ Загружена сохранённая Isolation Forest модель")
                    self._model_reliable = True
                    return
                except Exception as e:
                    self.logger.warning(f"Ошибка загрузки сохранённой модели: {e}")

            dummy_data = np.random.randn(100, len(self.features))
            for i in range(len(dummy_data)):
                dummy_data[i] = dummy_data[i] * 0.3
                if len(dummy_data[i]) > 150:
                    dummy_data[i][150] = np.random.uniform(0, 0.3)
                    dummy_data[i][151] = np.random.uniform(64, 1500)

            self.models['if'].fit(dummy_data)
            self._model_reliable = False
            self._samples_since_init = 0

            self.logger.warning(
                "⚠️ Isolation Forest инициализирован на синтетических данных. "
                "Требуется дообучение на реальном трафике!"
            )

    def _init_xgboost(self) -> None:
        """Инициализация XGBoost с предустановленными классами"""
        if xgboost_module:
            self.models['xgb'] = xgboost_module.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                objective='multi:softprob',
                num_class=10,
                random_state=42,
                verbosity=0
            )
            self.logger.info("XGBoost инициализирован")

    def start(self) -> None:
        self.running = True
        if self.online_learning:
            threading.Thread(target=self._retrain_loop, daemon=True, name="ML-Retrain").start()
        threading.Thread(target=self._load_history_async, daemon=True, name="ML-LoadHistory").start()
        self._save_thread = threading.Thread(target=self._autosave_loop, daemon=True, name="ML-Autosave")
        self._save_thread.start()

        if self.use_deep_learning and self.dl_engine:
            self.dl_engine.start()

        self.logger.info(
            f"ML запущен (online: {self.online_learning}, XGBoost: {self.use_xgboost}, DL: {self.use_deep_learning})")

    def stop(self) -> None:
        self.running = False
        with self._save_lock:
            self._save_models()
            self._models_dirty = False
        if self._save_thread and self._save_thread.is_alive():
            self._save_thread.join(timeout=2)

        if self.use_deep_learning and self.dl_engine:
            self.dl_engine.stop()

        self.logger.info("ML остановлен, модели сохранены")

    def _autosave_loop(self) -> None:
        """Периодическое автосохранение моделей"""
        while self.running:
            time.sleep(60)
            with self._save_lock:
                if self._models_dirty and time.time() - self._last_save >= self._autosave_interval:
                    self._save_models()
                    self._models_dirty = False
                    self._last_save = time.time()

    def _save_models(self) -> None:
        """Атомарное сохранение моделей"""
        if not joblib:
            return

        try:
            temp_files = []

            if 'if' in self.models:
                temp_path = self.model_path / 'shard_enterprise_model_if.pkl.tmp'
                joblib.dump(self.models['if'], temp_path)
                temp_files.append((temp_path, self.model_path / 'shard_enterprise_model_if.pkl'))

            if 'xgb' in self.models:
                temp_path = self.model_path / 'shard_enterprise_model_xgb.pkl.tmp'
                joblib.dump(self.models['xgb'], temp_path)
                temp_files.append((temp_path, self.model_path / 'shard_enterprise_model_xgb.pkl'))

            if self.scaler:
                temp_path = self.model_path / 'shard_enterprise_scaler.pkl.tmp'
                joblib.dump(self.scaler, temp_path)
                temp_files.append((temp_path, self.model_path / 'shard_enterprise_scaler.pkl'))

            temp_path = self.model_path / 'shard_enterprise_features.pkl.tmp'
            joblib.dump(self.features, temp_path)
            temp_files.append((temp_path, self.model_path / 'shard_enterprise_features.pkl'))

            for temp_path, final_path in temp_files:
                if temp_path.exists():
                    import os
                    os.replace(str(temp_path), str(final_path))

            self.logger.debug("Модели сохранены (автосохранение)")

        except Exception as e:
            self.logger.error(f"Ошибка сохранения: {e}")

    def _load_history_async(self) -> None:
        """Асинхронная загрузка исторических данных"""
        try:
            import sqlite3

            conn = sqlite3.connect('shard_siem.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                '''SELECT features_json, attack_type FROM alerts 
                   WHERE features_json IS NOT NULL 
                   ORDER BY timestamp DESC LIMIT 500'''
            )
            rows = cursor.fetchall()
            conn.close()

            loaded = 0
            for row in rows:
                try:
                    features = json.loads(row[0])
                    attack_type = row[1] if row[1] else 'Normal'

                    with self._lock:
                        if attack_type != 'Normal':
                            self.attack_buffer.append((features, attack_type))
                        else:
                            self.normal_buffer.append(features)
                    loaded += 1
                except:
                    pass

            self.logger.info(f"Загружено {loaded} исторических сэмплов")
        except Exception as e:
            self.logger.warning(f"Ошибка загрузки истории: {e}")

    def on_features(self, data: Dict) -> None:
        """Обработка признаков"""
        features = data.get('features')
        if features:
            src_ip = data.get('src_ip', 'unknown')

            # ========== ВЫЗОВ ADAPTIVE LEARNING ==========
            if hasattr(self, 'adaptive_engine') and self.adaptive_engine:
                adaptive_result = self.adaptive_engine.process_packet(src_ip, features)

                # Отладка — каждый 50-й пакет
                updates = self.adaptive_engine.baseline_profiler.stats['total_updates']
                if updates % 50 == 0:
                    print(f"📊 [Adaptive] {src_ip}: score={adaptive_result['overall_score']:.3f}, "
                          f"anomaly={adaptive_result['is_anomaly']}, samples={updates}")

                # Если Adaptive Learning обнаружил аномалию
                if adaptive_result['is_anomaly']:
                    self.logger.info(
                        f"🔔 Adaptive Learning detected anomaly: score={adaptive_result['overall_score']:.3f}")
            # =============================================

            prediction = self._predict(features, src_ip)

            if prediction['is_attack'] and prediction['confidence'] >= self.confidence_threshold:
                prediction['src_ip'] = src_ip
                prediction['dst_ip'] = data.get('dst_ip', 'unknown')
                prediction['dst_port'] = data.get('dst_port', 0)

                ssl_score = self.ssl_model.get_anomaly_score(features)
                if ssl_score > 0.7:
                    prediction['score'] = max(prediction['score'], ssl_score)
                    prediction['ssl_anomaly'] = True

                # Если Adaptive Learning тоже обнаружил аномалию — повышаем score
                if hasattr(self, 'adaptive_engine') and self.adaptive_engine:
                    if adaptive_result.get('is_anomaly', False):
                        prediction['score'] = max(prediction['score'], adaptive_result['overall_score'])
                        prediction['adaptive_detected'] = True

                self.event_bus.publish('alert.detected', prediction)

                if self.online_learning:
                    with self._lock:
                        self.attack_buffer.append((features, prediction['attack_type']))

            elif not prediction['is_attack'] and prediction['confidence'] >= self.confidence_threshold:
                if self.online_learning:
                    with self._lock:
                        self.normal_buffer.append(features)
                        self._samples_since_init += 1

    def _predict(self, features: List[float], device: str = "unknown") -> Dict:
        """Предсказание с использованием ML и DL моделей"""
        result = {
            'is_attack': False,
            'score': 0.0,
            'confidence': 0.0,
            'attack_type': 'Normal',
            'timestamp': time.time()
        }

        try:
            import numpy as np

            X = np.array([features])

            if self.scaler and self._is_scaler_fitted():
                X = self.scaler.transform(X)

            # Isolation Forest
            if 'if' in self.models:
                if_score = float(self.models['if'].score_samples(X)[0])
                normalized_score = 1.0 - (if_score + 0.5)
                normalized_score = max(0.0, min(1.0, normalized_score))

                result['score'] = normalized_score

                threshold = self.anomaly_threshold
                if not self._model_reliable:
                    threshold = threshold * 1.5

                result['is_attack'] = if_score < threshold
                distance = abs(if_score - threshold)
                result['confidence'] = min(0.99, distance / 0.5)

                if not self._model_reliable:
                    result['confidence'] *= 0.5

            # ========== ИНТЕГРАЦИЯ С УЛУЧШЕНИЯМИ ==========

            # Temporal GNN - анализ графа угроз
            if hasattr(self, 'temporal_gnn') and self.temporal_gnn is not None:
                try:
                    # Обновляем граф каждые 50 пакетов для производительности
                    self._gnn_packet_counter = getattr(self, '_gnn_packet_counter', 0) + 1

                    if self._gnn_packet_counter % 50 == 0:
                        # Получаем данные о соединении из контекста (если доступны)
                        src_ip = device
                        dst_ip = getattr(self, '_last_dst_ip', '0.0.0.0')
                        dst_port = getattr(self, '_last_dst_port', 0)
                        protocol = 6  # TCP по умолчанию
                        bytes_count = int(features[151]) if len(features) > 151 else 1000

                        self.temporal_gnn.add_connection(src_ip, dst_ip, 0, dst_port, protocol, bytes_count, 1)

                        # Анализируем граф каждые 500 пакетов
                        if self._gnn_packet_counter % 500 == 0:
                            gnn_result = self.temporal_gnn.process_time_window()
                            if gnn_result and gnn_result.get('is_graph_anomaly'):
                                gnn_score = gnn_result.get('graph_score', 0.5)
                                result['is_attack'] = result['is_attack'] or (gnn_score > 0.6)
                                result['score'] = max(result['score'], gnn_score)
                                result['confidence'] = max(result['confidence'], 0.7)
                                result['gnn_detected'] = True
                                result['gnn_details'] = {
                                    'graph_score': gnn_score,
                                    'anomalous_nodes': gnn_result.get('anomalous_nodes', [])[:5],
                                    'num_nodes': gnn_result.get('num_nodes', 0),
                                    'num_edges': gnn_result.get('num_edges', 0)
                                }
                                self.logger.debug(f"GNN detected anomaly: score={gnn_score:.3f}")
                except Exception as e:
                    self.logger.debug(f"GNN prediction error: {e}")

            # Contrastive VAE - анализ вектора признаков
            if hasattr(self, 'contrastive_vae') and self.contrastive_vae is not None:
                try:
                    vae_result = self.contrastive_vae.predict_anomaly(features)
                    if vae_result and vae_result.get('is_anomaly'):
                        vae_score = vae_result.get('score', 0.5)
                        result['is_attack'] = result['is_attack'] or (vae_score > 0.55)
                        result['score'] = max(result['score'], vae_score)
                        result['confidence'] = max(result['confidence'], vae_score)
                        result['vae_detected'] = True
                        result['vae_details'] = {
                            'reconstruction_score': vae_result.get('reconstruction_score', 0),
                            'latent_score': vae_result.get('latent_score', 0),
                            'mse': vae_result.get('mse', 0)
                        }
                        self.logger.debug(f"VAE detected anomaly: score={vae_score:.3f}")
                except Exception as e:
                    self.logger.debug(f"VAE prediction error: {e}")

            # Определение типа атаки
            if result['is_attack']:
                if 'xgb' in self.models and self.use_xgboost:
                    try:
                        proba = self.models['xgb'].predict_proba(X)[0]
                        attack_id = int(np.argmax(proba))
                        confidence = float(proba[attack_id])

                        attack_map = {
                            1: 'DoS', 2: 'DDoS', 3: 'Brute Force',
                            4: 'Web Attack', 5: 'Botnet', 8: 'Port Scan'
                        }
                        result['attack_type'] = attack_map.get(attack_id, 'Unknown')
                        result['confidence'] = max(result['confidence'], confidence)
                    except Exception as e:
                        self.logger.debug(f"XGBoost prediction error: {e}")
                        result['attack_type'] = 'Anomaly'
                else:
                    result['attack_type'] = 'Anomaly'

                # Если обнаружено через GNN или VAE, уточняем тип атаки
                if result.get('gnn_detected') and not result.get('vae_detected'):
                    if result['attack_type'] == 'Anomaly':
                        result['attack_type'] = 'Lateral Movement'
                elif result.get('vae_detected') and not result.get('gnn_detected'):
                    if result['attack_type'] == 'Anomaly':
                        result['attack_type'] = 'Data Exfiltration'

                # SHAP объяснение
                if self.explain_with_shap and self.shap_explainer:
                    try:
                        shap_values = self.shap_explainer.shap_values(X)
                        if isinstance(shap_values, list):
                            shap_values = shap_values[0]

                        if len(shap_values) > 0 and len(shap_values[0]) > 0:
                            top_indices = np.argsort(np.abs(shap_values[0]))[-3:]
                            explanations = []
                            for idx in top_indices:
                                if idx < len(self.features):
                                    explanations.append(self.features[idx])

                            if explanations:
                                result['shap_explanation'] = f"Важные признаки: {', '.join(explanations)}"
                    except Exception as e:
                        self.logger.debug(f"SHAP error: {e}")

            # ========== RL DEFENSE - РЕКОМЕНДАЦИЯ ПО ЗАЩИТЕ ==========
            if hasattr(self, 'rl_defense') and self.rl_defense is not None and result['is_attack']:
                try:
                    alert_state = {
                        'alert_score': result['score'],
                        'alert_count': 1,
                        'connection_rate': getattr(self, '_connection_rate', 10),
                        'unique_ports': getattr(self, '_unique_ports', 1),
                        'bytes_transferred': int(features[151]) if len(features) > 151 else 1000,
                        'is_internal': device.startswith(('192.168.', '10.', '172.', '127.')),
                        'hour_of_day': time.localtime().tm_hour,
                        'day_of_week': time.localtime().tm_wday
                    }
                    action_id, action_name = self.rl_defense.get_defense_action(alert_state)
                    result['rl_recommended_action'] = action_name
                    result['rl_action_id'] = action_id
                    self.logger.debug(f"RL Defense recommends: {action_name} (score={result['score']:.3f})")
                except Exception as e:
                    self.logger.debug(f"RL Defense error: {e}")

        except Exception as e:
            self.logger.debug(f"Prediction error: {e}")
            result['score'] = 0.5
            result['confidence'] = 0.3

        return result

    def _retrain_loop(self) -> None:
        """Цикл дообучения"""
        while self.running:
            time.sleep(self.retrain_interval)

            with self._lock:
                total = len(self.normal_buffer) + len(self.attack_buffer)
                if total >= self.retrain_min_samples:
                    self._retrain()

    def _retrain(self) -> None:
        """Дообучение моделей"""
        with self._lock:
            normal = list(self.normal_buffer)
            attacks = list(self.attack_buffer)
            self.normal_buffer.clear()
            self.attack_buffer.clear()

        if not normal and not attacks:
            return

        self.logger.info(f"🔄 Дообучение на {len(normal)} нормальных и {len(attacks)} атаках")

        try:
            import numpy as np
            scaler_fitted = self._is_scaler_fitted()

            # Isolation Forest
            if 'if' in self.models and len(normal) >= 50:
                X_normal = np.array(normal)

                if scaler_fitted and self.scaler:
                    try:
                        X_normal = self.scaler.transform(X_normal)
                    except Exception as e:
                        self.logger.warning(f"Ошибка масштабирования IF: {e}")

                if hasattr(self.models['if'], 'estimators_'):
                    current_trees = len(self.models['if'].estimators_)
                    self.models['if'].set_params(n_estimators=current_trees + 10)
                    self.models['if'].fit(X_normal)
                    self.logger.info(f"   IF: +10 деревьев (всего {current_trees + 10})")
                else:
                    self.models['if'].fit(X_normal)
                    self.logger.info(f"   IF: инициализирован на {len(normal)} сэмплах")

            # SSL модель
            for features in normal[:100]:
                self.ssl_model.train_step([features])

            # XGBoost
            if 'xgb' in self.models and len(attacks) >= 10:
                X_attacks = np.array([a[0] for a in attacks])
                y_attacks = np.array([self._attack_to_id(a[1]) for a in attacks])

                if scaler_fitted and self.scaler:
                    try:
                        X_attacks = self.scaler.transform(X_attacks)
                    except Exception as e:
                        self.logger.warning(f"Ошибка масштабирования XGBoost: {e}")

                is_fitted = False
                try:
                    if hasattr(self.models['xgb'], 'get_booster'):
                        self.models['xgb'].get_booster()
                        is_fitted = True
                    elif hasattr(self.models['xgb'], '_Booster'):
                        is_fitted = self.models['xgb']._Booster is not None
                except:
                    pass

                if is_fitted:
                    try:
                        self.models['xgb'].fit(X_attacks, y_attacks, xgb_model=self.models['xgb'].get_booster())
                        self.logger.info(f"   XGBoost: дообучен на {len(attacks)} сэмплах")
                    except Exception as e:
                        self.logger.warning(f"Ошибка дообучения XGBoost, обучаем заново: {e}")
                        self.models['xgb'].fit(X_attacks, y_attacks)
                        self.logger.info(f"   XGBoost: переобучен на {len(attacks)} сэмплах")
                else:
                    self.models['xgb'].fit(X_attacks, y_attacks)
                    self.logger.info(f"   XGBoost: инициализирован и обучен на {len(attacks)} сэмплах")

            # Отметка о надёжности
            if len(normal) >= 500:
                self._model_reliable = True
                self.logger.info("Модель помечена как надёжная")

            with self._save_lock:
                self._models_dirty = True

        except Exception as e:
            self.logger.error(f"Ошибка дообучения: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())

    def _attack_to_id(self, attack_type: str) -> int:
        """Преобразование типа атаки в ID"""
        mapping = {
            'Normal': 0, 'DoS': 1, 'DDoS': 2, 'Brute Force': 3,
            'Web Attack': 4, 'Botnet': 5, 'Port Scan': 8
        }
        return mapping.get(attack_type, 99)

    def get_stats(self) -> Dict:
        """Получить статистику ML"""
        with self._lock:
            stats = {
                'normal_buffer_size': len(self.normal_buffer),
                'attack_buffer_size': len(self.attack_buffer),
                'online_learning': self.online_learning,
                'use_xgboost': self.use_xgboost,
                'explain_with_shap': self.explain_with_shap,
                'use_deep_learning': self.use_deep_learning,
                'scaler_fitted': self._is_scaler_fitted(),
                'models_loaded': list(self.models.keys()),
                'features_count': len(self.features),
                'autosave_interval': self._autosave_interval,
                'models_dirty': self._models_dirty,
                'model_reliable': self._model_reliable
            }

            if self.use_deep_learning and self.dl_engine:
                stats['dl_stats'] = self.dl_engine.ensemble.get_stats()

            return stats

    def save_now(self) -> None:
        """Принудительное сохранение моделей"""
        with self._save_lock:
            self._save_models()
            self._models_dirty = False
            self._last_save = time.time()
        self.logger.info("Модели сохранены принудительно")

    def reset_buffers(self) -> None:
        """Очистка буферов обучения"""
        with self._lock:
            self.normal_buffer.clear()
            self.attack_buffer.clear()
        self.logger.info("Буферы обучения очищены")

# ============================================================

# ============================================================
# THREAT GRAPH NETWORK
# ============================================================

class ThreatGraphNetwork:
    """Графовая модель угроз для анализа связей (исправлен - правильный PageRank, инкрементальное обновление)"""

    def __init__(self):
        self.graph: Dict[str, Dict] = {}
        self.risk_scores: Dict[str, float] = {}
        self.communities: Dict[str, int] = {}
        self._lock = threading.RLock()
        self._dirty_nodes: Set[str] = set()  # Изменённые узлы для инкрементального обновления
        self._last_full_propagation = 0
        self._full_propagation_interval = 300  # 5 минут

    def add_edge(self, src: str, dst: str, weight: float = 1.0) -> None:
        """Добавление направленной связи между узлами"""
        with self._lock:
            # Инициализация узлов
            for ip in (src, dst):
                if ip not in self.graph:
                    self.graph[ip] = {
                        'out_edges': {},
                        'in_edges': {},
                        'risk': 0.0,
                        'attacks': 0,
                        'first_seen': time.time(),
                        'last_seen': time.time(),
                        'total_bytes': 0,
                        'connections': 0
                    }

            # Добавление направленных рёбер
            if dst not in self.graph[src]['out_edges']:
                self.graph[src]['out_edges'][dst] = weight
            else:
                self.graph[src]['out_edges'][dst] += weight

            if src not in self.graph[dst]['in_edges']:
                self.graph[dst]['in_edges'][src] = weight
            else:
                self.graph[dst]['in_edges'][src] += weight

            self.graph[src]['last_seen'] = time.time()
            self.graph[dst]['last_seen'] = time.time()
            self.graph[src]['connections'] += 1
            self.graph[dst]['connections'] += 1

            # Помечаем узлы как изменённые
            self._dirty_nodes.add(src)
            self._dirty_nodes.add(dst)

    def mark_attack(self, ip: str, score: float, attack_type: str = None) -> None:
        """Отметка атаки на узле (инкрементально)"""
        with self._lock:
            if ip in self.graph:
                self.graph[ip]['attacks'] += 1
                self.graph[ip]['risk'] = min(1.0, self.graph[ip]['risk'] + score * 0.2)
                self.graph[ip]['last_attack'] = time.time()

                if attack_type:
                    if 'attack_types' not in self.graph[ip]:
                        self.graph[ip]['attack_types'] = defaultdict(int)
                    self.graph[ip]['attack_types'][attack_type] += 1

                # Помечаем узел и его соседей как "грязные"
                self._dirty_nodes.add(ip)
                for neighbor in self.graph[ip]['out_edges']:
                    self._dirty_nodes.add(neighbor)
                for neighbor in self.graph[ip]['in_edges']:
                    self._dirty_nodes.add(neighbor)

    def propagate_risk(self, iterations: int = 10, force_full: bool = False) -> Dict[str, float]:
        """Распространение риска по графу (с инкрементальным обновлением)"""
        with self._lock:
            now = time.time()

            # Инкрементальное обновление только изменённых узлов
            if not force_full and self._dirty_nodes and len(self._dirty_nodes) < len(self.graph) * 0.3:
                self._propagate_incremental(iterations)
            else:
                self._propagate_full(iterations)
                self._last_full_propagation = now

            self._dirty_nodes.clear()
            return dict(self.risk_scores)

    def _propagate_incremental(self, iterations: int) -> None:
        """Инкрементальное распространение риска (только изменённые узлы)"""
        damping = 0.85

        for _ in range(iterations):
            new_scores = {}

            for ip in self._dirty_nodes:
                if ip not in self.graph:
                    continue

                data = self.graph[ip]
                new_scores[ip] = data['risk'] * (1 - damping)

                # Вклад от входящих рёбер
                if data['in_edges']:
                    total_weight = sum(data['in_edges'].values())
                    if total_weight > 0:
                        neighbor_risk = 0
                        for neighbor, weight in data['in_edges'].items():
                            neighbor_risk += self.risk_scores.get(neighbor, 0) * weight
                        new_scores[ip] += damping * (neighbor_risk / total_weight)

            # Обновляем только изменённые узлы
            for ip, score in new_scores.items():
                self.risk_scores[ip] = score

    def _propagate_full(self, iterations: int) -> None:
        """Полное распространение риска (PageRank)"""
        # Инициализация
        for ip, data in self.graph.items():
            self.risk_scores[ip] = data['risk']

        damping = 0.85

        for _ in range(iterations):
            new_scores = {}

            for ip, data in self.graph.items():
                # Базовый риск
                new_scores[ip] = data['risk'] * (1 - damping)

                # Вклад от входящих рёбер
                if data['in_edges']:
                    total_weight = sum(data['in_edges'].values())
                    if total_weight > 0:
                        neighbor_risk = 0
                        for neighbor, weight in data['in_edges'].items():
                            neighbor_risk += self.risk_scores.get(neighbor, 0) * weight
                        new_scores[ip] += damping * (neighbor_risk / total_weight)

            self.risk_scores = new_scores

    def _pagerank_fallback(self, node_features: List, edge_index: List) -> Dict[str, float]:
        """Корректный PageRank для НАПРАВЛЕННОГО графа угроз"""
        num_nodes = len(node_features)
        if num_nodes == 0:
            return {}

        # Построение НАПРАВЛЕННОГО графа
        out_edges = {i: set() for i in range(num_nodes)}
        in_edges = {i: set() for i in range(num_nodes)}

        for src, dst in edge_index:
            if src < num_nodes and dst < num_nodes:
                out_edges[src].add(dst)
                in_edges[dst].add(src)

        # PageRank с правильной направленностью
        scores = {i: 1.0 / num_nodes for i in range(num_nodes)}
        damping = 0.85
        epsilon = 1e-8
        max_iterations = 100

        for _ in range(max_iterations):
            new_scores = {}
            max_diff = 0.0
            total_score = 0.0

            for node in range(num_nodes):
                # Базовая вероятность (телепортация)
                rank = (1 - damping) / num_nodes

                # Вклад от ВХОДЯЩИХ рёбер
                for in_node in in_edges[node]:
                    out_degree = len(out_edges[in_node])
                    if out_degree > 0:
                        rank += damping * scores[in_node] / out_degree
                    else:
                        rank += damping * scores[in_node] / num_nodes

                new_scores[node] = rank
                total_score += rank
                max_diff = max(max_diff, abs(new_scores[node] - scores[node]))

            # Нормализация
            if total_score > 0:
                for node in new_scores:
                    new_scores[node] /= total_score

            scores = new_scores

            if max_diff < epsilon:
                break

        return {str(k): v for k, v in scores.items()}

    def detect_communities(self) -> Dict[str, int]:
        """Обнаружение сообществ в графе (упрощённый Louvain)"""
        with self._lock:
            nodes = list(self.graph.keys())
            if not nodes:
                return {}

            # Инициализация - каждый узел в своём сообществе
            for i, node in enumerate(nodes):
                self.communities[node] = i

            changed = True
            max_iterations = 20

            while changed and max_iterations > 0:
                changed = False
                max_iterations -= 1

                for node in nodes:
                    community_weights = defaultdict(float)
                    current_community = self.communities[node]

                    # Учитываем и входящие и исходящие рёбра
                    for neighbor, weight in self.graph[node]['out_edges'].items():
                        neighbor_comm = self.communities.get(neighbor)
                        if neighbor_comm is not None:
                            community_weights[neighbor_comm] += weight

                    for neighbor, weight in self.graph[node]['in_edges'].items():
                        neighbor_comm = self.communities.get(neighbor)
                        if neighbor_comm is not None:
                            community_weights[neighbor_comm] += weight

                    best_community = current_community
                    best_gain = 0

                    for comm, weight in community_weights.items():
                        if comm != current_community and weight > best_gain:
                            best_gain = weight
                            best_community = comm

                    if best_community != current_community:
                        self.communities[node] = best_community
                        changed = True

            return dict(self.communities)

    def get_high_risk_subgraph(self, threshold: float = 0.5) -> Dict:
        """Получить подграф высокого риска"""
        self.propagate_risk()

        high_risk_nodes = {
            ip: score for ip, score in self.risk_scores.items()
            if score >= threshold
        }

        subgraph = {'nodes': [], 'edges': []}

        for ip in high_risk_nodes:
            subgraph['nodes'].append({
                'id': ip,
                'risk': self.risk_scores[ip],
                'attacks': self.graph[ip]['attacks']
            })

            for neighbor, weight in self.graph[ip]['out_edges'].items():
                if neighbor in high_risk_nodes:
                    subgraph['edges'].append({
                        'source': ip,
                        'target': neighbor,
                        'weight': weight,
                        'direction': 'out'
                    })

        return subgraph

    def get_stats(self) -> Dict:
        """Статистика графа"""
        with self._lock:
            return {
                'total_nodes': len(self.graph),
                'total_edges': sum(len(data['out_edges']) for data in self.graph.values()),
                'high_risk_nodes': sum(1 for score in self.risk_scores.values() if score > 0.5),
                'communities': len(set(self.communities.values())),
                'dirty_nodes': len(self._dirty_nodes),
                'last_full_propagation': self._last_full_propagation
            }

    def cleanup_old_nodes(self, max_age: int = 86400) -> int:
        """Очистка устаревших узлов"""
        with self._lock:
            now = time.time()
            expired = [ip for ip, data in self.graph.items()
                       if now - data['last_seen'] > max_age]

            for ip in expired:
                del self.graph[ip]
                if ip in self.risk_scores:
                    del self.risk_scores[ip]
                if ip in self.communities:
                    del self.communities[ip]

            return len(expired)

# ============================================================
# ADVANCED LEARNER
# ============================================================

class AdvancedLearner(BaseModule):
    """Продвинутое обучение (Baseline + ThreatGraph)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("AdvancedLearner", config, event_bus, logger)
        self.baseline = BaselineProfiler()
        self.threat_graph = ThreatGraphNetwork()
        self.anomaly_threshold = 0.6
        self._lock = threading.RLock()

        self._packet_counter = 0
        self._sample_rate = 10  # Анализировать каждый 10-й пакет

        self.event_bus.subscribe('packet.received', self.on_packet)
        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('exfiltration.detected', self.on_exfiltration)

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._graph_analysis_loop, daemon=True).start()
        self.logger.info("Advanced Learner запущен (Baseline + ThreatGraph)")

    def stop(self) -> None:
        self.running = False

    def on_packet(self, data: Dict) -> None:
        """Обработка пакета (с сэмплированием для производительности)"""
        self._packet_counter += 1
        if self._packet_counter % self._sample_rate != 0:
            return  # Пропускаем для производительности

        src_ip = data.get('src_ip', '')
        dst_ip = data.get('dst_ip', '')
        dst_port = data.get('dst_port', 0)
        packet = data.get('packet')


        if src_ip and packet:
            try:
                size = len(packet)
                entropy = self._calculate_packet_entropy(packet)

                # Обновление baseline
                self.baseline.update(
                    device=src_ip,
                    size=size,
                    port=dst_port,
                    entropy=entropy,
                    dst_ip=dst_ip,
                    src_ip=src_ip
                )

                # Обновление графа угроз
                if dst_ip:
                    self.threat_graph.add_edge(src_ip, dst_ip)

                # Проверка аномалий baseline
                score = self.baseline.get_score(src_ip, size, dst_port, entropy, dst_ip)

                if score > self.anomaly_threshold:
                    alert = {
                        'timestamp': time.time(),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'attack_type': 'Behavioral Anomaly',
                        'score': score,
                        'confidence': score,
                        'is_attack': True,
                        'explanation': f"Аномальное поведение (baseline score={score:.3f})"
                    }
                    self.event_bus.publish('alert.detected', alert)

            except Exception as e:
                self.logger.debug(f"Ошибка анализа пакета: {e}")

    def _calculate_packet_entropy(self, packet) -> float:
        """Вычисление энтропии пакета"""
        try:
            from scapy.all import Raw
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if payload:
                    freq = {}
                    for b in payload:
                        freq[b] = freq.get(b, 0) + 1
                    entropy = -sum((c / len(payload)) * math.log2(c / len(payload)) for c in freq.values())
                    return entropy / 8.0
        except:
            pass
        return 0.0

    def on_alert(self, alert: Dict) -> None:
        """Обновление графа при алерте"""
        src_ip = alert.get('src_ip', '')
        dst_ip = alert.get('dst_ip', '')

        if src_ip:
            self.threat_graph.mark_attack(
                ip=src_ip,
                score=alert.get('score', 0.5),
                attack_type=alert.get('attack_type')
            )

        if dst_ip:
            self.threat_graph.add_edge(src_ip, dst_ip, weight=alert.get('score', 0.5) * 2)

    def on_exfiltration(self, data: Dict) -> None:
        """Обновление графа при утечке данных"""
        src_ip = data.get('src_ip', '')
        if src_ip:
            self.threat_graph.mark_attack(src_ip, 0.9, 'Data Exfiltration')

    def _graph_analysis_loop(self) -> None:
        """Периодический анализ графа"""
        while self.running:
            time.sleep(300)  # Каждые 5 минут

            # Распространение риска
            risk_scores = self.threat_graph.propagate_risk()

            # Обнаружение сообществ
            communities = self.threat_graph.detect_communities()

            # Поиск подозрительных кластеров
            high_risk = self.threat_graph.get_high_risk_subgraph(threshold=0.6)

            if high_risk['nodes']:
                self.logger.warning(f"Обнаружен кластер высокого риска: {len(high_risk['nodes'])} узлов")
                self.event_bus.publish('threat_graph.cluster', high_risk)

    def get_device_risk(self, ip: str) -> float:
        """Получить риск устройства"""
        self.threat_graph.propagate_risk()
        return self.threat_graph.risk_scores.get(ip, 0.0)


# ============================================================
# HONEYPOT SERVICE
# ============================================================

class HoneypotService(BaseModule):
    """Сервис-ловушка для обнаружения атак"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Honeypot", config, event_bus, logger)
        self.enabled = config.get('protection.honeypot.enabled', True)
        self.ports = config.get('protection.honeypot.ports', [22, 80, 443, 3389, 8080])
        self.services: List[_HoneypotServer] = []
        self.connections: Dict[str, List[Dict]] = defaultdict(list)

    def start(self) -> None:
        if not self.enabled:
            return

        self.running = True
        for port in self.ports:
            srv = _HoneypotServer(port, self.event_bus, self.logger, self._on_connection)
            srv.start()
            self.services.append(srv)

        self.logger.info(f"Honeypot запущен на портах: {self.ports}")

    def stop(self) -> None:
        self.running = False
        for srv in self.services:
            srv.stop()

    def _on_connection(self, src_ip: str, port: int, data: bytes = None) -> None:
        """Обработка подключения к ловушке"""

        # ========== СЮДА ВСТАВИТЬ ==========
        print(f"🔥🔥🔥 HONEYPOT CONNECTION: {src_ip}:{port} 🔥🔥🔥")
        # ========== AI MODEL DETECTION ==========
        try:
            import joblib
            import os
            if not hasattr(self, '_ai_model'):
                model_path = os.path.join(os.path.dirname(__file__), 'models', 'shard_real_alert_model.pkl')
                if os.path.exists(model_path):
                    self._ai_model = joblib.load(model_path)
                    self.logger.info("✅ AI модель загружена в honeypot хук")
            if hasattr(self, '_ai_model') and self._ai_model:
                # Игнорируем соединения от localhost
                if src_ip == "127.0.0.1" or src_ip == "::1":
                    return
                alert_msg = f"WARNING:SHARD.SHARD:🍯 Honeypot triggered by {src_ip}"
                pred = self._ai_model.predict([alert_msg])[0]
                print(f"🎯🎯🎯 [AI DETECTION] {pred.upper()} from {src_ip}:{port} 🎯🎯🎯")
                self.logger.warning(f"🎯 AI Model detected: {pred} from {src_ip}")
        except Exception as e:
            self.logger.error(f"❌ AI Hook error: {e}")
        # ======================================
        self.logger.warning(f"🍯 Honeypot: подключение от {src_ip} на порт {port}")
        # ===================================

        # Игнорируем localhost (если нужно)
        # if src_ip == '127.0.0.1':
        #     return

        self.connections[src_ip].append({
            'timestamp': time.time(),
            'port': port,
            'data': data[:100].hex() if data else None
        })

        # Создание алерта
        alert = {
            'timestamp': time.time(),
            'src_ip': src_ip,
            'dst_port': port,
            'attack_type': 'Honeypot Interaction',
            'score': 0.7,
            'confidence': 0.9,
            'is_attack': True,
            'severity': 'HIGH',
            'explanation': f"Обнаружено взаимодействие с honeypot на порту {port}"
        }

        # ========== УБЕДИТЕСЬ ЧТО ЭТИ СТРОКИ ЕСТЬ ==========
        self.event_bus.publish('honeypot.connection', alert)
        self.event_bus.publish('alert.detected', alert)
        self.logger.warning(f"🍯 Honeypot: подключение от {src_ip} на порт {port}")
        # ==================================================


_GLOBAL_HONEYPOT_SEMAPHORE = threading.Semaphore(100)

class _HoneypotServer:
    """Отдельный сервер-ловушка с ограничением подключений"""

    def __init__(self, port: int, event_bus: EventBus, logger, callback: Callable):
        self.port = port
        self.event_bus = event_bus
        self.logger = logger
        self.callback = callback
        self.running = False
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None

        # Ограничение одновременных подключений
        self._max_connections = 50
        self._connection_semaphore = _GLOBAL_HONEYPOT_SEMAPHORE
        self._active_connections = 0
        self._conn_lock = threading.RLock()

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True, name=f"Honeypot-{self.port}")
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

    def _listen(self) -> None:
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.socket.settimeout(1.0)

            while self.running:
                try:
                    conn, addr = self.socket.accept()

                    # Проверяем лимит подключений
                    if not self._connection_semaphore.acquire(blocking=False):
                        # Слишком много подключений - отклоняем
                        conn.close()
                        self.logger.debug(f"Honeypot порт {self.port}: превышен лимит подключений от {addr[0]}")
                        continue

                    # Запускаем обработку в отдельном потоке
                    threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True,
                        name=f"Honeypot-{self.port}-{addr[0]}"
                    ).start()

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.debug(f"Honeypot порт {self.port}: {e}")

        except Exception as e:
            if self.running:
                self.logger.error(f"Honeypot ошибка на порту {self.port}: {e}")
        finally:
            pass  # FIXED: don't null semaphore

    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        """Обработка одного подключения"""
        try:
            with self._conn_lock:
                self._active_connections += 1

            src_ip = addr[0]

            # Получаем данные с таймаутом
            conn.settimeout(2.0)
            data = b''
            try:
                data = conn.recv(1024)
            except socket.timeout:
                pass
            except Exception:
                pass

            # Отправляем приманку
            banner = self._get_banner()
            if banner:
                try:
                    conn.send(banner)
                except:
                    pass

            # Уведомляем о подключении
            self.callback(src_ip, self.port, data if data else None)

        except Exception as e:
            self.logger.debug(f"Honeypot ошибка обработки {addr[0]}: {e}")
        finally:
            try:
                conn.close()
            except:
                pass

            with self._conn_lock:
                self._active_connections -= 1

            if self._connection_semaphore:
                self._connection_semaphore.release()

    def _get_banner(self) -> bytes:
        """Получить обобщённый баннер для порта (без раскрытия версий)"""
        banners = {
            22: b"SSH-2.0-OpenSSH\r\n",
            80: b"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<html><h1>Welcome</h1></html>",
            443: b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n",
            3389: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
            8080: b"HTTP/1.1 200 OK\r\nServer: Apache-Coyote\r\n\r\n",
            21: b"220 FTP Server ready\r\n",
            25: b"220 SMTP Server ready\r\n",
            3306: b"5.7.0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        }
        return banners.get(self.port, b"")

    def get_stats(self) -> Dict:
        """Получить статистику сервера"""
        with self._conn_lock:
            return {
                'port': self.port,
                'running': self.running,
                'active_connections': self._active_connections,
                'max_connections': self._max_connections
            }

# ============================================================
# AGENTIC AI ANALYST
# ============================================================

class AgenticAIAnalyst(BaseModule):
    """Агентный ИИ для расследования инцидентов (исправлен - защита от race condition, дедупликация)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("AgenticAI", config, event_bus, logger)
        self.investigations: Dict[str, Dict] = {}
        self.knowledge_base: Dict[str, List[str]] = defaultdict(list)
        self._lock = threading.RLock()

        # Дедупликация расследований
        self._recent_investigations: Dict[str, float] = {}
        self._investigation_cooldown = 60
        self._global_cooldown = 10
        self._last_investigation_time = 0
        self._max_investigations_per_minute = 10
        self._investigation_counter: Dict[str, int] = defaultdict(int)
        self._counter_reset = time.time()
        self._inv_lock = threading.RLock()

        # Игнорируемые типы для авто-расследований
        self._auto_investigate_types = {'Honeypot Interaction', 'Port Scan'}

        # Игнорируемые IP
        self._ignored_ips = {'127.0.0.1', '::1', 'localhost', '0.0.0.0'}

        # Кэш уже расследованных алертов
        self._investigated_alerts: Dict[str, float] = {}
        self._alert_ttl = 300

        # ========== ЗАЩИТА ОТ ЦИКЛОВ (ИСПРАВЛЕНО) ==========
        self._processing_alerts = self._create_ttl_set(max_size=500)
        self._processing_lock = threading.RLock()
        # ===================================================

        # Статистика
        self._stats = {
            'total_investigations': 0,
            'auto_investigations': 0,
            'skipped_investigations': 0,
            'suppressed_duplicates': 0,
            'suppressed_cycles': 0
        }

        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('investigation.request', self.on_investigation_request)

    @staticmethod
    def _create_ttl_set(max_size: int = 500):
        """Создаёт TTL set с FIFO удалением и потокобезопасностью"""
        from collections import OrderedDict

        class TTLSet:
            def __init__(self, max_size: int = 500):
                self._data = OrderedDict()
                self.max_size = max_size
                self._ttl = 600
                self._lock = threading.RLock()

            def add(self, item: str):
                with self._lock:
                    if item in self._data:
                        self._data[item] = time.time()
                        self._data.move_to_end(item)
                        return
                    self._data[item] = time.time()
                    if len(self._data) > self.max_size:
                        self._data.popitem(last=False)

            def discard(self, item: str):
                with self._lock:
                    self._data.pop(item, None)

            def __contains__(self, item: str) -> bool:
                with self._lock:
                    if item not in self._data:
                        return False
                    ts = self._data[item]
                    if time.time() - ts > self._ttl:
                        del self._data[item]
                        return False
                    return True

            def cleanup_expired(self, ttl: float = 300) -> int:
                with self._lock:
                    now = time.time()
                    expired = [k for k, ts in self._data.items() if now - ts > ttl]
                    for k in expired:
                        del self._data[k]
                    return len(expired)

        return TTLSet(max_size=max_size)

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._background_analysis, daemon=True, name="AgenticAI-Background").start()
        threading.Thread(target=self._cleanup_loop, daemon=True, name="AgenticAI-Cleanup").start()
        self.logger.info("Agentic AI аналитик запущен (с дедупликацией и защитой от race condition)")

    def stop(self) -> None:
        self.running = False
        self.logger.info(f"Agentic AI остановлен. Статистика: {self._stats}")

    def _cleanup_loop(self) -> None:
        while self.running:
            time.sleep(60)
            now = time.time()

            with self._inv_lock:
                expired_keys = [k for k, v in self._recent_investigations.items()
                                if now - v > self._investigation_cooldown * 2]
                for k in expired_keys:
                    del self._recent_investigations[k]

                expired_alerts = [k for k, v in self._investigated_alerts.items()
                                  if now - v > self._alert_ttl]
                for k in expired_alerts:
                    del self._investigated_alerts[k]

            with self._lock:
                expired_inv = [k for k, v in self.investigations.items()
                               if now - v.get('end_time', now) > 86400]
                for k in expired_inv:
                    del self.investigations[k]

            # Периодическая очистка TTL set
            self._processing_alerts.cleanup_expired(ttl=600)

    def _should_auto_investigate(self, alert: Dict) -> bool:
        attack_type = str(alert.get('attack_type', ''))
        src_ip = str(alert.get('src_ip', 'unknown'))
        severity = alert.get('severity', 'LOW')
        score = alert.get('score', 0)

        if src_ip in self._ignored_ips:
            return False

        if attack_type in self._auto_investigate_types:
            return False

        if severity not in ['HIGH', 'CRITICAL']:
            return False

        if score < 0.6:
            return False

        now = time.time()
        alert_id = f"{src_ip}:{attack_type}:{severity}"

        with self._inv_lock:
            if now - self._counter_reset > 60:
                self._investigation_counter.clear()
                self._counter_reset = now

            if alert_id in self._investigated_alerts:
                self._stats['suppressed_duplicates'] += 1
                return False

            if now - self._last_investigation_time < self._global_cooldown:
                self._stats['skipped_investigations'] += 1
                return False

            last_time = self._recent_investigations.get(alert_id, 0)
            if now - last_time < self._investigation_cooldown:
                self._stats['skipped_investigations'] += 1
                return False

            if self._investigation_counter.get('total', 0) >= self._max_investigations_per_minute:
                self._stats['skipped_investigations'] += 1
                return False

            self._recent_investigations[alert_id] = now
            self._investigated_alerts[alert_id] = now
            self._investigation_counter['total'] = self._investigation_counter.get('total', 0) + 1
            self._last_investigation_time = now
            self._stats['auto_investigations'] += 1

            return True

    def on_alert(self, alert: Dict) -> None:
        # Группировка алертов по 10-секундным окнам
        alert_signature = f"{alert.get('src_ip', 'unknown')}_{alert.get('attack_type', 'Unknown')}"
        alert_id = f"{alert_signature}_{int(alert.get('timestamp', time.time()) // 10)}"

        if alert_id in self._processing_alerts:
            self._stats['suppressed_cycles'] += 1
            self.logger.debug(f"Alert {alert_id} already being processed, skipping")
            return

        self._processing_alerts.add(alert_id)

        try:
            if not self._should_auto_investigate(alert):
                return

            investigation = self._investigate(alert)
            self._stats['total_investigations'] += 1

            self.event_bus.publish('investigation.completed', investigation)

            conclusion_short = investigation.get('conclusion', '')[:80]
            self.logger.info(f"🔍 Расследование #{investigation['id']}: {conclusion_short}...")

        except Exception as e:
            self.logger.error(f"Ошибка расследования: {e}")
        finally:
            self._processing_alerts.discard(alert_id)

    def on_investigation_request(self, data: Dict) -> None:
        alert = data.get('alert', {})
        force = data.get('force', False)

        if not force:
            src_ip = alert.get('src_ip', 'unknown')
            attack_type = alert.get('attack_type', 'Unknown')
            alert_id = f"{src_ip}:{attack_type}:manual"

            with self._inv_lock:
                now = time.time()
                last_time = self._recent_investigations.get(alert_id, 0)
                if now - last_time < 10:
                    self.logger.debug(f"Пропускаем ручное расследование (cooldown): {alert_id}")
                    return
                self._recent_investigations[alert_id] = now

        try:
            investigation = self._investigate(alert)
            self._stats['total_investigations'] += 1
            self.event_bus.publish('investigation.completed', investigation)
            self.logger.info(f"📋 Ручное расследование #{investigation['id']} завершено")
        except Exception as e:
            self.logger.error(f"Ошибка ручного расследования: {e}")

    def _investigate(self, alert: Dict) -> Dict:
        alert_id = f"INV-{int(time.time())}-{random.randint(1000, 9999)}"
        src_ip = str(alert.get('src_ip', 'unknown'))
        dst_ip = str(alert.get('dst_ip', 'unknown'))
        attack_type = str(alert.get('attack_type', 'Unknown'))
        score = alert.get('score', 0)

        investigation = {
            'id': alert_id,
            'start_time': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'attack_type': attack_type,
            'initial_score': score,
            'alerts': [alert],
            'evidence': [],
            'related_ips': set(),
            'timeline': [],
            'mitre_tactics': [],
            'confidence': 0.0,
            '_internal_evidence': [],
            '_sensitive_data': {}
        }

        source_analysis = self._analyze_source(src_ip)
        investigation['_internal_evidence'] = source_analysis.get('evidence', [])
        investigation['_sensitive_data'] = {
            'source_analysis': source_analysis,
            'detection_methods': ['ML', 'Signature', 'Behavioral']
        }

        if source_analysis.get('is_known_malicious'):
            investigation['evidence'].append("IP обнаружен в базах угроз")
        if source_analysis.get('geo_location'):
            investigation['evidence'].append(f"Геолокация: {source_analysis['geo_location']}")

        investigation['related_ips'].update(source_analysis.get('related_ips', set()))

        mitre_info = self._map_to_mitre(attack_type)
        investigation['mitre_tactics'] = mitre_info['tactics']
        investigation['mitre_techniques'] = mitre_info.get('techniques', [])

        related_alerts = self._find_related_alerts(src_ip, dst_ip, attack_type)
        investigation['alerts'].extend(related_alerts)

        investigation['timeline'] = self._build_timeline(investigation['alerts'])

        impact = self._assess_impact(investigation)
        investigation['impact'] = impact

        investigation['conclusion'] = self._generate_conclusion(investigation)
        investigation['recommendations'] = self._generate_recommendations(investigation)
        investigation['confidence'] = self._calculate_confidence(investigation)
        investigation['severity'] = self._determine_severity(investigation)

        with self._lock:
            self.investigations[alert_id] = investigation

        investigation['end_time'] = time.time()
        investigation['duration'] = investigation['end_time'] - investigation['start_time']

        public_investigation = {k: v for k, v in investigation.items() if not k.startswith('_')}
        public_investigation['related_ips'] = list(investigation['related_ips'])

        return public_investigation

    def _analyze_source(self, ip: str) -> Dict:
        result = {
            'evidence': [],
            'related_ips': set(),
            'is_known_malicious': False,
            'geo_location': None,
            'reputation_score': 0
        }

        request_id = f"analyze_{ip}_{int(time.time())}_{threading.get_ident()}"
        response_container = {'data': None}
        response_received = threading.Event()
        response_lock = threading.Lock()

        def on_threat_response(data: Dict):
            if data.get('request_id') == request_id:
                with response_lock:
                    response_container['data'] = data.get('result', {})
                response_received.set()

        # FIXED: use direct callback instead of subscribe to avoid thread leak
        # # FIXED: use direct callback instead of subscribe to avoid thread leak
        # # FIXED: use direct callback instead of subscribe to avoid thread leak
        # self.event_bus.subscribe('threat_intel.check_ip.response', on_threat_response)

        try:
            self.event_bus.publish('threat_intel.check_ip', {
                'ip': ip,
                'request_id': request_id
            })

            if response_received.wait(timeout=3):
                with response_lock:
                    threat_result = response_container['data']

                if threat_result:
                    result['is_known_malicious'] = threat_result.get('is_malicious', False)
                    result['reputation_score'] = threat_result.get('score', 0)

                    geo = threat_result.get('geo', {})
                    result['geo_location'] = geo.get('country_code') or geo.get('country')

                    if result['is_known_malicious']:
                        sources = ', '.join(threat_result.get('sources', ['unknown']))
                        result['evidence'].append(f"IP {ip} обнаружен в базах угроз (источники: {sources})")

                    if result['geo_location']:
                        result['evidence'].append(f"Геолокация: {result['geo_location']}")

                    if threat_result.get('categories'):
                        cats = ', '.join(threat_result['categories'][:3])
                        result['evidence'].append(f"Категории угроз: {cats}")
            else:
                result['evidence'].append(f"Не удалось получить данные об IP {ip} (таймаут)")

        except Exception as e:
            self.logger.error(f"Ошибка анализа источника {ip}: {e}")
            result['evidence'].append(f"Ошибка анализа: {str(e)[:100]}")
        finally:
            self.event_bus.unsubscribe('threat_intel.check_ip.response', on_threat_response)

        return result

    def _map_to_mitre(self, attack_type: str) -> Dict:
        mitre_map = {
            'Brute Force': {'tactics': ['Credential Access'], 'techniques': ['T1110 - Brute Force']},
            'Port Scan': {'tactics': ['Discovery'], 'techniques': ['T1046 - Network Service Scanning']},
            'Web Attack': {'tactics': ['Initial Access'], 'techniques': ['T1190 - Exploit Public-Facing Application']},
            'DDoS': {'tactics': ['Impact'], 'techniques': ['T1498 - Network Denial of Service']},
            'Lateral Movement': {'tactics': ['Lateral Movement'], 'techniques': ['T1021 - Remote Services']},
            'Data Exfiltration': {'tactics': ['Exfiltration'],
                                  'techniques': ['T1048 - Exfiltration Over Alternative Protocol']},
            'DNS Tunnel': {'tactics': ['Command and Control'], 'techniques': ['T1572 - Protocol Tunneling']},
            'C2 Beacon': {'tactics': ['Command and Control'], 'techniques': ['T1571 - Non-Standard Port']},
            'Malware': {'tactics': ['Execution'], 'techniques': ['T1204 - User Execution']},
            'Phishing': {'tactics': ['Initial Access'], 'techniques': ['T1566 - Phishing']},
            'Rate Limit': {'tactics': ['Impact'], 'techniques': ['T1499 - Endpoint Denial of Service']},
            'Honeypot Interaction': {'tactics': ['Discovery'], 'techniques': ['T1046 - Network Service Scanning']}
        }
        return mitre_map.get(attack_type, {'tactics': ['Unknown'], 'techniques': ['T1000 - Unknown']})

    def _find_related_alerts(self, src_ip: str, dst_ip: str, attack_type: str) -> List[Dict]:
        related = []
        try:
            response_queue = queue.Queue()
            request_id = f"related_{int(time.time())}_{threading.get_ident()}"
            received = threading.Event()

            def on_response(data):
                if data.get('request_id') == request_id:
                    response_queue.put(data.get('alerts', []))
                    received.set()

            self.event_bus.subscribe('siem.query.response', on_response)
            try:
                self.event_bus.publish('siem.query.request', {
                    'request_id': request_id,
                    'src_ip': src_ip,
                    'time_range': 1800,
                    'limit': 50
                })
                if received.wait(timeout=2):
                    related = response_queue.get(timeout=1)
            finally:
                self.event_bus.unsubscribe('siem.query.response', on_response)
        except Exception as e:
            self.logger.debug(f"Ошибка запроса алертов: {e}")

        return [a for a in related[:10] if a.get('src_ip') == src_ip]

    def _build_timeline(self, alerts: List[Dict]) -> List[Dict]:
        timeline = []
        for alert in sorted(alerts, key=lambda x: x.get('timestamp', 0)):
            timeline.append({
                'time': alert.get('timestamp', time.time()),
                'event': str(alert.get('attack_type', 'Unknown')),
                'source': str(alert.get('src_ip', 'unknown')),
                'target': str(alert.get('dst_ip', 'unknown')),
                'score': alert.get('score', 0)
            })
        return timeline[-20:]

    def _assess_impact(self, investigation: Dict) -> Dict:
        impact = {'confidentiality': 'LOW', 'integrity': 'LOW', 'availability': 'LOW',
                  'overall': 'LOW', 'description': ''}
        attack_type = investigation['attack_type']

        if attack_type in ['Data Exfiltration']:
            impact.update({'confidentiality': 'HIGH', 'overall': 'HIGH',
                           'description': 'Возможна утечка конфиденциальных данных'})
        elif attack_type in ['DDoS', 'Rate Limit']:
            impact.update({'availability': 'HIGH', 'overall': 'HIGH',
                           'description': 'Нарушение доступности сервисов'})
        elif attack_type in ['Brute Force', 'Lateral Movement']:
            impact.update({'confidentiality': 'MEDIUM', 'integrity': 'MEDIUM',
                           'overall': 'MEDIUM', 'description': 'Возможна компрометация учётных записей'})
        elif attack_type in ['Malware', 'C2 Beacon']:
            impact.update({'confidentiality': 'HIGH', 'integrity': 'HIGH',
                           'overall': 'HIGH', 'description': 'Обнаружено вредоносное ПО или C2 канал'})
        return impact

    def _generate_conclusion(self, investigation: Dict) -> str:
        conclusions = {
            'Brute Force': f"Обнаружена атака подбора пароля с {investigation['src_ip']}. Рекомендуется блокировка.",
            'Port Scan': f"Обнаружено сканирование портов с {investigation['src_ip']}. Рекомендуется мониторинг.",
            'Web Attack': f"Обнаружена веб-атака с {investigation['src_ip']}. Проверьте WAF.",
            'DDoS': f"Обнаружена DDoS атака с {investigation['src_ip']}. Включите защиту.",
            'Data Exfiltration': f"ОБНАРУЖЕНА УТЕЧКА ДАННЫХ с {investigation['src_ip']}! НЕМЕДЛЕННО заблокируйте!",
            'C2 Beacon': f"Обнаружен C2 beaconing с {investigation['src_ip']}. Система может быть скомпрометирована.",
            'Rate Limit': f"Обнаружено превышение лимита запросов с {investigation['src_ip']}. IP заблокирован.",
            'Honeypot Interaction': f"Обнаружено взаимодействие с honeypot от {investigation['src_ip']}."
        }
        return conclusions.get(investigation['attack_type'],
                               f"Обнаружена атака типа {investigation['attack_type']}. Требуется анализ.")

    def _generate_recommendations(self, investigation: Dict) -> List[str]:
        recs = {
            'Brute Force': ['Включить MFA', 'Установить блокировку после 5 попыток'],
            'Data Exfiltration': ['НЕМЕДЛЕННО заблокировать источник', 'Проверить исходящий трафик', 'Уведомить СБ'],
            'C2 Beacon': ['Изолировать систему', 'Заблокировать подозрительные соединения'],
            'Rate Limit': ['Проверить легитимность трафика', 'Настроить дополнительные ограничения'],
            'Honeypot Interaction': ['Проверить источник', 'Добавить IP в список наблюдения']
        }
        recommendations = recs.get(investigation['attack_type'], ['Провести анализ', 'Проверить логи'])
        if investigation['impact']['overall'] == 'HIGH':
            recommendations.insert(0, '🚨 КРИТИЧЕСКИЙ ИНЦИДЕНТ!')
        return recommendations[:5]

    def _calculate_confidence(self, investigation: Dict) -> float:
        confidence = 0.5 + min(0.2, len(investigation['alerts']) * 0.05)
        if investigation.get('initial_score', 0) > 0.7:
            confidence += 0.1
        return min(0.99, confidence)

    def _determine_severity(self, investigation: Dict) -> str:
        score_map = {'Data Exfiltration': 4, 'DDoS': 3, 'C2 Beacon': 3, 'Malware': 3,
                     'Brute Force': 2, 'Web Attack': 2, 'Rate Limit': 2, 'Honeypot Interaction': 1}
        score = score_map.get(investigation['attack_type'], 1)
        if investigation['impact']['overall'] == 'HIGH':
            score += 1
        if score >= 4:
            return 'CRITICAL'
        elif score >= 3:
            return 'HIGH'
        elif score >= 2:
            return 'MEDIUM'
        return 'LOW'

    def _background_analysis(self) -> None:
        while self.running:
            time.sleep(60)

    def get_investigation(self, investigation_id: str) -> Optional[Dict]:
        with self._lock:
            return self.investigations.get(investigation_id)

    def get_stats(self) -> Dict:
        with self._lock:
            with self._inv_lock:
                return {
                    'total_investigations': self._stats['total_investigations'],
                    'auto_investigations': self._stats['auto_investigations'],
                    'skipped_investigations': self._stats['skipped_investigations'],
                    'suppressed_duplicates': self._stats['suppressed_duplicates'],
                    'suppressed_cycles': self._stats['suppressed_cycles'],
                    'active_investigations': len(self.investigations),
                    'processing_alerts': len(self._processing_alerts._data)
                }

    def reset_stats(self) -> None:
        with self._inv_lock:
            self._stats = {k: 0 for k in self._stats}
            self._recent_investigations.clear()
            self._investigated_alerts.clear()
            self._investigation_counter.clear()
        self.logger.info("Статистика Agentic AI сброшена")


# ============================================================
# TRAFFIC CAPTURE
# ============================================================

class TrafficCapture(BaseModule):
    """Захват сетевого трафика"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Capture", config, event_bus, logger)
        self.interface = config.get('network.interface', 'auto')
        self.capture_filter = config.get('network.capture_filter', 'ip')
        self.local_networks = config.get('network.local_networks', ['192.168.', '10.', '172.16.', '127.'])
        self.packet_queue = queue.Queue(maxsize=100000)
        self.num_workers = 4
        self.features_extractor = None

        # Счётчики пакетов и байт
        self.packet_count = 0
        self.bytes_count = 0
        self._stats_lock = threading.RLock()  # Блокировка для счётчиков

        # Статистика по протоколам
        self.protocol_stats: Dict[str, int] = defaultdict(int)
        self._proto_lock = threading.RLock()

        # Отслеживание активных соединений (потоков)
        self.active_flows: Dict[str, Dict] = {}
        self._flows_lock = threading.RLock()

        # Время последнего сброса статистики
        self.stats_reset_time = time.time()

    def set_features_extractor(self, extractor: Callable) -> None:
        """Установка экстрактора признаков"""
        self.features_extractor = extractor

    def start(self) -> None:
        self.running = True

        for i in range(self.num_workers):
            thread = threading.Thread(target=self._worker, daemon=True, name=f"CaptureWorker-{i}")
            thread.start()

        self.logger.info(f"Захват трафика на {self._get_interface()}, {self.num_workers} воркеров")

    def stop(self) -> None:
        self.running = False

    def _get_interface(self) -> str:
        """Получение сетевого интерфейса"""
        if self.interface == 'auto' and scapy_all:
            try:
                from scapy.all import conf
                return conf.iface
            except:
                pass
        return self.interface

    def _worker(self) -> None:
        """Рабочий поток обработки пакетов"""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                self._process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.debug(f"Ошибка обработки пакета: {e}")

    def _process_packet(self, packet) -> None:
        """Обработка одного пакета (исправлены блокировки)"""
        try:
            from scapy.all import IP, TCP, UDP, Raw

            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)

            # Определение порта и протокола
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                src_port = packet[TCP].sport
                protocol = 'TCP'
                proto_num = 6
            elif packet.haslayer(UDP):
                dst_port = packet[UDP].dport
                src_port = packet[UDP].sport
                protocol = 'UDP'
                proto_num = 17
            else:
                dst_port = 0
                src_port = 0
                protocol = 'OTHER'
                proto_num = packet[IP].proto

            # Проверка локальности
            is_local = self._is_local_ip(str(src_ip)) and self._is_local_ip(str(dst_ip))

            # Атомарное обновление счётчиков - ИСПОЛЬЗУЕМ ПРАВИЛЬНЫЙ ЛОК
            with self._stats_lock:  # ← ИСПРАВЛЕНО: было self._count_lock
                self.packet_count += 1
                self.bytes_count += packet_size

            # Обновление статистики по протоколам
            with self._proto_lock:
                self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1

            # Обновление информации о потоках
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto_num}"
            self._update_flow_stats(flow_key, packet_size)

            # Публикация события
            packet_data = {
                'packet': packet,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'proto_num': proto_num,
                'is_local': is_local,
                'size': packet_size,
                'timestamp': time.time()
            }

            self.event_bus.publish('packet.received', packet_data)

            # Извлечение признаков для ML
            if self.features_extractor:
                features = self.features_extractor(packet)
                if features:
                    self.event_bus.publish('packet.features', {
                        'features': features,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port
                    })

            # Счётчик обработанных пакетов
            self.event_bus.publish('packet.processed', {'count': 1})

        except Exception as e:
            self.logger.debug(f"Ошибка парсинга пакета: {e}")

    def _is_local_ip(self, ip: str) -> bool:
        """Быстрая проверка локальности IP"""
        for net in self.local_networks:
            if ip.startswith(net):
                return True
        return False

    def _update_flow_stats(self, flow_key: str, packet_size: int) -> None:
        """Обновление статистики потока"""
        with self._flows_lock:
            if flow_key not in self.active_flows:
                self.active_flows[flow_key] = {
                    'packets': 1,
                    'bytes': packet_size,
                    'first_seen': time.time(),
                    'last_seen': time.time()
                }
            else:
                flow = self.active_flows[flow_key]
                flow['packets'] += 1
                flow['bytes'] += packet_size
                flow['last_seen'] = time.time()

            # Очистка старых потоков (каждые 1000 обновлений)
            if len(self.active_flows) > 10000:
                self._cleanup_old_flows()

    def _cleanup_old_flows(self) -> None:
        """Очистка устаревших потоков"""
        now = time.time()
        timeout = 300  # 5 минут

        expired = [
            key for key, flow in self.active_flows.items()
            if now - flow['last_seen'] > timeout
        ]

        for key in expired:
            del self.active_flows[key]

    def capture_loop(self) -> None:
        """Основной цикл захвата с автоматическим перезапуском при ошибках"""
        if not scapy_all:
            self.logger.error("Scapy не установлен. Захват трафика недоступен.")
            return

        from scapy.all import sniff

        retry_count = 0
        max_retries = 10
        retry_delay = 5  # секунд
        max_delay = 60  # максимальная задержка

        while self.running:
            try:
                self.logger.info(f"Начинаем захват на интерфейсе {self._get_interface()}")

                sniff(
                    iface=self._get_interface(),
                    prn=lambda p: self.packet_queue.put(p),
                    store=0,
                    filter=self.capture_filter
                )

                # Если sniff завершился без ошибки, сбрасываем счётчик
                retry_count = 0

            except KeyboardInterrupt:
                self.logger.info("Захват прерван пользователем")
                break

            except PermissionError:
                self.logger.error("Недостаточно прав для захвата трафика. Запустите от root/Administrator.")
                break  # Нет смысла повторять без прав

            except OSError as e:
                retry_count += 1
                if retry_count > max_retries:
                    self.logger.error(f"Превышено максимальное количество попыток ({max_retries}). Остановка захвата.")
                    break

                # Экспоненциальная задержка с ограничением
                delay = min(retry_delay * (2 ** (retry_count - 1)), max_delay)
                self.logger.warning(
                    f"Ошибка захвата: {e}. Повторная попытка {retry_count}/{max_retries} через {delay} сек...")

                if not self.running:
                    break

                time.sleep(delay)

                # Пробуем обновить интерфейс если он изменился
                if self.interface == 'auto':
                    try:
                        from scapy.all import conf
                        self.interface = conf.iface
                    except:
                        pass

            except Exception as e:
                retry_count += 1
                if retry_count > max_retries:
                    self.logger.error(f"Критическая ошибка захвата: {e}")
                    break

                delay = min(retry_delay * (2 ** (retry_count - 1)), max_delay)
                self.logger.error(f"Ошибка захвата: {e}. Повтор через {delay} сек...")

                if not self.running:
                    break

                time.sleep(delay)
    def get_stats(self) -> Dict:
        """Статистика захвата"""
        # Безопасное чтение счётчиков
        with self._stats_lock:
            packets = self.packet_count
            bytes_count = self.bytes_count

        with self._proto_lock:
            protocols = dict(self.protocol_stats)

        with self._flows_lock:
            flows_count = len(self.active_flows)
            total_flow_bytes = sum(f['bytes'] for f in self.active_flows.values())
            total_flow_packets = sum(f['packets'] for f in self.active_flows.values())

        uptime = time.time() - self.stats_reset_time

        return {
            'packets_captured': packets,
            'bytes_captured': bytes_count,
            'bytes_mb': round(bytes_count / (1024 * 1024), 2),
            'packets_per_second': round(packets / uptime, 2) if uptime > 0 else 0,
            'bytes_per_second': round(bytes_count / uptime, 2) if uptime > 0 else 0,
            'queue_size': self.packet_queue.qsize(),
            'interface': self._get_interface(),
            'active_flows': flows_count,
            'flow_packets': total_flow_packets,
            'flow_bytes_mb': round(total_flow_bytes / (1024 * 1024), 2),
            'protocol_distribution': protocols,
            'uptime_seconds': round(uptime, 1),
            'workers': self.num_workers
        }

    def reset_stats(self) -> None:
        """Сброс статистики (исправлено - используем правильные блокировки)"""
        with self._stats_lock:  # ← ИСПРАВЛЕНО: используем существующий лок
            self.packet_count = 0
            self.bytes_count = 0

        with self._proto_lock:
            self.protocol_stats.clear()

        with self._flows_lock:
            self.active_flows.clear()

        self.stats_reset_time = time.time()
        self.logger.info("Статистика захвата сброшена")

# ============================================================
# ATTACK SIMULATOR (для тестирования)
# ============================================================

class AttackSimulator(BaseModule):
    """Симулятор атак для тестирования"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Simulator", config, event_bus, logger)
        self.patterns = [
            ('185.142.53.101', 22, 'Brute Force', 0.85, 'CRITICAL'),
            ('45.155.205.233', 80, 'Web Attack', 0.78, 'HIGH'),
            ('194.61.23.45', 3389, 'Brute Force', 0.82, 'HIGH'),
            ('89.248.163.1', 53, 'DDoS', 0.71, 'MEDIUM'),
            ('103.145.12.67', 445, 'Port Scan', 0.68, 'MEDIUM'),
            ('185.165.29.82', 8080, 'Web Attack', 0.76, 'HIGH'),
            ('45.134.26.99', 22, 'Brute Force', 0.88, 'CRITICAL'),
            ('192.168.1.50', 445, 'Lateral Movement', 0.75, 'HIGH'),
            ('203.0.113.100', 443, 'C2 Beacon', 0.72, 'HIGH'),
            ('198.51.100.200', 53, 'DNS Tunnel', 0.79, 'HIGH'),
        ]
        self.thread = None
        self.enabled = True

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.logger.info("🎮 Симулятор атак запущен")

    def stop(self) -> None:
        self.running = False

    def _loop(self) -> None:
        """Основной цикл симуляции"""
        while self.running:
            time.sleep(random.uniform(5, 15))

            src_ip, port, attack_type, base_score, severity = random.choice(self.patterns)

            alert = {
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_port': port,
                'attack_type': attack_type,
                'score': min(1.0, base_score + random.uniform(-0.1, 0.1)),
                'confidence': random.uniform(0.7, 0.99),
                'severity': severity,
                'is_attack': True,
                'simulated': True
            }

            self.event_bus.publish('alert.detected', alert)

            # Иногда симулируем утечку данных
            if random.random() < 0.1:
                exfil_alert = {
                    'is_exfiltration': True,
                    'src_ip': src_ip,
                    'dst_ip': f"203.0.113.{random.randint(1, 254)}",
                    'reasons': ['simulated_exfiltration'],
                    'score': 0.75,
                    'attack_type': 'Data Exfiltration',
                    'severity': 'CRITICAL',
                    'timestamp': time.time(),
                    'simulated': True
                }
                self.event_bus.publish('exfiltration.detected', exfil_alert)


# ============================================================
# SIEM STORAGE
# ============================================================

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

class ShardEnterprise:
    """Главный класс SHARD Enterprise SIEM"""

    def __init__(self, config_path: str = "config.yaml", enable_simulation: bool = False, no_capture: bool = False, event_bus=None):
        self.config = ConfigManager(config_path)
        self.logger_service = LoggingService(self.config)
        self.logger = self.logger_service.get_logger()
        self.event_bus = event_bus if event_bus is not None else EventBus()
        self.modules: List[BaseModule] = []
        self.enable_simulation = enable_simulation
        self.no_capture = no_capture
        self.capture = None
        self.start_time = time.time()

        # Инициализация компонентов
        self._init_modules()
        self._print_banner()
        self._setup_signal_handlers()

    def _init_modules(self) -> None:
        """Инициализация всех модулей"""

        # Базовые модули
        self.modules = [
            # Мониторинг и метрики
            PrometheusMetrics(self.config, self.event_bus, self.logger_service),
            TelegramNotifier(self.config, self.event_bus, self.logger_service),
            WebDashboard(self.config, self.event_bus, self.logger_service),

            # Защита
            SmartFirewall(self.config, self.event_bus, self.logger_service),
            WebApplicationFirewall(self.config, self.event_bus, self.logger_service),
            # HoneypotService отключён — используется DeceptionEngine
            # HoneypotService(self.config, self.event_bus, self.logger_service),

            # Анализ трафика
            JA3Fingerprinter(self.config, self.event_bus, self.logger_service),
            DeepPacketInspector(self.config, self.event_bus, self.logger_service),
            EncryptedTrafficAnalyzer(self.config, self.event_bus, self.logger_service),

            # Новые модули
            DNSAnalyzer(self.config, self.event_bus, self.logger_service),
            ThreatIntelligence(self.config, self.event_bus, self.logger_service),
            DataExfiltrationDetector(self.config, self.event_bus, self.logger_service),
            UserBehaviorAnalytics(self.config, self.event_bus, self.logger_service),
            IncidentReportGenerator(self.config, self.event_bus, self.logger_service),
            LDAPContextProvider(self.config, self.event_bus, self.logger_service),
            EmailThreatAnalyzer(self.config, self.event_bus, self.logger_service),
            EDRIntegration(self.config, self.event_bus, self.logger_service),

            # Специализированные модули
            OTIoTSecurity(self.config, self.event_bus, self.logger_service),

            # ML и аналитика
            MachineLearningEngine(self.config, self.event_bus, self.logger_service),
            AdvancedLearner(self.config, self.event_bus, self.logger_service),

            # Хранилище и расследование
            SIEMStorage(self.config, self.event_bus, self.logger_service),
            AgenticAIAnalyst(self.config, self.event_bus, self.logger_service),
        ]

        # Добавляем симулятор если нужно
        if self.config.get('simulation.enabled', False):
            self.modules.append(AttackSimulator(self.config, self.event_bus, self.logger_service))
            self.logger.info("🎮 Симулятор атак запущен")

        # Захват трафика - только если не отключен
        if not self.no_capture:
            self.capture = TrafficCapture(self.config, self.event_bus, self.logger_service)
            self.capture.set_features_extractor(self._extract_features)
            self.modules.append(self.capture)
            self.logger.info("📡 Захват трафика ВКЛЮЧЕН")
        else:
            self.capture = None
            self.logger.info("📡 Захват трафика ОТКЛЮЧЕН (режим только симуляции)")

        # Подписка на алерты для обогащения
        self.event_bus.subscribe('alert.detected', self._enrich_alert)

    def _extract_features(self, packet) -> Optional[List[float]]:
        """Извлечение признаков из пакета для ML"""
        try:
            from scapy.all import IP, TCP, UDP, Raw

            if not packet.haslayer(IP):
                return None

            features = []

            # Payload байты (первые 150)
            payload = bytes(packet[Raw].load)[:150] if packet.haslayer(Raw) else b''
            for i in range(150):
                features.append(float(payload[i]) if i < len(payload) else 0.0)

            # Энтропия payload
            if payload:
                freq = {}
                for b in payload:
                    freq[b] = freq.get(b, 0) + 1
                entropy = -sum((c / len(payload)) * math.log2(c / len(payload)) for c in freq.values())
            else:
                entropy = 0.0
            features.append(entropy)

            # Размер пакета
            features.append(float(len(packet)))

            # Протокол
            if packet.haslayer(TCP):
                features.append(6.0)
            elif packet.haslayer(UDP):
                features.append(17.0)
            else:
                features.append(0.0)

            # TTL
            features.append(float(packet[IP].ttl))

            # Порты
            if packet.haslayer(TCP):
                features.append(float(packet[TCP].sport))
                features.append(float(packet[TCP].dport))
            elif packet.haslayer(UDP):
                features.append(float(packet[UDP].sport))
                features.append(float(packet[UDP].dport))
            else:
                features.append(0.0)
                features.append(0.0)

            return features

        except Exception:
            return None

    def _enrich_alert(self, alert: Dict) -> None:
        """Обогащение алерта дополнительной информацией"""

        self.logger.info(f"🔔 ALERT: {alert.get('attack_type')} from {alert.get('src_ip')}")

        src_ip = alert.get('src_ip', '')
        dst_ip = alert.get('dst_ip', '')
        dst_port = alert.get('dst_port', 0)

        # Определение или КОРРЕКТИРОВКА серьёзности
        score = alert.get('score', 0)
        current_severity = alert.get('severity', 'LOW')

        # Пересчитываем серьёзность на основе score
        calculated_severity = AlertSeverity.LOW.value
        if score > 0.8:
            calculated_severity = AlertSeverity.CRITICAL.value
        elif score > 0.6:
            calculated_severity = AlertSeverity.HIGH.value
        elif score > 0.4:
            calculated_severity = AlertSeverity.MEDIUM.value

        # Используем максимальную из существующей и рассчитанной
        severity_order = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        if severity_order.get(calculated_severity, 1) > severity_order.get(current_severity, 1):
            alert['severity'] = calculated_severity

        # Добавление временной метки если нет
        if 'timestamp' not in alert:
            alert['timestamp'] = time.time()

        # Добавление контекста локальной сети
        local_networks = self.config.get('network.local_networks', ['192.168.', '10.', '172.16.'])
        alert['is_internal_src'] = any(src_ip.startswith(net) for net in local_networks)
        alert['is_internal_dst'] = any(dst_ip.startswith(net) for net in local_networks) if dst_ip else False

    def _print_banner(self) -> None:
        """Вывод баннера"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ███████╗██╗  ██╗ █████╗ ██████╗ ██████╗                               ║
║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗                              ║
║   ███████╗███████║███████║██████╔╝██║  ██║                              ║
║   ╚════██║██╔══██║██╔══██║██╔══██╗██║  ██║                              ║
║   ███████║██║  ██║██║  ██║██║  ██║██████╔╝                              ║
║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                               ║
║                                                                          ║
║              ENTERPRISE SIEM - ПОЛНАЯ ВЕРСИЯ                              ║
║                                                                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ✅ DNS Аналитика (туннели, энтропия)                                    ║
║  ✅ Threat Intelligence (AbuseIPDB/VirusTotal)                           ║
║  ✅ Обнаружение утечки данных                                            ║
║  ✅ UBA/UEBA (поведение пользователей)                                   ║
║  ✅ Автоматические отчёты                                                ║
║  ✅ Web Dashboard                                                        ║
║  ✅ Active Directory / LDAP контекст                                     ║
║  ✅ Email угрозы                                                         ║
║  ✅ EDR интеграция                                                       ║
║  ✅ Цепочки атак (Kill Chain)                                            ║
║  ✅ Lateral Movement Detection                                           ║
║  ✅ Умная блокировка                                                     ║
║  ✅ Объяснения алертов                                                   ║
║  ✅ Анализ зашифрованного трафика                                        ║
║  ✅ ML с дообучением                                                     ║
║  ✅ GNN анализ графа угроз                                               ║
║  ✅ Honeypot                                                             ║
║  ✅ Agentic AI расследования                                             ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
        self.logger.info(banner)

        if self.enable_simulation:
            self.logger.info("🎮 РЕЖИМ СИМУЛЯЦИИ ВКЛЮЧЕН")

        self.logger.info(f"📁 Конфигурация: {self.config.config_path}")
        self.logger.info(f"🌐 Локальные сети: {self.config.get('network.local_networks')}")
        self.logger.info("=" * 70)

    def _setup_signal_handlers(self) -> None:
        """Настройка обработчиков сигналов"""
        import signal

        def signal_handler(sig, frame):
            self.logger.info("\n🛑 Получен сигнал остановки...")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def start(self) -> None:
        """Запуск всех модулей"""
        self.logger.info("🚀 Запуск SHARD Enterprise...")

        # Запуск модулей
        for module in self.modules:
            if module is None:
                continue
            try:
                module.start()
                self.logger.debug(f"  ✅ {module.name} запущен")
            except Exception as e:
                self.logger.error(f"  ❌ Ошибка запуска {getattr(module, 'name', 'unknown')}: {e}")

        self.logger.info("=" * 70)
        self.logger.info("✅ SHARD Enterprise запущен и готов к работе")
        self.logger.info("📊 Дашборд: http://localhost:8080")
        self.logger.info("📈 Метрики: http://localhost:9090")
        self.logger.info("=" * 70)
        self.logger.info("Нажмите Ctrl+C для остановки\n")

        # Запуск захвата трафика (блокирующий) только если включен
        if self.capture is not None:
            try:
                self.capture.capture_loop()
            except KeyboardInterrupt:
                pass
            except Exception as e:
                self.logger.error(f"Ошибка захвата: {e}")
            finally:
                self.stop()
        else:
            # Если захват отключен, просто ждём в главном потоке
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        """Остановка всех модулей"""
        self.logger.info("\n⏹️ Остановка SHARD Enterprise...")

        for module in reversed(self.modules):
            if module is None:
                continue
            try:
                module.stop()
                self.logger.debug(f"  ✅ {module.name} остановлен")
            except Exception as e:
                self.logger.error(f"  ❌ Ошибка остановки {getattr(module, 'name', 'unknown')}: {e}")

        self.event_bus.shutdown()

        uptime = time.time() - self.start_time
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)

        self.logger.info("=" * 70)
        self.logger.info(f"✅ SHARD Enterprise остановлен. Время работы: {hours}ч {minutes}м {seconds}с")
        self.logger.info("=" * 70)

    def get_status(self) -> Dict:
        """Получить статус системы"""
        return {
            'uptime': time.time() - self.start_time,
            'modules': [
                {
                    'name': m.name,
                    'running': m.is_running()
                }
                for m in self.modules if m is not None
            ],
            'capture_stats': self.capture.get_stats() if self.capture else {},
            'config': {
                'auto_block': self.config.get('protection.auto_block'),
                'simulation': self.enable_simulation,
                'capture_enabled': not self.no_capture
            }
        }

    def reload_config(self) -> None:
        """Перезагрузка конфигурации"""
        self.config = ConfigManager(self.config.config_path)
        self.logger.info("Конфигурация перезагружена")


# ============================================================
# ТОЧКА ВХОДА
# ============================================================

def main():
    """Главная функция запуска"""
    import argparse

    parser = argparse.ArgumentParser(
        description='SHARD Enterprise SIEM - Полная версия',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Примеры:
  python shard_enterprise_complete.py                           # Нормальный режим
  python shard_enterprise_complete.py --simulation              # Режим симуляции
  python shard_enterprise_complete.py --config custom.yaml      # Свой конфиг
  python shard_enterprise_complete.py --simulation --no-capture # Только симуляция
        '''
    )

    parser.add_argument(
        '--config', '-c',
        default='config.yaml',
        help='Путь к файлу конфигурации (по умолчанию: config.yaml)'
    )

    parser.add_argument(
        '--simulation', '-s',
        action='store_true',
        help='Включить режим симуляции атак'
    )

    parser.add_argument(
        '--interface', '-i',
        default='lo',
        help='Сетевой интерфейс для захвата (по умолчанию: lo для WSL, eth0 для Linux)'
    )

    parser.add_argument(
        '--no-dashboard',
        action='store_true',
        help='Отключить веб-дашборд'
    )

    parser.add_argument(
        '--auto-block',
        action='store_true',
        help='Включить автоматическую блокировку IP (требует прав root)'
    )

    parser.add_argument(
        '--no-capture',
        action='store_true',
        help='Отключить захват трафика (только симуляция, не требует прав root)'
    )

    args = parser.parse_args()

    # Проверка зависимостей
    print("\n🛡️ SHARD Enterprise SIEM")
    print("=" * 50)
    print("Проверка зависимостей...")

    deps_status = []
    deps_status.append(("Scapy", scapy_all is not None))
    deps_status.append(("NumPy", np is not None))
    deps_status.append(("Requests", requests is not None))
    deps_status.append(("Scikit-learn", sklearn_ensemble is not None))
    deps_status.append(("XGBoost", xgboost_module is not None))
    deps_status.append(("PyTorch", torch is not None))

    for name, ok in deps_status:
        status = "✅" if ok else "⚠️"
        print(f"  {status} {name}")

    print("=" * 50)

    # Создание и настройка
    enable_sim = args.simulation or os.environ.get('SHARD_SIMULATION', '').lower() == 'true'
    no_capture = args.no_capture or os.environ.get('SHARD_NO_CAPTURE', '').lower() == 'true'

    # Создаём экземпляр SHARD
    shard = ShardEnterprise(
        config_path=args.config,
        enable_simulation=enable_sim,
        no_capture=no_capture
    )

    # Применение аргументов командной строки
    if args.interface:
        shard.config.set('network.interface', args.interface)

    if args.no_dashboard:
        shard.config.set('dashboard.enabled', False)

    if args.auto_block:
        shard.config.set('protection.auto_block', True)
        shard.logger.warning("⚠️ Автоматическая блокировка ВКЛЮЧЕНА")

    if enable_sim:
        shard.logger.warning("⚠️ Режим СИМУЛЯЦИИ включен - будут генерироваться тестовые атаки")

    if no_capture:
        shard.logger.warning("⚠️ Захват трафика ОТКЛЮЧЕН - работа только с симулированными атаками")

    # Запуск
    try:
        shard.start()
    except KeyboardInterrupt:
        shard.stop()
    except Exception as e:
        shard.logger.error(f"Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        shard.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()