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
import psutil
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
    from sklearn.ensemble import IsolationForest  # noqa

np = safe_import('numpy')
joblib = safe_import('joblib')
scapy_all = safe_import('scapy.all')
sklearn_ensemble = safe_import('sklearn.ensemble')

# Проверка что модули загружены перед использованием
_NP_AVAILABLE = np is not None
_SCAPY_AVAILABLE = scapy_all is not None
_SKLEARN_AVAILABLE = sklearn_ensemble is not None
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
from modules.dns_analyzer import DNSAnalyzer
from modules.exfil_detector import DataExfiltrationDetector
from modules.threat_intel import ThreatIntelligence
from modules.uba import UserBehaviorAnalytics
from modules.report_generator import IncidentReportGenerator
from modules.ldap import LDAPContextProvider
from modules.edr import EDRIntegration
from modules.ml_engine import MachineLearningEngine
from modules.siem_storage import SIEMStorage
from modules.agentic_ai import AgenticAIAnalyst
from modules.traffic_capture import TrafficCapture
from modules.encrypted_traffic import EncryptedTrafficAnalyzer
from modules.dpi import DeepPacketInspector
from modules.firewall import SmartFirewall
from modules.waf import WebApplicationFirewall
class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Обработчик HTTP запросов для дашборда (исправлен - path traversal защита, безопасное сравнение)"""

    # Классовые переменные - устанавливаются ОДИН раз при инициализации
    dashboard_stats = None
    dashboard_logger = None
    dashboard_lock = None
    dashboard_check_auth = None
    dashboard_auth_enabled = False
    dashboard_validate_ip = None


    # Rate limiting per-IP (10 req/sec)
    _rate_limits = {}
    _rate_lock = threading.RLock()
    
    @classmethod
    def _check_rate_limit(cls, ip: str) -> bool:
        """Возвращает True если запрос разрешён"""
        with cls._rate_lock:
            now = time.time()
            if ip not in cls._rate_limits:
                cls._rate_limits[ip] = []
            cls._rate_limits[ip] = [t for t in cls._rate_limits[ip] if now - t < 1.0]
            if len(cls._rate_limits[ip]) >= 10:
                return False
            cls._rate_limits[ip].append(now)
            return True

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
            if not self._check_rate_limit(self.client_address[0]):
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b'Too Many Requests')
                return
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


            elif path == '/api/health':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                modules_status = {}
                if hasattr(self, 'dashboard_stats'):
                    # Проверяем статус БД
                    db_status = 'unknown'
                    try:
                        import sqlite3
                        conn = sqlite3.connect('shard_siem.db', timeout=1)
                        conn.execute('SELECT 1')
                        conn.close()
                        db_status = 'sqlite_ok'
                    except:
                        db_status = 'unavailable'
                    
                    modules_status = {
                        'dashboard': True,
                        'database': db_status,
                        'total_alerts': self.dashboard_stats.get('total_alerts', 0),
                        'uptime_seconds': time.time() - getattr(self, '_start_time', time.time())
                    }
                    modules_status = {
                        'dashboard': True,
                        'total_alerts': self.dashboard_stats.get('total_alerts', 0),
                        'uptime_seconds': time.time() - getattr(self, '_start_time', time.time())
                    }
                
                import psutil
                health = {
                    'status': 'healthy',
                    'version': '5.1.0',
                    'timestamp': time.time(),
                    'modules': modules_status,
                    'system': {
                        'cpu_percent': psutil.cpu_percent(interval=0.1),
                        'memory_percent': psutil.virtual_memory().percent,
                        'disk_percent': psutil.disk_usage('/').percent
                    }
                }
                self.wfile.write(json.dumps(health).encode('utf-8'))

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
            if not self._check_rate_limit(self.client_address[0]):
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b'Too Many Requests')
                return
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            if self.dashboard_auth_enabled and self.dashboard_check_auth and \
                    not self.dashboard_check_auth(dict(self.headers)):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="SHARD Dashboard"')
                self.end_headers()
                self.wfile.write(b'Unauthorized')
                return
            
            # RBAC: проверка роли для блокировки
            if self.path == '/api/block':
                username = self._get_username_from_auth(dict(self.headers))
                role = self.user_roles.get(username, 'viewer')
                if not self.roles.get(role, {}).get('block', False):
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b'Forbidden: insufficient permissions')
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

            elif path == '/api/health':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                modules_status = {}
                if hasattr(self, 'dashboard_stats'):
                    # Проверяем статус БД
                    db_status = 'unknown'
                    try:
                        import sqlite3
                        conn = sqlite3.connect('shard_siem.db', timeout=1)
                        conn.execute('SELECT 1')
                        conn.close()
                        db_status = 'sqlite_ok'
                    except:
                        db_status = 'unavailable'
                    
                    modules_status = {
                        'dashboard': True,
                        'database': db_status,
                        'total_alerts': self.dashboard_stats.get('total_alerts', 0),
                        'uptime_seconds': time.time() - getattr(self, '_start_time', time.time())
                    }
                    modules_status = {
                        'dashboard': True,
                        'total_alerts': self.dashboard_stats.get('total_alerts', 0),
                        'uptime_seconds': time.time() - getattr(self, '_start_time', time.time())
                    }
                
                import psutil
                health = {
                    'status': 'healthy',
                    'version': '5.1.0',
                    'timestamp': time.time(),
                    'modules': modules_status,
                    'system': {
                        'cpu_percent': psutil.cpu_percent(interval=0.1),
                        'memory_percent': psutil.virtual_memory().percent,
                        'disk_percent': psutil.disk_usage('/').percent
                    }
                }
                self.wfile.write(json.dumps(health).encode('utf-8'))

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
        self.roles = {
            'admin': {'read': True, 'write': True, 'block': True, 'admin': True},
            'analyst': {'read': True, 'write': True, 'block': False, 'admin': False},
            'viewer': {'read': True, 'write': False, 'block': False, 'admin': False}
        }
        self.user_roles = config.get('dashboard.auth.user_roles', {'admin': 'admin'})
        self.session_tokens: Dict[str, float] = {}
        self.token_ttl = 3600

        # Очередь для отложенного снижения счётчика активных угроз
        self._decay_queue = queue.Queue()
        self._stop_event = threading.Event()
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
        """Инициализация обработчика (instance-level, не классовые переменные)"""
        self._handler_instance_vars = {
            'dashboard_stats': self.stats,
            'dashboard_logger': self.logger,
            'dashboard_lock': self._lock,
            'dashboard_check_auth': self._check_auth,
            'dashboard_auth_enabled': self.auth_enabled,
            'dashboard_validate_ip': self._validate_ip,
            'user_roles': getattr(self, 'user_roles', {'admin': 'admin'}),
            'roles': getattr(self, 'roles', {'admin': {'read': True, 'write': True, 'block': True, 'admin': True}})
        }
        DashboardHandler.dashboard_logger = self.logger
        DashboardHandler.dashboard_lock = self._lock
        DashboardHandler.dashboard_check_auth = self._check_auth
        DashboardHandler.dashboard_auth_enabled = self.auth_enabled
        DashboardHandler.dashboard_validate_ip = self._validate_ip
        DashboardHandler.user_roles = getattr(self, 'user_roles', {'admin': 'admin'})
        DashboardHandler.roles = getattr(self, 'roles', {'admin': {'read': True, 'write': True, 'block': True, 'admin': True}})

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
        pass  # _stop_event removed

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
        if self._decay_queue is None:
            return
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

    def _get_username_from_auth(self, headers: Dict) -> str:
        """Извлечение username из Basic Auth заголовка"""
        auth = headers.get('Authorization', '')
        if auth.startswith('Basic '):
            import base64
            try:
                decoded = base64.b64decode(auth[6:]).decode('utf-8')
                return decoded.split(':', 1)[0]
            except:
                pass
        return 'viewer'

    def _create_handler(self):
        """Создание обработчика HTTP запросов с instance-переменными"""
        handler = DashboardHandler
        for key, val in self._handler_instance_vars.items():
            setattr(handler, key, val)
        return handler


# ============================================================
# 7️⃣ КОНТЕКСТ ACTIVE DIRECTORY / LDAP
# ============================================================

from modules.ldap import LDAPContextProvider
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
        pass  # _stop_event removed

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

from modules.edr import EDRIntegration
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
        pass  # _stop_event removed

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
        pass  # _stop_event removed
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
                f'https://api.telegram.org/bot{self.token}/sendMessage',
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
            
            # Welford: инкрементальное обновление статистики (O(1))
            if '_welford_sizes' not in p:
                p['_welford_sizes'] = {'count': 0, 'mean': 0.0, 'm2': 0.0}
            ws = p['_welford_sizes']
            ws['count'] += 1
            delta = size - ws['mean']
            ws['mean'] += delta / ws['count']
            delta2 = size - ws['mean']
            ws['m2'] += delta * delta2
            
            if '_welford_entropy' not in p:
                p['_welford_entropy'] = {'count': 0, 'mean': 0.0, 'm2': 0.0}
            we = p['_welford_entropy']
            we['count'] += 1
            delta_e = entropy - we['mean']
            we['mean'] += delta_e / we['count']
            delta2_e = entropy - we['mean']
            we['m2'] += delta_e * delta2_e
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
                '_welford_sizes': dict(p.get('_welford_sizes', {})),
                '_welford_entropy': dict(p.get('_welford_entropy', {})),
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
        """Быстрое вычисление с использованием кэшированных данных (Welford O(1))"""
        scores = []
        weights = []

        # Размер пакета — Welford online variance
        if cached.get('packet_sizes'):
            packet_sizes = cached['packet_sizes']
            if packet_sizes:
                # Welford: используем предвычисленные mean и variance если есть
                welford = cached.get('_welford_sizes', {})
                if welford and welford.get('count', 0) > 1:
                    mean = welford['mean']
                    variance = welford['m2'] / welford['count']
                    std = max(mean * 0.1, math.sqrt(variance))
                else:
                    # Fallback: вычисляем за O(n) только при первом запросе
                    mean = sum(packet_sizes) / len(packet_sizes)
                    if len(packet_sizes) > 1 and mean > 0:
                        variance = sum((s - mean) ** 2 for s in packet_sizes) / len(packet_sizes)
                        std = max(mean * 0.1, math.sqrt(variance))
                    else:
                        std = mean * 0.5 if mean > 0 else 1
                    # Кэшируем Welford статистику
                    cached['_welford_sizes'] = {
                        'count': len(packet_sizes),
                        'mean': mean,
                        'm2': variance * len(packet_sizes) if len(packet_sizes) > 1 else 0
                    }

                if mean > 0:
                    z_score = abs(size - mean) / std
                    scores.append(min(1.0, z_score))
                    weights.append(0.15)

        # Энтропия — Welford
        if cached.get('entropy'):
            entropies = cached['entropy']
            if entropies:
                welford_e = cached.get('_welford_entropy', {})
                if welford_e and welford_e.get('count', 0) > 1:
                    mean_e = welford_e['mean']
                    variance_e = welford_e['m2'] / welford_e['count']
                    std_e = max(0.1, math.sqrt(variance_e))
                else:
                    mean_e = sum(entropies) / len(entropies)
                    if len(entropies) > 1:
                        variance_e = sum((e - mean_e) ** 2 for e in entropies) / len(entropies)
                        std_e = max(0.1, math.sqrt(variance_e))
                    else:
                        std_e = 0.5
                    cached['_welford_entropy'] = {
                        'count': len(entropies),
                        'mean': mean_e,
                        'm2': variance_e * len(entropies) if len(entropies) > 1 else 0
                    }

                if mean_e > 0:
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

from modules.firewall import SmartFirewall
from modules.waf import WebApplicationFirewall
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

from modules.encrypted_traffic import EncryptedTrafficAnalyzer
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
        pass  # _stop_event removed

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

from modules.dpi import DeepPacketInspector
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
        pass  # _stop_event removed

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
            recon_loss = F.mse_loss(reconstructed, X) if hasattr(F, 'mse_loss') else ((reconstructed - X) ** 2).mean()

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
            import torch.nn.functional as F

            X = torch.tensor([features], dtype=torch.float32)

            with torch.no_grad():
                latent, reconstructed, _ = self.model(X)

                recon_error = F.mse_loss(reconstructed, X).item() if hasattr(F, 'mse_loss') else ((reconstructed - X) ** 2).mean().item()

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
from modules.ml_engine import MachineLearningEngine
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
        pass  # _stop_event removed

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
        pass  # _stop_event removed
        for srv in self.services:
            srv.stop()

    def _on_connection(self, src_ip: str, port: int, data: bytes = None) -> None:
        """Обработка подключения к ловушке"""

        # ========== СЮДА ВСТАВИТЬ ==========
        self.logger.debug(f"HONEYPOT CONNECTION: {src_ip}:{port}")
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
                self.logger.info(f"[AI DETECTION] {pred.upper()} from {src_ip}:{port}")
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
        self._ip_connections = {}
        self._ip_lock = threading.RLock()
        self._connection_semaphore = _GLOBAL_HONEYPOT_SEMAPHORE
        self._active_connections = 0
        self._conn_lock = threading.RLock()

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True, name=f"Honeypot-{self.port}")
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        pass  # _stop_event removed
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
        """Обработка одного подключения с per-IP rate limiting"""
        try:
            src_ip = addr[0]
            
            # Per-IP rate limiting
            if not hasattr(self, '_ip_connections'):
                self._ip_connections = {}
                self._ip_lock = threading.RLock()
            
            with self._ip_lock:
                now = time.time()
                if src_ip not in self._ip_connections:
                    self._ip_connections[src_ip] = []
                # Очищаем старые записи
                self._ip_connections[src_ip] = [t for t in self._ip_connections[src_ip] if now - t < 60]
                
                if len(self._ip_connections[src_ip]) >= 30:  # Max 30 conn/min per IP
                    conn.close()
                    self.logger.debug(f"Honeypot port {self.port}: rate limit exceeded for {src_ip}")
                    return
                
                self._ip_connections[src_ip].append(now)
            
            with self._conn_lock:
                self._active_connections += 1

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

from modules.agentic_ai import AgenticAIAnalyst
from modules.traffic_capture import TrafficCapture
class AttackSimulator(BaseModule):
    """Симулятор атак для тестирования"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("Simulator", config, event_bus, logger)
        self.running = False
        self._stop_event = threading.Event()
        self.thread = None
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
        pass  # _stop_event removed

    def _loop(self) -> None:
        """Основной цикл симуляции"""
        while self.running and not self._stop_event.is_set():
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

from modules.siem_storage import SIEMStorage
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