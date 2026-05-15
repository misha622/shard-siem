#!/usr/bin/env python3
"""SHARD WebApplicationFirewall Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import time, threading, re, json
from typing import Dict, List, Set, Tuple
from collections import defaultdict, deque
from pathlib import Path

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

