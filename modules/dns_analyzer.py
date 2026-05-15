#!/usr/bin/env python3
"""SHARD DNS Analyzer Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
from shard_enterprise_complete import AttackType, AlertSeverity, DNSThresholds
import time, threading, math, re
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

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

from modules.threat_intel import ThreatIntelligence
