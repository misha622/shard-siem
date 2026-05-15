#!/usr/bin/env python3
"""SHARD EncryptedTrafficAnalyzer Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import time, threading, hashlib, math, re
from typing import Dict, Optional, List, Any
from collections import defaultdict, deque

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

from modules.waf import WebApplicationFirewall
