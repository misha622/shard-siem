#!/usr/bin/env python3
"""SHARD DeepPacketInspector Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import time, threading
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

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

