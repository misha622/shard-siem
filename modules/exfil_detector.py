#!/usr/bin/env python3
"""SHARD DataExfiltrationDetector Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import time, threading, re
from typing import Dict, Tuple, List, Optional, Any
from collections import defaultdict, deque

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

from modules.uba import UserBehaviorAnalytics
