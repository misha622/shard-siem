#!/usr/bin/env python3
"""SHARD TrafficCapture Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import os, time, threading, queue
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque

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

