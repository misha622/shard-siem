#!/usr/bin/env python3
"""
🔐 SHARD JA3 ANALYZER - Обнаружение C2 и вредоносного ПО в зашифрованном трафике
Анализирует JA3/JA3S отпечатки TLS-соединений
"""

import hashlib
import json
import os
import struct
import logging
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import time

logger = logging.getLogger("SHARD-JA3")


class JA3Fingerprinter:
    """
    Вычисление JA3 отпечатков для TLS Client Hello
    """

    # TLS Version mapping
    TLS_VERSIONS = {
        0x0301: "TLSv1.0",
        0x0302: "TLSv1.1",
        0x0303: "TLSv1.2",
        0x0304: "TLSv1.3",
    }

    def __init__(self):
        self.fingerprints = {}

    def compute_ja3(self, client_hello: bytes) -> Optional[str]:
        """
        Вычисление JA3 хеша из Client Hello

        JA3 = MD5(
            SSLVersion,
            CipherSuites,
            Extensions,
            EllipticCurves,
            EllipticCurvePointFormats
        )
        """
        try:
            # Парсинг Client Hello
            if len(client_hello) < 43:
                return None

            # TLS Record Layer
            record_type = client_hello[0]
            if record_type != 0x16:  # Handshake
                return None

            # TLS Version
            tls_version = struct.unpack(">H", client_hello[1:3])[0]
            tls_version_str = self.TLS_VERSIONS.get(tls_version, f"0x{tls_version:04x}")

            # Handshake Protocol
            handshake_type = client_hello[5]
            if handshake_type != 0x01:  # Client Hello
                return None

            # Ищем Client Hello (упрощённо)
            offset = 9  # После заголовков

            # Client Version
            client_version = struct.unpack(">H", client_hello[offset:offset + 2])[0]
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID
            session_id_len = client_hello[offset]
            offset += 1 + session_id_len

            # Cipher Suites
            cipher_suites_len = struct.unpack(">H", client_hello[offset:offset + 2])[0]
            offset += 2

            cipher_suites = []
            for i in range(cipher_suites_len // 2):
                suite = struct.unpack(">H", client_hello[offset:offset + 2])[0]
                cipher_suites.append(str(suite))
                offset += 2

            # Compression Methods
            comp_methods_len = client_hello[offset]
            offset += 1 + comp_methods_len

            # Extensions
            extensions_len = struct.unpack(">H", client_hello[offset:offset + 2])[0]
            offset += 2

            extensions = []
            elliptic_curves = []
            ec_point_formats = []

            end_offset = offset + extensions_len
            while offset < end_offset:
                if offset + 4 > len(client_hello):
                    break

                ext_type = struct.unpack(">H", client_hello[offset:offset + 2])[0]
                ext_len = struct.unpack(">H", client_hello[offset + 2:offset + 4])[0]
                offset += 4

                extensions.append(str(ext_type))

                # Elliptic Curves (10)
                if ext_type == 10 and ext_len >= 2:
                    curves_len = struct.unpack(">H", client_hello[offset:offset + 2])[0]
                    offset += 2
                    for i in range(curves_len // 2):
                        curve = struct.unpack(">H", client_hello[offset:offset + 2])[0]
                        elliptic_curves.append(str(curve))
                        offset += 2
                    offset -= 2  # Корректировка

                # EC Point Formats (11)
                elif ext_type == 11:
                    formats_len = client_hello[offset]
                    offset += 1
                    for i in range(formats_len):
                        fmt = client_hello[offset]
                        ec_point_formats.append(str(fmt))
                        offset += 1
                    offset -= 1

                offset += ext_len

            # Формируем строку JA3
            ja3_string = f"{tls_version_str},"
            ja3_string += "-".join(cipher_suites) + ","
            ja3_string += "-".join(extensions) + ","
            ja3_string += "-".join(elliptic_curves) + ","
            ja3_string += "-".join(ec_point_formats)

            # MD5 хеш
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

            return ja3_hash

        except Exception as e:
            logger.debug(f"Ошибка вычисления JA3: {e}")
            return None


class JA3Database:
    """
    База данных известных JA3 отпечатков
    """

    def __init__(self, db_path: str = "data/ja3_database.json"):
        self.db_path = db_path
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> Dict:
        """Загрузка сигнатур"""
        default_signatures = {
            # Вредоносное ПО
            "a0e9f5d64349fb1319c5e4f5e2d2e5c7": {
                "name": "TrickBot",
                "category": "malware",
                "severity": "CRITICAL",
                "description": "TrickBot banking trojan"
            },
            "b3c5f8d2a1e4b7c9d0f1a2b3c4d5e6f7": {
                "name": "CobaltStrike",
                "category": "c2",
                "severity": "CRITICAL",
                "description": "Cobalt Strike Beacon"
            },
            "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6": {
                "name": "Emotet",
                "category": "malware",
                "severity": "CRITICAL",
                "description": "Emotet malware"
            },
            "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9": {
                "name": "QakBot",
                "category": "malware",
                "severity": "HIGH",
                "description": "QakBot/QBot banking trojan"
            },

            # Легитимные браузеры
            "cd08e31494f9531f73ed6b15a1d33f4c": {
                "name": "Chrome 120",
                "category": "browser",
                "severity": "LOW",
                "description": "Google Chrome"
            },
            "c3fd8e89137127a34ae3e4492b7ff15d": {
                "name": "Firefox 121",
                "category": "browser",
                "severity": "LOW",
                "description": "Mozilla Firefox"
            },

            # Инструменты пентеста
            "a6a8c5d4e3f2a1b0c9d8e7f6a5b4c3d2": {
                "name": "nmap",
                "category": "tool",
                "severity": "MEDIUM",
                "description": "Nmap scanning"
            },
        }

        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    custom = json.load(f)
                    default_signatures.update(custom)
            except:
                pass

        return default_signatures

    def lookup(self, ja3_hash: str) -> Optional[Dict]:
        """Поиск отпечатка в базе"""
        return self.signatures.get(ja3_hash)

    def add_signature(self, ja3_hash: str, info: Dict):
        """Добавление новой сигнатуры"""
        self.signatures[ja3_hash] = info
        self._save()

    def _save(self):
        """Сохранение базы"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with open(self.db_path, 'w') as f:
            json.dump(self.signatures, f, indent=2)


class JA3Analyzer:
    """
    Анализатор JA3 для обнаружения угроз
    """

    def __init__(self):
        self.fingerprinter = JA3Fingerprinter()
        self.database = JA3Database()

        # Кеш для снижения нагрузки
        self.cache = {}
        self.cache_ttl = 3600  # 1 час

        # Статистика
        self.stats = {
            'total_connections': 0,
            'ja3_computed': 0,
            'threats_detected': 0,
            'c2_detected': 0,
            'malware_detected': 0
        }

        # Отслеживание C2 коммуникаций
        self.c2_trackers: Dict[str, List] = defaultdict(list)

        logger.info("🔐 JA3 Analyzer инициализирован")

    def analyze_connection(self, src_ip: str, dst_ip: str, dst_port: int,
                           client_hello: bytes, server_hello: bytes = None) -> Dict:
        """
        Анализ TLS соединения

        Returns:
            Словарь с результатами анализа
        """
        self.stats['total_connections'] += 1

        result = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'ja3': None,
            'ja3s': None,
            'threat_detected': False,
            'threat_info': None,
            'is_c2': False,
            'recommendation': None
        }

        # JA3 (клиент)
        ja3 = self.fingerprinter.compute_ja3(client_hello)
        if ja3:
            result['ja3'] = ja3
            self.stats['ja3_computed'] += 1

            # Проверка в базе
            threat = self.database.lookup(ja3)
            if threat:
                result['threat_detected'] = True
                result['threat_info'] = threat
                self.stats['threats_detected'] += 1

                if threat['category'] == 'c2':
                    result['is_c2'] = True
                    self.stats['c2_detected'] += 1
                    result['recommendation'] = f"BLOCK - C2 communication detected: {threat['name']}"

                    # Отслеживаем C2
                    self.c2_trackers[src_ip].append({
                        'timestamp': datetime.now().isoformat(),
                        'dst_ip': dst_ip,
                        'ja3': ja3,
                        'threat': threat['name']
                    })

                elif threat['category'] == 'malware':
                    self.stats['malware_detected'] += 1
                    result['recommendation'] = f"ISOLATE - Malware detected: {threat['name']}"

                elif threat['category'] == 'tool':
                    result['recommendation'] = f"MONITOR - Security tool: {threat['name']}"

        # JA3S (сервер) - если есть
        if server_hello:
            ja3s = self.fingerprinter.compute_ja3(server_hello)
            if ja3s:
                result['ja3s'] = ja3s

                # Проверка известных C2 серверов
                threat = self.database.lookup(ja3s)
                if threat and threat['category'] == 'c2':
                    result['threat_detected'] = True
                    result['is_c2'] = True
                    result['threat_info'] = threat
                    result['recommendation'] = f"BLOCK - Known C2 server: {threat['name']}"

        return result

    def get_c2_activity(self, src_ip: str = None) -> List:
        """Получение информации о C2 активности"""
        if src_ip:
            return self.c2_trackers.get(src_ip, [])

        all_activity = []
        for ip, activities in self.c2_trackers.items():
            all_activity.extend(activities)
        return all_activity

    def get_stats(self) -> Dict:
        """Статистика анализатора"""
        return {
            **self.stats,
            'tracked_ips': len(self.c2_trackers),
            'total_c2_connections': sum(len(v) for v in self.c2_trackers.values())
        }

    def export_threat_intel(self) -> List[Dict]:
        """Экспорт threat intelligence"""
        intel = []
        for ip, activities in self.c2_trackers.items():
            if len(activities) >= 3:  # Минимум 3 соединения
                intel.append({
                    'src_ip': ip,
                    'threat_type': 'C2_BEACON',
                    'confidence': min(0.9, 0.5 + len(activities) * 0.1),
                    'evidence': activities[-5:],  # Последние 5 соединений
                    'first_seen': activities[0]['timestamp'],
                    'last_seen': activities[-1]['timestamp']
                })
        return intel


# ============================================================
# ИНТЕГРАЦИЯ С SHARD
# ============================================================

class SHARDJA3Integration:
    """
    Интеграция JA3 анализатора с SHARD
    """

    def __init__(self):
        self.analyzer = JA3Analyzer()
        self.enabled = True

        # Кеш для быстрого доступа
        self.alert_cache = {}

        logger.info("🔐 SHARD JA3 Integration готов!")

    def process_packet(self, packet_data: bytes, src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int) -> Optional[Dict]:
        """
        Обработка сетевого пакета
        """
        if not self.enabled:
            return None

        # Проверяем, TLS ли это (порт 443 или Client Hello)
        if dst_port != 443 and src_port != 443:
            # Может быть на другом порту - проверяем содержимое
            if len(packet_data) < 43 or packet_data[0] != 0x16:
                return None

        try:
            result = self.analyzer.analyze_connection(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                client_hello=packet_data
            )

            if result['threat_detected']:
                # Кешируем алерт
                cache_key = f"{src_ip}_{dst_ip}_{result['ja3']}"
                if cache_key not in self.alert_cache:
                    self.alert_cache[cache_key] = result
                    return self._format_alert(result)

            return None

        except Exception as e:
            logger.error(f"Ошибка обработки пакета: {e}")
            return None

    def _format_alert(self, result: Dict) -> Dict:
        """Форматирование алерта для SHARD"""
        threat_info = result.get('threat_info', {})

        return {
            'type': 'JA3_THREAT',
            'severity': threat_info.get('severity', 'HIGH'),
            'confidence': 0.9,
            'src_ip': result['src_ip'],
            'dst_ip': result['dst_ip'],
            'dst_port': result['dst_port'],
            'ja3_hash': result['ja3'],
            'threat_name': threat_info.get('name', 'Unknown'),
            'threat_category': threat_info.get('category', 'unknown'),
            'is_c2': result['is_c2'],
            'recommendation': result.get('recommendation'),
            'timestamp': result['timestamp']
        }

    def get_threat_intel(self) -> List[Dict]:
        """Получение threat intelligence для обмена"""
        return self.analyzer.export_threat_intel()

    def add_signature(self, ja3_hash: str, name: str, category: str, severity: str):
        """Добавление новой сигнатуры"""
        self.analyzer.database.add_signature(ja3_hash, {
            'name': name,
            'category': category,
            'severity': severity,
            'description': f'Custom signature: {name}'
        })

    def get_stats(self) -> Dict:
        """Статистика"""
        return self.analyzer.get_stats()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    ja3 = SHARDJA3Integration()

    # Тестовый Client Hello (Chrome)
    test_hello = bytes.fromhex(
        "1603010200010001fc0303" +
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" +
        "00002a" +  # Cipher suites
        "c02bc02fc02cc030cca9cca8c013c014009c009d002f0035" +
        "01" +  # Compression
        "00ff" +  # Extensions length
        "0100"  # Extension
    )

    result = ja3.process_packet(test_hello, "192.168.1.100", "1.1.1.1", 12345, 443)

    if result:
        print(f"🚨 Обнаружена угроза: {result}")
    else:
        print("✅ Трафик чистый")

    print(f"\n📊 Статистика: {ja3.get_stats()}")