# tests/test_utils.py
import unittest
import tempfile
import threading
import time
import json
import os
import sys
from pathlib import Path
from collections import deque
from unittest.mock import Mock, patch, MagicMock

# Добавляем путь к исходному коду
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestEventBus(unittest.TestCase):
    """Тесты для EventBus"""

    def setUp(self):
        from shard_enterprise_complete import EventBus
        self.event_bus = EventBus()

    def test_subscribe_and_publish(self):
        """Проверка подписки и публикации"""
        received = []

        def callback(data):
            received.append(data)

        self.event_bus.subscribe('test.event', callback)
        self.event_bus.publish_sync('test.event', {'value': 42})

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]['value'], 42)

    def test_unsubscribe(self):
        """Проверка отписки"""
        received = []

        def callback(data):
            received.append(data)

        self.event_bus.subscribe('test.event', callback)
        self.event_bus.unsubscribe('test.event', callback)
        self.event_bus.publish_sync('test.event', {'value': 42})

        self.assertEqual(len(received), 0)

    def test_multiple_subscribers(self):
        """Проверка множественных подписчиков"""
        received1 = []
        received2 = []

        self.event_bus.subscribe('test.event', lambda d: received1.append(d))
        self.event_bus.subscribe('test.event', lambda d: received2.append(d))
        self.event_bus.publish_sync('test.event', {'value': 42})

        self.assertEqual(len(received1), 1)
        self.assertEqual(len(received2), 1)


class TestBaselineProfiler(unittest.TestCase):
    """Тесты для BaselineProfiler"""

    def setUp(self):
        from shard_enterprise_complete import BaselineProfiler
        self.profiler = BaselineProfiler()

    def test_update_and_get_score(self):
        """Проверка обновления профиля и получения оценки"""
        device = '192.168.1.100'

        # Добавляем нормальный трафик
        for _ in range(20):
            self.profiler.update(
                device=device,
                size=500,
                port=80,
                entropy=0.3,
                dst_ip='93.184.216.34'
            )

        # Проверяем нормальный трафик
        score = self.profiler.get_score(
            device=device,
            size=500,
            port=80,
            entropy=0.3,
            dst_ip='93.184.216.34'
        )
        self.assertLess(score, 0.5, "Нормальный трафик должен иметь низкий score")

    def test_anomaly_detection(self):
        """Проверка обнаружения аномалий"""
        device = '192.168.1.100'

        # Добавляем нормальный трафик
        for _ in range(20):
            self.profiler.update(
                device=device,
                size=500,
                port=80,
                entropy=0.3,
                dst_ip='93.184.216.34'
            )

        # Проверяем аномальный трафик
        score = self.profiler.get_score(
            device=device,
            size=50000,  # Очень большой пакет
            port=4444,  # Подозрительный порт
            entropy=0.9,  # Высокая энтропия
            dst_ip='185.142.53.101'  # Новый IP
        )
        self.assertGreater(score, 0.5, "Аномальный трафик должен иметь высокий score")

    def test_get_profile(self):
        """Проверка получения профиля"""
        device = '192.168.1.100'

        self.profiler.update(
            device=device,
            size=500,
            port=80,
            entropy=0.3,
            dst_ip='93.184.216.34'
        )

        profile = self.profiler.get_profile(device)
        self.assertIsNotNone(profile)
        self.assertGreater(profile['total_packets'], 0)


class TestAttackChainTracker(unittest.TestCase):
    """Тесты для AttackChainTracker"""

    def setUp(self):
        from shard_enterprise_complete import AttackChainTracker
        self.tracker = AttackChainTracker()

    def tearDown(self):
        self.tracker.stop()

    def test_add_event(self):
        """Проверка добавления события"""
        result = self.tracker.add_event('192.168.1.100', 'Port Scan', 0.6, 80)

        self.assertEqual(result['src_ip'], '192.168.1.100')
        self.assertEqual(result['event_count'], 1)
        self.assertEqual(result['stage'], 'reconnaissance')

    def test_chain_progression(self):
        """Проверка прогрессии цепочки атак"""
        self.tracker.add_event('192.168.1.100', 'Port Scan', 0.6, 80)
        self.tracker.add_event('192.168.1.100', 'Brute Force', 0.7, 22)
        result = self.tracker.add_event('192.168.1.100', 'Lateral Movement', 0.8, 445)

        self.assertEqual(result['event_count'], 3)
        self.assertEqual(result['stage'], 'lateral_movement')
        self.assertGreater(result['confidence'], 0.5)

    def test_get_chain(self):
        """Проверка получения цепочки"""
        self.tracker.add_event('192.168.1.100', 'Port Scan', 0.6, 80)

        chain = self.tracker.get_chain('192.168.1.100')
        self.assertIsNotNone(chain)
        self.assertEqual(chain['src_ip'], '192.168.1.100')


class TestDNSAnalyzer(unittest.TestCase):
    """Тесты для DNSAnalyzer"""

    def setUp(self):
        from shard_enterprise_complete import DNSAnalyzer, ConfigManager, EventBus, LoggingService

        self.config = ConfigManager()
        self.event_bus = EventBus()
        self.logger = LoggingService(self.config)
        self.analyzer = DNSAnalyzer(self.config, self.event_bus, self.logger)

    def test_calculate_entropy(self):
        """Проверка вычисления энтропии"""
        # Низкая энтропия
        low = self.analyzer._calculate_entropy("aaaaaa")
        # Высокая энтропия
        high = self.analyzer._calculate_entropy("xK9#mP2$qL5")

        self.assertLess(low, 3.0)
        self.assertGreater(high, 3.0)

    def test_dga_detection(self):
        """Проверка обнаружения DGA доменов"""
        # Нормальный домен
        result1 = self.analyzer._analyze_dns_query('192.168.1.100', 'google.com')
        self.assertLess(result1['score'], 0.3)

        # DGA домен (высокая энтропия)
        result2 = self.analyzer._analyze_dns_query('192.168.1.100', 'x7k9mp2ql5.xyz')
        self.assertGreater(result2['score'], 0.3)
        self.assertTrue(result2['is_suspicious'])


class TestSmartFirewall(unittest.TestCase):
    """Тесты для SmartFirewall"""

    def setUp(self):
        from shard_enterprise_complete import SmartFirewall, ConfigManager, EventBus, LoggingService

        self.config = ConfigManager()
        self.config.set('protection.auto_block', True)
        self.event_bus = EventBus()
        self.logger = LoggingService(self.config)
        self.firewall = SmartFirewall(self.config, self.event_bus, self.logger)

    def test_validate_ip_strict(self):
        """Проверка валидации IP"""
        valid_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '8.8.8.8']
        invalid_ips = ['256.1.1.1', '1.1.1', 'abc.def.ghi.jkl', '1.1.1.1; rm -rf /']

        for ip in valid_ips:
            self.assertTrue(self.firewall._validate_ip_strict(ip), f"IP должен быть валидным: {ip}")

        for ip in invalid_ips:
            self.assertFalse(self.firewall._validate_ip_strict(ip), f"IP должен быть невалидным: {ip}")

    def test_whitelist(self):
        """Проверка белого списка"""
        ip = '192.168.1.100'
        self.firewall.add_to_whitelist(ip)

        # Проверяем что IP в whitelist не блокируется
        result = self.firewall.block_ip(ip, 60)
        self.assertFalse(result)

        # Удаляем из whitelist
        self.firewall.remove_from_whitelist(ip)


class TestWebApplicationFirewall(unittest.TestCase):
    """Тесты для WAF"""

    def setUp(self):
        from shard_enterprise_complete import WebApplicationFirewall, ConfigManager, EventBus, LoggingService

        self.config = ConfigManager()
        self.event_bus = EventBus()
        self.logger = LoggingService(self.config)
        self.waf = WebApplicationFirewall(self.config, self.event_bus, self.logger)

    def test_sqli_detection(self):
        """Проверка обнаружения SQL инъекций"""
        payloads = [
            "' OR '1'='1",
            "1; SELECT * FROM users",
            "1' UNION SELECT password FROM users--",
            "1 AND SLEEP(5)"
        ]

        for payload in payloads:
            result = self.waf._analyze_text(payload, 'test')
            self.assertTrue(result['is_attack'], f"Должен обнаружить SQLi: {payload}")

    def test_xss_detection(self):
        """Проверка обнаружения XSS"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)"
        ]

        for payload in payloads:
            result = self.waf._analyze_text(payload, 'test')
            self.assertTrue(result['is_attack'], f"Должен обнаружить XSS: {payload}")

    def test_path_traversal(self):
        """Проверка обнаружения Path Traversal"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "/etc/passwd%00"
        ]

        for payload in payloads:
            result = self.waf._analyze_text(payload, 'test')
            self.assertTrue(result['is_attack'], f"Должен обнаружить Path Traversal: {payload}")


class TestThreatIntelligence(unittest.TestCase):
    """Тесты для ThreatIntelligence"""

    def setUp(self):
        from shard_enterprise_complete import ThreatIntelligence, ConfigManager, EventBus, LoggingService

        self.config = ConfigManager()
        self.event_bus = EventBus()
        self.logger = LoggingService(self.config)
        self.ti = ThreatIntelligence(self.config, self.event_bus, self.logger)

    def test_is_public_ip(self):
        """Проверка определения публичных IP"""
        public_ips = ['8.8.8.8', '1.1.1.1', '93.184.216.34']
        private_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '127.0.0.1']

        for ip in public_ips:
            self.assertTrue(self.ti._is_public_ip(ip), f"Должен быть публичным: {ip}")

        for ip in private_ips:
            self.assertFalse(self.ti._is_public_ip(ip), f"Не должен быть публичным: {ip}")

    def test_local_lists(self):
        """Проверка локальных списков"""
        # Добавляем IP в блок-лист
        self.ti.add_to_local_blocklist('203.0.113.1', 'test')

        # Проверяем
        result = self.ti._check_local_lists('203.0.113.1')
        self.assertTrue(result['is_malicious'])
        self.assertGreater(result['score'], 0.5)

        # Удаляем
        self.ti.remove_from_local_blocklist('203.0.113.1')


class TestDataExfiltrationDetector(unittest.TestCase):
    """Тесты для DataExfiltrationDetector"""

    def setUp(self):
        from shard_enterprise_complete import DataExfiltrationDetector, ConfigManager, EventBus, LoggingService

        self.config = ConfigManager()
        self.event_bus = EventBus()
        self.logger = LoggingService(self.config)
        self.detector = DataExfiltrationDetector(self.config, self.event_bus, self.logger)

    def test_normal_traffic(self):
        """Проверка нормального трафика"""
        # Имитация нормального трафика
        for _ in range(10):
            self.detector._analyze_outbound_traffic(
                src_ip='192.168.1.100',
                dst_ip='93.184.216.34',
                dst_port=443,
                bytes_count=1000,
                packet=None
            )

        stats = self.detector.get_stats('192.168.1.100')
        self.assertLess(stats.get('suspicious_score', 1.0), 0.3)


def run_tests():
    """Запуск всех тестов"""
    # Создаём test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Добавляем все тесты
    suite.addTests(loader.loadTestsFromTestCase(TestEventBus))
    suite.addTests(loader.loadTestsFromTestCase(TestBaselineProfiler))
    suite.addTests(loader.loadTestsFromTestCase(TestAttackChainTracker))
    suite.addTests(loader.loadTestsFromTestCase(TestDNSAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestSmartFirewall))
    suite.addTests(loader.loadTestsFromTestCase(TestWebApplicationFirewall))
    suite.addTests(loader.loadTestsFromTestCase(TestThreatIntelligence))
    suite.addTests(loader.loadTestsFromTestCase(TestDataExfiltrationDetector))

    # Запускаем
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)