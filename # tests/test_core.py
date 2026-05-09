# tests/test_core.py
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shard_enterprise_complete import (
    ConfigManager, EventBus, LoggingService, AttackType, AlertSeverity
)


class TestConfigManager(unittest.TestCase):
    def setUp(self):
        self.config = ConfigManager('config.yaml')

    def test_get_existing_key(self):
        self.assertEqual(self.config.get('dashboard.port'), 8080)

    def test_get_nonexistent_key(self):
        self.assertIsNone(self.config.get('nonexistent.key'))

    def test_get_with_default(self):
        self.assertEqual(self.config.get('nonexistent.key', 'default'), 'default')


class TestEventBus(unittest.TestCase):
    def setUp(self):
        self.event_bus = EventBus()

    def test_subscribe_and_publish(self):
        received = []

        def callback(data):
            received.append(data)

        self.event_bus.subscribe('test.event', callback)
        self.event_bus.publish_sync('test.event', {'value': 42})

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]['value'], 42)

    def test_unsubscribe(self):
        received = []

        def callback(data):
            received.append(data)

        self.event_bus.subscribe('test.event', callback)
        self.event_bus.unsubscribe('test.event', callback)
        self.event_bus.publish_sync('test.event', {'value': 42})

        self.assertEqual(len(received), 0)


class TestAttackType(unittest.TestCase):
    def test_from_string(self):
        self.assertEqual(AttackType.from_string('Port Scan'), AttackType.PORT_SCAN)
        self.assertEqual(AttackType.from_string('Unknown'), AttackType.UNKNOWN)

    def test_eq_string(self):
        self.assertTrue(AttackType.BRUTE_FORCE == 'Brute Force')
        self.assertFalse(AttackType.PORT_SCAN == 'Web Attack')


if __name__ == '__main__':
    unittest.main()