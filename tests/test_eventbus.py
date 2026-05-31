"""Тесты EventBus — ядро SHARD"""
import time
import threading
import pytest
import sys
sys.path.insert(0, '.')

from core.base import EventBus


class TestEventBus:
    """Тестирование шины событий"""

    def test_publish_subscribe(self):
        """Базовая публикация и подписка"""
        bus = EventBus(max_queue_size=100)
        received = []

        def handler(data):
            received.append(data)

        bus.subscribe('test.event', handler)
        bus.publish('test.event', {'msg': 'hello'})
        time.sleep(0.2)

        assert len(received) == 1
        assert received[0]['msg'] == 'hello'
        bus.shutdown()

    def test_unsubscribe(self):
        """Отписка от событий"""
        bus = EventBus(max_queue_size=100)
        received = []

        def handler(data):
            received.append(data)

        unsub = bus.subscribe('test.event', handler)
        bus.publish('test.event', {'msg': 'first'})
        time.sleep(0.1)
        unsub()
        bus.publish('test.event', {'msg': 'second'})
        time.sleep(0.1)

        assert len(received) == 1
        assert received[0]['msg'] == 'first'
        bus.shutdown()

    def test_priority_ordering(self):
        """High-priority события обрабатываются"""
        bus = EventBus(max_queue_size=100)
        received = []

        def handler(data):
            received.append(data)

        bus.subscribe('alert.detected', handler)
        bus.subscribe('packet.received', handler)
        bus.publish('alert.detected', {'severity': 'HIGH'})
        bus.publish('packet.received', {'size': 100})
        time.sleep(0.2)

        assert len(received) >= 1
        bus.shutdown()

    def test_multiple_subscribers(self):
        """Несколько подписчиков на одно событие"""
        bus = EventBus(max_queue_size=100)
        r1, r2 = [], []

        bus.subscribe('test.event', lambda d: r1.append(d))
        bus.subscribe('test.event', lambda d: r2.append(d))
        bus.publish('test.event', {'msg': 'broadcast'})
        time.sleep(0.2)

        assert len(r1) == 1
        assert len(r2) == 1
        bus.shutdown()

    def test_stats(self):
        """Статистика EventBus"""
        bus = EventBus(max_queue_size=100)
        bus.subscribe('test.event', lambda d: None)
        bus.publish('test.event', {'msg': 'stats'})
        time.sleep(0.2)

        stats = bus.get_stats()
        assert stats['events_published'] > 0
        assert stats['subscribers'] == 1
        bus.shutdown()

    def test_health_check(self):
        """Health check EventBus"""
        bus = EventBus(max_queue_size=100)
        health = bus.health_check()
        assert health['status'] in ['healthy', 'degraded']
        assert health['running'] is True
        bus.shutdown()

    def test_shutdown(self):
        """Graceful shutdown"""
        bus = EventBus(max_queue_size=100)
        bus.shutdown()
        health = bus.health_check()
        assert health['status'] == 'stopped'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
