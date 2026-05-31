"""Интеграционный тест — EventBus → Alert → Storage"""
import time
import pytest
import sys
import os
sys.path.insert(0, '.')
sys.path.insert(0, 'modules')

from core.base import EventBus
from modules.siem_storage import AlertBuffer


class TestIntegrationPipeline:
    """End-to-end: EventBus → обработчик → AlertBuffer"""

    def test_eventbus_to_alertbuffer(self):
        """Полный путь алерта"""
        bus = EventBus(max_queue_size=100)
        buf = AlertBuffer(batch_size=5, flush_interval=60)
        received = []

        def alert_handler(alert):
            buf.add(alert)

        bus.subscribe('alert.detected', alert_handler)

        # Отправляем алерты
        for i in range(5):
            bus.publish('alert.detected', {
                'timestamp': time.time(),
                'src_ip': f'10.0.0.{i}',
                'attack_type': 'Test',
                'score': 0.9,
                'severity': 'HIGH'
            })

        time.sleep(0.3)

        # Сбрасываем буфер
        def collect(alerts):
            received.extend(alerts)
            return True

        buf.flush_if_needed(collect)
        assert len(received) == 5
        bus.shutdown()

    def test_multiple_event_types(self):
        """Разные типы событий"""
        bus = EventBus(max_queue_size=100)
        alerts = []
        blocks = []

        bus.subscribe('alert.detected', lambda d: alerts.append(d))
        bus.subscribe('firewall.blocked', lambda d: blocks.append(d))

        bus.publish('alert.detected', {'type': 'alert'})
        bus.publish('firewall.blocked', {'type': 'block'})
        time.sleep(0.2)

        assert len(alerts) == 1
        assert len(blocks) == 1
        bus.shutdown()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
