"""Тесты AlertBuffer — SIEM Storage"""
import time
import pytest
import sys
sys.path.insert(0, '.')
sys.path.insert(0, 'modules')

from modules.siem_storage import AlertBuffer


class TestAlertBuffer:
    """Тестирование буфера алертов"""

    def test_add_and_flush(self):
        """Добавление и сброс алертов"""
        flushed = []

        def callback(alerts):
            flushed.extend(alerts)
            return True

        buf = AlertBuffer(batch_size=3, flush_interval=10)
        assert buf.add({'alert': 1}) is False  # Не достигнут batch_size
        assert buf.add({'alert': 2}) is False
        assert buf.add({'alert': 3}) is True   # Достигнут batch_size

        buf.flush_if_needed(callback)
        assert len(flushed) == 3

    def test_flush_interval(self):
        """Сброс по таймауту"""
        flushed = []

        def callback(alerts):
            flushed.extend(alerts)
            return True

        buf = AlertBuffer(batch_size=100, flush_interval=0.1)
        buf.add({'alert': 1})
        time.sleep(0.2)

        should_flush = buf.add({'alert': 2})
        if should_flush:
            buf.flush_if_needed(callback)
        assert len(flushed) >= 1

    def test_stats(self):
        """Статистика буфера"""
        buf = AlertBuffer(batch_size=10, flush_interval=10)
        buf.add({'alert': 1})
        buf.add({'alert': 2})

        stats = buf.stats
        assert stats['buffer_size'] == 2
        assert stats['total_buffered'] == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
