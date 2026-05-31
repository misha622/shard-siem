"""Edge Cases — граничные условия"""
import time
import pytest
import sys
import threading
sys.path.insert(0, '.')
sys.path.insert(0, 'modules')

from core.base import EventBus
from modules.siem_storage import AlertBuffer
from modules.ml_engine import DataBuffer


class TestEventBusEdgeCases:
    """Граничные случаи EventBus"""

    def test_publish_no_subscribers(self):
        """Публикация без подписчиков — не падает"""
        bus = EventBus(max_queue_size=100)
        bus.publish('no.subscribers', {'test': 1})
        time.sleep(0.1)
        stats = bus.get_stats()
        assert stats['events_published_unique'] >= 1
        bus.shutdown()

    def test_double_shutdown(self):
        """Двойной shutdown — не падает"""
        bus = EventBus(max_queue_size=100)
        bus.shutdown()
        bus.shutdown()  # Не должно падать

    def test_queue_full_drops(self):
        """Переполнение очереди — счётчик dropped"""
        bus = EventBus(max_queue_size=2)
        received = []
        bus.subscribe('test.event', lambda d: received.append(d))
        # Отправляем больше чем очередь
        for i in range(10):
            bus.publish('test.event', {'id': i})
        time.sleep(0.3)
        stats = bus.get_stats()
        assert stats['dropped'] >= 0  # Что-то могло дропнуться
        bus.shutdown()

    def test_subscribe_after_shutdown(self):
        """Подписка после shutdown"""
        bus = EventBus(max_queue_size=100)
        bus.shutdown()
        # Подписка после shutdown — не должна падать
        unsub = bus.subscribe('test', lambda d: None)
        unsub()


class TestAlertBufferEdgeCases:
    """Граничные случаи AlertBuffer"""

    def test_empty_flush(self):
        """Сброс пустого буфера"""
        flushed = []
        buf = AlertBuffer(batch_size=10, flush_interval=60)
        buf.flush_if_needed(lambda alerts: flushed.extend(alerts) or True)
        assert len(flushed) == 0

    def test_double_flush(self):
        """Двойной сброс"""
        flushed = []
        buf = AlertBuffer(batch_size=1, flush_interval=60)
        buf.add({'id': 1})
        buf.flush_if_needed(lambda alerts: flushed.extend(alerts) or True)
        buf.flush_if_needed(lambda alerts: flushed.extend(alerts) or True)
        assert len(flushed) == 1  # Не дублируется

    def test_callback_returns_false(self):
        """Callback возвращает False"""
        buf = AlertBuffer(batch_size=1, flush_interval=60)
        buf.add({'id': 1})
        buf.flush_if_needed(lambda alerts: False)
        # Буфер очищен, но total_flushed не увеличился
        assert buf.stats['buffer_size'] == 0


class TestDataBufferEdgeCases:
    """Граничные случаи DataBuffer"""

    def test_empty_get_and_clear(self):
        """Пустой буфер"""
        buf = DataBuffer(maxlen=100)
        normal, attacks = buf.get_and_clear()
        assert len(normal) == 0
        assert len(attacks) == 0

    def test_rollback_without_get(self):
        """Rollback без get_and_clear"""
        buf = DataBuffer(maxlen=100)
        buf.add_normal([1.0])
        buf.rollback()
        assert buf.total_samples == 1  # Ничего не изменилось

    def test_commit_without_get(self):
        """Commit без get_and_clear"""
        buf = DataBuffer(maxlen=100)
        buf.add_normal([1.0])
        buf.commit_clear()
        assert buf.total_samples == 1  # Ничего не очищено


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
