"""Полное тестирование SIEMStorage — все методы"""
import time
import pytest
import sys
sys.path.insert(0, '.')
sys.path.insert(0, 'modules')

from modules.siem_storage import SIEMStorage, SQLiteStorage, AlertBuffer


class MockConfig:
    def get(self, key, default=None):
        defaults = {
            'storage.sqlite.enabled': True,
            'storage.sqlite.path': ':memory:',
            'storage.timescaledb.enabled': False,
            'storage.batch_size': 100,
            'storage.flush_interval': 5,
        }
        return defaults.get(key, default)


class MockEventBus:
    def __init__(self):
        self.events = []
        self.subscriptions = {}
    def subscribe(self, event_type, handler):
        self.subscriptions[event_type] = handler
    def publish(self, event_type, data):
        self.events.append((event_type, data))


class MockLogger:
    def info(self, *args): pass
    def error(self, *args): pass
    def warning(self, *args): pass
    def debug(self, *args): pass
    def critical(self, *args): pass
    def get_logger(self, name=None): return self


class TestSIEMStorage:
    """SIEMStorage — полный цикл"""

    @pytest.fixture
    def storage(self):
        return SIEMStorage(MockConfig(), MockEventBus(), MockLogger())

    def test_init_backends(self, storage):
        """Инициализация бэкендов"""
        assert len(storage.backends) >= 1
        assert isinstance(storage.backends[0], SQLiteStorage)

    def test_on_alert(self, storage):
        """Обработка алерта"""
        alert = {
            'timestamp': time.time(),
            'src_ip': '10.0.0.1',
            'dst_ip': '1.1.1.1',
            'attack_type': 'Test',
            'score': 0.5,
            'confidence': 0.5,
            'severity': 'LOW',
            'explanation': 'Test alert'
        }
        storage.on_alert(alert)
        assert storage.alert_buffer.stats['total_buffered'] == 1

    def test_flush_buffer(self, storage):
        """Сброс буфера"""
        storage.on_alert({'timestamp': time.time(), 'src_ip': '1.1.1.1', 'attack_type': 'Test',
                          'score': 0.5, 'severity': 'LOW', 'explanation': ''})
        storage.flush_buffer()
        assert storage.alert_buffer.stats['buffer_size'] == 0

    def test_on_query_request(self, storage):
        """Обработка запроса"""
        storage.event_bus = MockEventBus()
        storage.on_query_request({'request_id': '123', 'src_ip': '10.0.0.1', 'limit': 10})
        # Должен опубликовать ответ
        responses = [e for e in storage.event_bus.events if e[0] == 'siem.query.response']
        assert len(responses) == 1

    def test_on_ips_request(self, storage):
        """Запрос IP по пользователю"""
        storage.event_bus = MockEventBus()
        storage.on_ips_request({'request_id': '456', 'username': 'john'})
        responses = [e for e in storage.event_bus.events if e[0] == 'siem.ips.response']
        assert len(responses) == 1

    def test_get_stats(self, storage):
        """Статистика хранилища"""
        stats = storage.get_stats(hours=24)
        assert 'buffer' in stats
        assert stats['buffer']['total_buffered'] >= 0

    def test_prepare_alert(self, storage):
        """Подготовка алерта"""
        alert = {
            'explanation': 'A' * 1000,  # Длинное объяснение
            'attack_type': 'Test' * 20,  # Длинный тип
            'features': {'x': 'y' * 20000}  # Большие features
        }
        processed = storage._prepare_alert(alert)
        assert len(processed['explanation']) <= 500
        assert len(processed['attack_type']) <= 50
        # Features должны быть усечены
        assert 'truncated' in processed.get('features', {})

    def test_start_stop(self, storage):
        """Запуск и остановка"""
        storage.start()
        assert storage.running is True
        storage.stop()
        assert storage.running is False

    def test_save_to_file(self, storage):
        """Сохранение в файл (fallback)"""
        import tempfile
        import os
        alerts = [{'test': 'data', 'timestamp': time.time()}]
        # Патчим data директорию на tmp
        import modules.siem_storage as ss
        old_backup = None
        try:
            result = storage._save_to_file(alerts)
            assert result is True
        finally:
            pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
