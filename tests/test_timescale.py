"""Тесты TimescaleDB Storage backend"""
import time
import pytest
import sys
sys.path.insert(0, '.')
sys.path.insert(0, 'modules')

from modules.siem_storage import TimescaleStorage


class MockConfig:
    def __init__(self, dsn=''):
        self._dsn = dsn
    def get(self, key, default=None):
        if key == 'storage.timescaledb.dsn':
            return self._dsn
        if key == 'storage.timescaledb.pool_min':
            return 2
        if key == 'storage.timescaledb.pool_max':
            return 5
        return default


class MockLogger:
    def info(self, *args): pass
    def error(self, *args): pass
    def warning(self, *args): pass
    def debug(self, *args): pass
    def critical(self, *args): pass


class TestTimescaleStorage:
    """TimescaleDB бэкенд — unit tests без реальной БД"""

    def test_initialize_without_dsn(self):
        """Инициализация без DSN — возвращает False"""
        config = MockConfig(dsn='')
        ts = TimescaleStorage(config, MockLogger())
        assert ts.initialize() is False

    def test_initialize_without_psycopg2(self):
        """Без psycopg2 — возвращает False"""
        config = MockConfig(dsn='postgresql://test')
        ts = TimescaleStorage(config, MockLogger())
        # psycopg2 не установлен в тестовом окружении — должен вернуть False
        assert ts.initialize() is False

    def test_store_alerts_empty(self):
        """Пустой список алертов — возвращает True"""
        config = MockConfig(dsn='postgresql://test')
        ts = TimescaleStorage(config, MockLogger())
        assert ts.store_alerts([]) is True

    def test_store_alerts_no_pool(self):
        """Store без пула — возвращает False"""
        config = MockConfig(dsn='postgresql://test')
        ts = TimescaleStorage(config, MockLogger())
        ts.pool = None
        assert ts.store_alerts([{'test': 1}]) is False

    def test_query_alerts_validation(self):
        """Валидация параметров запроса"""
        config = MockConfig(dsn='postgresql://test')
        ts = TimescaleStorage(config, MockLogger())
        # Невалидный IP
        assert ts.query_alerts(src_ip='invalid') == []
        # Лимит вне диапазона
        assert ts.query_alerts(limit=2000) == []

    def test_get_stats_no_pool(self):
        """Статистика без пула"""
        config = MockConfig(dsn='postgresql://test')
        ts = TimescaleStorage(config, MockLogger())
        ts.pool = None
        stats = ts.get_stats(hours=24)
        assert 'error' in stats

    def test_query_ips_by_user_validation(self):
        """Валидация username"""
        config = MockConfig(dsn='postgresql://test')
        ts = TimescaleStorage(config, MockLogger())
        assert ts.query_ips_by_user('') == []

    def test_close_no_pool(self):
        """Закрытие без пула — не падает"""
        config = MockConfig(dsn='postgresql://test')
        ts = TimescaleStorage(config, MockLogger())
        ts.pool = None
        ts.close()  # Не должно падать

    def test_validate_ip(self):
        """Валидация IP"""
        config = MockConfig(dsn='postgresql://test')
        ts = TimescaleStorage(config, MockLogger())
        assert ts._validate_ip('192.168.1.1') is True
        assert ts._validate_ip('999.1.1.1') is False
        assert ts._validate_ip('') is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
