"""Полное тестирование WebDashboard"""
import time
import json
import pytest
import sys
import threading
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location("sec", "shard_enterprise_complete.py")
sec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sec)

WebDashboard = sec.WebDashboard
DashboardHandler = sec.DashboardHandler


class MockConfig:
    def get(self, key, default=None):
        defaults = {
            'dashboard.port': 8080,
            'dashboard.enabled': True,
            'dashboard.auth.enabled': True,
            'dashboard.auth.username': 'admin',
            'dashboard.auth.password': 'test',
            'dashboard.auth.api_keys': [],
            'dashboard.ssl.enabled': False,
        }
        return defaults.get(key, default)


class MockEventBus:
    def subscribe(self, *args): pass


class MockLogger:
    def info(self, *args): pass
    def warning(self, *args): pass
    def error(self, *args): pass
    def debug(self, *args): pass
    def critical(self, *args): pass
    def get_logger(self, name=None): return self


class TestWebDashboard:
    """WebDashboard — полное покрытие"""

    @pytest.fixture
    def dash(self):
        return WebDashboard(MockConfig(), MockEventBus(), MockLogger())

    def test_init(self, dash):
        """Инициализация"""
        assert dash.enabled is True
        assert dash.port == 8080
        assert dash.auth_enabled is True

    def test_generate_default_password(self, dash):
        """Генерация пароля"""
        pwd = dash._generate_default_password()
        assert len(pwd) == 22  # token_urlsafe(16)

    def test_validate_ip(self, dash):
        """Валидация IP"""
        assert dash._validate_ip('192.168.1.1') is True
        assert dash._validate_ip('1.1.1.1;rm') is False
        assert dash._validate_ip('') is False

    def test_check_auth_valid(self, dash):
        """Проверка аутентификации"""
        import base64
        creds = base64.b64encode(b'admin:test').decode()
        assert dash._check_auth({'Authorization': f'Basic {creds}'}) is True

    def test_check_auth_invalid(self, dash):
        """Неверные креды"""
        import base64
        creds = base64.b64encode(b'admin:wrong').decode()
        assert dash._check_auth({'Authorization': f'Basic {creds}'}) is False

    def test_check_auth_no_header(self, dash):
        """Без заголовка"""
        assert dash._check_auth({}) is False

    def test_check_auth_bearer_invalid(self, dash):
        """Bearer token невалидный"""
        assert dash._check_auth({'Authorization': 'Bearer invalid'}) is False

    def test_on_packet(self, dash):
        """Обработка пакета"""
        dash.on_packet({'count': 5})
        with dash._lock:
            assert dash.stats['total_packets'] == 5

    def test_on_alert(self, dash):
        """Обработка алерта"""
        alert = {
            'src_ip': '10.0.0.1',
            'dst_ip': '192.168.1.1',
            'attack_type': 'DDoS',
            'score': 0.9,
            'severity': 'CRITICAL',
            'timestamp': time.time()
        }
        dash.on_alert(alert)
        with dash._lock:
            assert dash.stats['total_alerts'] == 1
            assert dash.stats['top_attackers']['10.0.0.1'] == 1

    def test_on_block(self, dash):
        """Обработка блокировки"""
        dash.on_block({'ip': '10.0.0.1'})
        with dash._lock:
            assert dash.stats['blocked_ips'] == 1

    def test_reset_stats(self, dash):
        """Сброс статистики"""
        dash.on_alert({'src_ip': '1.1.1.1', 'attack_type': 'Test', 'score': 0.5})
        dash.reset_stats()
        with dash._lock:
            assert dash.stats['total_alerts'] == 0

    def test_get_status(self, dash):
        """Статус дашборда"""
        status = dash.get_status()
        assert status['enabled'] is True
        assert 'port' in status
        assert 'stats' in status

    def test_start_stop(self, dash):
        """Запуск и остановка"""
        dash.start()
        assert dash.running is True
        dash.stop()
        assert dash.running is False

    def test_check_auth_disabled(self, dash):
        """Без аутентификации"""
        dash.auth_enabled = False
        assert dash._check_auth({}) is True

    def test_init_handler_class(self, dash):
        """Инициализация обработчика"""
        dash._init_handler_class()
        assert DashboardHandler.dashboard_stats is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
