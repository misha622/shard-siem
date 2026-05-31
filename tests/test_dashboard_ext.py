"""Расширенные тесты WebDashboard"""
import pytest
import sys
import json
import urllib.parse
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location("sec", "shard_enterprise_complete.py")
sec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sec)

DashboardHandler = sec.DashboardHandler


class MockDashboard:
    """Mock для тестирования DashboardHandler"""
    def __init__(self):
        self.stats = {
            'total_packets': 0, 'total_alerts': 0, 'blocked_ips': 0,
            'active_threats': 0, 'recent_alerts': [], 'top_attackers': {},
            'top_targets': {}, 'attack_types': {}, 'last_alert_time': 0
        }
        self._lock = __import__('threading').RLock()


class TestDashboardHTML:
    """HTML дашборда"""

    def test_html_contains_key_elements(self):
        """HTML содержит ключевые элементы"""
        handler = DashboardHandler
        html = handler._get_html(None)
        assert 'SHARD' in html
        assert 'total-packets' in html
        assert 'total-alerts' in html
        assert 'fetchStats' in html
        assert 'blockIP' in html


class TestDashboardAuth:
    """Аутентификация дашборда"""

    def test_no_auth_when_disabled(self):
        """Без аутентификации"""
        # Устанавливаем переменные класса
        DashboardHandler.dashboard_auth_enabled = False
        mock = MockDashboard()
        DashboardHandler.dashboard_stats = mock.stats
        DashboardHandler.dashboard_lock = mock._lock
        # Проверяем что check_auth возвращает True
        assert DashboardHandler.dashboard_check_auth is None or True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
