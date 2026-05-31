"""Тесты HoneypotService + Dashboard rate limiting"""
import time
import pytest
import sys
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location("sec", "shard_enterprise_complete.py")
sec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sec)

DashboardHandler = sec.DashboardHandler


class TestDashboardRateLimit:
    """Rate limiting дашборда"""

    def test_rate_limit_allows_first_requests(self):
        """Первые запросы разрешены"""
        # Сбрасываем состояние
        DashboardHandler._rate_limits = {}
        for _ in range(10):
            assert DashboardHandler._check_rate_limit('10.0.0.1') is True

    def test_rate_limit_blocks_after_threshold(self):
        """11-й запрос блокируется"""
        DashboardHandler._rate_limits = {}
        for _ in range(10):
            DashboardHandler._check_rate_limit('10.0.0.2')
        assert DashboardHandler._check_rate_limit('10.0.0.2') is False

    def test_rate_limit_resets_after_second(self):
        """Сброс через секунду"""
        DashboardHandler._rate_limits = {}
        for _ in range(10):
            DashboardHandler._check_rate_limit('10.0.0.3')
        time.sleep(1.1)
        assert DashboardHandler._check_rate_limit('10.0.0.3') is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
