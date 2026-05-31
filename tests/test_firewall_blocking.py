"""Тесты SmartFirewall — логика блокировок"""
import time
import pytest
import sys
sys.path.insert(0, '.')
sys.path.insert(0, 'modules')

from modules.firewall import SmartFirewall


class MockConfig:
    def get(self, key, default=None):
        return {
            'protection.auto_block': True,
            'protection.block_duration': 3600,
            'protection.rate_limit.threshold': 100,
            'protection.rate_limit.window': 60,
        }.get(key, default)


class MockEventBus:
    def __init__(self):
        self.events = []
    def subscribe(self, *args): pass
    def publish(self, event_type, data):
        self.events.append((event_type, data))


class MockLogger:
    def info(self, *args): pass
    def warning(self, *args): pass
    def error(self, *args): pass
    def debug(self, *args): pass
    def critical(self, *args): pass
    def get_logger(self, name=None): return self


class TestFirewallBlocking:
    """Тестирование graduated response"""

    @pytest.fixture
    def fw(self):
        return SmartFirewall(MockConfig(), MockEventBus(), MockLogger())

    def test_whitelist_add(self, fw):
        """Добавление в whitelist"""
        fw.add_to_whitelist('192.168.1.1')
        assert '192.168.1.1' in fw.whitelist

    def test_whitelist_blocks_block(self, fw):
        """Whitelist IP не блокируется"""
        fw.add_to_whitelist('192.168.1.1')
        assert fw.is_blocked('192.168.1.1') is False
        # Даже после алерта
        fw.on_alert({'src_ip': '192.168.1.1', 'severity': 'CRITICAL'})
        assert fw.is_blocked('192.168.1.1') is False

    def test_graduated_response(self, fw):
        """Градация ответа по severity"""
        fw.on_alert({'src_ip': '10.0.0.1', 'severity': 'LOW'})
        assert fw.action_levels['10.0.0.1'] == 1

        fw.on_alert({'src_ip': '10.0.0.1', 'severity': 'CRITICAL'})
        assert fw.action_levels['10.0.0.1'] == 5  # 1 + 4

    def test_exfiltration_immediate_block(self, fw):
        """Утечка данных — мгновенная блокировка"""
        eb = MockEventBus()
        fw.event_bus = eb
        fw.on_exfiltration({'src_ip': '10.0.0.99', 'score': 0.9})
        blocked_events = [e for e in eb.events if e[0] == 'firewall.blocked']
        assert len(blocked_events) >= 1

    def test_rate_limit_allows_normal(self, fw):
        """Rate limit пропускает нормальный трафик"""
        fw.add_to_whitelist('1.1.1.1')  # Для теста
        for _ in range(10):
            assert fw.check_rate_limit('1.1.1.1', 80) is True

    def test_get_status(self, fw):
        """Статус firewall"""
        fw.on_alert({'src_ip': '10.0.0.1', 'severity': 'HIGH'})
        status = fw.get_status()
        assert status['tracked_threats'] >= 1
        assert status['auto_block'] is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
