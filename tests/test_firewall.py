"""Тесты SmartFirewall"""
import pytest
import sys
sys.path.insert(0, '.')
sys.path.insert(0, 'modules')

from modules.firewall import SmartFirewall


class TestFirewallValidation:
    """Тестирование валидации IP и портов"""

    @pytest.fixture
    def fw(self):
        """Фикстура с минимальным firewall"""
        class MockConfig:
            def get(self, key, default=None):
                defaults = {
                    'protection.auto_block': False,
                    'protection.block_duration': 3600,
                    'protection.rate_limit.threshold': 100,
                    'protection.rate_limit.window': 60,
                }
                return defaults.get(key, default)

        class MockEventBus:
            def subscribe(self, *args): pass
            def publish(self, *args): pass

        class MockLogger:
            def info(self, *args): pass
            def warning(self, *args): pass
            def error(self, *args): pass
            def debug(self, *args): pass
            def critical(self, *args): pass
            def get_logger(self, name=None): return self

        return SmartFirewall(MockConfig(), MockEventBus(), MockLogger())

    def test_validate_ip_valid(self, fw):
        """Валидация корректного IP"""
        assert fw._validate_ip('192.168.1.1') is True
        assert fw._validate_ip('10.0.0.1') is True
        assert fw._validate_ip('8.8.8.8') is True

    def test_validate_ip_invalid(self, fw):
        """Валидация некорректного IP"""
        assert fw._validate_ip('256.1.1.1') is False
        assert fw._validate_ip('1.1.1') is False
        assert fw._validate_ip('abc.def.ghi.jkl') is False
        assert fw._validate_ip('') is False
        assert fw._validate_ip(None) is False

    def test_validate_ip_command_injection(self, fw):
        """Защита от command injection"""
        assert fw._validate_ip('1.1.1.1; rm -rf /') is False
        assert fw._validate_ip('1.1.1.1`id`') is False
        assert fw._validate_ip('1.1.1.1$(whoami)') is False

    def test_validate_port_valid(self, fw):
        """Валидация корректного порта"""
        assert fw._validate_port(80) is True
        assert fw._validate_port(443) is True
        assert fw._validate_port(65535) is True

    def test_validate_port_invalid(self, fw):
        """Валидация некорректного порта"""
        assert fw._validate_port(0) is False
        assert fw._validate_port(65536) is False
        assert fw._validate_port(-1) is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
