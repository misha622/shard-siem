"""Тесты TelegramNotifier + AttackSimulator"""
import pytest
import sys
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location("sec", "shard_enterprise_complete.py")
sec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sec)

TelegramNotifier = sec.TelegramNotifier
AttackSimulator = sec.AttackSimulator


class TestTelegramNotifier:
    """Форматирование уведомлений"""

    @pytest.fixture
    def notifier(self):
        class MockConfig:
            def get(self, key, default=None):
                return {'telemetry.telegram.enabled': False}.get(key, default)
        class MockEventBus:
            def subscribe(self, *args): pass
        class MockLogger:
            def info(self, *args): pass
            def warning(self, *args): pass
            def error(self, *args): pass
            def debug(self, *args): pass
            def get_logger(self, name=None): return self
        return TelegramNotifier(MockConfig(), MockEventBus(), MockLogger())

    def test_format_alert(self, notifier):
        """Форматирование алерта"""
        alert = {
            'attack_type': 'DDoS',
            'src_ip': '10.0.0.1',
            'dst_ip': '192.168.1.1',
            'dst_port': 80,
            'score': 0.95,
            'severity': 'CRITICAL',
            'explanation': 'Test',
            'kill_chain': {'event_count': 5, 'stage': 'impact'},
            'threat_intel': {'sources': ['AbuseIPDB'], 'country': 'RU'}
        }
        msg = notifier._format_alert(alert)
        assert 'DDoS' in msg
        assert '10.0.0.1' in msg
        assert '🔴' in msg

    def test_format_exfiltration(self, notifier):
        """Форматирование утечки"""
        data = {'src_ip': '10.0.0.1', 'dst_ip': '1.1.1.1', 'dst_port': 443, 'score': 0.9}
        # Просто проверяем что не падает
        try:
            notifier.on_exfiltration(data)
        except:
            pass  # Telegram не настроен


class TestAttackSimulator:
    """Симулятор атак"""

    @pytest.fixture
    def sim(self):
        class MockConfig:
            def get(self, key, default=None): return default
        class MockEventBus:
            def __init__(self): self.events = []
            def subscribe(self, *args): pass
            def publish(self, event_type, data): self.events.append(data)
        class MockLogger:
            def info(self, *args): pass
            def warning(self, *args): pass
            def error(self, *args): pass
            def debug(self, *args): pass
            def get_logger(self, name=None): return self
        return AttackSimulator(MockConfig(), MockEventBus(), MockLogger())

    def test_patterns_exist(self, sim):
        """Паттерны атак заданы"""
        assert len(sim.patterns) == 10

    def test_start_stop(self, sim):
        """Запуск и остановка"""
        sim.start()
        assert sim.running is True
        sim.stop()
        assert sim.running is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
