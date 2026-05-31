"""Тесты AttackChainTracker + LateralMovementDetector"""
import time
import pytest
import sys
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location("sec", "shard_enterprise_complete.py")
sec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sec)

AttackChainTracker = sec.AttackChainTracker
LateralMovementDetector = sec.LateralMovementDetector


class TestAttackChainTracker:
    """Цепочки атак (Kill Chain)"""

    @pytest.fixture
    def tracker(self):
        return AttackChainTracker()

    def test_add_event(self, tracker):
        """Добавление события в цепочку"""
        result = tracker.add_event('10.0.0.1', 'Port Scan', 0.6, 22)
        assert result['event_count'] == 1
        assert result['stage'] == 'reconnaissance'

    def test_multiple_events(self, tracker):
        """Несколько событий — эскалация"""
        tracker.add_event('10.0.0.1', 'Port Scan', 0.6)
        tracker.add_event('10.0.0.1', 'Brute Force', 0.8)
        result = tracker.add_event('10.0.0.1', 'Data Exfiltration', 0.9)
        assert result['event_count'] == 3
        assert result['stage'] == 'exfiltration'
        assert result['severity'] in ['MEDIUM', 'HIGH', 'CRITICAL']

    def test_get_chain(self, tracker):
        """Получение цепочки по IP"""
        tracker.add_event('10.0.0.1', 'C2 Beacon', 0.7)
        chain = tracker.get_chain('10.0.0.1')
        assert chain is not None
        assert chain['stage'] == 'command_and_control'

    def test_get_active_chains(self, tracker):
        """Активные цепочки"""
        tracker.add_event('10.0.0.1', 'Port Scan', 0.6)
        tracker.add_event('10.0.0.2', 'DDoS', 0.9)
        active = tracker.get_active_chains(min_severity='LOW')
        assert len(active) >= 2

    def test_reset_chain(self, tracker):
        """Сброс цепочки"""
        tracker.add_event('10.0.0.1', 'Port Scan', 0.6)
        assert tracker.reset_chain('10.0.0.1') is True
        assert tracker.get_chain('10.0.0.1') is None

    def test_get_stats(self, tracker):
        """Статистика цепочек"""
        tracker.add_event('10.0.0.1', 'Port Scan', 0.6)
        stats = tracker.get_stats()
        assert stats['total_chains'] >= 1

    def test_stop(self, tracker):
        """Остановка очистки"""
        tracker.stop()
        assert tracker._running is False


class TestLateralMovementDetector:
    """Обнаружение Lateral Movement"""

    @pytest.fixture
    def detector(self):
        return LateralMovementDetector(local_networks=['192.168.', '10.', '172.16.'])

    def test_is_local(self, detector):
        """Проверка локальных IP"""
        assert detector.is_local('192.168.1.1') is True
        assert detector.is_local('10.0.0.1') is True
        assert detector.is_local('8.8.8.8') is False

    def test_add_connection(self, detector):
        """Добавление внутреннего соединения"""
        result = detector.add_connection('192.168.1.1', '192.168.1.2', 445)
        assert result is not None
        assert result['type'] == 'lateral_movement'
        assert 'SMB' in str(result['service'])

    def test_ignore_external(self, detector):
        """Игнорирование внешних соединений"""
        result = detector.add_connection('8.8.8.8', '1.1.1.1', 80)
        assert result is None

    def test_suspicious_port_detection(self, detector):
        """Детекция подозрительных портов"""
        result = detector.add_connection('192.168.1.1', '192.168.1.2', 3389)
        assert result is not None
        assert result['score'] > 0.3


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
