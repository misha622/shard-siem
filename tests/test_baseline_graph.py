"""Тесты BaselineProfiler + ThreatGraphNetwork"""
import time
import pytest
import sys
sys.path.insert(0, '.')

# Импорт из shard_enterprise_complete
import importlib.util
spec = importlib.util.spec_from_file_location("sec", "shard_enterprise_complete.py")
sec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sec)

BaselineProfiler = sec.BaselineProfiler
ThreatGraphNetwork = sec.ThreatGraphNetwork


class TestBaselineProfiler:
    """Профилировщик базового поведения"""

    @pytest.fixture
    def bp(self):
        return BaselineProfiler()

    def test_update_creates_profile(self, bp):
        """Создание профиля при первом обновлении"""
        bp.update('device1', 100, 80, 2.5, '10.0.0.1', '192.168.1.1')
        profile = bp.get_profile('device1')
        assert profile is not None
        assert profile['total_packets'] == 1

    def test_score_low_for_normal(self, bp):
        """Низкий score для нормального трафика"""
        for _ in range(100):
            bp.update('device1', 500, 80, 2.5, '10.0.0.1')
        score = bp.get_score('device1', 500, 80, 2.5, '10.0.0.1')
        assert score < 0.5

    def test_score_high_for_anomaly(self, bp):
        """Высокий score для аномального трафика"""
        for _ in range(100):
            bp.update('device1', 500, 80, 2.5, '10.0.0.1')
        # Аномальный пакет — другой порт, большой размер
        score = bp.get_score('device1', 9999, 99999, 8.0, '99.99.99.99')
        assert score > 0.3  # Частично аномальный

    def test_get_all_devices(self, bp):
        """Список всех устройств"""
        bp.update('device1', 100, 80, 2.5)
        bp.update('device2', 200, 443, 3.0)
        devices = bp.get_all_devices()
        assert len(devices) == 2
        assert 'device1' in devices

    def test_reset_profile(self, bp):
        """Сброс профиля"""
        bp.update('device1', 100, 80, 2.5)
        assert bp.reset_profile('device1') is True
        assert bp.get_profile('device1') is None

    def test_summary_stats(self, bp):
        """Общая статистика"""
        bp.update('d1', 100, 80, 2.5)
        bp.update('d2', 200, 443, 3.0)
        stats = bp.get_summary_stats()
        assert stats['total_devices'] == 2
        assert stats['total_packets'] == 2


class TestThreatGraphNetwork:
    """Граф угроз"""

    @pytest.fixture
    def tg(self):
        return ThreatGraphNetwork()

    def test_add_edge(self, tg):
        """Добавление ребра"""
        tg.add_edge('192.168.1.1', '10.0.0.1', weight=0.8)
        assert '192.168.1.1' in tg.graph
        assert '10.0.0.1' in tg.graph

    def test_mark_attack(self, tg):
        """Отметка атаки"""
        tg.add_edge('attacker', 'victim')
        tg.mark_attack('attacker', 0.9, 'DDoS')
        assert tg.graph['attacker']['risk'] > 0

    def test_propagate_risk(self, tg):
        """Распространение риска"""
        tg.add_edge('a', 'b')
        tg.mark_attack('a', 0.9)
        scores = tg.propagate_risk(iterations=5)
        assert scores['a'] > 0
        assert 'b' in scores

    def test_get_stats(self, tg):
        """Статистика графа"""
        tg.add_edge('a', 'b')
        tg.add_edge('b', 'c')
        stats = tg.get_stats()
        assert stats['total_nodes'] == 3
        assert stats['total_edges'] == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
