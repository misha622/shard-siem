"""Тесты DataBuffer — ML Engine"""
import pytest
import sys
sys.path.insert(0, '.')
sys.path.insert(0, 'modules')

from modules.ml_engine import DataBuffer


class TestDataBuffer:
    """Тестирование буфера обучающих данных"""

    def test_add_normal(self):
        """Добавление нормальных сэмплов"""
        buf = DataBuffer(maxlen=100)
        buf.add_normal([1.0, 2.0, 3.0])
        buf.add_normal([4.0, 5.0, 6.0])
        assert buf.total_samples == 2

    def test_add_attack(self):
        """Добавление атакующих сэмплов"""
        buf = DataBuffer(maxlen=100)
        buf.add_attack([1.0, 2.0], 'DoS')
        buf.add_attack([3.0, 4.0], 'DDoS')
        assert buf.total_samples == 2

    def test_get_and_clear(self):
        """Атомарное получение и очистка"""
        buf = DataBuffer(maxlen=100)
        buf.add_normal([1.0])
        buf.add_attack([2.0], 'DoS')

        normal, attacks = buf.get_and_clear()
        assert len(normal) == 1
        assert len(attacks) == 1
        # После get_and_clear буфер должен быть пуст
        assert buf.total_samples == 0

    def test_commit_clear(self):
        """Подтверждение очистки"""
        buf = DataBuffer(maxlen=100)
        buf.add_normal([1.0])
        buf.get_and_clear()
        buf.commit_clear()
        assert buf.total_samples == 0

    def test_rollback(self):
        """Откат при ошибке обучения"""
        buf = DataBuffer(maxlen=100)
        buf.add_normal([1.0, 2.0])
        buf.add_attack([3.0, 4.0], 'DoS')

        normal, attacks = buf.get_and_clear()
        assert buf.total_samples == 0
        buf.rollback()
        assert buf.total_samples == 2

    def test_stats(self):
        """Статистика буфера"""
        buf = DataBuffer(maxlen=100)
        buf.add_normal([1.0])
        buf.add_attack([2.0], 'DoS')

        stats = buf.stats
        assert stats['normal_count'] == 1
        assert stats['attack_count'] == 1
        assert stats['total'] == 2

    def test_maxlen(self):
        """Ограничение размера буфера"""
        buf = DataBuffer(maxlen=10)
        for i in range(20):
            buf.add_normal([float(i)])
        assert buf.total_samples <= 10


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
