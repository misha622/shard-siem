"""Тесты Federated Learning — Byzantine Resilience + DP"""
import pytest
import sys
import numpy as np
sys.path.insert(0, '.')

from shard_federated import ByzantineResilience, SecureFederatedConfig, DifferentialPrivacyEngine


class TestByzantineResilience:
    """Византийская устойчивость"""

    @pytest.fixture
    def br(self):
        config = SecureFederatedConfig()
        config.byzantine_threshold = 2
        config.byzantine_m = 3
        return ByzantineResilience(config)

    def test_median_aggregation(self, br):
        """Медианная агрегация"""
        updates = [
            [np.array([1.0, 2.0, 3.0])],
            [np.array([2.0, 3.0, 4.0])],
            [np.array([100.0, 200.0, 300.0])],  # Byzantine!
        ]
        result = br.aggregate_median(updates)
        assert abs(result[0][0] - 2.0) < 0.01  # Медиана 1,2,100 = 2

    def test_trimmed_mean(self, br):
        """Trimmed Mean агрегация"""
        updates = [
            [np.array([1.0, 2.0])],
            [np.array([2.0, 3.0])],
            [np.array([3.0, 4.0])],
            [np.array([100.0, 200.0])],  # Выброс
            [np.array([-50.0, -100.0])],  # Выброс
        ]
        result = br.aggregate_trimmed_mean(updates, trim_ratio=0.2)
        # Среднее без крайних: (2.0 + 3.0) / 2 = 2.5
        assert 1.5 < result[0][0] < 3.5

    def test_multi_krum(self, br):
        """Multi-Krum выбирает честных клиентов"""
        updates = [
            [np.array([1.0])] for _ in range(10)
        ]
        updates.append([np.array([999.0])])  # Byzantine
        result = br.aggregate_multi_krum(updates, f=1, m=3)
        assert abs(result[0][0] - 1.0) < 0.1


class TestDifferentialPrivacy:
    """Differential Privacy"""

    @pytest.fixture
    def dp(self):
        config = SecureFederatedConfig()
        config.dp_noise_multiplier = 0.01
        config.dp_l2_norm_clip = 1.0
        return DifferentialPrivacyEngine(config)

    def test_clip_gradients(self, dp):
        """Клиппинг градиентов"""
        grads = [np.array([10.0, 20.0, 30.0])]
        clipped = dp.clip_gradients(grads)
        assert np.linalg.norm(clipped[0]) <= np.linalg.norm(grads[0])

    def test_add_noise(self, dp):
        """Добавление шума"""
        grads = [np.array([1.0, 1.0, 1.0])]
        noisy = dp.add_noise(grads)
        # Шум добавлен — значения изменились
        assert not np.array_equal(noisy[0], grads[0])

    def test_privacy_budget(self, dp):
        """Privacy budget tracking"""
        budget = dp.get_privacy_budget()
        assert 'epsilon' in budget
        assert 'budget_remaining' in budget
        assert dp.can_continue_training() is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
