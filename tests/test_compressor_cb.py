"""Тесты Model Compressor + Circuit Breaker"""
import pytest
import sys
import numpy as np
sys.path.insert(0, '.')

from shard_federated import ModelCompressor, CircuitBreaker


class TestModelCompressor:
    """Квантование и сжатие моделей"""

    def test_quantize_dequantize(self):
        """Квантование и восстановление"""
        weights = np.random.randn(100).astype(np.float32)
        quantized, scale, zp = ModelCompressor.quantize_weights(weights, bits=8)
        restored = ModelCompressor.dequantize_weights(quantized, scale, zp)
        # Восстановленные веса близки к оригиналу
        assert np.allclose(weights, restored, atol=0.1)

    def test_prune_weights(self):
        """Прунинг весов"""
        weights = np.array([0.01, 0.5, 0.02, 0.8, 0.03])
        pruned = ModelCompressor.prune_weights(weights, sparsity=0.4)
        # 40% наименьших весов = 2 из 5 обнулены
        zero_count = np.sum(pruned == 0)
        assert zero_count >= 1

    def test_compression_ratio(self):
        """Коэффициент сжатия"""
        original = np.random.randn(1000).astype(np.float32)
        quantized, _, _ = ModelCompressor.quantize_weights(original, bits=8)
        ratio = ModelCompressor.compression_ratio(original, quantized)
        assert ratio > 3.0  # float32 → int8 = ~4x сжатие


class TestCircuitBreaker:
    """Circuit Breaker"""

    def test_initial_state(self):
        cb = CircuitBreaker()
        assert cb.state == 'CLOSED'
        assert cb.allow_request() is True

    def test_opens_after_failures(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == 'OPEN'
        assert cb.allow_request() is False

    def test_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0)
        cb.record_failure()
        assert cb.allow_request() is True  # HALF_OPEN
        assert cb.state == 'HALF_OPEN'

    def test_closes_after_success(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0, half_open_max_requests=1)
        cb.record_failure()
        cb.allow_request()
        cb.record_success()
        assert cb.state == 'CLOSED'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
