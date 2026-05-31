"""Тесты JA3 Fingerprinter"""
import pytest
import sys
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location("sec", "shard_enterprise_complete.py")
sec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sec)

JA3Fingerprinter = sec.JA3Fingerprinter


class TestJA3Fingerprinter:
    """JA3 фингерпринтинг"""

    @pytest.fixture
    def ja3(self):
        class MockConfig:
            def get(self, key, default=None): return default
        class MockEventBus:
            def subscribe(self, *args): pass
        class MockLogger:
            def info(self, *args): pass
            def warning(self, *args): pass
            def error(self, *args): pass
            def debug(self, *args): pass
            def get_logger(self, name=None): return self
        return JA3Fingerprinter(MockConfig(), MockEventBus(), MockLogger())

    def test_malicious_ja3_known(self, ja3):
        """Известные вредоносные JA3"""
        assert len(ja3.MALICIOUS_JA3) >= 8
        assert 'Trickbot' in str(ja3.MALICIOUS_JA3.values())
        assert 'CobaltStrike' in str(ja3.MALICIOUS_JA3.values())

    def test_is_malicious_detection(self, ja3):
        """Детекция вредоносного JA3"""
        for hash_val, (name, severity) in ja3.MALICIOUS_JA3.items():
            is_mal, n, s = ja3._is_malicious(hash_val)
            assert is_mal is True
            assert n == name
            break

    def test_clean_ja3(self, ja3):
        """Чистый JA3 не детектится"""
        is_mal, _, _ = ja3._is_malicious('clean_hash_12345')
        assert is_mal is False

    def test_add_malicious_ja3(self, ja3):
        """Добавление вредоносного JA3"""
        ja3.add_malicious_ja3('test_hash', 'TestMalware', 'MEDIUM')
        assert 'test_hash' in ja3.MALICIOUS_JA3


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
