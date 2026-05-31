"""Тесты SecurityValidator — безопасность CLI"""
import pytest
import sys
from pathlib import Path
sys.path.insert(0, '.')

# Импортируем из run_shard.py
import importlib.util
spec = importlib.util.spec_from_file_location("run_shard", "run_shard.py")
run_shard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_shard)

SecurityValidator = run_shard.SecurityValidator
SecurityValidationError = run_shard.SecurityValidationError
SecurityContext = run_shard.SecurityContext


class TestSecurityValidator:
    """Тестирование валидатора безопасности"""

    def test_validate_ip_valid(self):
        """Валидация корректных IP"""
        assert SecurityValidator.validate_ip_address('192.168.1.1', allow_private=True) == '192.168.1.1'
        result = SecurityValidator.validate_ip_address('8.8.8.8')
        assert result is not None

    def test_validate_ip_private_blocked(self):
        """Приватные IP блокируются по умолчанию"""
        with pytest.raises(SecurityValidationError):
            SecurityValidator.validate_ip_address('10.0.0.1')

    def test_validate_ip_private_allowed(self):
        """Приватные IP разрешены с allow_private"""
        assert SecurityValidator.validate_ip_address('10.0.0.1', allow_private=True) == '10.0.0.1'

    def test_validate_ip_loopback_blocked(self):
        """Loopback блокируется"""
        with pytest.raises(SecurityValidationError):
            SecurityValidator.validate_ip_address('127.0.0.1')

    def test_validate_cve_valid(self):
        """Валидация CVE ID"""
        assert SecurityValidator.validate_cve_id('CVE-2021-44228') == 'CVE-2021-44228'

    def test_validate_cve_invalid(self):
        """Невалидный CVE ID"""
        with pytest.raises(SecurityValidationError):
            SecurityValidator.validate_cve_id('invalid')

    def test_validate_file_path(self, tmp_path):
        """Валидация пути к файлу"""
        test_file = tmp_path / 'test.txt'
        test_file.write_text('test')
        ctx = SecurityContext(allowed_paths={tmp_path})
        result = SecurityValidator.validate_file_path(str(test_file), ctx)
        assert result == test_file.resolve()

    def test_validate_file_path_blocked(self, tmp_path):
        """Блокировка пути вне разрешённых директорий"""
        test_file = tmp_path / 'test.txt'
        test_file.write_text('test')
        # Создаём контекст с путём, который точно не совпадает
        ctx = SecurityContext(allowed_paths={Path('/nonexistent/path')})
        with pytest.raises(SecurityValidationError):
            SecurityValidator.validate_file_path(str(test_file), ctx)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
