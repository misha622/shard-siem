"""Расширенные тесты SecurityValidator"""
import pytest
import sys
from pathlib import Path
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location("run_shard", "run_shard.py")
run_shard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_shard)

SecurityValidator = run_shard.SecurityValidator
SecurityValidationError = run_shard.SecurityValidationError
SecurityContext = run_shard.SecurityContext


class TestSecurityValidatorExtended:
    """Расширенная валидация безопасности"""

    def test_validate_ip_multicast_blocked(self):
        """Multicast адреса блокируются"""
        with pytest.raises(SecurityValidationError):
            SecurityValidator.validate_ip_address('224.0.0.1')

    def test_validate_ip_loopback_blocked(self):
        """Loopback блокируется"""
        with pytest.raises(SecurityValidationError):
            SecurityValidator.validate_ip_address('::1')

    def test_validate_file_size_limit(self, tmp_path):
        """Ограничение размера файла"""
        test_file = tmp_path / 'big.txt'
        test_file.write_text('x' * (101 * 1024 * 1024))  # 101 MB
        ctx = SecurityContext(max_file_size_mb=100, allowed_paths={tmp_path})
        with pytest.raises(SecurityValidationError):
            SecurityValidator.validate_file_path(str(test_file), ctx)

    def test_validate_path_traversal_blocked(self, tmp_path):
        """Path traversal блокируется"""
        ctx = SecurityContext(allowed_paths={tmp_path})
        with pytest.raises(SecurityValidationError):
            SecurityValidator.validate_file_path(str(tmp_path / '../etc/passwd'), ctx)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
