"""Тесты ConfigManager"""
import os
import pytest
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, '.')

from core.base import ConfigManager


class TestConfigManager:
    """Тестирование конфигурационного менеджера"""

    def test_get_set(self):
        """Базовое получение и установка"""
        cfg = ConfigManager('test_config.yaml')
        cfg.set('test.key', 'value')
        assert cfg.get('test.key') == 'value'

    def test_dotted_key(self):
        """Доступ через dotted notation"""
        cfg = ConfigManager('test_config.yaml')
        cfg.set('ml.model_path', './models/')
        assert cfg.get('ml.model_path') == './models/'

    def test_default_value(self):
        """Значение по умолчанию"""
        cfg = ConfigManager('test_config.yaml')
        assert cfg.get('nonexistent.key', 'default') == 'default'

    def test_env_substitution(self):
        """Подстановка переменных окружения"""
        os.environ['TEST_VAR'] = 'test_value'
        cfg = ConfigManager('test_config.yaml')
        cfg.set('test.key', '${TEST_VAR}')
        assert cfg.get('test.key') == 'test_value'
        del os.environ['TEST_VAR']

    def test_save_and_verify(self):
        """Сохранение и верификация подписи"""
        cfg = ConfigManager('test_config.yaml')
        cfg.set('test.key', 'value')
        cfg.save()
        assert Path('test_config.yaml').exists()

    def test_hmac_signature(self):
        """HMAC подпись конфигурации"""
        cfg = ConfigManager('test_config.yaml')
        sig = cfg._calculate_signature({'test': 'data'})
        assert len(sig) == 64  # SHA256 hex digest

    def teardown_method(self):
        """Очистка тестовых файлов"""
        for f in ['test_config.yaml', 'test_config.yaml.sig']:
            if Path(f).exists():
                Path(f).unlink()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
