"""Тесты ModuleRegistry"""
import pytest
import sys
sys.path.insert(0, '.')

from core.base import ModuleRegistry


class TestModuleRegistry:
    """Реестр модулей"""

    @pytest.fixture
    def registry(self):
        return ModuleRegistry()

    def test_register_and_get(self, registry):
        """Регистрация и получение"""
        obj = object()
        registry.register('test', obj)
        assert registry.get('test') is obj

    def test_unregister(self, registry):
        """Удаление модуля"""
        obj = object()
        registry.register('test', obj)
        removed = registry.unregister('test')
        assert removed is obj
        assert registry.get('test') is None

    def test_get_all(self, registry):
        """Все модули"""
        registry.register('a', 1)
        registry.register('b', 2)
        all_mods = registry.get_all()
        assert len(all_mods) == 2

    def test_get_by_type(self, registry):
        """Поиск по типу"""
        registry.register('str1', 'hello')
        registry.register('str2', 'world')
        registry.register('int1', 42)
        strings = registry.get_by_type(str)
        assert len(strings) == 2

    def test_count(self, registry):
        """Количество модулей"""
        assert registry.count == 0
        registry.register('a', 1)
        assert registry.count == 1

    def test_list_names(self, registry):
        """Список имён"""
        registry.register('firewall', object())
        registry.register('ml_engine', object())
        names = registry.list_names()
        assert 'firewall' in names
        assert 'ml_engine' in names

    def test_clear(self, registry):
        """Очистка"""
        registry.register('a', 1)
        registry.register('b', 2)
        registry.clear()
        assert registry.count == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
