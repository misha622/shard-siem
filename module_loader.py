#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Универсальный загрузчик модулей SHARD.
Устраняет дублирование кода в EnhancedShardEnterprise._init_enhancements()
"""

import importlib
import traceback
from typing import Dict, Optional, Any, Tuple
from module_specs import MODULE_SPECS, MODULES_WITH_SETUP, MODULES_WITH_STOP


class ModuleLoader:
    """
    Универсальный загрузчик модулей.
    
    Пример использования:
        loader = ModuleLoader(config, event_bus, logger_service)
        success, instance = loader.load_module('attention_lstm')
    """
    
    def __init__(self, config, event_bus, logger_service):
        self.config = config
        self.event_bus = event_bus
        self.logger_service = logger_service
        self.logger = logger_service.get_logger('ModuleLoader')
        self._loaded = {}
        self._availability = {}
    
    def load_module(self, module_name: str) -> Tuple[bool, Optional[Any]]:
        """
        Загружает модуль по спецификации.
        
        Returns:
            (success: bool, instance: Optional[Any])
        """
        if module_name in self._loaded:
            return True, self._loaded[module_name]
        
        spec = MODULE_SPECS.get(module_name)
        if not spec:
            self.logger.warning(f"Нет спецификации для модуля '{module_name}'")
            self._availability[module_name] = False
            return False, None
        
        # Обработка групп модулей
        if spec.get('is_group'):
            return self._load_group(module_name, spec)
        
        return self._load_single(module_name, spec)
    
    def _load_single(self, module_name: str, spec: Dict) -> Tuple[bool, Optional[Any]]:
        """Загрузка одного модуля"""
        try:
            # Импорт модуля
            import_path = spec['import_path']
            class_name = spec['class']
            
            try:
                module = importlib.import_module(import_path)
                ModuleClass = getattr(module, class_name)
            except ImportError as e:
                self._availability[module_name] = False
                print(f"⚠️ {module_name} недоступен: {e}")
                return False, None
            
            # Создание экземпляра
            instance = self._create_instance(module_name, spec, ModuleClass)
            
            if instance is None:
                return False, None
            
            # Вызов start() если нужно
            start_method = spec.get('start_method')
            if start_method:
                start_kwargs = self._resolve_kwargs(spec.get('start_kwargs', {}))
                getattr(instance, start_method)(**start_kwargs)
            
            self._loaded[module_name] = instance
            self._availability[module_name] = True
            print(f"✅ {module_name.replace('_', ' ').title()} загружен")
            return True, instance
            
        except Exception as e:
            self._availability[module_name] = False
            print(f"❌ {module_name}: {str(e)[:100]}")
            # traceback.print_exc()  # Отключено для чистоты вывода
            return False, None
    
    def _load_group(self, group_name: str, spec: Dict) -> Tuple[bool, Optional[Any]]:
        """Загрузка группы связанных модулей"""
        members = spec.get('members', {})
        results = {}
        
        for import_path, class_names in members.items():
            try:
                module = importlib.import_module(import_path)
                for class_name in class_names:
                    try:
                        cls = getattr(module, class_name)
                        results[class_name] = cls
                    except AttributeError:
                        pass
            except ImportError:
                pass
        
        if results:
            self._loaded[group_name] = results
            self._availability[group_name] = True
            return True, results
        
        self._availability[group_name] = False
        return False, None
    
    def _create_instance(self, module_name: str, spec: Dict, ModuleClass) -> Optional[Any]:
        """Создаёт экземпляр модуля с правильными аргументами"""
        
        # Особая логика для некоторых модулей
        custom_init = spec.get('custom_init')
        if custom_init == 'adaptive_learning':
            return self._init_adaptive_learning(ModuleClass)
        
        if custom_init == 'federated':
            mode = self.config.get('federated.mode', 'client')
            return ModuleClass(mode=mode)
        
        # Стандартные аргументы конструктора
        constructor_args = spec.get('constructor_args', [])
        
        if 'config' in constructor_args or 'event_bus' in constructor_args:
            # Передаём config, event_bus, logger_service
            return ModuleClass(self.config, self.event_bus, self.logger_service)
        
        # Создание конфига если нужен
        config_class_name = spec.get('config_class')
        if config_class_name:
            ConfigClass = self._load_config_class(spec, config_class_name)
            if ConfigClass:
                config = ConfigClass()
                # Применяем переопределения из конфигурации
                for attr, config_key in spec.get('config_overrides', {}).items():
                    value = self.config.get(config_key)
                    if value is not None:
                        setattr(config, attr, value)
                return ModuleClass(config)
        
        # Без аргументов
        return ModuleClass()
    
    def _load_config_class(self, spec: Dict, config_class_name: str):
        """Загружает класс конфигурации из того же модуля"""
        import_path = spec['import_path']
        try:
            module = importlib.import_module(import_path)
            return getattr(module, config_class_name)
        except (ImportError, AttributeError):
            return None
    
    def _init_adaptive_learning(self, ModuleClass) -> Optional[Any]:
        """Особая инициализация Adaptive Learning Engine"""
        adaptive_config = {
            'forgetting_factor': self.config.get('adaptive_learning.forgetting_factor', 0.95),
            'use_deep_features': self.config.get('adaptive_learning.use_deep_features', True),
            'deep_feature_dims': self.config.get('adaptive_learning.deep_feature_dims', [128, 64, 32]),
            'ensemble_temperature': self.config.get('adaptive_learning.ensemble_temperature', 2.0),
            'feature_dim': 156,
            'pretrain_threshold': self.config.get('adaptive_learning.pretrain_threshold', 1000)
        }
        return ModuleClass(adaptive_config)
    
    def _resolve_kwargs(self, kwargs_spec: Dict) -> Dict:
        """Разрешает аргументы из конфигурации"""
        resolved = {}
        for key, config_key in kwargs_spec.items():
            resolved[key] = self.config.get(config_key, False)
        return resolved
    
    def setup_module(self, module_name: str, instance: Any, 
                     registry: Optional[Any] = None) -> None:
        """Вызывает setup() для модуля если нужно"""
        if module_name in MODULES_WITH_SETUP and hasattr(instance, 'setup'):
            spec = MODULE_SPECS.get(module_name, {})
            setup_args = self._resolve_setup_args(spec.get('setup_args', []), registry)
            instance.setup(*setup_args)
    
    def stop_module(self, module_name: str, instance: Any) -> None:
        """Останавливает модуль"""
        if module_name in MODULES_WITH_STOP and hasattr(instance, 'stop'):
            try:
                instance.stop()
            except Exception:
                pass
    
    def _resolve_setup_args(self, arg_names: list, registry: Optional[Any] = None) -> list:
        """Разрешает аргументы для setup()"""
        args = []
        arg_map = {
            'event_bus': self.event_bus,
            'logger': self.logger_service.get_logger('module'),
            'logger_service': self.logger_service,
            'config': self.config,
        }
        
        for name in arg_names:
            if name == 'firewall' and registry:
                args.append(registry.get('firewall'))
            elif name in arg_map:
                args.append(arg_map[name])
            else:
                args.append(None)
        
        return args
    
    def get_loaded_modules(self) -> Dict:
        """Возвращает все загруженные модули"""
        return dict(self._loaded)
    
    def get_availability(self) -> Dict[str, bool]:
        """Возвращает статус доступности модулей"""
        return dict(self._availability)
    
    def is_available(self, module_name: str) -> bool:
        """Проверяет, доступен ли модуль"""
        return self._availability.get(module_name, False)


# Глобальный экземпляр лоадера (создаётся в EnhancedShardEnterprise)
_module_loader: Optional[ModuleLoader] = None


def get_module_loader() -> Optional[ModuleLoader]:
    """Получить глобальный экземпляр загрузчика"""
    return _module_loader


def set_module_loader(loader: ModuleLoader) -> None:
    """Установить глобальный экземпляр загрузчика"""
    global _module_loader
    _module_loader = loader
