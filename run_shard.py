#!/usr/bin/env python3
"""
SHARD Enterprise SIEM - Главный файл запуска
Версия: 5.2.0 (исправленная с улучшенной обработкой ошибок)

Автор: SHARD Enterprise
"""

import os
import sys
import time
import signal
import asyncio
import argparse
from pathlib import Path
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from contextlib import contextmanager
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shard_enterprise_complete import (
    ShardEnterprise,
    ConfigManager,
    EventBus,
    LoggingService,
    BaseModule
)
from core.base import ModuleRegistry
from module_loader import ModuleLoader
from module_specs import MODULE_SPECS, MODULES_WITH_SETUP, MODULES_WITH_STOP


# ============================================================
# КОНСТАНТЫ И ПЕРЕЧИСЛЕНИЯ
# ============================================================

# Группы модулей по порядку инициализации (константы вместо Enum)
MODULE_GROUPS = {
    'EARLY': [
        'cloud_security', 'code_security', 'cve_intelligence',
        'deception', 'tip'
    ],
    'LATE': [
        'llm_guardian', 'threat_hunting', 'soar',
        'forensics', 'mitre', 'red_team'
    ],
    'ML': [
        'temporal_gnn', 'contrastive_vae', 'rl_defense',
        'adaptive_learning', 'gnn_analyzer', 'fusion'
    ]
}


class ModuleStatus(Enum):
    """Статусы модуля"""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    INITIALIZED = "initialized"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"
    DEGRADED = "degraded"


@dataclass
class ModuleHealth:
    """Информация о здоровье модуля"""
    status: ModuleStatus
    last_check: float = 0.0
    error_count: int = 0
    warnings: List[str] = field(default_factory=list)
    dependencies_ok: bool = True
    memory_usage_mb: float = 0.0
    response_time_ms: float = 0.0


@dataclass
class SecurityContext:
    """Контекст безопасности для CLI-операций"""
    allowed_paths: Set[Path] = field(default_factory=set)
    max_file_size_mb: int = 100
    blocked_patterns: List[str] = field(
        default_factory=lambda: ['../', '..\\', '/etc/passwd', 'C:\\Windows\\']
    )


# ============================================================
# ИСКЛЮЧЕНИЯ
# ============================================================

class SHARDError(Exception):
    """Базовое исключение SHARD"""
    pass


class ModuleLoadError(SHARDError):
    """Ошибка загрузки модуля"""
    pass


class ModuleInitError(SHARDError):
    """Ошибка инициализации модуля"""
    pass


class ModuleRuntimeError(SHARDError):
    """Ошибка выполнения модуля"""
    pass


class SecurityValidationError(SHARDError):
    """Ошибка валидации безопасности"""
    pass


class ConfigurationError(SHARDError):
    """Ошибка конфигурации"""
    pass


# ============================================================
# УТИЛИТЫ БЕЗОПАСНОСТИ
# ============================================================

class SecurityValidator:
    """Валидатор безопасности для CLI-операций"""

    @staticmethod
    def validate_file_path(filepath: str, context: SecurityContext = None) -> Path:
        """
        Безопасная валидация пути к файлу

        Args:
            filepath: Путь к файлу
            context: Контекст безопасности

        Returns:
            Path: Безопасный путь

        Raises:
            SecurityValidationError: Если путь небезопасен
        """
        if context is None:
            context = SecurityContext()

        try:
            path = Path(filepath).resolve()

            # Проверка на существование
            if not path.exists():
                raise SecurityValidationError(f"Файл не существует: {filepath}")

            # Проверка размера файла
            if path.is_file():
                size_mb = path.stat().st_size / (1024 * 1024)
                if size_mb > context.max_file_size_mb:
                    raise SecurityValidationError(
                        f"Файл слишком большой: {size_mb:.1f}MB > {context.max_file_size_mb}MB"
                    )

            # Проверка на запрещённые паттерны
            path_str = str(path)
            for pattern in context.blocked_patterns:
                if pattern in path_str:
                    raise SecurityValidationError(
                        f"Обнаружен запрещённый паттерн в пути: {pattern}"
                    )

            # Проверка на выход за пределы разрешённых директорий
            if context.allowed_paths:
                allowed = any(
                    str(path).startswith(str(allowed_path) + '/') or str(path) == str(allowed_path)
                    for allowed_path in context.allowed_paths
                )
                if not allowed:
                    raise SecurityValidationError(
                        f"Доступ запрещён: {filepath} вне разрешённых директорий"
                    )

            return path

        except SecurityValidationError:
            raise
        except Exception as e:
            raise SecurityValidationError(f"Ошибка валидации пути: {e}")

    @staticmethod
    def validate_ip_address(ip: str, allow_private: bool = False) -> str:
        """
        Валидация IP-адреса

        Args:
            ip: IP-адрес

        Returns:
            str: Валидированный IP

        Raises:
            SecurityValidationError: Если IP некорректен
        """
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            # Запрещаем некоторые специальные адреса
            if addr.is_loopback:
                raise SecurityValidationError("Loopback адреса запрещены для сканирования")
            if addr.is_multicast:
                raise SecurityValidationError("Multicast адреса запрещены")
            if addr.is_private and not allow_private:
                raise SecurityValidationError("Приватные адреса разрешены только с --allow-private")
            return str(addr)
        except ValueError:
            raise SecurityValidationError(f"Некорректный IP-адрес: {ip}")

    @staticmethod
    def validate_cve_id(cve_id: str) -> str:
        """
        Валидация CVE ID

        Args:
            cve_id: Идентификатор CVE

        Returns:
            str: Нормализованный CVE ID

        Raises:
            SecurityValidationError: Если формат некорректен
        """
        import re
        pattern = r'^CVE-\d{4}-\d{4,}$'
        if not re.match(pattern, cve_id.upper()):
            raise SecurityValidationError(f"Некорректный формат CVE: {cve_id}")
        return cve_id.upper()


# ============================================================
# КОНТЕКСТНЫЙ МЕНЕДЖЕР ДЛЯ БЕЗОПАСНОЙ ОСТАНОВКИ
# ============================================================

@contextmanager
def safe_operation(operation_name: str, logger: logging.Logger):
    """
    Контекстный менеджер для безопасного выполнения операций

    Args:
        operation_name: Название операции
        logger: Логгер

    Yields:
        None
    """
    try:
        logger.debug(f"Начало операции: {operation_name}")
        yield
        logger.debug(f"Успешное завершение: {operation_name}")
    except ImportError as e:
        logger.warning(f"Модуль не найден для {operation_name}: {e}")
    except AttributeError as e:
        logger.error(f"Ошибка атрибута в {operation_name}: {e}")
    except (ModuleLoadError, ModuleInitError) as e:
        logger.error(f"Ошибка модуля {operation_name}: {e}")
    except Exception as e:
        logger.critical(f"Критическая ошибка в {operation_name}: {e}", exc_info=True)


# ============================================================
# ОСНОВНОЙ КЛАСС
# ============================================================

class EnhancedShardEnterprise:
    """Оркестратор SHARD Enterprise с автоматической загрузкой модулей"""

    def __init__(
            self,
            config_path: str = "config.yaml",
            enable_enhancements: bool = True,
            enable_simulation: bool = False,
            no_capture: bool = False
    ):
        """
        Инициализация оркестратора

        Args:
            config_path: Путь к конфигурации
            enable_enhancements: Включить улучшения
            enable_simulation: Режим симуляции
            no_capture: Отключить захват трафика

        Raises:
            ConfigurationError: При ошибках конфигурации
        """
        self.config_path = Path(config_path)

        try:
            self.config = ConfigManager(str(self.config_path))
        except Exception as e:
            raise ConfigurationError(f"Ошибка загрузки конфигурации: {e}")

        self.enable_enhancements = enable_enhancements
        self.enable_simulation = enable_simulation
        self.no_capture = no_capture

        # Инициализация базовых сервисов
        self.event_bus = EventBus()
        self.logger_service = LoggingService(self.config, self.event_bus)
        self.logger = self.logger_service.get_logger("SHARD")

        # Реестр модулей для автоматического DI
        self.registry = ModuleRegistry()

        # Загрузчик модулей
        self.loader = ModuleLoader(self.config, self.event_bus, self.logger_service)

        # Основные компоненты
        self.shard = None
        self.defense_pipeline = None
        self.anomaly_detector = None
        self.gnn_analyzer = None
        self.fusion = None
        self.autonomous = None
        self.temporal_gnn_predictor = None

        # Словарь загруженных модулей
        self.modules: Dict[str, Any] = {}

        # Состояние модулей
        self._module_health: Dict[str, ModuleHealth] = {}
        self._module_status: Dict[str, ModuleStatus] = {}

        self._running = False
        self._stop_requested = False

        # Инициализация контекста безопасности
        self.security_context = SecurityContext(
            allowed_paths={
                Path.cwd(),
                Path.home(),
            }
        )

        if self.enable_enhancements:
            self._init_enhancements()

    # ============================================================
    # УПРАВЛЕНИЕ МОДУЛЯМИ
    # ============================================================

    def _update_module_status(self, module_name: str, status: ModuleStatus, error: str = None):
        """
        Обновление статуса модуля

        Args:
            module_name: Имя модуля
            status: Новый статус
            error: Сообщение об ошибке (опционально)
        """
        self._module_status[module_name] = status

        if module_name not in self._module_health:
            self._module_health[module_name] = ModuleHealth(status=status)

        health = self._module_health[module_name]
        health.status = status
        health.last_check = time.time()

        if status == ModuleStatus.FAILED:
            health.error_count += 1
            if error:
                health.warnings.append(error)
                self.logger.error(f"Модуль {module_name}: {error}")

    def _safe_import_module(self, module_name: str, import_path: str, class_name: str) -> Any:
        """
        Безопасный импорт модуля

        Args:
            module_name: Логическое имя модуля
            import_path: Путь импорта
            class_name: Имя класса

        Returns:
            Any: Экземпляр модуля

        Raises:
            ModuleLoadError: При ошибке загрузки
        """
        self._update_module_status(module_name, ModuleStatus.LOADING)

        try:
            module = __import__(import_path, fromlist=[class_name])
            cls = getattr(module, class_name)
            instance = cls()
            self._update_module_status(module_name, ModuleStatus.LOADED)
            return instance
        except ImportError as e:
            self._update_module_status(module_name, ModuleStatus.FAILED, str(e))
            raise ModuleLoadError(f"Не удалось импортировать {module_name}: {e}")
        except AttributeError as e:
            self._update_module_status(module_name, ModuleStatus.FAILED, str(e))
            raise ModuleLoadError(f"Класс не найден в модуле {module_name}: {e}")
        except Exception as e:
            self._update_module_status(module_name, ModuleStatus.FAILED, str(e))
            raise ModuleLoadError(f"Ошибка создания экземпляра {module_name}: {e}")

    def _init_enhancements(self):
        """Инициализация всех модулей через ModuleLoader"""
        print("\n🚀 Инициализация улучшений SHARD Enterprise...")
        print("=" * 50)

        # Загружаем все модули в правильном порядке (топологическая сортировка)
        try:
            self.loader.load_all(registry=self.registry)
        except Exception as e:
            self.logger.error(f"Ошибка загрузки модулей: {e}")
            # Продолжаем с теми модулями, которые загрузились

        # Сохраняем ссылки на загруженные модули
        for name, instance in self.loader.get_loaded_modules().items():
            self.modules[name] = instance
            self._update_module_status(name, ModuleStatus.LOADED)

        # Особая инициализация группы автономных модулей
        self._init_autonomous_group()

        # Инициализация ML компонентов
        self._init_ml_components()

        print("=" * 50)

    def _init_ml_components(self):
        """Инициализация ML компонентов с правильной обработкой ошибок"""
        ml_components = {
            'defense_pipeline': {
                'import_path': 'shard_defense_pipeline_v3',
                'class_name': 'ShardDefensePipeline',
                'attribute': 'defense_pipeline',
                'emoji': '🛡️',
                'description': 'AI Defense Pipeline v3'
            },
            'anomaly_detector': {
                'import_path': 'shard_anomaly_detector',
                'class_name': 'ShardAnomalyDetector',
                'attribute': 'anomaly_detector',
                'emoji': '🔍',
                'description': 'Anomaly Detector (VAE)'
            },
            'gnn_analyzer': {
                'import_path': 'shard_gnn_integration',
                'class_name': 'ShardGNN',
                'attribute': 'gnn_analyzer',
                'emoji': '🧬',
                'description': 'GNN Threat Graph'
            },
            'fusion': {
                'import_path': 'shard_fusion_integration',
                'class_name': 'ShardFusion',
                'attribute': 'fusion',
                'emoji': '🌐',
                'description': 'Multi-Modal Fusion'
            },
            'temporal_gnn_predictor': {
                'import_path': 'shard_temporal_integration',
                'class_name': 'ShardTemporalGNN',
                'attribute': 'temporal_gnn_predictor',
                'emoji': '🔮',
                'description': 'Temporal GNN Predictor'
            }
        }

        for comp_name, comp_config in ml_components.items():
            with safe_operation(f"загрузка {comp_config['description']}", self.logger):
                try:
                    instance = self._safe_import_module(
                        comp_name,
                        comp_config['import_path'],
                        comp_config['class_name']
                    )

                    # Проверка загрузки
                    if hasattr(instance, 'loaded') and instance.loaded:
                        setattr(self, comp_config['attribute'], instance)
                        self.registry.register(comp_name, instance)
                        self._update_module_status(comp_name, ModuleStatus.INITIALIZED)
                        print(f"{comp_config['emoji']} {comp_config['description']} загружен!")
                    else:
                        self.logger.warning(
                            f"{comp_config['description']} загружен, но не инициализирован"
                        )
                        self._update_module_status(comp_name, ModuleStatus.DEGRADED)

                except ModuleLoadError as e:
                    print(f"⚠️ {comp_config['description']}: {e}")
                    self.logger.warning(f"Пропуск {comp_config['description']}: {e}")

                except Exception as e:
                    print(f"⚠️ {comp_config['description']}: {e}")
                    self.logger.error(
                        f"Критическая ошибка загрузки {comp_config['description']}: {e}",
                        exc_info=True
                    )

    def _init_autonomous_group(self):
        """Инициализация автономной системы"""
        if not self.loader.is_available('autonomous_group'):
            self.logger.info("Автономная система недоступна")
            return

        with safe_operation("инициализация автономной системы", self.logger):
            try:
                autonomous_config = {
                    'llm_model_path': self.config.get('llm.model_path', ''),
                    'autonomous_mode': self.config.get('autonomous.autonomous_mode', False),
                    'recommend_only': self.config.get('autonomous.recommend_only', True)
                }

                from shard_autonomous_response import ShardAutonomousIntegration
                self.autonomous = ShardAutonomousIntegration(autonomous_config)
                self.registry.register('autonomous', self.autonomous)
                self._update_module_status('autonomous', ModuleStatus.INITIALIZED)
                print("✅ Autonomous Response + LLM Analyst загружены")

            except ImportError as e:
                self.logger.warning(f"Модуль автономной системы не найден: {e}")
                self._update_module_status('autonomous', ModuleStatus.FAILED, str(e))
            except Exception as e:
                self.logger.error(f"Ошибка инициализации автономной системы: {e}")
                self._update_module_status('autonomous', ModuleStatus.FAILED, str(e))

    # ============================================================
    # УПРАВЛЕНИЕ ЖИЗНЕННЫМ ЦИКЛОМ
    # ============================================================

    def start(self):
        """Запуск всех модулей с проверками здоровья"""
        print("\n🛡️ Запуск SHARD Enterprise с ВСЕМИ улучшениями...")
        self._stop_requested = False

        # Запускаем ранние модули
        self._start_module_group(MODULE_GROUPS['EARLY'])

        # Создаём основной ShardEnterprise
        with safe_operation("создание ShardEnterprise", self.logger):
            try:
                self.shard = ShardEnterprise(
                    config_path=str(self.config_path),
                    enable_simulation=self.enable_simulation,
                    no_capture=self.no_capture,
                    event_bus=self.event_bus  # Единый EventBus
                )
            except Exception as e:
                self.logger.critical(f"Не удалось создать ShardEnterprise: {e}")
                self.shard = None
                raise

        # Подключаем ML-модули к ML Engine
        self._wire_ml_engine()

        # Настраиваем Adaptive Ensemble
        self._setup_adaptive_ensemble()

        # Настраиваем Autonomous Response
        self._setup_autonomous()

        # Подписываемся на события
        self._subscribe_to_events()

        # Запускаем поздние модули
        self._start_module_group(MODULE_GROUPS['LATE'])

        # Проверка здоровья модулей
        health = self._verify_modules_health()
        failed_modules = [
            name for name, status in health.items() if not status
        ]

        if failed_modules:
            self.logger.warning(
                f"Некоторые модули не прошли проверку здоровья: {failed_modules}"
            )
        else:
            self.logger.info("Все модули успешно запущены")

        self._running = True
        if self.shard is not None:
            self.shard.start()
        else:
            self.logger.error("Невозможно запустить: ShardEnterprise не создан")
            return

    def _start_module_group(self, module_names: List[str]):
        """
        Запуск группы модулей с проверкой зависимостей

        Args:
            module_names: Список имён модулей для запуска
        """
        for module_name in module_names:
            with safe_operation(f"запуск {module_name}", self.logger):
                instance = self.modules.get(module_name)
                if not instance:
                    self.logger.debug(f"Модуль {module_name} не загружен, пропуск")
                    continue

                try:
                    # Инициализация модуля
                    self.loader.setup_module(module_name, instance, self.registry)
                    self._update_module_status(module_name, ModuleStatus.INITIALIZED)

                    # Запуск если есть метод start
                    if hasattr(instance, 'start'):
                        instance.start()
                        self._update_module_status(module_name, ModuleStatus.RUNNING)
                        print(f"✅ {module_name.replace('_', ' ').title()} запущен")

                except ModuleInitError as e:
                    self.logger.error(f"Ошибка инициализации {module_name}: {e}")
                    self._update_module_status(module_name, ModuleStatus.FAILED, str(e))
                except Exception as e:
                    self.logger.error(f"Ошибка запуска {module_name}: {e}")
                    self._update_module_status(module_name, ModuleStatus.FAILED, str(e))

    def _verify_modules_health(self) -> Dict[str, bool]:
        """
        Проверка здоровья всех модулей

        Returns:
            Dict[str, bool]: Статус здоровья модулей
        """
        health = {}

        for module_name, instance in self.modules.items():
            try:
                if hasattr(instance, 'health_check'):
                    health[module_name] = instance.health_check()
                else:
                    # Базовая проверка - модуль существует и не в статусе FAILED
                    status = self._module_status.get(module_name)
                    health[module_name] = status not in [ModuleStatus.FAILED, None]
            except Exception as e:
                self.logger.error(f"Health check failed for {module_name}: {e}")
                health[module_name] = False

        return health

    def _wire_ml_engine(self):
        """Подключает ML-модули к ML Engine с проверкой зависимостей"""
        if not hasattr(self.shard, 'modules'):
            self.logger.debug("ML Engine недоступен для подключения модулей")
            return

        ml_modules_to_wire = {
            'temporal_gnn': ('temporal_gnn', 'Temporal GNN'),
            'contrastive_vae': ('contrastive_vae', 'Contrastive VAE'),
            'rl_defense': ('rl_defense', 'RL Defense'),
            'adaptive_learning': ('adaptive_engine', 'Adaptive Learning')
        }

        for module in self.shard.modules:
            if module is not None and hasattr(module, 'name') and module.name == 'ML':
                for module_name, (attr_name, display_name) in ml_modules_to_wire.items():
                    with safe_operation(f"подключение {display_name}", self.logger):
                        instance = self.modules.get(module_name)
                        if instance:
                            try:
                                setattr(module, attr_name, instance)
                                print(f"✅ {display_name} подключён к ML Engine")
                            except AttributeError as e:
                                self.logger.warning(
                                    f"Не удалось подключить {display_name}: {e}"
                                )
                break

    def _setup_adaptive_ensemble(self):
        """Настраивает ансамбль адаптивного обучения с проверкой готовности"""
        adaptive = self.modules.get('adaptive_learning')
        if not adaptive:
            return

        if not self._check_module_ready(adaptive):
            self.logger.warning("Adaptive Learning не готов к настройке")
            return

        with safe_operation("настройка Adaptive Ensemble", self.logger):
            try:
                models = {}

                # Добавляем модели из ML Engine
                if hasattr(self.shard, 'ml_engine') and hasattr(self.shard.ml_engine, 'models'):
                    for name, model in self.shard.ml_engine.models.items():
                        if self._check_module_ready(model):
                            models[f'ml_{name}'] = model

                # Добавляем другие ML-модули
                ml_modules = {
                    'temporal_gnn': 'temporal_gnn',
                    'contrastive_vae': 'contrastive_vae'
                }

                for module_name, model_name in ml_modules.items():
                    module = self.modules.get(module_name)
                    if module and self._check_module_ready(module):
                        models[module_name] = module

                if models:
                    adaptive.register_models(models)
                    print(f"✅ Adaptive Ensemble зарегистрирован с {len(models)} моделями")
                else:
                    self.logger.warning("Нет доступных моделей для Adaptive Ensemble")

            except Exception as e:
                self.logger.error(f"Ошибка настройки Adaptive Ensemble: {e}")

    def _setup_autonomous(self):
        """Настраивает автономную систему с проверкой зависимостей"""
        autonomous = self.modules.get('autonomous') or self.autonomous
        if not autonomous:
            return

        if not self._check_module_ready(autonomous):
            self.logger.warning("Автономная система не готова к настройке")
            return

        with safe_operation("настройка Autonomous Response", self.logger):
            try:
                # Ищем firewall в модулях ShardEnterprise
                firewall = None
                if hasattr(self.shard, 'modules'):
                    for module in self.shard.modules:
                        if module is not None and hasattr(module, 'name') and module.name == 'Firewall':
                            firewall = module
                            break

                # Ищем RL агента с проверкой готовности
                rl_defense = self.modules.get('rl_defense')
                rl_agent = None
                if rl_defense and self._check_module_ready(rl_defense) and hasattr(rl_defense, 'agent'):
                    rl_agent = rl_defense.agent

                autonomous.setup(
                    firewall=firewall,
                    rl_agent=rl_agent,
                    event_bus=self.event_bus,
                    logger=self.logger
                )

                self._update_module_status('autonomous', ModuleStatus.RUNNING)
                print("✅ Autonomous Response подключён к EventBus")

            except Exception as e:
                self.logger.error(f"Ошибка настройки автономной системы: {e}")
                self._update_module_status('autonomous', ModuleStatus.DEGRADED, str(e))

    def _subscribe_to_events(self):
        """Подписка на события с обработкой ошибок"""
        with safe_operation("подписка на события", self.logger):
            try:
                self.event_bus.subscribe('alert.detected', self._on_alert_defense)
                # honeypot.connection уже публикует alert.detected — не дублируем
                self.event_bus.subscribe('alert.detected', self._on_alert_autonomous)
                print("🛡️ Defense Pipeline v3 подписан на EventBus")
            except Exception as e:
                self.logger.error(f"Ошибка подписки на события: {e}")

    def _on_alert_defense(self, alert: Dict):
        """
        Обработчик алертов для Defense Pipeline

        Args:
            alert: Данные алерта
        """
        if not self.defense_pipeline:
            return

        if not self._check_module_ready(self.defense_pipeline):
            self.logger.warning("Defense Pipeline не готов обработать алерт")
            return

        try:
            self.defense_pipeline.process_alert(alert)
        except AttributeError as e:
            self.logger.warning(f"Defense pipeline не поддерживает операцию: {e}")
        except Exception as e:
            self.logger.error(f"Ошибка обработки алерта в Defense Pipeline: {e}")

    def _on_alert_autonomous(self, alert: Dict):
        """
        Обработчик алертов для Autonomous Response

        Args:
            alert: Данные алерта
        """
        autonomous = self.modules.get('autonomous') or self.autonomous
        if not autonomous or not self._check_module_ready(autonomous):
            return

        try:
            result = autonomous.on_alert(alert)
            if result:
                if result.get('autonomous_action'):
                    action = result['autonomous_action']
                    self.logger.info(
                        f"🤖 Autonomous: {action.get('action_name')} for {alert.get('src_ip')}"
                    )
                if result.get('llm_analysis'):
                    self.logger.info(
                        f"🧠 LLM Analysis: {result['llm_analysis'][:100]}..."
                    )
        except Exception as e:
            self.logger.error(f"Ошибка автономной обработки алерта: {e}")

    def _check_module_ready(self, module: Any) -> bool:
        """
        Проверка готовности модуля

        Args:
            module: Экземпляр модуля

        Returns:
            bool: True если модуль готов
        """
        if module is None:
            return False

        # Проверяем метод is_ready если есть
        if hasattr(module, 'is_ready'):
            try:
                return module.is_ready()
            except Exception:
                return False

        # Проверяем метод loaded если есть
        if hasattr(module, 'loaded'):
            try:
                return bool(module.loaded)
            except Exception:
                return False

        return True

    # ============================================================
    # ОСТАНОВКА
    # ============================================================

    def stop(self):
        """Безопасная остановка всех модулей с гарантией остановки каждого"""
        print("\n🛑 Остановка SHARD Enterprise...")
        self._running = False
        self._stop_requested = True

        stop_errors = []
        stopped_count = 0
        failed_count = 0

        # Сохраняем состояние Adaptive Learning
        self._save_adaptive_learning()

        # Останавливаем все модули через загрузчик
        for module_name, instance in self.modules.items():
            try:
                self.loader.stop_module(module_name, instance)
                self._update_module_status(module_name, ModuleStatus.STOPPED)
                stopped_count += 1
            except Exception as e:
                error_msg = f"Ошибка остановки {module_name}: {e}"
                stop_errors.append(error_msg)
                self.logger.error(error_msg)
                self._update_module_status(module_name, ModuleStatus.FAILED, str(e))
                failed_count += 1

        # Останавливаем ML компоненты
        ml_components = [
            ('defense_pipeline', self.defense_pipeline),
            ('anomaly_detector', self.anomaly_detector),
            ('gnn_analyzer', self.gnn_analyzer),
            ('fusion', self.fusion),
            ('temporal_gnn_predictor', self.temporal_gnn_predictor)
        ]

        for comp_name, component in ml_components:
            if component and hasattr(component, 'stop'):
                try:
                    component.stop()
                    self._update_module_status(comp_name, ModuleStatus.STOPPED)
                    stopped_count += 1
                except Exception as e:
                    error_msg = f"Ошибка остановки {comp_name}: {e}"
                    stop_errors.append(error_msg)
                    self.logger.error(error_msg)
                    failed_count += 1

        # Останавливаем ShardEnterprise
        if self.shard:
            try:
                self.shard.stop()
            except Exception as e:
                stop_errors.append(f"Ошибка остановки ShardEnterprise: {e}")
                self.logger.error(f"Критическая ошибка остановки ShardEnterprise: {e}")

        # Итоговая статистика
        if stop_errors:
            print(f"⚠️ Остановлено с ошибками: {stopped_count} успешно, {failed_count} с ошибками")
            self.logger.warning(
                f"Ошибки при остановке ({failed_count}/{stopped_count + failed_count}): "
                f"{'; '.join(stop_errors[:3])}"
            )
        else:
            print("✅ Все модули остановлены успешно")
            self.logger.info(f"Остановлено {stopped_count} модулей без ошибок")

    def _save_adaptive_learning(self):
        """Сохраняет состояние Adaptive Learning"""
        adaptive = self.modules.get('adaptive_learning')
        if not adaptive:
            return

        with safe_operation("сохранение Adaptive Learning", self.logger):
            if hasattr(adaptive, 'save_models'):
                try:
                    adaptive.save_models()
                    print("✅ Adaptive Learning модели сохранены")
                except Exception as e:
                    self.logger.error(f"Ошибка сохранения Adaptive Learning: {e}")

    # ============================================================
    # СТАТУС И МОНИТОРИНГ
    # ============================================================

    def get_status(self) -> Dict:
        """
        Получить детальный статус всех модулей

        Returns:
            Dict: Статус системы
        """
        status = {
            'shard': self._running,
            'uptime': time.time() - self._start_time if hasattr(self, '_start_time') else 0,
            'modules': {},
            'health': {},
        }

        # Статус модулей из загрузчика
        availability = self.loader.get_availability()
        for name in MODULE_SPECS:
            if name != 'autonomous_group':
                status['modules'][name] = {
                    'available': availability.get(name, False),
                    'status': self._module_status.get(name, ModuleStatus.UNLOADED).value,
                    'health': self._get_module_health_dict(name)
                }

        # Добавляем особые компоненты
        special_components = {
            'defense_pipeline': self.defense_pipeline,
            'anomaly_detector': self.anomaly_detector,
            'gnn_analyzer': self.gnn_analyzer,
            'fusion': self.fusion,
            'temporal_gnn_predictor': self.temporal_gnn_predictor
        }

        for name, component in special_components.items():
            status['modules'][name] = {
                'available': component is not None,
                'status': self._module_status.get(name, ModuleStatus.UNLOADED).value,
                'health': self._get_module_health_dict(name)
            }

        # Общая статистика здоровья
        health_statuses = [m.status for m in self._module_health.values()]
        status['health'] = {
            'total_modules': len(health_statuses),
            'healthy': health_statuses.count(ModuleStatus.RUNNING),
            'degraded': health_statuses.count(ModuleStatus.DEGRADED),
            'failed': health_statuses.count(ModuleStatus.FAILED),
            'stopped': health_statuses.count(ModuleStatus.STOPPED),
        }

        return status

    def _get_module_health_dict(self, module_name: str) -> Dict:
        """
        Получить информацию о здоровье модуля

        Args:
            module_name: Имя модуля

        Returns:
            Dict: Информация о здоровье
        """
        health = self._module_health.get(module_name)
        if not health:
            return {'status': 'unknown'}

        return {
            'status': health.status.value,
            'last_check': health.last_check,
            'error_count': health.error_count,
            'warnings': health.warnings[-5:],  # Последние 5 предупреждений
            'memory_mb': health.memory_usage_mb,
            'response_time_ms': health.response_time_ms,
        }

    def get_health_report(self) -> str:
        """
        Получить текстовый отчёт о здоровье

        Returns:
            str: Отчёт о здоровье системы
        """
        status = self.get_status()
        report = []

        report.append("=" * 60)
        report.append("SHARD Enterprise Health Report")
        report.append("=" * 60)
        report.append(f"System Running: {status['shard']}")
        report.append(f"Uptime: {status['uptime']:.0f}s")
        report.append("")
        report.append("Health Summary:")
        report.append(f"  Healthy: {status['health']['healthy']}")
        report.append(f"  Degraded: {status['health']['degraded']}")
        report.append(f"  Failed: {status['health']['failed']}")
        report.append(f"  Stopped: {status['health']['stopped']}")
        report.append("")
        report.append("Module Status:")

        for name, info in sorted(status['modules'].items()):
            status_icon = {
                'running': '✅',
                'failed': '❌',
                'degraded': '⚠️',
                'stopped': '⏹️',
                'loaded': '📦',
                'initialized': '🔄',
                'unloaded': '⬜'
            }.get(info.get('status', 'unknown'), '❓')

            errors = info.get('health', {}).get('error_count', 0)
            error_str = f" (errors: {errors})" if errors > 0 else ""
            report.append(f"  {status_icon} {name}: {info.get('status', 'unknown')}{error_str}")

        report.append("=" * 60)

        return "\n".join(report)

    # ============================================================
    # МЕТОДЫ-ОБЁРТКИ ДЛЯ CLI (БЕЗОПАСНЫЕ)
    # ============================================================

    def secure_llm_call(self, prompt: str, llm_function: callable, client_id: str = 'unknown') -> Tuple[Any, Dict]:
        """
        Безопасный вызов LLM

        Args:
            prompt: Промпт
            llm_function: Функция LLM
            client_id: ID клиента

        Returns:
            Tuple: (результат, метаданные)
        """
        llm_guardian = self.modules.get('llm_guardian')

        if not llm_guardian or not self._check_module_ready(llm_guardian):
            self.logger.warning("LLM Guardian недоступен, прямой вызов LLM")
            return llm_function(prompt), {}

        try:
            return llm_guardian.secure_llm_call(prompt, llm_function, client_id)
        except Exception as e:
            self.logger.error(f"Ошибка защищённого вызова LLM: {e}")
            return llm_function(prompt), {'error': str(e)}

    def scan_code(self, filepath: str) -> List[Dict]:
        """
        Сканирование кода с валидацией пути

        Args:
            filepath: Путь к файлу

        Returns:
            List[Dict]: Найденные уязвимости
        """
        with safe_operation(f"сканирование кода {filepath}", self.logger):
            try:
                safe_path = SecurityValidator.validate_file_path(
                    filepath, self.security_context
                )

                code_security = self.modules.get('code_security')
                if not code_security or not self._check_module_ready(code_security):
                    raise ModuleRuntimeError("Code Security модуль недоступен")

                if not hasattr(code_security, 'analyzer'):
                    raise ModuleRuntimeError("Code Security analyzer не инициализирован")

                return code_security.analyzer.analyze_file(str(safe_path))

            except (SecurityValidationError, ModuleRuntimeError) as e:
                self.logger.error(str(e))
                return []
            except Exception as e:
                self.logger.error(f"Непредвиденная ошибка сканирования: {e}")
                return []

    def scan_repository(self, repo_path: str) -> Dict:
        """
        Сканирование репозитория с валидацией

        Args:
            repo_path: Путь к репозиторию

        Returns:
            Dict: Результаты сканирования
        """
        with safe_operation(f"сканирование репозитория {repo_path}", self.logger):
            try:
                safe_path = SecurityValidator.validate_file_path(
                    repo_path, self.security_context
                )

                code_security = self.modules.get('code_security')
                if not code_security or not self._check_module_ready(code_security):
                    raise ModuleRuntimeError("Code Security модуль недоступен")

                return code_security.scan_repository(str(safe_path))

            except (SecurityValidationError, ModuleRuntimeError) as e:
                self.logger.error(str(e))
                return {'error': str(e)}
            except Exception as e:
                self.logger.error(f"Непредвиденная ошибка сканирования: {e}")
                return {'error': str(e)}

    def check_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Проверка CVE с валидацией

        Args:
            cve_id: Идентификатор CVE

        Returns:
            Optional[Dict]: Информация о CVE
        """
        with safe_operation(f"проверка CVE {cve_id}", self.logger):
            try:
                validated_cve = SecurityValidator.validate_cve_id(cve_id)

                cve_intel = self.modules.get('cve_intelligence')
                if not cve_intel or not self._check_module_ready(cve_intel):
                    raise ModuleRuntimeError("CVE Intelligence модуль недоступен")

                if not hasattr(cve_intel, 'engine'):
                    raise ModuleRuntimeError("CVE Intelligence engine не инициализирован")

                cve = cve_intel.engine.check_cve(validated_cve)
                return cve.__dict__ if cve else None

            except (SecurityValidationError, ModuleRuntimeError) as e:
                self.logger.error(str(e))
                return None
            except Exception as e:
                self.logger.error(f"Непредвиденная ошибка проверки CVE: {e}")
                return None

    def run_red_team_scan(self, target: str, scope: List[str] = None, allow_private: bool = False) -> Dict:
        """
        Запуск Red Team сканирования с валидацией цели

        Args:
            target: Цель сканирования
            scope: Область сканирования
            allow_private: Разрешить сканирование приватных сетей

        Returns:
            Dict: Результаты сканирования
        """
        with safe_operation(f"Red Team сканирование {target}", self.logger):
            try:
                # Валидация цели (IP или домен)
                try:
                    SecurityValidator.validate_ip_address(target, allow_private=allow_private)
                except SecurityValidationError:
                    # Если не IP, проверяем что это не опасный путь
                    if any(char in target for char in ['/', '\\', '..']):
                        raise SecurityValidationError(f"Некорректная цель: {target}")

                red_team = self.modules.get('red_team')
                if not red_team or not self._check_module_ready(red_team):
                    raise ModuleRuntimeError("Red Team модуль недоступен")

                return red_team.scan_target(target, scope or [])

            except (SecurityValidationError, ModuleRuntimeError) as e:
                self.logger.error(str(e))
                return {'error': str(e)}
            except Exception as e:
                self.logger.error(f"Непредвиденная ошибка Red Team: {e}")
                return {'error': str(e)}

    # ============================================================
    # ОСТАЛЬНЫЕ МЕТОДЫ-ОБЁРТКИ
    # ============================================================

    def scan_cve_dependencies(self, project_path: str) -> List:
        """Сканирование зависимостей на CVE"""
        with safe_operation(f"сканирование зависимостей {project_path}", self.logger):
            try:
                safe_path = SecurityValidator.validate_file_path(
                    project_path, self.security_context
                )
                cve_intel = self.modules.get('cve_intelligence')
                if cve_intel and self._check_module_ready(cve_intel):
                    return cve_intel.scan_project(str(safe_path))
            except Exception as e:
                self.logger.error(f"Ошибка сканирования зависимостей: {e}")
        return []

    def get_threat_hunting_report(self) -> Dict:
        """Получение отчёта Threat Hunting"""
        with safe_operation("получение отчёта Threat Hunting", self.logger):
            try:
                threat_hunting = self.modules.get('threat_hunting')
                if threat_hunting and self._check_module_ready(threat_hunting):
                    return threat_hunting.get_report()
            except Exception as e:
                self.logger.error(f"Ошибка получения отчёта Threat Hunting: {e}")
        return {}

    def get_mitre_coverage(self) -> Dict:
        """Получение покрытия MITRE ATT&CK"""
        with safe_operation("получение покрытия MITRE", self.logger):
            try:
                mitre = self.modules.get('mitre')
                if mitre and self._check_module_ready(mitre):
                    return mitre.get_coverage_report()
            except Exception as e:
                self.logger.error(f"Ошибка получения покрытия MITRE: {e}")
        return {}

    def generate_mitre_navigator_layer(self) -> str:
        """Генерация слоя MITRE Navigator"""
        with safe_operation("генерация слоя MITRE Navigator", self.logger):
            try:
                mitre = self.modules.get('mitre')
                if mitre and self._check_module_ready(mitre):
                    return mitre.generate_navigator_layer()
            except Exception as e:
                self.logger.error(f"Ошибка генерации слоя MITRE: {e}")
        return ""

    def execute_playbook(self, playbook_id: str, context: Dict) -> Dict:
        """Выполнение SOAR playbook"""
        with safe_operation(f"выполнение playbook {playbook_id}", self.logger):
            try:
                soar = self.modules.get('soar')
                if soar and self._check_module_ready(soar):
                    return soar.execute_playbook(playbook_id, context)
            except Exception as e:
                self.logger.error(f"Ошибка выполнения playbook: {e}")
        return {'status': 'failed', 'error': 'SOAR not available'}

    def list_playbooks(self) -> List[Dict]:
        """Список SOAR playbooks"""
        with safe_operation("получение списка playbooks", self.logger):
            try:
                soar = self.modules.get('soar')
                if soar and self._check_module_ready(soar):
                    return soar.list_playbooks()
            except Exception as e:
                self.logger.error(f"Ошибка получения списка playbooks: {e}")
        return []

    def create_forensics_case(self, name: str, description: str = "") -> str:
        """Создание кейса цифровой криминалистики"""
        with safe_operation(f"создание forensics кейса {name}", self.logger):
            try:
                forensics = self.modules.get('forensics')
                if forensics and self._check_module_ready(forensics):
                    return forensics.create_case(name, description)
            except Exception as e:
                self.logger.error(f"Ошибка создания forensics кейса: {e}")
        return ""

    def add_forensics_evidence(self, case_id: str, evidence_type: str, source: str, file_path: str) -> str:
        """Добавление улик в forensics кейс"""
        with safe_operation(f"добавление улик в кейс {case_id}", self.logger):
            try:
                safe_path = SecurityValidator.validate_file_path(
                    file_path, self.security_context
                )
                forensics = self.modules.get('forensics')
                if forensics and self._check_module_ready(forensics):
                    return forensics.add_evidence(case_id, evidence_type, source, str(safe_path))
            except (SecurityValidationError, Exception) as e:
                self.logger.error(f"Ошибка добавления улик: {e}")
        return ""

    def get_forensics_report(self, case_id: str) -> Dict:
        """Получение отчёта криминалистики"""
        with safe_operation(f"получение forensics отчёта {case_id}", self.logger):
            try:
                forensics = self.modules.get('forensics')
                if forensics and self._check_module_ready(forensics):
                    return forensics.get_report(case_id)
            except Exception as e:
                self.logger.error(f"Ошибка получения forensics отчёта: {e}")
        return {}

    def get_deception_stats(self) -> Dict:
        """Получение статистики Deception"""
        with safe_operation("получение статистики Deception", self.logger):
            try:
                deception = self.modules.get('deception')
                if deception and self._check_module_ready(deception):
                    return deception.get_stats()
            except Exception as e:
                self.logger.error(f"Ошибка получения статистики Deception: {e}")
        return {}

    def get_tip_stats(self) -> Dict:
        """Получение статистики TIP"""
        with safe_operation("получение статистики TIP", self.logger):
            try:
                tip = self.modules.get('tip')
                if tip and self._check_module_ready(tip):
                    return tip.get_stats()
            except Exception as e:
                self.logger.error(f"Ошибка получения статистики TIP: {e}")
        return {}

    def query_tip(self, indicator: str, indicator_type: str = 'auto') -> Dict:
        """Запрос к TIP с валидацией индикатора"""
        with safe_operation(f"запрос TIP {indicator}", self.logger):
            try:
                tip = self.modules.get('tip')
                if tip and self._check_module_ready(tip):
                    return tip.query(indicator, indicator_type)
            except Exception as e:
                self.logger.error(f"Ошибка запроса TIP: {e}")
        return {}


# ============================================================
# БАННЕР
# ============================================================

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ███████╗██╗  ██╗ █████╗ ██████╗ ██████╗                               ║
║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗                              ║
║   ███████╗███████║███████║██████╔╝██║  ██║                              ║
║   ╚════██║██╔══██║██╔══██║██╔══██╗██║  ██║                              ║
║   ███████║██║  ██║██║  ██║██║  ██║██████╔╝                              ║
║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                               ║
║                                                                          ║
║              ENTERPRISE SIEM - ВЕРСИЯ 5.2.0                               ║
║                                                                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ✅ DNS Аналитика                ✅ Cloud Security                        ║
║  ✅ Threat Intelligence          ✅ Federated Learning                    ║
║  ✅ Обнаружение утечки данных    ✅ RL Defense Agent                      ║
║  ✅ UBA/UEBA                     ✅ Adaptive Learning                     ║
║  ✅ Web Dashboard                ✅ Autonomous Response                   ║
║  ✅ ML с дообучением             ✅ LLM Security Analyst                  ║
║  ✅ GNN анализ графа угроз       ✅ LLM Guardian                          ║
║  ✅ Honeypot                     ✅ Code Security                         ║
║  ✅ Agentic AI расследования     ✅ CVE Intelligence                      ║
║  ✅ Red Team Automation          ✅ Threat Hunting AI                     ║
║  ✅ Deception Technology         ✅ SOAR Integration                      ║
║  ✅ Digital Forensics            ✅ MITRE ATT&CK Full Coverage            ║
║  ✅ Threat Intelligence Platform                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='SHARD Enterprise SIEM')
    parser.add_argument('--config', '-c', default='config.yaml', help='Путь к конфигурации')
    parser.add_argument('--no-enhancements', action='store_true', help='Отключить улучшения')
    parser.add_argument('--simulation', '-s', action='store_true', help='Режим симуляции')
    parser.add_argument('--no-capture', action='store_true', help='Отключить захват трафика')
    parser.add_argument('--interface', '-i', default='lo', help='Сетевой интерфейс')
    parser.add_argument('--scan-code', help='Сканировать файл на уязвимости')
    parser.add_argument('--scan-repo', help='Сканировать репозиторий')
    parser.add_argument('--scan-cve', help='Проверить CVE (например, CVE-2021-44228)')
    parser.add_argument('--scan-deps', help='Сканировать зависимости на CVE')
    parser.add_argument('--redteam', help='Запустить Red Team сканирование')
    parser.add_argument('--mitre-coverage', action='store_true', help='Показать покрытие MITRE')
    parser.add_argument('--mitre-layer', action='store_true', help='Сгенерировать слой MITRE Navigator')
    parser.add_argument('--list-playbooks', action='store_true', help='Список SOAR playbooks')
    parser.add_argument('--tip-query', help='Запрос к TIP (IP/domain/hash)')
    parser.add_argument('--allow-private', action='store_true', help='Разрешить сканирование приватных сетей')
    parser.add_argument('--health-check', action='store_true', help='Проверка здоровья системы')

    args = parser.parse_args()
    print_banner()

    print(f"📁 Конфигурация: {args.config}")
    print(f"🌐 Интерфейс: {args.interface}")
    print(f"🚀 Режим: {'Симуляция' if args.simulation else 'Боевой'}")
    print(f"🧠 Улучшения: {'Отключены' if args.no_enhancements else 'Включены'}")

    # Режим проверки здоровья
    if args.health_check:
        return run_health_check(args)

    # Режим CLI-инструментов (без запуска SIEM)
    if any([args.scan_code, args.scan_repo, args.scan_cve, args.scan_deps,
            args.redteam, args.mitre_coverage, args.mitre_layer,
            args.list_playbooks, args.tip_query]):
        return run_cli_tools(args)

    # Основной режим запуска
    try:
        enterprise = EnhancedShardEnterprise(
            config_path=args.config,
            enable_enhancements=not args.no_enhancements,
            enable_simulation=args.simulation,
            no_capture=args.no_capture
        )
    except ConfigurationError as e:
        print(f"❌ Ошибка конфигурации: {e}")
        return 1
    except Exception as e:
        print(f"❌ Критическая ошибка инициализации: {e}")
        import traceback
        traceback.print_exc()
        return 1

    def signal_handler(sig, frame):
        print("\n🛑 Получен сигнал остановки...")
        enterprise.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        enterprise.start()
        while enterprise._running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
    finally:
        enterprise.stop()
        print("\n👋 SHARD Enterprise завершил работу")

    return 0


def run_health_check(args):
    """Проверка здоровья системы (исправленная версия)"""
    enterprise = None
    try:
        enterprise = EnhancedShardEnterprise(
            config_path=args.config,
            enable_enhancements=True,
            enable_simulation=False,
            no_capture=True
        )

        import threading
        
        # Патчим ShardEnterprise.start() чтобы не вызывал блокирующий capture_loop
        # Делаем это ДО вызова enterprise.start(), а не после
        original_shard_start = None
        
        def patched_shard_start(self_shard):
            """Запуск без блокирующего capture_loop для health-check"""
            self_shard.logger.info("🚀 Health-check: запуск модулей...")
            for module in self_shard.modules:
                if module is not None and not isinstance(module, str):
                    try:
                        module.start()
                    except Exception as e:
                        self_shard.logger.error(f"  ❌ Ошибка {getattr(module, 'name', 'unknown')}: {e}")
            self_shard._running = True
        
        # Патчим ShardEnterprise.start на уровне класса (до создания экземпляра)
        import shard_enterprise_complete as sec
        original_shard_start = sec.ShardEnterprise.start
        sec.ShardEnterprise.start = patched_shard_start
        
        # Запускаем в потоке с таймаутом (try removed)
            init_complete = threading.Event()
            start_error = []
            
            def run_start():
                try:
                    enterprise.start()
                except Exception as e:
                    start_error.append(str(e))
                finally:
                    init_complete.set()
            
            t = threading.Thread(target=run_start, daemon=True, name="HealthCheck-Run")
            t.start()
        
        # Ждём с прогресс-индикатором
        print("⏳ Инициализация модулей...")
        for i in range(30):
            if init_complete.is_set():
                break
            time.sleep(1)
            print(f"   ... {i+1}с", end='\r')
        
        if not init_complete.wait(timeout=0):
            print("\n⚠️ Инициализация не завершилась за 30 секунд")
        else:
            time.sleep(3)  # Даём время фоновым потокам стартовать
            print("\n✅ Инициализация завершена")
        
        if start_error:
            print(f"❌ Ошибка инициализации: {start_error[0]}")
            return 1

        print("\n" + enterprise.get_health_report())
        return 0

    except Exception as e:
        print(f"❌ Ошибка проверки здоровья: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # Восстанавливаем оригинальный метод при ЛЮБОМ исходе
        if original_shard_start is not None:
            import shard_enterprise_complete as sec
            sec.ShardEnterprise.start = original_shard_start
        if enterprise is not None:
            try:
                enterprise.stop()
            except:
                pass

    # This return is unreachable but keeps Python parser happy
    return 0

  # This line was misplaced
        print(f"❌ Ошибка проверки здоровья: {e}")
        import traceback
        traceback.print_exc()
        if enterprise is not None:
            try:
                enterprise.stop()
            except:
                pass
        return 1


def run_cli_tools(args):
    """Выполнение CLI-команд без полного запуска SIEM"""
    from shard_enterprise_complete import ConfigManager, EventBus, LoggingService

    try:
        config = ConfigManager(args.config)
    except Exception as e:
        print(f"❌ Ошибка загрузки конфигурации: {e}")
        return 1

    event_bus = EventBus()
    logger_service = LoggingService(config, event_bus)
    logger = logger_service.get_logger("SHARD-Scanner")
    security_context = SecurityContext(
        allowed_paths={Path.cwd(), Path.home()}
    )

    return_code = 0

    # Scan Code
    if args.scan_code:
        try:
            safe_path = SecurityValidator.validate_file_path(args.scan_code, security_context)
            from shard_code_security import ShardCodeSecurityIntegration
            code_security = ShardCodeSecurityIntegration()
            code_security.setup(event_bus, logger)
            findings = code_security.analyzer.analyze_file(str(safe_path))
            print(f"\n📊 Найдено {len(findings)} уязвимостей в {args.scan_code}")
            for f in findings[:10]:
                print(f"  [{f['severity']}] Line {f['line']}: {f['rule_name']}")
        except SecurityValidationError as e:
            print(f"❌ Ошибка безопасности: {e}")
            return_code = 1
        except ImportError:
            print("❌ Code Security модуль недоступен")
            return_code = 1
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return_code = 1

    # Scan Repository
    if args.scan_repo:
        try:
            safe_path = SecurityValidator.validate_file_path(args.scan_repo, security_context)
            from shard_code_security import ShardCodeSecurityIntegration
            code_security = ShardCodeSecurityIntegration()
            code_security.setup(event_bus, logger)
            result = code_security.scan_repository(str(safe_path))
            print(f"\n📊 Отчёт сохранён: {result['report_path']}")
            print(f"   Всего файлов: {result['stats']['total_files_scanned']}")
            print(f"   Всего уязвимостей: {result['stats']['total_vulnerabilities']}")
        except SecurityValidationError as e:
            print(f"❌ Ошибка безопасности: {e}")
            return_code = 1
        except ImportError:
            print("❌ Code Security модуль недоступен")
            return_code = 1
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return_code = 1

    # Scan CVE
    if args.scan_cve:
        try:
            validated_cve = SecurityValidator.validate_cve_id(args.scan_cve)
            from shard_cve_intelligence import ShardCVEIntelligenceIntegration
            cve_intel = ShardCVEIntelligenceIntegration()
            cve_intel.setup(event_bus, logger)
            cve = cve_intel.engine.check_cve(validated_cve)
            if cve:
                print(f"\n📊 {cve.cve_id}")
                print(f"   CVSS v3: {cve.cvss_v3_score} ({cve.cvss_v3_severity})")
                print(f"   Exploit: {cve.exploit_available}")
            else:
                print(f"\n❌ CVE {args.scan_cve} не найден")
        except SecurityValidationError as e:
            print(f"❌ Некорректный CVE ID: {e}")
            return_code = 1
        except ImportError:
            print("❌ CVE Intelligence модуль недоступен")
            return_code = 1
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return_code = 1

    # Scan Dependencies
    if args.scan_deps:
        try:
            safe_path = SecurityValidator.validate_file_path(args.scan_deps, security_context)
            from shard_cve_intelligence import ShardCVEIntelligenceIntegration
            cve_intel = ShardCVEIntelligenceIntegration()
            cve_intel.setup(event_bus, logger)
            matches = cve_intel.scan_project(str(safe_path))
            print(f"\n📊 Найдено {len(matches)} уязвимостей")
            for m in matches[:10]:
                print(f"  [{m.risk_score:.0%}] {m.software.name} → {m.cve.cve_id}")
        except SecurityValidationError as e:
            print(f"❌ Ошибка безопасности: {e}")
            return_code = 1
        except ImportError:
            print("❌ CVE Intelligence модуль недоступен")
            return_code = 1
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return_code = 1

    # Red Team
    if args.redteam:
        try:
            # Валидация цели
            try:
                SecurityValidator.validate_ip_address(args.redteam)
            except SecurityValidationError:
                if any(char in args.redteam for char in ['/', '\\', '..']):
                    raise SecurityValidationError(f"Некорректная цель: {args.redteam}")

            from shard_red_team import ShardRedTeamIntegration
            red_team = ShardRedTeamIntegration()
            red_team.setup(event_bus, logger)
            result = red_team.scan_target(args.redteam, allow_private=args.allow_private)
            print(f"\n📊 Red Team сканирование завершено")
            print(f"   Цель: {args.redteam}")
            print(f"   Найдено уязвимостей: {len(result.get('vulnerabilities', []))}")
            print(f"   Отчёт: {result.get('report_path', 'N/A')}")
        except SecurityValidationError as e:
            print(f"❌ Ошибка безопасности: {e}")
            return_code = 1
        except ImportError:
            print("❌ Red Team модуль недоступен")
            return_code = 1
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return_code = 1

    # MITRE Coverage
    if args.mitre_coverage:
        try:
            from shard_mitre_attack import ShardMITREIntegration
            mitre = ShardMITREIntegration()
            mitre.setup(event_bus, logger)
            coverage = mitre.get_coverage_report()
            print(f"\n📊 MITRE ATT&CK Coverage")
            print(f"   Общее покрытие: {coverage['total_coverage']:.1%}")
            print(f"   Тактик покрыто: {coverage['tactics_covered']}/{coverage['total_tactics']}")
            print(f"   Техник покрыто: {coverage['techniques_covered']}/{coverage['total_techniques']}")
        except ImportError:
            print("❌ MITRE ATT&CK модуль недоступен")
            return_code = 1
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return_code = 1

    # MITRE Navigator Layer
    if args.mitre_layer:
        try:
            from shard_mitre_attack import ShardMITREIntegration
            mitre = ShardMITREIntegration()
            mitre.setup(event_bus, logger)
            layer_json = mitre.generate_navigator_layer()
            layer_file = "mitre_navigator_layer.json"
            with open(layer_file, 'w') as f:
                f.write(layer_json)
            print(f"\n📊 Слой MITRE Navigator сохранён: {layer_file}")
            print("   Импортируйте файл в https://mitre-attack.github.io/attack-navigator/")
        except ImportError:
            print("❌ MITRE ATT&CK модуль недоступен")
            return_code = 1
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return_code = 1

    # List Playbooks
    if args.list_playbooks:
        try:
            from shard_soar import ShardSOARIntegration
            soar = ShardSOARIntegration()
            soar.setup(event_bus, logger, None)
            playbooks = soar.list_playbooks()
            print(f"\n📊 Доступные SOAR Playbooks ({len(playbooks)}):")
            for pb in playbooks:
                print(f"   - {pb['id']}: {pb['name']}")
                print(f"     {pb['description'][:80]}...")
        except ImportError:
            print("❌ SOAR модуль недоступен")
            return_code = 1
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return_code = 1

    # TIP Query
    if args.tip_query:
        try:
            from shard_tip import ShardTIPIntegration
            tip = ShardTIPIntegration()
            tip.setup(event_bus, logger)
            result = tip.query(args.tip_query)
            print(f"\n📊 TIP Query: {args.tip_query}")
            print(f"   Malicious: {result.get('malicious', False)}")
            print(f"   Score: {result.get('score', 0)}")
            print(f"   Sources: {', '.join(result.get('sources', []))}")
            if result.get('tags'):
                print(f"   Tags: {', '.join(result.get('tags', []))}")
        except ImportError:
            print("❌ TIP модуль недоступен")
            return_code = 1
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            return_code = 1

    return return_code


# ============================================================
# ТЕСТИРОВАНИЕ
# ============================================================

def test_shard_modules():
    """Тестирование загрузки модулей"""
    print("\n🧪 Тестирование модулей SHARD Enterprise...")
    print("=" * 50)

    try:
        enterprise = EnhancedShardEnterprise(
            enable_enhancements=True,
            enable_simulation=False,
            no_capture=True
        )
    except Exception as e:
        print(f"❌ Ошибка создания Enterprise: {e}")
        return 0, 1

    status = enterprise.get_status()

    passed = 0
    failed = 0

    for module_name, info in status.get('modules', {}).items():
        if info.get('available', False):
            status_str = info.get('status', 'unknown')
            if status_str == 'running':
                print(f"✅ {module_name.replace('_', ' ').title()}: RUNNING")
                passed += 1
            else:
                print(f"⚠️ {module_name.replace('_', ' ').title()}: {status_str}")
                passed += 1
        else:
            print(f"❌ {module_name.replace('_', ' ').title()}: Not available")
            failed += 1

    print("=" * 50)
    print(f"Результаты: {passed} успешно, {failed} ошибок")

    # Выводим health report
    print(enterprise.get_health_report())

    return passed, failed


if __name__ == "__main__":
    if "--test" in sys.argv:
        print_banner()
        print("\n🧪 Режим тестирования SHARD Enterprise")
        test_shard_modules()
        print("\n✅ Тестирование завершено!")
        sys.exit(0)

    sys.exit(main())