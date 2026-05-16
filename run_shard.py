#!/usr/bin/env python3
"""
SHARD Enterprise SIEM - Главный файл запуска
Версия: 5.1.0 (рефакторинг с ModuleLoader)

Автор: SHARD Enterprise
"""

import os
import sys
import time
import signal
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

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


class EnhancedShardEnterprise:
    """Оркестратор SHARD Enterprise с автоматической загрузкой модулей"""

    def __init__(self, config_path: str = "config.yaml", enable_enhancements: bool = True,
                 enable_simulation: bool = False, no_capture: bool = False):
        self.config_path = config_path
        self.config = ConfigManager(config_path)
        self.enable_enhancements = enable_enhancements
        self.enable_simulation = enable_simulation
        self.no_capture = no_capture

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

        # Словарь загруженных модулей
        self.modules: Dict[str, Any] = {}

        self._running = False

        if self.enable_enhancements:
            self._init_enhancements()

    def _init_enhancements(self):
        """Инициализация всех модулей через ModuleLoader"""
        print("\n🚀 Инициализация улучшений SHARD Enterprise...")
        print("=" * 50)

        # Список модулей для загрузки (в порядке зависимости)
        module_load_order = [
            # ML модули
            'attention_lstm',
            'temporal_gnn',
            'contrastive_vae',
            'federated',
            'rl_defense',
            'adaptive_learning',
            # Группа автономных модулей
            'autonomous_group',
            # Безопасность
            'cloud_security',
            'llm_guardian',
            'code_security',
            'cve_intelligence',
            'red_team',
            'threat_hunting',
            'deception',
            # Оркестрация и разведка
            'soar',
            'forensics',
            'mitre',
            'tip',
        ]

        # Загружаем все модули
        for module_name in module_load_order:
            success, instance = self.loader.load_module(module_name)
            if success:
                self.modules[module_name] = instance
                # Регистрируем в реестре для DI
                self.registry.register(module_name, instance)

        # Особая инициализация группы автономных модулей
        self._init_autonomous_group()

        # Ручная инициализация Defence Pipeline (зависит от модели)
        try:
            from shard_defense_pipeline_v3 import ShardDefensePipeline
            self.defense_pipeline = ShardDefensePipeline()
            if self.defense_pipeline.model.loaded:
                print("🛡️ AI Defense Pipeline v3 загружен!")
            self.registry.register('defense_pipeline', self.defense_pipeline)
        except Exception as e:
            print(f"⚠️ Defense Pipeline: {e}")

        # Ручная инициализация Anomaly Detector
        try:
            from shard_anomaly_detector import ShardAnomalyDetector
            self.anomaly_detector = ShardAnomalyDetector()
            if self.anomaly_detector.loaded:
                print("🔍 Anomaly Detector (VAE) загружен!")
            self.registry.register('anomaly_detector', self.anomaly_detector)
        except Exception as e:
            print(f"⚠️ Anomaly Detector: {e}")

        # GNN Threat Graph
        try:
            from shard_gnn_integration import ShardGNN
            self.gnn_analyzer = ShardGNN()
            if self.gnn_analyzer.loaded:
                print("🧬 GNN Threat Graph загружен!")
            self.registry.register('gnn_analyzer', self.gnn_analyzer)
        except Exception as e:
            print(f"⚠️ GNN: {e}")

        # Multi-Modal Fusion
        try:
            from shard_fusion_integration import ShardFusion
            self.fusion = ShardFusion()
            if self.fusion.loaded:
                print("🌐 Multi-Modal Fusion загружен!")
            self.registry.register('fusion', self.fusion)
        except Exception as e:
            print(f"⚠️ Fusion: {e}")

        # Temporal GNN Predictor (отдельный от temporal_gnn)
        try:
            from shard_temporal_integration import ShardTemporalGNN
            self.temporal_gnn_predictor = ShardTemporalGNN()
            if self.temporal_gnn_predictor.loaded:
                print("🔮 Temporal GNN Predictor загружен!")
            self.registry.register('temporal_gnn_predictor', self.temporal_gnn_predictor)
        except Exception as e:
            print(f"⚠️ Temporal GNN Predictor: {e}")

        print("=" * 50)

    def _init_autonomous_group(self):
        """Инициализация автономной системы"""
        if not self.loader.is_available('autonomous_group'):
            return

        try:
            autonomous_config = {
                'llm_model_path': self.config.get('llm.model_path', ''),
                'autonomous_mode': self.config.get('autonomous.autonomous_mode', False),
                'recommend_only': self.config.get('autonomous.recommend_only', True)
            }

            from shard_autonomous_response import ShardAutonomousIntegration
            self.autonomous = ShardAutonomousIntegration(autonomous_config)
            self.registry.register('autonomous', self.autonomous)
            print("✅ Autonomous Response + LLM Analyst загружены")
        except Exception as e:
            print(f"❌ Autonomous Response: {e}")

    def start(self):
        """Запуск всех модулей"""
        print("\n🛡️ Запуск SHARD Enterprise с ВСЕМИ улучшениями...")

        # Запускаем модули, требующие start()
        startup_order = [
            'cloud_security', 'code_security', 'cve_intelligence',
            'deception', 'tip'
        ]

        for module_name in startup_order:
            instance = self.modules.get(module_name)
            if instance:
                self.loader.setup_module(module_name, instance, self.registry)
                if hasattr(instance, 'start'):
                    instance.start()
                    print(f"✅ {module_name.replace('_', ' ').title()} запущен")

        # Создаём основной ShardEnterprise
        self.shard = ShardEnterprise(
            config_path=self.config_path,
            enable_simulation=self.enable_simulation,
            no_capture=self.no_capture,
            event_bus=self.event_bus  # Единый EventBus
        )

        # Подключаем ML-модули к ML Engine
        self._wire_ml_engine()

        # Настраиваем Adaptive Ensemble
        self._setup_adaptive_ensemble()

        # Настраиваем Autonomous Response
        self._setup_autonomous()

        # Подписываемся на события
        self.event_bus.subscribe('alert.detected', self._on_alert_defense)
        self.event_bus.subscribe('honeypot.connection', self._on_alert_defense)
        print("🛡️ Defense Pipeline v3 подписан на EventBus")

        # Запускаем оставшиеся модули
        late_startup = ['llm_guardian', 'threat_hunting', 'soar',
                       'forensics', 'mitre', 'red_team']

        for module_name in late_startup:
            instance = self.modules.get(module_name)
            if instance:
                self.loader.setup_module(module_name, instance, self.registry)
                if hasattr(instance, 'start'):
                    instance.start()
                    print(f"✅ {module_name.replace('_', ' ').title()} запущен")

        self._running = True
        self.shard.start()

    def _wire_ml_engine(self):
        """Подключает ML-модули к ML Engine"""
        if not hasattr(self.shard, 'modules'):
            return

        for module in self.shard.modules:
            if module is not None and hasattr(module, 'name') and module.name == 'ML':
                # Подключаем Temporal GNN
                temporal = self.modules.get('temporal_gnn')
                if temporal:
                    module.temporal_gnn = temporal
                    print("✅ Temporal GNN подключён к ML Engine")

                # Подключаем Contrastive VAE
                contrastive = self.modules.get('contrastive_vae')
                if contrastive:
                    module.contrastive_vae = contrastive
                    print("✅ Contrastive VAE подключён к ML Engine")

                # Подключаем RL Defense
                rl_defense = self.modules.get('rl_defense')
                if rl_defense:
                    module.rl_defense = rl_defense
                    print("✅ RL Defense подключён к ML Engine")

                # Подключаем Adaptive Learning
                adaptive = self.modules.get('adaptive_learning')
                if adaptive:
                    module.adaptive_engine = adaptive
                    print("✅ Adaptive Learning подключён к ML Engine")
                break

    def _setup_adaptive_ensemble(self):
        """Настраивает ансамбль адаптивного обучения"""
        adaptive = self.modules.get('adaptive_learning')
        if not adaptive:
            return

        models = {}

        # Добавляем модели из ML Engine
        if hasattr(self.shard, 'ml_engine'):
            ml_engine = self.shard.ml_engine
            if hasattr(ml_engine, 'models'):
                for name, model in ml_engine.models.items():
                    models[f'ml_{name}'] = model

        # Добавляем другие ML-модули
        temporal = self.modules.get('temporal_gnn')
        if temporal:
            models['temporal_gnn'] = temporal

        contrastive = self.modules.get('contrastive_vae')
        if contrastive:
            models['contrastive_vae'] = contrastive

        if models:
            adaptive.register_models(models)
            print(f"✅ Adaptive Ensemble зарегистрирован с {len(models)} моделями")

    def _setup_autonomous(self):
        """Настраивает автономную систему"""
        autonomous = self.modules.get('autonomous') or self.autonomous
        if not autonomous:
            return

        # Ищем firewall в модулях ShardEnterprise
        firewall = None
        if hasattr(self.shard, 'modules'):
            for module in self.shard.modules:
                if module is not None and hasattr(module, 'name') and module.name == 'Firewall':
                    firewall = module
                    break

        # Ищем RL агента
        rl_defense = self.modules.get('rl_defense')
        rl_agent = rl_defense.agent if rl_defense and hasattr(rl_defense, 'agent') else None

        autonomous.setup(
            firewall=firewall,
            rl_agent=rl_agent,
            event_bus=self.event_bus,
            logger=self.logger
        )
        self.event_bus.subscribe('alert.detected', self._on_alert_autonomous)
        print("✅ Autonomous Response подключён к EventBus")

    def _on_alert_defense(self, alert: Dict):
        if self.defense_pipeline:
            try:
                self.defense_pipeline.process_alert(alert)
            except Exception as e:
                self.logger.debug(f"Defense pipeline error: {e}")

    def _on_alert_autonomous(self, alert: Dict):
        autonomous = self.modules.get('autonomous') or self.autonomous
        if autonomous:
            result = autonomous.on_alert(alert)
            if result and result.get('autonomous_action'):
                action = result['autonomous_action']
                self.logger.info(f"🤖 Autonomous: {action.get('action_name')} for {alert.get('src_ip')}")
            if result and result.get('llm_analysis'):
                self.logger.info(f"🧠 LLM Analysis: {result['llm_analysis'][:100]}...")

    def stop(self):
        """Остановка всех модулей"""
        print("\n🛑 Остановка SHARD Enterprise...")
        self._running = False

        # Останавливаем Adaptive Learning с сохранением
        adaptive = self.modules.get('adaptive_learning')
        if adaptive and hasattr(adaptive, 'save_models'):
            try:
                adaptive.save_models()
                print("✅ Adaptive Learning модели сохранены")
            except Exception as e:
                print(f"⚠️ Ошибка сохранения Adaptive Learning: {e}")

        # Останавливаем все модули через загрузчик
        for module_name, instance in self.modules.items():
            self.loader.stop_module(module_name, instance)

        # Останавливаем Defence Pipeline и детекторы
        for component in [self.defense_pipeline, self.anomaly_detector,
                         self.gnn_analyzer, self.fusion]:
            if component and hasattr(component, 'stop'):
                try:
                    component.stop()
                except:
                    pass

        if self.shard:
            self.shard.stop()

        print("✅ Все модули остановлены")

    def get_status(self) -> Dict:
        """Получить статус всех модулей"""
        status = {
            'shard': self._running,
        }

        # Статус модулей из загрузчика
        availability = self.loader.get_availability()
        for name in MODULE_SPECS:
            if name != 'autonomous_group':
                status[name] = availability.get(name, False)

        # Добавляем особые компоненты
        status['defense_pipeline'] = self.defense_pipeline is not None
        status['anomaly_detector'] = self.anomaly_detector is not None
        status['gnn_analyzer'] = self.gnn_analyzer is not None
        status['fusion'] = self.fusion is not None

        return status

    # === Методы-обёртки для CLI ===

    def secure_llm_call(self, prompt: str, llm_function: callable, client_id: str = 'unknown') -> Tuple[Any, Dict]:
        llm_guardian = self.modules.get('llm_guardian')
        if llm_guardian:
            return llm_guardian.secure_llm_call(prompt, llm_function, client_id)
        return llm_function(prompt), {}

    def scan_code(self, filepath: str) -> List[Dict]:
        code_security = self.modules.get('code_security')
        if code_security and hasattr(code_security, 'analyzer'):
            return code_security.analyzer.analyze_file(filepath)
        return []

    def scan_repository(self, repo_path: str) -> Dict:
        code_security = self.modules.get('code_security')
        if code_security:
            return code_security.scan_repository(repo_path)
        return {}

    def check_cve(self, cve_id: str) -> Optional[Dict]:
        cve_intel = self.modules.get('cve_intelligence')
        if cve_intel and hasattr(cve_intel, 'engine'):
            cve = cve_intel.engine.check_cve(cve_id)
            return cve.__dict__ if cve else None
        return None

    def scan_cve_dependencies(self, project_path: str) -> List:
        cve_intel = self.modules.get('cve_intelligence')
        if cve_intel:
            return cve_intel.scan_project(project_path)
        return []

    def run_red_team_scan(self, target: str, scope: List[str] = None) -> Dict:
        red_team = self.modules.get('red_team')
        if red_team:
            return red_team.scan_target(target, scope)
        return {}

    def get_threat_hunting_report(self) -> Dict:
        threat_hunting = self.modules.get('threat_hunting')
        if threat_hunting:
            return threat_hunting.get_report()
        return {}

    def get_mitre_coverage(self) -> Dict:
        mitre = self.modules.get('mitre')
        if mitre:
            return mitre.get_coverage_report()
        return {}

    def generate_mitre_navigator_layer(self) -> str:
        mitre = self.modules.get('mitre')
        if mitre:
            return mitre.generate_navigator_layer()
        return ""

    def execute_playbook(self, playbook_id: str, context: Dict) -> Dict:
        soar = self.modules.get('soar')
        if soar:
            return soar.execute_playbook(playbook_id, context)
        return {'status': 'failed', 'error': 'SOAR not available'}

    def list_playbooks(self) -> List[Dict]:
        soar = self.modules.get('soar')
        if soar:
            return soar.list_playbooks()
        return []

    def create_forensics_case(self, name: str, description: str = "") -> str:
        forensics = self.modules.get('forensics')
        if forensics:
            return forensics.create_case(name, description)
        return ""

    def add_forensics_evidence(self, case_id: str, evidence_type: str, source: str, file_path: str) -> str:
        forensics = self.modules.get('forensics')
        if forensics:
            return forensics.add_evidence(case_id, evidence_type, source, file_path)
        return ""

    def get_forensics_report(self, case_id: str) -> Dict:
        forensics = self.modules.get('forensics')
        if forensics:
            return forensics.get_report(case_id)
        return {}

    def get_deception_stats(self) -> Dict:
        deception = self.modules.get('deception')
        if deception:
            return deception.get_stats()
        return {}

    def get_tip_stats(self) -> Dict:
        tip = self.modules.get('tip')
        if tip:
            return tip.get_stats()
        return {}

    def query_tip(self, indicator: str, indicator_type: str = 'auto') -> Dict:
        tip = self.modules.get('tip')
        if tip:
            return tip.query(indicator, indicator_type)
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
║              ENTERPRISE SIEM - ВЕРСИЯ 5.1.0                               ║
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

    args = parser.parse_args()
    print_banner()

    print(f"📁 Конфигурация: {args.config}")
    print(f"🌐 Интерфейс: {args.interface}")
    print(f"🚀 Режим: {'Симуляция' if args.simulation else 'Боевой'}")
    print(f"🧠 Улучшения: {'Отключены' if args.no_enhancements else 'Включены'}")

    # Режим CLI-инструментов (без запуска SIEM)
    if any([args.scan_code, args.scan_repo, args.scan_cve, args.scan_deps,
            args.redteam, args.mitre_coverage, args.mitre_layer,
            args.list_playbooks, args.tip_query]):
        return run_cli_tools(args)

    # Основной режим запуска
    enterprise = EnhancedShardEnterprise(
        config_path=args.config,
        enable_enhancements=not args.no_enhancements,
        enable_simulation=args.simulation,
        no_capture=args.no_capture
    )

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


def run_cli_tools(args):
    """Выполнение CLI-команд без полного запуска SIEM"""
    from shard_enterprise_complete import ConfigManager, EventBus, LoggingService

    config = ConfigManager(args.config)
    event_bus = EventBus()
    logger_service = LoggingService(config, event_bus)
    logger = logger_service.get_logger("SHARD-Scanner")

    # Импортируем нужные модули
    try:
        from module_loader import ModuleLoader
        loader = ModuleLoader(config, event_bus, logger_service)
    except ImportError:
        print("⚠️ ModuleLoader недоступен, используются прямые импорты")
        loader = None

    # Scan Code
    if args.scan_code:
        try:
            from shard_code_security import ShardCodeSecurityIntegration
            code_security = ShardCodeSecurityIntegration()
            code_security.setup(event_bus, logger)
            findings = code_security.analyzer.analyze_file(args.scan_code)
            print(f"\n📊 Найдено {len(findings)} уязвимостей в {args.scan_code}")
            for f in findings[:10]:
                print(f"  [{f['severity']}] Line {f['line']}: {f['rule_name']}")
        except ImportError:
            print("❌ Code Security модуль недоступен")

    # Scan Repository
    if args.scan_repo:
        try:
            from shard_code_security import ShardCodeSecurityIntegration
            code_security = ShardCodeSecurityIntegration()
            code_security.setup(event_bus, logger)
            result = code_security.scan_repository(args.scan_repo)
            print(f"\n📊 Отчёт сохранён: {result['report_path']}")
            print(f"   Всего файлов: {result['stats']['total_files_scanned']}")
            print(f"   Всего уязвимостей: {result['stats']['total_vulnerabilities']}")
        except ImportError:
            print("❌ Code Security модуль недоступен")

    # Scan CVE
    if args.scan_cve:
        try:
            from shard_cve_intelligence import ShardCVEIntelligenceIntegration
            cve_intel = ShardCVEIntelligenceIntegration()
            cve_intel.setup(event_bus, logger)
            cve = cve_intel.engine.check_cve(args.scan_cve)
            if cve:
                print(f"\n📊 {cve.cve_id}")
                print(f"   CVSS v3: {cve.cvss_v3_score} ({cve.cvss_v3_severity})")
                print(f"   Exploit: {cve.exploit_available}")
            else:
                print(f"\n❌ CVE {args.scan_cve} не найден")
        except ImportError:
            print("❌ CVE Intelligence модуль недоступен")

    # Scan Dependencies
    if args.scan_deps:
        try:
            from shard_cve_intelligence import ShardCVEIntelligenceIntegration
            cve_intel = ShardCVEIntelligenceIntegration()
            cve_intel.setup(event_bus, logger)
            matches = cve_intel.scan_project(args.scan_deps)
            print(f"\n📊 Найдено {len(matches)} уязвимостей")
            for m in matches[:10]:
                print(f"  [{m.risk_score:.0%}] {m.software.name} → {m.cve.cve_id}")
        except ImportError:
            print("❌ CVE Intelligence модуль недоступен")

    # Red Team
    if args.redteam:
        try:
            from shard_red_team import ShardRedTeamIntegration
            red_team = ShardRedTeamIntegration()
            red_team.setup(event_bus, logger)
            result = red_team.scan_target(args.redteam)
            print(f"\n📊 Red Team сканирование завершено")
            print(f"   Цель: {args.redteam}")
            print(f"   Найдено уязвимостей: {len(result.get('vulnerabilities', []))}")
            print(f"   Отчёт: {result.get('report_path', 'N/A')}")
        except ImportError:
            print("❌ Red Team модуль недоступен")

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

    return 0


# ============================================================
# ТЕСТИРОВАНИЕ
# ============================================================

def test_shard_modules():
    """Тестирование загрузки модулей"""
    print("\n🧪 Тестирование модулей SHARD Enterprise...")
    print("=" * 50)

    enterprise = EnhancedShardEnterprise(
        enable_enhancements=True,
        enable_simulation=False,
        no_capture=True
    )

    status = enterprise.get_status()

    passed = 0
    failed = 0

    for module_name, available in status.items():
        if available:
            print(f"✅ {module_name.replace('_', ' ').title()}: OK")
            passed += 1
        else:
            print(f"⚠️ {module_name.replace('_', ' ').title()}: Not available")
            passed += 1  # Не считаем недоступные как ошибку

    print("=" * 50)
    print(f"Результаты: {passed} проверено, {failed} ошибок")
    return passed, failed


if __name__ == "__main__":
    if "--test" in sys.argv:
        print_banner()
        print("\n🧪 Режим тестирования SHARD Enterprise")
        test_shard_modules()
        print("\n✅ Тестирование завершено!")
        sys.exit(0)

    sys.exit(main())
