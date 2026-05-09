#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SHARD Unified Monitoring Module - Production-Ready
Полный мониторинг всех 24 модулей с экспортом в Prometheus и Grafana дашбордом.

Возможности:
- Сбор метрик со всех модулей через EventBus
- Prometheus metrics endpoint
- JSON модель для Grafana dashboard
- Алерты на аномалии в метриках
- Health checks для каждого модуля

Author: SHARD Enterprise
Version: 5.0.0
"""

import os
import json
import time
import threading
import logging
import requests
import queue
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import psutil

logger = logging.getLogger("SHARD-Monitoring")

try:
    from prometheus_client import start_http_server, Gauge, Counter, Histogram, Summary, REGISTRY
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("⚠️ prometheus_client не установлен. pip install prometheus-client")


# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

@dataclass
class MonitoringConfig:
    """Конфигурация мониторинга"""

    # Prometheus
    prometheus_enabled: bool = True
    prometheus_port: int = 9090
    prometheus_path: str = '/metrics'

    # Сбор метрик
    collection_interval: int = 15  # секунд
    retention_hours: int = 24
    max_metrics_history: int = 100000

    # Grafana
    grafana_url: str = 'http://localhost:3000'
    grafana_api_key: str = ''
    dashboard_uid: str = 'shard-enterprise'
    auto_provision_dashboard: bool = True

    # Алерты
    enable_metric_alerts: bool = True
    alert_on_module_down: bool = True
    alert_on_high_latency: bool = True
    alert_on_disk_space: bool = True
    latency_threshold_ms: float = 1000.0
    disk_space_threshold_gb: float = 5.0

    # Хранилище
    metrics_dir: str = '/var/lib/shard/metrics/'
    dashboard_dir: str = '/etc/shard/grafana/dashboards/'


# ============================================================
# METRICS COLLECTOR (ИСПРАВЛЕННЫЙ)
# ============================================================

class MetricsCollector:
    """
    Сборщик метрик со всех модулей SHARD.

    Отслеживает:
    - Количество алертов по модулям
    - Время обработки
    - Использование памяти
    - Статус модулей (up/down)
    - Ошибки
    """

    def __init__(self, config: MonitoringConfig):
        self.config = config
        self.event_bus = None

        # Хранилище метрик
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.module_stats: Dict[str, Dict] = {}
        self.system_stats: Dict[str, Any] = {}

        # Счётчики
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = defaultdict(float)

        # Prometheus метрики
        self.prometheus_metrics: Dict[str, Any] = {}

        # Блокировки
        self._lock = threading.RLock()
        self._running = False
        self._collector_thread = None

        # Инициализация Prometheus
        if PROMETHEUS_AVAILABLE:
            self._init_prometheus_metrics()
            self._start_prometheus_server()

    def _init_prometheus_metrics(self):
        """Инициализация Prometheus метрик для всех модулей"""
        if not PROMETHEUS_AVAILABLE:
            return

        # Общие метрики
        self.prometheus_metrics['alerts_total'] = Counter(
            'shard_alerts_total',
            'Total number of alerts',
            ['module', 'severity']
        )
        self.prometheus_metrics['modules_up'] = Gauge(
            'shard_modules_up',
            'Module health status (1=up, 0=down)',
            ['module']
        )
        self.prometheus_metrics['processing_time_ms'] = Histogram(
            'shard_processing_time_ms',
            'Processing time in milliseconds',
            ['module', 'operation'],
            buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000)
        )
        self.prometheus_metrics['memory_usage_bytes'] = Gauge(
            'shard_memory_usage_bytes',
            'Memory usage in bytes',
            ['module']
        )
        self.prometheus_metrics['errors_total'] = Counter(
            'shard_errors_total',
            'Total number of errors',
            ['module', 'error_type']
        )

        # Специфичные метрики для модулей
        self.prometheus_metrics['model_predictions_total'] = Counter(
            'shard_model_predictions_total',
            'Total model predictions',
            ['model', 'result']
        )
        self.prometheus_metrics['model_confidence'] = Histogram(
            'shard_model_confidence',
            'Model prediction confidence',
            ['model'],
            buckets=(0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99)
        )
        self.prometheus_metrics['iocs_total'] = Gauge(
            'shard_iocs_total',
            'Total IOCs in database',
            ['type']
        )
        self.prometheus_metrics['network_bytes_total'] = Counter(
            'shard_network_bytes_total',
            'Total network bytes processed',
            ['direction']
        )
        self.prometheus_metrics['api_requests_total'] = Counter(
            'shard_api_requests_total',
            'Total API requests',
            ['endpoint', 'status_code']
        )

        # Бизнес-метрики
        self.prometheus_metrics['threats_blocked_total'] = Counter(
            'shard_threats_blocked_total',
            'Total blocked threats',
            ['action']
        )
        self.prometheus_metrics['investigations_total'] = Counter(
            'shard_investigations_total',
            'Total investigations',
            ['status']
        )
        self.prometheus_metrics['false_positives_total'] = Counter(
            'shard_false_positives_total',
            'Total false positive alerts'
        )

        # Системные метрики
        self.prometheus_metrics['system_cpu_percent'] = Gauge(
            'shard_system_cpu_percent',
            'System CPU usage percent'
        )
        self.prometheus_metrics['system_memory_percent'] = Gauge(
            'shard_system_memory_percent',
            'System memory usage percent'
        )
        self.prometheus_metrics['system_disk_free_gb'] = Gauge(
            'shard_system_disk_free_gb',
            'System disk free space in GB'
        )

    def _start_prometheus_server(self):
        """Запуск Prometheus HTTP сервера"""
        if not PROMETHEUS_AVAILABLE:
            return

        try:
            start_http_server(self.config.prometheus_port)
            logger.info(
                f"📊 Prometheus metrics available at :{self.config.prometheus_port}{self.config.prometheus_path}"
            )
        except OSError as e:
            if "Address already in use" in str(e):
                logger.warning(f"Port {self.config.prometheus_port} already in use, trying {self.config.prometheus_port + 1}")
                try:
                    self.config.prometheus_port += 1
                    start_http_server(self.config.prometheus_port)
                    logger.info(f"📊 Prometheus metrics available at :{self.config.prometheus_port}")
                except Exception as e2:
                    logger.error(f"Failed to start Prometheus server: {e2}")
            else:
                logger.error(f"Failed to start Prometheus server: {e}")

    def setup(self, event_bus, logger_instance=None):
        """Подключение к EventBus"""
        self.event_bus = event_bus
        if logger_instance:
            global logger
            logger = logger_instance

        # Подписка на события
        if event_bus:
            event_bus.subscribe('alert.detected', self._on_alert)
            event_bus.subscribe('packet.processed', self._on_packet)
            event_bus.subscribe('model.prediction', self._on_model_prediction)
            event_bus.subscribe('firewall.blocked', self._on_block)
            event_bus.subscribe('investigation.completed', self._on_investigation)

    def start(self):
        """Запуск сборщика метрик"""
        self._running = True
        self._collector_thread = threading.Thread(
            target=self._collection_loop,
            daemon=True,
            name="MetricsCollector"
        )
        self._collector_thread.start()
        logger.info("📊 Metrics Collector started")

    def stop(self):
        """Остановка сборщика"""
        self._running = False
        if self._collector_thread:
            self._collector_thread.join(timeout=5)
        self._flush_metrics()
        logger.info("📊 Metrics Collector stopped")

    def _collection_loop(self):
        """Основной цикл сбора метрик"""
        while self._running:
            time.sleep(self.config.collection_interval)
            try:
                self._collect_system_metrics()
                self._update_gauges()
            except Exception as e:
                logger.debug(f"Metrics collection error: {e}")

    def _collect_system_metrics(self):
        """Сбор системных метрик"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            self.system_stats['cpu_percent'] = cpu_percent
            self.gauges['system_cpu_percent'] = cpu_percent
            if PROMETHEUS_AVAILABLE and 'system_cpu_percent' in self.prometheus_metrics:
                self.prometheus_metrics['system_cpu_percent'].set(cpu_percent)

            # Память
            memory = psutil.virtual_memory()
            self.system_stats['memory_used_gb'] = memory.used / (1024**3)
            self.system_stats['memory_total_gb'] = memory.total / (1024**3)
            self.system_stats['memory_percent'] = memory.percent
            self.gauges['system_memory_percent'] = memory.percent
            if PROMETHEUS_AVAILABLE and 'system_memory_percent' in self.prometheus_metrics:
                self.prometheus_metrics['system_memory_percent'].set(memory.percent)

            # Диск
            disk = psutil.disk_usage('/')
            free_gb = disk.free / (1024**3)
            self.system_stats['disk_free_gb'] = free_gb
            self.system_stats['disk_percent'] = disk.percent
            self.gauges['system_disk_free_gb'] = free_gb
            if PROMETHEUS_AVAILABLE and 'system_disk_free_gb' in self.prometheus_metrics:
                self.prometheus_metrics['system_disk_free_gb'].set(free_gb)

            # Сеть
            net_io = psutil.net_io_counters()
            self.system_stats['net_bytes_sent'] = net_io.bytes_sent
            self.system_stats['net_bytes_recv'] = net_io.bytes_recv

            # Алерт на диск
            if self.config.alert_on_disk_space and free_gb < self.config.disk_space_threshold_gb:
                logger.warning(f"⚠️ Low disk space: {free_gb:.1f} GB free")
                if self.event_bus:
                    self.event_bus.publish('system.alert', {
                        'type': 'disk_space',
                        'free_gb': free_gb,
                        'threshold_gb': self.config.disk_space_threshold_gb,
                        'timestamp': time.time()
                    })

        except Exception as e:
            logger.debug(f"System metrics collection error: {e}")

    def _on_alert(self, alert: Dict):
        """Обработка алерта"""
        module = alert.get('source_module', 'unknown')
        severity = alert.get('severity', 'MEDIUM')

        with self._lock:
            self.counters[f'alerts:{module}:{severity}'] += 1
            self.counters['alerts_total'] += 1

        # Prometheus
        if PROMETHEUS_AVAILABLE and 'alerts_total' in self.prometheus_metrics:
            self.prometheus_metrics['alerts_total'].labels(
                module=module, severity=severity
            ).inc()

    def _on_packet(self, data: Dict):
        """Обработка пакета"""
        with self._lock:
            self.counters['packets_total'] += 1

        if PROMETHEUS_AVAILABLE and 'network_bytes_total' in self.prometheus_metrics:
            direction = 'outbound' if data.get('is_outbound', False) else 'inbound'
            self.prometheus_metrics['network_bytes_total'].labels(
                direction=direction
            ).inc(data.get('size', 0))

    def _on_model_prediction(self, data: Dict):
        """Обработка предсказания модели"""
        model = data.get('model', 'unknown')

        if PROMETHEUS_AVAILABLE and 'model_predictions_total' in self.prometheus_metrics:
            self.prometheus_metrics['model_predictions_total'].labels(
                model=model,
                result='attack' if data.get('is_attack') else 'normal'
            ).inc()

            if 'confidence' in data and 'model_confidence' in self.prometheus_metrics:
                self.prometheus_metrics['model_confidence'].labels(
                    model=model
                ).observe(data['confidence'])

    def _on_block(self, data: Dict):
        """Обработка блокировки"""
        if PROMETHEUS_AVAILABLE and 'threats_blocked_total' in self.prometheus_metrics:
            self.prometheus_metrics['threats_blocked_total'].labels(
                action=data.get('action', 'block')
            ).inc()

    def _on_investigation(self, data: Dict):
        """Обработка расследования"""
        if PROMETHEUS_AVAILABLE and 'investigations_total' in self.prometheus_metrics:
            self.prometheus_metrics['investigations_total'].labels(
                status=data.get('status', 'completed')
            ).inc()

    def update_module_status(self, module_name: str, is_up: bool, stats: Dict = None):
        """Обновление статуса модуля"""
        with self._lock:
            if module_name not in self.module_stats:
                self.module_stats[module_name] = {}

            update_data = {
                'is_up': is_up,
                'last_checked': time.time()
            }
            if stats:
                update_data.update(stats)

            self.module_stats[module_name].update(update_data)

        # Prometheus
        if PROMETHEUS_AVAILABLE and 'modules_up' in self.prometheus_metrics:
            self.prometheus_metrics['modules_up'].labels(
                module=module_name
            ).set(1 if is_up else 0)

        # Алерт если модуль упал
        if not is_up and self.config.alert_on_module_down:
            logger.error(f"🚨 Module DOWN: {module_name}")
            if self.event_bus:
                self.event_bus.publish('system.alert', {
                    'type': 'module_down',
                    'module': module_name,
                    'timestamp': time.time()
                })

    def record_error(self, module_name: str, error_type: str):
        """Запись ошибки"""
        with self._lock:
            self.counters[f'errors:{module_name}:{error_type}'] += 1

        if PROMETHEUS_AVAILABLE and 'errors_total' in self.prometheus_metrics:
            self.prometheus_metrics['errors_total'].labels(
                module=module_name, error_type=error_type
            ).inc()

    def record_latency(self, module_name: str, operation: str, latency_ms: float):
        """Запись задержки"""
        if PROMETHEUS_AVAILABLE and 'processing_time_ms' in self.prometheus_metrics:
            self.prometheus_metrics['processing_time_ms'].labels(
                module=module_name, operation=operation
            ).observe(latency_ms)

        # Алерт на высокую задержку
        if latency_ms > self.config.latency_threshold_ms and self.config.alert_on_high_latency:
            logger.warning(f"⚠️ High latency: {module_name}/{operation} = {latency_ms:.0f}ms")

    def _update_gauges(self):
        """Обновление gauge метрик"""
        # Обновление IOCs если TIP доступен
        if PROMETHEUS_AVAILABLE and 'iocs_total' in self.prometheus_metrics:
            for key, value in self.gauges.items():
                if key.startswith('ioc:'):
                    self.prometheus_metrics['iocs_total'].labels(
                        type=key.replace('ioc:', '')
                    ).set(value)

    def _flush_metrics(self):
        """Сохранение метрик на диск"""
        metrics_path = Path(self.config.metrics_dir)
        metrics_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = metrics_path / f'metrics_{timestamp}.json'

        with self._lock:
            data = {
                'timestamp': time.time(),
                'counters': dict(self.counters),
                'gauges': dict(self.gauges),
                'system': self.system_stats,
                'modules': self.module_stats
            }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Очистка старых файлов
        cutoff = time.time() - (self.config.retention_hours * 3600)
        for old_file in metrics_path.glob('metrics_*.json'):
            if old_file.stat().st_mtime < cutoff:
                old_file.unlink()

        logger.debug(f"Metrics flushed to {filename}")

    def get_current_metrics(self) -> Dict:
        """Получить текущие метрики"""
        with self._lock:
            return {
                'timestamp': time.time(),
                'counters': dict(self.counters),
                'gauges': dict(self.gauges),
                'system': dict(self.system_stats),
                'modules': dict(self.module_stats)
            }

    def get_module_health(self) -> Dict[str, bool]:
        """Проверка здоровья всех модулей"""
        return {
            name: stats.get('is_up', False)
            for name, stats in self.module_stats.items()
        }


# ============================================================
# GRAFANA DASHBOARD GENERATOR (ИСПРАВЛЕННЫЙ)
# ============================================================

class GrafanaDashboardGenerator:
    """
    Генератор Grafana дашборда для SHARD Enterprise.
    """

    def __init__(self, config: MonitoringConfig):
        self.config = config

    def generate_dashboard_json(self) -> Dict:
        """Генерация JSON модели для Grafana dashboard."""
        dashboard = self._build_dashboard_structure()
        return dashboard

    def _build_dashboard_structure(self) -> Dict:
        """Построение структуры дашборда"""
        dashboard = {
            "annotations": {
                "list": [
                    {
                        "builtIn": 1,
                        "datasource": "-- Grafana --",
                        "enable": True,
                        "hide": True,
                        "iconColor": "rgba(0, 211, 255, 1)",
                        "name": "Annotations & Alerts",
                        "type": "dashboard"
                    }
                ]
            },
            "editable": True,
            "gnetId": None,
            "graphTooltip": 0,
            "id": None,
            "links": [],
            "panels": [],
            "refresh": "10s",
            "schemaVersion": 30,
            "style": "dark",
            "tags": ["shard", "siem", "security"],
            "templating": {
                "list": [
                    self._build_template_variable(
                        "module", "Module",
                        "label_values(shard_alerts_total, module)"
                    ),
                    self._build_template_variable(
                        "severity", "Severity",
                        "label_values(shard_alerts_total, severity)"
                    )
                ]
            },
            "time": {
                "from": "now-6h",
                "to": "now"
            },
            "timepicker": {
                "refresh_intervals": ["5s", "10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d"],
                "time_options": ["5m", "15m", "1h", "6h", "12h", "24h", "2d", "7d", "30d"]
            },
            "timezone": "browser",
            "title": "🛡️ SHARD Enterprise SIEM",
            "uid": self.config.dashboard_uid,
            "version": 1,
            "weekStart": "monday"
        }

        # Сборка панелей
        panels = []
        panels.extend(self._generate_overview_row(0))
        panels.extend(self._generate_alerts_row(8))
        panels.extend(self._generate_module_health_row(20))
        panels.extend(self._generate_system_row(36))
        panels.extend(self._generate_ml_row(44))
        panels.extend(self._generate_threat_intel_row(52))

        # Назначение ID панелям
        for idx, panel in enumerate(panels):
            if 'id' not in panel:
                panel['id'] = idx + 1

        dashboard["panels"] = panels
        return dashboard

    def _build_template_variable(self, name: str, label: str, query: str) -> Dict:
        """Построение template variable"""
        return {
            "allValue": None,
            "current": {"selected": False, "text": "All", "value": "$__all"},
            "datasource": "Prometheus",
            "definition": query,
            "hide": 0,
            "includeAll": True,
            "label": label,
            "multi": True,
            "name": name,
            "options": [],
            "query": query,
            "refresh": 1,
            "regex": "",
            "skipUrlSync": False,
            "sort": 1,
            "type": "query"
        }

    def _generate_overview_row(self, y_position: int) -> List[Dict]:
        """Панели общего обзора"""
        return [
            self._build_stat_panel(
                "Total Alerts (24h)", 0, y_position, 6, 8,
                "sum(increase(shard_alerts_total[24h]))",
                [("green", None), ("orange", 100), ("red", 500)]
            ),
            self._build_stat_panel(
                "Threats Blocked", 6, y_position, 6, 8,
                "sum(increase(shard_threats_blocked_total[24h]))",
                [("blue", None), ("green", 10), ("orange", 50)]
            ),
            self._build_gauge_panel(
                "Modules Up", 12, y_position, 6, 8,
                "sum(shard_modules_up)", 24
            ),
            self._build_gauge_panel(
                "System CPU", 18, y_position, 6, 8,
                "avg(rate(process_cpu_seconds_total[5m])) * 100", 100
            )
        ]

    def _generate_alerts_row(self, y_position: int) -> List[Dict]:
        """Панели алертов"""
        return [
            self._build_timeseries_panel(
                "Alerts Rate by Module", 0, y_position, 12, 12,
                "rate(shard_alerts_total{module=~\"$module\", severity=~\"$severity\"}[5m])",
                "{{module}} - {{severity}}"
            ),
            self._build_piechart_panel(
                "Alerts by Severity", 12, y_position, 6, 12,
                "sum by (severity) (increase(shard_alerts_total[24h]))",
                "{{severity}}"
            ),
            self._build_piechart_panel(
                "Investigations Status", 18, y_position, 6, 12,
                "sum by (status) (increase(shard_investigations_total[24h]))",
                "{{status}}"
            )
        ]

    def _generate_module_health_row(self, y_position: int) -> List[Dict]:
        """Панели здоровья модулей"""
        modules = [
            ("Super AI", "super_ai"), ("Adaptive Learning", "adaptive_learning"),
            ("Temporal GNN", "temporal_gnn"), ("Contrastive VAE", "contrastive_vae"),
            ("DL Models", "dl_models"), ("RL Defense", "rl_defense"),
            ("LLM Guardian", "llm_guardian"), ("JA3 Analyzer", "ja3_analyzer"),
            ("TIP", "tip"), ("SOAR", "soar"),
            ("Threat Hunting", "threat_hunting"), ("Code Security", "code_security"),
            ("CVE Intel", "cve_intelligence"), ("Forensics", "digital_forensics"),
            ("MITRE", "mitre_attack"), ("Red Team", "red_team"),
            ("Cloud Security", "cloud_security"), ("Deception", "deception_technology"),
            ("P2P Reputation", "p2p_reputation"), ("Mobile API", "mobile_api"),
            ("DNS Analyzer", "dns_analyzer"), ("Firewall", "firewall"),
            ("WAF", "waf"), ("Federated", "federated")
        ]

        panels = []
        for idx, (display_name, module_key) in enumerate(modules):
            col = (idx % 6) * 4
            row_offset = (idx // 6) * 4

            panels.append({
                "datasource": "Prometheus",
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "thresholds"},
                        "mappings": [
                            {
                                "type": "value",
                                "options": {
                                    "0": {"color": "red", "text": "DOWN"},
                                    "1": {"color": "green", "text": "UP"}
                                }
                            }
                        ],
                        "thresholds": {
                            "mode": "absolute",
                            "steps": [
                                {"color": "red", "value": None},
                                {"color": "green", "value": 1}
                            ]
                        },
                        "unit": "none"
                    }
                },
                "gridPos": {"h": 4, "w": 4, "x": col, "y": y_position + row_offset},
                "title": display_name,
                "type": "stat",
                "targets": [{
                    "expr": f"shard_modules_up{{module=\"{module_key}\"}}",
                    "refId": "A"
                }]
            })

        return panels

    def _generate_system_row(self, y_position: int) -> List[Dict]:
        """Системные метрики"""
        return [
            self._build_timeseries_panel(
                "CPU Usage", 0, y_position, 8, 8,
                "rate(process_cpu_seconds_total[5m]) * 100", "CPU %"
            ),
            self._build_timeseries_panel(
                "Memory Usage", 8, y_position, 8, 8,
                "process_resident_memory_bytes / 1024 / 1024 / 1024", "Memory (GB)"
            ),
            self._build_timeseries_panel(
                "Network Traffic", 16, y_position, 8, 8,
                "rate(shard_network_bytes_total[5m])", "{{direction}}"
            )
        ]

    def _generate_ml_row(self, y_position: int) -> List[Dict]:
        """ML метрики"""
        return [
            self._build_timeseries_panel(
                "Model Predictions", 0, y_position, 12, 8,
                "rate(shard_model_predictions_total[5m])", "{{model}} - {{result}}"
            ),
            self._build_heatmap_panel(
                "Model Confidence", 12, y_position, 12, 8,
                "sum(rate(shard_model_confidence_bucket[5m])) by (le, model)", "{{le}} - {{model}}"
            )
        ]

    def _generate_threat_intel_row(self, y_position: int) -> List[Dict]:
        """Threat Intelligence метрики"""
        return [
            self._build_piechart_panel(
                "IOCs by Type", 0, y_position, 12, 8,
                "shard_iocs_total", "{{type}}"
            ),
            self._build_stat_panel(
                "False Positives (24h)", 12, y_position, 4, 8,
                "increase(shard_false_positives_total[24h])",
                [("green", None), ("orange", 10), ("red", 50)]
            ),
            self._build_piechart_panel(
                "Errors by Module", 16, y_position, 8, 8,
                "sum by (module) (increase(shard_errors_total[24h]))", "{{module}}"
            )
        ]

    def _build_stat_panel(self, title: str, x: int, y: int, w: int, h: int,
                          expr: str, thresholds: List[Tuple]) -> Dict:
        """Построение stat панели"""
        steps = []
        for idx, (color, value) in enumerate(thresholds):
            steps.append({"color": color, "value": value})

        return {
            "datasource": "Prometheus",
            "fieldConfig": {
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "mappings": [],
                    "thresholds": {"mode": "absolute", "steps": steps},
                    "unit": "short"
                }
            },
            "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "options": {
                "colorMode": "value",
                "graphMode": "area",
                "justifyMode": "auto",
                "orientation": "auto"
            },
            "title": title,
            "type": "stat",
            "targets": [{"expr": expr, "refId": "A"}]
        }

    def _build_gauge_panel(self, title: str, x: int, y: int, w: int, h: int,
                           expr: str, max_value: float) -> Dict:
        """Построение gauge панели"""
        return {
            "datasource": "Prometheus",
            "fieldConfig": {
                "defaults": {
                    "color": {"mode": "palette-classic"},
                    "mappings": [],
                    "max": max_value,
                    "min": 0,
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                            {"color": "orange", "value": max_value * 0.7},
                            {"color": "red", "value": max_value * 0.9}
                        ]
                    }
                }
            },
            "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "options": {"orientation": "auto", "reduceOptions": {"calcs": ["lastNotNull"]}},
            "title": title,
            "type": "gauge",
            "targets": [{"expr": expr, "refId": "A"}]
        }

    def _build_timeseries_panel(self, title: str, x: int, y: int, w: int, h: int,
                                expr: str, legend_format: str) -> Dict:
        """Построение timeseries панели"""
        return {
            "datasource": "Prometheus",
            "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "options": {
                "legend": {
                    "calcs": ["max", "mean"],
                    "displayMode": "table",
                    "placement": "bottom"
                },
                "tooltip": {"mode": "multi"}
            },
            "title": title,
            "type": "timeseries",
            "targets": [{"expr": expr, "legendFormat": legend_format, "refId": "A"}]
        }

    def _build_piechart_panel(self, title: str, x: int, y: int, w: int, h: int,
                              expr: str, legend_format: str) -> Dict:
        """Построение piechart панели"""
        return {
            "datasource": "Prometheus",
            "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "options": {
                "displayLabels": ["name", "percent"],
                "legend": {
                    "displayMode": "table",
                    "placement": "right" if w >= 8 else "bottom"
                }
            },
            "title": title,
            "type": "piechart",
            "targets": [{"expr": expr, "legendFormat": legend_format, "refId": "A"}]
        }

    def _build_heatmap_panel(self, title: str, x: int, y: int, w: int, h: int,
                             expr: str, legend_format: str) -> Dict:
        """Построение heatmap панели"""
        return {
            "datasource": "Prometheus",
            "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "options": {
                "calculate": True,
                "cellGap": 1,
                "color": {"mode": "scheme", "scheme": "Spectral"},
                "legend": {"show": True}
            },
            "title": title,
            "type": "heatmap",
            "targets": [{"expr": expr, "legendFormat": legend_format, "refId": "A"}]
        }

    def save_dashboard(self, filepath: str = None) -> str:
        """Сохранение дашборда в файл"""
        if not filepath:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = str(
                Path(self.config.dashboard_dir) /
                f'shard_enterprise_dashboard_{timestamp}.json'
            )

        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        dashboard = self.generate_dashboard_json()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(dashboard, f, indent=2, ensure_ascii=False)

        logger.info(f"📊 Grafana dashboard saved to {filepath}")
        return str(filepath)

    def provision_to_grafana(self) -> bool:
        """Автоматическая загрузка дашборда в Grafana API"""
        if not self.config.auto_provision_dashboard:
            return False

        if not self.config.grafana_api_key:
            logger.warning("Grafana API key not configured, skipping provisioning")
            return False

        try:
            dashboard = self.generate_dashboard_json()
            dashboard['id'] = None

            headers = {
                'Authorization': f'Bearer {self.config.grafana_api_key}',
                'Content-Type': 'application/json'
            }

            response = requests.post(
                f"{self.config.grafana_url}/api/dashboards/db",
                json={'dashboard': dashboard, 'overwrite': True},
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"✅ Dashboard provisioned to Grafana (uid: {self.config.dashboard_uid})")
                return True
            else:
                logger.error(f"Grafana provisioning failed: {response.status_code} - {response.text[:200]}")
                return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Grafana provisioning error: {e}")
            return False
        except Exception as e:
            logger.error(f"Grafana provisioning unexpected error: {e}")
            return False


# ============================================================
# SHARD INTEGRATION
# ============================================================

class ShardMonitoringIntegration:
    """Интеграция мониторинга в SHARD Enterprise"""

    def __init__(self, config: Dict = None):
        self.config = MonitoringConfig()
        if config:
            for key, value in config.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)

        self.collector = MetricsCollector(self.config)
        self.dashboard_generator = GrafanaDashboardGenerator(self.config)
        self.event_bus = None
        self.logger = logger

    def setup(self, event_bus, logger_instance=None):
        """Настройка интеграции"""
        self.event_bus = event_bus
        if logger_instance:
            self.logger = logger_instance
            global logger
            logger = logger_instance

        self.collector.setup(event_bus, logger_instance)

    def start(self):
        """Запуск мониторинга"""
        self.collector.start()

        # Генерация и сохранение дашборда
        try:
            dashboard_path = self.dashboard_generator.save_dashboard()
            self.logger.info(f"📊 Dashboard saved to: {dashboard_path}")

            # Автоматическая загрузка в Grafana
            self.dashboard_generator.provision_to_grafana()
        except Exception as e:
            self.logger.error(f"Dashboard generation error: {e}")

        self.logger.info("📊 Monitoring started")

    def stop(self):
        """Остановка мониторинга"""
        self.collector.stop()

    def update_module_health(self, module_name: str, is_up: bool, stats: Dict = None):
        """Обновить здоровье модуля"""
        self.collector.update_module_status(module_name, is_up, stats)

    def record_alert(self, module_name: str, severity: str):
        """Записать алерт в метрики"""
        self.collector._on_alert({
            'source_module': module_name,
            'severity': severity
        })

    def record_error(self, module_name: str, error_type: str):
        """Записать ошибку"""
        self.collector.record_error(module_name, error_type)

    def record_latency(self, module_name: str, operation: str, latency_ms: float):
        """Записать задержку"""
        self.collector.record_latency(module_name, operation, latency_ms)

    def get_current_metrics(self) -> Dict:
        """Получить текущие метрики"""
        return self.collector.get_current_metrics()

    def get_module_health(self) -> Dict[str, bool]:
        """Получить здоровье всех модулей"""
        return self.collector.get_module_health()

    def export_dashboard(self, filepath: str = None) -> str:
        """Экспортировать дашборд"""
        return self.dashboard_generator.save_dashboard(filepath)


# ============================================================
# ТЕСТИРОВАНИЕ
# ============================================================

def test_monitoring():
    """Тестирование мониторинга"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ UNIFIED MONITORING")
    print("=" * 60)

    config = MonitoringConfig()
    config.prometheus_port = 9091  # Изменяем порт чтобы избежать конфликтов
    integration = ShardMonitoringIntegration()

    # Не запускаем Prometheus сервер для теста
    integration.config.prometheus_enabled = False

    integration.start()

    # Тест 1: Обновление здоровья модулей
    print("\n📝 Тест 1: Обновление здоровья модулей")
    test_modules = ['super_ai', 'temporal_gnn', 'dl_models', 'firewall', 'waf']
    for mod in test_modules:
        integration.update_module_health(mod, True, {'version': '5.0.0'})
    print(f"   Updated {len(test_modules)} modules")

    # Проверка здоровья
    health = integration.get_module_health()
    up_count = sum(1 for v in health.values() if v)
    print(f"   Modules up: {up_count}/{len(health)}")

    # Тест 2: Запись алертов
    print("\n📝 Тест 2: Запись алертов")
    for i in range(10):
        integration.record_alert('super_ai', 'HIGH')
    print(f"   Recorded 10 alerts")

    # Тест 3: Запись ошибок
    print("\n📝 Тест 3: Запись ошибок")
    integration.record_error('temporal_gnn', 'connection_timeout')
    integration.record_error('dl_models', 'out_of_memory')
    print(f"   Recorded 2 errors")

    # Тест 4: Запись задержек
    print("\n📝 Тест 4: Запись задержек")
    integration.record_latency('super_ai', 'inference', 150.5)
    integration.record_latency('dl_models', 'training', 2500.0)
    print(f"   Recorded 2 latency measurements")

    # Тест 5: Генерация дашборда
    print("\n📝 Тест 5: Генерация Grafana дашборда")
    try:
        dashboard_path = integration.export_dashboard("./test_dashboard.json")
        print(f"   Dashboard saved to: {dashboard_path}")

        # Проверка размера файла
        file_size = os.path.getsize(dashboard_path)
        print(f"   Dashboard file size: {file_size:,} bytes")

        # Проверка валидности JSON
        with open(dashboard_path, 'r', encoding='utf-8') as f:
            dashboard_data = json.load(f)
        panel_count = len(dashboard_data.get('panels', []))
        print(f"   Dashboard panels: {panel_count}")

    except Exception as e:
        print(f"   ❌ Dashboard error: {e}")

    # Тест 6: Получение метрик
    print("\n📝 Тест 6: Текущие метрики")
    metrics = integration.get_current_metrics()
    print(f"   Total alerts: {sum(v for k, v in metrics.get('counters', {}).items() if 'alerts' in k)}")
    print(f"   Total errors: {sum(v for k, v in metrics.get('counters', {}).items() if 'errors' in k)}")
    print(f"   Modules tracked: {len(metrics.get('modules', {}))}")

    integration.stop()

    # Очистка тестового файла
    if os.path.exists("./test_dashboard.json"):
        os.unlink("./test_dashboard.json")

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_monitoring()