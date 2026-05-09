#!/usr/bin/env python3
"""SHARD Monitoring Dashboard - Prometheus + Grafana ready"""

import json
import time
from datetime import datetime


# ============================================================
# PROMETHEUS METRICS EXPORTER
# ============================================================

class MetricsExporter:
    """Экспорт метрик в Prometheus формат"""

    def __init__(self):
        self.metrics = {}

    def export(self) -> str:
        """Экспорт всех метрик"""
        lines = [
            '# HELP shard_packets_total Total packets processed',
            '# TYPE shard_packets_total counter',
            f'shard_packets_total {self.metrics.get("packets", 0)}',
            '',
            '# HELP shard_alerts_total Total alerts',
            '# TYPE shard_alerts_total counter',
            f'shard_alerts_total{{severity="CRITICAL"}} {self.metrics.get("alerts_critical", 0)}',
            f'shard_alerts_total{{severity="HIGH"}} {self.metrics.get("alerts_high", 0)}',
            f'shard_alerts_total{{severity="MEDIUM"}} {self.metrics.get("alerts_medium", 0)}',
            '',
            '# HELP shard_fp_suppressed_total False positives suppressed',
            '# TYPE shard_fp_suppressed_total counter',
            f'shard_fp_suppressed_total {self.metrics.get("fp_suppressed", 0)}',
            '',
            '# HELP shard_modules_up Module health',
            '# TYPE shard_modules_up gauge',
            f'shard_modules_up {self.metrics.get("modules_up", 0)}',
            '',
            '# HELP shard_cpu_percent CPU usage',
            '# TYPE shard_cpu_percent gauge',
            f'shard_cpu_percent {self.metrics.get("cpu", 0)}',
            '',
            '# HELP shard_memory_percent Memory usage',
            '# TYPE shard_memory_percent gauge',
            f'shard_memory_percent {self.metrics.get("memory", 0)}',
        ]
        return '\n'.join(lines) + '\n'


# ============================================================
# GRAFANA DASHBOARD JSON
# ============================================================

GRAFANA_DASHBOARD = {
    "title": "SHARD Production Pipeline",
    "uid": "shard-pipeline",
    "panels": [
        {
            "title": "Packets/sec",
            "type": "graph",
            "targets": [{"expr": "rate(shard_packets_total[1m])"}]
        },
        {
            "title": "Alerts/min",
            "type": "graph",
            "targets": [{"expr": "rate(shard_alerts_total[1m])*60"}]
        },
        {
            "title": "FP Suppressed",
            "type": "stat",
            "targets": [{"expr": "shard_fp_suppressed_total"}]
        },
        {
            "title": "Modules Up",
            "type": "gauge",
            "targets": [{"expr": "shard_modules_up"}],
            "max": 23
        }
    ]
}

if __name__ == "__main__":
    print(json.dumps(GRAFANA_DASHBOARD, indent=2))