#!/usr/bin/env python3
"""
SHARD Enterprise - Production Pipeline
Стабильный запуск с контролем ложных срабатываний и мониторингом
"""

import os
import sys
import time
import signal
import logging
import threading
from pathlib import Path
from datetime import datetime
from collections import deque

import numpy as np
import psutil


PIPELINE_CONFIG = {
    "capture_interface": "eth0",
    "capture_filter": "ip",
    "packet_buffer_size": 50000,

    "fp_threshold": 3,
    "fp_window_minutes": 60,
    "auto_suppress_fp": True,
    "min_confidence": 0.7,

    "metrics_interval": 10,
    "health_check_interval": 30,
    "alert_threshold": 100,
    "cpu_threshold": 80,
    "memory_threshold": 85,

    "restart_on_crash": True,
    "max_restarts": 5,
    "restart_cooldown": 60,
    "graceful_shutdown_timeout": 30,
}


class FalsePositiveController:

    def __init__(self, config: dict):
        self.config = config
        self.fp_counter = {}
        self.fp_timestamps = {}
        self.suppressed_rules = set()
        self._lock = threading.RLock()

        self.stats = {
            'total_fp_suppressed': 0,
            'active_suppressions': 0,
            'fp_by_rule': {}
        }

    def record_alert(self, rule_id: str, is_false_positive: bool = False):
        if not is_false_positive:
            return

        with self._lock:
            if rule_id not in self.fp_counter:
                self.fp_counter[rule_id] = 0
                self.fp_timestamps[rule_id] = deque(maxlen=100)

            now = time.time()
            self.fp_counter[rule_id] += 1
            self.fp_timestamps[rule_id].append(now)

            cutoff = now - (self.config['fp_window_minutes'] * 60)
            while self.fp_timestamps[rule_id] and self.fp_timestamps[rule_id][0] < cutoff:
                self.fp_timestamps[rule_id].popleft()
                self.fp_counter[rule_id] -= 1

            recent_count = len(self.fp_timestamps[rule_id])
            if recent_count >= self.config['fp_threshold'] and rule_id not in self.suppressed_rules:
                self.suppress_rule(rule_id)

    def suppress_rule(self, rule_id: str):
        with self._lock:
            self.suppressed_rules.add(rule_id)
            self.stats['total_fp_suppressed'] += 1
            self.stats['active_suppressions'] = len(self.suppressed_rules)
            self.stats['fp_by_rule'][rule_id] = self.fp_counter.get(rule_id, 0)

            logging.getLogger("SHARD-FP").warning(
                f"🚫 Rule {rule_id} suppressed due to {self.fp_counter[rule_id]} false positives"
            )

    def is_suppressed(self, rule_id: str) -> bool:
        with self._lock:
            return rule_id in self.suppressed_rules

    def unsuppress_rule(self, rule_id: str):
        with self._lock:
            self.suppressed_rules.discard(rule_id)
            if rule_id in self.fp_counter:
                self.fp_counter[rule_id] = 0
                self.fp_timestamps[rule_id].clear()
            self.stats['active_suppressions'] = len(self.suppressed_rules)

    def should_alert(self, rule_id: str, confidence: float) -> bool:
        if self.is_suppressed(rule_id):
            return False
        if confidence < self.config['min_confidence']:
            return False
        return True

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self.stats)


class PipelineMonitor:

    def __init__(self, config: dict):
        self.config = config
        self.metrics = {
            'packets_processed': 0,
            'alerts_generated': 0,
            'alerts_blocked': 0,
            'errors': 0,
            'cpu_percent': 0,
            'memory_percent': 0,
            'disk_free_gb': 0,
            'uptime_seconds': 0,
            'alerts_per_minute': 0,
            'packets_per_second': 0,
        }

        self.alert_buffer = deque(maxlen=1000)
        self.start_time = time.time()
        self._lock = threading.RLock()
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._metrics_loop, daemon=True, name="PipelineMonitor").start()
        threading.Thread(target=self._health_check_loop, daemon=True, name="HealthCheck").start()

    def _metrics_loop(self):
        last_packets = 0
        last_alerts = 0
        last_time = time.time()

        while self._running:
            time.sleep(self.config['metrics_interval'])

            with self._lock:
                self.metrics['cpu_percent'] = psutil.cpu_percent()
                self.metrics['memory_percent'] = psutil.virtual_memory().percent
                self.metrics['disk_free_gb'] = psutil.disk_usage('/').free / (1024 ** 3)
                self.metrics['uptime_seconds'] = time.time() - self.start_time

                now = time.time()
                elapsed = now - last_time

                if elapsed > 0:
                    pps = (self.metrics['packets_processed'] - last_packets) / elapsed
                    apm = (self.metrics['alerts_generated'] - last_alerts) / elapsed * 60

                    self.metrics['packets_per_second'] = round(pps, 1)
                    self.metrics['alerts_per_minute'] = round(apm, 1)

                last_packets = self.metrics['packets_processed']
                last_alerts = self.metrics['alerts_generated']
                last_time = now

                self._check_thresholds()

    def _health_check_loop(self):
        while self._running:
            time.sleep(self.config['health_check_interval'])
            self._health_check()

    def _health_check(self):
        pass

    def _check_thresholds(self):
        warnings = []

        if self.metrics['cpu_percent'] > self.config['cpu_threshold']:
            warnings.append(f"High CPU: {self.metrics['cpu_percent']}%")

        if self.metrics['memory_percent'] > self.config['memory_threshold']:
            warnings.append(f"High Memory: {self.metrics['memory_percent']}%")

        if self.metrics['alerts_per_minute'] > self.config['alert_threshold']:
            warnings.append(f"Alert storm: {self.metrics['alerts_per_minute']}/min")

        for w in warnings:
            logging.getLogger("SHARD-Monitor").warning(f"⚠️ {w}")

    def record_packet(self):
        with self._lock:
            self.metrics['packets_processed'] += 1

    def record_alert(self, blocked: bool = False):
        with self._lock:
            self.metrics['alerts_generated'] += 1
            if blocked:
                self.metrics['alerts_blocked'] += 1

    def record_error(self):
        with self._lock:
            self.metrics['errors'] += 1

    def get_metrics(self) -> dict:
        with self._lock:
            return dict(self.metrics)

    def stop(self):
        self._running = False


class ProductionPipeline:

    def __init__(self, config: dict = None):
        self.config = config or PIPELINE_CONFIG
        self.fp_controller = FalsePositiveController(self.config)
        self.monitor = PipelineMonitor(self.config)
        self.shard = None
        self._running = False
        self.restart_count = 0
        self.last_restart = 0

        self._setup_logging()
        self.logger = logging.getLogger("SHARD-Pipeline")

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            handlers=[
                logging.FileHandler('shard_pipeline.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def start(self):
        self.logger.info("=" * 60)
        self.logger.info("🚀 SHARD PRODUCTION PIPELINE STARTING")
        self.logger.info("=" * 60)

        self.monitor.start()

        self._start_shard()

        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
        finally:
            self.stop()

    def _start_shard(self):
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from run_shard import EnhancedShardEnterprise

            self.shard = EnhancedShardEnterprise(
                config_path="config.yaml",
                enable_enhancements=True,
                enable_simulation=False,
                no_capture=False
            )

            self._hook_alerts()

            self.shard.start()
            self._running = True

        except Exception as e:
            self.logger.error(f"Failed to start SHARD: {e}")
            self._handle_crash()

    def _hook_alerts(self):
        if not self.shard or not self.shard.event_bus:
            return

        def alert_filter(alert):
            rule_id = alert.get('rule_id', alert.get('attack_type', 'unknown'))
            confidence = alert.get('confidence', 0.5)

            if not self.fp_controller.should_alert(rule_id, confidence):
                self.monitor.record_alert(blocked=True)
                return

            self.monitor.record_alert()

        self.shard.event_bus.subscribe('alert.detected', alert_filter)

    def report_false_positive(self, rule_id: str):
        self.fp_controller.record_alert(rule_id, is_false_positive=True)

    def _handle_crash(self):
        if not self.config['restart_on_crash']:
            return

        now = time.time()
        if now - self.last_restart < self.config['restart_cooldown']:
            self.logger.error("Restart cooldown active, not restarting")
            return

        if self.restart_count >= self.config['max_restarts']:
            self.logger.critical(f"Max restarts ({self.config['max_restarts']}) reached, giving up")
            return

        self.restart_count += 1
        self.last_restart = now

        self.logger.warning(f"Restarting SHARD (attempt {self.restart_count}/{self.config['max_restarts']})")
        time.sleep(5)
        self._start_shard()

    def stop(self):
        self.logger.info("Stopping production pipeline...")
        self._running = False

        if self.shard:
            try:
                self.shard.stop()
            except Exception as e:
                self.logger.error(f"Error stopping SHARD: {e}")

        self.monitor.stop()

        self._print_final_stats()

    def _print_final_stats(self):
        metrics = self.monitor.get_metrics()
        fp_stats = self.fp_controller.get_stats()

        self.logger.info("=" * 60)
        self.logger.info("FINAL STATISTICS")
        self.logger.info("=" * 60)
        self.logger.info(f"Uptime: {metrics['uptime_seconds']:.0f}s")
        self.logger.info(f"Packets: {metrics['packets_processed']}")
        self.logger.info(f"Alerts: {metrics['alerts_generated']}")
        self.logger.info(f"Blocked (FP): {metrics['alerts_blocked']}")
        self.logger.info(f"Errors: {metrics['errors']}")
        self.logger.info(f"FP Suppressed: {fp_stats['total_fp_suppressed']}")
        self.logger.info("=" * 60)

    def get_status(self) -> dict:
        return {
            'running': self._running,
            'restart_count': self.restart_count,
            'metrics': self.monitor.get_metrics(),
            'fp_control': self.fp_controller.get_stats(),
        }


def main():
    pipeline = ProductionPipeline()

    def signal_handler(sig, frame):
        pipeline.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    pipeline.start()


if __name__ == "__main__":
    main()