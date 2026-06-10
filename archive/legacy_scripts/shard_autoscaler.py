
#!/usr/bin/env python3
"""SHARD Auto-Scaling & Load Balancer"""
import time
import threading
import logging
import psutil
import json
from typing import Dict, List
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger("SHARD.Scaler")

@dataclass
class ScalingMetrics:
    """Metrics for auto-scaling decisions"""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    event_queue_size: int = 0
    processing_latency_ms: float = 0.0
    active_alerts: int = 0
    network_throughput_mbps: float = 0.0
    timestamp: float = field(default_factory=time.time)


class AutoScaler:
    """Automatic horizontal scaling based on load"""
    
    def __init__(self, 
                 min_workers: int = 2,
                 max_workers: int = 16,
                 scale_up_threshold: float = 0.7,
                 scale_down_threshold: float = 0.3,
                 cooldown_seconds: int = 60):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_up_threshold = scale_up_threshold
        self.scale_down_threshold = scale_down_threshold
        self.cooldown_seconds = cooldown_seconds
        
        self.current_workers = min_workers
        self.last_scale_time = 0
        self.metrics_history: deque = deque(maxlen=100)
        self._running = False
        self._lock = threading.RLock()
        
        # Kubernetes API client (optional)
        self.k8s_client = None
        try:
            from kubernetes import client, config
            config.load_incluster_config()
            self.k8s_client = client.AppsV1Api()
            logger.info("✅ Kubernetes auto-scaler initialized")
        except ImportError:
            logger.info("ℹ️ Kubernetes not available, using process scaling")
        except Exception:
            logger.info("ℹ️ Not in Kubernetes cluster")
    
    def start(self):
        """Start auto-scaling loop"""
        self._running = True
        threading.Thread(target=self._scaling_loop, daemon=True, 
                        name="AutoScaler").start()
        logger.info(f"🚀 Auto-scaler started ({self.min_workers}-{self.max_workers} workers)")
    
    def _scaling_loop(self):
        """Monitor load and scale"""
        while self._running:
            time.sleep(10)
            
            metrics = self._collect_metrics()
            self.metrics_history.append(metrics)
            
            if time.time() - self.last_scale_time < self.cooldown_seconds:
                continue
            
            load_score = self._calculate_load_score(metrics)
            
            if load_score > self.scale_up_threshold:
                self._scale_up()
            elif load_score < self.scale_down_threshold:
                self._scale_down()
    
    def _collect_metrics(self) -> ScalingMetrics:
        """Collect system metrics"""
        return ScalingMetrics(
            cpu_percent=psutil.cpu_percent(interval=1),
            memory_percent=psutil.virtual_memory().percent,
            event_queue_size=self._get_queue_size(),
            processing_latency_ms=self._get_avg_latency(),
            active_alerts=self._get_active_alerts(),
        )
    
    def _calculate_load_score(self, metrics: ScalingMetrics) -> float:
        """Calculate weighted load score"""
        if not self.metrics_history:
            return 0.0
        
        # Weighted average of recent metrics
        recent = list(self.metrics_history)[-5:]
        
        cpu_avg = sum(m.cpu_percent for m in recent) / len(recent) / 100
        mem_avg = sum(m.memory_percent for m in recent) / len(recent) / 100
        queue_avg = min(1.0, sum(m.event_queue_size for m in recent) / len(recent) / 1000)
        latency_avg = min(1.0, sum(m.processing_latency_ms for m in recent) / len(recent) / 100)
        
        # Weights: CPU 30%, Memory 20%, Queue 35%, Latency 15%
        return cpu_avg * 0.3 + mem_avg * 0.2 + queue_avg * 0.35 + latency_avg * 0.15
    
    def _scale_up(self):
        """Add worker"""
        if self.current_workers >= self.max_workers:
            return
        
        self.current_workers += 1
        self.last_scale_time = time.time()
        
        if self.k8s_client:
            self._k8s_scale(self.current_workers)
        else:
            self._process_scale(self.current_workers)
        
        logger.warning(f"📈 Scaled UP to {self.current_workers} workers")
    
    def _scale_down(self):
        """Remove worker"""
        if self.current_workers <= self.min_workers:
            return
        
        self.current_workers -= 1
        self.last_scale_time = time.time()
        
        if self.k8s_client:
            self._k8s_scale(self.current_workers)
        
        logger.info(f"📉 Scaled DOWN to {self.current_workers} workers")
    
    def _k8s_scale(self, replicas: int):
        """Scale Kubernetes deployment"""
        try:
            self.k8s_client.patch_namespaced_deployment_scale(
                name='shard-worker',
                namespace='shard',
                body={'spec': {'replicas': replicas}}
            )
        except Exception as e:
            logger.error(f"K8s scale failed: {e}")
    
    def _process_scale(self, workers: int):
        """Scale within single process (threads)"""
        # Adjust ThreadPoolExecutor size
        pass
    
    def _get_queue_size(self) -> int:
        """Get current event queue size"""
        return 0  # Placeholder — integrate with EventBus
    
    def _get_avg_latency(self) -> float:
        """Get average processing latency"""
        return 0.0  # Placeholder
    
    def _get_active_alerts(self) -> int:
        """Get number of active alerts"""
        return 0  # Placeholder
    
    def stop(self):
        """Stop auto-scaler"""
        self._running = False


class LoadBalancer:
    """Distribute load across SHARD workers"""
    
    def __init__(self, workers: List[str] = None):
        self.workers = workers or ['localhost:8000']
        self.current_index = 0
        self._lock = threading.RLock()
        self.worker_health: Dict[str, bool] = {}
    
    def get_worker(self) -> str:
        """Get next healthy worker (round-robin)"""
        with self._lock:
            for _ in range(len(self.workers)):
                self.current_index = (self.current_index + 1) % len(self.workers)
                worker = self.workers[self.current_index]
                
                if self.worker_health.get(worker, True):
                    return worker
            
            return self.workers[0]  # Fallback
    
    def mark_unhealthy(self, worker: str):
        """Mark worker as unhealthy"""
        with self._lock:
            self.worker_health[worker] = False
            logger.warning(f"🏥 Worker {worker} marked unhealthy")
    
    def mark_healthy(self, worker: str):
        """Mark worker as healthy"""
        with self._lock:
            self.worker_health[worker] = True
    
    def health_check(self):
        """Check health of all workers"""
        import requests
        
        for worker in self.workers:
            try:
                response = requests.get(
                    f"http://{worker}/api/health", 
                    timeout=5
                )
                if response.status_code == 200:
                    self.mark_healthy(worker)
                else:
                    self.mark_unhealthy(worker)
            except Exception:
                self.mark_unhealthy(worker)
