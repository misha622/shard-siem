#!/usr/bin/env python3
"""
SHARD Zero-Day Detection System
Обнаружение неизвестных атак через анализ аномальных паттернов.
"""

import numpy as np
import time
import hashlib
import threading
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("SHARD-ZeroDay")

try:
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class ZeroDaySeverity(Enum):
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ZeroDaySignature:
    """Сигнатура новой атаки"""
    id: str
    name: str
    description: str
    severity: ZeroDaySeverity
    confidence: float
    patterns: Dict[str, Any]
    first_seen: float
    last_seen: float
    affected_systems: List[str]
    mitre_tactics: List[str]
    iocs: List[Dict]
    detection_count: int = 1
    recommended_defense: Optional[str] = None
    status: str = "active"  # active, mitigated, false_positive


class AnomalyCluster:
    """Кластер аномалий — потенциальная zero-day атака"""

    def __init__(self, cluster_id: int):
        self.id = cluster_id
        self.samples: List[Dict] = []
        self.features: List[np.ndarray] = []
        self.centroid: Optional[np.ndarray] = None
        self.radius: float = 0.0
        self.first_seen: float = time.time()
        self.last_seen: float = time.time()
        self.count: int = 0
        self.novelty_score: float = 0.0
        self.label: Optional[str] = None

    def add_sample(self, features: np.ndarray, metadata: Dict):
        self.samples.append(metadata)
        self.features.append(features)
        self.last_seen = time.time()
        self.count += 1

        # Обновление центроида
        if len(self.features) > 0:
            self.centroid = np.mean(self.features, axis=0)
            if len(self.features) > 1:
                self.radius = max(
                    np.linalg.norm(f - self.centroid) for f in self.features
                )


class ZeroDayDetector:
    """
    Обнаружение zero-day атак через:
    1. Кластеризацию аномалий (DBSCAN)
    2. Поиск неизвестных паттернов
    3. Оценку новизны и опасности
    """

    def __init__(self):
        self.clusters: Dict[int, AnomalyCluster] = {}
        self.signatures: Dict[str, ZeroDaySignature] = {}
        self.baseline: Optional[np.ndarray] = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None

        # Буферы
        self.anomaly_buffer: deque = deque(maxlen=10000)
        self.normal_buffer: deque = deque(maxlen=50000)

        # Статистика
        self.stats = {
            'total_anomalies': 0,
            'clusters_formed': 0,
            'zero_days_found': 0,
            'false_positives': 0,
            'active_clusters': 0
        }

        self._lock = threading.RLock()
        self._running = False

        # Известные атаки (для сравнения)
        self.known_attacks = {
            'brute_force', 'port_scan', 'dos', 'ddos', 'sql_injection',
            'xss', 'c2_beacon', 'dns_tunnel', 'data_exfiltration',
            'lateral_movement', 'phishing', 'malware', 'ransomware'
        }

    def extract_features(self, alert: Dict) -> np.ndarray:
        """Извлечение признаков для кластеризации"""
        features = []

        # Базовые признаки (первые 20)
        features.extend([
            alert.get('score', 0),
            alert.get('confidence', 0),
            1.0 if alert.get('is_internal', False) else 0.0,
            alert.get('dst_port', 0) / 65535.0,
            alert.get('src_port', 0) / 65535.0,
            len(str(alert.get('attack_type', ''))) / 50,
            alert.get('hour_of_day', datetime.now().hour) / 24.0,
            alert.get('day_of_week', datetime.now().weekday()) / 7.0,
        ])

        # Хеш признаков для уникальности паттерна
        pattern_hash = int(
            hashlib.md5(
                str(alert.get('attack_type', '')).encode()
            ).hexdigest()[:8], 16
        ) / 4294967295.0  # 2^32 - 1

        features.append(pattern_hash)

        # Поведенческие признаки
        features.extend([
            alert.get('connection_count', 0) / 100,
            alert.get('bytes_transferred', 0) / 1_000_000,
            alert.get('unique_ports', 0) / 100,
            alert.get('packet_size_avg', 0) / 1500,
            alert.get('packet_size_std', 0) / 500,
            alert.get('entropy', 0) / 8.0,
            alert.get('protocol', 0) / 255,
            alert.get('tcp_flags', 0) / 255,
            alert.get('duration', 0) / 3600,
            alert.get('packets_per_second', 0) / 1000,
        ])

        return np.array(features, dtype=np.float32)

    def add_alert(self, alert: Dict) -> Optional[Dict]:
        """
        Обработка алерта — поиск zero-day паттернов.
        """
        with self._lock:
            self.stats['total_anomalies'] += 1

            # Извлекаем признаки
            features = self.extract_features(alert)
            self.anomaly_buffer.append(features)

            # Проверяем, является ли атака известной
            attack_type = str(alert.get('attack_type', '')).lower()
            is_known = any(
                known in attack_type
                for known in self.known_attacks
            )

            if is_known:
                return None  # Известная атака — не zero-day

            # Кластеризация
            if len(self.anomaly_buffer) >= 50 and SKLEARN_AVAILABLE:
                result = self._cluster_anomalies(features, alert)
                if result:
                    return result

            return None

    def _cluster_anomalies(self, new_features: np.ndarray, alert: Dict) -> Optional[Dict]:
        """Кластеризация аномалий для поиска новых паттернов"""
        if not SKLEARN_AVAILABLE:
            return None

        try:
            # Подготавливаем данные
            recent = np.array(list(self.anomaly_buffer)[-200:])

            if len(recent) < 10:
                return None

            # Масштабирование
            if self.scaler:
                recent_scaled = self.scaler.fit_transform(recent)
                new_scaled = self.scaler.transform([new_features])[0]
            else:
                recent_scaled = recent
                new_scaled = new_features

            # DBSCAN кластеризация
            clustering = DBSCAN(eps=0.5, min_samples=3)
            labels = clustering.fit_predict(recent_scaled)

            # Анализ кластеров
            unique_labels = set(labels)
            new_label = labels[-1] if len(labels) > 0 else -1

            if new_label >= 0:
                # Новый сэмпл попал в существующий кластер
                if new_label not in self.clusters:
                    self.clusters[new_label] = AnomalyCluster(new_label)
                    self.stats['clusters_formed'] += 1

                cluster = self.clusters[new_label]
                cluster.add_sample(new_scaled, alert)

                # Если кластер вырос — возможно zero-day
                if cluster.count >= 10 and not cluster.label:
                    zero_day = self._create_zero_day_signature(cluster, alert)
                    return zero_day

            elif new_label == -1:
                # Новый сэмпл не попал ни в один кластер — noise
                # Проверяем не является ли это началом нового кластера
                if self._is_potential_new_cluster(new_features):
                    # Создаём новый кластер
                    new_id = max(self.clusters.keys(), default=-1) + 1
                    self.clusters[new_id] = AnomalyCluster(new_id)
                    self.clusters[new_id].add_sample(new_scaled, alert)
                    self.stats['clusters_formed'] += 1

        except Exception as e:
            logger.debug(f"Clustering error: {e}")

        return None

    def _is_potential_new_cluster(self, features: np.ndarray) -> bool:
        """Проверка на потенциально новый кластер"""
        # Высокая уверенность + необычный паттерн
        if len(self.anomaly_buffer) < 20:
            return False

        recent = np.array(list(self.anomaly_buffer)[-20:])
        distances = np.linalg.norm(recent - features, axis=1)

        # Если точка далеко от всех остальных — новый кластер
        if np.min(distances) > np.percentile(distances, 80):
            return True

        return False

    def _create_zero_day_signature(
        self, cluster: AnomalyCluster, alert: Dict
    ) -> Dict:
        """Создание сигнатуры zero-day атаки"""
        self.stats['zero_days_found'] += 1

        # Генерация имени
        attack_name = f"Unknown_Attack_{int(time.time()) % 100000:05d}"
        severity = self._assess_severity(cluster, alert)
        confidence = self._calculate_confidence(cluster)

        sig = ZeroDaySignature(
            id=f"ZD-{int(time.time())}-{hash(cluster.id)}",
            name=attack_name,
            description=f"Обнаружен новый тип атаки. "
                       f"Кластер: {cluster.id}, "
                       f"Образцов: {cluster.count}, "
                       f"Уверенность: {confidence:.0%}",
            severity=severity,
            confidence=confidence,
            patterns={
                'cluster_id': cluster.id,
                'centroid': cluster.centroid.tolist() if cluster.centroid is not None else None,
                'radius': cluster.radius,
                'sample_count': cluster.count,
                'first_seen': cluster.first_seen,
                'novelty_score': cluster.novelty_score
            },
            first_seen=cluster.first_seen,
            last_seen=cluster.last_seen,
            affected_systems=self._extract_affected_systems(cluster),
            mitre_tactics=self._map_to_mitre(alert),
            iocs=self._extract_iocs(cluster, alert),
            recommended_defense=self._generate_defense_recommendation(cluster, alert)
        )

        self.signatures[sig.id] = sig
        cluster.label = attack_name

        logger.warning(f"""
╔══════════════════════════════════════════════════════════╗
║ 🚨 ZERO-DAY ОБНАРУЖЕН!                                  ║
╠══════════════════════════════════════════════════════════╣
║ ID:        {sig.id}
║ Имя:       {attack_name}
║ Серьёзность: {severity.name}
║ Уверенность: {confidence:.0%}
║ Образцов:  {cluster.count}
║ Систем:    {len(sig.affected_systems)}
╚══════════════════════════════════════════════════════════╝
""")

        return {
            'is_zero_day': True,
            'signature': sig.__dict__,
            'cluster_id': cluster.id,
            'recommended_action': 'IMMEDIATE_INVESTIGATION',
            'defense_code': sig.recommended_defense
        }

    def _assess_severity(
        self, cluster: AnomalyCluster, alert: Dict
    ) -> ZeroDaySeverity:
        """Оценка серьёзности zero-day"""
        score = 0

        # Большой кластер = опаснее
        if cluster.count > 50:
            score += 2
        elif cluster.count > 20:
            score += 1

        # Высокая уверенность алерта
        if alert.get('confidence', 0) > 0.8:
            score += 1

        # Атака на критическую инфраструктуру
        dst_port = alert.get('dst_port', 0)
        if dst_port in [22, 3389, 445, 3306, 5432, 6379, 27017]:
            score += 1

        # Много затронутых систем
        if len(cluster.samples) > 10:
            score += 1

        if score >= 4:
            return ZeroDaySeverity.CRITICAL
        elif score >= 3:
            return ZeroDaySeverity.HIGH
        elif score >= 2:
            return ZeroDaySeverity.MEDIUM
        return ZeroDaySeverity.LOW

    def _calculate_confidence(self, cluster: AnomalyCluster) -> float:
        """Расчёт уверенности в zero-day"""
        confidence = 0.5

        # Больше образцов = выше уверенность
        confidence += min(0.3, cluster.count / 100)

        # Плотный кластер = выше уверенность
        if cluster.radius > 0:
            confidence += min(0.2, 1.0 / (cluster.radius + 0.1))

        return min(0.99, confidence)

    def _extract_affected_systems(self, cluster: AnomalyCluster) -> List[str]:
        """Извлечение затронутых систем"""
        systems = set()
        for sample in cluster.samples[-20:]:
            if 'dst_ip' in sample:
                systems.add(sample['dst_ip'])
            if 'src_ip' in sample:
                systems.add(sample['src_ip'])
        return list(systems)[:10]

    def _map_to_mitre(self, alert: Dict) -> List[str]:
        """Маппинг на MITRE ATT&CK"""
        # Для неизвестных атак — используем общие тактики
        return [
            'TA0043 - Reconnaissance',
            'TA0001 - Initial Access',
            'TA0002 - Execution'
        ]

    def _extract_iocs(self, cluster: AnomalyCluster, alert: Dict) -> List[Dict]:
        """Извлечение IOCs"""
        iocs = []

        # IP адреса
        ips = set()
        for sample in cluster.samples[-20:]:
            for key in ['src_ip', 'dst_ip']:
                ip = sample.get(key, '')
                if ip and not ip.startswith(('192.168.', '10.', '172.', '127.')):
                    ips.add(ip)

        for ip in list(ips)[:5]:
            iocs.append({'type': 'ip', 'value': ip})

        # Порты
        ports = set()
        for sample in cluster.samples[-20:]:
            port = sample.get('dst_port', 0)
            if port:
                ports.add(port)

        for port in list(ports)[:3]:
            iocs.append({'type': 'port', 'value': port})

        return iocs

    def _generate_defense_recommendation(
        self, cluster: AnomalyCluster, alert: Dict
    ) -> str:
        """Генерация рекомендаций по защите от zero-day"""
        ports = set()
        ips = set()

        for sample in cluster.samples[-20:]:
            if 'dst_port' in sample:
                ports.add(sample['dst_port'])
            if 'src_ip' in sample:
                ips.add(sample['src_ip'])

        recommendations = [
            "# SHARD AI - Zero-Day Defense Recommendation",
            f"# Attack: {cluster.label or 'Unknown'}",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "# Immediate Actions:",
        ]

        for ip in list(ips)[:5]:
            recommendations.append(f"iptables -A INPUT -s {ip} -j DROP")

        for port in list(ports)[:3]:
            recommendations.append(f"iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP")

        recommendations.extend([
            "",
            "# Monitor for similar patterns:",
            "tcpdump -i any -w /tmp/shard_zeroday_$(date +%s).pcap host " + " or host ".join(list(ips)[:3])
        ])

        return '\n'.join(recommendations)

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                **self.stats,
                'active_signatures': len(self.signatures),
                'buffer_size': len(self.anomaly_buffer)
            }

    def export_signatures(self) -> List[Dict]:
        """Экспорт сигнатур для обмена"""
        return [
            {
                'id': sig.id,
                'name': sig.name,
                'severity': sig.severity.name,
                'confidence': sig.confidence,
                'detection_count': sig.detection_count,
                'iocs': sig.iocs,
                'patterns': sig.patterns
            }
            for sig in self.signatures.values()
            if sig.status == 'active'
        ]


# Тест
if __name__ == "__main__":
    print("🧪 Тест Zero-Day Detector")
    detector = ZeroDayDetector()

    # Симулируем неизвестную атаку
    for i in range(30):
        alert = {
            'attack_type': 'Unknown_Pattern',
            'score': 0.85 + np.random.random() * 0.1,
            'confidence': 0.8 + np.random.random() * 0.15,
            'src_ip': f'203.0.113.{np.random.randint(1,255)}',
            'dst_ip': f'192.168.1.{np.random.randint(1,50)}',
            'dst_port': np.random.choice([4444, 5555, 6666, 7777]),
            'src_port': np.random.randint(30000, 60000),
            'is_internal': False,
            'connection_count': np.random.randint(50, 200),
            'bytes_transferred': np.random.randint(100000, 500000),
            'entropy': np.random.random() * 8,
            'protocol': 6,
            'tcp_flags': np.random.randint(0, 64),
            'duration': np.random.randint(10, 300),
            'packets_per_second': np.random.randint(100, 1000),
            'unique_ports': np.random.randint(5, 20),
            'packet_size_avg': np.random.randint(200, 800),
            'packet_size_std': np.random.randint(50, 200),
        }
        result = detector.add_alert(alert)
        if result:
            print(f"✅ Zero-Day обнаружен: {result['signature']['name']}")

    print(f"\nСтатистика: {detector.get_stats()}")