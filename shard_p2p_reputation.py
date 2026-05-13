import os
#!/usr/bin/env python3
"""
🌐 SHARD P2P REPUTATION - Децентрализованный обмен данными о репутации
Использует IPFS для анонимного обмена threat intelligence
"""

import json
import hashlib
import time
import threading
import logging
import requests
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import queue
import random

logger = logging.getLogger("SHARD-P2P")


class IPFSClient:
    """
    Простой клиент для IPFS
    """

    def __init__(self, api_url: str = "http://localhost:5001"):
        self.api_url = api_url
        self.connected = self._check_connection()

    def _check_connection(self) -> bool:
        """Проверка соединения с IPFS"""
        try:
            response = requests.post(f"{self.api_url}/api/v0/version", timeout=5)
            return response.status_code == 200
        except:
            logger.warning("⚠️ IPFS недоступен, работаем в офлайн-режиме")
            return False

    def add(self, data: Dict) -> Optional[str]:
        """Добавление данных в IPFS"""
        if not self.connected:
            content = json.dumps(data, sort_keys=True)
            return hashlib.sha256(content.encode()).hexdigest()[:16]

        try:
            files = {'file': json.dumps(data)}
            response = requests.post(f"{self.api_url}/api/v0/add", files=files, timeout=10)
            if response.status_code == 200:
                result = response.json()
                return result.get('Hash')
        except Exception as e:
            logger.error(f"Ошибка IPFS add: {e}")

        return None

    def get(self, hash_value: str) -> Optional[Dict]:
        """Получение данных из IPFS"""
        if not self.connected:
            return None

        try:
            response = requests.post(f"{self.api_url}/api/v0/cat", params={'arg': hash_value}, timeout=10)
            if response.status_code == 200:
                return response.json()
        except:
            pass

        return None

    def publish(self, topic: str, data: Dict) -> bool:
        """Публикация в pubsub"""
        if not self.connected:
            return False

        try:
            payload = json.dumps(data)
            response = requests.post(
                f"{self.api_url}/api/v0/pubsub/pub",
                params={'arg': topic, 'arg': payload},
                timeout=5
            )
            return response.status_code == 200
        except:
            return False

    def subscribe(self, topic: str, callback) -> bool:
        """Подписка на pubsub (упрощённо - через polling)"""
        if not self.connected:
            return False

        def poller():
            last_id = ""
            while True:
                try:
                    response = requests.post(
                        f"{self.api_url}/api/v0/pubsub/sub",
                        params={'arg': topic, 'timeout': '30s'},
                        timeout=35
                    )
                    if response.status_code == 200:
                        for line in response.iter_lines():
                            if line:
                                try:
                                    data = json.loads(line.decode())
                                    if data.get('from') != last_id:
                                        callback(data.get('data', {}))
                                        last_id = data.get('from')
                                except:
                                    pass
                except:
                    pass
                time.sleep(5)

        thread = threading.Thread(target=poller, daemon=True)
        thread.start()
        return True


class ReputationManager:
    """
    Менеджер репутации IP/доменов
    """

    def __init__(self):
        self.reputation: Dict[str, Dict] = {}

        self.publish_queue = queue.Queue()

        self.peers: Set[str] = set()

        self.stats = {
            'published': 0,
            'received': 0,
            'local_threats': 0,
            'external_threats': 0
        }

        self._load_local_db()

    def _load_local_db(self):
        """Загрузка локальной базы репутации"""
        db_path = "data/reputation.json"
        if os.path.exists(db_path):
            try:
                with open(db_path, 'r') as f:
                    self.reputation = json.load(f)
            except:
                pass

    def _save_local_db(self):
        """Сохранение локальной базы"""
        os.makedirs("data", exist_ok=True)
        with open("data/reputation.json", 'w') as f:
            json.dump(self.reputation, f, indent=2)

    def add_threat(self, indicator: str, indicator_type: str, threat_type: str,
                   confidence: float, source: str = "local", evidence: Dict = None) -> Dict:
        """
        Добавление угрозы в базу репутации

        Returns:
            Запись о репутации
        """
        now = datetime.now().isoformat()

        if indicator not in self.reputation:
            self.reputation[indicator] = {
                'indicator': indicator,
                'type': indicator_type,
                'first_seen': now,
                'last_seen': now,
                'threats': [],
                'score': 0.0,
                'confidence': 0.0,
                'reports': 0,
                'sources': set()
            }

        record = self.reputation[indicator]
        record['last_seen'] = now
        record['threats'].append({
            'type': threat_type,
            'confidence': confidence,
            'timestamp': now,
            'source': source,
            'evidence': evidence or {}
        })
        record['reports'] = len(record['threats'])
        record['sources'].append(source)

        record['score'] = self._calculate_score(record)
        record['confidence'] = min(1.0, record['confidence'] + confidence * 0.1)

        self._save_local_db()

        if source == "local":
            self.stats['local_threats'] += 1
        else:
            self.stats['external_threats'] += 1

        if record['score'] > 0.7:
            self.publish_queue.put({
                'indicator': indicator,
                'type': indicator_type,
                'threat_type': threat_type,
                'score': record['score'],
                'confidence': confidence,
                'timestamp': now
            })

        return record

    def _calculate_score(self, record: Dict) -> float:
        """Расчёт скора репутации"""
        base_score = min(1.0, record['reports'] * 0.2)

        source_bonus = min(0.3, len(record['sources']) * 0.1)

        last_seen = datetime.fromisoformat(record['last_seen'])
        freshness = max(0, 1.0 - (datetime.now() - last_seen).days / 30)

        return min(1.0, (base_score + source_bonus) * freshness)

    def get_reputation(self, indicator: str) -> Optional[Dict]:
        """Получение репутации индикатора"""
        if indicator in self.reputation:
            record = self.reputation[indicator].copy()
            record['sources'] = list(record['sources'])
            return record
        return None

    def is_malicious(self, indicator: str, threshold: float = 0.6) -> Tuple[bool, float]:
        """Проверка, является ли индикатор вредоносным"""
        record = self.reputation.get(indicator)
        if record:
            return record['score'] >= threshold, record['score']
        return False, 0.0

    def merge_external(self, data: Dict):
        """Объединение с внешними данными"""
        indicator = data.get('indicator')
        if not indicator:
            return

        self.add_threat(
            indicator=indicator,
            indicator_type=data.get('type', 'unknown'),
            threat_type=data.get('threat_type', 'unknown'),
            confidence=data.get('confidence', 0.5),
            source=f"p2p_{data.get('source', 'unknown')}",
            evidence=data.get('evidence')
        )

        self.stats['received'] += 1

    def get_top_threats(self, limit: int = 100) -> List[Dict]:
        """Получение топ угроз для обмена"""
        threats = []
        for indicator, record in self.reputation.items():
            if record['score'] > 0.5 and record['reports'] >= 2:
                threats.append({
                    'indicator': indicator,
                    'type': record['type'],
                    'score': record['score'],
                    'reports': record['reports'],
                    'last_seen': record['last_seen']
                })

        threats.sort(key=lambda x: x['score'], reverse=True)
        return threats[:limit]

    def get_stats(self) -> Dict:
        """Статистика"""
        return {
            **self.stats,
            'total_indicators': len(self.reputation),
            'high_risk': sum(1 for r in self.reputation.values() if r['score'] > 0.7),
            'medium_risk': sum(1 for r in self.reputation.values() if 0.3 < r['score'] <= 0.7),
            'low_risk': sum(1 for r in self.reputation.values() if r['score'] <= 0.3)
        }


class SHARDP2PNetwork:
    """
    Децентрализованная P2P сеть для обмена репутацией
    """

    def __init__(self, node_id: str = None):
        self.node_id = node_id or hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        self.ipfs = IPFSClient()
        self.reputation = ReputationManager()

        self.THREAT_TOPIC = "shard-threat-intel-v1"
        self.PEER_DISCOVERY = "shard-peer-discovery-v1"

        self.bootstrap_peers = [
            "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        ]

        self.running = True
        self.announce_thread = None

        self._setup_subscriptions()

        self._start_announce()

        self._start_publisher()

        logger.info(f"🌐 SHARD P2P Network запущена (node: {self.node_id})")

    def _setup_subscriptions(self):
        """Настройка подписок"""

        def on_threat(data):
            try:
                if isinstance(data, str):
                    data = json.loads(data)
                self.reputation.merge_external(data)
                logger.debug(f"📥 Получена угроза из P2P: {data.get('indicator')}")
            except Exception as e:
                logger.error(f"Ошибка обработки P2P данных: {e}")

        def on_peer(data):
            try:
                if isinstance(data, str):
                    data = json.loads(data)
                peer_id = data.get('peer_id')
                if peer_id and peer_id != self.node_id:
                    self.reputation.peers.add(peer_id)
            except:
                pass

        self.ipfs.subscribe(self.THREAT_TOPIC, on_threat)
        self.ipfs.subscribe(self.PEER_DISCOVERY, on_peer)

    def _start_announce(self):
        """Периодическое анонсирование"""

        def announcer():
            while self.running:
                self.ipfs.publish(self.PEER_DISCOVERY, {
                    'peer_id': self.node_id,
                    'timestamp': datetime.now().isoformat(),
                    'threats_count': len(self.reputation.reputation)
                })
                time.sleep(300)

        self.announce_thread = threading.Thread(target=announcer, daemon=True)
        self.announce_thread.start()

    def _start_publisher(self):
        """Публикация угроз из очереди"""

        def publisher():
            while self.running:
                try:
                    threat = self.reputation.publish_queue.get(timeout=10)

                    threat['source'] = self.node_id
                    threat['version'] = 1

                    success = self.ipfs.publish(self.THREAT_TOPIC, threat)
                    if success:
                        self.reputation.stats['published'] += 1
                        logger.info(f"📤 Опубликована угроза: {threat['indicator']}")

                except queue.Empty:
                    pass
                except Exception as e:
                    logger.error(f"Ошибка публикации: {e}")

        thread = threading.Thread(target=publisher, daemon=True)
        thread.start()

    def share_threat(self, indicator: str, indicator_type: str, threat_type: str,
                     confidence: float, evidence: Dict = None) -> Dict:
        """
        Поделиться угрозой с сетью
        """
        record = self.reputation.add_threat(
            indicator=indicator,
            indicator_type=indicator_type,
            threat_type=threat_type,
            confidence=confidence,
            source="local",
            evidence=evidence
        )

        return record

    def check_reputation(self, indicator: str) -> Dict:
        """
        Проверка репутации индикатора
        """
        is_malicious, score = self.reputation.is_malicious(indicator)
        record = self.reputation.get_reputation(indicator)

        return {
            'indicator': indicator,
            'malicious': is_malicious,
            'score': score,
            'details': record
        }

    def get_network_stats(self) -> Dict:
        """Статистика сети"""
        return {
            'node_id': self.node_id,
            'peers': len(self.reputation.peers),
            'reputation': self.reputation.get_stats(),
            'ipfs_connected': self.ipfs.connected
        }

    def export_for_sharing(self) -> List[Dict]:
        """Экспорт угроз для обмена"""
        return self.reputation.get_top_threats(100)

    def stop(self):
        """Остановка"""
        self.running = False
        logger.info("🛑 P2P Network остановлена")



class SHARDP2PIntegration:
    """
    Интеграция P2P репутации с SHARD
    """

    def __init__(self):
        self.p2p = SHARDP2PNetwork()
        self.enabled = True

        logger.info("🌐 SHARD P2P Integration готов!")

    def check_ip(self, ip: str) -> Dict:
        """Проверка IP через P2P сеть"""
        return self.p2p.check_reputation(ip)

    def report_threat(self, alert: Dict):
        """Отправка угрозы в P2P сеть"""
        src_ip = alert.get('src_ip')
        if not src_ip or src_ip in ['127.0.0.1', '::1', 'localhost']:
            return

        threat_type = alert.get('attack_type', alert.get('type', 'unknown'))
        confidence = alert.get('confidence', 0.5)

        self.p2p.share_threat(
            indicator=src_ip,
            indicator_type='ip',
            threat_type=threat_type,
            confidence=confidence,
            evidence={'alert': alert}
        )

    def get_stats(self) -> Dict:
        """Статистика"""
        return self.p2p.get_network_stats()

    def stop(self):
        """Остановка"""
        self.p2p.stop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    import os

    p2p = SHARDP2PIntegration()

    result = p2p.check_ip("185.142.53.101")
    print(f"🔍 Проверка IP: {result}")

    p2p.report_threat({
        'src_ip': '185.142.53.101',
        'attack_type': 'brute_force',
        'confidence': 0.95
    })

    print(f"\n📊 Статистика: {p2p.get_stats()}")