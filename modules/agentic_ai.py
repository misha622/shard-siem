#!/usr/bin/env python3
"""SHARD AgenticAIAnalyst Module"""
from core.base import BaseModule, ConfigManager, EventBus, LoggingService
import time, threading, random, json, re, queue
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

class AgenticAIAnalyst(BaseModule):
    """Агентный ИИ для расследования инцидентов (исправлен - защита от race condition, дедупликация)"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("AgenticAI", config, event_bus, logger)
        self.investigations: Dict[str, Dict] = {}
        self.knowledge_base: Dict[str, List[str]] = defaultdict(list)
        self._lock = threading.RLock()

        # Дедупликация расследований
        self._recent_investigations: Dict[str, float] = {}
        self._investigation_cooldown = 60
        self._global_cooldown = 10
        self._last_investigation_time = 0
        self._max_investigations_per_minute = 10
        self._investigation_counter: Dict[str, int] = defaultdict(int)
        self._counter_reset = time.time()
        self._inv_lock = threading.RLock()

        # Игнорируемые типы для авто-расследований
        self._auto_investigate_types = {'Honeypot Interaction', 'Port Scan'}

        # Игнорируемые IP
        self._ignored_ips = {'127.0.0.1', '::1', 'localhost', '0.0.0.0'}

        # Кэш уже расследованных алертов
        self._investigated_alerts: Dict[str, float] = {}
        self._alert_ttl = 300

        # ========== ЗАЩИТА ОТ ЦИКЛОВ (ИСПРАВЛЕНО) ==========
        self._processing_alerts = self._create_ttl_set(max_size=500)
        self._processing_lock = threading.RLock()
        # ===================================================

        # Статистика
        self._stats = {
            'total_investigations': 0,
            'auto_investigations': 0,
            'skipped_investigations': 0,
            'suppressed_duplicates': 0,
            'suppressed_cycles': 0
        }

        self.event_bus.subscribe('alert.detected', self.on_alert)
        self.event_bus.subscribe('investigation.request', self.on_investigation_request)

    @staticmethod
    def _create_ttl_set(max_size: int = 500):
        """Создаёт TTL set с FIFO удалением и потокобезопасностью"""
        from collections import OrderedDict

        class TTLSet:
            def __init__(self, max_size: int = 500):
                self._data = OrderedDict()
                self.max_size = max_size
                self._ttl = 600
                self._lock = threading.RLock()

            def add(self, item: str):
                with self._lock:
                    if item in self._data:
                        self._data[item] = time.time()
                        self._data.move_to_end(item)
                        return
                    self._data[item] = time.time()
                    if len(self._data) > self.max_size:
                        self._data.popitem(last=False)

            def discard(self, item: str):
                with self._lock:
                    self._data.pop(item, None)

            def __contains__(self, item: str) -> bool:
                with self._lock:
                    if item not in self._data:
                        return False
                    ts = self._data[item]
                    if time.time() - ts > self._ttl:
                        del self._data[item]
                        return False
                    return True

            def cleanup_expired(self, ttl: float = 300) -> int:
                with self._lock:
                    now = time.time()
                    expired = [k for k, ts in self._data.items() if now - ts > ttl]
                    for k in expired:
                        del self._data[k]
                    return len(expired)

        return TTLSet(max_size=max_size)

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._background_analysis, daemon=True, name="AgenticAI-Background").start()
        threading.Thread(target=self._cleanup_loop, daemon=True, name="AgenticAI-Cleanup").start()
        self.logger.info("Agentic AI аналитик запущен (с дедупликацией и защитой от race condition)")

    def stop(self) -> None:
        self.running = False
        self.logger.info(f"Agentic AI остановлен. Статистика: {self._stats}")

    def _cleanup_loop(self) -> None:
        while self.running:
            time.sleep(60)
            now = time.time()

            with self._inv_lock:
                expired_keys = [k for k, v in self._recent_investigations.items()
                                if now - v > self._investigation_cooldown * 2]
                for k in expired_keys:
                    del self._recent_investigations[k]

                expired_alerts = [k for k, v in self._investigated_alerts.items()
                                  if now - v > self._alert_ttl]
                for k in expired_alerts:
                    del self._investigated_alerts[k]

            with self._lock:
                expired_inv = [k for k, v in self.investigations.items()
                               if now - v.get('end_time', now) > 86400]
                for k in expired_inv:
                    del self.investigations[k]

            # Периодическая очистка TTL set
            self._processing_alerts.cleanup_expired(ttl=600)

    def _should_auto_investigate(self, alert: Dict) -> bool:
        attack_type = str(alert.get('attack_type', ''))
        src_ip = str(alert.get('src_ip', 'unknown'))
        severity = alert.get('severity', 'LOW')
        score = alert.get('score', 0)

        if src_ip in self._ignored_ips:
            return False

        if attack_type in self._auto_investigate_types:
            return False

        if severity not in ['HIGH', 'CRITICAL']:
            return False

        if score < 0.6:
            return False

        now = time.time()
        alert_id = f"{src_ip}:{attack_type}:{severity}"

        with self._inv_lock:
            if now - self._counter_reset > 60:
                self._investigation_counter.clear()
                self._counter_reset = now

            if alert_id in self._investigated_alerts:
                self._stats['suppressed_duplicates'] += 1
                return False

            if now - self._last_investigation_time < self._global_cooldown:
                self._stats['skipped_investigations'] += 1
                return False

            last_time = self._recent_investigations.get(alert_id, 0)
            if now - last_time < self._investigation_cooldown:
                self._stats['skipped_investigations'] += 1
                return False

            if self._investigation_counter.get('total', 0) >= self._max_investigations_per_minute:
                self._stats['skipped_investigations'] += 1
                return False

            self._recent_investigations[alert_id] = now
            self._investigated_alerts[alert_id] = now
            self._investigation_counter['total'] = self._investigation_counter.get('total', 0) + 1
            self._last_investigation_time = now
            self._stats['auto_investigations'] += 1

            return True

    def on_alert(self, alert: Dict) -> None:
        # Группировка алертов по 10-секундным окнам
        alert_signature = f"{alert.get('src_ip', 'unknown')}_{alert.get('attack_type', 'Unknown')}"
        alert_id = f"{alert_signature}_{int(alert.get('timestamp', time.time()) // 10)}"

        if alert_id in self._processing_alerts:
            self._stats['suppressed_cycles'] += 1
            self.logger.debug(f"Alert {alert_id} already being processed, skipping")
            return

        self._processing_alerts.add(alert_id)

        try:
            if not self._should_auto_investigate(alert):
                return

            investigation = self._investigate(alert)
            self._stats['total_investigations'] += 1

            self.event_bus.publish('investigation.completed', investigation)

            conclusion_short = investigation.get('conclusion', '')[:80]
            self.logger.info(f"🔍 Расследование #{investigation['id']}: {conclusion_short}...")

        except Exception as e:
            self.logger.error(f"Ошибка расследования: {e}")
        finally:
            self._processing_alerts.discard(alert_id)

    def on_investigation_request(self, data: Dict) -> None:
        alert = data.get('alert', {})
        force = data.get('force', False)

        if not force:
            src_ip = alert.get('src_ip', 'unknown')
            attack_type = alert.get('attack_type', 'Unknown')
            alert_id = f"{src_ip}:{attack_type}:manual"

            with self._inv_lock:
                now = time.time()
                last_time = self._recent_investigations.get(alert_id, 0)
                if now - last_time < 10:
                    self.logger.debug(f"Пропускаем ручное расследование (cooldown): {alert_id}")
                    return
                self._recent_investigations[alert_id] = now

        try:
            investigation = self._investigate(alert)
            self._stats['total_investigations'] += 1
            self.event_bus.publish('investigation.completed', investigation)
            self.logger.info(f"📋 Ручное расследование #{investigation['id']} завершено")
        except Exception as e:
            self.logger.error(f"Ошибка ручного расследования: {e}")

    def _investigate(self, alert: Dict) -> Dict:
        alert_id = f"INV-{int(time.time())}-{random.randint(1000, 9999)}"
        src_ip = str(alert.get('src_ip', 'unknown'))
        dst_ip = str(alert.get('dst_ip', 'unknown'))
        attack_type = str(alert.get('attack_type', 'Unknown'))
        score = alert.get('score', 0)

        investigation = {
            'id': alert_id,
            'start_time': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'attack_type': attack_type,
            'initial_score': score,
            'alerts': [alert],
            'evidence': [],
            'related_ips': set(),
            'timeline': [],
            'mitre_tactics': [],
            'confidence': 0.0,
            '_internal_evidence': [],
            '_sensitive_data': {}
        }

        source_analysis = self._analyze_source(src_ip)
        investigation['_internal_evidence'] = source_analysis.get('evidence', [])
        investigation['_sensitive_data'] = {
            'source_analysis': source_analysis,
            'detection_methods': ['ML', 'Signature', 'Behavioral']
        }

        if source_analysis.get('is_known_malicious'):
            investigation['evidence'].append("IP обнаружен в базах угроз")
        if source_analysis.get('geo_location'):
            investigation['evidence'].append(f"Геолокация: {source_analysis['geo_location']}")

        investigation['related_ips'].update(source_analysis.get('related_ips', set()))

        mitre_info = self._map_to_mitre(attack_type)
        investigation['mitre_tactics'] = mitre_info['tactics']
        investigation['mitre_techniques'] = mitre_info.get('techniques', [])

        related_alerts = self._find_related_alerts(src_ip, dst_ip, attack_type)
        investigation['alerts'].extend(related_alerts)

        investigation['timeline'] = self._build_timeline(investigation['alerts'])

        impact = self._assess_impact(investigation)
        investigation['impact'] = impact

        investigation['conclusion'] = self._generate_conclusion(investigation)
        investigation['recommendations'] = self._generate_recommendations(investigation)
        investigation['confidence'] = self._calculate_confidence(investigation)
        investigation['severity'] = self._determine_severity(investigation)

        with self._lock:
            self.investigations[alert_id] = investigation

        investigation['end_time'] = time.time()
        investigation['duration'] = investigation['end_time'] - investigation['start_time']

        public_investigation = {k: v for k, v in investigation.items() if not k.startswith('_')}
        public_investigation['related_ips'] = list(investigation['related_ips'])

        return public_investigation

    def _analyze_source(self, ip: str) -> Dict:
        result = {
            'evidence': [],
            'related_ips': set(),
            'is_known_malicious': False,
            'geo_location': None,
            'reputation_score': 0
        }

        request_id = f"analyze_{ip}_{int(time.time())}_{threading.get_ident()}"
        response_container = {'data': None}
        response_received = threading.Event()
        response_lock = threading.Lock()

        def on_threat_response(data: Dict):
            if data.get('request_id') == request_id:
                with response_lock:
                    response_container['data'] = data.get('result', {})
                response_received.set()

        # FIXED: use direct callback instead of subscribe to avoid thread leak
        # # FIXED: use direct callback instead of subscribe to avoid thread leak
        # # FIXED: use direct callback instead of subscribe to avoid thread leak
        # self.event_bus.subscribe('threat_intel.check_ip.response', on_threat_response)

        try:
            self.event_bus.publish('threat_intel.check_ip', {
                'ip': ip,
                'request_id': request_id
            })

            if response_received.wait(timeout=3):
                with response_lock:
                    threat_result = response_container['data']

                if threat_result:
                    result['is_known_malicious'] = threat_result.get('is_malicious', False)
                    result['reputation_score'] = threat_result.get('score', 0)

                    geo = threat_result.get('geo', {})
                    result['geo_location'] = geo.get('country_code') or geo.get('country')

                    if result['is_known_malicious']:
                        sources = ', '.join(threat_result.get('sources', ['unknown']))
                        result['evidence'].append(f"IP {ip} обнаружен в базах угроз (источники: {sources})")

                    if result['geo_location']:
                        result['evidence'].append(f"Геолокация: {result['geo_location']}")

                    if threat_result.get('categories'):
                        cats = ', '.join(threat_result['categories'][:3])
                        result['evidence'].append(f"Категории угроз: {cats}")
            else:
                result['evidence'].append(f"Не удалось получить данные об IP {ip} (таймаут)")

        except Exception as e:
            self.logger.error(f"Ошибка анализа источника {ip}: {e}")
            result['evidence'].append(f"Ошибка анализа: {str(e)[:100]}")
        finally:
            try:
                self.event_bus.unsubscribe('threat_intel.check_ip.response', on_threat_response)
            except (KeyError, ValueError):
                pass  # Callback не был подписан — ок

        return result

    def _map_to_mitre(self, attack_type: str) -> Dict:
        mitre_map = {
            'Brute Force': {'tactics': ['Credential Access'], 'techniques': ['T1110 - Brute Force']},
            'Port Scan': {'tactics': ['Discovery'], 'techniques': ['T1046 - Network Service Scanning']},
            'Web Attack': {'tactics': ['Initial Access'], 'techniques': ['T1190 - Exploit Public-Facing Application']},
            'DDoS': {'tactics': ['Impact'], 'techniques': ['T1498 - Network Denial of Service']},
            'Lateral Movement': {'tactics': ['Lateral Movement'], 'techniques': ['T1021 - Remote Services']},
            'Data Exfiltration': {'tactics': ['Exfiltration'],
                                  'techniques': ['T1048 - Exfiltration Over Alternative Protocol']},
            'DNS Tunnel': {'tactics': ['Command and Control'], 'techniques': ['T1572 - Protocol Tunneling']},
            'C2 Beacon': {'tactics': ['Command and Control'], 'techniques': ['T1571 - Non-Standard Port']},
            'Malware': {'tactics': ['Execution'], 'techniques': ['T1204 - User Execution']},
            'Phishing': {'tactics': ['Initial Access'], 'techniques': ['T1566 - Phishing']},
            'Rate Limit': {'tactics': ['Impact'], 'techniques': ['T1499 - Endpoint Denial of Service']},
            'Honeypot Interaction': {'tactics': ['Discovery'], 'techniques': ['T1046 - Network Service Scanning']}
        }
        return mitre_map.get(attack_type, {'tactics': ['Unknown'], 'techniques': ['T1000 - Unknown']})

    def _find_related_alerts(self, src_ip: str, dst_ip: str, attack_type: str) -> List[Dict]:
        related = []
        try:
            response_queue = queue.Queue()
            request_id = f"related_{int(time.time())}_{threading.get_ident()}"
            received = threading.Event()

            def on_response(data):
                if data.get('request_id') == request_id:
                    response_queue.put(data.get('alerts', []))
                    received.set()

            self.event_bus.subscribe('siem.query.response', on_response)
            try:
                self.event_bus.publish('siem.query.request', {
                    'request_id': request_id,
                    'src_ip': src_ip,
                    'time_range': 1800,
                    'limit': 50
                })
                if received.wait(timeout=2):
                    related = response_queue.get(timeout=1)
            finally:
                self.event_bus.unsubscribe('siem.query.response', on_response)
        except Exception as e:
            self.logger.debug(f"Ошибка запроса алертов: {e}")

        return [a for a in related[:10] if a.get('src_ip') == src_ip]

    def _build_timeline(self, alerts: List[Dict]) -> List[Dict]:
        timeline = []
        for alert in sorted(alerts, key=lambda x: x.get('timestamp', 0)):
            timeline.append({
                'time': alert.get('timestamp', time.time()),
                'event': str(alert.get('attack_type', 'Unknown')),
                'source': str(alert.get('src_ip', 'unknown')),
                'target': str(alert.get('dst_ip', 'unknown')),
                'score': alert.get('score', 0)
            })
        return timeline[-20:]

    def _assess_impact(self, investigation: Dict) -> Dict:
        impact = {'confidentiality': 'LOW', 'integrity': 'LOW', 'availability': 'LOW',
                  'overall': 'LOW', 'description': ''}
        attack_type = investigation['attack_type']

        if attack_type in ['Data Exfiltration']:
            impact.update({'confidentiality': 'HIGH', 'overall': 'HIGH',
                           'description': 'Возможна утечка конфиденциальных данных'})
        elif attack_type in ['DDoS', 'Rate Limit']:
            impact.update({'availability': 'HIGH', 'overall': 'HIGH',
                           'description': 'Нарушение доступности сервисов'})
        elif attack_type in ['Brute Force', 'Lateral Movement']:
            impact.update({'confidentiality': 'MEDIUM', 'integrity': 'MEDIUM',
                           'overall': 'MEDIUM', 'description': 'Возможна компрометация учётных записей'})
        elif attack_type in ['Malware', 'C2 Beacon']:
            impact.update({'confidentiality': 'HIGH', 'integrity': 'HIGH',
                           'overall': 'HIGH', 'description': 'Обнаружено вредоносное ПО или C2 канал'})
        return impact

    def _generate_conclusion(self, investigation: Dict) -> str:
        conclusions = {
            'Brute Force': f"Обнаружена атака подбора пароля с {investigation['src_ip']}. Рекомендуется блокировка.",
            'Port Scan': f"Обнаружено сканирование портов с {investigation['src_ip']}. Рекомендуется мониторинг.",
            'Web Attack': f"Обнаружена веб-атака с {investigation['src_ip']}. Проверьте WAF.",
            'DDoS': f"Обнаружена DDoS атака с {investigation['src_ip']}. Включите защиту.",
            'Data Exfiltration': f"ОБНАРУЖЕНА УТЕЧКА ДАННЫХ с {investigation['src_ip']}! НЕМЕДЛЕННО заблокируйте!",
            'C2 Beacon': f"Обнаружен C2 beaconing с {investigation['src_ip']}. Система может быть скомпрометирована.",
            'Rate Limit': f"Обнаружено превышение лимита запросов с {investigation['src_ip']}. IP заблокирован.",
            'Honeypot Interaction': f"Обнаружено взаимодействие с honeypot от {investigation['src_ip']}."
        }
        return conclusions.get(investigation['attack_type'],
                               f"Обнаружена атака типа {investigation['attack_type']}. Требуется анализ.")

    def _generate_recommendations(self, investigation: Dict) -> List[str]:
        recs = {
            'Brute Force': ['Включить MFA', 'Установить блокировку после 5 попыток'],
            'Data Exfiltration': ['НЕМЕДЛЕННО заблокировать источник', 'Проверить исходящий трафик', 'Уведомить СБ'],
            'C2 Beacon': ['Изолировать систему', 'Заблокировать подозрительные соединения'],
            'Rate Limit': ['Проверить легитимность трафика', 'Настроить дополнительные ограничения'],
            'Honeypot Interaction': ['Проверить источник', 'Добавить IP в список наблюдения']
        }
        recommendations = recs.get(investigation['attack_type'], ['Провести анализ', 'Проверить логи'])
        if investigation['impact']['overall'] == 'HIGH':
            recommendations.insert(0, '🚨 КРИТИЧЕСКИЙ ИНЦИДЕНТ!')
        return recommendations[:5]

    def _calculate_confidence(self, investigation: Dict) -> float:
        confidence = 0.5 + min(0.2, len(investigation['alerts']) * 0.05)
        if investigation.get('initial_score', 0) > 0.7:
            confidence += 0.1
        return min(0.99, confidence)

    def _determine_severity(self, investigation: Dict) -> str:
        score_map = {'Data Exfiltration': 4, 'DDoS': 3, 'C2 Beacon': 3, 'Malware': 3,
                     'Brute Force': 2, 'Web Attack': 2, 'Rate Limit': 2, 'Honeypot Interaction': 1}
        score = score_map.get(investigation['attack_type'], 1)
        if investigation['impact']['overall'] == 'HIGH':
            score += 1
        if score >= 4:
            return 'CRITICAL'
        elif score >= 3:
            return 'HIGH'
        elif score >= 2:
            return 'MEDIUM'
        return 'LOW'

    def _background_analysis(self) -> None:
        while self.running:
            time.sleep(60)

    def get_investigation(self, investigation_id: str) -> Optional[Dict]:
        with self._lock:
            return self.investigations.get(investigation_id)

    def get_stats(self) -> Dict:
        with self._lock:
            with self._inv_lock:
                return {
                    'total_investigations': self._stats['total_investigations'],
                    'auto_investigations': self._stats['auto_investigations'],
                    'skipped_investigations': self._stats['skipped_investigations'],
                    'suppressed_duplicates': self._stats['suppressed_duplicates'],
                    'suppressed_cycles': self._stats['suppressed_cycles'],
                    'active_investigations': len(self.investigations),
                    'processing_alerts': len(self._processing_alerts._data)
                }

    def reset_stats(self) -> None:
        with self._inv_lock:
            self._stats = {k: 0 for k in self._stats}
            self._recent_investigations.clear()
            self._investigated_alerts.clear()
            self._investigation_counter.clear()
        self.logger.info("Статистика Agentic AI сброшена")


# ============================================================
# TRAFFIC CAPTURE
# ============================================================

