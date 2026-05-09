#!/usr/bin/env python3
"""
SHARD Defense Pipeline v2.1 — с ML-классификатором и keyword matching fallback
"""

import pickle
import time
import threading
import logging
import re
from pathlib import Path
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SHARD-Pipeline")


# ============================================================
# ЗАГРУЗЧИК МОДЕЛИ
# ============================================================

class DefenseModelLoader:
    """
    Загрузчик модели защиты.
    Приоритет: ML модель (TfidfVectorizer + XGBoost) → keyword matching (fallback).
    """

    def __init__(self, model_path='./models/defense_classifier_v3.pkl'):
        self.model_path = Path(model_path)
        self.attack_types = [
            'SQL Injection', 'Brute Force', 'DDoS', 'Port Scan', 'C2 Beacon',
            'DNS Tunnel', 'XSS', 'Lateral Movement', 'Data Exfiltration',
            'Botnet', 'Ransomware', 'Phishing', 'Zero-Day'
        ]
        self.loaded = False
        self._ml_loaded = False

        # ML компоненты (загружаются из defense_classifier_v3.pkl)
        self.vectorizer = None      # TfidfVectorizer
        self.classifier = None      # XGBoost
        self.label_encoder = None   # LabelEncoder

        # Keyword matching keywords (расширенный словарь)
        self._keywords = {
            'SQL Injection': ['sql', 'injection', 'sqli', 'union', 'select', 'mysql', 'postgresql', 'blind',
                              'error-based', 'time-based', 'out-of-band', 'second-order'],
            'Brute Force': ['brute', 'force', 'ssh', 'ftp', 'login', 'password', 'hydra', 'dictionary', 'credential',
                            'stuffing', 'rdp', 'telnet'],
            'DDoS': ['ddos', 'syn', 'flood', 'udp', 'icmp', 'amplification', 'slowloris', 'http flood', 'memcached',
                     'ntp', 'dns amplification'],
            'Port Scan': ['port', 'scan', 'nmap', 'scanning', 'probe', 'masscan', 'syn scan', 'connect scan',
                          'udp scan', 'aggressive scan', 'service version'],
            'C2 Beacon': ['c2', 'beacon', 'command', 'cobalt', 'meterpreter', 'empire', 'sliver', 'reverse shell',
                          'periodic', 'websocket'],
            'DNS Tunnel': ['dns', 'tunnel', 'exfil', 'iodine', 'dnscat', 'dns over https', 'txt record',
                           'high-entropy dns', 'dns beaconing'],
            'XSS': ['xss', 'script', 'javascript', 'onerror', 'alert', 'cross-site', 'dom', 'stored', 'reflected',
                    'polyglot', 'mutation'],
            'Lateral Movement': ['lateral', 'movement', 'smb', 'rdp', 'psexec', 'wmi', 'pass-the-hash', 'winrm',
                                 'scheduled task', 'service creation'],
            'Data Exfiltration': ['exfil', 'data', 'upload', 'transfer', 'leak', 'dump', 'archive', 'cloud storage',
                                  'ftp exfiltration', 'encrypted channel'],
            'Botnet': ['botnet', 'bot', 'zombie', 'mirai', 'gafgyt', 'mozi', 'emotet', 'trickbot', 'qakbot', 'iot'],
            'Ransomware': ['ransom', 'encrypt', 'locker', 'wannacry', 'ryuk', 'lockbit', 'conti', 'revil', 'blackcat',
                           'ransom note'],
            'Phishing': ['phish', 'fake', 'credential', 'spoof', 'social', 'harvesting', 'spear', 'clone', 'whaling',
                         'business email', 'malicious redirect'],
            'Zero-Day': ['zero', 'unknown', 'new', 'suspicious', 'novel', 'zero-day', 'unclassified', 'emerging',
                         'previously unseen', 'anomalous'],
        }

        self._load()

    def _load(self):
        """Загрузка модели с диска"""
        try:
            if self.model_path.exists():
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)

                # Загружаем типы атак
                self.attack_types = data.get('attack_types', self.attack_types)

                # Пробуем загрузить ML компоненты
                self.vectorizer = data.get('vectorizer')
                self.classifier = data.get('classifier')
                self.label_encoder = data.get('label_encoder')

                if self.vectorizer is not None and self.classifier is not None and self.label_encoder is not None:
                    self._ml_loaded = True
                    model_version = data.get('model_version', 'unknown')
                    model_type = data.get('model_type', 'unknown')
                    feature_count = data.get('feature_count', 0)
                    logger.info(
                        f"✅ Defense ML модель загружена: {model_type} v{model_version}, "
                        f"{feature_count} признаков, {len(self.attack_types)} классов"
                    )
                else:
                    logger.info(f"✅ Defense модель загружена (keyword mode): {len(self.attack_types)} типов")

                self.loaded = True
            else:
                logger.warning(f"Модель не найдена ({self.model_path}), использую keyword matching")
                self.loaded = True
        except Exception as e:
            logger.error(f"Ошибка загрузки модели: {e}")
            self.loaded = True

    def predict(self, text: str) -> Tuple[str, float]:
        """
        Предсказание типа атаки.
        Приоритет: ML модель → keyword matching (fallback).
        Returns: (attack_type, confidence)
        """
        # Шаг 1: Пробуем ML модель
        if self._ml_loaded and self.vectorizer is not None and self.classifier is not None:
            try:
                X = self.vectorizer.transform([text])
                proba = self.classifier.predict_proba(X)[0]
                idx = proba.argmax()
                confidence = float(proba[idx])

                if confidence >= 0.35:
                    predicted = self.label_encoder.inverse_transform([idx])[0]
                    predicted = self._normalize_attack_type(predicted)
                    return predicted, confidence
            except Exception as e:
                logger.debug(f"ML prediction error, falling back to keywords: {type(e).__name__}: {e}")

        # Шаг 2: Fallback на keyword matching
        return self._keyword_predict(text)

    def _keyword_predict(self, text: str) -> Tuple[str, float]:
        """Keyword matching — надёжный fallback"""
        text_lower = text.lower()
        scores: Dict[str, int] = {}
        total_matches = 0

        for attack_type, keywords in self._keywords.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            scores[attack_type] = matches
            total_matches += matches

        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]

        if total_matches > 0:
            confidence = best_score / total_matches
            other_matches = [s for at, s in scores.items() if at != best_type and s > 0]
            if not other_matches:
                confidence = min(0.95, confidence + 0.2)
        else:
            best_type = 'Zero-Day'
            confidence = 0.3

        return best_type, confidence

    def _normalize_attack_type(self, attack_type: str) -> str:
        """Нормализация имени типа атаки"""
        if attack_type in self.attack_types:
            return attack_type

        attack_lower = attack_type.lower()
        for at in self.attack_types:
            at_lower = at.lower()
            if attack_lower in at_lower or at_lower in attack_lower:
                return at
            attack_words = set(attack_lower.split())
            at_words = set(at_lower.split())
            if attack_words & at_words:
                return at

        return attack_type

    def get_info(self) -> Dict:
        """Информация о загруженной модели"""
        return {
            'loaded': self.loaded,
            'ml_loaded': self._ml_loaded,
            'attack_types': len(self.attack_types),
            'vectorizer_type': type(self.vectorizer).__name__ if self.vectorizer else None,
            'classifier_type': type(self.classifier).__name__ if self.classifier else None,
            'model_path': str(self.model_path),
            'fallback': 'keyword_matching' if not self._ml_loaded else 'ml_with_keyword_fallback',
        }


# ============================================================
# ГЕНЕРАТОР КОДА ЗАЩИТЫ
# ============================================================

class ModelCodeGen:
    """Генератор защитного кода на основе типа атаки"""

    def __init__(self, model: DefenseModelLoader):
        self.model = model
        self.templates = {
            'SQL Injection': (
                'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n'
                '# WAF rule: ModSecurity SQLi protection\n'
                'SecRule REQUEST_URI "@rx union.*select" "id:1001,phase:2,deny,status:403"'
            ),
            'Brute Force': (
                'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n'
                'iptables -A INPUT -p tcp --dport {port} -m state --state NEW '
                '-m recent --update --seconds 300 --hitcount 3 -j DROP'
            ),
            'DDoS': (
                'iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT\n'
                'iptables -A INPUT -p tcp --syn -j DROP\n'
                'echo 1 > /proc/sys/net/ipv4/tcp_syncookies'
            ),
            'Port Scan': (
                'iptables -A INPUT -s {ip} -j DROP\n'
                'iptables -A INPUT -m recent --name portscan --rcheck --seconds 60 -j DROP'
            ),
            'C2 Beacon': (
                'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n'
                'iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP'
            ),
            'DNS Tunnel': (
                'iptables -A INPUT -s {ip} -p udp --dport 53 -m length --length 512:65535 -j DROP'
            ),
            'Zero-Day': (
                'iptables -A INPUT -s {ip} -j DROP\n'
                'iptables -A OUTPUT -d {ip} -j DROP\n'
                'tcpdump -i any -w /tmp/shard_zeroday.pcap host {ip} &'
            ),
            'Botnet': (
                'iptables -A INPUT -s {ip} -j DROP\n'
                'iptables -A OUTPUT -d {ip} -j DROP\n'
                'iptables -A FORWARD -s {ip} -j DROP'
            ),
            'Ransomware': (
                'iptables -A INPUT -s {ip} -j DROP\n'
                'iptables -A OUTPUT -d {ip} -j DROP\n'
                'iptables -A OUTPUT -p tcp --dport 445 -j DROP'
            ),
            'XSS': (
                'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP\n'
                'SecRule REQUEST_URI "@rx <script" "id:2001,phase:2,deny,status:403"'
            ),
            'Lateral Movement': (
                'iptables -A INPUT -s {ip} -p tcp --dport 445 -j DROP\n'
                'iptables -A INPUT -s {ip} -p tcp --dport 139 -j DROP\n'
                'iptables -A FORWARD -s {ip} -j DROP'
            ),
            'Data Exfiltration': (
                'iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP\n'
                'iptables -A OUTPUT -d {ip} -j DROP'
            ),
            'Phishing': (
                'iptables -A INPUT -s {ip} -p tcp --dport 80 -j DROP\n'
                'iptables -A INPUT -s {ip} -p tcp --dport 443 -j DROP'
            ),
        }

    def generate(self, atype: str, alert: Dict) -> str:
        """Генерация кода защиты для алерта"""
        ip = alert.get('src_ip', '0.0.0.0')
        port = alert.get('dst_port', 80)

        # Нормализация типа атаки
        atype = self.model._normalize_attack_type(atype)

        template = self.templates.get(
            atype,
            self.templates['Zero-Day']  # Fallback для неизвестных атак
        )
        return f"# SHARD Defense: {atype}\n" + template.format(ip=ip, port=port)


# ============================================================
# DEFENSE PIPELINE
# ============================================================

class DefensePipeline:
    """Основной пайплайн защиты"""

    def __init__(self):
        self.model = DefenseModelLoader()
        self.codegen = ModelCodeGen(self.model)
        self.ethical = None  # Будет установлен при интеграции с Ethical Control
        self.stats = {
            'alerts': 0,
            'defense_generated': 0,
            'ml_predictions': 0,
            'keyword_fallbacks': 0,
        }
        self._lock = threading.RLock()

    def start(self):
        logger.info("🛡️ Defense Pipeline v2.1 активирован")

    def process_alert(self, alert: Dict) -> Dict:
        """Обработка алерта и генерация защиты"""
        with self._lock:
            self.stats['alerts'] += 1

            # Получаем текст для анализа
            attack_text = alert.get('explanation', alert.get('attack_type', ''))

            # Определяем тип атаки (ML или keyword)
            atype, conf = self.model.predict(attack_text)

            # Считаем статистику
            if self.model._ml_loaded:
                self.stats['ml_predictions'] += 1
            else:
                self.stats['keyword_fallbacks'] += 1

            # Генерируем код защиты
            code = self.codegen.generate(atype, alert)
            self.stats['defense_generated'] += 1

            logger.warning(f"🛡️ DEFENSE: {atype} ({conf:.0%}) → {alert.get('src_ip')}")

            return {
                'attack_type': atype,
                'confidence': conf,
                'code': code,
                'method': 'ml' if self.model._ml_loaded else 'keyword',
            }

    def get_stats(self) -> Dict:
        """Статистика пайплайна"""
        with self._lock:
            return {
                **self.stats,
                'model_info': self.model.get_info(),
            }


# ============================================================
# ДЛЯ ОБРАТНОЙ СОВМЕСТИМОСТИ
# ============================================================

# run_shard.py импортирует ShardDefensePipeline
ShardDefensePipeline = DefensePipeline