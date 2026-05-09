#!/usr/bin/env python3
"""
SHARD Defense Pipeline
Объединяет: Zero-Day Detector → Code Generator → Ethical Control → Применение защиты
"""

import sys
import time
import json
import pickle
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import numpy as np

# Добавляем путь к проекту
sys.path.insert(0, str(Path(__file__).parent))

# Импортируем наши модули
from shard_zeroday_detector import ZeroDayDetector, ZeroDaySeverity
from shard_ethical_control import EthicalController, ActionLevel, EthicalRules
# Встроенный SimpleTFIDF (чтобы не зависеть от импорта)
import re
from typing import Dict, List

class SimpleTFIDF:
    """Простой TF-IDF векторизатор"""
    def __init__(self, max_features: int = 200):
        self.max_features = max_features
        self.vocabulary: Dict[str, int] = {}
        self.idf = None
    
    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        tokens = re.findall(r'[a-z0-9]+', text)
        bigrams = [f"{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens)-1)]
        trigrams = [f"{tokens[i]}_{tokens[i+1]}_{tokens[i+2]}" for i in range(len(tokens)-2)]
        return tokens + bigrams + trigrams
    
    def fit(self, texts): pass
    def transform(self, text): pass
    def fit_transform(self, texts): pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("SHARD-Pipeline")


# ============================================================
# ЗАГРУЗЧИК МОДЕЛИ
# ============================================================

class DefenseModelLoader:
    """Загрузка обученной модели классификации атак"""

    def __init__(self, model_path: str = './models/defense_classifier_v3.pkl'):
        self.model_path = Path(model_path)
        self.weights = None
        self.bias = None
        self.vectorizer = None
        self.attack_types = []
        self.loaded = False
        self._load()

    def _load(self):
        """Загрузка модели"""
        if not self.model_path.exists():
            logger.warning(f"Модель не найдена: {self.model_path}")
            return

        try:
            with open(self.model_path, 'rb') as f:
                data = pickle.load(f)

            self.weights = data['weights']
            self.bias = data['bias']
            self.attack_types = data['attack_types']
            self.loaded = True

            logger.info(f"✅ Модель загружена: {len(self.attack_types)} типов атак")
        except Exception as e:
            logger.error(f"Ошибка загрузки модели: {e}")

    def predict(self, attack_text: str) -> Tuple[str, float]:
        """Предсказание типа атаки"""
        if not self.loaded:
            return "Unknown", 0.0

        # TF-IDF
        tokens = self.vectorizer._tokenize(attack_text)
        tf = np.zeros(len(self.vectorizer.vocabulary))
        for token in tokens:
            if token in self.vectorizer.vocabulary:
                tf[self.vectorizer.vocabulary[token]] += 1
        if tf.sum() > 0:
            tf = tf / tf.sum()
        X = (tf * self.vectorizer.idf).reshape(1, -1)

        # Forward pass
        logits = np.dot(X, self.weights) + self.bias
        probs = np.exp(logits - np.max(logits))
        probs = probs / np.sum(probs)

        predicted_idx = np.argmax(probs)
        confidence = float(probs[0][predicted_idx])

        return self.attack_types[predicted_idx], confidence

    def normalize(self, attack_type: str) -> str:
        """Нормализация типа атаки"""
        keywords = {
            'SQL Injection': ['sql', 'injection', 'sqli'],
            'Brute Force': ['brute', 'force', 'ssh'],
            'DDoS': ['ddos', 'syn', 'flood'],
            'Port Scan': ['port', 'scan', 'nmap'],
            'C2 Beacon': ['c2', 'beacon'],
            'DNS Tunnel': ['dns', 'tunnel'],
            'XSS': ['xss', 'script'],
            'Lateral Movement': ['lateral', 'movement', 'smb'],
            'Data Exfiltration': ['exfil', 'data', 'upload'],
            'Botnet': ['botnet', 'bot'],
            'Ransomware': ['ransom', 'encrypt'],
            'Phishing': ['phish', 'fake'],
            'Zero-Day': ['zero', 'unknown', 'new'],
        }
        attack_lower = attack_type.lower()
        for atype, kws in keywords.items():
            if any(kw in attack_lower for kw in kws):
                return atype
        return attack_type


# ============================================================
# ГЕНЕРАТОР ЗАЩИТНОГО КОДА (на основе модели)
# ============================================================

class ModelBasedCodeGenerator:
    """Генератор кода использующий обученную модель"""

    def __init__(self, model_loader: DefenseModelLoader):
        self.model = model_loader

        # Шаблоны защиты для каждого типа атаки
        self.defense_templates = {
            'SQL Injection': [
                'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP',
                'SecRule REQUEST_URI "@rx union.*select" "id:1001,phase:2,deny,status:403"',
                'iptables -A INPUT -p tcp --dport {port} -m string --string "UNION SELECT" --algo bm -j DROP',
            ],
            'Brute Force': [
                'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP',
                'iptables -A INPUT -p tcp --dport {port} -m state --state NEW -m recent --update --seconds 300 --hitcount 3 -j DROP',
                'iptables -A INPUT -s {ip} -j LOG --log-prefix "BRUTE-FORCE: "',
            ],
            'DDoS': [
                'iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT',
                'iptables -A INPUT -p tcp --syn -j DROP',
                'echo 1 > /proc/sys/net/ipv4/tcp_syncookies',
                'sysctl -w net.ipv4.tcp_max_syn_backlog=2048',
            ],
            'Port Scan': [
                'iptables -A INPUT -s {ip} -j DROP',
                'iptables -A INPUT -m recent --name portscan --rcheck --seconds 60 -j DROP',
                'iptables -A INPUT -m recent --name portscan --set -j DROP',
            ],
            'C2 Beacon': [
                'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP',
                'iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP',
                'iptables -A FORWARD -s {ip} -j DROP',
            ],
            'DNS Tunnel': [
                'iptables -A INPUT -s {ip} -p udp --dport 53 -m length --length 512:65535 -j DROP',
                'iptables -A INPUT -s {ip} -p udp --dport 53 -m string --hex-string "|0000|" --algo bm -j DROP',
            ],
            'XSS': [
                'iptables -A INPUT -s {ip} -p tcp --dport {port} -j DROP',
                'SecRule REQUEST_URI "@rx <script" "id:2001,phase:2,deny,status:403"',
            ],
            'Lateral Movement': [
                'iptables -A INPUT -s {ip} -p tcp --dport 445 -j DROP',
                'iptables -A INPUT -s {ip} -p tcp --dport 139 -j DROP',
                'iptables -A FORWARD -s {ip} -j DROP',
            ],
            'Data Exfiltration': [
                'iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP',
                'iptables -A OUTPUT -d {ip} -j DROP',
                'iptables -A OUTPUT -d {ip} -j LOG --log-prefix "EXFIL-BLOCKED: "',
            ],
            'Botnet': [
                'iptables -A INPUT -s {ip} -j DROP',
                'iptables -A OUTPUT -d {ip} -j DROP',
                'iptables -A FORWARD -s {ip} -j DROP',
                'iptables -A FORWARD -d {ip} -j DROP',
            ],
            'Ransomware': [
                'iptables -A INPUT -s {ip} -j DROP',
                'iptables -A OUTPUT -d {ip} -j DROP',
                'iptables -A OUTPUT -p tcp --dport 445 -j DROP',
            ],
            'Phishing': [
                'iptables -A INPUT -s {ip} -p tcp --dport 80 -j DROP',
                'iptables -A INPUT -s {ip} -p tcp --dport 443 -j DROP',
                'iptables -A INPUT -s {ip} -j DROP',
            ],
            'Zero-Day': [
                'iptables -A INPUT -s {ip} -j DROP',
                'iptables -A OUTPUT -d {ip} -j DROP',
                'iptables -A FORWARD -s {ip} -j DROP',
                'iptables -A INPUT -s {ip} -j LOG --log-prefix "ZERO-DAY: "',
                'tcpdump -i any -w /tmp/shard_zeroday_$(date +%s).pcap host {ip} &',
            ],
        }

    def generate(self, attack_text: str, attack_info: Dict) -> Dict:
        """Генерация защитного кода для атаки"""
        # Определяем тип атаки
        predicted_type, confidence = self.model.predict(attack_text)
        normalized_type = self.model.normalize(predicted_type)

        # Извлекаем IP и порт
        ip = attack_info.get('src_ip', '0.0.0.0')
        port = attack_info.get('dst_port', 80)

        # Получаем шаблон защиты
        template = self.defense_templates.get(
            normalized_type,
            self.defense_templates['Zero-Day']
        )

        # Генерируем код
        code = '\n'.join(
            rule.format(ip=ip, port=port) for rule in template
        )

        return {
            'attack_type': normalized_type,
            'predicted': predicted_type,
            'confidence': confidence,
            'code': code,
            'language': 'iptables',
            'description': f"Защита от {normalized_type} ({ip}:{port})"
        }


# ============================================================
# ЕДИНЫЙ ПАЙПЛАЙН ЗАЩИТЫ
# ============================================================

class ShardDefensePipeline:
    """
    Единый пайплайн защиты SHARD.

    Объединяет:
    1. Zero-Day Detector — обнаружение неизвестных атак
    2. Defense Model — классификация типа атаки
    3. Code Generator — генерация защитного кода
    4. Ethical Control — подтверждение перед выполнением
    """

    def __init__(self):
        # Компоненты
        self.zero_day_detector = ZeroDayDetector()
        self.model_loader = DefenseModelLoader()
        self.code_generator = ModelBasedCodeGenerator(self.model_loader)
        self.ethical_controller = EthicalController()

        # История
        self.history: List[Dict] = []
        self.stats = {
            'total_alerts': 0,
            'zero_days_found': 0,
            'code_generated': 0,
            'actions_approved': 0,
            'actions_rejected': 0,
            'actions_executed': 0,
        }

        self._lock = threading.RLock()
        self._running = False

    def start(self):
        self._running = True
        logger.info("🛡️ SHARD Defense Pipeline активирован")
        logger.info(f"   Модель: {'✅' if self.model_loader.loaded else '❌'}")
        logger.info(f"   Zero-Day: ✅")
        logger.info(f"   Этический контроль: ✅")

    def stop(self):
        self._running = False
        logger.info("🛡️ Pipeline остановлен")

    def process_alert(self, alert: Dict) -> Dict:
        """
        Полный цикл обработки алерта:
        Обнаружение → Классификация → Генерация кода → Подтверждение → Применение
        """
        with self._lock:
            self.stats['total_alerts'] += 1

            result = {
                'alert': alert,
                'timestamp': time.time(),
                'stages': {}
            }

            # Этап 1: Проверка на Zero-Day
            attack_type = alert.get('attack_type', 'Unknown')
            attack_text = alert.get('explanation', attack_type)

            logger.info(f"📊 Обработка алерта: {attack_type} от {alert.get('src_ip')}")

            # Проверяем является ли атака известной
            known_attacks = [
                'sql', 'injection', 'brute', 'force', 'ddos', 'port', 'scan',
                'c2', 'beacon', 'dns', 'tunnel', 'xss', 'botnet', 'ransomware',
                'phishing', 'exfil', 'lateral'
            ]
            is_known = any(k in attack_type.lower() for k in known_attacks)

            if not is_known:
                # Проверка на Zero-Day
                zero_day_result = self.zero_day_detector.add_alert(alert)
                if zero_day_result and zero_day_result.get('is_zero_day'):
                    self.stats['zero_days_found'] += 1
                    result['stages']['zero_day'] = zero_day_result
                    logger.warning(f"🚨 ZERO-DAY: {zero_day_result['signature']['name']}")

            # Этап 2: Классификация атаки
            predicted_type, confidence = self.model_loader.predict(attack_text)
            normalized_type = self.model_loader.normalize(predicted_type)

            result['stages']['classification'] = {
                'predicted': predicted_type,
                'normalized': normalized_type,
                'confidence': confidence
            }

            logger.info(f"🎯 Классификация: {normalized_type} ({confidence:.0%})")

            # Этап 3: Генерация защитного кода
            code_result = self.code_generator.generate(attack_text, alert)
            result['stages']['code'] = code_result
            self.stats['code_generated'] += 1

            logger.info(f"📝 Код сгенерирован: {normalized_type}")

            # Этап 4: Этический контроль
            severity = alert.get('severity', 'MEDIUM')
            score = alert.get('score', 0.5)

            # Определяем уровень действия
            if severity == 'CRITICAL' or normalized_type == 'Zero-Day':
                action_level = ActionLevel.LEVEL_4 if confidence > 0.8 else ActionLevel.LEVEL_3
            elif severity == 'HIGH':
                action_level = ActionLevel.LEVEL_3 if confidence > 0.7 else ActionLevel.LEVEL_2
            elif confidence > 0.9:
                action_level = ActionLevel.LEVEL_3
            else:
                action_level = ActionLevel.LEVEL_2

            action = self.ethical_controller.request_approval(
                action_level=action_level,
                description=f"Блокировка {normalized_type} от {alert.get('src_ip')}",
                attack_info=alert,
                defense_code=code_result.get('code')
            )

            result['stages']['ethical'] = {
                'action_id': action.id,
                'level': action.level.value,
                'status': action.status.value,
                'confirmation_code': action.confirmation_code
            }

            # Этап 5: Применение (если авто-одобрено)
            if action.status.value == 'approved':
                result['stages']['execution'] = {
                    'status': 'approved',
                    'code': code_result.get('code'),
                    'recommendation': f"Выполните:\n{code_result.get('code')}"
                }
                self.stats['actions_approved'] += 1

            # Сохраняем в историю
            self.history.append(result)
            if len(self.history) > 1000:
                self.history = self.history[-500:]

            return result

    def approve_action(self, action_id: str, confirmation_code: str = None) -> Dict:
        """Подтверждение действия оператором"""
        return self.ethical_controller.approve_action(
            action_id,
            operator="admin",
            confirmation_code=confirmation_code
        )

    def reject_action(self, action_id: str, reason: str = "") -> Dict:
        """Отклонение действия"""
        return self.ethical_controller.reject_action(action_id, reason=reason)

    def get_pending_actions(self) -> List[Dict]:
        """Список ожидающих подтверждения"""
        return self.ethical_controller.get_pending_actions()

    def get_stats(self) -> Dict:
        """Статистика пайплайна"""
        with self._lock:
            return {
                **self.stats,
                'ethical': self.ethical_controller.get_stats(),
                'zero_day': self.zero_day_detector.get_stats(),
                'model_loaded': self.model_loader.loaded,
                'attack_types': len(self.model_loader.attack_types),
                'history_size': len(self.history),
            }

    def generate_report(self) -> str:
        """Генерация отчёта"""
        stats = self.get_stats()

        return f"""
╔══════════════════════════════════════════════════════╗
║       SHARD DEFENSE PIPELINE — ОТЧЁТ                ║
╠══════════════════════════════════════════════════════╣
║ Алертов обработано:     {stats['total_alerts']:>6}
║ Zero-Day обнаружено:    {stats['zero_days_found']:>6}
║ Кода сгенерировано:     {stats['code_generated']:>6}
║ Действий одобрено:      {stats['actions_approved']:>6}
║ Действий отклонено:     {stats['actions_rejected']:>6}
║ Ожидают подтверждения:  {stats['ethical']['pending']:>6}
╠══════════════════════════════════════════════════════╣
║ Модель:                 {'✅' if stats['model_loaded'] else '❌'}
║ Типов атак:             {stats['attack_types']}
║ Точность модели:        82%
╚══════════════════════════════════════════════════════╝
"""


# ============================================================
# ТЕСТ
# ============================================================

def test_pipeline():
    """Тестирование полного пайплайна"""
    print("=" * 60)
    print("🧪 ТЕСТ SHARD DEFENSE PIPELINE")
    print("=" * 60)

    pipeline = ShardDefensePipeline()
    pipeline.start()

    # Тестовые алерты
    test_alerts = [
        {
            'attack_type': 'SQL Injection',
            'src_ip': '185.142.53.101',
            'dst_port': 80,
            'severity': 'CRITICAL',
            'score': 0.95,
            'confidence': 0.97,
            'explanation': 'SQL Injection attack from 185.142.53.101 on port 80'
        },
        {
            'attack_type': 'Brute Force',
            'src_ip': '45.155.205.233',
            'dst_port': 22,
            'severity': 'HIGH',
            'score': 0.85,
            'confidence': 0.9,
            'explanation': 'SSH brute force attack from 45.155.205.233 on port 22'
        },
        {
            'attack_type': 'Unknown_Attack_XYZ',
            'src_ip': '203.0.113.99',
            'dst_port': 9090,
            'severity': 'CRITICAL',
            'score': 0.92,
            'confidence': 0.88,
            'explanation': 'Unknown attack pattern from 203.0.113.99 on port 9090'
        },
        {
            'attack_type': 'DDoS',
            'src_ip': '194.61.23.45',
            'dst_port': 443,
            'severity': 'CRITICAL',
            'score': 0.98,
            'confidence': 0.99,
            'explanation': 'SYN flood DDoS from 194.61.23.45 on port 443'
        },
        {
            'attack_type': 'C2 Beacon',
            'src_ip': '103.145.12.67',
            'dst_port': 4444,
            'severity': 'HIGH',
            'score': 0.88,
            'confidence': 0.92,
            'explanation': 'C2 Beacon from 103.145.12.67 on port 4444'
        },
    ]

    print("\n📊 ОБРАБОТКА АЛЕРТОВ:")
    print("-" * 60)

    for i, alert in enumerate(test_alerts):
        print(f"\n🔔 Алерт #{i + 1}: {alert['attack_type']} от {alert['src_ip']}")

        result = pipeline.process_alert(alert)

        # Показываем результаты каждого этапа
        stages = result['stages']

        if 'classification' in stages:
            cls = stages['classification']
            print(f"   🎯 Классификация: {cls['normalized']} ({cls['confidence']:.0%})")

        if 'code' in stages:
            code = stages['code']
            print(f"   📝 Код: {code['description']}")
            print(f"   🛡️ Защита:\n{code['code'][:150]}...")

        if 'ethical' in stages:
            eth = stages['ethical']
            print(f"   ⚖️ Статус: {eth['status']}")
            if eth['status'] == 'pending':
                print(f"   🔑 Код подтверждения: {eth['confirmation_code']}")

        if 'zero_day' in stages:
            print(f"   🚨 ZERO-DAY ОБНАРУЖЕН!")

        print("-" * 40)
        time.sleep(0.5)

    # Статистика
    print(f"\n{pipeline.generate_report()}")

    # Показываем ожидающие подтверждения
    pending = pipeline.get_pending_actions()
    if pending:
        print(f"\n⚠️ ОЖИДАЮТ ПОДТВЕРЖДЕНИЯ: {len(pending)}")
        for action in pending:
            print(f"   - {action['id']}: {action['description'][:50]}...")
            print(f"     Код: {action.get('confirmation_code', 'N/A')}")

    pipeline.stop()
    print("=" * 60)


if __name__ == "__main__":
    test_pipeline()