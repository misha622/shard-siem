#!/usr/bin/env python3
"""
SHARD Autonomous AI Defender
Не просто обнаруживает — ОТБИВАЕТ атаки и ПИШЕТ КОД защиты.

Возможности:
- Генерация iptables/nftables правил
- Создание WAF сигнатур
- Авто-изоляция хостов
- Написание временных патчей
- Самообучение на успешных/неуспешных действиях
- Генерация Python-скриптов для защиты
"""

import os
import re
import json
import time
import hashlib
import socket
import struct
import subprocess
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import deque, defaultdict
from datetime import datetime
from enum import Enum

import numpy as np

logger = logging.getLogger("SHARD-Defender")


# ============================================================
# ТИПЫ ЗАЩИТНЫХ ДЕЙСТВИЙ
# ============================================================

class DefenseLevel(Enum):
    MONITOR = 0  # Только наблюдение
    THROTTLE = 1  # Замедление трафика
    BLOCK_PORT = 2  # Блокировка порта
    BLOCK_IP = 3  # Блокировка IP
    ISOLATE = 4  # Изоляция хоста
    REDIRECT = 5  # Перенаправление на honeypot
    COUNTER_ATTACK = 6  # Активное противодействие


# ============================================================
# ГЕНЕРАТОР ЗАЩИТНОГО КОДА
# ============================================================

class DefenseCodeGenerator:
    """
    AI-генератор защитного кода.
    Создаёт iptables правила, WAF сигнатуры, временные патчи.
    """

    def __init__(self):
        self.generated_rules: List[Dict] = []
        self.generated_scripts: List[Path] = []
        self.code_templates = self._load_templates()
        self.script_dir = Path('./defense_scripts')
        self.script_dir.mkdir(exist_ok=True)

    def _load_templates(self) -> Dict[str, str]:
        """Шаблоны защитного кода"""
        return {
            'iptables_block': '''
# Сгенерировано SHARD AI Defender
# Атака: {attack_type} от {src_ip}:{src_port}
# Время: {timestamp}

# Блокировка источника атаки
iptables -A INPUT -s {src_ip} -j DROP
iptables -A FORWARD -s {src_ip} -j DROP
iptables -A OUTPUT -d {src_ip} -j DROP

# Блокировка конкретного порта
iptables -A INPUT -s {src_ip} -p tcp --dport {dst_port} -j DROP

# Rate limiting для похожих атак
iptables -A INPUT -p tcp --dport {dst_port} -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport {dst_port} -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP

echo "SHARD: {src_ip} заблокирован ({attack_type})"
''',

            'nginx_waf_rule': '''
# Сгенерировано SHARD AI Defender
# Атака: {attack_type}
# Сигнатура: {signature}

location / {{
    # Блокировка по User-Agent
    if ($http_user_agent ~* "{bad_user_agent}") {{
        return 403;
    }}

    # Блокировка SQL инъекций
    if ($query_string ~* "{sql_pattern}") {{
        return 403;
    }}

    # Блокировка Path Traversal
    if ($uri ~* "{path_pattern}") {{
        return 403;
    }}

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=shard_limit:10m rate=5r/s;
    limit_req zone=shard_limit burst=10 nodelay;
}}
''',

            'python_defense_script': '''
#!/usr/bin/env python3
\"\"\"
SHARD AI Defender - Автосгенерированный скрипт защиты
Атака: {attack_type}
Источник: {src_ip}
Время: {timestamp}
\"\"\"

import subprocess
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SHARD-Defense")

def block_ip(ip: str, port: int = None):
    \"\"\"Блокировка IP адреса\"\"\"
    logger.warning(f"🚫 Блокировка IP: {{ip}}")

    # iptables правила
    rules = [
        ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
        ['iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'],
        ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
    ]

    if port:
        rules.append(['iptables', '-A', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP'])

    for rule in rules:
        subprocess.run(rule, capture_output=True)
        logger.debug(f"  ✓ {{' '.join(rule)}}")

def rate_limit(port: int, max_connections: int = 10):
    \"\"\"Rate limiting для порта\"\"\"
    subprocess.run([
        'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port),
        '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set'
    ])
    subprocess.run([
        'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port),
        '-m', 'state', '--state', 'NEW', '-m', 'recent', '--update',
        '--seconds', '60', '--hitcount', str(max_connections), '-j', 'DROP'
    ])

def monitor_logs(log_file: str = '/var/log/shard/attacks.log'):
    \"\"\"Мониторинг логов атак\"\"\"
    logger.info(f"📊 Мониторинг логов: {{log_file}}")
    with open(log_file, 'r') as f:
        for line in f:
            if '{src_ip}' in line:
                logger.warning(f"🔴 Обнаружена активность {{src_ip}}")

def main():
    \"\"\"Главная функция защиты\"\"\"
    logger.info("🛡️ SHARD AI Defender активен")
    logger.info(f"   Цель: защита от {{attack_type}}")
    logger.info(f"   Источник: {{src_ip}}")

    # Блокировка источника
    block_ip('{src_ip}', {dst_port})

    # Rate limiting
    rate_limit({dst_port}, max_connections=5)

    # Мониторинг
    monitor_logs()

if __name__ == "__main__":
    main()
''',

            'waf_signature': '''
# Сгенерировано SHARD AI Defender
# Правило WAF для {attack_type}

SecRule REQUEST_URI "{pattern}" \\
    "id:{rule_id},\\
    phase:2,\\
    deny,\\
    status:403,\\
    msg:'SHARD: {attack_type} detected',\\
    severity:'{severity}',\\
    tag:'SHARD-AI'"
''',

            'honeypot_redirect': '''
# Редирект атакующего на honeypot
iptables -t nat -A PREROUTING -s {src_ip} -p tcp --dport {dst_port} \\
    -j DNAT --to-destination 127.0.0.1:{honeypot_port}
iptables -t nat -A POSTROUTING -s {src_ip} -j MASQUERADE
echo "SHARD: {src_ip} перенаправлен на honeypot:{honeypot_port}"
''',
        }

    def generate_iptables_rules(self, attack_info: Dict) -> str:
        """Генерация iptables правил для атаки"""
        template = self.code_templates['iptables_block']
        return template.format(
            attack_type=attack_info.get('attack_type', 'Unknown'),
            src_ip=attack_info.get('src_ip', '0.0.0.0'),
            src_port=attack_info.get('src_port', 0),
            dst_port=attack_info.get('dst_port', 0),
            timestamp=datetime.now().isoformat()
        )

    def generate_waf_rule(self, attack_info: Dict) -> str:
        """Генерация WAF сигнатуры"""
        attack_type = attack_info.get('attack_type', '')

        if 'SQL' in attack_type:
            pattern = "union.*select|or.*1=1|'--"
            sig = "SQL Injection"
        elif 'XSS' in attack_type:
            pattern = "<script|javascript:|onerror="
            sig = "XSS Attack"
        elif 'Path Traversal' in attack_type:
            pattern = r"\.\.\/|\.\.\\\\|/etc/passwd"
            sig = "Path Traversal"
        elif 'Brute Force' in attack_type:
            pattern = "too many requests"
            sig = "Brute Force"
        else:
            pattern = attack_type.lower().replace(' ', '_')
            sig = attack_type

        return f'''# SHARD AI Defender - WAF Rule
# {sig}: {pattern}
SecRule REQUEST_URI "@rx {pattern}" \\
    "id:{hash(attack_type) % 1000000:06d},\\
    phase:2,\\
    deny,\\
    status:403,\\
    msg:'SHARD: {sig} detected',\\
    severity:'CRITICAL',\\
    tag:'SHARD-AI'"
'''

    def generate_defense_script(self, attack_info: Dict) -> Path:
        """Генерация полноценного Python скрипта защиты"""
        template = self.code_templates['python_defense_script']
        code = template.format(
            attack_type=attack_info.get('attack_type', 'Unknown'),
            src_ip=attack_info.get('src_ip', '0.0.0.0'),
            dst_port=attack_info.get('dst_port', 0),
            timestamp=datetime.now().isoformat()
        )

        filename = f"defense_{attack_info.get('attack_type', 'unknown').lower().replace(' ', '_')}_{int(time.time())}.py"
        filepath = self.script_dir / filename

        with open(filepath, 'w') as f:
            f.write(code)
        os.chmod(filepath, 0o755)

        self.generated_scripts.append(filepath)
        logger.info(f"📝 Сгенерирован защитный скрипт: {filepath}")
        return filepath

    def generate_honeypot_redirect(self, attack_info: Dict) -> str:
        """Перенаправление атакующего на honeypot"""
        template = self.code_templates['honeypot_redirect']
        return template.format(
            src_ip=attack_info.get('src_ip', '0.0.0.0'),
            dst_port=attack_info.get('dst_port', 80),
            honeypot_port=attack_info.get('honeypot_port', 8888)
        )

    def get_best_defense(self, attack_info: Dict) -> Dict:
        """AI выбирает лучшую стратегию защиты"""
        attack_type = attack_info.get('attack_type', '')
        severity = attack_info.get('severity', 'MEDIUM')
        score = attack_info.get('score', 0.5)
        confidence = attack_info.get('confidence', 0.5)

        strategies = []

        # Strategy 1: Block IP (always for CRITICAL)
        if severity in ['CRITICAL', 'HIGH'] and confidence > 0.7:
            strategies.append({
                'action': DefenseLevel.BLOCK_IP,
                'priority': 100,
                'code': self.generate_iptables_rules(attack_info),
                'script': self.generate_defense_script(attack_info),
                'description': f"Блокировка IP {attack_info.get('src_ip')}"
            })

        # Strategy 2: WAF Rule (Web Attacks)
        if any(t in attack_type for t in ['SQL', 'XSS', 'Web', 'Path Traversal', 'Injection']):
            strategies.append({
                'action': DefenseLevel.BLOCK_PORT,
                'priority': 90,
                'code': self.generate_waf_rule(attack_info),
                'description': f"WAF правило для {attack_type}"
            })

        # Strategy 3: Rate Limiting
        if attack_type in ['Brute Force', 'DDoS', 'DoS']:
            strategies.append({
                'action': DefenseLevel.THROTTLE,
                'priority': 80,
                'code': self.generate_iptables_rules(attack_info),
                'description': "Rate limiting активирован"
            })

        # Strategy 4: Honeypot Redirect
        if severity not in ['CRITICAL'] and confidence > 0.6:
            strategies.append({
                'action': DefenseLevel.REDIRECT,
                'priority': 70,
                'code': self.generate_honeypot_redirect(attack_info),
                'description': "Перенаправление на honeypot"
            })

        # Strategy 5: Isolate Host
        if attack_type in ['Botnet', 'C2 Beacon', 'Malware']:
            strategies.append({
                'action': DefenseLevel.ISOLATE,
                'priority': 110,
                'code': self.generate_iptables_rules(attack_info),
                'script': self.generate_defense_script(attack_info),
                'description': f"Изоляция хоста {attack_info.get('dst_ip', 'unknown')}"
            })

        # Sort by priority
        strategies.sort(key=lambda x: x['priority'], reverse=True)

        return {
            'strategies': strategies,
            'recommended': strategies[0] if strategies else None,
            'all_code': '\n\n'.join([s.get('code', '') for s in strategies])
        }


# ============================================================
# АВТОНОМНЫЙ ЗАЩИТНИК
# ============================================================

class AutonomousDefender:
    """
    Автономный AI Защитник.
    Принимает решения на основе ML, генерирует код, отбивает атаки.
    """

    def __init__(self, event_bus=None, logger_instance=None):
        self.event_bus = event_bus
        self.logger = logger_instance or logger
        self.code_gen = DefenseCodeGenerator()

        # История защитных действий
        self.defense_history: deque = deque(maxlen=10000)
        self.successful_defenses: List[Dict] = []
        self.failed_defenses: List[Dict] = []

        # Статистика
        self.stats = {
            'total_attacks': 0,
            'blocked': 0,
            'redirected': 0,
            'isolated': 0,
            'scripts_generated': 0,
            'false_positives': 0
        }

        # Обучение на defensive действиях
        self.defense_effectiveness: Dict[str, float] = defaultdict(lambda: 0.5)
        self.attack_patterns: Dict[str, Dict] = {}

        self._lock = threading.RLock()
        self._running = False

    def on_alert(self, alert: Dict) -> Dict:
        """
        Реакция на алерт — выбор и применение защиты.
        """
        with self._lock:
            self.stats['total_attacks'] += 1

            # Анализ атаки и выбор защиты
            defense_plan = self.code_gen.get_best_defense(alert)

            result = {
                'timestamp': time.time(),
                'alert': alert,
                'defense_plan': defense_plan,
                'actions_taken': [],
                'code_generated': [],
                'success': False
            }

            # Применяем рекомендованную защиту
            if defense_plan['recommended']:
                action = defense_plan['recommended']

                if self.logger:
                    self.logger.warning(
                        f"🛡️ AI DEFENDER: {action['description']} "
                        f"(priority={action['priority']})"
                    )

                # Выполняем действие
                if action['action'] == DefenseLevel.BLOCK_IP:
                    self._execute_block_ip(alert, action)
                    result['actions_taken'].append('block_ip')
                    self.stats['blocked'] += 1

                elif action['action'] == DefenseLevel.REDIRECT:
                    self._execute_redirect(alert, action)
                    result['actions_taken'].append('redirect')
                    self.stats['redirected'] += 1

                elif action['action'] == DefenseLevel.ISOLATE:
                    self._execute_isolate(alert, action)
                    result['actions_taken'].append('isolate')
                    self.stats['isolated'] += 1

                # Генерируем защитный скрипт
                if 'script' in action:
                    script_path = action['script']
                    result['code_generated'].append(str(script_path))
                    self.stats['scripts_generated'] += 1

                result['success'] = True

            # Сохраняем в историю
            self.defense_history.append(result)

            # Публикуем результат
            if self.event_bus:
                self.event_bus.publish('defense.action', result)

            return result

    def _execute_block_ip(self, alert: Dict, action: Dict):
        """Блокировка IP"""
        src_ip = alert.get('src_ip', '')
        if not src_ip or src_ip in ['127.0.0.1', '::1', 'localhost']:
            return

        try:
            if os.name != 'nt':  # Linux/WSL
                rules = [
                    ['iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP'],
                    ['iptables', '-A', 'FORWARD', '-s', src_ip, '-j', 'DROP'],
                ]
                for rule in rules:
                    subprocess.run(rule, capture_output=True, timeout=5)

                if self.logger:
                    self.logger.info(f"🚫 IP {src_ip} заблокирован iptables")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Ошибка блокировки {src_ip}: {e}")

    def _execute_redirect(self, alert: Dict, action: Dict):
        """Перенаправление на honeypot"""
        src_ip = alert.get('src_ip', '')
        if not src_ip or src_ip in ['127.0.0.1', '::1']:
            return

        try:
            if os.name != 'nt':
                subprocess.run([
                    'iptables', '-t', 'nat', '-A', 'PREROUTING',
                    '-s', src_ip, '-j', 'DNAT',
                    '--to-destination', '127.0.0.1:8888'
                ], capture_output=True, timeout=5)

                if self.logger:
                    self.logger.info(f"🍯 {src_ip} перенаправлен на honeypot")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Ошибка редиректа {src_ip}: {e}")

    def _execute_isolate(self, alert: Dict, action: Dict):
        """Изоляция хоста"""
        dst_ip = alert.get('dst_ip', '')
        if not dst_ip or dst_ip in ['127.0.0.1', '::1']:
            return

        try:
            if os.name != 'nt':
                rules = [
                    ['iptables', '-A', 'INPUT', '-s', dst_ip, '-j', 'DROP'],
                    ['iptables', '-A', 'OUTPUT', '-d', dst_ip, '-j', 'DROP'],
                    ['iptables', '-A', 'FORWARD', '-s', dst_ip, '-j', 'DROP'],
                    ['iptables', '-A', 'FORWARD', '-d', dst_ip, '-j', 'DROP'],
                ]
                for rule in rules:
                    subprocess.run(rule, capture_output=True, timeout=5)

                if self.logger:
                    self.logger.warning(f"🔒 Хост {dst_ip} изолирован!")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Ошибка изоляции {dst_ip}: {e}")

    def learn_from_result(self, attack_info: Dict, was_successful: bool):
        """Обучение на результате защиты"""
        attack_type = attack_info.get('attack_type', 'Unknown')
        action_taken = attack_info.get('action_taken', 'unknown')

        key = f"{attack_type}:{action_taken}"

        if was_successful:
            self.defense_effectiveness[key] = min(1.0, self.defense_effectiveness[key] + 0.1)
            self.successful_defenses.append(attack_info)
        else:
            self.defense_effectiveness[key] = max(0.0, self.defense_effectiveness[key] - 0.1)
            self.failed_defenses.append(attack_info)
            self.stats['false_positives'] += 1

        if self.logger:
            self.logger.info(
                f"📚 AI обучение: {key} эффективность={self.defense_effectiveness[key]:.2f} "
                f"({'✅' if was_successful else '❌'})"
            )

    def get_defense_stats(self) -> Dict:
        """Статистика защитных действий"""
        with self._lock:
            return {
                **self.stats,
                'effectiveness': dict(self.defense_effectiveness),
                'history_size': len(self.defense_history),
                'successful': len(self.successful_defenses),
                'failed': len(self.failed_defenses),
                'scripts_generated': len(self.code_gen.generated_scripts)
            }

    def rollback_last_defense(self) -> bool:
        """Откат последнего защитного действия"""
        with self._lock:
            if not self.defense_history:
                return False

            last = self.defense_history[-1]
            alert = last.get('alert', {})
            src_ip = alert.get('src_ip', '')

            try:
                if os.name != 'nt':
                    # Удаляем iptables правила для этого IP
                    subprocess.run(
                        ['iptables', '-D', 'INPUT', '-s', src_ip, '-j', 'DROP'],
                        capture_output=True, timeout=5
                    )
                    subprocess.run(
                        ['iptables', '-D', 'FORWARD', '-s', src_ip, '-j', 'DROP'],
                        capture_output=True, timeout=5
                    )

                if self.logger:
                    self.logger.info(f"↩️ Откат защиты для {src_ip}")
                return True
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Ошибка отката: {e}")
                return False


# ============================================================
# ИНТЕГРАЦИЯ С SHARD
# ============================================================

class ShardAutonomousDefenderIntegration:
    """Интеграция автономного защитника в SHARD"""

    def __init__(self, event_bus=None, logger_instance=None):
        self.defender = AutonomousDefender(event_bus, logger_instance)
        self.event_bus = event_bus
        self.logger = logger_instance or logger
        self._running = False

    def setup(self, event_bus, logger_instance=None):
        """Подключение к SHARD"""
        self.event_bus = event_bus
        self.defender.event_bus = event_bus
        if logger_instance:
            self.logger = logger_instance
            self.defender.logger = logger_instance

        if event_bus:
            event_bus.subscribe('alert.detected', self.on_alert)

    def start(self):
        """Запуск защитника"""
        self._running = True
        self.logger.info("🛡️ AI Autonomous Defender активирован")

    def stop(self):
        """Остановка"""
        self._running = False
        self.logger.info("🛡️ AI Defender остановлен")

    def on_alert(self, alert: Dict):
        """Обработка алерта — защита"""
        result = self.defender.on_alert(alert)

        if result['success']:
            self.logger.warning(
                f"🛡️ ЗАЩИТА: {', '.join(result['actions_taken'])} "
                f"против {alert.get('attack_type')} от {alert.get('src_ip')}"
            )

            # Публикуем сгенерированный код
            if result.get('code_generated'):
                for code_file in result['code_generated']:
                    self.logger.info(f"📝 Сгенерирован код защиты: {code_file}")

                    if self.event_bus:
                        self.event_bus.publish('defense.code_generated', {
                            'file': str(code_file),
                            'alert': alert
                        })

    def generate_defense_report(self) -> Dict:
        """Отчёт о защитных действиях"""
        return {
            'stats': self.defender.get_defense_stats(),
            'generated_scripts': [
                str(p) for p in self.defender.code_gen.generated_scripts
            ],
            'effectiveness': dict(self.defender.defense_effectiveness)
        }

    def get_stats(self) -> Dict:
        return self.defender.get_defense_stats()


# ============================================================
# ТЕСТ
# ============================================================

def test_defender():
    """Тестирование автономного защитника"""
    print("=" * 60)
    print("🧪 ТЕСТ AI AUTONOMOUS DEFENDER")
    print("=" * 60)

    defender = AutonomousDefender()

    # Тестовые атаки
    test_attacks = [
        {
            'attack_type': 'SQL Injection',
            'src_ip': '185.142.53.101',
            'dst_port': 80,
            'severity': 'CRITICAL',
            'score': 0.95,
            'confidence': 0.97
        },
        {
            'attack_type': 'Brute Force',
            'src_ip': '45.155.205.233',
            'dst_port': 22,
            'severity': 'HIGH',
            'score': 0.85,
            'confidence': 0.9
        },
        {
            'attack_type': 'DDoS',
            'src_ip': '194.61.23.45',
            'dst_port': 443,
            'severity': 'CRITICAL',
            'score': 0.92,
            'confidence': 0.95
        },
        {
            'attack_type': 'Botnet',
            'src_ip': '89.248.163.1',
            'dst_ip': '192.168.1.50',
            'dst_port': 4444,
            'severity': 'CRITICAL',
            'score': 0.98,
            'confidence': 0.99
        }
    ]

    for alert in test_attacks:
        print(f"\n📊 Атака: {alert['attack_type']} от {alert['src_ip']}")
        result = defender.on_alert(alert)

        if result['success']:
            print(f"   🛡️ Защита: {', '.join(result['actions_taken'])}")
            if result.get('code_generated'):
                for code_file in result['code_generated']:
                    print(f"   📝 Код: {code_file}")
                    # Покажем содержимое сгенерированного файла
                    if Path(code_file).exists():
                        with open(code_file) as f:
                            lines = f.readlines()[:5]
                            for line in lines:
                                print(f"      {line.rstrip()}")

    # Статистика
    stats = defender.get_defense_stats()
    print(f"\n📊 Статистика защиты:")
    print(f"   Атак: {stats['total_attacks']}")
    print(f"   Заблокировано: {stats['blocked']}")
    print(f"   Перенаправлено: {stats['redirected']}")
    print(f"   Изолировано: {stats['isolated']}")
    print(f"   Скриптов: {stats['scripts_generated']}")

    print(f"\n📁 Сгенерированные скрипты в: defense_scripts/")
    print("=" * 60)


if __name__ == "__main__":
    test_defender()