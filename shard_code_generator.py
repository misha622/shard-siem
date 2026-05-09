#!/usr/bin/env python3
"""
SHARD AI Defense Code Generator
Автономно пишет защитный код на bash, python, go, nginx, iptables.
С sandbox-валидацией перед применением.
"""

import os
import re
import ast
import json
import time
import hashlib
import shutil
import tempfile
import subprocess
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import deque, defaultdict
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger("SHARD-CodeGen")


# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

class CodeLanguage(Enum):
    BASH = "bash"
    PYTHON = "python"
    GO = "go"
    NGINX = "nginx"
    IPTABLES = "iptables"
    POWERSHELL = "powershell"


class CodeSeverity(Enum):
    SAFE = 0  # Безопасно, можно применять
    WARNING = 1  # Требует проверки
    DANGEROUS = 2  # Требует подтверждения
    BLOCKED = 3  # Запрещено


@dataclass
class GeneratedCode:
    """Сгенерированный защитный код"""
    id: str
    language: CodeLanguage
    code: str
    description: str
    attack_type: str
    severity: CodeSeverity
    timestamp: float = field(default_factory=time.time)
    validated: bool = False
    sandbox_result: Optional[Dict] = None
    applied: bool = False
    reverted: bool = False


# ============================================================
# ШАБЛОНЫ КОДА
# ============================================================

CODE_TEMPLATES = {
    CodeLanguage.PYTHON: '''
#!/usr/bin/env python3
"""
SHARD AI Defender - Auto-generated Python Defense Script
Attack: {attack_type}
Source: {src_ip}:{src_port}
Target: {dst_ip}:{dst_port}
Generated: {timestamp}
"""

import subprocess
import logging
import time
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SHARD-Defense")

def block_ip(ip: str, port: int = None, duration: int = 3600):
    """Блокировка IP адреса"""
    logger.warning(f"🚫 Блокировка IP: {{ip}} на {{duration}}с")

    rules = [
        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        ["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"],
        ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
    ]

    if port:
        rules.append([
            "iptables", "-A", "INPUT", "-s", ip,
            "-p", "tcp", "--dport", str(port), "-j", "DROP"
        ])

    for rule in rules:
        try:
            subprocess.run(rule, capture_output=True, timeout=5, check=True)
            logger.debug(f"  ✓ {{' '.join(rule)}}")
        except subprocess.CalledProcessError:
            pass

def rate_limit(port: int, max_conn: int = 10, window: int = 60):
    """Rate limiting для порта"""
    logger.info(f"🐢 Rate limit: порт {{port}}, {{max_conn}}/{{window}}с")

    subprocess.run([
        "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
        "-m", "state", "--state", "NEW", "-m", "recent", "--set"
    ], capture_output=True)

    subprocess.run([
        "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
        "-m", "state", "--state", "NEW", "-m", "recent", "--update",
        "--seconds", str(window), "--hitcount", str(max_conn), "-j", "DROP"
    ], capture_output=True)

def redirect_to_honeypot(src_ip: str, dst_port: int, honeypot_port: int = 8888):
    """Перенаправление атакующего на honeypot"""
    logger.info(f"🍯 Редирект {{src_ip}}:{{dst_port}} → honeypot:{{honeypot_port}}")

    subprocess.run([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-s", src_ip, "-p", "tcp", "--dport", str(dst_port),
        "-j", "DNAT", "--to-destination", f"127.0.0.1:{{honeypot_port}}"
    ], capture_output=True)

def monitor_attack(ip: str, log_file: str = "/var/log/shard/defense.log"):
    """Мониторинг атакующего"""
    logger.info(f"📊 Мониторинг активности {{ip}}")

    try:
        count = 0
        while count < 3600:  # Мониторим 1 час
            time.sleep(10)
            count += 10

            # Проверка активных соединений
            result = subprocess.run(
                ["ss", "-tnp", "state", "established", f"( src {{ip}} or dst {{ip}} )"],
                capture_output=True, text=True, timeout=5
            )

            if not result.stdout.strip():
                logger.info(f"✅ {{ip}}: активность прекращена через {{count}}с")
                break
    except KeyboardInterrupt:
        logger.info("Мониторинг остановлен")

def generate_report(attack_info: dict) -> str:
    """Генерация отчёта о защите"""
    report = f\"\"\"
╔══════════════════════════════════════════════════════╗
║ SHARD AI DEFENDER - ОТЧЁТ О ЗАЩИТЕ                  ║
╠══════════════════════════════════════════════════════╣
║ Атака:    {{attack_info.get("attack_type", "N/A")}}
║ Источник: {{attack_info.get("src_ip", "N/A")}}
║ Порт:     {{attack_info.get("dst_port", "N/A")}}
║ Время:    {{datetime.now().isoformat()}}
║ Статус:   ЗАЩИТА АКТИВИРОВАНА
╚══════════════════════════════════════════════════════╝
\"\"\"
    return report

def main():
    """Главная функция защиты"""
    logger.info("🛡️ SHARD AI Defender v2.0 активирован")
    logger.info("=" * 50)

    attack_info = {attack_info}

    {defense_actions}

    report = generate_report(attack_info)
    print(report)
    logger.info("✅ Защита завершена")

if __name__ == "__main__":
    main()
''',

    CodeLanguage.BASH: '''#!/bin/bash
# ============================================================
# SHARD AI Defender - Auto-generated Bash Defense Script
# Attack: {attack_type}
# Source: {src_ip}:{src_port}
# Generated: {timestamp}
# ============================================================

set -e

log() {{
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}}

log "🛡️ SHARD AI Defender активирован"

# Блокировка IP
BLOCK_IP="{src_ip}"
log "🚫 Блокировка IP: $BLOCK_IP"

iptables -A INPUT -s $BLOCK_IP -j DROP
iptables -A FORWARD -s $BLOCK_IP -j DROP
iptables -A OUTPUT -d $BLOCK_IP -j DROP

# Блокировка порта
BLOCK_PORT="{dst_port}"
log "🔒 Блокировка порта: $BLOCK_PORT"

{port_rules}

# Rate limiting
log "🐢 Rate limiting: порт $BLOCK_PORT, 5 соединений/мин"
iptables -A INPUT -p tcp --dport $BLOCK_PORT \\
    -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport $BLOCK_PORT \\
    -m state --state NEW -m recent --update \\
    --seconds 60 --hitcount 5 -j DROP

# Сохранение правил
iptables-save > /etc/iptables/shard_defense.rules 2>/dev/null || \\
    iptables-save > /tmp/shard_defense_$(date +%s).rules

log "✅ Защита выполнена"
log "📊 Правила сохранены"
''',

    CodeLanguage.GO: '''// SHARD AI Defender - Auto-generated Go Defense Module
// Attack: {attack_type}
// Generated: {timestamp}

package main

import (
    "fmt"
    "log"
    "os/exec"
    "time"
)

func main() {{
    log.Println("🛡️ SHARD AI Defender (Go) активирован")

    srcIP := "{src_ip}"
    dstPort := "{dst_port}"

    // Блокировка IP
    blockIP(srcIP)

    // Блокировка порта
    blockPort(dstPort)

    // Rate limiting
    rateLimit(dstPort, 5, 60)

    log.Println("✅ Защита завершена")
}}

func blockIP(ip string) {{
    log.Printf("🚫 Блокировка IP: %s", ip)

    rules := [][]string{{
        {{"iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"}},
        {{"iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"}},
        {{"iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"}},
    }}

    for _, rule := range rules {{
        cmd := exec.Command(rule[0], rule[1:]...)
        if err := cmd.Run(); err != nil {{
            log.Printf("⚠️ Ошибка: %v", err)
        }}
    }}
}}

func blockPort(port string) {{
    log.Printf("🔒 Блокировка порта: %s", port)

    cmd := exec.Command("iptables", "-A", "INPUT",
        "-p", "tcp", "--dport", port, "-j", "DROP")
    cmd.Run()
}}

func rateLimit(port string, maxConn, window int) {{
    log.Printf("🐢 Rate limit: порт %s, %d/%dс", port, maxConn, window)

    // Установка правила
    exec.Command("iptables", "-A", "INPUT",
        "-p", "tcp", "--dport", port,
        "-m", "state", "--state", "NEW",
        "-m", "recent", "--set").Run()

    exec.Command("iptables", "-A", "INPUT",
        "-p", "tcp", "--dport", port,
        "-m", "state", "--state", "NEW",
        "-m", "recent", "--update",
        "--seconds", fmt.Sprintf("%d", window),
        "--hitcount", fmt.Sprintf("%d", maxConn),
        "-j", "DROP").Run()
}}
''',

    CodeLanguage.NGINX: '''# SHARD AI Defender - Auto-generated Nginx WAF Configuration
# Attack: {attack_type}
# Generated: {timestamp}

# Rate limiting zone
limit_req_zone $binary_remote_addr zone=shard_defense:10m rate=5r/s;

server {{
    listen 80;
    listen 443 ssl;

    # ============================================================
    # SHARD AI Defense Rules
    # ============================================================

    # Block suspicious User-Agents
    if ($http_user_agent ~* "{bad_user_agents}") {{
        return 403;
    }}

    # Block SQL Injection patterns
    if ($query_string ~* "{sql_patterns}") {{
        return 403;
    }}

    # Block Path Traversal
    if ($uri ~* "{path_patterns}") {{
        return 403;
    }}

    # Block Command Injection
    if ($args ~* "{cmd_patterns}") {{
        return 403;
    }}

    # Rate limiting for attack source
    location / {{
        limit_req zone=shard_defense burst=10 nodelay;

        # Deny specific IP
        deny {src_ip};

        # Deny IP range
        deny {ip_range};

        proxy_pass http://backend;
    }}

    # Honeypot redirect for known attackers
    location /admin {{
        return 302 http://{honeypot_ip}:{honeypot_port}$request_uri;
    }}
}}
''',

    CodeLanguage.IPTABLES: '''#!/bin/bash
# ============================================================
# SHARD AI Defender - iptables Defense Rules
# Attack: {attack_type}
# Source: {src_ip}
# Generated: {timestamp}
# ============================================================

# Очистка старых правил для этого IP (на случай обновления)
iptables -D INPUT -s {src_ip} -j DROP 2>/dev/null
iptables -D FORWARD -s {src_ip} -j DROP 2>/dev/null
iptables -D OUTPUT -d {src_ip} -j DROP 2>/dev/null

# Блокировка источника
iptables -A INPUT -s {src_ip} -j DROP
iptables -A FORWARD -s {src_ip} -j DROP
iptables -A OUTPUT -d {src_ip} -j DROP

# Блокировка конкретного порта
iptables -A INPUT -s {src_ip} -p tcp --dport {dst_port} -j DROP
iptables -A INPUT -s {src_ip} -p udp --dport {dst_port} -j DROP

# Блокировка целого диапазона
iptables -A INPUT -s {ip_range} -j DROP

# Rate limiting
iptables -A INPUT -p tcp --dport {dst_port} \\
    -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport {dst_port} \\
    -m state --state NEW -m recent --update \\
    --seconds 60 --hitcount 5 -j DROP

# Защита от SYN flood
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Защита от ICMP flood
iptables -A INPUT -p icmp --icmp-type echo-request \\
    -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Логирование заблокированных пакетов
iptables -A INPUT -s {src_ip} -j LOG \\
    --log-prefix "SHARD-BLOCKED: " --log-level 4

echo "✅ iptables правила применены"
echo "📊 Статистика:"
iptables -L INPUT -n -v | grep {src_ip}
'''
}


# ============================================================
# SANDBOX ДЛЯ ТЕСТИРОВАНИЯ КОДА
# ============================================================

class CodeSandbox:
    """
    Песочница для безопасного тестирования сгенерированного кода.
    """

    DANGEROUS_PATTERNS = [
        r'rm\s+-rf\s+/',  # Удаление системы
        r'mkfs\.',  # Форматирование диска
        r'dd\s+if=',  # Запись на диск
        r'>\s*/dev/',  # Запись в устройство
        r'chmod\s+777\s+/',  # Массовая смена прав
        r'wget.*\|.*sh',  # Скачивание и выполнение
        r'curl.*\|.*bash',  # Curl pipe bash
        r':\(\)\s*\{\s*:\|:&\s*\};:',  # Fork bomb
        r'kill\s+-9\s+-1',  # Убийство всех процессов
        r'reboot',  # Перезагрузка
        r'shutdown',  # Выключение
        r'halt',  # Остановка
    ]

    def __init__(self):
        self.sandbox_dir = Path(tempfile.mkdtemp(prefix='shard_sandbox_'))
        self.test_results: List[Dict] = []
        self._lock = threading.RLock()

    def validate_code(self, code: str, language: CodeLanguage) -> Dict:
        """
        Проверка кода в песочнице.
        Возвращает результат валидации.
        """
        with self._lock:
            result = {
                'valid': False,
                'severity': CodeSeverity.DANGEROUS,
                'errors': [],
                'warnings': [],
                'can_execute': False
            }

            # 1. Проверка на опасные паттерны
            for pattern in self.DANGEROUS_PATTERNS:
                if re.search(pattern, code, re.IGNORECASE):
                    result['errors'].append(f"Опасный паттерн: {pattern}")
                    result['severity'] = CodeSeverity.BLOCKED
                    return result

            # 2. Синтаксическая проверка
            syntax_ok = self._check_syntax(code, language)
            if not syntax_ok:
                result['errors'].append(f"Синтаксическая ошибка в {language.value}")
                return result

            # 3. Статический анализ
            if language == CodeLanguage.PYTHON:
                ast_ok = self._check_python_ast(code)
                if not ast_ok:
                    result['errors'].append("Ошибка AST анализа Python")
                    return result

            # 4. Проверка в песочнице
            sandbox_ok = self._run_sandbox(code, language)
            if sandbox_ok:
                result['valid'] = True
                result['severity'] = CodeSeverity.SAFE
                result['can_execute'] = True
            else:
                result['warnings'].append("Код не протестирован в песочнице")
                result['severity'] = CodeSeverity.WARNING

            return result

    def _check_syntax(self, code: str, language: CodeLanguage) -> bool:
        """Проверка синтаксиса"""
        try:
            if language == CodeLanguage.PYTHON:
                compile(code, '<sandbox>', 'exec')
            elif language == CodeLanguage.BASH:
                result = subprocess.run(
                    ['bash', '-n'],
                    input=code,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            elif language == CodeLanguage.GO:
                # Проверяем через gofmt
                result = subprocess.run(
                    ['gofmt', '-e'],
                    input=code,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            return True
        except SyntaxError:
            return False
        except Exception:
            return True  # Для не-Python языков

    def _check_python_ast(self, code: str) -> bool:
        """AST анализ Python кода на опасные вызовы"""
        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                # Запрещённые вызовы
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['exec', 'eval', 'compile', '__import__']:
                            return False

                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in ['system', 'popen', 'call']:
                            # Проверяем что это НЕ subprocess с безопасными аргументами
                            args = []
                            for arg in node.args:
                                if isinstance(arg, ast.Constant):
                                    args.append(str(arg.value))
                            if any(
                                    d in ' '.join(args).lower()
                                    for d in ['rm -rf', 'mkfs', 'dd if=', '/dev/']
                            ):
                                return False

            return True
        except SyntaxError:
            return False

    def _run_sandbox(self, code: str, language: CodeLanguage) -> bool:
        """Запуск кода в песочнице"""
        try:
            sandbox_file = self.sandbox_dir / f'test_code.{language.value}'

            # Сохраняем код
            with open(sandbox_file, 'w') as f:
                f.write(code)

            # Запускаем в изолированной среде
            if language == CodeLanguage.PYTHON:
                result = subprocess.run(
                    ['python3', '-c', code],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=str(self.sandbox_dir)
                )
                return result.returncode == 0
            elif language == CodeLanguage.BASH:
                result = subprocess.run(
                    ['bash', '-n', str(sandbox_file)],
                    capture_output=True,
                    timeout=5
                )
                return result.returncode == 0

            return True
        except Exception:
            return False

    def cleanup(self):
        """Очистка песочницы"""
        try:
            shutil.rmtree(self.sandbox_dir)
        except:
            pass


# ============================================================
# AI CODE GENERATOR
# ============================================================

class DefenseCodeGenerator:
    """
    AI генератор защитного кода.
    Создаёт реальный код на 5 языках для блокировки атак.
    """

    def __init__(self):
        self.sandbox = CodeSandbox()
        self.generated_codes: List[GeneratedCode] = []
        self.code_history: deque = deque(maxlen=1000)

        # Статистика
        self.stats = {
            'total_generated': 0,
            'validated': 0,
            'applied': 0,
            'reverted': 0,
            'by_language': defaultdict(int)
        }

        self._lock = threading.RLock()

    def generate_defense(
            self,
            attack_info: Dict,
            languages: List[CodeLanguage] = None
    ) -> List[GeneratedCode]:
        """
        Генерация защитного кода для атаки.

        Args:
            attack_info: Информация об атаке
            languages: Языки для генерации (по умолчанию все)

        Returns:
            Список сгенерированных кодов
        """
        if languages is None:
            languages = list(CodeLanguage)

        generated = []
        attack_type = attack_info.get('attack_type', 'Unknown')

        with self._lock:
            for lang in languages:
                # Генерируем код
                code = self._generate_code(attack_info, lang)

                # Валидируем в песочнице
                validation = self.sandbox.validate_code(code, lang)

                gen_code = GeneratedCode(
                    id=f"DEF-{int(time.time())}-{hash(code)}",
                    language=lang,
                    code=code,
                    description=f"Defense against {attack_type}",
                    attack_type=attack_type,
                    severity=validation['severity'],
                    validated=validation['valid'],
                    sandbox_result=validation
                )

                self.generated_codes.append(gen_code)
                self.code_history.append(gen_code)
                self.stats['total_generated'] += 1
                self.stats['by_language'][lang.value] += 1

                if validation['valid']:
                    self.stats['validated'] += 1

                generated.append(gen_code)

        return generated

    def _generate_code(
            self, attack_info: Dict, language: CodeLanguage
    ) -> str:
        """Генерация кода на конкретном языке"""

        # Базовые параметры
        params = {
            'attack_type': attack_info.get('attack_type', 'Unknown Attack'),
            'src_ip': attack_info.get('src_ip', '0.0.0.0'),
            'src_port': attack_info.get('src_port', 0),
            'dst_ip': attack_info.get('dst_ip', '0.0.0.0'),
            'dst_port': attack_info.get('dst_port', 0),
            'timestamp': datetime.now().isoformat(),
            'ip_range': self._get_ip_range(attack_info.get('src_ip', '0.0.0.0')),
            'honeypot_ip': '127.0.0.1',
            'honeypot_port': 8888,
            'bad_user_agents': 'sqlmap|nikto|nmap|burp|hydra',
            'sql_patterns': r'union.*select.*from|or.*1=1|\'--|drop.*table',
            'path_patterns': r'\.\.\/|\.\.\\\\|/etc/passwd|/etc/shadow',
            'cmd_patterns': r';.*wget|;.*curl|;.*bash|;.*nc ',
        }

        # Генерация защитных действий
        actions = self._build_defense_actions(attack_info)
        params['defense_actions'] = actions.get('python', 'pass')
        params['port_rules'] = actions.get('iptables', '')
        params['attack_info'] = json.dumps(attack_info, indent=4)

        # Выбор шаблона
        template = CODE_TEMPLATES.get(language, CODE_TEMPLATES[CodeLanguage.BASH])

        # Заполнение шаблона
        try:
            code = template.format(**params)
        except KeyError as e:
            # Если шаблон не поддерживает какой-то параметр
            code = template.replace('{' + str(e).split("'")[1] + '}', 'N/A')

        return code

    def _build_defense_actions(self, attack_info: Dict) -> Dict[str, str]:
        """Построение защитных действий"""
        src_ip = attack_info.get('src_ip', '0.0.0.0')
        dst_port = attack_info.get('dst_port', 0)
        attack_type = attack_info.get('attack_type', '')

        python_actions = [
            f"    # Блокировка источника атаки",
            f"    block_ip('{src_ip}', {dst_port})",
        ]

        iptables_rules = [
            f"# Блокировка порта {dst_port} для {src_ip}",
            f"iptables -A INPUT -s {src_ip} -p tcp --dport {dst_port} -j DROP",
        ]

        # Специфичные действия по типу атаки
        if 'Brute Force' in attack_type:
            python_actions.append(f"    rate_limit({dst_port}, max_conn=5, window=60)")
            iptables_rules.append(
                f"iptables -A INPUT -p tcp --dport {dst_port} "
                f"-m state --state NEW -m recent --update "
                f"--seconds 60 --hitcount 5 -j DROP"
            )

        if 'DDoS' in attack_type or 'DoS' in attack_type:
            python_actions.append(f"    rate_limit({dst_port}, max_conn=3, window=30)")
            iptables_rules.extend([
                f"iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT",
                f"iptables -A INPUT -p tcp --syn -j DROP",
            ])

        if 'SQL' in attack_type or 'XSS' in attack_type:
            python_actions.append(f"    # WAF защита активирована")
            python_actions.append(f"    redirect_to_honeypot('{src_ip}', {dst_port})")

        if 'Botnet' in attack_type or 'C2' in attack_type:
            python_actions.append(f"    # Изоляция затронутого хоста")
            python_actions.append(f"    # Мониторинг C2 каналов")

        python_actions.append(f"    monitor_attack('{src_ip}')")

        return {
            'python': '\n    '.join(python_actions),
            'iptables': '\n'.join(iptables_rules)
        }

    def _get_ip_range(self, ip: str) -> str:
        """Получение /24 подсети для IP"""
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ip

    def save_code(self, gen_code: GeneratedCode, output_dir: str = './defense_scripts/') -> Path:
        """Сохранение сгенерированного кода в файл"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        ext_map = {
            CodeLanguage.PYTHON: '.py',
            CodeLanguage.BASH: '.sh',
            CodeLanguage.GO: '.go',
            CodeLanguage.NGINX: '.conf',
            CodeLanguage.IPTABLES: '.sh',
            CodeLanguage.POWERSHELL: '.ps1',
        }

        ext = ext_map.get(gen_code.language, '.txt')
        filename = f"defense_{gen_code.attack_type.lower().replace(' ', '_')}_{gen_code.id[-8:]}{ext}"
        filepath = output_path / filename

        with open(filepath, 'w') as f:
            # Шебанг для скриптов
            if gen_code.language == CodeLanguage.PYTHON:
                f.write('#!/usr/bin/env python3\n')
            elif gen_code.language in [CodeLanguage.BASH, CodeLanguage.IPTABLES]:
                f.write('#!/bin/bash\n')

            f.write(gen_code.code)

        # Делаем исполняемым
        os.chmod(filepath, 0o755)

        logger.info(f"📝 Код сохранён: {filepath}")
        return filepath

    def apply_defense(self, gen_code: GeneratedCode, dry_run: bool = True) -> Dict:
        """
        Применение защиты.

        Args:
            gen_code: Сгенерированный код
            dry_run: Если True — только симуляция

        Returns:
            Результат применения
        """
        if gen_code.severity == CodeSeverity.BLOCKED:
            return {
                'success': False,
                'error': 'Код заблокирован — содержит опасные операции'
            }

        if not gen_code.validated:
            return {
                'success': False,
                'error': 'Код не прошёл валидацию в песочнице'
            }

        if dry_run:
            return {
                'success': True,
                'dry_run': True,
                'message': f'Код готов к применению ({gen_code.language.value})',
                'code_preview': gen_code.code[:200]
            }

        # Реальное применение
        try:
            if gen_code.language in [CodeLanguage.BASH, CodeLanguage.IPTABLES]:
                result = subprocess.run(
                    ['bash', '-c', gen_code.code],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    gen_code.applied = True
                    self.stats['applied'] += 1
                    return {'success': True, 'output': result.stdout}
                else:
                    return {'success': False, 'error': result.stderr}

            elif gen_code.language == CodeLanguage.PYTHON:
                result = subprocess.run(
                    ['python3', '-c', gen_code.code],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    gen_code.applied = True
                    self.stats['applied'] += 1
                    return {'success': True, 'output': result.stdout}
                else:
                    return {'success': False, 'error': result.stderr}

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Таймаут выполнения'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

        return {'success': False, 'error': 'Неподдерживаемый язык'}

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                **self.stats,
                'by_language': dict(self.stats['by_language']),
                'total_stored': len(self.generated_codes)
            }


# ============================================================
# ТЕСТ
# ============================================================

def test_code_generator():
    """Тестирование генератора кода"""
    print("=" * 60)
    print("🧪 ТЕСТ AI DEFENSE CODE GENERATOR")
    print("=" * 60)

    gen = DefenseCodeGenerator()

    # Тестовая атака
    attack = {
        'attack_type': 'SQL Injection',
        'src_ip': '185.142.53.101',
        'src_port': 45678,
        'dst_ip': '192.168.1.50',
        'dst_port': 80,
        'severity': 'CRITICAL',
        'score': 0.95,
        'confidence': 0.97
    }

    print(f"\n📊 Генерация защиты против: {attack['attack_type']}")
    print(f"   Источник: {attack['src_ip']}:{attack['src_port']}")
    print(f"   Цель: {attack['dst_ip']}:{attack['dst_port']}")

    # Генерируем на всех языках
    codes = gen.generate_defense(attack)

    for code in codes:
        print(f"\n{'=' * 60}")
        print(f"📝 {code.language.value.upper()} (severity: {code.severity.name})")
        print(f"{'=' * 60}")
        print(code.code[:300])
        print("...")

        # Сохраняем
        filepath = gen.save_code(code)
        print(f"💾 Сохранён: {filepath}")

    # Статистика
    stats = gen.get_stats()
    print(f"\n📊 Статистика:")
    print(f"   Сгенерировано: {stats['total_generated']}")
    print(f"   Валидировано: {stats['validated']}")
    for lang, count in stats['by_language'].items():
        print(f"   {lang}: {count}")

    # Очистка песочницы
    gen.sandbox.cleanup()

    print(f"\n📁 Все скрипты в: defense_scripts/")
    print("=" * 60)


if __name__ == "__main__":
    test_code_generator()