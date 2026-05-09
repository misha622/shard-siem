#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SHARD Red Team Automation Module
Автоматизация пентестов и Red Team операций
Аналог Claude + Kali для SHARD

Author: SHARD Enterprise
Version: 5.0.0
"""

import os
import re
import json
import time
import threading
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml


# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

class AttackPhase(Enum):
    """Фазы атаки по MITRE ATT&CK"""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class FindingSeverity(Enum):
    """Серьёзность находки"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RedTeamConfig:
    """Конфигурация Red Team Automation"""

    # Основные настройки
    enabled: bool = True
    mode: str = "safe"  # safe, aggressive, custom

    # Цели
    target: str = ""
    scope: List[str] = field(default_factory=list)
    excluded_targets: List[str] = field(default_factory=list)

    # Лимиты
    max_concurrent_scans: int = 5
    scan_timeout: int = 3600
    rate_limit_delay: float = 0.5

    # Инструменты
    tools_path: str = "/usr/bin"
    wordlists_path: str = "/usr/share/wordlists"

    # Отчёты
    reports_dir: str = "./data/red_team/reports/"
    save_evidence: bool = True
    evidence_dir: str = "./data/red_team/evidence/"

    # Уведомления
    alert_on_critical: bool = True
    alert_on_high: bool = True


@dataclass
class Finding:
    """Находка пентеста"""
    id: str
    name: str
    description: str
    severity: FindingSeverity
    phase: AttackPhase
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    timestamp: float = field(default_factory=time.time)
    raw_output: Optional[str] = None


# ============================================================
# БАЗОВЫЙ КЛАСС СКАНЕРА
# ============================================================

class BaseScanner:
    """Базовый класс для всех сканеров"""

    def __init__(self, config: RedTeamConfig, logger=None):
        self.config = config
        self.logger = logger
        self.findings: List[Finding] = []
        self._running = False
        self._lock = threading.RLock()

    def run(self, target: str) -> List[Finding]:
        """Запуск сканирования"""
        raise NotImplementedError

    def _run_command(self, cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
        """Безопасный запуск команды"""
        try:
            # Проверка что команда в разрешённом списке
            allowed_commands = ['nmap', 'gobuster', 'nikto', 'sqlmap', 'hydra', 'enum4linux',
                                'whatweb', 'wpscan', 'searchsploit', 'msfconsole', 'dirb', 'ffuf']

            if cmd[0] not in allowed_commands:
                if self.logger:
                    self.logger.warning(f"Command {cmd[0]} not in allowed list")
                return -1, "", f"Command {cmd[0]} not allowed"

            # Запуск
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(timeout=timeout)
            return process.returncode, stdout, stderr

        except subprocess.TimeoutExpired:
            process.kill()
            return -1, "", "Timeout"
        except Exception as e:
            return -1, "", str(e)

    def _add_finding(self, finding: Finding):
        """Добавление находки"""
        with self._lock:
            self.findings.append(finding)
            if self.logger:
                self.logger.info(f"🔍 Finding: [{finding.severity.value}] {finding.name} on {finding.target}")

    def _save_evidence(self, finding_id: str, data: str):
        """Сохранение доказательства"""
        if not self.config.save_evidence:
            return

        evidence_path = Path(self.config.evidence_dir)
        evidence_path.mkdir(parents=True, exist_ok=True)

        filename = evidence_path / f"{finding_id}_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            f.write(data)

        return str(filename)


# ============================================================
# СКАНЕР ПОРТОВ (NMAP)
# ============================================================

class PortScanner(BaseScanner):
    """Сканер портов через Nmap"""

    def run(self, target: str) -> List[Finding]:
        """Запуск сканирования портов"""
        self._running = True
        self.findings = []

        if self.logger:
            self.logger.info(f"🔍 Scanning ports on {target}")

        # Быстрое сканирование 1000 портов
        cmd = ['nmap', '-sV', '-sC', '-T4', '--open', target]
        returncode, stdout, stderr = self._run_command(cmd, timeout=600)

        if returncode == 0:
            findings = self._parse_nmap(stdout, target)
            for f in findings:
                self._add_finding(f)

        # Сканирование UDP портов (топ 100)
        if self.config.mode == 'aggressive':
            cmd = ['nmap', '-sU', '-sV', '--top-ports', '100', target]
            returncode, stdout, stderr = self._run_command(cmd, timeout=600)
            if returncode == 0:
                findings = self._parse_nmap(stdout, target, proto='udp')
                for f in findings:
                    self._add_finding(f)

        self._running = False
        return self.findings

    def _parse_nmap(self, output: str, target: str, proto: str = 'tcp') -> List[Finding]:
        """Парсинг вывода Nmap"""
        findings = []

        # Парсинг открытых портов
        port_pattern = r'(\d+)/(tcp|udp)\s+(\w+)\s+(\w+)\s*(.*)'
        service_info = {}

        for line in output.split('\n'):
            match = re.search(port_pattern, line)
            if match:
                port = int(match.group(1))
                proto_type = match.group(2)
                state = match.group(3)
                service = match.group(4)
                version = match.group(5).strip()

                if state == 'open':
                    service_info[port] = {
                        'service': service,
                        'version': version,
                        'proto': proto_type
                    }

                    severity = FindingSeverity.INFO
                    if service in ['http', 'https', 'ssh', 'telnet', 'ftp', 'smb', 'rdp', 'vnc']:
                        severity = FindingSeverity.LOW
                    if port in [21, 23, 445, 3389]:
                        severity = FindingSeverity.MEDIUM

                    finding = Finding(
                        id=f"PORT-{port}-{proto_type}",
                        name=f"Open {proto_type.upper()} port {port} ({service})",
                        description=f"Port {port}/{proto_type} is open running {service} {version}",
                        severity=severity,
                        phase=AttackPhase.RECONNAISSANCE,
                        target=target,
                        port=port,
                        service=service,
                        remediation=self._get_port_remediation(port, service),
                        raw_output=line
                    )
                    findings.append(finding)

        # Сохраняем полный вывод
        if findings:
            self._save_evidence(f"nmap_{target.replace('.', '_')}", output)

        return findings

    def _get_port_remediation(self, port: int, service: str) -> str:
        """Рекомендации по порту"""
        recommendations = {
            21: "Disable FTP or use SFTP/FTPS instead",
            23: "Disable Telnet, use SSH instead",
            445: "Block SMB from external access, use VPN",
            3389: "Restrict RDP access, use RD Gateway or VPN",
        }
        return recommendations.get(port, f"Review if {service} needs to be exposed")


# ============================================================
# СКАНЕР ВЕБ-УЯЗВИМОСТЕЙ (NIKTO)
# ============================================================

class WebVulnerabilityScanner(BaseScanner):
    """Сканер веб-уязвимостей через Nikto"""

    def run(self, target: str, port: int = None) -> List[Finding]:
        """Запуск сканирования веб-уязвимостей"""
        self._running = True
        self.findings = []

        url = target
        if port and port not in [80, 443]:
            url = f"{target}:{port}"

        if not url.startswith('http'):
            url = f"http://{url}"

        if self.logger:
            self.logger.info(f"🔍 Scanning web vulnerabilities on {url}")

        # Nikto сканирование
        cmd = ['nikto', '-h', url, '-Tuning', '123456789', '-Format', 'txt']
        returncode, stdout, stderr = self._run_command(cmd, timeout=1800)

        if returncode == 0 or returncode == 1:  # Nikto returns 1 when vulnerabilities found
            findings = self._parse_nikto(stdout, target, port)
            for f in findings:
                self._add_finding(f)
            self._save_evidence(f"nikto_{target.replace('.', '_')}", stdout)

        # Дополнительно WhatWeb для определения технологий
        cmd = ['whatweb', url, '--no-errors']
        returncode, stdout, stderr = self._run_command(cmd, timeout=60)
        if returncode == 0:
            tech_finding = self._parse_whatweb(stdout, target, port)
            if tech_finding:
                self._add_finding(tech_finding)

        self._running = False
        return self.findings

    def _parse_nikto(self, output: str, target: str, port: int = None) -> List[Finding]:
        """Парсинг вывода Nikto"""
        findings = []

        for line in output.split('\n'):
            if '+ OSVDB-' in line or 'OSVDB-' in line:
                # Извлечение информации
                severity = FindingSeverity.MEDIUM
                if 'critical' in line.lower() or 'high' in line.lower():
                    severity = FindingSeverity.HIGH

                finding = Finding(
                    id=f"NIKTO-{hash(line) % 10000}",
                    name="Web Vulnerability Detected",
                    description=line.strip(),
                    severity=severity,
                    phase=AttackPhase.INITIAL_ACCESS,
                    target=target,
                    port=port,
                    service='http',
                    remediation="Review and patch the identified vulnerability",
                    raw_output=line
                )
                findings.append(finding)

        return findings

    def _parse_whatweb(self, output: str, target: str, port: int = None) -> Optional[Finding]:
        """Парсинг вывода WhatWeb"""
        if not output.strip():
            return None

        return Finding(
            id=f"TECH-{hash(output) % 10000}",
            name="Technology Detection",
            description=f"Detected technologies: {output[:200]}",
            severity=FindingSeverity.INFO,
            phase=AttackPhase.RECONNAISSANCE,
            target=target,
            port=port,
            service='http',
            raw_output=output
        )


# ============================================================
# СКАНЕР ДИРЕКТОРИЙ (GOBUSTER)
# ============================================================

class DirectoryScanner(BaseScanner):
    """Сканер директорий через Gobuster"""

    def run(self, target: str, port: int = None) -> List[Finding]:
        """Запуск сканирования директорий"""
        self._running = True
        self.findings = []

        url = target
        if port and port not in [80, 443]:
            url = f"{target}:{port}"

        if not url.startswith('http'):
            url = f"http://{url}"

        wordlist = Path(self.config.wordlists_path) / 'dirb' / 'common.txt'
        if not wordlist.exists():
            wordlist = Path(self.config.wordlists_path) / 'common.txt'

        if not wordlist.exists():
            if self.logger:
                self.logger.warning("Wordlist not found, skipping directory scan")
            return []

        if self.logger:
            self.logger.info(f"🔍 Scanning directories on {url}")

        cmd = ['gobuster', 'dir', '-u', url, '-w', str(wordlist), '-q', '-k']
        returncode, stdout, stderr = self._run_command(cmd, timeout=600)

        if returncode == 0 and stdout.strip():
            findings = self._parse_gobuster(stdout, target, port)
            for f in findings:
                self._add_finding(f)
            self._save_evidence(f"gobuster_{target.replace('.', '_')}", stdout)

        self._running = False
        return self.findings

    def _parse_gobuster(self, output: str, target: str, port: int = None) -> List[Finding]:
        """Парсинг вывода Gobuster"""
        findings = []

        sensitive_paths = ['admin', 'login', 'wp-admin', 'phpmyadmin', '.git', '.env', 'backup', 'config']

        for line in output.split('\n'):
            if line.strip() and 'Status: 200' in line:
                path = line.split()[0]

                is_sensitive = any(s in path.lower() for s in sensitive_paths)
                severity = FindingSeverity.MEDIUM if is_sensitive else FindingSeverity.LOW

                finding = Finding(
                    id=f"DIR-{hash(path) % 10000}",
                    name=f"Directory discovered: {path}",
                    description=f"Accessible directory: {path}" + (" (potentially sensitive)" if is_sensitive else ""),
                    severity=severity,
                    phase=AttackPhase.DISCOVERY,
                    target=target,
                    port=port,
                    service='http',
                    remediation="Restrict access to sensitive directories" if is_sensitive else "Review if directory should be public",
                    raw_output=line
                )
                findings.append(finding)

        return findings


# ============================================================
# SQL ИНЪЕКЦИИ (SQLMAP)
# ============================================================

class SQLInjectionScanner(BaseScanner):
    """Сканер SQL инъекций через SQLMap"""

    def run(self, target: str, port: int = None) -> List[Finding]:
        """Запуск сканирования SQL инъекций"""
        self._running = True
        self.findings = []

        url = target
        if port and port not in [80, 443]:
            url = f"{target}:{port}"

        if not url.startswith('http'):
            url = f"http://{url}"

        if self.logger:
            self.logger.info(f"🔍 Scanning SQL injection on {url}")

        # SQLMap с базовыми параметрами
        cmd = ['sqlmap', '-u', url, '--batch', '--level=1', '--risk=1', '--random-agent']
        returncode, stdout, stderr = self._run_command(cmd, timeout=1200)

        if returncode == 0:
            if 'vulnerable' in stdout.lower() or 'parameter' in stdout.lower():
                finding = Finding(
                    id=f"SQLI-{hash(url) % 10000}",
                    name="SQL Injection Vulnerability",
                    description="SQL injection vulnerability detected",
                    severity=FindingSeverity.CRITICAL,
                    phase=AttackPhase.INITIAL_ACCESS,
                    target=target,
                    port=port,
                    service='http',
                    remediation="Use parameterized queries and input validation",
                    raw_output=stdout[:1000]
                )
                self._add_finding(finding)
                self._save_evidence(f"sqlmap_{target.replace('.', '_')}", stdout)

        self._running = False
        return self.findings


# ============================================================
# СКАНЕР УЯЗВИМЫХ ПАРОЛЕЙ (HYDRA)
# ============================================================

class PasswordBruteForceScanner(BaseScanner):
    """Сканер слабых паролей через Hydra"""

    def run(self, target: str, service: str, port: int = None) -> List[Finding]:
        """Запуск проверки паролей (только в safe mode с предупреждением)"""
        self._running = True
        self.findings = []

        if self.config.mode != 'aggressive':
            if self.logger:
                self.logger.warning("Password brute-force requires aggressive mode")
            return []

        if self.logger:
            self.logger.info(f"🔍 Testing weak passwords on {target}:{port} ({service})")

        # Используем минимальный словарь для проверки
        wordlist = Path(self.config.wordlists_path) / 'fasttrack.txt'
        if not wordlist.exists():
            return []

        port_arg = port or self._get_default_port(service)

        cmd = ['hydra', '-l', 'admin', '-P', str(wordlist), f'{service}://{target}']
        if port_arg:
            cmd.extend(['-s', str(port_arg)])
        cmd.extend(['-t', '4', '-W', '30'])

        returncode, stdout, stderr = self._run_command(cmd, timeout=600)

        if 'login:' in stdout.lower() or 'password:' in stdout.lower():
            finding = Finding(
                id=f"WEAKPASS-{service}-{hash(target) % 10000}",
                name=f"Weak password on {service}",
                description=f"Default or weak credentials detected on {service}",
                severity=FindingSeverity.CRITICAL,
                phase=AttackPhase.CREDENTIAL_ACCESS,
                target=target,
                port=port_arg,
                service=service,
                remediation=f"Change default credentials and enforce strong password policy",
                raw_output=stdout[:500]
            )
            self._add_finding(finding)

        self._running = False
        return self.findings

    def _get_default_port(self, service: str) -> int:
        """Порт по умолчанию для сервиса"""
        ports = {
            'ssh': 22,
            'ftp': 21,
            'telnet': 23,
            'smtp': 25,
            'http': 80,
            'https': 443,
            'mysql': 3306,
            'postgresql': 5432,
            'rdp': 3389,
            'vnc': 5900
        }
        return ports.get(service, 0)


# ============================================================
# ОСНОВНОЙ ДВИЖОК RED TEAM
# ============================================================

class RedTeamEngine:
    """
    Основной движок Red Team Automation
    Координирует все сканеры и генерирует отчёты
    """

    def __init__(self, config: RedTeamConfig = None, logger=None):
        self.config = config or RedTeamConfig()
        self.logger = logger

        # Сканеры
        self.port_scanner = PortScanner(config, logger)
        self.web_scanner = WebVulnerabilityScanner(config, logger)
        self.dir_scanner = DirectoryScanner(config, logger)
        self.sql_scanner = SQLInjectionScanner(config, logger)
        self.password_scanner = PasswordBruteForceScanner(config, logger)

        # Результаты
        self.findings: List[Finding] = []
        self.scan_history: deque = deque(maxlen=100)

        # Статистика
        self.stats = {
            'total_scans': 0,
            'total_findings': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0
        }

        self._lock = threading.RLock()
        self._running = False

    def run_full_assessment(self, target: str, scope: List[str] = None) -> Dict:
        """
        Запуск полной оценки безопасности цели

        Args:
            target: Основная цель
            scope: Дополнительные цели в области

        Returns:
            Отчёт с результатами
        """
        self._running = True
        start_time = time.time()

        if self.logger:
            self.logger.info(f"🚀 Starting Red Team assessment on {target}")

        all_findings = []

        # Фаза 1: Разведка
        if self.logger:
            self.logger.info("📍 Phase 1: Reconnaissance")

        # Сканирование портов
        port_findings = self.port_scanner.run(target)
        all_findings.extend(port_findings)

        # Определение веб-портов
        web_ports = []
        for f in port_findings:
            if f.service in ['http', 'https'] and f.port:
                web_ports.append(f.port)

        # Фаза 2: Сканирование веб-приложений
        if web_ports:
            if self.logger:
                self.logger.info("📍 Phase 2: Web Application Scanning")

            for port in web_ports[:3]:  # Ограничиваем количество
                web_findings = self.web_scanner.run(target, port)
                all_findings.extend(web_findings)

                dir_findings = self.dir_scanner.run(target, port)
                all_findings.extend(dir_findings)

                if self.config.mode == 'aggressive':
                    sql_findings = self.sql_scanner.run(target, port)
                    all_findings.extend(sql_findings)

        # Фаза 3: Проверка сервисов
        if self.logger:
            self.logger.info("📍 Phase 3: Service Testing")

        services_tested = set()
        for f in port_findings:
            if f.service and f.service not in services_tested:
                services_tested.add(f.service)

                if self.config.mode == 'aggressive' and f.service in ['ssh', 'ftp', 'mysql']:
                    pass_findings = self.password_scanner.run(target, f.service, f.port)
                    all_findings.extend(pass_findings)

        # Обновление статистики
        with self._lock:
            self.findings.extend(all_findings)
            self.stats['total_scans'] += 1
            self.stats['total_findings'] += len(all_findings)

            for f in all_findings:
                if f.severity == FindingSeverity.CRITICAL:
                    self.stats['critical_findings'] += 1
                elif f.severity == FindingSeverity.HIGH:
                    self.stats['high_findings'] += 1
                elif f.severity == FindingSeverity.MEDIUM:
                    self.stats['medium_findings'] += 1
                elif f.severity == FindingSeverity.LOW:
                    self.stats['low_findings'] += 1

        duration = time.time() - start_time

        # Генерация отчёта
        report = self.generate_report(target, all_findings, duration)

        # Сохранение в историю
        self.scan_history.append({
            'target': target,
            'timestamp': start_time,
            'duration': duration,
            'findings_count': len(all_findings),
            'report': report
        })

        self._running = False

        if self.logger:
            self.logger.info(f"✅ Assessment completed in {duration:.1f}s. Found {len(all_findings)} findings")

        return report

    def run_quick_scan(self, target: str) -> List[Finding]:
        """Быстрое сканирование (только порты)"""
        return self.port_scanner.run(target)

    def generate_report(self, target: str, findings: List[Finding], duration: float) -> Dict:
        """Генерация отчёта"""
        # Группировка по серьёзности
        by_severity = defaultdict(list)
        for f in findings:
            by_severity[f.severity.value].append({
                'id': f.id,
                'name': f.name,
                'description': f.description,
                'target': f.target,
                'port': f.port,
                'service': f.service,
                'remediation': f.remediation
            })

        # Группировка по фазе
        by_phase = defaultdict(list)
        for f in findings:
            by_phase[f.phase.value].append(f.id)

        return {
            'scan_info': {
                'target': target,
                'timestamp': time.time(),
                'duration': duration,
                'total_findings': len(findings),
                'mode': self.config.mode
            },
            'summary': {
                'critical': len(by_severity.get('CRITICAL', [])),
                'high': len(by_severity.get('HIGH', [])),
                'medium': len(by_severity.get('MEDIUM', [])),
                'low': len(by_severity.get('LOW', [])),
                'info': len(by_severity.get('INFO', []))
            },
            'findings_by_severity': dict(by_severity),
            'findings_by_phase': dict(by_phase),
            'mitre_attack': self._map_to_mitre(findings),
            'recommendations': self._generate_recommendations(findings)
        }

    def _map_to_mitre(self, findings: List[Finding]) -> Dict:
        """Маппинг находок на MITRE ATT&CK"""
        tactics = defaultdict(set)

        phase_to_tactic = {
            AttackPhase.RECONNAISSANCE: 'TA0043',
            AttackPhase.INITIAL_ACCESS: 'TA0001',
            AttackPhase.EXECUTION: 'TA0002',
            AttackPhase.PERSISTENCE: 'TA0003',
            AttackPhase.PRIVILEGE_ESCALATION: 'TA0004',
            AttackPhase.DEFENSE_EVASION: 'TA0005',
            AttackPhase.CREDENTIAL_ACCESS: 'TA0006',
            AttackPhase.DISCOVERY: 'TA0007',
            AttackPhase.LATERAL_MOVEMENT: 'TA0008',
            AttackPhase.COLLECTION: 'TA0009',
            AttackPhase.COMMAND_AND_CONTROL: 'TA0011',
            AttackPhase.EXFILTRATION: 'TA0010',
            AttackPhase.IMPACT: 'TA0040'
        }

        for f in findings:
            tactic = phase_to_tactic.get(f.phase)
            if tactic:
                tactics[tactic].add(f.id)

        return {k: list(v) for k, v in tactics.items()}

    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        """Генерация рекомендаций"""
        recommendations = set()

        # Приоритет по серьёзности
        for f in sorted(findings, key=lambda x: x.severity.value, reverse=True):
            if f.remediation:
                recommendations.add(f.remediation)

        # Общие рекомендации
        if any(f.port == 23 for f in findings):
            recommendations.add("Disable Telnet - use SSH instead")
        if any(f.port == 21 for f in findings):
            recommendations.add("Replace FTP with SFTP or FTPS")
        if any('http' in (f.service or '') for f in findings if f.port == 80):
            recommendations.add("Redirect HTTP to HTTPS")

        return list(recommendations)[:10]

    def save_report(self, report: Dict, filename: str = None) -> str:
        """Сохранение отчёта"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            target = report['scan_info']['target'].replace('.', '_').replace(':', '_')
            filename = f"redteam_{target}_{timestamp}.json"

        report_path = Path(self.config.reports_dir) / filename
        report_path.parent.mkdir(parents=True, exist_ok=True)

        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        return str(report_path)

    def generate_html_report(self, report: Dict) -> str:
        """Генерация HTML отчёта"""
        summary = report['summary']

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SHARD Red Team Report - {report['scan_info']['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        h1 {{ color: #333; border-bottom: 3px solid #dc3545; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }}
        .card {{ padding: 20px; border-radius: 10px; color: white; text-align: center; }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: black; }}
        .low {{ background: #28a745; }}
        .info {{ background: #17a2b8; }}
        .finding {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid; border-radius: 5px; }}
        .finding.critical {{ border-color: #dc3545; }}
        .finding.high {{ border-color: #fd7e14; }}
        .finding.medium {{ border-color: #ffc107; }}
        .finding.low {{ border-color: #28a745; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SHARD Red Team Assessment Report</h1>
        <p><strong>Target:</strong> {report['scan_info']['target']}</p>
        <p><strong>Date:</strong> {datetime.fromtimestamp(report['scan_info']['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Duration:</strong> {report['scan_info']['duration']:.1f} seconds</p>

        <div class="summary">
            <div class="card critical"><h2>{summary['critical']}</h2>CRITICAL</div>
            <div class="card high"><h2>{summary['high']}</h2>HIGH</div>
            <div class="card medium"><h2>{summary['medium']}</h2>MEDIUM</div>
            <div class="card low"><h2>{summary['low']}</h2>LOW</div>
            <div class="card info"><h2>{summary['info']}</h2>INFO</div>
        </div>

        <h2>Findings</h2>
"""

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            findings = report['findings_by_severity'].get(severity, [])
            if findings:
                html += f"<h3>{severity} ({len(findings)})</h3>"
                for f in findings:
                    html += f"""
        <div class="finding {severity.lower()}">
            <strong>{f['name']}</strong>
            <p>{f['description']}</p>
            <p><strong>Target:</strong> {f['target']}{':' + str(f['port']) if f.get('port') else ''}</p>
            <p><strong>Remediation:</strong> {f.get('remediation', 'N/A')}</p>
        </div>
"""

        html += """
        <h2>Recommendations</h2>
        <ul>
"""
        for rec in report.get('recommendations', []):
            html += f"            <li>{rec}</li>\n"

        html += """
        </ul>
        <hr>
        <p style="color: #999; text-align: right;">SHARD Enterprise SIEM - Red Team Module</p>
    </div>
</body>
</html>
"""
        return html

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            return dict(self.stats)

    def get_last_scan(self) -> Optional[Dict]:
        """Получить последнее сканирование"""
        if self.scan_history:
            return self.scan_history[-1]
        return None


# ============================================================
# ИНТЕГРАЦИЯ С SHARD
# ============================================================

class ShardRedTeamIntegration:
    """Интеграция Red Team Automation в SHARD"""

    def __init__(self, config: Dict = None):
        self.config = RedTeamConfig()
        self.engine: Optional[RedTeamEngine] = None
        self.event_bus = None
        self.logger = None

    def setup(self, event_bus, logger):
        """Настройка интеграции"""
        self.event_bus = event_bus
        self.logger = logger
        self.engine = RedTeamEngine(self.config, logger)

        if event_bus:
            event_bus.subscribe('redteam.scan', self.on_scan_request)
            event_bus.subscribe('redteam.quick', self.on_quick_scan)

    def on_scan_request(self, data: Dict):
        """Обработка запроса сканирования"""
        target = data.get('target', '')
        scope = data.get('scope', [])

        if not target:
            return

        if self.logger:
            self.logger.info(f"🎯 Red Team scan requested for {target}")

        # Запуск в отдельном потоке
        def run_scan():
            report = self.engine.run_full_assessment(target, scope)

            # Сохранение отчёта
            json_path = self.engine.save_report(report)
            html_report = self.engine.generate_html_report(report)
            html_path = json_path.replace('.json', '.html')
            with open(html_path, 'w') as f:
                f.write(html_report)

            # Публикация критических находок как алертов
            for severity in ['CRITICAL', 'HIGH']:
                for finding in report['findings_by_severity'].get(severity, []):
                    self._publish_alert(finding, target)

            if self.event_bus:
                self.event_bus.publish('redteam.scan.completed', {
                    'target': target,
                    'report_path': json_path,
                    'summary': report['summary'],
                    'request_id': data.get('request_id')
                })

            if self.logger:
                self.logger.info(
                    f"✅ Red Team scan completed: {report['summary']['critical']} critical, {report['summary']['high']} high")

        threading.Thread(target=run_scan, daemon=True).start()

    def on_quick_scan(self, data: Dict):
        """Быстрое сканирование"""
        target = data.get('target', '')
        if not target:
            return

        findings = self.engine.run_quick_scan(target)

        if self.event_bus:
            self.event_bus.publish('redteam.quick.completed', {
                'target': target,
                'findings': [
                    {
                        'name': f.name,
                        'severity': f.severity.value,
                        'port': f.port,
                        'service': f.service
                    }
                    for f in findings
                ],
                'request_id': data.get('request_id')
            })

    def _publish_alert(self, finding: Dict, target: str):
        """Публикация находки как алерта"""
        if self.event_bus:
            severity = finding.get('severity', 'HIGH')
            self.event_bus.publish('alert.detected', {
                'attack_type': 'Red Team Finding',
                'severity': severity,
                'score': 0.9 if severity == 'CRITICAL' else 0.7,
                'confidence': 0.95,
                'explanation': finding.get('description', ''),
                'details': {
                    'finding_id': finding.get('id'),
                    'name': finding.get('name'),
                    'target': target,
                    'port': finding.get('port'),
                    'service': finding.get('service'),
                    'remediation': finding.get('remediation')
                }
            })

    def scan_target(self, target: str, scope: List[str] = None) -> Dict:
        """Синхронное сканирование цели"""
        if not self.engine:
            self.engine = RedTeamEngine(self.config, self.logger)
        return self.engine.run_full_assessment(target, scope)

    def get_stats(self) -> Dict:
        """Получить статистику"""
        if self.engine:
            return self.engine.get_stats()
        return {}

    def get_last_report(self) -> Optional[Dict]:
        """Получить последний отчёт"""
        if self.engine:
            return self.engine.get_last_scan()
        return None


# ============================================================
# ТЕСТИРОВАНИЕ
# ============================================================

def test_red_team():
    """Тестирование Red Team Automation"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ RED TEAM AUTOMATION")
    print("=" * 60)

    config = RedTeamConfig()
    config.mode = "safe"

    engine = RedTeamEngine(config)

    # Тест 1: Сканирование портов localhost
    print("\n📝 Тест 1: Сканирование портов localhost")
    findings = engine.port_scanner.run("127.0.0.1")
    print(f"   Найдено открытых портов: {len(findings)}")
    for f in findings:
        print(f"      [{f.severity.value}] Port {f.port}: {f.service}")

    # Тест 2: Статистика
    print("\n📝 Тест 2: Статистика")
    stats = engine.get_stats()
    print(f"   Всего сканирований: {stats['total_scans']}")
    print(f"   Всего находок: {stats['total_findings']}")

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_red_team()